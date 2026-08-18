//
// LaBRADOR-backed pi2 (response proof) for the M1 milestone. See
// src/nizk_labrador.hpp for the high-level contract and
// docs/labrador-primer.md §3 for the conceptual mapping.
//
// Encoding (quotient-polynomial lifting; soundness NOT claimed, open M1
// co-design item): over the integers,
//
//     sum_j s_j (*) c_j     + e3   + p0 * k_h    = h
//     sum_i s_i (*) B[i][j] + e1_j + p0 * k_t[j] = t_j        (j < K)
//
// with (*) the negacyclic convolution in Z[X]/(X^256+1) (all polynomials
// centered representatives). These equalities hold verbatim mod LaBRADOR's PS_Q ~ 2^38, so they are handed to LaBRADOR
// as rank-1 sparsecnsts with an empty quadfunc. The witness is
//     s (K polys) | e1 (K) | e3 (1) | k_t (K) | k_h (1)
// with L2APPROX norm bounds (n*N for ternary blocks, N*(K*N+1)^2 for the
// quotient blocks). The quotient blocks are what keep the mod-PS_Q encoding
// from being vacuous.
//
// Proof wire format (Proof::bytes), all integers little-endian:
//   "LAB1" | u32 nrounds
//   per round: u32 kappa1 (cross-check; verifier recomputes it)
//              | m[0] (kappa1 polz) | m[2] (LIFTS polz) | m[3] (kappa1 polz)
//              | p[256] as i32
//   final witness: nn polys of the final residual statement
// Each polz is 256 coefficients u64 (values in [0, 2^LOGQ) as produced by
// polz_reduce; the lift constant coefficient can be exactly PS_Q == 0);
// each witness coefficient is an int16 sign-extended to u64. The verifier
// replays lab_params_gen + ldr_reduce per round, so all other shape
// metadata (per-round lengths, residual witness shape) is recomputed
// deterministically and only cross-checked.
//
// Composite prove loop mirrors test_labrador.c
// (test_ldr_prove_reduce_composite): repeat lab_params_gen -> ldr_prove
// until no size improvement (or params generation fails), then open the
// final residual witness in the clear.

#include "nizk_labrador.hpp"

#include "drbg.hpp"

// The vendored labrador headers are C99: poly.h declares functions taking
// `double complex`, and polz.h / labrador_core.h declare functions with C99
// VLA parameters -- none of which is valid C++. We never call those
// functions, so neutralize just those declarations: `complex` expands to
// nothing (leaving plain `double r[N/2]` prototypes) and the VLA prototypes
// are renamed into harmless empty declarations by variadic macros. NOTE:
// poly.h includes <complex.h>, and libstdc++'s <complex.h> re-#undefs the
// `complex` macro on every inclusion -- that include resolves to the empty
// shim src/labrador_cxx_shim/complex.h for this translation unit (see
// CMakeLists.txt), which is what keeps the macro below alive.
#define complex
#define polzvec_fromint64vec(...) labrador_cxx_swallow_1()
#define lab_addcheck_amortization(...) labrador_cxx_swallow_2()
#define lab_addcheck_quadg(...) labrador_cxx_swallow_3()
#define lab_addcheck_ling(...) labrador_cxx_swallow_4()

extern "C" {
// The vendored labrador headers have no extern "C" guards of their own.
#include "comkey.h"
#include "labrador.h"
#include "labrador_core.h"
}

#undef complex
#undef polzvec_fromint64vec
#undef lab_addcheck_amortization
#undef lab_addcheck_quadg
#undef lab_addcheck_ling

// labrador's data.h leaks short macros (N=256, K=6, L=3, T=10, SLACK=2)
// which would clobber our P::K / P::D member accesses below. All labrador
// declarations were already preprocessed above, so undefining is safe.
#undef N
#undef K
#undef L
#undef T
#undef SLACK

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <vector>

namespace blnskv {
namespace {

constexpr size_t LAB_N = 256;   // labrador ring degree (data.h N) == P::D
constexpr uint64_t PSQ = PS_Q;  // labrador proof modulus (~2^38)

// Width bookkeeping value for uniform-mod-PS_Q polxvecs (same convention as
// polxvec_almostuniform / polz_topolx in the vendored code).
double uniform_width() { return std::ldexp(1.0, 2 * LOGQ) / 12.0; }

// --- little-endian wire IO ---------------------------------------------------

struct LeWriter {
  std::vector<uint8_t> &out;
  void u32(uint32_t v) {
    for (int i = 0; i < 4; i++)
      out.push_back(static_cast<uint8_t>(v >> (8 * i)));
  }
  void u64(uint64_t v) {
    for (int i = 0; i < 8; i++)
      out.push_back(static_cast<uint8_t>(v >> (8 * i)));
  }
};

struct LeReader {
  const uint8_t *p;
  size_t left;
  bool ok = true;
  uint64_t u64() {
    if (left < 8) {
      ok = false;
      return 0;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
      v |= static_cast<uint64_t>(p[i]) << (8 * i);
    p += 8;
    left -= 8;
    return v;
  }
  uint32_t u32() {
    if (left < 4) {
      ok = false;
      return 0;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
      v |= static_cast<uint32_t>(p[i]) << (8 * i);
    p += 4;
    left -= 4;
    return v;
  }
};

// --- RAII holder for labrador statement/witness ------------------------------
// The vendored types are C array-of-one structs with manual memory
// management (statement_free / witness_free). Non-copyable: the structs
// contain owning pointers.
struct Slot {
  statement st{};
  witness wt{};
  bool st_init = false;
  bool wt_init = false;
  // NOTE: when setting wt_init = true (right after witness_init), immediately
  // set wt->s[0] = nullptr so the destructor's witness_free stays safe even
  // if the s[0] allocation throws.
  Slot() = default;
  Slot(const Slot &) = delete;
  Slot &operator=(const Slot &) = delete;
  ~Slot() {
    if (st_init)
      statement_free(st);
    if (wt_init)
      witness_free(wt);
  }
};

// --- integer conversions ------------------------------------------------------

// Centered representative of one coefficient of our R_Q poly, in (-Q/2, Q/2].
template <typename P>
cpp_int centered_coeff(const Ring<P> &R, const typename Ring<P>::Poly &a,
                       size_t i) {
  cpp_int x = R.reconstruct(a, i);
  if (x > R.Q() / 2)
    x -= R.Q();
  return x;
}

// Reduce a (signed) integer mod PS_Q into [0, PS_Q).
int64_t to_mod_psq(const cpp_int &x) {
  cpp_int m = x % PSQ;
  if (m < 0)
    m += PSQ;
  return static_cast<int64_t>(m);
}

using IntPoly = std::array<cpp_int, LAB_N>;

template <typename P>
void centered_poly(const Ring<P> &R, const typename Ring<P>::Poly &a,
                   IntPoly &out) {
  for (size_t k = 0; k < LAB_N; k++)
    out[k] = centered_coeff(R, a, k);
}

// Exact integer negacyclic convolution in Z[X]/(X^256+1).
IntPoly convolve_negacyclic(const IntPoly &a, const IntPoly &b) {
  IntPoly r;
  for (size_t i = 0; i < LAB_N; i++) {
    for (size_t j = 0; j < LAB_N; j++) {
      size_t k = i + j;
      cpp_int t = a[i] * b[j];
      if (k >= LAB_N)
        r[k - LAB_N] -= t;
      else
        r[k] += t;
    }
  }
  return r;
}

void check_i16(const cpp_int &v) {
  if (v < -32768 || v > 32767)
    throw std::logic_error("LabradorNizk: witness coefficient out of range");
}

// --- statement / witness builders ----------------------------------------------

// Witness blocks: s (K) | e1 (K) | e3 (1) | k_t (K) | k_h (1); nn = 3K+2.
template <typename P>
void build_witness(const Ring<P> &R, const ResponseStatement<P> &stmt,
                   const ResponseWitness<P> &wit, Slot &slot) {
  constexpr size_t Kv = P::K;

  if (!R.is_ternary(wit.s) || !R.is_ternary(wit.e1) || !R.is_ternary(wit.e3))
    throw std::logic_error("LabradorNizk: non-ternary witness");

  const cpp_int p0 = cpp_int(R.prime(0)); // NMOD == 1, so Q == p0

  std::array<IntPoly, Kv> S, E1, KT;
  IntPoly E3, KH;
  for (size_t i = 0; i < Kv; i++) {
    centered_poly(R, wit.s[i], S[i]);
    centered_poly(R, wit.e1[i], E1[i]);
  }
  centered_poly(R, wit.e3, E3);

  // Quotient polynomial for h: k_h = (sum_j s_j (*) c_j - h + e3) / p0.
  {
    IntPoly conv, H;
    for (size_t j = 0; j < Kv; j++) {
      IntPoly cj;
      centered_poly(R, stmt.c[j], cj);
      IntPoly prod = convolve_negacyclic(S[j], cj);
      for (size_t k = 0; k < LAB_N; k++)
        conv[k] += prod[k];
    }
    centered_poly(R, stmt.h, H);
    for (size_t k = 0; k < LAB_N; k++) {
      cpp_int num = H[k] - conv[k] - E3[k]; // = h - s^T(*)c - e3 = p0 * k_h
      if (num % p0 != 0)
        throw std::logic_error("LabradorNizk: response witness does not match h");
      KH[k] = num / p0;
    }
  }

  // Quotient polynomials for t: k_t[j] = (sum_i s_i (*) B[i][j] - t_j + e1_j)/p0.
  for (size_t j = 0; j < Kv; j++) {
    IntPoly conv, tj;
    for (size_t i = 0; i < Kv; i++) {
      IntPoly bij;
      centered_poly(R, stmt.B[i][j], bij);
      IntPoly prod = convolve_negacyclic(S[i], bij);
      for (size_t k = 0; k < LAB_N; k++)
        conv[k] += prod[k];
    }
    centered_poly(R, stmt.t[j], tj);
    for (size_t k = 0; k < LAB_N; k++) {
      cpp_int num = tj[k] - conv[k] - E1[j][k]; // = t_j - s^T(*)B[:,j] - e1_j
      if (num % p0 != 0)
        throw std::logic_error("LabradorNizk: response witness does not match t");
      KT[j][k] = num / p0;
    }
  }

  for (size_t i = 0; i < Kv; i++)
    for (size_t k = 0; k < LAB_N; k++) {
      check_i16(S[i][k]);
      check_i16(E1[i][k]);
      check_i16(KT[i][k]);
    }
  for (size_t k = 0; k < LAB_N; k++) {
    check_i16(E3[k]);
    check_i16(KH[k]);
  }

  // Lay out into a labrador witness (coefficient-domain int16 polys).
  const size_t nn = 3 * Kv + 2;
  witness_init(slot.wt, 5, 5);
  slot.wt_init = true;
  slot.wt->s[0] = nullptr;
  slot.wt->n[0] = Kv;
  slot.wt->n[1] = Kv;
  slot.wt->n[2] = 1;
  slot.wt->n[3] = Kv;
  slot.wt->n[4] = 1;
  slot.wt->s[0] = static_cast<poly *>(std::aligned_alloc(64, nn * sizeof(poly)));
  if (!slot.wt->s[0])
    throw std::bad_alloc();
  for (size_t i = 1; i < 5; i++)
    slot.wt->s[i] = &slot.wt->s[i - 1][slot.wt->n[i - 1]];

  size_t pos = 0;
  auto fill = [&](const IntPoly &a) {
    for (size_t k = 0; k < LAB_N; k++)
      slot.wt->s[0][pos]->c[k] = static_cast<int16_t>(a[k]);
    pos++;
  };
  for (size_t i = 0; i < Kv; i++)
    fill(S[i]);
  for (size_t i = 0; i < Kv; i++)
    fill(E1[i]);
  fill(E3);
  for (size_t i = 0; i < Kv; i++)
    fill(KT[i]);
  fill(KH);
}

// Canonical public-statement bytes for the Fiat-Shamir binding hash.
template <typename P>
std::vector<std::vector<uint8_t>> serialize_public(const Ring<P> &R,
                                                   const ResponseStatement<P> &stmt) {
  std::vector<std::vector<uint8_t>> parts;
  for (size_t i = 0; i < P::K; i++)
    parts.push_back(R.serialize(stmt.B[i]));
  parts.push_back(R.serialize(stmt.t));
  parts.push_back(R.serialize(stmt.c));
  parts.push_back(R.serialize(stmt.h));
  return parts;
}

// Statement: K+1 rank-1 sparsecnsts (empty quadfunc), L2APPROX bounds.
template <typename P>
void build_statement(const Ring<P> &R, const ResponseStatement<P> &stmt,
                     Slot &slot) {
  constexpr size_t Kv = P::K;

  statement_init(slot.st, 5, 5);
  slot.st_init = true;
  auto st = slot.st; // decays to struct _statement*

  st->n[0] = Kv;
  st->n[1] = Kv;
  st->n[2] = 1;
  st->n[3] = Kv;
  st->n[4] = 1;
  // Ternary blocks: n*N. Quotient blocks: N*(K*N+1)^2 (|k coeff| <= K*N+1).
  const uint64_t qbound =
      static_cast<uint64_t>(LAB_N) * (Kv * LAB_N + 1) * (Kv * LAB_N + 1);
  st->normsq[0] = Kv * LAB_N;
  st->normsq[1] = Kv * LAB_N;
  st->normsq[2] = LAB_N;
  st->normsq[3] = qbound;
  st->normsq[4] = qbound;
  for (size_t i = 0; i < 5; i++)
    st->normty[i] = L2APPROX;

  rqcnstset_init(st->rqcnst, Kv + 1, 0);
  st->rqcnst->sparse_nchal = Kv + 1; // one challenge per rank-1 constraint
  st->rqcnst->com_nchal = 0;
  // zqcnst stays empty (zeroed by statement_init).

  const int64_t p0mod = to_mod_psq(cpp_int(R.prime(0)));

  // Public polys reduced mod PS_Q, per constraint.
  std::array<std::vector<int64_t>, Kv + 1> phi0; // Kv polys each (s-block part)
  std::array<std::vector<int64_t>, Kv + 1> bbuf; // target poly
  for (size_t j = 0; j <= Kv; j++) {
    phi0[j].resize(Kv * LAB_N);
    bbuf[j].resize(LAB_N);
    for (size_t i = 0; i < Kv; i++) {
      const typename Ring<P>::Poly &a = (j < Kv) ? stmt.B[i][j] : stmt.c[i];
      for (size_t k = 0; k < LAB_N; k++)
        phi0[j][i * LAB_N + k] = to_mod_psq(centered_coeff(R, a, k));
    }
    const typename Ring<P>::Poly &tgt = (j < Kv) ? stmt.t[j] : stmt.h;
    for (size_t k = 0; k < LAB_N; k++)
      bbuf[j][k] = to_mod_psq(centered_coeff(R, tgt, k));
  }

  for (size_t j = 0; j <= Kv; j++) {
    auto sp = st->rqcnst->sparse[j];
    sparsecnst_init(sp, 1); // rank 1, empty quadfunc, b allocated
    linfunc_init(sp->lin, 1, 3, 3);
    // part 0: s block (off 0, len K) with the public column c resp. B[:,j]
    sp->lin->off[0] = 0;
    polxvec_init(sp->lin->phi[0], Kv, 1);
    polxvec_fromint64vec(sp->lin->phi[0], phi0[j].data(), Kv, 1, uniform_width());
    // part 1: the e-block entry (identity poly)
    sp->lin->off[1] = (j < Kv) ? Kv + j : 2 * Kv;
    polxvec_init(sp->lin->phi[1], 1, 1);
    polxvec_monomial(sp->lin->phi[1], 0, 0, 1);
    // part 2: the k-block entry (scalar p0 poly)
    sp->lin->off[2] = (j < Kv) ? 2 * Kv + 1 + j : 3 * Kv + 1;
    polxvec_init(sp->lin->phi[2], 1, 1);
    polxvec_monomial(sp->lin->phi[2], 0, 0, p0mod);
    // b = target poly mod PS_Q
    polxvec_fromint64vec(sp->b, bbuf[j].data(), 1, 1, uniform_width());
  }

  // Bind the Fiat-Shamir transcript to the public statement.
  auto h16 = xof("BLNSKV-LAB1-STMT-v0", serialize_public(R, stmt), 16);
  std::memcpy(st->h, h16.data(), 16);
}

// --- serialization helpers -----------------------------------------------------

void write_polzvec(LeWriter &w, const polz *z, size_t len) {
  for (size_t i = 0; i < len; i++) {
    for (size_t k = 0; k < LAB_N; k++) {
      zz c;
      polz_getcoeff(c, z[i], static_cast<int>(k));
      w.u64(static_cast<uint64_t>(int64_fromzz(c)));
    }
  }
}

bool read_polzvec(LeReader &r, polz *z, size_t len) {
  // polz_reduce outputs coefficients in [0, 2^LOGQ); in particular the lifts'
  // constant coefficient can be exactly PS_Q (== 0 mod PS_Q).
  for (size_t i = 0; i < len; i++) {
    for (size_t k = 0; k < LAB_N; k++) {
      uint64_t v = r.u64();
      if (!r.ok || v >= (1ULL << LOGQ))
        return false;
      polz_setcoeff_fromint64(z[i], static_cast<int64_t>(v), static_cast<int>(k));
    }
  }
  return true;
}

void write_round(LeWriter &w, const lab_proof pi, const lab_params pp) {
  const size_t kappa1 = pp->kappa[1];
  w.u32(static_cast<uint32_t>(kappa1));
  write_polzvec(w, pi->m[0], kappa1);
  write_polzvec(w, pi->m[2], LIFTS);
  write_polzvec(w, pi->m[3], kappa1);
  for (int k = 0; k < 256; k++)
    w.u32(static_cast<uint32_t>(pi->p[k]));
}

void write_witness(LeWriter &w, const witness wt) {
  size_t nn = 0;
  for (size_t i = 0; i < wt->r; i++)
    nn += wt->n[i];
  for (size_t j = 0; j < nn; j++)
    for (size_t k = 0; k < LAB_N; k++)
      w.u64(static_cast<uint64_t>(
          static_cast<int64_t>(wt->s[0][j]->c[k])));
}

} // namespace

// --- prove ----------------------------------------------------------------------

template <typename P>
Proof LabradorNizk<P>::prove_response(const Ring<P> &R,
                                      const ResponseStatement<P> &stmt,
                                      const ResponseWitness<P> &wit) {
  constexpr size_t Kv = P::K;
  const size_t nn0 = 3 * Kv + 2;

  auto cur = std::make_unique<Slot>();
  build_witness(R, stmt, wit, *cur); // throws if the relation does not hold
  build_statement(R, stmt, *cur);

  comkey_init(nn0);
  if (!::verify(cur->st, cur->wt)) // sanity: translation is correct
    throw std::logic_error("LabradorNizk: statement translation failed self-check");

  Proof proof;
  proof.bytes = {'L', 'A', 'B', '1'};
  LeWriter w{proof.bytes};
  const size_t nrounds_off = proof.bytes.size();
  w.u32(0); // patched after the loop

  size_t iwtbits = 2 * nn0 * LAB_N; // ~2 bits per coefficient (test convention)
  uint32_t nrounds = 0;
  size_t round = 0;
  for (;;) {
    round++;
    lab_params pp;
    size_t pibits = 0, owtbits = 0;
    int ret = lab_params_gen(pp, &pibits, &owtbits, cur->st, 0, 0, 0, 1, 1,
                             JL_L2_SLACK);
    bool improve =
        (ret == 0) && ((double)(pibits + owtbits) < 0.9 * (double)iwtbits);
    if (ret || (!improve && round > 1)) {
      if (!ret)
        lab_params_free(pp);
      break;
    }

    auto nxt = std::make_unique<Slot>();
    lab_proof pi;
    ldr_prove(pi, nxt->st, nxt->wt, cur->st, cur->wt, pp);
    nxt->st_init = true;
    nxt->wt_init = true;

    write_round(w, pi, pp);
    lab_proof_free(pi);
    lab_params_free(pp);

    iwtbits = owtbits;
    cur = std::move(nxt);
    nrounds++;
    if (nrounds > 64)
      throw std::logic_error("LabradorNizk: composite loop did not terminate");
  }

  for (int i = 0; i < 4; i++)
    proof.bytes[nrounds_off + i] = static_cast<uint8_t>(nrounds >> (8 * i));

  // Open the final residual witness in the clear.
  write_witness(w, cur->wt);
  return proof;
}

// --- verify ---------------------------------------------------------------------

template <typename P>
bool LabradorNizk<P>::verify_response(const Ring<P> &R,
                                      const ResponseStatement<P> &stmt,
                                      const Proof &proof) {
  constexpr size_t Kv = P::K;
  const size_t nn0 = 3 * Kv + 2;

  if (proof.bytes.size() < 8 ||
      std::memcmp(proof.bytes.data(), "LAB1", 4) != 0)
    return false;
  LeReader r{proof.bytes.data() + 4, proof.bytes.size() - 4};
  uint32_t nrounds = r.u32();
  if (!r.ok || nrounds > 64)
    return false;

  auto cur = std::make_unique<Slot>();
  build_statement(R, stmt, *cur);

  comkey_init(nn0);
  for (uint32_t rd = 0; rd < nrounds; rd++) {
    lab_params pp;
    size_t pibits = 0, owtbits = 0;
    if (lab_params_gen(pp, &pibits, &owtbits, cur->st, 0, 0, 0, 1, 1,
                       JL_L2_SLACK))
      return false;

    uint32_t kappa1 = r.u32();
    if (!r.ok || kappa1 != pp->kappa[1]) {
      lab_params_free(pp);
      return false;
    }

    lab_proof pi;
    lab_proof_init(pi, pp);
    bool ok = read_polzvec(r, pi->m[0], kappa1) &&
              read_polzvec(r, pi->m[2], LIFTS) &&
              read_polzvec(r, pi->m[3], kappa1);
    for (int k = 0; ok && k < 256; k++)
      pi->p[k] = static_cast<int32_t>(r.u32());
    ok = ok && r.ok;

    auto nxt = std::make_unique<Slot>();
    int ret = -1;
    if (ok)
      ret = ldr_reduce(nxt->st, cur->st, pi, pp);
    lab_proof_free(pi);
    lab_params_free(pp);
    if (!ok || ret != 0)
      return false; // note: ldr_reduce frees nxt->st itself on failure
    nxt->st_init = true;
    cur = std::move(nxt);
  }

  // Decode the final residual witness; its shape is the final statement's.
  Slot fin;
  witness_init(fin.wt, cur->st->r, cur->st->r);
  fin.wt_init = true;
  fin.wt->s[0] = nullptr;
  size_t nn = 0;
  for (size_t i = 0; i < cur->st->r; i++) {
    fin.wt->n[i] = cur->st->n[i];
    nn += fin.wt->n[i];
  }
  fin.wt->s[0] = static_cast<poly *>(std::aligned_alloc(64, nn * sizeof(poly)));
  if (!fin.wt->s[0])
    throw std::bad_alloc();
  for (size_t i = 1; i < fin.wt->r; i++)
    fin.wt->s[i] = &fin.wt->s[i - 1][fin.wt->n[i - 1]];

  for (size_t j = 0; j < nn; j++) {
    for (size_t k = 0; k < LAB_N; k++) {
      int64_t v = static_cast<int64_t>(r.u64());
      if (!r.ok || v < -32768 || v > 32767)
        return false;
      fin.wt->s[0][j]->c[k] = static_cast<int16_t>(v);
    }
  }
  if (r.left != 0)
    return false;

  return ::verify(cur->st, fin.wt);
}

template class LabradorNizk<ToyParams>;

} // namespace blnskv
