#pragma once
//
// Single-key cut-and-choose keyed-verification blind signature
// (docs/single-key-cut-and-choose-kvbs.tex). Replaces BLNS23's expensive
// round-1 well-formedness proof with kappa parallel cut-and-choose lanes
// under ONE signer key: the user commits to 2*kappa branch vectors by summing
// them into a single aggregate plus a per-branch leaf-hash list; the
// challenge is hashed from aggregate + full leaf list (commit before
// challenge); the signer re-expands the kappa opened seeds, peels them off
// the aggregate, and signs the remaining sum with its one key.
//
// Protocol flow:
//   user:   per lane i, branch b: z[i][b] seed;
//           (r,e2,delta) = G(sid,i,b,z);  rho = H_rho(sid,i,b,r,e2);
//           mu = Com(M; phi0 + delta);    u = H_R(i, mu, rho);
//           c = B*r + e2 + u;             leaf = H_leaf(sid,i,b,c)
//           c_agg = sum c; chi = H_chal(issuer,pk,sid,c_agg,mu_0,leaves);
//           msg1 = (sid, c_agg, {z[i][chi_i]}, {leaf[i][1-chi_i]}, mu_0, chi)
//   signer: re-expand opened seeds, reassemble leaf list, recompute chi;
//           C_sel = c_agg - sum c[i][chi_i];
//           e = H_De(K, sid, c_agg);  h = s^T*C_sel + e;  prove R_resp
//   user:   v = round(h - t^T * sum r_i*)         (selected branches)
//   mint:   verify: v == round(s^T * sum_i H_R(i, mu_i*, rho_i*))
//
// Message-binding strengthening (tex Section 4.6 / "common-message binding",
// in scope here): every lane is bound to one hidden message M through a
// publicly rerandomizable commitment
//      Com(M; phi) = U(M) + B_c * phi  in R_q^n,
// where U(M) is a hash-to-ring embedding of M, B_c is derived from a public
// seed, and phi is short (ternary). The user commits mu_0 = Com(M; phi0);
// branch (i,b) carries the rerandomization mu_{i,b} = mu_0 + B_c*delta_{i,b}
// with delta seed-derived; mu_0 enters H_chal; the signer re-checks opened
// branches against mu_0; the lane hash uses mu in place of the paper's m;
// the credential carries M + (phi0, {delta_i*}, {rho_i*}) so the verifier
// rebuilds every mu_i*. This Com instantiation is OUR choice (the paper
// leaves Com unpinned): hiding rests on the B_c*phi mask (module-LWE-shaped),
// binding on inhomogeneous module-SIS (an opening to M' != M needs short
// phi, phi' with U(M) - U(M') = B_c*(phi' - phi)).
//
// Deliberate choices / deviations from the tex:
//  * The paper leaves the branch norm bounds (beta) unpinned; we use TERNARY
//    r, e2, delta, s, e1, e everywhere, matching the base scheme (blnskv.hpp).
//  * msg1 carries an explicit chi hint (KAPPA bits) that the tex's msg1 does
//    not have. Without it the signer cannot recover which position each
//    opened seed belongs to: G and H_leaf take b as input, so reassembly
//    needs chi, while chi = H_chal(...) needs the reassembled leaf list --
//    an infeasible random-oracle fixpoint search. The hint is UNTRUSTED: the
//    signer reassembles the leaf list at the claimed positions, recomputes
//    H_chal, and rejects on mismatch, so the commit-before-challenge
//    argument of the paper is unchanged.
//  * Hash inputs encode ring elements by their raw RNS coefficient words
//    (little-endian, per (coeff, prime) slot). This is canonical for a fixed
//    parameter set and versioned label; wire formats below still use the
//    portable CRT serialization of ring.hpp.
//  * The lane hash H_R ("CCKVBS-HR-v0") takes (i, mu, rho) and MUST NOT
//    include sid (tex lines 478-480): sid is bound into branch formation and
//    the challenge only, so credentials verify without the issuance session.
//
// Domain labels (versioned, SHAKE256): CCKVBS-G-v0 (branch expansion),
// CCKVBS-RHO-v0, CCKVBS-HR-v0 (lane hash), CCKVBS-LEAF-v0, CCKVBS-CHAL-v0,
// CCKVBS-DE-v0 (deterministic response error), CCKVBS-COM-v0 (message
// commitment: matrix seed + embedding), CCKVBS-EB-v0 (Expand_B),
// CCKVBS-FINAL-v0 (application payload), CCKVBS-NULL-v0 (scoped nullifier).
//
// OPERATIONAL CONVENTIONS (caller obligations, load-bearing per the paper):
//  (SID) Session identifiers must never repeat within a key epoch --
//        including under concurrency, rollback and replication. Freshness
//        storage is the CALLER's job; this class keeps no state.
//  (KV)  Key validation: B is seed-derived, B = Expand_B(seed_B). Call
//        valid_public_key(pk) before committing to an untrusted pk.
//  (ABORT) Blindness needs both-or-neither delivery of concurrent sessions;
//        orchestrating that is the caller's job.
//  The signer MUST answer the same msg1 deterministically (e is a PRF of
//  (K, sid, c_agg)); respond-once-per-sid enforcement is again the caller's.
//
// SECURITY WARNING: research prototype. The paper states the construction
// "must not be deployed as a secure credential system": its security rests on
// the isolated ssHMLWE/SDI assumptions, not on a standard reduction. On top
// of that, ToyParams is NOT secure, CutAndChooseParams is a paper-flavoured
// shape with a wider Q (186 vs 152 bits) and unvalidated parameters, and the
// MockNizk used by default is NOT zero-knowledge/sound -- it exists to
// exercise the arithmetic. Do not use for anything real.

#include "drbg.hpp"
#include "nizk.hpp"
#include "ring.hpp"
#include "sampling.hpp"

#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace blnskv::cc {

template <typename P, size_t KAPPA> class Scheme {
public:
  using Poly = typename Ring<P>::Poly;
  using Vec = typename Ring<P>::Vec;
  using Mat = typename Ring<P>::Mat;

  static constexpr size_t D = P::D;
  static constexpr size_t K = P::K;
  static constexpr size_t NMOD = P::NMOD;
  static constexpr size_t Kappa = KAPPA;

  static constexpr size_t ISSUER_BYTES = 32;
  static constexpr size_t EPOCH_BYTES = 8;
  static constexpr size_t NONCE_BYTES = 16;
  static constexpr size_t SID_BYTES =
      ISSUER_BYTES + EPOCH_BYTES + 2 * NONCE_BYTES;
  static constexpr size_t SEED_BYTES = 32;
  static constexpr size_t RHO_BYTES = 32;
  static constexpr size_t LEAF_BYTES = 32;

  using SeedArr = std::array<uint8_t, SEED_BYTES>;
  using RhoArr = std::array<uint8_t, RHO_BYTES>;
  using LeafArr = std::array<uint8_t, LEAF_BYTES>;
  using IssuerArr = std::array<uint8_t, ISSUER_BYTES>;
  // Flattened branch table: leaves[2*i + b] is the leaf of lane i, branch b.
  using LeafList = std::array<LeafArr, 2 * KAPPA>;

  struct SessionId {
    IssuerArr issuer{};
    std::array<uint8_t, EPOCH_BYTES> key_epoch{};
    std::array<uint8_t, NONCE_BYTES> user_nonce{};
    std::array<uint8_t, NONCE_BYTES> signer_nonce{};

    // Canonical concatenation, mixed into every session-bound hash.
    std::array<uint8_t, SID_BYTES> to_bytes() const {
      std::array<uint8_t, SID_BYTES> out;
      auto it = out.begin();
      it = std::copy(issuer.begin(), issuer.end(), it);
      it = std::copy(key_epoch.begin(), key_epoch.end(), it);
      it = std::copy(user_nonce.begin(), user_nonce.end(), it);
      std::copy(signer_nonce.begin(), signer_nonce.end(), it);
      return out;
    }
    bool operator==(const SessionId &) const = default;
  };

  struct PublicKey {
    SeedArr seed_B{}; // B = Expand_B(seed_B); check with valid_public_key()
    Mat B{};
    Vec t{};
  };
  struct SigningKey {
    Vec s{}, e1{};
    Drbg::Seed de_key; // K for the deterministic response error
    PublicKey pk;
  };

  // Internal: the expansion products of one branch seed (G).
  struct Branch {
    Vec r, e2, delta; // all ternary
    RhoArr rho;
  };

  struct UserState {
    SessionId sid;
    std::vector<uint8_t> M;
    Vec phi0{};
    Vec r_sum{}; // sum of the selected blinding vectors r_i*
    Vec c_sel{}; // sum of the selected branch vectors (the peeled sum)
    std::bitset<KAPPA> chi;
    // Selected seeds: private to the user, NEVER presented (they would reveal
    // the blinding vectors and link the credential to its issuance).
    std::array<SeedArr, KAPPA> z_sel;
  };

  struct Message1 {
    SessionId sid;
    Vec c_agg{};
    std::array<SeedArr, KAPPA> opened_seeds;     // z[i][chi_i]
    std::array<LeafArr, KAPPA> unopened_leaves;  // leaf[i][1-chi_i]
    Vec mu_0{};
    std::bitset<KAPPA> chi; // untrusted position hint; re-verified via H_chal
  };

  struct Response {
    Poly h{};
    Proof pi;
  };

  struct Credential {
    std::vector<uint8_t> M;
    Vec phi0{};
    // Heap-backed: KAPPA vectors are far too big for inline storage at the
    // paper's kappa=512. Always exactly KAPPA entries.
    std::vector<Vec> delta; // selected rerandomization deltas (ternary)
    std::array<RhoArr, KAPPA> rho;
    std::vector<uint64_t> v; // D values in [0, ROUND_P)
  };

  Scheme() {
    if (R.coeff_bytes() != COEFF_BYTES)
      throw std::logic_error("cckvbs: unexpected coeff_bytes for NMOD");
  }

  // --- key generation --------------------------------------------------------
  // B = Expand_B(seed_B), so a public key is self-certifying under (KV):
  // valid_public_key() re-derives B and compares.
  //
  // keygen_into writes into caller-provided storage: at large parameter sets
  // a SigningKey holds ~13MB of matrix and must live on the heap, so prefer
  //     auto sk = std::make_unique<Scheme::SigningKey>();
  //     scheme.keygen_into(*sk);
  // keygen() by value is kept (blnskv::Scheme parity) for small parameters.
  void keygen_into(SigningKey &sk) {
    auto drbg = Drbg::from_os();
    auto seed = drbg.bytes(SEED_BYTES);
    std::copy_n(seed.begin(), SEED_BYTES, sk.pk.seed_B.begin());
    expand_b(sk.pk.seed_B, sk.pk.B);
    sk.s = sample_ternary_vec<P>(R, drbg);
    sk.e1 = sample_ternary_vec<P>(R, drbg);
    sk.pk.t = R.add(R.vecmat_T(sk.s, sk.pk.B), sk.e1);
    sk.de_key = drbg.bytes(32);
  }

  SigningKey keygen() {
    SigningKey sk;
    keygen_into(sk);
    return sk;
  }

  static void expand_b(const SeedArr &seed_B, Mat &out) {
    Ring<P> R;
    Drbg d(xof("CCKVBS-EB-v0", {to_vec(seed_B)}, 64));
    sample_uniform_mat_into<P>(R, d, out);
  }

  static bool valid_public_key(const PublicKey &pk) {
    Ring<P> R;
    auto B = std::make_unique<Mat>(); // heap: too big for the stack at large P
    expand_b(pk.seed_B, *B);
    for (size_t i = 0; i < K; i++)
      for (size_t j = 0; j < K; j++)
        if (!R.equal((*B)[i][j], pk.B[i][j]))
          return false;
    return true;
  }

  // --- round 1 (user) ---------------------------------------------------------
  std::pair<UserState, Message1> user_commit(const PublicKey &pk,
                                             const SessionId &sid,
                                             std::span<const uint8_t> M,
                                             Drbg &drbg) {
    UserState st;
    st.sid = sid;
    st.M.assign(M.begin(), M.end());
    st.phi0 = sample_ternary_vec<P>(R, drbg);
    Vec mu_0 = com(st.M, st.phi0);

    std::array<std::array<SeedArr, 2>, KAPPA> z;
    for (auto &lane : z)
      for (auto &seed : lane) {
        auto b = drbg.bytes(SEED_BYTES);
        std::copy_n(b.begin(), SEED_BYTES, seed.begin());
      }

    // Pass 1: build both branches of every lane, aggregate, leaf list.
    LeafList leaves;
    Vec c_agg = zero_vec();
    for (size_t i = 0; i < KAPPA; i++)
      for (uint8_t b = 0; b < 2; b++) {
        Branch br = expand_branch(sid, i, b, z[i][b]);
        Vec c = branch_vec(pk, i, br, mu_0);
        leaves[2 * i + b] = hash_leaf(sid, i, b, c);
        c_agg = R.add(c_agg, c);
      }

    st.chi = challenge(sid.issuer, pk, sid, c_agg, mu_0, leaves);

    // Pass 2: re-expand the selected branches; accumulate what finalize needs.
    st.r_sum = zero_vec();
    st.c_sel = zero_vec();
    for (size_t i = 0; i < KAPPA; i++) {
      uint8_t bs = st.chi[i] ? 0 : 1;
      st.z_sel[i] = z[i][bs];
      Branch br = expand_branch(sid, i, bs, z[i][bs]);
      st.r_sum = R.add(st.r_sum, br.r);
      st.c_sel = R.add(st.c_sel, branch_vec(pk, i, br, mu_0));
    }

    Message1 m1;
    m1.sid = sid;
    m1.c_agg = c_agg;
    m1.mu_0 = mu_0;
    m1.chi = st.chi;
    for (size_t i = 0; i < KAPPA; i++) {
      m1.opened_seeds[i] = z[i][st.chi[i] ? 1 : 0];
      m1.unopened_leaves[i] = leaves[2 * i + (st.chi[i] ? 0 : 1)];
    }
    return {st, m1};
  }

  // --- round 2 (signer) -------------------------------------------------------
  // Re-expands every opened seed and re-checks everything. Any failure returns
  // nullopt BEFORE any secret-dependent value is computed.
  std::optional<Response> signer_respond(const SigningKey &sk,
                                         const Message1 &m1, Nizk<P> &nizk) {
    LeafList leaves;
    Vec c_open_sum = zero_vec();
    for (size_t i = 0; i < KAPPA; i++) {
      uint8_t b = m1.chi[i] ? 1 : 0;
      Branch br = expand_branch(m1.sid, i, b, m1.opened_seeds[i]);
      // Formation checks: labels, sid and lane index are enforced by the
      // domain-separated expansions; bounds are checked explicitly.
      if (!fast_is_ternary(br.r) || !fast_is_ternary(br.e2) ||
          !fast_is_ternary(br.delta))
        return std::nullopt;
      // Rerandomization consistency with mu_0 is structural: mu is rebuilt
      // from the received mu_0 and the seed-derived delta, never transmitted.
      Vec c = branch_vec(sk.pk, i, br, m1.mu_0);
      leaves[2 * i + b] = hash_leaf(m1.sid, i, b, c);
      leaves[2 * i + (1 - b)] = m1.unopened_leaves[i];
      c_open_sum = R.add(c_open_sum, c);
    }
    // The claimed challenge must match the recomputed one over the received
    // aggregate, mu_0 and the reassembled full leaf list.
    if (challenge(m1.sid.issuer, sk.pk, m1.sid, m1.c_agg, m1.mu_0, leaves) !=
        m1.chi)
      return std::nullopt;

    // Peel the opened branches off the aggregate.
    Vec c_sel = vec_sub(m1.c_agg, c_open_sum);

    // Deterministic per (K, sid, c_agg): answering the same input twice with
    // independent noise would leak s.
    Poly e = response_error(sk.de_key, m1.sid, m1.c_agg);
    Response resp;
    resp.h = R.add(R.inner(sk.s, c_sel), e);
    // Heap-built field by field: aggregate-initializing the statement would
    // copy the matrix (~13MB at the paper shape) onto the stack.
    auto stmt = std::make_unique<ResponseStatement<P>>();
    stmt->B = sk.pk.B;
    stmt->t = sk.pk.t;
    stmt->c = c_sel;
    stmt->h = resp.h;
    resp.pi = nizk.prove_response(R, *stmt, ResponseWitness<P>{sk.s, sk.e1, e});
    return resp;
  }

  // --- finalize (user) --------------------------------------------------------
  std::optional<Credential> user_finalize(const PublicKey &pk,
                                          const UserState &st,
                                          const Response &resp, Nizk<P> &nizk) {
    // Heap-built field by field: see signer_respond.
    auto stmt = std::make_unique<ResponseStatement<P>>();
    stmt->B = pk.B;
    stmt->t = pk.t;
    stmt->c = st.c_sel;
    stmt->h = resp.h;
    if (!nizk.verify_response(R, *stmt, resp.pi))
      return std::nullopt;
    Credential cred;
    cred.M = st.M;
    cred.phi0 = st.phi0;
    cred.delta.resize(KAPPA);
    for (size_t i = 0; i < KAPPA; i++) {
      uint8_t bs = st.chi[i] ? 0 : 1;
      Branch br = expand_branch(st.sid, i, bs, st.z_sel[i]);
      cred.delta[i] = std::move(br.delta);
      cred.rho[i] = br.rho;
    }
    // v = round(h - t^T * sum r_i*)
    cred.v = R.round_poly(R.sub(resp.h, R.inner(pk.t, st.r_sum)));
    return cred;
  }

  // --- keyed verification (mint only) ------------------------------------------
  // v == round(s^T * sum_i H_R(i, mu_i*, rho_i*)) with mu_i* rebuilt from the
  // presented message and selected randomness. Exact match, no sid involved.
  bool verify(const SigningKey &sk, const Credential &cred) const {
    if (cred.v.size() != D || cred.delta.size() != KAPPA)
      return false;
    if (!fast_is_ternary(cred.phi0))
      return false;
    for (const auto &d : cred.delta)
      if (!fast_is_ternary(d))
        return false;
    Vec mu_0 = com(cred.M, cred.phi0);
    Vec u_sum = zero_vec();
    for (size_t i = 0; i < KAPPA; i++) {
      Vec mu = R.add(mu_0, R.matvec(com_matrix(), cred.delta[i]));
      u_sum = R.add(u_sum, hash_lane(i, mu, cred.rho[i]));
    }
    return R.round_poly(R.inner(sk.s, u_sum)) == cred.v;
  }

  // --- application payload / nullifier -----------------------------------------
  // M_payload = H_final(issuer, type, credential lane material).
  static IssuerArr finalize_payload(const IssuerArr &issuer,
                                    std::span<const uint8_t> type,
                                    const Credential &cred) {
    std::vector<uint8_t> buf;
    append_len_prefixed(buf, type);
    append_len_prefixed(buf, cred.M);
    for (const auto &rho : cred.rho)
      buf.insert(buf.end(), rho.begin(), rho.end());
    for (const auto &d : cred.delta)
      append_packed(buf, pack_ternary_vec(d));
    auto out = xof("CCKVBS-FINAL-v0", {to_vec(issuer), buf}, 32);
    IssuerArr res;
    std::copy_n(out.begin(), 32, res.begin());
    return res;
  }

  // Scoped nullifier H(M, scope): the unique public value whose reuse flags a
  // double presentation. M should carry a per-issuance serial; see the tex's
  // "M as nullifier" paragraph for the linkage caveat.
  static IssuerArr nullifier(const Credential &cred,
                             std::span<const uint8_t> scope) {
    std::vector<uint8_t> buf;
    append_len_prefixed(buf, scope);
    append_len_prefixed(buf, cred.M);
    auto out = xof("CCKVBS-NULL-v0", {buf}, 32);
    IssuerArr res;
    std::copy_n(out.begin(), 32, res.begin());
    return res;
  }

  // --- domain-separated helpers (SHAKE256; see header for labels) --------------
  static Branch expand_branch(const SessionId &sid, uint32_t i, uint8_t b,
                              const SeedArr &z) {
    Ring<P> R;
    Drbg d(xof("CCKVBS-G-v0",
               {to_vec(sid.to_bytes()), u32_bytes(i), std::vector<uint8_t>{b},
                to_vec(z)},
               64));
    Branch br;
    br.r = sample_ternary_vec<P>(R, d);
    br.e2 = sample_ternary_vec<P>(R, d);
    br.delta = sample_ternary_vec<P>(R, d);
    br.rho = hash_rho_cc(sid, i, b, br.r, br.e2);
    return br;
  }

  static RhoArr hash_rho_cc(const SessionId &sid, uint32_t i, uint8_t b,
                            const Vec &r, const Vec &e2) {
    auto out = xof("CCKVBS-RHO-v0",
                   {to_vec(sid.to_bytes()), u32_bytes(i),
                    std::vector<uint8_t>{b}, fast_bytes(r), fast_bytes(e2)},
                   RHO_BYTES);
    RhoArr rho;
    std::copy_n(out.begin(), RHO_BYTES, rho.begin());
    return rho;
  }

  // H_R: the credential lane hash. MUST NOT include sid (see header).
  static Vec hash_lane(uint32_t i, const Vec &mu, const RhoArr &rho) {
    Ring<P> R;
    Drbg d(xof("CCKVBS-HR-v0",
               {u32_bytes(i), fast_bytes(mu), to_vec(rho)}, 64));
    return sample_uniform_vec<P>(R, d);
  }

  static LeafArr hash_leaf(const SessionId &sid, uint32_t i, uint8_t b,
                           const Vec &c) {
    auto out = xof("CCKVBS-LEAF-v0",
                   {to_vec(sid.to_bytes()), u32_bytes(i),
                    std::vector<uint8_t>{b}, fast_bytes(c)},
                   LEAF_BYTES);
    LeafArr leaf;
    std::copy_n(out.begin(), LEAF_BYTES, leaf.begin());
    return leaf;
  }

  // H_chal: covers the aggregate AND the full leaf list AND mu_0, so the
  // branch table is fixed before the challenge exists. pk enters as
  // (seed_B, t); seed_B pins B since B = Expand_B(seed_B).
  static std::bitset<KAPPA> challenge(const IssuerArr &issuer,
                                      const PublicKey &pk, const SessionId &sid,
                                      const Vec &c_agg, const Vec &mu_0,
                                      const LeafList &leaves) {
    std::vector<uint8_t> leaf_bytes(2 * KAPPA * LEAF_BYTES);
    for (size_t j = 0; j < 2 * KAPPA; j++)
      std::copy_n(leaves[j].begin(), LEAF_BYTES,
                  leaf_bytes.begin() + j * LEAF_BYTES);
    auto bits = xof("CCKVBS-CHAL-v0",
                    {to_vec(issuer), to_vec(pk.seed_B), fast_bytes(pk.t),
                     to_vec(sid.to_bytes()), fast_bytes(c_agg),
                     fast_bytes(mu_0), leaf_bytes},
                    (KAPPA + 7) / 8);
    std::bitset<KAPPA> chi;
    for (size_t i = 0; i < KAPPA; i++)
      chi[i] = (bits[i / 8] >> (i % 8)) & 1;
    return chi;
  }

  // Deterministic response error e = H_De(K, sid, c_agg), ternary, mirroring
  // the "BLNSKV-E3-v0" pattern of the base scheme.
  static Poly response_error(const Drbg::Seed &key, const SessionId &sid,
                             const Vec &c_agg) {
    Ring<P> R;
    Drbg d(xof("CCKVBS-DE-v0",
               {key, to_vec(sid.to_bytes()), fast_bytes(c_agg)}, 64));
    return sample_ternary<P>(R, d);
  }

  // Com(M; phi) = U(M) + B_c * phi. Our instantiation choice; see header.
  static Vec com(std::span<const uint8_t> M, const Vec &phi) {
    Ring<P> R;
    return R.add(com_embed(M), R.matvec(com_matrix(), phi));
  }

  // --- Message1 wire format ------------------------------------------------------
  // sid || c_agg || opened_seeds || unopened_leaves || mu_0 || chi (LSB-first)
  static constexpr size_t Q_BITS = 62 * NMOD; // NFLlib primes are 62-bit
  static constexpr size_t COEFF_BYTES = (Q_BITS + 7) / 8;
  static constexpr size_t VEC_BYTES = K * D * COEFF_BYTES;
  static constexpr size_t CHI_BYTES = (KAPPA + 7) / 8;
  static constexpr size_t MSG1_BYTES = SID_BYTES + 2 * VEC_BYTES +
                                       KAPPA * SEED_BYTES +
                                       KAPPA * LEAF_BYTES + CHI_BYTES;

  std::vector<uint8_t> serialize_msg1(const Message1 &m1) const {
    std::vector<uint8_t> out;
    out.reserve(MSG1_BYTES);
    auto sidb = m1.sid.to_bytes();
    out.insert(out.end(), sidb.begin(), sidb.end());
    append_packed(out, R.serialize(m1.c_agg));
    for (const auto &s : m1.opened_seeds)
      out.insert(out.end(), s.begin(), s.end());
    for (const auto &l : m1.unopened_leaves)
      out.insert(out.end(), l.begin(), l.end());
    append_packed(out, R.serialize(m1.mu_0));
    for (size_t j = 0; j < CHI_BYTES; j++) {
      uint8_t byte = 0;
      for (size_t k = 0; k < 8 && 8 * j + k < KAPPA; k++)
        byte |= static_cast<uint8_t>(m1.chi[8 * j + k]) << k;
      out.push_back(byte);
    }
    return out;
  }

  std::optional<Message1>
  deserialize_msg1(const std::vector<uint8_t> &bytes) const {
    if (bytes.size() != MSG1_BYTES)
      return std::nullopt;
    const uint8_t *in = bytes.data();
    Message1 m1;
    auto take = [&](uint8_t *dst, size_t n) {
      std::memcpy(dst, in, n);
      in += n;
    };
    take(m1.sid.issuer.data(), ISSUER_BYTES);
    take(m1.sid.key_epoch.data(), EPOCH_BYTES);
    take(m1.sid.user_nonce.data(), NONCE_BYTES);
    take(m1.sid.signer_nonce.data(), NONCE_BYTES);
    m1.c_agg = R.deserialize_vec(in);
    for (auto &s : m1.opened_seeds)
      take(s.data(), SEED_BYTES);
    for (auto &l : m1.unopened_leaves)
      take(l.data(), LEAF_BYTES);
    m1.mu_0 = R.deserialize_vec(in);
    for (size_t i = 0; i < KAPPA; i++)
      m1.chi[i] = (in[i / 8] >> (i % 8)) & 1;
    return m1;
  }

  // --- Credential wire format ----------------------------------------------------
  // u32 mlen || M || rho[KAPPA] || ternary-packed phi0 || packed delta[KAPPA]
  // || bit-packed v. Ternary packing: 2 bits per coefficient, symbols
  // 0/1/2 = 0/+1/-1; symbol 3 is rejected on parse.
  static constexpr size_t round_bits() {
    size_t b = 0;
    for (uint64_t p = P::ROUND_P; p > 1; p >>= 1)
      b++;
    return b;
  }
  static constexpr size_t TPACK_BYTES = (K * D * 2 + 7) / 8;
  static constexpr size_t VPACK_BYTES = (D * round_bits() + 7) / 8;
  static constexpr size_t CRED_FIXED_BYTES = 4 + KAPPA * RHO_BYTES +
                                             (KAPPA + 1) * TPACK_BYTES +
                                             VPACK_BYTES;
  static constexpr size_t cred_bytes(size_t mlen) {
    return CRED_FIXED_BYTES + mlen;
  }

  std::vector<uint8_t> serialize_credential(const Credential &cred) const {
    std::vector<uint8_t> out;
    out.reserve(cred_bytes(cred.M.size()));
    for (int j = 0; j < 4; j++)
      out.push_back(static_cast<uint8_t>(cred.M.size() >> (8 * j)));
    out.insert(out.end(), cred.M.begin(), cred.M.end());
    for (const auto &rho : cred.rho)
      out.insert(out.end(), rho.begin(), rho.end());
    append_packed(out, pack_ternary_vec(cred.phi0));
    for (const auto &d : cred.delta)
      append_packed(out, pack_ternary_vec(d));
    // v bit-packed LSB-first (same packing as blnskv::Scheme::serialize_sig)
    uint8_t acc = 0;
    size_t acc_bits = 0;
    for (uint64_t x : cred.v) {
      acc |= static_cast<uint8_t>(x) << acc_bits;
      acc_bits += round_bits();
      while (acc_bits >= 8) {
        out.push_back(acc);
        acc >>= 8;
        acc_bits -= 8;
      }
    }
    if (acc_bits > 0)
      out.push_back(acc);
    return out;
  }

  std::optional<Credential>
  deserialize_credential(const std::vector<uint8_t> &bytes) const {
    if (bytes.size() < CRED_FIXED_BYTES)
      return std::nullopt;
    const uint8_t *in = bytes.data();
    uint32_t mlen = 0;
    for (int j = 0; j < 4; j++)
      mlen |= static_cast<uint32_t>(*in++) << (8 * j);
    if (bytes.size() != cred_bytes(mlen))
      return std::nullopt;
    Credential cred;
    cred.M.assign(in, in + mlen);
    in += mlen;
    for (auto &rho : cred.rho) {
      std::memcpy(rho.data(), in, RHO_BYTES);
      in += RHO_BYTES;
    }
    cred.delta.resize(KAPPA);
    if (!unpack_ternary_vec(in, cred.phi0))
      return std::nullopt;
    for (auto &d : cred.delta)
      if (!unpack_ternary_vec(in, d))
        return std::nullopt;
    cred.v.resize(D);
    size_t bitpos = static_cast<size_t>(in - bytes.data()) * 8;
    uint64_t mask = P::ROUND_P - 1;
    for (size_t i = 0; i < D; i++) {
      uint64_t x = 0;
      for (size_t b = 0; b < round_bits(); b++, bitpos++)
        x |= static_cast<uint64_t>((bytes[bitpos / 8] >> (bitpos % 8)) & 1)
             << b;
      cred.v[i] = x & mask;
    }
    return cred;
  }

private:
  Ring<P> R;

  // --- internal helpers ---------------------------------------------------------

  template <size_t N>
  static std::vector<uint8_t> to_vec(const std::array<uint8_t, N> &a) {
    return {a.begin(), a.end()};
  }
  static std::vector<uint8_t> u32_bytes(uint32_t x) {
    std::vector<uint8_t> out(4);
    for (int j = 0; j < 4; j++)
      out[j] = static_cast<uint8_t>(x >> (8 * j));
    return out;
  }
  static void append_packed(std::vector<uint8_t> &out,
                            const std::vector<uint8_t> &b) {
    out.insert(out.end(), b.begin(), b.end());
  }
  static void append_len_prefixed(std::vector<uint8_t> &out,
                                  std::span<const uint8_t> b) {
    for (int j = 0; j < 4; j++)
      out.push_back(static_cast<uint8_t>(b.size() >> (8 * j)));
    out.insert(out.end(), b.begin(), b.end());
  }

  Vec zero_vec() const {
    Vec v;
    for (auto &p : v)
      p = R.zero_poly();
    return v;
  }
  Vec vec_sub(const Vec &a, const Vec &b) const {
    Vec out;
    for (size_t i = 0; i < K; i++)
      out[i] = R.sub(a[i], b[i]);
    return out;
  }

  // Raw RNS words, little-endian, per (coefficient, prime) slot. Canonical for
  // a fixed parameter set; used only as hash input (see header).
  static std::vector<uint8_t> fast_bytes(const Poly &a) {
    std::vector<uint8_t> out(D * NMOD * 8);
    uint8_t *p = out.data();
    for (size_t i = 0; i < D; i++)
      for (size_t cm = 0; cm < NMOD; cm++) {
        uint64_t v = a.v(cm, i);
        for (int j = 0; j < 8; j++)
          p[j] = static_cast<uint8_t>(v >> (8 * j));
        p += 8;
      }
    return out;
  }
  static std::vector<uint8_t> fast_bytes(const Vec &v) {
    std::vector<uint8_t> out;
    out.reserve(K * D * NMOD * 8);
    for (const auto &p : v)
      append_packed(out, fast_bytes(p));
    return out;
  }

  // Coefficient-wise {0, +1, -1} check on raw RNS slots; equivalent to
  // Ring::is_ternary without the CRT reconstruction.
  static bool fast_is_ternary(const Poly &a) {
    for (size_t i = 0; i < D; i++)
      for (size_t cm = 0; cm < NMOD; cm++) {
        uint64_t v = a.v(cm, i);
        if (v != 0 && v != 1 && Ring<P>::NPoly::get_modulus(cm) - 1 != v)
          return false;
      }
    return true;
  }
  static bool fast_is_ternary(const Vec &v) {
    for (const auto &p : v)
      if (!fast_is_ternary(p))
        return false;
    return true;
  }

  // c = B*r + e2 + H_R(i, mu_0 + B_c*delta, rho)
  static Vec branch_vec(const PublicKey &pk, uint32_t i, const Branch &br,
                        const Vec &mu_0) {
    Ring<P> R;
    Vec mu = R.add(mu_0, R.matvec(com_matrix(), br.delta));
    Vec u = hash_lane(i, mu, br.rho);
    return R.add(R.add(R.matvec(pk.B, br.r), br.e2), u);
  }

  static const Mat &com_matrix() {
    // Heap + fill-style sampling: a Mat is ~13MB at the paper shape, too big
    // to rely on NRVO eliding stack temporaries.
    static const Mat *Bc = [] {
      Ring<P> R;
      Drbg d(xof("CCKVBS-COM-v0", {std::vector<uint8_t>{'m'}}, 64));
      auto *m = new Mat();
      sample_uniform_mat_into<P>(R, d, *m);
      return m;
    }();
    return *Bc;
  }
  static Vec com_embed(std::span<const uint8_t> M) {
    Ring<P> R;
    Drbg d(xof("CCKVBS-COM-v0",
               {std::vector<uint8_t>{'e'},
                std::vector<uint8_t>(M.begin(), M.end())},
               64));
    return sample_uniform_vec<P>(R, d);
  }

  // 2-bit-per-coefficient packing of a ternary vector, LSB-first, 4 per byte.
  static std::vector<uint8_t> pack_ternary_vec(const Vec &v) {
    std::vector<uint8_t> out(TPACK_BYTES, 0);
    size_t idx = 0;
    for (const auto &p : v)
      for (size_t i = 0; i < D; i++, idx++) {
        uint64_t c = p.v(0, i); // ternary => slot 0 decides the symbol
        uint8_t sym = (c == 0) ? 0 : (c == 1) ? 1 : 2;
        out[idx / 4] |= static_cast<uint8_t>(sym << (2 * (idx % 4)));
      }
    return out;
  }
  static bool unpack_ternary_vec(const uint8_t *&in, Vec &v) {
    size_t idx = 0;
    for (auto &p : v)
      for (size_t i = 0; i < D; i++, idx++) {
        uint8_t sym = (in[idx / 4] >> (2 * (idx % 4))) & 3;
        if (sym == 3)
          return false;
        for (size_t cm = 0; cm < NMOD; cm++) {
          uint64_t val = (sym == 0)   ? 0
                         : (sym == 1) ? 1
                                      : Ring<P>::NPoly::get_modulus(cm) - 1;
          p.v(cm, i) = val;
        }
      }
    in += TPACK_BYTES;
    return true;
  }
};

} // namespace blnskv::cc
