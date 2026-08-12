#pragma once
//
// NIZK interface for the two proofs in the keyed-verification scheme:
//
//   pi1 (user, round 1): knowledge of ternary r, e2 and (msg, rho) with
//        c  =  B * r + e2 + H_to_ring(msg, rho),   rho = H_rho(r, e2)
//        -- this is the hash-heavy statement (needs the ZK-friendly hash).
//
//   pi2 (signer, round 2): knowledge of short s, e1, e3 with
//        h  =  s^T * c + e3   and   t  =  s^T * B + e1^T
//        -- a pure lattice relation; this is the one LaBRADOR handles
//           directly once wired up.
//
// MockNizk embeds the witness in the "proof" and re-checks the relation on
// verification. It is NOT zero-knowledge, NOT succinct and NOT sound against
// a malicious prover: it exists purely to exercise the protocol flow and the
// correctness of the arithmetic. Do not ship.

#include "hashring.hpp"
#include "ring.hpp"

#include <cstring>
#include <optional>
#include <vector>

namespace blnskv {

template <typename P> struct CommitStatement {
  typename Ring<P>::Mat B;
  typename Ring<P>::Vec c;
};
template <typename P> struct CommitWitness {
  typename Ring<P>::Vec r, e2;
  std::vector<uint8_t> msg, rho;
};

template <typename P> struct ResponseStatement {
  typename Ring<P>::Mat B;
  typename Ring<P>::Vec t, c;
  typename Ring<P>::Poly h;
};
template <typename P> struct ResponseWitness {
  typename Ring<P>::Vec s, e1;
  typename Ring<P>::Poly e3;
};

struct Proof {
  std::vector<uint8_t> bytes;
};

template <typename P> class Nizk {
public:
  virtual ~Nizk() = default;
  virtual Proof prove_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                             const CommitWitness<P> &wit) = 0;
  virtual bool verify_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                             const Proof &proof) = 0;
  virtual Proof prove_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                               const ResponseWitness<P> &wit) = 0;
  virtual bool verify_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                               const Proof &proof) = 0;
};

// INSECURE placeholder. See warning above.
template <typename P> class MockNizk final : public Nizk<P> {
public:
  Proof prove_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                     const CommitWitness<P> &wit) override;
  bool verify_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                     const Proof &proof) override;
  Proof prove_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                       const ResponseWitness<P> &wit) override;
  bool verify_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                       const Proof &proof) override;

private:
  // witness serialization helpers (mock proof = magic || witness bytes)
  static constexpr char MAGIC[4] = {'M', 'O', 'C', 'K'};
};

// --- MockNizk implementation -----------------------------------------------

template <typename P>
Proof MockNizk<P>::prove_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                                const CommitWitness<P> &wit) {
  // Recompute the statement from the witness; refuse to "prove" false
  // statements so bugs surface at proving time during tests.
  auto c_check = R.add(R.matvec(stmt.B, wit.r), wit.e2);
  c_check = R.add(c_check, hash_to_vec<P>(R, wit.msg, wit.rho));
  for (size_t i = 0; i < Ring<P>::K; i++)
    if (!R.equal(c_check[i], stmt.c[i]))
      throw std::logic_error("MockNizk: commit witness does not match statement");
  if (!R.is_ternary(wit.r) || !R.is_ternary(wit.e2))
    throw std::logic_error("MockNizk: non-ternary witness");
  if (hash_rho<P>(R, wit.r, wit.e2) != wit.rho)
    throw std::logic_error("MockNizk: rho mismatch");

  Proof proof;
  proof.bytes.assign(MAGIC, MAGIC + 4);
  auto append = [&proof](const std::vector<uint8_t> &b) {
    proof.bytes.insert(proof.bytes.end(), b.begin(), b.end());
  };
  append(R.serialize(wit.r));
  append(R.serialize(wit.e2));
  auto push_u32 = [&proof](uint32_t n) {
    for (int i = 0; i < 4; i++)
      proof.bytes.push_back(static_cast<uint8_t>(n >> (8 * i)));
  };
  push_u32(static_cast<uint32_t>(wit.msg.size()));
  append(wit.msg);
  append(wit.rho);
  return proof;
}

template <typename P>
bool MockNizk<P>::verify_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                                const Proof &proof) {
  const uint8_t *p = proof.bytes.data();
  size_t remaining = proof.bytes.size();
  if (remaining < 4 || std::memcmp(p, MAGIC, 4) != 0)
    return false;
  p += 4;
  remaining -= 4;
  const size_t vec_bytes = Ring<P>::K * Ring<P>::D * R.coeff_bytes();
  if (remaining < 2 * vec_bytes + 4 + P::RHO_BYTES)
    return false;

  CommitWitness<P> wit;
  wit.r = R.deserialize_vec(p);
  wit.e2 = R.deserialize_vec(p);
  uint32_t mlen = 0;
  for (int i = 0; i < 4; i++)
    mlen |= static_cast<uint32_t>(*p++) << (8 * i);
  size_t consumed = static_cast<size_t>(p - proof.bytes.data());
  if (proof.bytes.size() - consumed < mlen + P::RHO_BYTES)
    return false;
  wit.msg.assign(p, p + mlen);
  p += mlen;
  wit.rho.assign(p, p + P::RHO_BYTES);

  // relation checks
  if (!R.is_ternary(wit.r) || !R.is_ternary(wit.e2))
    return false;
  if (hash_rho<P>(R, wit.r, wit.e2) != wit.rho)
    return false;
  auto c_check = R.add(R.matvec(stmt.B, wit.r), wit.e2);
  c_check = R.add(c_check, hash_to_vec<P>(R, wit.msg, wit.rho));
  for (size_t i = 0; i < Ring<P>::K; i++)
    if (!R.equal(c_check[i], stmt.c[i]))
      return false;
  return true;
}

template <typename P>
Proof MockNizk<P>::prove_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                                  const ResponseWitness<P> &wit) {
  auto h_check = R.add(R.inner(wit.s, stmt.c), wit.e3);
  if (!R.equal(h_check, stmt.h))
    throw std::logic_error("MockNizk: response witness does not match h");
  auto t_check = R.vecmat_T(wit.s, stmt.B); // = s^T * B
  t_check = R.add(t_check, wit.e1);
  for (size_t i = 0; i < Ring<P>::K; i++)
    if (!R.equal(t_check[i], stmt.t[i]))
      throw std::logic_error("MockNizk: response witness does not match t");
  if (!R.is_ternary(wit.s) || !R.is_ternary(wit.e1) || !R.is_ternary(wit.e3))
    throw std::logic_error("MockNizk: non-ternary witness");

  Proof proof;
  proof.bytes.assign(MAGIC, MAGIC + 4);
  auto append = [&proof](const std::vector<uint8_t> &b) {
    proof.bytes.insert(proof.bytes.end(), b.begin(), b.end());
  };
  append(R.serialize(wit.s));
  append(R.serialize(wit.e1));
  append(R.serialize(wit.e3));
  return proof;
}

template <typename P>
bool MockNizk<P>::verify_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                                  const Proof &proof) {
  const uint8_t *p = proof.bytes.data();
  size_t remaining = proof.bytes.size();
  const size_t vec_bytes = Ring<P>::K * Ring<P>::D * R.coeff_bytes();
  const size_t poly_bytes = Ring<P>::D * R.coeff_bytes();
  if (remaining != 4 + 2 * vec_bytes + poly_bytes)
    return false;
  if (std::memcmp(p, MAGIC, 4) != 0)
    return false;
  p += 4;

  ResponseWitness<P> wit;
  wit.s = R.deserialize_vec(p);
  wit.e1 = R.deserialize_vec(p);
  wit.e3 = R.deserialize_poly(p);

  if (!R.is_ternary(wit.s) || !R.is_ternary(wit.e1) || !R.is_ternary(wit.e3))
    return false;
  auto h_check = R.add(R.inner(wit.s, stmt.c), wit.e3);
  if (!R.equal(h_check, stmt.h))
    return false;
  auto t_check = R.add(R.vecmat_T(wit.s, stmt.B), wit.e1);
  for (size_t i = 0; i < Ring<P>::K; i++)
    if (!R.equal(t_check[i], stmt.t[i]))
      return false;
  return true;
}

} // namespace blnskv
