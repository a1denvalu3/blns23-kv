#pragma once
//
// BLNS23 keyed-verification blind signature (ePrint 2023/077, Section 1.2 /
// Fig. 5). A lattice analogue of the hashed-Diffie-Hellman OPRF: the mint's
// signature on a message is (rho, v) with v = round(s^T * H(msg, rho)), which
// only the holder of s can compute -- keyed verification, exactly the trust
// model of Chaumian ecash.
//
// Protocol flow (2 rounds, round-optimal):
//   user:   r,e2 ternary; rho = H_rho(r,e2); u = H(msg,rho);
//           c = B*r + e2 + u  +  pi1 (proof of well-formedness)
//   mint:   e3 = PRF_K(c) (deterministic per c!);
//           h = s^T*c + e3  +  pi2 (proof linking h to public key t)
//   user:   v = round(h - t^T*r) = round(s^T*u + small noise)
//   mint:   verify(msg, (rho,v)): v == round(s^T*H(msg,rho))
//
// SECURITY WARNING: research prototype. Toy parameters are NOT secure, the
// mock NIZK is NOT zero-knowledge/sound, and the Poseidon2 hash-to-ring is
// not yet co-designed with the (future) proof system's arithmetic. Do not
// use for anything real.

#include "hashring.hpp"
#include "nizk.hpp"
#include "ring.hpp"
#include "sampling.hpp"

#include <optional>
#include <span>

namespace blnskv {

template <typename P> class Scheme {
public:
  using Poly = typename Ring<P>::Poly;
  using Vec = typename Ring<P>::Vec;
  using Mat = typename Ring<P>::Mat;

  struct PublicKey {
    Mat B;
    Vec t;
  };
  struct SigningKey {
    Vec s, e1;
    Drbg::Seed prf_key;
    PublicKey pk;
  };

  struct Commitment {
    Vec c;
    Proof pi1;
  };
  struct UserState {
    Vec r, e2, c;
    std::vector<uint8_t> rho, msg;
  };
  struct Response {
    Poly h;
    Proof pi2;
  };
  struct Signature {
    std::vector<uint8_t> rho;   // RHO_BYTES
    std::vector<uint64_t> v;    // D values in [0, ROUND_P)
  };

  Scheme() = default;

  SigningKey keygen() {
    auto drbg = Drbg::from_os();
    SigningKey sk;
    sk.pk.B = sample_uniform_mat<P>(R, drbg);
    sk.s = sample_ternary_vec<P>(R, drbg);
    sk.e1 = sample_ternary_vec<P>(R, drbg);
    sk.pk.t = R.add(R.vecmat_T(sk.s, sk.pk.B), sk.e1);
    sk.prf_key = drbg.bytes(32);
    return sk;
  }

  // Round 1 (user).
  std::pair<UserState, Commitment> commit(const PublicKey &pk,
                                          std::span<const uint8_t> msg,
                                          Nizk<P> &nizk) {
    auto drbg = Drbg::from_os();
    UserState st;
    st.r = sample_ternary_vec<P>(R, drbg);
    st.e2 = sample_ternary_vec<P>(R, drbg);
    st.msg.assign(msg.begin(), msg.end());
    st.rho = hash_rho<P>(R, st.r, st.e2);

    Vec u = hash_to_vec<P>(R, st.msg, st.rho);
    Commitment com;
    com.c = R.add(R.add(R.matvec(pk.B, st.r), st.e2), u);
    st.c = com.c;
    com.pi1 = nizk.prove_commit(R, {pk.B, com.c},
                                {st.r, st.e2, st.msg, st.rho});
    return {st, com};
  }

  // Round 2 (mint/signer). Throws if pi1 does not verify.
  Response respond(const SigningKey &sk, const Commitment &com, Nizk<P> &nizk) {
    if (!nizk.verify_commit(R, {sk.pk.B, com.c}, com.pi1))
      throw std::invalid_argument("invalid commitment proof");

    // e3 must be a *deterministic* function of c: answering the same c twice
    // with independent noise would leak s. PRF under the signer's key.
    Drbg e3_drbg(xof("BLNSKV-E3-v0", {sk.prf_key, R.serialize(com.c)}, 64));
    Poly e3 = sample_ternary<P>(R, e3_drbg);

    Response resp;
    resp.h = R.add(R.inner(sk.s, com.c), e3);
    resp.pi2 = nizk.prove_response(R, {sk.pk.B, sk.pk.t, com.c, resp.h},
                                   {sk.s, sk.e1, e3});
    return resp;
  }

  // Finalize (user). Nullopt if pi2 does not verify.
  std::optional<Signature> finalize(const PublicKey &pk, const UserState &st,
                                    const Response &resp, Nizk<P> &nizk) {
    if (!nizk.verify_response(R, {pk.B, pk.t, st.c, resp.h}, resp.pi2))
      return std::nullopt;
    // v = round(h - t^T * r)
    Poly diff = R.sub(resp.h, R.inner(pk.t, st.r));
    Signature sig;
    sig.rho = st.rho;
    sig.v = R.round_poly(diff);
    return sig;
  }

  // Keyed verification (mint only): v == round(s^T * H(msg, rho)).
  bool verify(const SigningKey &sk, std::span<const uint8_t> msg,
              const Signature &sig) const {
    if (sig.rho.size() != P::RHO_BYTES || sig.v.size() != P::D)
      return false;
    Vec u = hash_to_vec<P>(R, msg, sig.rho);
    Poly w = R.inner(sk.s, u);
    return R.round_poly(w) == sig.v;
  }

  // --- signature wire format ------------------------------------------------
  // rho (RHO_BYTES) || v bit-packed (log2(ROUND_P) bits per coefficient).

  static constexpr size_t round_bits() {
    size_t b = 0;
    for (uint64_t p = P::ROUND_P; p > 1; p >>= 1)
      b++;
    return b;
  }
  static constexpr size_t SIG_BYTES =
      P::RHO_BYTES + (P::D * round_bits() + 7) / 8;

  std::vector<uint8_t> serialize_sig(const Signature &sig) const {
    std::vector<uint8_t> out;
    out.reserve(SIG_BYTES);
    out.insert(out.end(), sig.rho.begin(), sig.rho.end());
    // LSB-first bit packing of v
    uint8_t acc = 0;
    size_t acc_bits = 0;
    for (uint64_t x : sig.v) {
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

  std::optional<Signature> deserialize_sig(
      const std::vector<uint8_t> &bytes) const {
    if (bytes.size() != SIG_BYTES)
      return std::nullopt;
    Signature sig;
    sig.rho.assign(bytes.begin(), bytes.begin() + P::RHO_BYTES);
    sig.v.resize(P::D);
    size_t bitpos = P::RHO_BYTES * 8;
    uint64_t mask = P::ROUND_P - 1;
    for (size_t i = 0; i < P::D; i++) {
      uint64_t x = 0;
      for (size_t b = 0; b < round_bits(); b++, bitpos++)
        x |= static_cast<uint64_t>((bytes[bitpos / 8] >> (bitpos % 8)) & 1)
             << b;
      sig.v[i] = x & mask;
    }
    return sig;
  }

private:
  Ring<P> R;
};

} // namespace blnskv
