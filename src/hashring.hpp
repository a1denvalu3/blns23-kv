#pragma once
//
// Hashing into the ring.
//
// WARNING: both functions below are SHAKE256-based *placeholders*. The
// round-1 NIZK must prove knowledge of preimages of hash_to_vec() inside the
// proof system; doing that with SHAKE256 is what made the paper's issuance
// protocol slow (~2^12 SHA evaluations). Before any real-world use, replace
// with a ZK-friendly construction (e.g. Poseidon2-style) and re-do the
// parameter/security analysis. The interface below is designed so that the
// swap only touches this file.

#include "drbg.hpp"
#include "ring.hpp"
#include "sampling.hpp"

#include <span>

namespace blnskv {

// rho = H_rho(r, e2): binds the user's randomness into a short tag.
template <typename P>
std::vector<uint8_t> hash_rho(const Ring<P> &R, const typename Ring<P>::Vec &r,
                              const typename Ring<P>::Vec &e2) {
  return xof("BLNSKV-RHO-v0", {R.serialize(r), R.serialize(e2)}, P::RHO_BYTES);
}

// u = H_to_ring(msg, rho): maps into R_Q^K, uniform.
template <typename P>
typename Ring<P>::Vec hash_to_vec(const Ring<P> &R, std::span<const uint8_t> msg,
                                  std::span<const uint8_t> rho) {
  Drbg drbg(xof("BLNSKV-H2R-v0",
                {std::vector<uint8_t>(msg.begin(), msg.end()),
                 std::vector<uint8_t>(rho.begin(), rho.end())},
                64));
  return sample_uniform_vec<P>(R, drbg);
}

} // namespace blnskv
