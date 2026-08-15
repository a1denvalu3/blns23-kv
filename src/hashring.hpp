#pragma once
//
// Hashing into the ring, built on Poseidon2 over the Goldilocks field
// (see poseidon2.hpp). Poseidon2 is ZK-friendly: the round-1 NIZK must prove
// knowledge of preimages of hash_to_vec() inside the proof system, and
// proving Poseidon2 permutations is ~100x cheaper than proving SHAKE256 --
// the paper's bottleneck (see docs/how-it-works.md).
//
// Still open (roadmap M2): co-design of the Goldilocks field vs. the proof
// system's arithmetic and the RNS primes of Q, plus the joint parameter
// re-analysis. The byte encoding is internal to poseidon2.hpp (injective:
// length-prefixed parts, 4 bytes per field element).

#include "poseidon2.hpp"
#include "ring.hpp"
#include "sampling.hpp"

#include <span>

namespace blnskv {

// rho = H_rho(r, e2): binds the user's randomness into a short tag.
template <typename P>
std::vector<uint8_t> hash_rho(const Ring<P> &R, const typename Ring<P>::Vec &r,
                              const typename Ring<P>::Vec &e2) {
  Poseidon2Xof h("BLNSKV-RHO-v1", {R.serialize(r), R.serialize(e2)});
  return h.bytes(P::RHO_BYTES);
}

// u = H_to_ring(msg, rho): maps into R_Q^K, uniform (rejection sampling from
// the Poseidon2 byte stream).
template <typename P>
typename Ring<P>::Vec hash_to_vec(const Ring<P> &R, std::span<const uint8_t> msg,
                                  std::span<const uint8_t> rho) {
  Poseidon2Xof h("BLNSKV-H2R-v1",
                 {std::vector<uint8_t>(msg.begin(), msg.end()),
                  std::vector<uint8_t>(rho.begin(), rho.end())});
  return sample_uniform_vec<P>(R, h);
}

} // namespace blnskv
