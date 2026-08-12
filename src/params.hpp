#pragma once
//
// Parameter sets for the BLNS23 keyed-verification blind signature
// (ePrint 2023/077, Section 4 / Fig. 5).
//
// Ring: R_Q = Z_Q[X]/(X^D + 1) with composite Q = product of NMOD 62-bit
// NTT primes (NFLlib). Element/vector lengths: vectors have K polynomials.
//
// SECURITY WARNING: the "toy" preset exists for functional testing ONLY.
// It is not a secure parameter set. Secure parameters (paper: q ~ 2^150,
// total LWE dimension ~ 6000) require re-analysis together with the
// ZK-friendly hash used inside the round-1 proof -- see README.

#pragma once

#include <cstddef>
#include <cstdint>

namespace blnskv {

template <size_t D_, size_t K_, size_t NMOD_>
struct Params {
  static constexpr size_t D = D_;       // ring degree (power of two)
  static constexpr size_t K = K_;       // number of ring elements per vector
  static constexpr size_t NMOD = NMOD_; // number of 62-bit NTT primes in Q

  // Rounding: verification value v keeps the top ROUND_BITS of each
  // coefficient of s^T*u (out of log2(Q)).
  static constexpr uint64_t ROUND_P = 2; // rounding modulus (power of two)

  static constexpr size_t LAMBDA = 128;       // target classical security bits
  static constexpr size_t RHO_BYTES = 32;     // 2*lambda bits
};

// Functional-test parameters. NOT SECURE.
using ToyParams = Params<256, 4, 1>;

// Paper-flavoured shape (larger dimension + wide Q via RNS). Still NOT a
// validated secure parameter set -- placeholder for future analysis.
using PaperShapeParams = Params<4096, 2, 3>;

} // namespace blnskv
