#pragma once
//
// Samplers over R_Q. Deterministic when driven by a seeded Drbg.

#include "drbg.hpp"
#include "ring.hpp"

namespace blnskv {

// Uniform in R_Q: uniform in each RNS slot (CRT => uniform mod Q).
template <typename P>
typename Ring<P>::Poly sample_uniform(const Ring<P> &R, Drbg &drbg);

// Ternary: coefficients uniform in {-1, 0, +1} (same integer in every slot).
template <typename P>
typename Ring<P>::Poly sample_ternary(const Ring<P> &R, Drbg &drbg);

template <typename P>
typename Ring<P>::Vec sample_uniform_vec(const Ring<P> &R, Drbg &drbg);

template <typename P>
typename Ring<P>::Vec sample_ternary_vec(const Ring<P> &R, Drbg &drbg);

template <typename P>
typename Ring<P>::Mat sample_uniform_mat(const Ring<P> &R, Drbg &drbg);

} // namespace blnskv

// --- implementation --------------------------------------------------------
namespace blnskv {

template <typename P>
typename Ring<P>::Poly sample_uniform(const Ring<P> &R, Drbg &drbg) {
  typename Ring<P>::Poly p = R.zero_poly();
  for (size_t cm = 0; cm < Ring<P>::NMOD; cm++)
    for (size_t i = 0; i < Ring<P>::D; i++)
      R.set_coeff(p, cm, i, drbg.next_below(R.prime(cm)));
  return p;
}

template <typename P>
typename Ring<P>::Poly sample_ternary(const Ring<P> &R, Drbg &drbg) {
  typename Ring<P>::Poly p = R.zero_poly();
  for (size_t i = 0; i < Ring<P>::D; i++) {
    uint64_t c = drbg.next_below(3); // 0,1,2 -> 0,+1,-1
    for (size_t cm = 0; cm < Ring<P>::NMOD; cm++) {
      uint64_t v = (c == 0) ? 0 : (c == 1) ? 1 : R.prime(cm) - 1;
      R.set_coeff(p, cm, i, v);
    }
  }
  return p;
}

template <typename P>
typename Ring<P>::Vec sample_uniform_vec(const Ring<P> &R, Drbg &drbg) {
  typename Ring<P>::Vec v{};
  for (auto &p : v)
    p = sample_uniform<P>(R, drbg);
  return v;
}

template <typename P>
typename Ring<P>::Vec sample_ternary_vec(const Ring<P> &R, Drbg &drbg) {
  typename Ring<P>::Vec v{};
  for (auto &p : v)
    p = sample_ternary<P>(R, drbg);
  return v;
}

template <typename P>
typename Ring<P>::Mat sample_uniform_mat(const Ring<P> &R, Drbg &drbg) {
  typename Ring<P>::Mat m{};
  for (auto &row : m)
    row = sample_uniform_vec<P>(R, drbg);
  return m;
}

} // namespace blnskv
