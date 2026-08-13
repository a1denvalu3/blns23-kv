#pragma once
//
// Ring adapter: R_Q = Z_Q[X]/(X^D + 1) with Q = prod_i p_i over NFLlib's
// NTT primes (RNS representation). All Poly objects are kept in
// *coefficient* domain; multiplication transforms internally.
//
// Exact integer reconstruction (CRT) and rounding use boost::multiprecision
// and only run on the finalize/verify path, never in the hot path.

#include "params.hpp"

#include <boost/multiprecision/cpp_int.hpp>
#include <nfl/poly.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace blnskv {

using boost::multiprecision::cpp_int;

template <typename P> class Ring {
public:
  static constexpr size_t D = P::D;
  static constexpr size_t K = P::K;
  static constexpr size_t NMOD = P::NMOD;

  using NPoly = nfl::poly<uint64_t, D, NMOD>; // RNS polynomial
  // NFLlib poly requires 32-byte alignment (SIMD). The wrapper propagates it
  // so that stack/vector storage of Poly stays aligned.
  struct alignas(32) Poly {
    NPoly v{};
  };
  using Vec = std::array<Poly, K>;
  using Mat = std::array<Vec, K>; // K x K, row-major: (matvec)_{i} = sum_j M[i][j]*x[j]

  Ring() {
    for (size_t i = 0; i < NMOD; i++) {
      primes_[i] = NPoly::get_modulus(i);
      Q_ *= primes_[i];
    }
    // CRT coefficients: x = sum_i x_i * M_i * inv_i (mod Q), M_i = Q/p_i
    for (size_t i = 0; i < NMOD; i++) {
      cpp_int Mi = Q_ / primes_[i];
      cpp_int inv = 1;
      // modular inverse of (Mi mod p_i) via Euler: p_i prime
      cpp_int a = Mi % primes_[i];
      cpp_int e = primes_[i] - 2;
      cpp_int p = primes_[i];
      cpp_int base = a, r = cpp_int(1);
      while (e > 0) {
        if ((e & 1) == 1)
          r = (r * base) % p;
        base = (base * base) % p;
        e >>= 1;
      }
      crt_M_[i] = Mi;
      crt_inv_[i] = r;
    }
  }

  const cpp_int &Q() const { return Q_; }
  uint64_t prime(size_t i) const { return primes_[i]; }

  // --- coefficient access -------------------------------------------------
  uint64_t coeff(const Poly &a, size_t mod, size_t i) const { return a.v(mod, i); }
  void set_coeff(Poly &a, size_t mod, size_t i, uint64_t v) const { a.v(mod, i) = v; }

  // Reconstruct one coefficient as an integer in [0, Q).
  cpp_int reconstruct(const Poly &a, size_t i) const {
    cpp_int x = 0;
    for (size_t cm = 0; cm < NMOD; cm++) {
      cpp_int t = (cpp_int(a.v(cm, i)) * crt_inv_[cm]) % primes_[cm];
      x += t * crt_M_[cm];
    }
    return x % Q_;
  }

  // --- arithmetic (coefficient domain in/out) ------------------------------
  Poly add(const Poly &a, const Poly &b) const { return Poly{a.v + b.v}; }
  Poly sub(const Poly &a, const Poly &b) const { return Poly{a.v - b.v}; }

  Poly mul(const Poly &a, const Poly &b) const {
    NPoly x = a.v, y = b.v;
    x.ntt_pow_phi();
    y.ntt_pow_phi();
    NPoly z = x * y; // pointwise in NTT domain
    z.invntt_pow_invphi();
    return Poly{z};
  }

  Poly inner(const Vec &a, const Vec &b) const { // sum_i a_i * b_i
    Poly acc = zero_poly();
    for (size_t i = 0; i < K; i++)
      acc = add(acc, mul(a[i], b[i]));
    return acc;
  }

  Vec matvec(const Mat &M, const Vec &x) const {
    Vec out{};
    for (size_t i = 0; i < K; i++) {
      Poly acc = zero_poly();
      for (size_t j = 0; j < K; j++)
        acc = add(acc, mul(M[i][j], x[j]));
      out[i] = acc;
    }
    return out;
  }

  // out_j = sum_i x_i * M[i][j]   (i.e. x^T * M)
  Vec vecmat_T(const Vec &x, const Mat &M) const {
    Vec out{};
    for (size_t j = 0; j < K; j++) {
      Poly acc = zero_poly();
      for (size_t i = 0; i < K; i++)
        acc = add(acc, mul(x[i], M[i][j]));
      out[j] = acc;
    }
    return out;
  }

  Vec add(const Vec &a, const Vec &b) const {
    Vec out{};
    for (size_t i = 0; i < K; i++)
      out[i] = add(a[i], b[i]);
    return out;
  }

  bool equal(const Poly &a, const Poly &b) const {
    for (size_t cm = 0; cm < NMOD; cm++)
      for (size_t i = 0; i < D; i++)
        if (a.v(cm, i) != b.v(cm, i))
          return false;
    return true;
  }

  Poly zero_poly() const {
    Poly p;
    for (size_t cm = 0; cm < NMOD; cm++)
      for (size_t i = 0; i < D; i++)
        p.v(cm, i) = 0;
    return p;
  }

  // --- rounding ------------------------------------------------------------
  // Round-to-top-bits: floor(x * ROUND_P / Q) for x in [0, Q).
  uint64_t round_coeff(const cpp_int &x) const {
    cpp_int y = (x * P::ROUND_P) / Q_;
    return static_cast<uint64_t>(y);
  }

  std::vector<uint64_t> round_poly(const Poly &a) const {
    std::vector<uint64_t> out(D);
    for (size_t i = 0; i < D; i++)
      out[i] = round_coeff(reconstruct(a, i));
    return out;
  }

  // --- serialization (canonical, little-endian per coefficient) -------------
  size_t coeff_bytes() const {
    size_t bits = static_cast<size_t>(msb(Q_)) + 1;
    return (bits + 7) / 8;
  }

  std::vector<uint8_t> serialize(const Poly &a) const {
    size_t nb = coeff_bytes();
    std::vector<uint8_t> out(D * nb);
    for (size_t i = 0; i < D; i++) {
      cpp_int x = reconstruct(a, i);
      for (size_t j = 0; j < nb; j++) {
        out[i * nb + j] = static_cast<uint8_t>(x & 0xff);
        x >>= 8;
      }
    }
    return out;
  }

  std::vector<uint8_t> serialize(const Vec &v) const {
    std::vector<uint8_t> out;
    for (const auto &p : v) {
      auto b = serialize(p);
      out.insert(out.end(), b.begin(), b.end());
    }
    return out;
  }

  Poly deserialize_poly(const uint8_t *&in) const {
    size_t nb = coeff_bytes();
    Poly p;
    for (size_t i = 0; i < D; i++) {
      cpp_int x = 0;
      for (size_t j = nb; j-- > 0;) {
        x <<= 8;
        x |= in[i * nb + j];
      }
      x %= Q_;
      for (size_t cm = 0; cm < NMOD; cm++) {
        cpp_int r = x % primes_[cm];
        p.v(cm, i) = static_cast<uint64_t>(r);
      }
    }
    in += D * nb;
    return p;
  }

  Vec deserialize_vec(const uint8_t *&in) const {
    Vec v{};
    for (auto &p : v)
      p = deserialize_poly(in);
    return v;
  }

  // Each coefficient must reconstruct to 0, +1 or -1 (i.e. Q-1).
  bool is_ternary(const Poly &a) const {
    for (size_t i = 0; i < D; i++) {
      cpp_int x = reconstruct(a, i);
      if (x != 0 && x != 1 && x != Q_ - 1)
        return false;
    }
    return true;
  }
  bool is_ternary(const Vec &v) const {
    for (const auto &p : v)
      if (!is_ternary(p))
        return false;
    return true;
  }

private:
  std::array<uint64_t, NMOD> primes_{};
  std::array<cpp_int, NMOD> crt_M_{};
  std::array<cpp_int, NMOD> crt_inv_{};
  cpp_int Q_ = 1;
};

} // namespace blnskv
