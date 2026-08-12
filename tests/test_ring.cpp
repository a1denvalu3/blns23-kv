// Ring arithmetic tests: validate the NFLlib-backed adapter against a
// schoolbook negacyclic reference implementation.

#include "minitest.hpp"
#include "ring.hpp"
#include "sampling.hpp"

using namespace blnskv;
using P = ToyParams;
using R = Ring<P>;

// Schoolbook negacyclic multiply on reconstructed integers (independent
// reference; uses cpp_int throughout, no NFLlib).
static R::Poly schoolbook_mul(const R &ring, const R::Poly &a, const R::Poly &b) {
  cpp_int Q = ring.Q();
  std::vector<cpp_int> ai(P::D), bi(P::D), ci(2 * P::D, 0);
  for (size_t i = 0; i < P::D; i++) {
    ai[i] = ring.reconstruct(a, i);
    bi[i] = ring.reconstruct(b, i);
  }
  for (size_t i = 0; i < P::D; i++)
    for (size_t j = 0; j < P::D; j++)
      ci[i + j] += ai[i] * bi[j];
  // reduce mod (X^D + 1): X^D = -1
  std::vector<cpp_int> coeff(P::D, 0);
  for (size_t t = 0; t < 2 * P::D; t++) {
    size_t i = t % P::D;
    if (t < P::D)
      coeff[i] += ci[t];
    else
      coeff[i] -= ci[t];
  }
  // serialize canonical reps and let the ring deserialize them
  size_t nb = ring.coeff_bytes();
  std::vector<uint8_t> buf(P::D * nb);
  for (size_t i = 0; i < P::D; i++) {
    cpp_int x = ((coeff[i] % Q) + Q) % Q;
    for (size_t j = 0; j < nb; j++) {
      buf[i * nb + j] = static_cast<uint8_t>(x & 0xff);
      x >>= 8;
    }
  }
  const uint8_t *ptr = buf.data();
  return ring.deserialize_poly(ptr);
}

TEST(ring_add_sub_inverse) {
  R ring;
  auto drbg = Drbg::from_u64(1);
  auto a = sample_uniform<P>(ring, drbg);
  auto b = sample_uniform<P>(ring, drbg);
  auto c = ring.sub(ring.add(a, b), b);
  CHECK(ring.equal(c, a));
}

TEST(ring_mul_matches_schoolbook) {
  R ring;
  auto drbg = Drbg::from_u64(2);
  for (int trial = 0; trial < 5; trial++) {
    auto a = sample_uniform<P>(ring, drbg);
    auto b = sample_uniform<P>(ring, drbg);
    auto fast = ring.mul(a, b);
    auto ref = schoolbook_mul(ring, a, b);
    CHECK(ring.equal(fast, ref));
  }
}

TEST(ring_mul_by_x_is_negacyclic_shift) {
  R ring;
  auto drbg = Drbg::from_u64(3);
  auto f = sample_uniform<P>(ring, drbg);
  // X as a polynomial
  auto x = ring.zero_poly();
  for (size_t cm = 0; cm < R::NMOD; cm++)
    ring.set_coeff(x, cm, 1, 1);
  auto xf = ring.mul(x, f);
  // (X*f)[i] = f[i-1] for i>=1; (X*f)[0] = -f[D-1]
  for (size_t i = 1; i < P::D; i++)
    CHECK(ring.reconstruct(xf, i) == ring.reconstruct(f, i - 1));
  CHECK(ring.reconstruct(xf, 0) == ring.Q() - ring.reconstruct(f, P::D - 1));
}

TEST(ring_matvec_inner_consistent) {
  R ring;
  auto drbg = Drbg::from_u64(4);
  auto M = sample_uniform_mat<P>(ring, drbg);
  auto x = sample_ternary_vec<P>(ring, drbg);
  auto y = sample_ternary_vec<P>(ring, drbg);
  auto Mx = ring.matvec(M, x);
  // y^T (M x) == (y^T M) x
  auto lhs = ring.inner(y, Mx);
  auto yM = ring.vecmat_T(y, M);
  auto rhs = ring.inner(yM, x);
  CHECK(ring.equal(lhs, rhs));
}

TEST(ring_serialize_roundtrip) {
  R ring;
  auto drbg = Drbg::from_u64(5);
  auto a = sample_uniform_vec<P>(ring, drbg);
  auto bytes = ring.serialize(a);
  const uint8_t *ptr = bytes.data();
  auto b = ring.deserialize_vec(ptr);
  for (size_t i = 0; i < R::K; i++)
    CHECK(ring.equal(a[i], b[i]));
}

TEST(ring_ternary_check) {
  R ring;
  auto drbg = Drbg::from_u64(6);
  auto t = sample_ternary_vec<P>(ring, drbg);
  CHECK(ring.is_ternary(t));
  auto u = sample_uniform_vec<P>(ring, drbg);
  CHECK(!ring.is_ternary(u)); // negligibly unlikely to pass by chance
}

TEST(ring_rounding_stable_under_small_noise) {
  R ring;
  auto drbg = Drbg::from_u64(7);
  cpp_int margin = ring.Q() / (2 * P::ROUND_P);
  for (int trial = 0; trial < 20; trial++) {
    auto a = sample_uniform<P>(ring, drbg);
    // small noise in {-1,0,1}
    auto n = sample_ternary<P>(ring, drbg);
    auto an = ring.add(a, n);
    auto ra = ring.round_poly(a);
    auto ran = ring.round_poly(an);
    // count disagreements: only possible when a coefficient sits within
    // the noise of a rounding boundary (prob ~ 2p/Q per coeff)
    size_t diff = 0;
    for (size_t i = 0; i < P::D; i++)
      diff += (ra[i] != ran[i]);
    (void)margin;
    CHECK(diff <= 2); // generous; expected 0 with overwhelming probability
  }
}

RUN_ALL_TESTS()
