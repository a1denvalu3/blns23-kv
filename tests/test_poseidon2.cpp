// Poseidon2 (Goldilocks, width 12) tests: known-answer vector from Plonky3,
// field arithmetic edge cases, sponge/XOF behavior, hash-to-ring properties.

#include "hashring.hpp"
#include "minitest.hpp"
#include "poseidon2.hpp"

using namespace blnskv;
using TP = ToyParams;

// KAT from Plonky3 (goldilocks/src/poseidon2.rs, test_default_goldilocks_
// poseidon2_width_12): permute([0, 1, ..., 11]).
TEST(poseidon2_permutation_kat) {
  poseidon2::State s = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  poseidon2::permute(s);
  const poseidon2::State expected = {
      0xf292ab67c0f14b03ULL, 0x0a32f1b37656544cULL, 0x053c61ab895498deULL,
      0x02ff92e55b196ffbULL, 0x58176e8f6f58cab2ULL, 0xb0aa1206e7aec0f8ULL,
      0xe90c13f3dce83ca4ULL, 0xf4da15333edf39c2ULL, 0x23b701c053c2ca6cULL,
      0xd233d593dcdfbf58ULL, 0x4effa5f9516fb52eULL, 0x0aaf4489f1f40166ULL,
  };
  CHECK(s == expected);
}

TEST(poseidon2_field_arithmetic) {
  namespace p2 = poseidon2;
  const uint64_t p = p2::P;
  CHECK(p2::fadd(p - 1, 1) == 0); // wraparound
  CHECK(p2::fadd(p - 1, p - 1) == p - 2);
  CHECK(p2::fsub(0, 1) == p - 1);
  CHECK(p2::fsub(5, 5) == 0);
  CHECK(p2::fmul(p - 1, p - 1) == 1); // (-1)^2
  CHECK(p2::fmul(0xFFFFFFFFFFFFFFFFULL, 1) == 0xFFFFFFFFFFFFFFFFULL % p);
  CHECK(p2::pow7(0) == 0);
  CHECK(p2::pow7(1) == 1);
  CHECK(p2::pow7(2) == 128);
}

TEST(poseidon2_xof_deterministic_and_separated) {
  auto a1 = Poseidon2Xof("DOM-A", {{1, 2, 3}}).bytes(64);
  auto a2 = Poseidon2Xof("DOM-A", {{1, 2, 3}}).bytes(64);
  auto b = Poseidon2Xof("DOM-B", {{1, 2, 3}}).bytes(64);
  auto c = Poseidon2Xof("DOM-A", {{1, 2, 4}}).bytes(64);
  CHECK(a1 == a2);  // deterministic
  CHECK(a1 != b);   // domain separation
  CHECK(a1 != c);   // input sensitivity
  // length-prefix injectivity: ("ab","c") != ("a","bc")
  auto x = Poseidon2Xof("D", {{'a', 'b'}, {'c'}}).bytes(32);
  auto y = Poseidon2Xof("D", {{'a'}, {'b', 'c'}}).bytes(32);
  CHECK(x != y);
  // streaming: byte-at-a-time reads match one bulk read
  Poseidon2Xof bulk("DOM-A", {{1, 2, 3}});
  Poseidon2Xof drip("DOM-A", {{1, 2, 3}});
  auto all = bulk.bytes(100);
  std::vector<uint8_t> drop(100);
  for (auto &byte : drop)
    drip.fill(&byte, 1);
  CHECK(all == drop);
}

TEST(hash_rho_basic) {
  Ring<TP> R;
  auto drbg = Drbg::from_u64(42);
  auto r = sample_ternary_vec<TP>(R, drbg);
  auto e2 = sample_ternary_vec<TP>(R, drbg);
  auto rho1 = hash_rho<TP>(R, r, e2);
  auto rho2 = hash_rho<TP>(R, r, e2);
  CHECK(rho1.size() == TP::RHO_BYTES);
  CHECK(rho1 == rho2); // deterministic
  auto e2b = sample_ternary_vec<TP>(R, drbg);
  CHECK(hash_rho<TP>(R, r, e2b) != rho1);
}

TEST(hash_to_vec_basic) {
  Ring<TP> R;
  std::vector<uint8_t> msg = {'m', 's', 'g'};
  std::vector<uint8_t> rho(TP::RHO_BYTES, 0x5a);
  auto u1 = hash_to_vec<TP>(R, msg, rho);
  auto u2 = hash_to_vec<TP>(R, msg, rho);
  for (size_t i = 0; i < TP::K; i++)
    CHECK(R.equal(u1[i], u2[i])); // deterministic
  // coefficients in range and not all identical
  bool varied = false;
  uint64_t first = R.coeff(u1[0], 0, 0);
  for (size_t i = 0; i < TP::D; i++) {
    for (size_t cm = 0; cm < TP::NMOD; cm++) {
      uint64_t c = R.coeff(u1[0], cm, i);
      CHECK(c < R.prime(cm));
      if (cm == 0 && c != first)
        varied = true;
    }
  }
  CHECK(varied);
  rho[0] ^= 1;
  auto u3 = hash_to_vec<TP>(R, msg, rho);
  CHECK(!R.equal(u1[0], u3[0]));
}

RUN_ALL_TESTS()
