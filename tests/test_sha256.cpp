// Known-answer tests for the vendored SHA-256 (src/sha256.hpp) and for the
// SHA-256 counter-mode DRBG / xof_sha256 (src/drbg.hpp).

#include "drbg.hpp"
#include "minitest.hpp"
#include "sha256.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

using namespace blnskv;

static std::string hex(const uint8_t *d, size_t n) {
  std::string out;
  const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out.push_back(digits[d[i] >> 4]);
    out.push_back(digits[d[i] & 0xf]);
  }
  return out;
}

static std::string sha256_hex(const uint8_t *in, size_t n) {
  uint8_t d[32];
  sha256(in, n, d);
  return hex(d, 32);
}

TEST(sha256_kat_empty) {
  CHECK(sha256_hex(reinterpret_cast<const uint8_t *>(""), 0) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(sha256_kat_abc) {
  CHECK(sha256_hex(reinterpret_cast<const uint8_t *>("abc"), 3) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(sha256_kat_million_a) {
  std::vector<uint8_t> m(1000000, 'a');
  CHECK(sha256_hex(m.data(), m.size()) ==
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(sha256_kat_56_byte_boundary) {
  // exercises the two-block padding path (len % 64 == 56)
  std::string m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  CHECK(m.size() == 56);
  CHECK(sha256_hex(reinterpret_cast<const uint8_t *>(m.data()), m.size()) ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(sha256_drbg_determinism) {
  std::vector<uint8_t> seed(32, 0x42);
  Sha256Drbg a(seed), b(seed);
  auto sa = a.bytes(100); // crosses several 32-byte counter blocks
  auto sb = b.bytes(100);
  CHECK(sa == sb);

  std::vector<uint8_t> seed2(32, 0x43);
  Sha256Drbg c(seed2);
  auto sc = c.bytes(100);
  CHECK(sa != sc);

  // contiguous consumption: split draws equal the one-shot squeeze, including
  // across 32-byte block boundaries
  Sha256Drbg d(seed), e(seed);
  auto d1 = d.bytes(13); // stream bytes [0, 13)
  auto d2 = d.bytes(19); // stream bytes [13, 32): crosses into block 1
  auto d3 = d.bytes(68); // stream bytes [32, 100)
  auto whole = e.bytes(100);
  CHECK(std::memcmp(whole.data(), d1.data(), 13) == 0);
  CHECK(std::memcmp(whole.data() + 13, d2.data(), 19) == 0);
  CHECK(std::memcmp(whole.data() + 32, d3.data(), 68) == 0);
}

TEST(sha256_drbg_next_below) {
  Sha256Drbg d(std::vector<uint8_t>(48, 0x11));
  for (int i = 0; i < 10000; i++) {
    uint64_t v = d.next_below(3);
    CHECK(v < 3);
  }
  uint64_t prime = 4611686018326724609ULL; // NFLlib 62-bit prime
  for (int i = 0; i < 1000; i++) {
    uint64_t v = d.next_below(prime);
    CHECK(v < prime);
  }
  bool threw = false;
  try {
    d.next_below(0);
  } catch (const std::invalid_argument &) {
    threw = true;
  }
  CHECK(threw);
}

TEST(xof_sha256_determinism_and_domain_separation) {
  std::vector<std::vector<uint8_t>> parts{{'a', 'b'}, {'c'}};
  auto x1 = xof_sha256("DOM-v1", parts, 64); // multi-block output
  auto x2 = xof_sha256("DOM-v1", parts, 64);
  CHECK(x1 == x2);
  auto x3 = xof_sha256("DOM-v2", parts, 64);
  CHECK(x1 != x3);
  // prefix property: shorter output is a prefix of longer
  auto x4 = xof_sha256("DOM-v1", parts, 16);
  CHECK(std::memcmp(x1.data(), x4.data(), 16) == 0);
}

RUN_ALL_TESTS()
