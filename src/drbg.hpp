#pragma once
//
// SHAKE256-based counter DRBG.
//
// Also provides the implementation of nfl::fastrandombytes() required to
// link NFLlib's sampling code (NFLlib upstream uses an asm Salsa20; we use
// this DRBG instead so that tests can run with fixed seeds).

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

extern "C" {
#include "fips202.h" // shake256incctx
}

namespace blnskv {

class Drbg {
public:
  using Seed = std::vector<uint8_t>;

  explicit Drbg(const Seed &seed);
  static Drbg from_os();          // seeded from getrandom()
  static Drbg from_u64(uint64_t); // deterministic, for tests only

  void fill(uint8_t *out, size_t n);
  std::vector<uint8_t> bytes(size_t n);

  // Uniform in [0, bound) via rejection sampling.
  uint64_t next_below(uint64_t bound);

private:
  shake256incctx ctx_;
  uint64_t counter_ = 0;
};

// One-shot SHAKE256: out = SHAKE256(domain || part[0] || part[1] || ...)
void xof(std::string_view domain, const std::vector<std::vector<uint8_t>> &parts,
         uint8_t *out, size_t outlen);
std::vector<uint8_t> xof(std::string_view domain,
                         const std::vector<std::vector<uint8_t>> &parts,
                         size_t outlen);

} // namespace blnskv
