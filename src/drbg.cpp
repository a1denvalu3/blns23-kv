#include "drbg.hpp"

#include <cstring>
#include <stdexcept>
#include <sys/random.h>

namespace blnskv {

Drbg::Drbg(const Seed &seed) {
  shake256_inc_init(&ctx_);
  shake256_inc_absorb(&ctx_, seed.data(), seed.size());
  shake256_inc_finalize(&ctx_);
}

Drbg Drbg::from_os() {
  Seed seed(48);
  size_t off = 0;
  while (off < seed.size()) {
    ssize_t r = getrandom(seed.data() + off, seed.size() - off, 0);
    if (r <= 0)
      throw std::runtime_error("getrandom() failed");
    off += static_cast<size_t>(r);
  }
  return Drbg(seed);
}

Drbg Drbg::from_u64(uint64_t x) {
  Seed seed(8);
  for (int i = 0; i < 8; i++)
    seed[i] = static_cast<uint8_t>(x >> (8 * i));
  return Drbg(seed);
}

void Drbg::fill(uint8_t *out, size_t n) {
  // Counter mode: squeeze blocks under an ever-increasing counter so that
  // output length does not affect the stream prefix of other outputs.
  size_t off = 0;
  while (off < n) {
    shake256incctx round = ctx_; // copy state
    uint64_t ctr_le = counter_++;
    shake256_inc_absorb(&round, reinterpret_cast<uint8_t *>(&ctr_le), 8);
    shake256_inc_finalize(&round);
    uint8_t block[SHAKE256_RATE];
    shake256_inc_squeeze(block, SHAKE256_RATE, &round);
    size_t take = std::min(n - off, sizeof(block));
    std::memcpy(out + off, block, take);
    off += take;
  }
}

std::vector<uint8_t> Drbg::bytes(size_t n) {
  std::vector<uint8_t> out(n);
  fill(out.data(), n);
  return out;
}

uint64_t Drbg::next_below(uint64_t bound) {
  if (bound == 0)
    throw std::invalid_argument("next_below(0)");
  // rejection sampling on the smallest word that covers bound
  if (bound <= (1u << 8)) {
    for (;;) {
      uint8_t b;
      fill(&b, 1);
      if (b < static_cast<uint8_t>(bound * (256 / bound)))
        return b % bound;
    }
  }
  for (;;) {
    uint64_t v;
    fill(reinterpret_cast<uint8_t *>(&v), 8);
    if (v < UINT64_MAX - (UINT64_MAX % bound))
      return v % bound;
  }
}

void xof(std::string_view domain, const std::vector<std::vector<uint8_t>> &parts,
         uint8_t *out, size_t outlen) {
  shake256incctx ctx;
  shake256_inc_init(&ctx);
  shake256_inc_absorb(&ctx, reinterpret_cast<const uint8_t *>(domain.data()),
                      domain.size());
  uint8_t sep = 0x00;
  for (const auto &p : parts) {
    shake256_inc_absorb(&ctx, &sep, 1);
    shake256_inc_absorb(&ctx, p.data(), p.size());
  }
  shake256_inc_finalize(&ctx);
  shake256_inc_squeeze(out, outlen, &ctx);
}

std::vector<uint8_t> xof(std::string_view domain,
                         const std::vector<std::vector<uint8_t>> &parts,
                         size_t outlen) {
  std::vector<uint8_t> out(outlen);
  xof(domain, parts, out.data(), outlen);
  return out;
}

} // namespace blnskv

// --- NFLlib glue -----------------------------------------------------------
// NFLlib's samplers call nfl::fastrandombytes(). We back it with a
// thread-local OS-seeded DRBG.
namespace nfl {
void fastrandombytes(unsigned char *r, unsigned long long n) {
  static thread_local blnskv::Drbg drbg = blnskv::Drbg::from_os();
  drbg.fill(r, static_cast<size_t>(n));
}
} // namespace nfl
