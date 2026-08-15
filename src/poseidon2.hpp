#pragma once
//
// Poseidon2 over the Goldilocks field p = 2^64 - 2^32 + 1, width t = 12
// (rate 8 / capacity 4 -> 128-bit sponge security), S-box x^7, RF = 8 full
// rounds, RP = 22 partial rounds, per the Poseidon2 paper (ePrint 2023/323).
//
// Round constants and the internal-layer diagonal are the Grain-LFSR-generated
// values used by Plonky3 (goldilocks/src/poseidon2.rs); the permutation is
// validated against Plonky3's width-12 known-answer test in
// tests/test_poseidon2.cpp.
//
// Field arithmetic uses plain 128-bit multiply + reduce. This is a
// correctness-first implementation (hashing is not the hot path at the
// current parameters); optimize only if profiling says so.
//
// Poseidon2Xof is a byte-oriented sponge/XOF on top of the permutation with
// the same interface as Drbg (fill/bytes/next_below), so it can drive the
// samplers in sampling.hpp. Encoding (injective, see absorb()):
//   message = domain || 0x00 || for each part: u64le(len(part)) || part
//   packed 4 bytes per field element (little-endian, always < p)
// Squeeze: each rate element serialized as 8 little-endian bytes. A rate
// element is uniform in [0, p) with p/2^64 ~ 1 - 2^-32; for raw byte output
// (hash_rho) this bias is irrelevant, and for sampling (hash_to_vec) the
// downstream rejection sampler removes it.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace blnskv {
namespace poseidon2 {

constexpr uint64_t P = 0xFFFFFFFF00000001ULL; // 2^64 - 2^32 + 1
constexpr size_t WIDTH = 12;
constexpr size_t RATE = 8;
constexpr size_t HALF_FULL_ROUNDS = 4;
constexpr size_t PARTIAL_ROUNDS = 22;

using State = std::array<uint64_t, WIDTH>;

// --- field arithmetic --------------------------------------------------------

inline uint64_t fadd(uint64_t a, uint64_t b) {
  unsigned __int128 s = static_cast<unsigned __int128>(a) + b; // < 2p
  if (s >= P)
    s -= P;
  return static_cast<uint64_t>(s);
}

inline uint64_t fsub(uint64_t a, uint64_t b) { return a >= b ? a - b : a + (P - b); }

inline uint64_t fmul(uint64_t a, uint64_t b) {
  return static_cast<uint64_t>((static_cast<unsigned __int128>(a) * b) % P);
}

inline uint64_t pow7(uint64_t x) {
  uint64_t x2 = fmul(x, x);
  uint64_t x4 = fmul(x2, x2);
  return fmul(fmul(x4, x2), x);
}

// --- linear layers -----------------------------------------------------------

// The 4x4 MDS matrix used by Plonky3's Goldilocks Poseidon2 (apply_mat4),
// the circulant circ(2, 3, 1, 1):
//   [2 3 1 1]
//   [1 2 3 1]
//   [1 1 2 3]
//   [3 1 1 2]
inline void mds4(uint64_t *x) {
  uint64_t y0 = fadd(fadd(fadd(fmul(2, x[0]), fmul(3, x[1])), x[2]), x[3]);
  uint64_t y1 = fadd(fadd(fadd(x[0], fmul(2, x[1])), fmul(3, x[2])), x[3]);
  uint64_t y2 = fadd(fadd(fadd(x[0], x[1]), fmul(2, x[2])), fmul(3, x[3]));
  uint64_t y3 = fadd(fadd(fadd(fmul(3, x[0]), x[1]), x[2]), fmul(2, x[3]));
  x[0] = y0;
  x[1] = y1;
  x[2] = y2;
  x[3] = y3;
}

// External layer M_E = circ(2*M4, M4, M4): M4 per chunk, then each chunk
// element gets the element-wise sum over all chunks added.
inline void external_layer(State &s) {
  for (size_t c = 0; c < WIDTH; c += 4)
    mds4(&s[c]);
  std::array<uint64_t, 4> sums{};
  for (size_t c = 0; c < WIDTH; c += 4)
    for (size_t j = 0; j < 4; j++)
      sums[j] = fadd(sums[j], s[c + j]);
  for (size_t c = 0; c < WIDTH; c += 4)
    for (size_t j = 0; j < 4; j++)
      s[c + j] = fadd(s[c + j], sums[j]);
}

// Internal layer: s[i] = sum(s) + DIAG[i] * s[i].
inline void internal_layer(State &s) {
  static constexpr std::array<uint64_t, WIDTH> DIAG = {
      0xfffffffeffffffffULL, // -2
      0x0000000000000001ULL, // 1
      0x0000000000000002ULL, // 2
      0x7fffffff80000001ULL, // 1/2
      0x0000000000000003ULL, // 3
      0x0000000000000004ULL, // 4
      0x7fffffff80000000ULL, // -1/2
      0xfffffffefffffffeULL, // -3
      0xfffffffefffffffdULL, // -4
      0xbfffffff40000001ULL, // 1/2^2
      0x3fffffffc0000000ULL, // -1/2^2
      0xdfffffff20000001ULL, // 1/2^3
  };
  uint64_t sum = 0;
  for (uint64_t x : s)
    sum = fadd(sum, x);
  for (size_t i = 0; i < WIDTH; i++)
    s[i] = fadd(sum, fmul(DIAG[i], s[i]));
}

// --- round constants (Grain LFSR, field_type=1, alpha=7, n=64, t=12, --------
// --- RF=8, RP=22; same values as Plonky3) ------------------------------------

// clang-format off
static constexpr std::array<std::array<uint64_t, WIDTH>, HALF_FULL_ROUNDS>
    RC_EXTERNAL_INITIAL = {{
        {{0x13dcf33aba214f46ULL, 0x30b3b654a1da6d83ULL, 0x1fc634ada6159b56ULL,
          0x937459964dc03466ULL, 0xedd2ef2ca7949924ULL, 0xede9affde0e22f68ULL,
          0x8515b9d6bac9282dULL, 0x6b5c07b4e9e900d8ULL, 0x1ec66368838c8a08ULL,
          0x9042367d80d1fbabULL, 0x400283564a3c3799ULL, 0x4a00be0466bca75eULL}},
        {{0x7913beee58e3817fULL, 0xf545e88532237d90ULL, 0x22f8cb8736042005ULL,
          0x6f04990e247a2623ULL, 0xfe22e87ba37c38cdULL, 0xd20e32c85ffe2815ULL,
          0x117227674048fe73ULL, 0x4e9fb7ea98a6b145ULL, 0xe0866c232b8af08bULL,
          0x00bbc77916884964ULL, 0x7031c0fb990d7116ULL, 0x240a9e87cf35108fULL}},
        {{0x2e6363a5a12244b3ULL, 0x5e1c3787d1b5011cULL, 0x4132660e2a196e8bULL,
          0x3a013b648d3d4327ULL, 0xf79839f49888ea43ULL, 0xfe85658ebafe1439ULL,
          0xb6889825a14240bdULL, 0x578453605541382bULL, 0x4508cda8f6b63ce9ULL,
          0x9c3ef35848684c91ULL, 0x0812bde23c87178cULL, 0xfe49638f7f722c14ULL}},
        {{0x8e3f688ce885cbf5ULL, 0xb8e110acf746a87dULL, 0xb4b2e8973a6dabefULL,
          0x9e714c5da3d462ecULL, 0x6438f9033d3d0c15ULL, 0x24312f7cf1a27199ULL,
          0x23f843bb47acbf71ULL, 0x9183f11a34be9f01ULL, 0x839062fbb9d45dbfULL,
          0x24b56e7e6c2e43faULL, 0xe1683da61c962a72ULL, 0xa95c63971a19bfa7ULL}},
    }};

static constexpr std::array<std::array<uint64_t, WIDTH>, HALF_FULL_ROUNDS>
    RC_EXTERNAL_FINAL = {{
        {{0xc68be7c94882a24dULL, 0xaf996d5d5cdaedd9ULL, 0x9717f025e7daf6a5ULL,
          0x6436679e6e7216f4ULL, 0x8a223d99047af267ULL, 0xbb512e35a133ba9aULL,
          0xfbbf44097671aa03ULL, 0xf04058ebf6811e61ULL, 0x5cca84703fac7ffbULL,
          0x9b55c7945de6469fULL, 0x8e05bf09808e934fULL, 0x2ea900de876307d7ULL}},
        {{0x7748fff2b38dfb89ULL, 0x6b99a676dd3b5d81ULL, 0xac4bb7c627cf7c13ULL,
          0xadb6ebe5e9e2f5baULL, 0x2d33378cafa24ae3ULL, 0x1e5b73807543f8c2ULL,
          0x09208814bfebb10fULL, 0x782e64b6bb5b93ddULL, 0xadd5a48eac90b50fULL,
          0xadd4c54c736ea4b1ULL, 0xd58dbb86ed817fd8ULL, 0x6d5ed1a533f34dddULL}},
        {{0x28686aa3e36b7cb9ULL, 0x591abd3476689f36ULL, 0x047d766678f13875ULL,
          0xa2a11112625f5b49ULL, 0x21fd10a3f8304958ULL, 0xf9b40711443b0280ULL,
          0xd2697eb8b2bde88eULL, 0x3493790b51731b3fULL, 0x11caf9dd73764023ULL,
          0x7acfb8f72878164eULL, 0x744ec4db23cefc26ULL, 0x1e00e58f422c6340ULL}},
        {{0x21dd28d906a62ddaULL, 0xf32a46ab5f465b5fULL, 0xbfce13201f3f7e6bULL,
          0xf30d2e7adb5304e2ULL, 0xecdf4ee4abad48e9ULL, 0xf94e82182d395019ULL,
          0x4ee52e3744d887c5ULL, 0xa1341c7cac0083b2ULL, 0x2302fb26c30c834aULL,
          0xaea3c587273bf7d3ULL, 0xf798e24961823ec7ULL, 0x962deba3e9a2cd94ULL}},
    }};

static constexpr std::array<uint64_t, PARTIAL_ROUNDS> RC_INTERNAL = {
    0x4adf842aa75d4316ULL, 0xf8fbb871aa4ab4ebULL, 0x68e85b6eb2dd6aebULL,
    0x07a0b06b2d270380ULL, 0xd94e0228bd282de4ULL, 0x8bdd91d3250c5278ULL,
    0x209c68b88bba778fULL, 0xb5e18cdab77f3877ULL, 0xb296a3e808da93faULL,
    0x8370ecbda11a327eULL, 0x3f9075283775dad8ULL, 0xb78095bb23c6aa84ULL,
    0x3f36b9fe72ad4e5fULL, 0x69bc96780b10b553ULL, 0x3f1d341f2eb7b881ULL,
    0x4e939e9815838818ULL, 0xda366b3ae2a31604ULL, 0xbc89db1e7287d509ULL,
    0x6102f411f9ef5659ULL, 0x58725c5e7ac1f0abULL, 0x0df5856c798883e7ULL,
    0xf7bb62a8da4c961bULL,
};
// clang-format on

// --- permutation -------------------------------------------------------------

inline void full_round(State &s, const std::array<uint64_t, WIDTH> &rc) {
  for (size_t i = 0; i < WIDTH; i++)
    s[i] = pow7(fadd(s[i], rc[i]));
  external_layer(s);
}

inline void permute(State &s) {
  external_layer(s); // initial linear layer (Poseidon2, unlike Poseidon1)
  for (size_t r = 0; r < HALF_FULL_ROUNDS; r++)
    full_round(s, RC_EXTERNAL_INITIAL[r]);
  for (size_t r = 0; r < PARTIAL_ROUNDS; r++) {
    s[0] = pow7(fadd(s[0], RC_INTERNAL[r]));
    internal_layer(s);
  }
  for (size_t r = 0; r < HALF_FULL_ROUNDS; r++)
    full_round(s, RC_EXTERNAL_FINAL[r]);
}

} // namespace poseidon2

// --- byte-oriented sponge/XOF --------------------------------------------------
// Same interface as Drbg (fill/bytes/next_below) so it can drive sampling.hpp.

class Poseidon2Xof {
public:
  static constexpr size_t RATE = poseidon2::RATE;

  Poseidon2Xof(std::string_view domain,
               const std::vector<std::vector<uint8_t>> &parts) {
    // Injective encoding: domain || 0x00 || u64le(len) || part ...  The
    // length prefixes make distinct (domain, parts) tuples produce distinct
    // byte streams even after zero-padding to 4-byte groups.
    absorb_bytes(reinterpret_cast<const uint8_t *>(domain.data()),
                 domain.size());
    uint8_t sep = 0x00;
    absorb_bytes(&sep, 1);
    for (const auto &p : parts) {
      uint64_t len = p.size();
      uint8_t lenle[8];
      for (int i = 0; i < 8; i++)
        lenle[i] = static_cast<uint8_t>(len >> (8 * i));
      absorb_bytes(lenle, 8);
      absorb_bytes(p.data(), p.size());
    }
    flush_absorb();
  }

  void fill(uint8_t *out, size_t n) {
    size_t off = 0;
    while (off < n) {
      if (sq_pos_ == RATE * 8) {
        poseidon2::permute(state_);
        sq_pos_ = 0;
        for (size_t i = 0; i < RATE; i++)
          for (int j = 0; j < 8; j++)
            sq_buf_[i * 8 + j] = static_cast<uint8_t>(state_[i] >> (8 * j));
      }
      size_t take = std::min(n - off, RATE * 8 - sq_pos_);
      std::memcpy(out + off, sq_buf_ + sq_pos_, take);
      off += take;
      sq_pos_ += take;
    }
  }

  std::vector<uint8_t> bytes(size_t n) {
    std::vector<uint8_t> out(n);
    fill(out.data(), n);
    return out;
  }

  // Uniform in [0, bound) via rejection sampling (same algorithm as Drbg).
  uint64_t next_below(uint64_t bound) {
    if (bound == 0)
      throw std::invalid_argument("next_below(0)");
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

private:
  // Buffer bytes, pack 4 per field element (LE), absorb RATE elements per
  // permutation call. Trailing bytes are zero-padded by flush_absorb().
  void absorb_bytes(const uint8_t *in, size_t n) {
    size_t off = 0;
    while (off < n) {
      if (ab_pos_ == RATE * 4) {
        absorb_block();
        ab_pos_ = 0;
      }
      size_t take = std::min(n - off, RATE * 4 - ab_pos_);
      std::memcpy(ab_buf_ + ab_pos_, in + off, take);
      off += take;
      ab_pos_ += take;
    }
  }

  void absorb_block() {
    for (size_t i = 0; i < RATE; i++) {
      uint64_t e = 0;
      for (int j = 0; j < 4; j++)
        e |= static_cast<uint64_t>(ab_buf_[i * 4 + j]) << (8 * j);
      state_[i] = poseidon2::fadd(state_[i], e);
    }
    poseidon2::permute(state_);
  }

  void flush_absorb() {
    if (ab_pos_ > 0) {
      std::memset(ab_buf_ + ab_pos_, 0, RATE * 4 - ab_pos_);
      absorb_block();
      ab_pos_ = 0;
    }
    // first squeeze block
    for (size_t i = 0; i < RATE; i++)
      for (int j = 0; j < 8; j++)
        sq_buf_[i * 8 + j] = static_cast<uint8_t>(state_[i] >> (8 * j));
    sq_pos_ = 0;
  }

  poseidon2::State state_{};
  uint8_t ab_buf_[RATE * 4]{};
  size_t ab_pos_ = 0;
  uint8_t sq_buf_[RATE * 8]{};
  size_t sq_pos_ = RATE * 8; // forces block fill on first use (flush_absorb sets 0)
};

} // namespace blnskv
