// End-to-end demo of the BLNS23 keyed-verification blind signature:
// mint keygen -> user commits -> mint responds -> user finalizes ->
// mint verifies. Prints object sizes and per-stage timings.
//
// NOTE: toy parameters + mock NIZK. Sizes marked [*] are witness-sized mock
// proofs, not the final proof sizes.

#include "blnskv.hpp"

#include <chrono>
#include <cstdio>

using namespace blnskv;
using Clock = std::chrono::steady_clock;

static double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

int main() {
  using P = ToyParams;
  Scheme<P> scheme;
  MockNizk<P> nizk;
  Ring<P> ring;

  std::printf("=== blns23-kv demo (toy params, MOCK proofs) ===\n");
  std::printf("ring: D=%zu K=%zu NMOD=%zu, log2(Q) ~ %zu, rounding p=%lu\n", P::D,
              P::K, P::NMOD, static_cast<size_t>(msb(ring.Q()) + 1),
              (unsigned long)P::ROUND_P);

  auto t0 = Clock::now();
  auto sk = scheme.keygen();
  double t_keygen = ms_since(t0);

  const int N = 5;
  double t_commit = 0, t_respond = 0, t_finalize = 0, t_verify = 0;
  size_t sz_c = 0, sz_pi1 = 0, sz_h = 0, sz_pi2 = 0, sz_sig = 0;
  bool ok = false;

  for (int i = 0; i < N; i++) {
    std::string m = "cashu-note-serial-" + std::to_string(i);
    std::vector<uint8_t> msg(m.begin(), m.end());

    t0 = Clock::now();
    auto [st, com] = scheme.commit(sk.pk, msg, nizk);
    t_commit += ms_since(t0);

    t0 = Clock::now();
    auto resp = scheme.respond(sk, com, nizk);
    t_respond += ms_since(t0);

    t0 = Clock::now();
    auto sig = scheme.finalize(sk.pk, st, resp, nizk);
    t_finalize += ms_since(t0);
    if (!sig) {
      std::printf("finalize FAILED\n");
      return 1;
    }

    t0 = Clock::now();
    ok = scheme.verify(sk, msg, *sig);
    t_verify += ms_since(t0);

    if (i == 0) {
      sz_c = ring.serialize(com.c).size();
      sz_pi1 = com.pi1.bytes.size();
      sz_h = ring.serialize(resp.h).size();
      sz_pi2 = resp.pi2.bytes.size();
      auto wire = scheme.serialize_sig(*sig);
      sz_sig = wire.size();
      // wire roundtrip sanity
      auto sig2 = scheme.deserialize_sig(wire);
      if (!sig2 || !scheme.verify(sk, msg, *sig2)) {
        std::printf("wire roundtrip FAILED\n");
        return 1;
      }
    }
  }

  std::printf("\n--- sizes (bytes) ---\n");
  std::printf("commitment c        %8zu\n", sz_c);
  std::printf("pi1 (mock [*])      %8zu\n", sz_pi1);
  std::printf("response h          %8zu\n", sz_h);
  std::printf("pi2 (mock [*])      %8zu\n", sz_pi2);
  std::printf("SIGNATURE (rho,v)   %8zu   <- the ecash note\n", sz_sig);
  std::printf("  (paper target:      48)\n");

  std::printf("\n--- timings (avg of %d) ---\n", N);
  std::printf("keygen    %8.2f ms\n", t_keygen);
  std::printf("commit    %8.2f ms   (incl. mock pi1)\n", t_commit / N);
  std::printf("respond   %8.2f ms   (incl. mock pi2)\n", t_respond / N);
  std::printf("finalize  %8.2f ms   (incl. rounding)\n", t_finalize / N);
  std::printf("verify    %8.2f ms   <- the hot path\n", t_verify / N);

  std::printf("\nroundtrip: %s\n", ok ? "OK (signature verifies)" : "FAILURE");
  return ok ? 0 : 1;
}
