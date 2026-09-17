// End-to-end demo of the single-key cut-and-choose KVBS (cckvbs.hpp):
// mint keygen -> user commits (2*kappa branches, aggregate + leaves) ->
// mint peels and responds -> user finalizes -> mint verifies. Prints wire
// sizes and per-stage timings.
//
// NOTE: toy parameters + mock NIZK. Sizes marked [*] are witness-sized mock
// proofs, not the final proof sizes. The paper's 145,888-byte msg1 figure
// assumes 152-bit Q and carries neither mu_0 nor the chi hint; our Q is
// 186 bits wide (see params.hpp) and msg1 additionally carries mu_0 and chi.

#include "cckvbs.hpp"

#include <chrono>
#include <cstdio>
#include <memory>

using namespace blnskv;
using Clock = std::chrono::steady_clock;

static double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

template <typename P, size_t KAPPA> static int run(const char *name) {
  using Sch = cc::Scheme<P, KAPPA>;
  Sch scheme;
  MockNizk<P> nizk;
  Ring<P> ring;

  std::printf("=== cc-kvbs demo [%s] (kappa=%zu, MOCK proofs) ===\n", name,
              KAPPA);
  std::printf("ring: D=%zu K=%zu NMOD=%zu, log2(Q) ~ %zu, rounding p=%lu\n",
              P::D, P::K, P::NMOD, static_cast<size_t>(msb(ring.Q()) + 1),
              (unsigned long)P::ROUND_P);

  auto t0 = Clock::now();
  // heap: at the paper shape a SigningKey holds ~13MB of matrix
  auto sk_ptr = std::make_unique<typename Sch::SigningKey>();
  scheme.keygen_into(*sk_ptr);
  const auto &sk = *sk_ptr;
  double t_keygen = ms_since(t0);
  if (!Sch::valid_public_key(sk.pk)) {
    std::printf("valid_public_key FAILED\n");
    return 1;
  }

  typename Sch::SessionId sid;
  sid.issuer.fill(0xA0);
  sid.key_epoch.fill(0x01);
  auto drbg_user = Drbg::from_os();
  auto un = drbg_user.bytes(16);
  std::copy_n(un.begin(), 16, sid.user_nonce.begin());
  auto sn = Drbg::from_os().bytes(16);
  std::copy_n(sn.begin(), 16, sid.signer_nonce.begin());

  std::string mstr = "age>=18; serial 2026-0001";
  std::vector<uint8_t> M(mstr.begin(), mstr.end());

  t0 = Clock::now();
  auto [st, m1] = scheme.user_commit(sk.pk, sid, M, drbg_user);
  double t_commit = ms_since(t0);

  t0 = Clock::now();
  auto resp = scheme.signer_respond(sk, m1, nizk);
  double t_respond = ms_since(t0);
  if (!resp) {
    std::printf("signer_respond FAILED\n");
    return 1;
  }

  t0 = Clock::now();
  auto cred = scheme.user_finalize(sk.pk, st, *resp, nizk);
  double t_finalize = ms_since(t0);
  if (!cred) {
    std::printf("user_finalize FAILED\n");
    return 1;
  }

  t0 = Clock::now();
  bool ok = scheme.verify(sk, *cred);
  double t_verify = ms_since(t0);

  size_t sz_msg1 = Sch::MSG1_BYTES;
  size_t sz_h = ring.serialize(resp->h).size();
  size_t sz_pi = resp->pi.bytes.size();
  size_t sz_cred = scheme.serialize_credential(*cred).size();
  auto payload = Sch::finalize_payload(sid.issuer,
                                       std::span<const uint8_t>(
                                           reinterpret_cast<const uint8_t *>("age-check"), 9),
                                       *cred);
  auto nul = Sch::nullifier(*cred, std::span<const uint8_t>(
                                       reinterpret_cast<const uint8_t *>("shop-42"), 7));
  std::printf("payload[0..3]=%02x%02x%02x%02x nullifier[0..3]=%02x%02x%02x%02x\n",
              payload[0], payload[1], payload[2], payload[3], nul[0], nul[1],
              nul[2], nul[3]);

  std::printf("\n--- sizes (bytes) ---\n");
  std::printf("msg1 (sid,c_agg,seeds,leaves,mu_0,chi) %9zu\n", sz_msg1);
  if constexpr (std::is_same_v<P, CutAndChooseParams>) {
    std::printf("  (paper msg1 at kappa=512:           145888   [assumes "
                "152-bit Q, no mu_0/chi])\n");
    std::printf("  ours  at kappa=512:                 %9zu\n",
                cc::Scheme<CutAndChooseParams, 512>::MSG1_BYTES);
  }
  std::printf("response h                          %9zu\n", sz_h);
  std::printf("pi_resp (mock [*])                  %9zu\n", sz_pi);
  std::printf("CREDENTIAL (M,phi0,deltas,rhos,v)   %9zu   <- the ecash note\n",
              sz_cred);

  std::printf("\n--- timings ---\n");
  std::printf("keygen    %9.2f ms\n", t_keygen);
  std::printf("commit    %9.2f ms   (2*kappa branch expansions, offline)\n",
              t_commit);
  std::printf("respond   %9.2f ms   (kappa expansions + peel + mock pi)\n",
              t_respond);
  std::printf("finalize  %9.2f ms   (incl. rounding)\n", t_finalize);
  std::printf("verify    %9.2f ms   <- the hot path\n", t_verify);

  std::printf("\nroundtrip: %s\n\n", ok ? "OK (credential verifies)" : "FAILURE");
  return ok ? 0 : 1;
}

int main() {
  int rc = run<ToyParams, 8>("toy params");
  // The paper's operating point is kappa=512; that run takes minutes with the
  // mock tooling, so the demo runs the paper shape at kappa=64. The msg1 size
  // line above prints both kappa=512 figures for comparison.
  rc |= run<CutAndChooseParams, 64>("paper shape, reduced kappa");
  return rc;
}
