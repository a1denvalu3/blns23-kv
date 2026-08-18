// Tests for the LaBRADOR-backed pi2 adapter (src/nizk_labrador.cpp).
//
// Runs under Intel SDE on hosts without AVX-512 (registered via the SDE
// launcher in tests/CMakeLists.txt). A single honest LaBRADOR proof is
// produced once and shared across the checks -- one composite prove costs
// minutes under emulation; the remaining checks are verify replays.

#include "blnskv.hpp"
#include "drbg.hpp"
#include "minitest.hpp"
#include "nizk.hpp"
#include "nizk_labrador.hpp"
#include "sampling.hpp"

#include <cstdio>

using namespace blnskv;
using P = ToyParams;

// Honest instance, proven once (lazy). pi2 is a real LaBRADOR proof; pi1 is
// mock inside the adapter.
struct Honest {
  Scheme<P>::SigningKey sk;
  Scheme<P>::UserState st;
  Scheme<P>::Commitment com;
  Scheme<P>::Response resp;
  ResponseStatement<P> rstmt;
  std::vector<uint8_t> msg;

  Honest() {
    Scheme<P> scheme;
    LabradorNizk<P> nizk;
    sk = scheme.keygen();
    msg = {'l', 'a', 'b', '1'};
    auto [st_, com_] = scheme.commit(sk.pk, msg, nizk);
    st = std::move(st_);
    com = std::move(com_);
    resp = scheme.respond(sk, com, nizk); // the LaBRADOR prove happens here
    rstmt = {sk.pk.B, sk.pk.t, com.c, resp.h};
    std::fprintf(stderr, "honest pi2 proof: %zu bytes\n", resp.pi2.bytes.size());
  }
};

static const Honest &honest() {
  static Honest h;
  return h;
}

TEST(labrador_e2e_roundtrip) {
  Scheme<P> scheme;
  LabradorNizk<P> nizk;
  const Honest &h = honest();
  auto sig = scheme.finalize(h.sk.pk, h.st, h.resp, nizk);
  CHECK(sig.has_value());
  CHECK(scheme.verify(h.sk, h.msg, *sig));
}

TEST(labrador_tampered_h_rejected) {
  const Honest &h = honest();
  Ring<P> ring;
  LabradorNizk<P> nizk;
  ResponseStatement<P> stmt = h.rstmt;
  typename Ring<P>::Poly one = ring.zero_poly();
  ring.set_coeff(one, 0, 0, 1);
  stmt.h = ring.add(stmt.h, one);
  CHECK(!nizk.verify_response(ring, stmt, h.resp.pi2));
}

TEST(labrador_flipped_byte_rejected) {
  const Honest &h = honest();
  Ring<P> ring;
  LabradorNizk<P> nizk;
  Proof bad = h.resp.pi2;
  CHECK(bad.bytes.size() > 16);
  bad.bytes[12] ^= 0x01; // inside the first round's m[0] commitment
  CHECK(!nizk.verify_response(ring, h.rstmt, bad));
}

TEST(labrador_mock_consistency) {
  // The same honest statement/witness must also prove and verify under the
  // mock backend: cross-check that the instance itself is genuinely valid,
  // not merely accepted by the adapter.
  const Honest &h = honest();
  Ring<P> ring;
  // Recompute e3 = PRF_K(c) exactly as Scheme::respond does.
  Drbg e3_drbg(xof("BLNSKV-E3-v0", {h.sk.prf_key, ring.serialize(h.com.c)}, 64));
  auto e3 = sample_ternary<P>(ring, e3_drbg);
  MockNizk<P> mock;
  Proof mp = mock.prove_response(ring, h.rstmt, {h.sk.s, h.sk.e1, e3});
  CHECK(mock.verify_response(ring, h.rstmt, mp));
}

RUN_ALL_TESTS()
