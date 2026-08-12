// End-to-end protocol tests with the mock NIZK.

#include "blnskv.hpp"
#include "minitest.hpp"

using namespace blnskv;
using P = ToyParams;

static std::vector<uint8_t> to_bytes(std::string_view s) {
  return {s.begin(), s.end()};
}

TEST(protocol_end_to_end) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();

  auto msg = to_bytes("cashu-note-serial-0001");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  auto resp = scheme.respond(sk, com, nizk);
  auto sig = scheme.finalize(sk.pk, st, resp, nizk);
  CHECK(sig.has_value());
  CHECK(scheme.verify(sk, msg, *sig));
}

TEST(protocol_wrong_message_rejected) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto msg = to_bytes("note-A");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  auto resp = scheme.respond(sk, com, nizk);
  auto sig = scheme.finalize(sk.pk, st, resp, nizk);
  CHECK(sig.has_value());
  CHECK(!scheme.verify(sk, to_bytes("note-B"), *sig));
}

TEST(protocol_tampered_rho_rejected) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto msg = to_bytes("note-C");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  auto resp = scheme.respond(sk, com, nizk);
  auto sig = scheme.finalize(sk.pk, st, resp, nizk);
  CHECK(sig.has_value());
  sig->rho[0] ^= 1;
  CHECK(!scheme.verify(sk, msg, *sig));
}

TEST(protocol_wrong_key_rejected) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk1 = scheme.keygen();
  auto sk2 = scheme.keygen();
  auto msg = to_bytes("note-D");
  auto [st, com] = scheme.commit(sk1.pk, msg, nizk);
  auto resp = scheme.respond(sk1, com, nizk);
  auto sig = scheme.finalize(sk1.pk, st, resp, nizk);
  CHECK(sig.has_value());
  CHECK(!scheme.verify(sk2, msg, *sig));
}

TEST(protocol_signer_deterministic_per_commitment) {
  // Same c must yield the same h (e3 is a PRF of c) -- otherwise two
  // responses to one c would leak s.
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto msg = to_bytes("note-E");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  auto r1 = scheme.respond(sk, com, nizk);
  auto r2 = scheme.respond(sk, com, nizk);
  Ring<P> ring;
  CHECK(ring.equal(r1.h, r2.h));
}

TEST(protocol_mint_learns_nothing_structure) {
  // Sanity: the commitment c must not trivially contain the message.
  // (Not a blindness proof -- just checks c looks unrelated to H(msg,rho).)
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto msg = to_bytes("note-F");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  Ring<P> ring;
  auto u = hash_to_vec<P>(ring, msg, st.rho);
  // c - u = B*r + e2 must NOT be zero (i.e. commitment actually blinded)
  auto blinded = ring.sub(com.c[0], u[0]);
  CHECK(!ring.equal(blinded, ring.zero_poly()));
}

TEST(protocol_signature_serialization_roundtrip) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto msg = to_bytes("note-serial-G");
  auto [st, com] = scheme.commit(sk.pk, msg, nizk);
  auto resp = scheme.respond(sk, com, nizk);
  auto sig = scheme.finalize(sk.pk, st, resp, nizk);
  CHECK(sig.has_value());
  auto bytes = scheme.serialize_sig(*sig);
  CHECK(bytes.size() == decltype(scheme)::SIG_BYTES);
  auto sig2 = scheme.deserialize_sig(bytes);
  CHECK(sig2.has_value());
  CHECK(scheme.verify(sk, msg, *sig2));
  // truncated / extended / corrupted forms must not verify
  auto truncated = bytes;
  truncated.pop_back();
  CHECK(!scheme.deserialize_sig(truncated).has_value());
  auto corrupted = bytes;
  corrupted.back() ^= 1;
  auto sig3 = scheme.deserialize_sig(corrupted);
  CHECK(!sig3.has_value() || !scheme.verify(sk, msg, *sig3));
}

TEST(protocol_many_random_runs_verify) {
  Scheme<P> scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  for (int i = 0; i < 25; i++) {
    auto msg = to_bytes("note-" + std::to_string(i));
    auto [st, com] = scheme.commit(sk.pk, msg, nizk);
    auto resp = scheme.respond(sk, com, nizk);
    auto sig = scheme.finalize(sk.pk, st, resp, nizk);
    CHECK(sig.has_value());
    CHECK(scheme.verify(sk, msg, *sig));
  }
}

RUN_ALL_TESTS()
