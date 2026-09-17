// End-to-end tests for the single-key cut-and-choose KVBS (cckvbs.hpp) with
// the mock NIZK.

#include "cckvbs.hpp"
#include "minitest.hpp"

#include <chrono>
#include <cstdio>
#include <memory>

using namespace blnskv;
using P = ToyParams;
static constexpr size_t KAP = 8;
using Sch = cc::Scheme<P, KAP>;

static Sch::SessionId make_sid(uint8_t tag) {
  Sch::SessionId sid;
  sid.issuer.fill(0xA0);
  sid.key_epoch.fill(0x01);
  sid.user_nonce.fill(tag);
  sid.signer_nonce.fill(static_cast<uint8_t>(tag + 1));
  return sid;
}

static std::vector<uint8_t> to_bytes(std::string_view s) {
  return {s.begin(), s.end()};
}

struct Session {
  Sch::UserState st;
  Sch::Message1 m1;
  Sch::Response resp;
  Sch::Credential cred;
};

static Session run_session(Sch &scheme, MockNizk<P> &nizk,
                           const Sch::SigningKey &sk,
                           const std::vector<uint8_t> &M,
                           const Sch::SessionId &sid) {
  auto drbg = Drbg::from_os();
  Session s;
  auto [st, m1] = scheme.user_commit(sk.pk, sid, M, drbg);
  s.st = std::move(st);
  s.m1 = std::move(m1);
  auto resp = scheme.signer_respond(sk, s.m1, nizk);
  if (!resp)
    throw std::runtime_error("signer_respond rejected an honest msg1");
  s.resp = std::move(*resp);
  auto cred = scheme.user_finalize(sk.pk, s.st, s.resp, nizk);
  if (!cred)
    throw std::runtime_error("user_finalize rejected an honest response");
  s.cred = std::move(*cred);
  return s;
}

TEST(cc_end_to_end) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  CHECK(Sch::valid_public_key(sk.pk));
  auto M = to_bytes("age>=18; serial 0001");
  auto s = run_session(scheme, nizk, sk, M, make_sid(1));
  CHECK(scheme.verify(sk, s.cred));
  // payload / nullifier helpers produce 32-byte images
  auto payload =
      Sch::finalize_payload(s.m1.sid.issuer, to_bytes("age-check"), s.cred);
  auto nul = Sch::nullifier(s.cred, to_bytes("shop-42"));
  CHECK(payload.size() == 32 && nul.size() == 32);
}

TEST(cc_wrong_message_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto s = run_session(scheme, nizk, sk, to_bytes("note-A"), make_sid(2));
  auto bad = s.cred;
  bad.M = to_bytes("note-B");
  CHECK(!scheme.verify(sk, bad));
}

TEST(cc_flipped_rho_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto s = run_session(scheme, nizk, sk, to_bytes("note-C"), make_sid(3));
  auto bad = s.cred;
  bad.rho[0][0] ^= 1;
  CHECK(!scheme.verify(sk, bad));
}

TEST(cc_swapped_lane_at_presentation_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto s = run_session(scheme, nizk, sk, to_bytes("note-D"), make_sid(4));
  auto bad = s.cred;
  std::swap(bad.rho[0], bad.rho[1]);
  std::swap(bad.delta[0], bad.delta[1]);
  CHECK(!scheme.verify(sk, bad));
}

TEST(cc_corrupted_opened_seed_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC01); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(5), to_bytes("note-E"), drbg);
  m1.opened_seeds[0][0] ^= 1;
  CHECK(!scheme.signer_respond(sk, m1, nizk).has_value());
}

TEST(cc_corrupted_unopened_leaf_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC02); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(6), to_bytes("note-F"), drbg);
  m1.unopened_leaves[0][0] ^= 1;
  CHECK(!scheme.signer_respond(sk, m1, nizk).has_value());
}

TEST(cc_wrong_lane_seed_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC03); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(7), to_bytes("note-G"), drbg);
  std::swap(m1.opened_seeds[0], m1.opened_seeds[1]);
  CHECK(!scheme.signer_respond(sk, m1, nizk).has_value());
}

TEST(cc_sid_mismatch_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC04); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(8), to_bytes("note-H"), drbg);
  m1.sid.user_nonce[0] ^= 1;
  CHECK(!scheme.signer_respond(sk, m1, nizk).has_value());
}

TEST(cc_tampered_c_agg_rejected) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC05); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(9), to_bytes("note-I"), drbg);
  auto wire = scheme.serialize_msg1(m1);
  wire[Sch::SID_BYTES] ^= 1; // first byte of c_agg
  auto m1bad = scheme.deserialize_msg1(wire);
  CHECK(m1bad.has_value());
  CHECK(!scheme.signer_respond(sk, *m1bad, nizk).has_value());
}

TEST(cc_signer_deterministic_per_msg1) {
  // Same msg1 must yield the same h (e is a PRF of (K, sid, c_agg)) --
  // otherwise two responses to one input would leak s.
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC06); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(10), to_bytes("note-J"), drbg);
  auto r1 = scheme.signer_respond(sk, m1, nizk);
  auto r2 = scheme.signer_respond(sk, m1, nizk);
  CHECK(r1.has_value() && r2.has_value());
  Ring<P> ring;
  CHECK(ring.equal(r1->h, r2->h));
}

TEST(cc_two_session_splice_rejected) {
  // Mixing one lane of session B into session A's credential must not verify:
  // rho/delta are session-bound through sid (via H_rho / the branch hashes).
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto M = to_bytes("note-splice");
  auto a = run_session(scheme, nizk, sk, M, make_sid(11));
  auto b = run_session(scheme, nizk, sk, M, make_sid(12));
  auto splice = a.cred;
  splice.rho[2] = b.cred.rho[2];
  splice.delta[2] = b.cred.delta[2];
  CHECK(!scheme.verify(sk, splice));
  // and the honest credentials both verify (sanity)
  CHECK(scheme.verify(sk, a.cred));
  CHECK(scheme.verify(sk, b.cred));
}

TEST(cc_msg1_serialization_roundtrip) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC07); // fixed: deterministic tamper checks
  auto sid = make_sid(13);
  auto [st, m1] = scheme.user_commit(sk.pk, sid, to_bytes("note-K"), drbg);
  auto wire = scheme.serialize_msg1(m1);
  CHECK(wire.size() == Sch::MSG1_BYTES);
  auto back = scheme.deserialize_msg1(wire);
  CHECK(back.has_value());
  CHECK(scheme.serialize_msg1(*back) == wire);
  // the parsed message still responds and finalizes
  auto resp = scheme.signer_respond(sk, *back, nizk);
  CHECK(resp.has_value());
  CHECK(scheme.user_finalize(sk.pk, st, *resp, nizk).has_value());
  // truncated / extended forms are rejected by the parser
  auto truncated = wire;
  truncated.pop_back();
  CHECK(!scheme.deserialize_msg1(truncated).has_value());
  auto extended = wire;
  extended.push_back(0);
  CHECK(!scheme.deserialize_msg1(extended).has_value());
  // corrupted chi byte parses but the signer rejects it
  auto corrupted = wire;
  corrupted.back() ^= 0x01;
  auto m1bad = scheme.deserialize_msg1(corrupted);
  CHECK(!m1bad.has_value() ||
        !scheme.signer_respond(sk, *m1bad, nizk).has_value());
}

TEST(cc_credential_serialization_roundtrip) {
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto M = to_bytes("note-L");
  auto s = run_session(scheme, nizk, sk, M, make_sid(14));
  auto wire = scheme.serialize_credential(s.cred);
  CHECK(wire.size() == Sch::cred_bytes(M.size()));
  auto back = scheme.deserialize_credential(wire);
  CHECK(back.has_value());
  CHECK(scheme.verify(sk, *back));
  // truncated / corrupted forms must not verify
  auto truncated = wire;
  truncated.pop_back();
  CHECK(!scheme.deserialize_credential(truncated).has_value());
  auto corrupted = wire;
  corrupted.back() ^= 1; // inside v
  auto bad = scheme.deserialize_credential(corrupted);
  CHECK(!bad.has_value() || !scheme.verify(sk, *bad));
}

TEST(cc_mock_refuses_false_statement) {
  // The mock prover must throw when asked to prove a false R_resp statement.
  Sch scheme;
  MockNizk<P> nizk;
  auto sk = scheme.keygen();
  auto drbg = Drbg::from_u64(0xCC08); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk.pk, make_sid(15), to_bytes("note-M"), drbg);
  auto resp = scheme.signer_respond(sk, m1, nizk);
  CHECK(resp.has_value());
  Ring<P> ring;
  Sch::Poly h_bad = resp->h;
  ring.set_coeff(h_bad, 0, 0, ring.coeff(h_bad, 0, 0) + 1);
  bool threw = false;
  try {
    ResponseStatement<P> stmt{sk.pk.B, sk.pk.t, st.c_sel, h_bad};
    Sch::Poly e = Sch::response_error(sk.de_key, m1.sid, m1.c_agg);
    nizk.prove_response(ring, stmt, ResponseWitness<P>{sk.s, sk.e1, e});
  } catch (const std::logic_error &) {
    threw = true;
  }
  CHECK(threw);
}

TEST(cc_paper_shape_smoke) {
  // One full run at the paper's shape (d=64, n=93, p=4, log2(Q)=186). The
  // paper's kappa=512 is too slow for ctest here; kappa=64 exercises the same
  // code paths. See cc-demo for a larger run.
  using PS = cc::Scheme<CutAndChooseParams, 64>;
  PS scheme;
  MockNizk<CutAndChooseParams> nizk;
  auto t0 = std::chrono::steady_clock::now();
  // heap: a SigningKey at this shape holds ~13MB of matrix
  auto sk = std::make_unique<PS::SigningKey>();
  scheme.keygen_into(*sk);
  PS::SessionId sid;
  sid.issuer.fill(0xB0);
  sid.key_epoch.fill(0x01);
  sid.user_nonce.fill(0x11);
  sid.signer_nonce.fill(0x22);
  auto M = to_bytes("paper-shape smoke");
  auto drbg = Drbg::from_u64(0xCC09); // fixed: deterministic tamper checks
  auto [st, m1] = scheme.user_commit(sk->pk, sid, M, drbg);
  auto resp = scheme.signer_respond(*sk, m1, nizk);
  CHECK(resp.has_value());
  auto cred = scheme.user_finalize(sk->pk, st, *resp, nizk);
  CHECK(cred.has_value());
  CHECK(scheme.verify(*sk, *cred));
  double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("  cc_paper_shape_smoke (kappa=64) took %.1f s\n", secs);
}

RUN_ALL_TESTS()
