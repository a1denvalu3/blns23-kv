# Implementation roadmap

Status legend: [x] done, [~] partial, [ ] open.

Testing is not a phase at the end — each milestone has its own testing
deliverables, and there is a continuous testing track (section T) at the
bottom whose items gate milestone acceptance.

## M0 — Protocol skeleton (DONE)

- [x] Repo scaffold, CMake, vendored deps (NFLlib patched, fips202, labrador
      submodule behind `BLNSKV_WITH_LABRADOR`)
- [x] Ring arithmetic: NTT/RNS ops (NFLlib), CRT reconstruction + exact
      rounding (boost::multiprecision), canonical serialization
- [x] Protocol: keygen / commit / respond / finalize / verify
- [x] MockNizk exercising the real relations (witness re-checking)
- [x] Signature wire format (`serialize_sig`/`deserialize_sig`), 64 B at toy
      params
- [x] `blnskv-demo` end-to-end roundtrip with sizes/timings
- [x] `blnskv-bench` benchmark harness (per-stage protocol timings +
      primitive ops, toy and paper-shape parameters) — see "Benchmarks"
- [x] Testing: cross-validated NTT vs. schoolbook reference, property tests
      (rounding stability, signer determinism), negative tests (wrong
      key/msg/rho, truncated/corrupted wire formats) — see T1–T4

## M1 — Real round-2 proof (pi2) via LaBRADOR

Conceptual background on the vendored proof system and how pi2 maps onto
its constraint language: [docs/labrador-primer.md](labrador-primer.md).

The signer-side relation is a pure lattice relation and maps directly onto
LaBRADOR:

    witness (short):  s, e1  (ternary vectors),  e3 (ternary poly)
    public:           B, t, c, h
    constraints:      h - sᵀc - e3 = 0
                      t - sᵀB - e1ᵀ = 0
                      ||s||, ||e1||, ||e3|| small (ternary norm bounds)

Tasks:
- [ ] Read labrador's `constraints.h`/`proofsystem.h` API; write
      `src/nizk_labrador.cpp` implementing `Nizk<P>::prove_response` /
      `verify_response`. Dev/test loop works locally without AVX-512: the
      library compiles with pinned Ice Lake-class flags (any x86-64
      toolchain) and its self-tests run under Intel SDE
      (`tools/sde-external-*`, registered as `labrador-jlproj` /
      `labrador-smoke` ctest entries; the full 72-instance sweep binary
      `labrador-test-round` is built for manual runs on real hardware).
- [ ] Parameter mapping: LaBRADOR works over its own proof modulus; confirm
      the relation modulus vs. our Q (likely prove mod each RNS prime, or
      pick Q to match a LaBRADOR-friendly modulus — co-design with M2)
- [ ] Benchmarks on an AVX-512 machine (none locally — needs remote host);
      record pi2 prove/verify time and proof size in docs/benchmarks.md —
      this is the first public performance data for this scheme, so numbers
      are a deliverable in their own right
- [ ] Testing: soundness suite for pi2 — false statements (wrong h, wrong t,
      non-ternary witness) must fail verification; mutated proof transcripts
      rejected; mock vs. LaBRADOR cross-checks on identical instances (T4)
- Acceptance: pi2 proves/verifies on AVX-512; proof size measured; mock
  replaced in `respond`/`finalize` behind the same `Nizk<P>` interface.

## M2 — ZK-friendly hash + parameter co-design (the core research task)

The round-1 proof must prove `rho = H_rho(r, e2)` and `u = H_to_ring(msg,
rho)` inside the NIZK. SHAKE256 is what makes the paper's issuance slow.

- [ ] Choose the hash family. Options and tensions:
  - Poseidon2/Monolith over a prime field — field/prime must embed into the
    proof system's arithmetic (mismatch with 62-bit NTT primes needs care).
    **Working implementation landed:** Poseidon2 over Goldilocks
    (`src/poseidon2.hpp`, Plonky3-KAT-tested), now backing
    `hash_rho`/`hash_to_vec`. Remaining for this item: confirm it against the
    proof-system co-design below, or replace it if that analysis says so.
  - RainHash-style binary-field hashes (cheap in VOLEitH; unclear in
    LaBRADOR)
  - Lattice-native (Ajtai/SIS-style) "hash" — cheapest to prove, but it is
    NOT a random oracle; the OMUF analysis changes (research question!)
- [ ] Parameter search tooling: script (sage + lattice-estimator) computing
  dimension/Q/noise-margin/rounding-failure probability jointly with the
  hash choice
- [x] Implement chosen hash behind the existing `hashring.hpp` interface
      (Poseidon2/Goldilocks; byte encoding and sponge in `src/poseidon2.hpp`,
      swap confined to `src/hashring.hpp`)
- [ ] Testing: golden KAT vectors for the hash (T2); differential test
  against a reference implementation of the chosen hash (T1); documented
  rounding-failure probability < 2^-80 with a statistical test harness (T3)
- Acceptance: hash-to-ring provable in the target proof system at <1s
  marginal cost.

## M3 — Round-1 proof (pi1) with hash-in-ZK

- [ ] Express pi1 (hashes + linear relation + ternary bounds) in the
      LaBRADOR constraint language
- [ ] Benchmark end-to-end issuance latency (the paper's open question:
      ~30 min with SHA-in-ZK, target <5 s with a ZK-friendly hash — document
      the measured ratio); iterate on parameters
- [ ] Testing: soundness suite for pi1 (wrong c, wrong rho, non-ternary r/e2
      all rejected); attack regression test demonstrating the unit-vector
      key-recovery attack when pi1 is bypassed (T5)
- Acceptance: full issuance (commit+respond) with REAL proofs, total prover
  time target < 5 s on desktop for v1 (paper estimated ~30 min with SHA;
  the whole point is beating this by ~100x).

## M4 — Paper-scale parameters & hardening

- [ ] Exercise the NMOD=3 path (Q ~ 2^186), PaperShapeParams
- [ ] Testing: constant-time review + dudect-style timing tests on
      secret-dependent ops (NTT, rounding, PRF) (T7); libFuzzer harnesses on
      all deserializers/parsers with seeded corpus in CI (T6); golden
      end-to-end vectors + versioned domain separators (T2)
- Acceptance: reproducible vectors; clean fuzz runs; timing leaktight within
  measurement noise.

## M5 — Ecash integration sketch

- [ ] Note format: mint signs `H(serial)`; amount binding via per-amount
      keysets (Cashu-style) or committed amount in msg
- [ ] Double-spend check = seen-(rho,v) table at the mint
- [ ] Wallet/mint API mapping to Cashu NUTs (mint/swap/melt flows)
- [ ] Testing: integration tests against a stub mint server (double-spend
      rejection, concurrent issuance, malformed API inputs)
- Acceptance: interoperable demo against a stub mint server.

## Benchmarks

BLNS23 has essentially no public implementations (the authors never released
code), so timing data is a project deliverable in itself. Harness:
`blnskv-bench [--iters N]`, results collected in `docs/benchmarks.md`.

- [x] Harness: per-stage protocol timings (keygen/commit/respond/finalize/
      verify) + primitive ops (mul/matvec/inner/round/serialize), toy and
      paper-shape parameters
- [x] First numbers recorded (mock NIZK, see docs/benchmarks.md)
- [ ] M1: pi2 LaBRADOR prove/verify time + proof size (AVX-512 host)
- [ ] M3: end-to-end issuance with real proofs — headline metric
- [ ] M4: reproducible benchmark table in docs (CPU, flags, params, code
      hash), CI benchmark regression check

## Open problems (research-level)

- OMUF proof for the rounded-PRF construction with the *replaced* hash (the
  paper's argument is SHAKE-in-ROM; a SIS-style hash needs a new argument)
- QROM vs ROM analysis
- Concurrent-session security bounds
- Proving e3 = PRF_K(c) inside pi2 is currently NOT done (K is the signer's
  secret; determinism protects the signer, not verified by user) — revisit
  if the security analysis needs it

## T — Testing track (continuous)

Cryptographic protocol code needs several orthogonal layers; each catches a
different failure class. Items marked [x] exist and run in `ctest`.

1. [x] **Cross-validation / differential testing** — optimized components
   checked against an independent, obviously-correct reference (NTT vs.
   schoolbook in `test_ring.cpp`).
   - [ ] Extend: second independent implementation of the full scheme (Sage
         or Python) cross-checked on random seeds (M4)
2. [ ] **Known-answer tests (KATs)** — fixed seed => fixed bytes for all
   deterministic functions (DRBG, hashes, serialization); golden JSON
   vectors, regenerated only deliberately (M2/M4)
3. [x] **Property tests** — protocol invariants on random inputs: rounding
   agreement under small noise, signer determinism per commitment,
   serialize/deserialize roundtrips
4. [x] **Negative & forgery tests** — wrong key/message/rho rejected,
   malformed commitments and truncated/corrupted wire formats rejected
   - [ ] Extend: soundness tests for the real NIZK — false statements and
         mutated Fiat-Shamir transcripts must not verify (M1/M3)
5. [ ] **Attack regression tests** — known attacks as executable tests; e.g.
   bypass pi1, send `c = e_i`, show `h` leaks `s_i` (M3)
6. [ ] **Fuzzing** — libFuzzer on every byte-parsing entry point
   (signatures, commitments, proofs), corpus in CI (M4)
7. [ ] **Side-channel testing** — dudect-style timing oracles on
   secret-handling paths; constant-time review of NTT/rounding/PRF (M4)
8. [ ] **Interop vectors** — cross-implementation test vectors if/when a
   second implementation exists (M4+)
