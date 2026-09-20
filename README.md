# blns23-kv

A C++ implementation of a **single-key cut-and-choose keyed-verification
blind signature** (cc-kvbs) — a variant of the BLNS23 lattice blind
signature that replaces its expensive round-1 NIZK with kappa parallel
cut-and-choose lanes under one signer key.

> Design and security analysis:
> [docs/single-key-cut-and-choose-kvbs.tex](docs/single-key-cut-and-choose-kvbs.tex)
> (rendered PDF alongside it).
>
> Base scheme: W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler.
> *Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal.*
> ACM CCS 2023 / ePrint 2023/077 (Section 1.2, Fig. 5).
> Local copy: [docs/blns23-eprint-2023-077.pdf](docs/blns23-eprint-2023-077.pdf)
> (mirrored from https://eprint.iacr.org/2023/077).

The scheme is a lattice analogue of the hashed-Diffie-Hellman OPRF: only
the holder of the secret `s` can verify a credential — the trust model of
keyed-verification anonymous tokens (e.g. Chaumian ecash, Privacy Pass),
where the issuing server is also the only verifier.
A gentle walkthrough of the underlying construction lives in
[docs/how-it-works.md](docs/how-it-works.md).

**Status: research prototype.** Functional end-to-end with a mock NIZK.
The variant's own analysis states the construction "must not be deployed
as a secure credential system" (its security rests on the isolated
ssHMLWE/SDI assumptions, not on a standard reduction). See "Security"
below before touching anything real.

## Protocol (cc-kvbs)

Two rounds, over `R_Q = Z_Q[X]/(X^D+1)`, vectors of length K, with kappa
cut-and-choose lanes. All lanes are bound to one hidden message `M`
through a publicly rerandomizable commitment `Com(M; phi) = U(M) + B_c·phi`
(the paper's message-binding strengthening; `M` doubles as the
double-presentation nullifier):

```
user                                    server (s, e1; pk = (B, t = sᵀB + e1ᵀ))
----                                    ------
per lane i, branch b ∈ {0,1}:
  z[i][b] ← seed
  (r, e2, Δ) = G(sid, i, b, z)
  ρ = H_rho(sid, i, b, r, e2)
  μ = Com(M; φ0 + Δ)
  c = B·r + e2 + H_R(i, μ, ρ)
  leaf = H_leaf(sid, i, b, c)
c_agg = Σ c ;  χ = H_chal(issuer, pk, sid, c_agg, μ0, leaves)

       c_agg, {z[i][χ_i]}, {leaf[i][1−χ_i]}, μ0, χ  ──►
                                          re-expand opened seeds, re-check,
                                          recompute χ (any failure → ⊥)
                                          C_sel = c_agg − Σ c[i][χ_i]
                                          e = H_De(K, sid, c_agg)  (deterministic!)
                                          h = sᵀ·C_sel + e
                                          π = NIZK{ h, t consistent w/ s }
                                   h, π  ◄──
v = round(h − tᵀ·Σ r_i*)                  = round(sᵀ·Σ H_R(i, μ_i*, ρ_i*) + noise)
credential = (M, φ0, {Δ_i*}, {ρ_i*}, v)
```

Keyed verification: the mint rebuilds each `μ_i*` from the presented
`(M, φ0, Δ_i*)` and checks `v == round(sᵀ·Σ H_R(i, μ_i*, ρ_i*))` exactly.
The rounding absorbs the cut-and-choose noise (~2κ+1 small terms), which
is why the modulus Q must be large relative to it. Selected seeds are
never presented — they would reveal the blinding and link issuance.

## Benchmarks

This machine (i7-1365U, 12 threads, `-O3`, mock proofs). Toy params
(D=256, K=4) at kappa=8; paper shape (D=64, K=93, Q ~ 2^186, p=4) at
kappa=64, with kappa=512 extrapolated linearly:

| stage | toy k=8 | paper shape k=64 | paper shape k=512 (extrap.) |
|---|---|---|---|
| keygen | 3.6 ms | 193 ms | 193 ms (one-time, kappa-independent) |
| commit (offline, user) | 11 ms | 616 ms | ~5 s |
| respond (signer) | 5.2 ms | 186 ms | ~1.5 s |
| finalize (user) | 2.6 ms | 44 ms | ~0.35 s |
| **verify (mint, hot path)** | 4.1 ms | **81 ms** | **~0.65 s** |

(Optimization history: cached-NTT matvec + lane parallelism + SHA-256 +
buffered DRBG took kappa=64 commit/respond/verify from 12.5 s / 3.9 s /
1.93 s to the above.)

## Wire sizes

| item | paper shape k=64 | paper shape k=512 |
|---|---|---|
| msg1 (sid, c_agg, seeds, leaves, mu_0, chi) | 289,872 B | 318,600 B |
| response h | 1,536 B | 1,536 B |
| pi_resp | 287,236 B (mock, not a real proof size) | — |
| credential: MAC part (kappa rho's + v) | 2,064 B | 16,400 B |
| credential: full note (M, phi0, deltas, rhos, v) | 98,813 B | ~780,000 B |

Two honest deltas against the paper's table: its msg1 figure (145,888 B)
assumes a 152-bit Q and carries no mu_0/chi — ours uses the closest
NFLlib RNS fit (186-bit Q) and adds an untrusted chi hint the signer
re-verifies; and its 32 KiB credential figure predates the message
binding — the rerandomization randomness (per-lane ternary deltas, 2-bit
packed) is what makes the full note ~762 KiB at kappa=512. The MAC part
matches the paper's 16,400 B exactly.

## The base scheme (blnskv.hpp)

`src/blnskv.hpp` implements the original BLNS23 protocol the variant
builds on: a single blinding vector `c = B·r + e2 + H(msg, rho)` with a
round-1 well-formedness NIZK (the expensive step the cut-and-choose
variant eliminates), deterministic signer error `e3 = PRF_K(c)`, and
`v = round(h − tᵀ·r)` unblinding. Signatures are 48 bytes at the paper's
parameters. It remains the reference for the pi2 LaBRADOR adapter work
(see roadmap); cc-kvbs reuses its `Nizk` interface for the response
proof and does not otherwise depend on it.

## Layout

```
src/
  cckvbs.hpp     the cut-and-choose protocol (the scheme; see above)
  blnskv.hpp     base BLNS23 protocol (building block / reference)
  params.hpp     parameter presets (CutAndChooseParams, ToyParams,
                 PaperShapeParams)
  ring.hpp       R_Q arithmetic adapter over NFLlib (NTT, RNS); CRT +
                 exact rounding via boost::multiprecision (header-only)
  sampling.hpp   uniform / ternary samplers
  drbg.hpp       SHAKE256 + SHA-256 counter-DRBGs (buffered streams)
  sha256.hpp     vendored SHA-256 (FIPS 180-4, KAT-tested)
  hashring.hpp   H_rho / H_to_ring (Poseidon2 over Goldilocks, see below)
  nizk.hpp       NIZK interface + MockNizk (INSECURE, witness-embedding)
examples/        cc-demo (the variant), blnskv-demo (base scheme)
tests/           ring + end-to-end protocol tests (incl. cckvbs, sha256)
third_party/     vendored NFLlib (GMP-stripped), fips202, labrador submodule
docs/            the cut-and-choose paper + supporting notes
```

## Build & test

```bash
git submodule update --init
cmake -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
./build/cc-demo        # cc-kvbs end-to-end roundtrip with sizes/timings
./build/blnskv-demo    # base scheme roundtrip
```

Requirements: C++20 compiler, CMake ≥ 3.22, Boost headers
(`boost/multiprecision`), Linux (getrandom). No GMP/MPFR needed.
No AVX-512 needed for anything above.

LaBRADOR NIZK backend (base scheme's pi2 only — not needed by cc-kvbs):

```bash
cmake -B build-lab -DBLNSKV_WITH_LABRADOR=ON && cmake --build build-lab -j
```

This **compiles** on any x86-64 toolchain (we pin an explicit Ice Lake-class
flag set instead of upstream's `-march=native`). **Running** the LaBRADOR
code needs AVX-512 hardware — or an emulator: unpack Intel SDE into
`tools/` and the vendored self-tests are registered with ctest through it:

```bash
curl -L -o tools/sde.tar.xz https://downloadmirror.intel.com/915934/sde-external-10.8.0-2026-03-15-lin.tar.xz
tar -xJf tools/sde.tar.xz -C tools
cmake -B build-lab -DBLNSKV_WITH_LABRADOR=ON   # re-run configure to pick up SDE
ctest --test-dir build-lab -R labrador --output-on-failure
```

Emulation is for functional testing only — timings under SDE are
meaningless, so benchmarking still needs an AVX-512 host (roadmap M1).

## Security — read this

- **The cc-kvbs paper says do not deploy.** Its security rests on two
  isolated assumptions (ssHMLWE, SDI) without standard reductions; the
  QROM analysis and several proof gaps are explicitly open.
- **Toy parameters are not secure.** `ToyParams` (D=256, K=4, one 62-bit
  prime) exists to test correctness of the arithmetic and protocol flow.
  `CutAndChooseParams` is a paper-flavoured shape with a wider Q
  (186 vs 152 bits) and unvalidated parameters.
- **MockNizk is not a proof system.** It embeds the witness in cleartext.
  Zero privacy, zero succinctness. It only exists so the protocol flow and
  the witness-generating arithmetic can be tested.
- **Operational conventions are load-bearing** (session-id freshness,
  key validation, both-or-neither delivery) and are the caller's
  responsibility — see the `cckvbs.hpp` header.
- **H_to_ring (base scheme) is Poseidon2, not yet co-designed with the
  proof system** (`src/poseidon2.hpp`). cc-kvbs sidesteps this: its
  hashes never appear inside a proof, and its XOF is plain SHA-256.
- No side-channel hardening, no constant-time guarantees, no audits.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the base-scheme plan. Short
version:

- [x] M0: ring arithmetic (NFLlib NTT/RNS), full protocol flow with mock
      NIZK, signature wire format, demo binary, tests
- [ ] M1: LaBRADOR-backed `Nizk` adapter for the round-2 relation (primer:
      [docs/labrador-primer.md](docs/labrador-primer.md))
- [ ] M2: ZK-friendly hash-to-ring + parameter co-design
- [ ] M3: round-1 relation with hash-in-ZK — **superseded for the
      cut-and-choose variant**, which eliminates the round-1 proof
      entirely (implemented in `cckvbs.hpp`; its remaining gaps are the
      mock response proof and the open items in the paper's Section 6)
- [ ] M4: paper-scale parameters, benchmarks, hardening
- [ ] M5: Cashu-style ecash integration sketch

## License

MIT (see [LICENSE](LICENSE)). Vendored components under `third_party/`
retain their own licenses (MIT / Apache-2.0 / public domain — see
[third_party/VENDOR.md](third_party/VENDOR.md)).
