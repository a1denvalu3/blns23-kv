# blns23-kv

A C++ implementation of the **keyed-verification blind signature** from

> W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler.
> *Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal.*
> ACM CCS 2023 / ePrint 2023/077 (Section 1.2, Fig. 5).
>
> Local copy: [docs/blns23-eprint-2023-077.pdf](docs/blns23-eprint-2023-077.pdf)
> (mirrored from https://eprint.iacr.org/2023/077).

A gentle walkthrough of the construction (including the rounding trick and
why verification needs no ZK machinery) lives in
[docs/how-it-works.md](docs/how-it-works.md).

The scheme is a lattice analogue of the hashed-Diffie-Hellman OPRF: a
signature on `msg` is `(rho, v)` with `v = round(s^T * H(msg, rho))`, which
only the holder of the secret `s` can verify — the trust model of keyed-
verification anonymous tokens (e.g. Chaumian ecash, Privacy Pass), where the
issuing server is also the only verifier.
Signatures are **48 bytes** at the paper's parameters.

**Status: research prototype.** Functional end-to-end with a mock NIZK at toy
parameters. See "Security" below before touching anything real.

## Protocol

Two rounds (round-optimal), over `R_Q = Z_Q[X]/(X^D+1)`, vectors of length K:

```
user                                    server (s, e1; pk = (B, t = sᵀB + e1ᵀ))
----                                    ------
r, e2 ← ternary
rho = H_rho(r, e2)
u   = H(msg, rho)
c   = B·r + e2 + u
pi1 = NIZK{ c well-formed }
                c, pi1  ──►
                                          e3 = PRF_K(c)   (deterministic per c!)
                                          h  = sᵀ·c + e3
                                          pi2 = NIZK{ h, t consistent w/ s }
                          h, pi2  ◄──
v = round(h − tᵀ·r)                        = round(sᵀu + tiny noise)
signature = (rho, v)
```

Keyed verification: `v == round(sᵀ·H(msg, rho))`. The rounding absorbs the
small noise `sᵀe2 + e3 − e1ᵀr`, which is why the modulus Q must be large
relative to that noise.

Blindness: `c` is a hiding commitment to `(msg, rho)`. One-more
unforgeability: for a fresh message, `H(msg, rho)` is a fresh random-oracle
output and `round(sᵀu)` is LWE-pseudorandom.

## Layout

```
src/
  params.hpp     parameter presets (ToyParams, PaperShapeParams)
  ring.hpp       R_Q arithmetic adapter over NFLlib (NTT, RNS); CRT +
                 exact rounding via boost::multiprecision (header-only)
  sampling.hpp   uniform / ternary samplers
  drbg.hpp       SHAKE256 counter-DRBG (also backs nfl::fastrandombytes)
  hashring.hpp   H_rho / H_to_ring (Poseidon2 over Goldilocks, see below)
  nizk.hpp       NIZK interface + MockNizk (INSECURE, witness-embedding)
  blnskv.hpp     the protocol (keygen / commit / respond / finalize / verify)
tests/           ring + end-to-end protocol tests
third_party/     vendored NFLlib (GMP-stripped), fips202, labrador submodule
```

## Build & test

```bash
git submodule update --init
cmake -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
./build/blnskv-demo   # end-to-end roundtrip with sizes/timings
```

Requirements: C++20 compiler, CMake ≥ 3.22, Boost headers
(`boost/multiprecision`), Linux (getrandom). No GMP/MPFR needed.

LaBRADOR NIZK backend (AVX-512 machines only):

```bash
cmake -B build -DBLNSKV_WITH_LABRADOR=ON
```

## Security — read this

- **Toy parameters are not secure.** `ToyParams` (D=256, K=4, one 62-bit
  prime) exists to test correctness of the arithmetic and protocol flow.
- **MockNizk is not a proof system.** It embeds the witness in cleartext.
  Zero privacy, zero succinctness. It only exists so the protocol flow and
  the witness-generating arithmetic can be tested.
- **H_to_ring is Poseidon2, not yet co-designed with the proof system.**
  `H_rho`/`H_to_ring` now use Poseidon2 over the Goldilocks field
  (`src/poseidon2.hpp`), which is ~100x cheaper to prove in ZK than the
  SHAKE256 placeholder it replaced. Still open: embedding the hash field
  into the proof system's arithmetic and re-doing the parameter analysis
  (roadmap M2).
- No side-channel hardening, no constant-time guarantees, no audits.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the full plan (M1: LaBRADOR
adapter for pi2, M2: ZK-friendly hash + parameter co-design, M3: round-1
hash-in-ZK, M4: hardening, M5: ecash integration) including the testing
strategy. Short version:

- [x] M0: ring arithmetic (NFLlib NTT/RNS), full protocol flow with mock
      NIZK, signature wire format, demo binary, tests
- [ ] M1: LaBRADOR-backed `Nizk` adapter for the round-2 relation (primer:
      [docs/labrador-primer.md](docs/labrador-primer.md))
- [ ] M2: ZK-friendly hash-to-ring + parameter co-design
- [ ] M3: round-1 relation with hash-in-ZK
- [ ] M4: paper-scale parameters, benchmarks, hardening
- [ ] M5: Cashu-style ecash integration sketch

## License

MIT (see [LICENSE](LICENSE)). Vendored components under `third_party/`
retain their own licenses (MIT / Apache-2.0 / public domain — see
[third_party/VENDOR.md](third_party/VENDOR.md)).
