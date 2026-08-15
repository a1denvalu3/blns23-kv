# How the BLNS23 keyed-verification blind signature works

Companion explainer for this repository's implementation of the
keyed-verification scheme from *Lattice-Based Blind Signatures: Short,
Efficient, and Round-Optimal* (Beullens, Lyubashevsky, Nguyen, Seiler —
CCS 2023, [ePrint 2023/077](https://eprint.iacr.org/2023/077), Section 1.2 /
Figure 5; local copy: `blns23-eprint-2023-077.pdf`).

## The template: same as BDHKE (Cashu's scheme)

Cashu's blind signature is a "hashed-Diffie-Hellman" OPRF: the user sends
`H(x)^r`, the mint returns `H(x)^{rk}`, the user unblinds by `r⁻¹` and keeps
`(x, C = H(x)^k)`. Verification needs the secret `k` — *keyed* verification,
which is fine for ecash because the mint is the only verifier. The signature
is nothing more than the PRF value `F_k(x)`.

The BLNS23 keyed-verification scheme transplants exactly this template to
lattices: the "PRF value" becomes a **rounded LWE sample** under the signer's
secret, evaluated at a hash of the message:

```
signature on msg  =  (rho, v)   with   v = round( sᵀ · H(msg, rho) )
```

Everything else in the protocol exists so that the user can learn this value
without revealing `msg` (or `rho`) to the signer.

## Setup

All arithmetic happens in a polynomial ring `R_q = Z_q[X]/(X^d + 1)` with
vectors of length `k`.

- Signer secret: a low-norm (ternary) polynomial vector **s**.
- Public key: a random k×k polynomial matrix **B**, and the MLWE sample
  **t**ᵀ = **s**ᵀ**B** + **e**₁ᵀ (with **e**₁ ternary). The public key is not
  needed for verification — only for the zero-knowledge proofs during
  issuance.

## Issuance (2 rounds, round-optimal)

**Round 1 — user commits.** The user picks ternary randomness (**r**, **e**₂),
sets

```
rho = H_rho(r, e2)              (a short tag binding the randomness)
u   = H(msg, rho)               (hash into the ring)
c   = B·r + e2 + u              (hiding commitment to (msg, rho))
```

and sends `c` plus a NIZK `pi1` that `c` is well-formed (knowledge of ternary
`r, e2` consistent with the hashes). Putting the randomness inside the hash
forces `c` to be uniform and outside the user's control — this is what
one-more unforgeability hinges on.

**Round 2 — signer evaluates.** The signer computes an LWE sample of `c`
under its secret:

```
h = sᵀ·c + e3
```

plus a NIZK `pi2` proving `h` is consistent with the same `s` that appears in
the public key `t`. Two important details:

- **`e3` is generated deterministically** as `e3 = PRF_K(c)`. Otherwise a
  malicious user could send the same `c` twice, receive `sᵀc + e3` and
  `sᵀc + e3'`, subtract, and start learning about `s`.
- **No "noise drowning"** (huge masking error term) is needed — that is the
  key relaxation versus a full VOPRF, and what keeps the modulus and lattice
  dimension from blowing up even further.

## The agreement trick

Watch what happens when the user subtracts **t**ᵀ·**r** from `h`:

```
h − tᵀ·r  =  sᵀ(B·r + e2 + u) + e3  −  (sᵀB + e1ᵀ)·r
          =  sᵀ·u   +   ( sᵀe2 + e3 − e1ᵀr )
             └── PRF value ──┘   └── small noise ──┘
```

The user obtained `sᵀu` plus small garbage. Since the signer can compute
`sᵀu` *exactly*, both parties **round each coefficient to its top few bits**
(`round(·)`), and with overwhelming probability they agree on

```
v  =  round( sᵀ·u )
```

For the rounding to agree, the modulus `q` must dwarf the worst-case noise
`sᵀe2 + e3 − e1ᵀr` — this is the dominant constraint on the parameters.

## The signature and verification

```
sig = (rho, v)     ->     2λ + d·log p bits  =  48 bytes at paper parameters
```

Verification is **keyed**: the mint, knowing `s`, recomputes
`u = H(msg, rho)` and checks `v == round(sᵀ·u)`. No zero-knowledge proofs are
involved in verification at all — just a hash, an inner product, and a
rounding. Extremely fast, and the verification path never touches the
expensive machinery.

## Why it's blind and why it's unforgeable

- **Blindness:** `c` is a uniformly distributed, hiding commitment to
  `(msg, rho)`; everything else is proven in zero knowledge. The signer never
  sees `rho`, so it cannot recognize `(msg, rho, v)` later.
- **One-more unforgeability:** for any *fresh* message, `u = H(msg, rho)` is
  a fresh random-oracle output, and `round(sᵀu)` is pseudorandom under the
  LWE assumption — you cannot predict it for a message you did not get
  issued. Binding `u` to `H(msg, rho)` is essential: if the user could choose
  `u` freely, linearity attacks like `u' = u_1 + u_2` would work.

## The asterisk: why the paper says "more work is needed"

The 48-byte signature and the cheap verification are real; **issuance** is
the bottleneck. For the two roundings to agree, the modulus must dwarf the
accumulated noise, forcing `q ≈ 2^150` and lattice dimension ≈ 6000. That
makes the codomain of `H` huge, so the user's round-1 NIZK must prove
knowledge of preimages spanning ~2^12 ≈ 4096 SHA evaluations — estimated at
~30 minutes of proving with 2023-era techniques.

The paper's suggested fixes, which this repository is structured around:

1. **Swap in a ZK-friendly hash** (Poseidon2-style) for `H_rho`/`H_to_ring` —
   collapses the hash-in-ZK circuit by ~100x. **Done** in this repo: Poseidon2
   over the Goldilocks field (`src/poseidon2.hpp`), confined to
   `src/hashring.hpp`. What remains is co-designing the hash field with the
   proof system's arithmetic and the RNS primes of Q (roadmap M2).
2. **Prove with lattice-native proof systems** (LaBRADOR & successors)
   instead of proving SHA — the round-2 relation (`h = sᵀc + e3`,
   `t = sᵀB + e1ᵀ`) is already a pure lattice relation; the round-1 relation
   becomes one too once the hash is ZK-friendly. LaBRADOR is vendored as a
   submodule behind `BLNSKV_WITH_LABRADOR=ON` (requires AVX-512).

## Where the pieces live in this repo

| Concept | File |
|---|---|
| `R_q` arithmetic (NTT/RNS), CRT reconstruction, `round(·)` | `src/ring.hpp` |
| Ternary/uniform sampling | `src/sampling.hpp` |
| `H_rho`, `H_to_ring` (Poseidon2 over Goldilocks) | `src/hashring.hpp` |
| NIZK interface + mock prover | `src/nizk.hpp` |
| Protocol: keygen / commit / respond / finalize / verify | `src/blnskv.hpp` |
