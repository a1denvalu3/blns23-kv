# LaBRADOR primer: how the vendored proof system proves lattice relations

Companion explainer for the M1 milestone (a LaBRADOR-backed NIZK adapter,
`src/nizk_labrador.cpp`). It covers the concepts behind LaBRADOR
(Beullens–Seiler, [ePrint 2022/1341](https://eprint.iacr.org/2022/1341)) as
realized by the vendored code in `third_party/labrador/` — a re-implementation
that also underlies Orthus (ePrint 2026/398) and the *Toolkit for Succinct
Lattice-Based Zero Knowledge Proofs* work (see `third_party/labrador/README.md`).
Read this alongside `docs/how-it-works.md`, which explains the BLNS23 scheme
itself.

## 1. What LaBRADOR proves

LaBRADOR proves knowledge of a short witness — a collection of vectors of
polynomials over the proof ring — satisfying a set of linear and quadratic
constraints plus norm bounds. Everything is non-interactive from the start
(Fiat–Shamir throughout, see §2).

The vendored types map one-to-one onto this (`proofsystem.h`):

- `witness`: `r` vectors of `poly`s, lengths `n[i]`, all concatenated in one
  buffer `s`. The witness lives over LaBRADOR's own ring
  `R_q = Z_q[X]/(X^N + 1)` with `N = 256` and proof modulus
  `PS_Q = 2^LOGQ - QOFF` (≈ 2^38 by default; `LOGQ`, `N`, `QOFF` are set in
  `data.h`, not `labrador_core.h`).
- `statement`: the public side. Per witness vector: a squared ℓ2 bound
  `normsq[i]`, a norm *type* `normty[i]`, and optionally `normsq_req[i]`, the
  bound the proof is required to actually guarantee (see the slack discussion
  in §2). Plus two constraint sets: `rqcnst` (constraints over the full ring
  `R_q`) and `zqcnst` (constraints on constant coefficients only, i.e.
  statements over `Z_q`), and a 16-byte Fiat–Shamir state `h`.

The constraint language (`constraints.h`):

- `quadfunc(s) = Σ_i coeffs[i] · ⟨s[rows[i]], s[cols[i]]⟩` — a quadratic form
  over the witness vectors, stored sparsely (`rows`/`cols`/`coeffs`).
- `linfunc(s) = ⟨φ, s⟩` — a sparse linear form; `rank > 1` means the inner
  product is taken over an extension ring.
- `sparsecnst`: one equation `quadfunc(s) + linfunc(s) = b`. This is the
  workhorse: `ldr_aggregate_*` ultimately folds *everything* into a single
  `sparsecnst`.
- `comcnst`: a commitment constraint `Σ scalar·⟨comkey, s⟩ + ⟨φ, s⟩ = b`,
  tying witness blocks to values committed under the global commitment key
  (used internally by the protocol's own recursion checks).
- `zqcnstset` additionally has `sigmam1cnst` (`c·σ₋₁(s₁) = s₂`, where `σ₋₁`
  is the negacyclic automorphism `X ↦ −X⁻¹`) and `intcnst` ("this polynomial
  is a constant"). These exist because constant-coefficient tricks are how
  exact statements about `Z_q` are encoded.

The four `normtype`s (`proofsystem.h`):

- `L2EXACT` — the claimed ℓ2 bound is proven exactly.
- `L2APPROX` — the bound is proven only up to a slack factor, via a
  Johnson–Lindenstrauss projection (§2). Cheap, and sufficient whenever the
  application tolerates the gap.
- `BIN` — all coefficients are in `{0,1}`. `compile_bincnst` (in
  `proofsystem.c`) compiles this away: it appends `σ₋₁(s)` as an extra witness
  vector, links it with a `sigmam1cnst`, and adds a `Z_q` constraint whose
  constant coefficient is `Σ (sᵢ² − sᵢ) = 0` — which, together with the norm
  bound, forces binarity.
- `NONORM` — no norm claim.

A plain statement/witness pair can be checked directly with `verify()`
(`proofsystem.c`) — norm checks, binary checks, then `rqcnstset_check` /
`zqcnstset_check`. The proof system exists because this direct check sends
the whole witness; LaBRADOR replaces it with a much smaller proof plus a
much smaller residual statement.

## 2. Core mechanisms

**Witness commitment (Module-SIS).** There is one global commitment key
`comkey`, expanded from a public seed by `comkey_init` (`comkey.c`);
`commit(out, in)` (`proofsystem.c`) computes an inner product
`⟨comkey, s⟩` over an extension ring. This is an Ajtai/Module-SIS
commitment: binding under SIS, and the *only* thing hiding the witness is
that the committed vector is short and the key is compressing. Commitments
of garbage terms and decompositions are what the prover's messages consist
of; `SIS1_NCOEF` (32) is the coefficient count needed for SIS hardness at
infinity norm 1 (`proofsystem.h`).

**Fiat–Shamir aggregation.** A statement carries many constraints; the
prover must not have to answer for each one separately. All challenges are
derived from a running 16-byte shake128 state (`update_hash_polz`, the
`sample_chal*` functions in `proofsystem.c`). `ldr_aggregate_zq` and
`ldr_aggregate_rq` (`labrador.c`) take random challenge-weighted sums of the
`Z_q` constraints (including the JL projection constraint, see below) and of
the `R_q` constraints, collapsing the whole statement into **one**
`sparsecnst` — one quadratic equation in the witness. Soundness is the
usual Schwartz–Zippel-style argument: a cheating prover that violates any
individual constraint fails the aggregated one with overwhelming probability
over the challenge. Because constraint coefficients wrap around modulo
`PS_Q`, the aggregation is done in `LIFTS = ⌈128/LOGQ⌉` lifted copies so the
constant coefficient holds over the integers, not just mod `q`.

**Approximate norm proofs via JL projections.** Instead of proving
`‖s‖₂ ≤ β` directly, the verifier's hash is used to expand a random
projection matrix with coefficients in `{−1, 0, +1}` (`jl_sample_mat`,
`proofsystem.c`; the `P(±1)=1/4, P(0)=1/2` distribution is built as the
halved difference of two `±1` matrices, `jlproj.c`). The prover sends the
256-dimensional projection `p = Π·s` **in the clear** (`jl_project`), and
the verifier checks `‖p‖₂² ≤ 337 · normsq_global` (`ldr_reduce`). Two facts
make this work (`proofsystem.h`, comments on the `JL_*` macros):

- *Completeness:* a random projection of a short vector stays short with
  high probability — `‖Πs‖∞ < 9.75·‖s‖₂` (`JL_INF_MULT 9.75`), and
  `‖Πs‖₂² < 337·‖s‖₂²` (`JL_L2_MULT 337`).
- *Soundness, with slack:* if `‖s‖₂` were much larger, the projection would
  exceed the bound with high probability — but only once
  `‖s‖₂ > (9.75/0.74)·β ≈ 13.2·β` (`JL_INF_SLACK`). So an accepted proof
  guarantees a bound that is a constant factor *looser* than the claimed one.
  `normsq_req` in the statement records what the proof actually guarantees;
  the `JL_*_MAXNORM` macros give the range of bounds for which the trick is
  applicable at a given `PS_Q`.

The key algebraic point: the projection relation `Π·s = p` is **linear** in
`s`, so after the challenge is fixed it folds into the same aggregated
`sparsecnst` as everything else (`jl_aggregate_mat` /
`jl_aggregate_proj`). Revealing 256 noisy-ish linear combinations of a long
witness is exactly the amortization LaBRADOR's analysis accounts for.

**The prove/reduce recursion.** `ldr_prove` and `ldr_reduce`
(`labrador.c`) are two views of one round:

- `ldr_prove(pi, ost, owt, ist, iwt, pp)`: commits to the (split) witness,
  computes the "garbage" cross-terms `g_ij = ⟨s_i, s_j⟩` and
  `h_ij = ⟨s_i, φ_j⟩` that arise when expanding the aggregated constraint
  over an amortized opening `z = Σ chal_i·s_i`, commits to everything
  (messages `pi->m[0..3]`, plus the JL projection `pi->p`), and outputs a
  *new, smaller* statement/witness pair `(ost, owt)` attesting that all the
  commitments and decompositions were formed correctly.
- `ldr_reduce(ost, ist, pi, pp)`: the verifier's re-derivation of `ost`
  from the input statement and the proof alone. It re-checks the JL norm
  bound (return 1 on failure) and that the lifting polynomials have zero
  constant coefficient (return 2), then replays the Fiat–Shamir chain and
  rebuilds the check constraints (`ldr_addchecks`). It never sees the
  witness.

The crucial observation (from the paper): *verifying one round is itself a
lattice relation*, so rounds compose. `test_labrador.c`
(`test_ldr_prove_reduce_composite`) shows the loop: repeat
`lab_params_gen` → `ldr_prove` → `ldr_reduce`, feeding each round's output
statement into the next, until `pibits + owtbits` stops improving on the
input witness size — then open the final small witness in the clear
(the `tail` flag in `lab_params_gen`; `labrador_tail.c`). `lab_params_gen`
(`labrador_core.c`) is where witness splitting, commitment ranks
(`kappa[3]`: inner/middle/outer), and decomposition bases (`bz`, `bu`,
`bg`) are chosen, subject to `sis_secure`.

A minimal single-round usage, distilled from `test_labrador.c` and
`test_proofsystem_setup.c`:

```c
witness_init(iwt, r, r);
ps_witness_set(iwt, sxl, &sxq, &nn, &iwtbits, len, seed, &nonce); // ternary
comkey_init(nn);                                                  // SIS key
statement_init(ist, r, r);
ps_statement_set(ist, iwt, sxl, sxq, nn, ncnst, seed, &nonce);    // cnsts
verify(ist, iwt);                          // sanity: statement holds

lab_params_gen(pp, &pibits, &owtbits, ist, 0, 0, 0, 1, 1, JL_L2_SLACK);
ldr_prove(pi, ostp, owt, ist, iwt, pp);    // prover
ret = ldr_reduce(ostv, ist, pi, pp);       // verifier, no witness
verify(ostv, owt);                         // residual statement checks out
```

## 3. Our round-2 proof (pi2) in LaBRADOR terms

The signer-side relation (`src/nizk.hpp`, `ResponseStatement`/`ResponseWitness`)
is, with public `B, t, c, h` and ternary witness `s, e1, e3`:

```
h  =  sᵀ·c + e3          (one ring element)
t  =  sᵀB + e1ᵀ          (K ring elements)
```

Both equations are **linear in the witness** — `c` and `B` are public
constants, so `s ↦ sᵀc` and `s ↦ sᵀB` are just linear forms over `R_q`. The
natural encoding is therefore:

- `witness` with `r = 3` vectors: `s` (length `K`), `e1` (length `K`),
  `e3` (length 1).
- `K + 1` `sparsecnst`s in `rqcnst`, each with an **empty** `quadfunc`
  (`len = 0`): the `linfunc` parts are built from the public `c` and rows of
  `B`, and `b` holds the corresponding coefficients of `h` and `t`. The
  quadratic machinery in `constraints.h` still runs internally — LaBRADOR's
  own garbage terms are quadratic — but our statement needs no quadratic
  constraints of its own.
- Ternary bounds. Two options, both expressible:
  - `L2APPROX` with `normsq[i] = n[i]·N` (the convention in
    `ps_statement_set`): ternary vectors meet this exactly, and the proof
    guarantees the bound up to the JL slack (~13× in norm). Whether pi2's
    soundness can tolerate a witness that is merely *somewhat short* rather
    than ternary is a design question for M1.
  - Exactness via binary decomposition: write `s = s⁺ − s⁻` with
    `s⁺, s⁻` binary (`BIN`), disjointness enforced by the norm bound. This
    doubles the witness but proves ternarity exactly. (`BIN` alone proves
    `{0,1}`, not `{−1,0,1}`.)

**The modulus question — the open M1 co-design item.** Our scheme works in
`R_Q` with composite `Q` = product of `NMOD` 62-bit NTT primes and degree
`D` (`src/params.hpp`: `D=256, NMOD=1` toy; `D=4096, NMOD=3` paper-shape).
LaBRADOR works in `R_q` with a single prime-ish `PS_Q ≈ 2^38` and `N = 256`
(`data.h`). The relation `h = sᵀc + e3` holds mod `Q`; a LaBRADOR proof
establishes it mod `PS_Q`. As `docs/roadmap.md` notes, the options are:

- prove the relation mod each RNS prime of `Q` separately (one statement per
  prime, or one statement whose constraints embed all of them), or
- pick `Q` (or one factor of it) to match a LaBRADOR-friendly modulus and
  degree, co-designed with the M2 hash choice.

The degree mismatch at paper shape (`D = 4096` vs `N = 256`) must be
absorbed either by splitting each of our polynomials into 16 blocks of
degree 256 or by restructuring the relation coefficient-wise. Toy params
(`D = 256`) line up with LaBRADOR's `N` exactly, which is where the first
adapter should be built.

**Implementation status.** The adapter exists: `src/nizk_labrador.{hpp,cpp}`
(`LabradorNizk<P>`, ToyParams only) builds exactly the `r = 5` witness and
the `K + 1` rank-1 `sparsecnst`s described above, computes the quotient
polynomials by exact integer convolution, drives the composite
prove/reduce loop, and serializes the transcript. It uses the
quotient-lifting option with `L2APPROX` bounds on the quotient blocks;
the soundness question above remains open and is tracked in the roadmap.
Interop notes for anyone touching that file: the vendored headers are C99
(`double complex` prototypes, VLA parameters) and are neutralized via a
macro + an empty `src/labrador_cxx_shim/complex.h`; `data.h` leaks short
macros (`N`, `K`, `L`, `T`, `SLACK`) that must be `#undef`ed after the
includes; `polz` wire values range over `[0, 2^LOGQ)` (a lift constant
coefficient can be exactly `PS_Q`); the two vendored fips202 copies
resolve to one copy at link time without intervention.

## 4. Practical notes

- **AVX-512 only.** The submodule does not compile or run without AVX-512
  codegen (`immintrin.h` / `__m512i` throughout `data.h`, `jlproj.c`, the
  NTT). We compile with pinned Ice Lake-class flags, which works on any
  x86-64 toolchain; *running* needs AVX-512 hardware or Intel SDE (the
  `labrador-jlproj`/`labrador-round` ctest entries run under SDE when it is
  unpacked in `tools/`). Emulation is fine for the functional dev loop but
  timings under it are meaningless — M1 benchmarking still needs a remote
  AVX-512 host (roadmap M1).
- **Research-grade.** The submodule README warns the code has not undergone
  security review, testing, or validation for production. Same posture as
  the rest of this repo: fine for measuring pi2, not for shipping.
- **What M1 concretely builds** (`docs/roadmap.md`): ~~`src/nizk_labrador.cpp`
  implementing `Nizk<P>::prove_response`/`verify_response`~~ — built, see
  §3's implementation-status note. Remaining: benchmarks (pi2 prove/verify
  time, proof size) into `docs/benchmarks.md` on an AVX-512 host.
- **Testing deliverables (M1/T4):** soundness suite — wrong `h`, wrong `t`,
  non-ternary witness must fail `ldr_reduce`/`verify`; mutated transcripts
  rejected; mock vs. LaBRADOR cross-checks on identical instances. Note the
  adapter boundary is a natural fuzzing/negative-test surface: statement
  translation bugs are silent completeness failures, so keep the
  `verify(ist, iwt)` sanity check from the test harness in debug builds.
- `e3 = PRF_K(c)` determinism is *not* proven inside pi2 (roadmap, "Open
  problems") — the proof only covers the linear relations and bounds.

## Where to start reading the code

1. `third_party/labrador/README.md` — provenance, warnings, build constraints.
2. `third_party/labrador/proofsystem.h` — `statement`/`witness`, norm types,
   the `JL_*` constants and what they promise.
3. `third_party/labrador/constraints.h` — the constraint language
   (`quadfunc`/`linfunc`/`sparsecnst`/`comcnst`), as doc comments.
4. `third_party/labrador/labrador.c` — `ldr_prove`/`ldr_reduce` top to
   bottom; the whole protocol in ~250 lines.
5. `third_party/labrador/test_labrador.c` + `test_proofsystem_setup.c` — how
   a statement and witness are actually filled in and driven through a round.
6. `third_party/labrador/proofsystem.c` — `verify`, `commit`,
   `compile_bincnst`, the Fiat–Shamir helpers.
