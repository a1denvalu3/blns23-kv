import React, { useState, useCallback, useEffect } from 'react';
import katex from 'katex';
import { WireBreakdown, MessageSizes, AttackCosts } from './Charts';

const T = String.raw;

function Tex({ children, block = false }) {
  const html = katex.renderToString(children, {
    displayMode: block,
    throwOnError: false,
    strict: false,
  });
  return block
    ? <div className="math-block" dangerouslySetInnerHTML={{ __html: html }} />
    : <span className="math" dangerouslySetInnerHTML={{ __html: html }} />;
}

/* ── Slide 0: Title ── */
function TitleSlide() {
  return (
    <div className="title-slide">
      <h1>Lattice-based<br />keyed-verification credentials</h1>
      <p className="subtitle">
        How to get a blind lattice credential without the expensive proof —
        one key, one summed commitment, and a challenge hash.
      </p>
      <p className="title-meta">Technical working session · September 2026 · Research draft — not for deployment</p>
    </div>
  );
}

/* ── Slide 1: Setting ── */
function SettingSlide() {
  return (
    <>
      <span className="tag tag-purple">Background</span>
      <h2>Keyed-verification credentials</h2>
      <p className="subtitle">
        A blind signature where issuing and checking use the same secret key —
        think of it as a MAC the user can obtain without showing its message.
      </p>
      <div className="cards three">
        <div className="card">
          <h3><span className="material-symbols-outlined">person</span>User</h3>
          <p>Runs one issuance with the signer, then <strong>unblinds</strong> the answer
          into a credential <Tex>{T`\sigma`}</Tex>. The signer never learns the message.</p>
        </div>
        <div className="card">
          <h3><span className="material-symbols-outlined">key</span>Signer</h3>
          <p>Holds a secret vector <Tex>{T`\mathbf{s}`}</Tex> and answers one blinded
          evaluation per issuance. Public key:{' '}
          <Tex>{T`\mathbf{t}^{T} = \mathbf{s}^{T} B + \mathbf{e}_1^{T}`}</Tex>.</p>
        </div>
        <div className="card">
          <h3><span className="material-symbols-outlined">verified</span>Verifier</h3>
          <p>Holds the <em>same</em> secret <Tex>{T`\mathbf{s}`}</Tex> and checks a
          credential by recomputing the same evaluation — no public-key signature
          involved.</p>
        </div>
      </div>
      <div className="callout d2">
        Our starting point is BLNS23 (ePrint 2023/077), a short lattice blind signature
        of this kind. Almost all of its issuance cost sits in one place: a proof the
        user must attach to its request. That proof is what we want to eliminate.
      </div>
    </>
  );
}

/* ── LWE: one noisy equation ── */
function LweSlide() {
  return (
    <>
      <h2>Learning with Errors: a noisy equation</h2>
      <p className="subtitle">
        Take a linear equation in a secret vector. Add a small, random error to its answer.
      </p>
      <div className="lesson-equation">
        <Tex block>{T`b = \langle \underbrace{\mathbf{a}}_{\text{public}},\, \underbrace{\mathbf{s}}_{\text{secret}} \rangle + \underbrace{e}_{\text{small error}} \pmod q`}</Tex>
      </div>
      <div className="cards d1">
        <div className="card">
          <h3>Generate one sample</h3>
          <p className="small">Toy arithmetic, modulo 17</p>
          <p><Tex>{T`\mathbf{a}=(4,7),\quad \mathbf{s}=(2,3),\quad e=1`}</Tex></p>
          <Tex block>{T`b = 4\cdot2 + 7\cdot3 + 1 = 30 \equiv 13 \pmod{17}`}</Tex>
        </div>
        <div className="card">
          <h3>Publish only the pair</h3>
          <Tex block>{T`(\mathbf{a},b)=\bigl((4,7),13\bigr)`}</Tex>
          <p>The secret and the error stay hidden. Repeat with the same secret,
          a fresh random vector, and fresh noise.</p>
        </div>
      </div>
      <div className="callout d2">
        <strong>Why add noise?</strong> Enough independent exact equations reveal the
        secret by linear algebra. With noise and suitable parameters, recovering it
        from many samples is assumed hard.
      </div>
      <p className="slide-source">Background: <a href="https://cims.nyu.edu/~regev/papers/lwesurvey.pdf" target="_blank" rel="noreferrer">Regev, The Learning with Errors Problem</a></p>
    </>
  );
}

/* ── No errors: recover the secret by elimination ── */
function NoiselessSystemSlide() {
  return (
    <>
      <h2>Without errors, solve for the secret</h2>
      <p className="subtitle">
        Two independent equations reveal the two secret coordinates.
        All arithmetic below is modulo 17.
      </p>
      <div className="cards d1">
        <div className="card">
          <h3>1. Observe two public equations</h3>
          <Tex block>{T`\begin{aligned}(1)\quad 4s_1+7s_2&\equiv12\\(2)\quad s_1+2s_2&\equiv8\end{aligned}`}</Tex>
          <p>Removing <Tex>{T`e=1`}</Tex> from our first sample changes
          its answer from 13 to 12. Add a second sample with public vector{' '}
          <Tex>{T`(1,2)`}</Tex> and answer 8.</p>
        </div>
        <div className="card">
          <h3>2. Eliminate the first unknown</h3>
          <p>Multiply equation (2) by 4:</p>
          <Tex block>{T`4s_1+8s_2\equiv32\equiv15`}</Tex>
          <p>Subtract equation (1) to cancel <Tex>{T`s_1`}</Tex>:</p>
          <Tex block>{T`(8-7)s_2\equiv15-12\quad\Rightarrow\quad s_2=3`}</Tex>
        </div>
      </div>
      <div className="callout d2">
        <strong>3. Substitute back into (2):</strong>{' '}
        <Tex>{T`s_1\equiv8-2\cdot3\equiv2`}</Tex>.
        The recovered secret is <Tex>{T`\boxed{\mathbf{s}=(2,3)}`}</Tex>.
      </div>
      <p className="small">
        This is Gaussian elimination: cancel one unknown, then substitute back.
        With noise, these operations also combine the unknown errors.
      </p>
    </>
  );
}

/* ── Module-LWE: polynomial vectors ── */
function MlweSlide() {
  return (
    <>
      <h2>Module Learning with Errors</h2>
      <p className="subtitle">
        The same noisy equation, now with vectors of polynomials.
      </p>
      <div className="cards d1">
        <div className="card">
          <h3>Numbers become polynomials</h3>
          <Tex block>{T`a(x)=a_0+a_1x+\cdots+a_{n-1}x^{n-1}`}</Tex>
          <p>Work in the ring <Tex>{T`R_q=\mathbb{Z}_q[x]/(x^n+1)`}</Tex>:
          coefficients wrap modulo <Tex>{T`q`}</Tex>, and{' '}
          <Tex>{T`x^n=-1`}</Tex> keeps the degree below <Tex>{T`n`}</Tex>.</p>
        </div>
        <div className="card">
          <h3>Vectors hold k polynomials</h3>
          <Tex block>{T`\mathbf{a},\mathbf{s}\in R_q^k,\qquad b=\sum_{j=1}^{k} a_j s_j+e`}</Tex>
          <p>Each entry is a polynomial. The error <Tex>{T`e`}</Tex> is a polynomial
          too, with small coefficients.</p>
        </div>
      </div>
      <div className="callout d2">
        One polynomial sample bundles <strong>n structured scalar equations</strong>.
        This structure makes arithmetic efficient and descriptions compact;
        Module-LWE assumes these noisy samples still look random.
      </div>
      <p className="small">In this credential construction:{' '}
        <Tex>{T`n=64,\quad k=93,\quad q\approx 2^{152}`}</Tex>.
      </p>
      <p className="slide-source">Background: <a href="https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf" target="_blank" rel="noreferrer">Kyber specification, §4.3: Module-LWE</a></p>
    </>
  );
}

/* ── Module-LWE: noisy Diffie–Hellman intuition ── */
function KeyExchangeSlide() {
  return (
    <>
      <h2>A Diffie–Hellman-style handshake</h2>
      <p className="subtitle handshake-subtitle">
        Public matrix <Tex>{T`B\in R_q^{k\times k}`}</Tex>;
        each party chooses secret vectors and errors with small coefficients.
      </p>
      <div className="seq handshake d1">
        <div className="actor">Alice · keeps <Tex>{T`\mathbf{s},\mathbf{e}_1`}</Tex></div>
        <div />
        <div className="actor">Bob · keeps <Tex>{T`\mathbf{r},\mathbf{e}_2`}</Tex></div>

        <div className="msg"><Tex>{T`\mathbf{t}^{T}=\mathbf{s}^{T}B+\mathbf{e}_1^{T}`}</Tex></div>
        <div className="chan">→</div>
        <div className="exchange-label">receives Alice’s public vector</div>

        <div className="exchange-label">receives Bob’s public vector</div>
        <div className="chan">←</div>
        <div className="msg"><Tex>{T`\mathbf{u}=B\mathbf{r}+\mathbf{e}_2`}</Tex></div>

        <div className="local"><Tex>{T`z_A=\mathbf{s}^{T}\mathbf{u}`}</Tex></div>
        <div className="chan">≈</div>
        <div className="local"><Tex>{T`z_B=\mathbf{t}^{T}\mathbf{r}`}</Tex></div>
      </div>
      <Tex block>{T`\left\lVert z_A-z_B\right\rVert_\infty=\left\lVert\mathbf{s}^{T}\mathbf{e}_2-\mathbf{e}_1^{T}\mathbf{r}\right\rVert_\infty\le\beta`}</Tex>
      <div className="callout d2">
        <strong>Reconciliation:</strong> Bob sends a public hint. Both sides recover
        identical bits from their nearby values, then hash those bits into a shared key.
      </div>
      <p className="small">Toy scalars modulo 97:{' '}
        <Tex>{T`B=9,\ s=3,\ r=2,\ e_1=1,\ e_2=-1`}</Tex>.{' '}
        <Tex>{T`(t,u)=(28,17),\quad(z_A,z_B)=(51,56)`}</Tex>.
      </p>
      <p className="slide-source">Norms use centered coefficients modulo q; β is the noise bound. Illustrative exchange; reconciliation: <a href="https://cryptojedi.org/papers/newhope-20160328.pdf" target="_blank" rel="noreferrer">NewHope</a>.</p>
    </>
  );
}

/* ── Slide 3: HMLWE ── */
function HmlweSlide() {
  return (
    <>
      <span className="tag tag-purple">Hardness assumption</span>
      <h2>HMLWE: hashing the input first</h2>
      <p className="subtitle">
        Same game, but the public vector is a hash output chosen by the attacker:
        “<Tex>{T`\mathbf{s}^{T}H(x)`}</Tex> looks random, even if you pick x.”
      </p>
      <div className="game">
        <div className="side real">
          <h4>Real oracle</h4>
          <div className="gline"><Tex>{T`\text{attacker picks a fresh } x`}</Tex></div>
          <div className="gline"><Tex>{T`\text{gets back } \mathbf{s}^{T} H(x) + e`}</Tex></div>
        </div>
        <div className="side ideal">
          <h4>Ideal oracle</h4>
          <div className="gline"><Tex>{T`\text{attacker picks a fresh } x`}</Tex></div>
          <div className="gline"><Tex>{T`\text{gets back an independent random value}`}</Tex></div>
        </div>
      </div>
      <ul className="d2">
        <li><strong>The assumption:</strong> nobody can tell the two oracles apart with
        meaningful probability.</li>
        <li><strong>BLNS23, Lemma 4.3:</strong> if we model the hash as an ideal random
        function, HMLWE and plain MLWE are equivalent — the hash output can stand in for
        the random public vector.</li>
        <li><strong>Why we care:</strong> then <Tex>{T`x \mapsto \mathbf{s}^{T} H(x)`}</Tex>{' '}
        behaves like a random function that only the key holder can compute — and that is
        exactly what a MAC is.</li>
      </ul>
    </>
  );
}

/* ── Slide 4: BLNS23 math ── */
function BlnsMathSlide() {
  return (
    <>
      <span className="tag tag-purple">BLNS23 mechanics</span>
      <h2>How the keyed-verification MAC works</h2>
      <div className="seq">
        <div className="actor">User</div>
        <div></div>
        <div className="actor">Signer / Verifier (same key <Tex>{T`\mathbf{s}`}</Tex>)</div>

        <div className="local">
          commit: <Tex>{T`u = H_R(m, \rho)`}</Tex>,{' '}
          <Tex>{T`c = B\mathbf{r} + \mathbf{e}_2 + u`}</Tex>
        </div>
        <div className="chan"></div>
        <div></div>

        <div className="msg"><Tex>{T`c`}</Tex> — blinded commitment</div>
        <div className="chan">→</div>
        <div></div>

        <div></div>
        <div className="chan">←</div>
        <div className="local">response <Tex>{T`h = \mathbf{s}^{T} c + e`}</Tex></div>

        <div className="local">
          unblind: <Tex>{T`v = \lceil h - \mathbf{t}^{T}\mathbf{r} \rfloor_4`}</Tex>
          <br /><span className="small">r never leaves the user</span>
        </div>
        <div className="chan"></div>
        <div></div>

        <div className="msg"><Tex>{T`(m, \rho, v)`}</Tex> — the credential</div>
        <div className="chan">→</div>
        <div className="local">check: <Tex>{T`v \overset{?}{=} \lceil \mathbf{s}^{T} H_R(m, \rho) \rfloor_4`}</Tex></div>
      </div>
      <div className="d2">
        <Tex block>{T`\textbf{Why it verifies:}\quad \mathbf{s}^{T} c - \mathbf{t}^{T} \mathbf{r} = \mathbf{s}^{T}(B\mathbf{r} + \mathbf{e}_2 + u) - (\mathbf{s}^{T}B + \mathbf{e}_1^{T})\mathbf{r} = \mathbf{s}^{T} u + \underbrace{(\mathbf{s}^{T}\mathbf{e}_2 - \mathbf{e}_1^{T}\mathbf{r})}_{\text{small error}} \approx \mathbf{s}^{T} H_R(m, \rho)`}</Tex>
      </div>
    </>
  );
}

/* ── Slide 5: why the user proof is needed ── */
function WhyProofSlide() {
  return (
    <>
      <span className="tag tag-red">Problem</span>
      <h2>The signer must not sign just anything</h2>
      <p className="subtitle">
        The signer computes <Tex>{T`h = \mathbf{s}^{T} c + e`}</Tex> on whatever{' '}
        <Tex>{T`c`}</Tex> shows up. A maliciously shaped{' '}
        <Tex>{T`c`}</Tex> leaks the key.
      </p>
      <div className="cards">
        <div className="card">
          <h3><span className="material-symbols-outlined">warning</span>Stealing the key</h3>
          <p>Send a unit vector <Tex>{T`c = \mathbf{e}_j`}</Tex>: the answer is{' '}
          <Tex>{T`h = s_j + e`}</Tex> — one key coordinate plus a little noise. Repeat per
          coordinate and the whole key falls out. Cost: essentially <strong>zero</strong>.</p>
        </div>
        <div className="card">
          <h3><span className="material-symbols-outlined">content_copy</span>Mix-and-match forgery</h3>
          <p>Pick <Tex>{T`c`}</Tex> to cancel what an earlier session contained and inject
          copied material: answers from different sessions can be recombined into new
          credentials for free.</p>
        </div>
      </div>
      <div className="callout bad d2">
        So BLNS23 makes the user prove: <em>“my c really is{' '}
        <Tex>{T`B\mathbf{r} + \mathbf{e}_2 + H_R(m, \rho)`}</Tex> for short{' '}
        <Tex>{T`\mathbf{r}, \mathbf{e}_2`}</Tex> and some{' '}
        <Tex>{T`(m, \rho)`}</Tex>.”</em> With that guarantee, c always contains an honest
        hash image, and the security proof can simulate the signer without knowing the key.
      </div>
    </>
  );
}

/* ── Slide 6: what the proof entails ── */
function ProofCostSlide() {
  return (
    <>
      <span className="tag tag-red">The expensive part</span>
      <h2>That proof contains hash evaluations — yikes</h2>
      <p className="subtitle">
        The statement to prove is not pure linear algebra: it contains{' '}
        <Tex>{T`u = H_R(m, \rho)`}</Tex>, i.e. a hash computation, inside a
        zero-knowledge proof.
      </p>
      <div className="cols">
        <div className="col">
          <h3>What providing that proof means</h3>
          <ul>
            <li>Rewrite the hash function as a big system of equations over the proof
            ring — one equation per internal gate.</li>
            <li>Thousands of constraints per hash evaluation, per commitment.</li>
            <li>All of it zero-knowledge, and small enough to send.</li>
          </ul>
        </div>
        <div className="col">
          <h3>Why it dominates issuance</h3>
          <ul>
            <li>The purely linear parts (<Tex>{T`B\mathbf{r} + \mathbf{e}_2`}</Tex>, norm
            bounds) are cheap — LaBRADOR-style proofs eat those for breakfast.</li>
            <li>The hash is the nonlinear part. It drives proof size, prover time, and
            code complexity.</li>
          </ul>
        </div>
      </div>
      <div className="callout warn d2">
        <strong>The goal:</strong> keep the blind credential, drop the hash proof.
        Cut-and-choose trades <em>proving every commitment correct</em> for{' '}
        <em>spot-checking a random subset</em> — and signing only the unchecked rest.
      </div>
    </>
  );
}

/* ── Slide 7: cut-and-choose k=2 ── */
function CcIntroSlide() {
  return (
    <>
      <span className="tag tag-purple">Cut-and-choose 101</span>
      <h2>Cut-and-choose: the basic idea (k = 2, live challenge)</h2>
      <div className="cc-flow">
        <div className="cc-step"><strong>1 · commit</strong>prepare two candidates<br /><Tex>{T`c_0,\; c_1`}</Tex></div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>2 · challenge</strong>verifier flips a coin<br /><Tex>{T`\chi \in \{0,1\}`}</Tex></div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>3 · open</strong>reveal branch <Tex>{T`\chi`}</Tex><br />fully checked</div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>4 · use</strong>branch <Tex>{T`1-\chi`}</Tex><br />used unchecked</div>
      </div>
      <div className="cc d1">
        <div className="branch opened">
          <div className="b-name">branch χ — opened</div>
          <p>Revealed in full; the verifier checks everything.</p>
          <div className="b-state">must be honest</div>
        </div>
        <div className="cc-arrow">⇢</div>
        <div className="branch used">
          <div className="b-name">branch 1−χ — selected</div>
          <p>Never opened, never checked — this is the one that gets used.</p>
          <div className="b-state">trusted by statistics</div>
        </div>
      </div>
      <ul className="d2">
        <li>A cheater must guess <em>which</em> branch will be checked, so one bad branch
        slips through with probability <Tex>{T`1/2`}</Tex>.</li>
        <li>The coin must be flipped <strong>after</strong> the commitment. That ordering
        is the entire mechanism — remember it.</li>
      </ul>
    </>
  );
}

/* ── Slide 8: scaling up ── */
function CcScaleSlide() {
  const lanes = [
    { i: 0, chi: 0 }, { i: 1, chi: 1 }, { i: 2, chi: 1 },
  ];
  return (
    <>
      <span className="tag tag-purple">Cut-and-choose 101</span>
      <h2>κ lanes at once</h2>
      <p className="subtitle">
        The verifier now flips κ independent coins, one per lane. Every lane has its
        opened half checked; the unopened halves are what get used.
      </p>
      <div className="lanes d1">
        {lanes.map(({ i, chi }) => (
          <div className="lane-row" key={i}>
            <div className="lane-name">lane {i}</div>
            <div className="lane-bit"><Tex>{T`\chi_${i} = ${chi}`}</Tex></div>
            <div className={`branchbox ${chi === 0 ? 'opened' : 'used'}`}>
              <Tex>{T`c_{${i},0}`}</Tex>
              <span className="b-state">{chi === 0 ? 'opened · checked' : 'selected · unchecked'}</span>
            </div>
            <div className={`branchbox ${chi === 1 ? 'opened' : 'used'}`}>
              <Tex>{T`c_{${i},1}`}</Tex>
              <span className="b-state">{chi === 1 ? 'opened · checked' : 'selected · unchecked'}</span>
            </div>
          </div>
        ))}
        <div className="lane-row lane-dots">
          <div></div><div className="lane-bit">⋮</div><div className="lane-ellipsis">⋮</div><div className="lane-ellipsis">⋮</div>
        </div>
        <div className="lane-row">
          <div className="lane-name">lane κ−1</div>
          <div className="lane-bit"><Tex>{T`\chi_{\kappa-1} = 0`}</Tex></div>
          <div className="branchbox opened">
            <Tex>{T`c_{\kappa-1,0}`}</Tex>
            <span className="b-state">opened · checked</span>
          </div>
          <div className="branchbox used">
            <Tex>{T`c_{\kappa-1,1}`}</Tex>
            <span className="b-state">selected · unchecked</span>
          </div>
        </div>
      </div>
      <ul className="d2">
        <li>Amplification: a bad branch survives only if its lane's coin keeps it
        unopened. Dodging k checks has probability <Tex>{T`2^{-k}`}</Tex>.</li>
        <li>At κ = 512 lanes, placing even a quarter of the branches badly succeeds with
        probability ≈ <Tex>{T`2^{-128}`}</Tex> — per attempt, against a live verifier.</li>
      </ul>
    </>
  );
}

/* ── Slide 9: Fiat–Shamir ── */
function FiatShamirSlide() {
  return (
    <>
      <span className="tag tag-purple">Cut-and-choose 101</span>
      <h2>Removing interactivity: Fiat–Shamir</h2>
      <p className="subtitle">
        The verifier's coin flip becomes a hash — computed by the user, but only after
        every commitment is frozen.
      </p>
      <div className="game d1">
        <div className="side real">
          <h4>Before · live verifier</h4>
          <div className="gline">1. user commits: <Tex>{T`\mathbf{c}_{\mathrm{agg}}`}</Tex></div>
          <div className="gline">2. verifier flips coins: <Tex>{T`\boldsymbol{\chi} \leftarrow \{0,1\}^{\kappa}`}</Tex></div>
          <div className="gline">3. user opens branch χ<sub>i</sub> in every lane</div>
        </div>
        <div className="side ideal">
          <h4>After · Fiat–Shamir</h4>
          <div className="gline">1. user hashes every branch: <Tex>{T`\ell_{i,b} = H_{\mathrm{leaf}}(\mathsf{sid}, i, b, \mathbf{c}_{i,b})`}</Tex></div>
          <div className="gline">2. user derives the coins itself: <Tex>{T`\boldsymbol{\chi} = H_{\mathrm{chal}}(\mathbf{c}_{\mathrm{agg}}, \ell_{0,0}, \ell_{0,1}, \ldots, \ell_{\kappa-1,1})`}</Tex></div>
          <div className="gline">3. sends <Tex>{T`\mathbf{c}_{\mathrm{agg}}`}</Tex> + openings; signer recomputes χ and checks</div>
        </div>
      </div>
      <div className="callout good d2">
        <strong>What goes into the challenge hash:</strong> the final aggregate{' '}
        <Tex>{T`\mathbf{c}_{\mathrm{agg}}`}</Tex> plus the hash of <em>every</em>{' '}
        commitment — opened and unopened alike. All 2κ branches are frozen before{' '}
        <Tex>{T`\boldsymbol{\chi}`}</Tex> exists, so no branch can be swapped after the
        coins are known.
      </div>
    </>
  );
}

/* ── Slide 9: our variant ── */
function OurVariantSlide() {
  return (
    <>
      <span className="tag tag-green">Our construction</span>
      <h2>Putting it all together</h2>
      <p className="subtitle">
        One key <Tex>{T`\mathbf{s}`}</Tex> for every lane, one aggregate vector on the
        wire, one Fiat–Shamir challenge, one answer.
      </p>
      <div className="seq">
        <div className="actor">User (offline)</div>
        <div></div>
        <div className="actor">Signer (online, holds <Tex>{T`\mathbf{s}`}</Tex>)</div>

        <div className="local">
          expand 2κ branches from seeds and commit to the whole table:<br />
          <Tex>{T`\mathbf{c}_{i,b} = B\mathbf{r}_{i,b} + \mathbf{e}_{2,i,b} + H_R(\text{lane } i, m_{i,b}, \rho_{i,b})`}</Tex><br />
          <Tex>{T`\mathbf{c}_{\mathrm{agg}} = \textstyle\sum_{i,b} \mathbf{c}_{i,b}`}</Tex>,{' '}
          <Tex>{T`\ell_{i,b} = H_{\mathrm{leaf}}(\mathsf{sid}, i, b, \mathbf{c}_{i,b})`}</Tex>,{' '}
          <Tex>{T`\boldsymbol{\chi} = H_{\mathrm{chal}}(\cdots, \mathbf{c}_{\mathrm{agg}}, \{\ell_{i,b}\})`}</Tex>
        </div>
        <div className="chan"></div>
        <div></div>

        <div className="msg">
          <Tex>{T`\mathbf{c}_{\mathrm{agg}}`}</Tex> + κ opened seeds + κ unopened leaf
          hashes <span className="small">(one message, non-interactive)</span>
        </div>
        <div className="chan">→</div>
        <div className="local">
          rebuild the opened half from the seeds, check leaves and χ, then peel:<br />
          <Tex>{T`\mathbf{C}_{\mathrm{sel}} = \mathbf{c}_{\mathrm{agg}} - \textstyle\sum_i \mathbf{c}_{i,\chi_i} = \textstyle\sum_i \mathbf{c}_{i,\,1-\chi_i}`}</Tex>{' '}
          — exactly the selected half
        </div>

        <div></div>
        <div className="chan">←</div>
        <div className="local">
          one answer: <Tex>{T`h = \mathbf{s}^{T} \mathbf{C}_{\mathrm{sel}} + e`}</Tex>
        </div>

        <div className="local">
          unblind the selected lanes:{' '}
          <Tex>{T`v = \lceil h - \mathbf{t}^{T} \textstyle\sum_i \mathbf{r}_{i,\,1-\chi_i} \rfloor_4`}</Tex>{' '}
          → credential <Tex>{T`\sigma = \bigl((m_{i,\,1-\chi_i}, \rho_{i,\,1-\chi_i})_{i=0}^{\kappa-1},\, v\bigr)`}</Tex>
          <br /><span className="small">the signer never sees the selected branches</span>
        </div>
        <div className="chan"></div>
        <div></div>
      </div>
    </>
  );
}

/* ── Slide 10: wire sizes ── */
function WireSlide() {
  return (
    <>
      <span className="tag tag-green">Our construction</span>
      <h2>What it costs on the wire (κ = 512)</h2>
      <p className="subtitle">The first message is ≈ 142.5 KiB — almost entirely one big
      vector, and no hash-proof anywhere. Exact numbers from the construction.</p>
      <div className="cols">
        <div className="col chart-wrap d1">
          <h3>First message, by component</h3>
          <WireBreakdown />
        </div>
        <div className="col chart-wrap d2">
          <h3>The three messages</h3>
          <MessageSizes />
        </div>
      </div>
      <p className="small d3" style={{ textAlign: 'center' }}>
        The aggregate is 93 · 64 · 152 bits packed = 113,088 B. The credential itself
        (κ tags + messages + v) is ≈ 32 KiB. The small response proof is not yet
        instantiated, so it is excluded.
      </p>
    </>
  );
}

/* ── Slide 11: security status ── */
function SecuritySlide() {
  return (
    <>
      <span className="tag tag-green">Our results</span>
      <h2>What we proved</h2>
      <p className="subtitle">
        A classical random-oracle theorem for the challenge game, a key-recovery
        reduction, and a conditional one-more unforgeability theorem.
      </p>
      <div className="cols d1">
        <div className="col">
          <h3>Theorem 5.4 · Fixpoint hardness</h3>
          <p>Assume unique sessions and commitment of the aggregate and leaf list
          before the challenge:</p>
          <ul>
            <li><strong>Hiding:</strong> ≤ κ/2 free lanes in an accepted session:
            probability ≤ <Tex>{T`Q_h\,2^{-\kappa/2}`}</Tex>.</li>
            <li><strong>Targeting:</strong> a peeled sum hits a precommitted set{' '}
            <Tex>{T`T`}</Tex>: probability ≤ <Tex>{T`Q_h\,|T|\,2^{-\kappa}`}</Tex>.</li>
            <li><strong>Relations:</strong> a precommitted difference relation
            between sessions: probability ≤{' '}
            <Tex>{T`Q_h\,Q\,|T_{\mathrm{rel}}|\,2^{-\kappa}`}</Tex>.</li>
          </ul>
          <p className="small">Free = both branches openable. Proof: Lemmas 5.1–5.3
          + a union bound, plus oracle regularity and distinctness errors.</p>
        </div>
        <div className="col">
          <h3>Theorems 5.5 &amp; 5.8 · Reductions</h3>
          <ul>
            <li><strong>Key recovery (5.5):</strong> a key extractor yields an
            ssHMLWE distinguisher through a candidate-key check.</li>
            <li><strong>One-more unforgeability (5.8, conditional):</strong> with
            ssHMLWE, common-message commitment binding and public rerandomization,
            and the stated hybrids, we bound the chance of presenting{' '}
            <Tex>{T`Q+1`}</Tex> distinct messages after{' '}
            <Tex>{T`Q`}</Tex> accepted issuances.</li>
          </ul>
          <p className="small">ssHMLWE is the new assumption that the structured-sum
          responses look random.</p>
        </div>
      </div>
      <div className="callout warn d2">
        <strong>Still open:</strong> ssHMLWE itself, the quantum analysis, and the
        one-more hybrid details: response-proof simulation, key validation, and
        the correctness bound.
      </div>
      <p className="small">Source: docs/single-key-cut-and-choose-kvbs.tex, §§5.5–5.6.
      {' '}<Tex>{T`Q_h`}</Tex> counts challenge queries; <Tex>{T`Q`}</Tex> counts accepted sessions.</p>
    </>
  );
}

/* ── Slide 12: attack costs ── */
function AttacksSlide() {
  return (
    <>
      <span className="tag tag-amber">Security status</span>
      <h2>Attack landscape at κ = 512</h2>
      <p className="subtitle">Work factor of every attack route we know (log₂ scale) —
      the cheapest one sets the floor.</p>
      <div className="chart-wrap d1">
        <AttackCosts />
        <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 8 }}>
          The balanced splice (2²⁵⁶ classical, 2¹²⁸ quantum) is the binding constraint;
          the aiming routes are far out of reach.
        </p>
      </div>
      <ul className="d2">
        <li>The splice never picks a target — it <em>manufactures</em> one from copied
        material, so only the challenge-dodging cost <Tex>{T`2^{\kappa/2}`}</Tex> remains.</li>
        <li>Wagner's k-tree algorithm dies on the sheer size of the sum space:{' '}
        <Tex>{T`2^{N/(1+\log_2 \kappa)}`}</Tex> with{' '}
        <Tex>{T`N = 93 \cdot 64 \cdot 152 \approx 904{,}704`}</Tex> bits.</li>
      </ul>
    </>
  );
}

/* ── Slide 13: four-corner attack ── */
function RectangleSlide() {
  return (
    <>
      <span className="tag tag-red">Attack</span>
      <h2>The four-corner forgery — and why freshness blocks it</h2>
      <p className="subtitle">
        Write <Tex>{T`F_i(x) = \mathbf{s}^{T} H_R(\text{lane } i, x)`}</Tex>{' '}
        and <Tex>{T`Y = \textstyle\sum_i F_i(x_i)`}</Tex>. Split the κ lanes into two
        halves, pick two left inputs <Tex>{T`L_0, L_1`}</Tex> and two right
        inputs <Tex>{T`R_0, R_1`}</Tex>, and issue three of the four
        corners <Tex>{T`Y_{ab} = Y(L_a, R_b)`}</Tex>:
      </p>
      <div className="rect d1">
        <div className="cell issued"><Tex>{T`Y_{00}`}</Tex><br /><span className="small">issued</span></div>
        <div className="cell issued"><Tex>{T`Y_{01}`}</Tex><br /><span className="small">issued</span></div>
        <div className="cell issued"><Tex>{T`Y_{10}`}</Tex><br /><span className="small">issued</span></div>
        <div className="cell forged"><Tex>{T`Y_{11}`}</Tex><br /><span className="small">never issued — forged</span></div>
      </div>
      <div className="cols d2">
        <div className="col">
          <h3>What makes it work</h3>
          <p>Y splits along the halves:{' '}
          <Tex>{T`Y(L_a, R_b) = (\text{left on }L_a) + (\text{right on }R_b)`}</Tex>,
          so <Tex>{T`Y_{10} + Y_{01} - Y_{00} = Y_{11}`}</Tex> — but only if the
          same halves may be reused across sessions. Three corners issued honestly,
          the fourth comes for free.</p>
        </div>
        <div className="col">
          <h3>What kills it</h3>
          <p>Every tag carries a globally unique session id:{' '}
          <Tex>{T`\rho = H_\rho(\mathsf{sid}, i, b, \mathbf{r}, \mathbf{e}_2)`}</Tex>, and
          the leaf hashes do too. Reusing an input across sessions means inverting a
          hash — so the rectangle never closes.</p>
        </div>
      </div>
      <div className="callout warn d3">
        Freshness is mandatory, not optional — and it must survive concurrency, rollback,
        and replicated signer state.
      </div>
    </>
  );
}

/* ── Slide 14: common message M ── */
function CommonMessageSlide() {
  return (
    <>
      <span className="tag tag-green">Countermeasure</span>
      <h2>Bind every lane to one message M</h2>
      <p className="subtitle">
        Even with fresh sessions, the balanced splice costs only{' '}
        <Tex>{T`2^{\kappa/2}`}</Tex>. The common-message binding decides what that work
        buys: a duplicate, not a forgery.
      </p>
      <div className="cc-flow">
        <div className="cc-step"><strong>commit once</strong><Tex>{T`\mu_0 = \mathsf{Com}(M; \phi_0)`}</Tex></div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>every branch</strong><Tex>{T`\mu_{i,b} = \mathsf{Com}(M; \phi_0 + \Delta_{i,b})`}</Tex><br />(publicly re-randomized)</div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>challenge covers μ₀</strong>lane hash: <Tex>{T`H_R(i, \mu_{i,b}, \rho_{i,b})`}</Tex></div>
        <span className="cc-arrow2">→</span>
        <div className="cc-step"><strong>presentation</strong>reveal M + randomness</div>
      </div>
      <div className="cards three d1">
        <div className="card">
          <h3><span className="material-symbols-outlined">link</span>Demotion</h3>
          <p>A commitment opens to only one message, so a credential is consistent with
          exactly one M. Splicing can then only re-issue an existing message:{' '}
          <strong>forgery → duplication</strong>.</p>
        </div>
        <div className="card">
          <h3><span className="material-symbols-outlined">block</span>M as nullifier</h3>
          <p>M carries a per-issuance serial, so it names the credential instance;
          presenting it twice is detectable. The trade-off is linkage; scoped variants{' '}
          <Tex>{T`H(M, \mathsf{scope})`}</Tex> are possible.</p>
        </div>
        <div className="card">
          <h3><span className="material-symbols-outlined">database</span>Verifier storage</h3>
          <p>Duplicate detection collapses to <strong>one stored hash per message</strong> —
          instead of recording all κ lane inputs of every credential ever shown.</p>
        </div>
      </div>
      <p className="small d2">
        Honest caveat: the demotion is proven only conditionally (one-more unforgeability
        from ssHMLWE + commitment binding), and it does nothing against key recovery —
        that independently costs 2<sup>κ/2</sup>.
      </p>
    </>
  );
}

/* ── Slide 15: summary ── */
function SummarySlide() {
  return (
    <>
      <span className="tag tag-purple">Summary</span>
      <h2>Where this leaves us</h2>
      <div className="cards three">
        <div className="card">
          <h3 style={{ color: 'var(--semantic-green)' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--semantic-green)' }}>check_circle</span>
            What we get</h3>
          <ul>
            <li>No hash evaluations inside any proof — the BLNS23 bottleneck is gone.</li>
            <li>First message ≈ 142.5 KiB at κ = 512: one vector, κ seeds, κ hashes.</li>
            <li>Signer state: one key, one matrix, one small proof.</li>
            <li>The challenge game is proven; its bounds match the known attacks.</li>
          </ul>
        </div>
        <div className="card">
          <h3 style={{ color: 'var(--semantic-amber)' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--semantic-amber)' }}>paid</span>
            What it costs</h3>
          <ul>
            <li>One new assumption (ssHMLWE): the signer's answers look random even under
            attacker influence.</li>
            <li>No standard proof can supply it — the junk term{' '}
            <Tex>{T`\mathbf{s}^{T}\mathbf{w}`}</Tex> is out of every HMLWE oracle's reach.</li>
            <li>The common-message binding is needed to demote splicing to duplication.</li>
            <li>The credential itself stays ≈ 32 KiB.</li>
          </ul>
        </div>
        <div className="card">
          <h3 style={{ color: 'var(--semantic-red)' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--semantic-red)' }}>help</span>
            What's open</h3>
          <ul>
            <li>Attack ssHMLWE directly — a break would be a checkable, common,
            key-leaking shape for the signed sum.</li>
            <li>Quantum attackers (the proofs assume classical hashing).</li>
            <li>Remaining simulation details; privacy against a cheating signer.</li>
            <li>Final parameters; κ = 512 is a starting point.</li>
          </ul>
        </div>
      </div>
      <div className="callout d2">
        A target for analysis, not for deployment. The full construction, proofs, and
        attack pricing are in the accompanying document.
      </div>
    </>
  );
}

const SLIDES = [
  TitleSlide, SettingSlide, LweSlide, NoiselessSystemSlide, MlweSlide, KeyExchangeSlide, HmlweSlide,
  BlnsMathSlide, WhyProofSlide,
  ProofCostSlide, CcIntroSlide, CcScaleSlide, FiatShamirSlide, OurVariantSlide, WireSlide,
  SecuritySlide, AttacksSlide, RectangleSlide, CommonMessageSlide, SummarySlide,
];

function Slide({ active, children }) {
  return (
    <div className={`slide ${active ? 'active' : ''}`}>
      <div className={`slide-content${active ? ' anim' : ''}`}>
        {children}
      </div>
    </div>
  );
}

function Nav({ cur, total, go, setCur }) {
  return (
    <nav>
      <button onClick={() => go(-1)} disabled={cur === 0}>←</button>
      <div className="dots">
        {Array.from({ length: total }, (_, i) => (
          <div key={i} className={`dot${i === cur ? ' on' : ''}`} onClick={() => setCur(i)} />
        ))}
      </div>
      <button onClick={() => go(1)} disabled={cur === total - 1}>→</button>
      <span className="slide-number">{cur + 1} / {total}</span>
    </nav>
  );
}

export default function App() {
  const [cur, setCur] = useState(0);
  const go = useCallback(
    (d) => setCur((c) => Math.max(0, Math.min(SLIDES.length - 1, c + d))),
    [],
  );

  useEffect(() => {
    const h = (e) => {
      if (e.target.tagName === 'INPUT') return;
      if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); go(1); }
      if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [go]);

  return (
    <>
      <div className="progress" style={{ width: `${((cur + 1) / SLIDES.length) * 100}%` }} />
      {SLIDES.map((S, i) => (
        <Slide key={i} active={i === cur}>
          <S />
        </Slide>
      ))}
      <Nav cur={cur} total={SLIDES.length} go={go} setCur={setCur} />
    </>
  );
}
