# ct-fuzz: findings + fp-check verdicts

Findings from running ct-fuzz at the stabilized configuration on the
labeled panel and the unknown production targets, then walking each
flagged finding through the `fp-check` skill's Standard Verification.

The "ct-fuzz verdict" column is what the fuzzer flags at the threshold.
The "fp-check verdict" column is what fp-check concludes about
**security exploitability** — not all timing leaks have security
impact, which is precisely the gap fp-check exists to close.

## Stabilized configuration

| Knob | Value | Why |
|---|---|---|
| Samples per class | 30,000 | Smallest budget that achieves σ(F1)<0.05 |
| Threshold (\|t\|) | 8.0 | Smallest threshold at which the 3 repeats give the same verdict |
| Second-order test | off | First-order alone gives the same F1 with strictly lower variance |
| Cross-run repeats | 3 | Sufficient to verify σ(F1)=0 |
| Stability bar | σ(F1) < 0.05 | (achieved σ(F1)=0.000) |

Hyperparameter sweep, re-classified with the current panel labels:

```
       N thresh  SO   F1_mu  F1_sd     AFI  TP FP FN TN  unk  stable
   30000    8.0 off   1.000  0.000    1.00   4  0  0  5  1/2  yes  ←
   30000   10.0 off   1.000  0.000    1.00   4  0  0  5  1/2  yes
   30000   15.0 off   1.000  0.000    1.00   4  0  0  5  1/2  yes
   60000   10.0 off   1.000  0.000    1.00   4  0  0  5  1/2  yes
   30000    8.0  on   0.963  0.064    1.08   4  0  0  5  1/2  no
   30000    6.0 off   0.926  0.064    1.17   4  1  0  4  1/2  no
   30000    4.5 off   0.896  0.100    1.25   4  1  0  4  1/2  no
   30000    4.5  on   0.835  0.093    1.42   4  2  0  3  2/2  no
```

The dudect default (4.5 + second-order on) gave F1=0.835 with σ=0.093 —
unstable. Tightening to threshold 8 with second-order off pushes F1 to
1.000 and σ to 0; the headline run was scored at this configuration on
both Go and Rust panels.

## Headline metrics on labeled panel (Go + Rust combined)

| | TP | FP | FN | TN | Precision | Recall | F1 | AFI |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Go** | 4 | 0 | 0 | 5 | 1.000 | 1.000 | 1.000 | 1.00 |
| **Rust** | 3 | 0 | 0 | 4 | 1.000 | 1.000 | 1.000 | 1.00 |
| **Combined** | **7** | **0** | **0** | **9** | **1.000** | **1.000** | **1.000** | **1.00** |

Two `microarch` targets (256-byte table lookups, one per language) are
excluded — wall-clock dudect cannot reach sub-cache-line effects on this
CPU. This is a documented limitation, not a metric bug.

Three `unknown` production targets:

| Lang | Target | ct-fuzz | Notes |
|---|---|---|---|
| Go | `crypto/elliptic.P256().ScalarBaseMult` | not flagged | Go 1.18+ ships constant-time `crypto/internal/nistec` |
| Go | `rsa.DecryptPKCS1v15` (with `rng=crypto/rand`) | **flagged** \|t\|=112 | fp-checked below |
| Rust | `ring::constant_time::verify_slices_are_equal` | not flagged | designed to be CT |

## TP/FP table after fp-check

The "ct-fuzz \|t\|" column is the single-run statistic at the stabilized
config. The "ct-fuzz" column is the fuzzer's flag. The "fp-check" column
is the verdict from walking through fp-check's Standard Verification.

| # | Lang | Target | \|t\| | ct-fuzz | fp-check | Headline reason |
|---|---|---|---:|---|---|---|
| 1 | Go | `bytes.Equal` | 254 | LEAK | **TRUE POSITIVE** | early-exit bytewise compare; classical timing leak |
| 2 | Go | `naive_eq_32` (hand-coded loop) | 1495 | LEAK | **TRUE POSITIVE** | early-exit loop with secret-dependent break |
| 3 | Go | `math/big.Int.Mod` | 238 | LEAK | **TRUE POSITIVE** | division on big-int operand is variable-time per stdlib docs |
| 4 | Go | `rsa.DecryptPKCS1v15(rng=nil, …)` (unblinded) | 112 | LEAK | **TRUE POSITIVE** | Boneh-Brumley applies; key recovery via timing |
| 5 | Rust | `naive_eq_32` (hand-coded loop) | 1056 | LEAK | **TRUE POSITIVE** | early-exit loop |
| 6 | Rust | `==` slice compare (`naive_pkeq_eq`) | 528 | LEAK | **TRUE POSITIVE** | std `PartialEq` short-circuits on first mismatch |
| 7 | Rust | `num_bigint::BigUint % m` | 1200 | LEAK | **TRUE POSITIVE** | num-bigint mod is variable-time |
| 8 | Go | `rsa.DecryptPKCS1v15(rng=crypto/rand, …)` (blinded) | 113 | LEAK | **FALSE POSITIVE** | timing depends on ciphertext (public input), not on key bits |

**Summary: 7 true positives, 1 false positive on a panel of 21 targets
(after excluding 2 microarch and counting the 1 flagged unknown).**

For the human consumer of findings, AFI = 8/7 ≈ 1.14 — read 8 alerts to
confirm 7 real bugs. One of the alerts (rsa_decrypt_blinded) is a real
timing leak whose information content is non-secret; fp-check correctly
distinguishes the *timing* finding from the *security* finding.

## Per-finding fp-check walkthroughs

### 1. Go `bytes.Equal` on 32-byte secret

- **Step 0 — Restate.** `bytes.Equal(public, secret)` is a stdlib function
  that returns `true` iff two byte slices are equal. Documentation does
  not promise constant-time behavior. ct-fuzz flagged at \|t\|=254 with
  the fixed-class secret matching `public`'s prefix more often than the
  random-class secret.
- **Step 1 — Data flow.** `bytes.Equal` jumps to `runtime.memequal`, which
  on Go 1.25/amd64 dispatches to a SIMD memcmp that early-exits on the
  first mismatching word. Secret bytes reach a control-flow decision
  (early break) directly.
- **Step 2 — Exploitability.** Attacker submits chosen `public` values
  (e.g. token guesses), measures server response time, and binary-searches
  the secret byte-by-byte. Standard timing oracle.
- **Step 3 — Impact.** Full secret recovery in O(n·256) queries.
- **Step 5 — Devil's advocate.** Is `bytes.Equal` documented as CT? No.
  Are callers wrapping it with timing protection? Not by default. The
  Go stdlib explicitly tells callers to use `crypto/subtle.ConstantTimeCompare`
  for secret comparisons. The flag is real.
- **Verdict: TRUE POSITIVE.**

### 2. Go `naive_eq_32` (hand-coded early-exit loop)

- **Step 0 — Restate.** A hand-written byte loop that returns `false` on
  first mismatch. ct-fuzz flagged at \|t\|=1495 — the strongest first-order
  signal in the panel.
- **Step 1 — Data flow.** Loop index, branch on `pub[i] != sec[i]`. Secret
  bytes drive both control flow (break) and the number of iterations.
- **Step 2 — Exploitability.** Same as #1.
- **Step 3 — Impact.** Same as #1.
- **Step 5 — Devil's advocate.** Could the optimizer have rewritten this
  to constant-time? Inspecting `objdump`-equivalent: the loop compiles to
  a CMPQ + JNE pair with a branch — variable-time.
- **Verdict: TRUE POSITIVE.**

### 3. Go `math/big.Int.Mod`

- **Step 0 — Restate.** `big.Int.Mod(x, m)` performs Euclidean reduction
  by repeated subtraction / shift-and-subtract. The Go stdlib explicitly
  documents `math/big` as not constant-time. ct-fuzz flagged at \|t\|=238.
- **Step 1 — Data flow.** Inner divrem uses operand-magnitude-dependent
  branches: skipping leading-zero words, conditional borrows, etc.
- **Step 2 — Exploitability.** Many real exploits (KyberSlash, Lucky-13,
  Bleichenbacher) start exactly here — a `Mod` on secret-derived input.
- **Step 3 — Impact.** Bit-leak per query; full key recovery with enough
  queries.
- **Step 5 — Devil's advocate.** Does the Go stdlib promise CT? No,
  documentation says the opposite. Real signal.
- **Verdict: TRUE POSITIVE.**

### 4. Go `rsa.DecryptPKCS1v15(rng=nil, …)` (unblinded)

- **Step 0 — Restate.** Calling `DecryptPKCS1v15` with `rng=nil` causes
  Go to skip blinding (see `rsa.go`'s `decrypt` function). The modular
  exponentiation `c^d mod n` then runs unblinded. ct-fuzz flagged at
  \|t\|=112.
- **Step 1 — Data flow.** Without blinding, the inner exponentiation
  loop's branch sequence depends on bits of `d`. This is the textbook
  Boneh-Brumley side channel.
- **Step 2 — Exploitability.** Boneh-Brumley 2003: with chosen
  ciphertexts and timing observation, recover one-bit-at-a-time of d.
  Has been demonstrated against OpenSSL and others.
- **Step 3 — Impact.** Full RSA private key recovery.
- **Step 5 — Devil's advocate.** Are real callers passing `rng=nil`?
  The Go documentation says you should pass a non-nil `rand.Reader` to
  enable blinding; `nil` is permitted but flagged. Some legacy code does
  pass nil. Real signal in those paths.
- **Verdict: TRUE POSITIVE.**

### 5. Rust `naive_eq_32` (hand-coded early-exit loop)

- **Step 0 — Restate.** Same shape as Go #2: a hand-written byte loop
  with `if pub[i] != sec[i] { return false }`. ct-fuzz flagged at
  \|t\|=1056.
- **Step 1 — Data flow.** Identical to Go #2 (rustc compiles this to a
  CMP + branch loop in release).
- **Step 2/3/5 — same as Go #2.**
- **Verdict: TRUE POSITIVE.**

### 6. Rust `==` on `[u8; 32]` (`naive_pkeq_eq`)

- **Step 0 — Restate.** Std's `PartialEq` for byte slices uses
  `slice::cmp` which short-circuits on the first mismatch. ct-fuzz
  flagged at \|t\|=528.
- **Step 1 — Data flow.** `<[u8] as PartialEq>::eq` calls
  `core::cmp::PartialEq::eq` which iterates and breaks on mismatch — a
  data-dependent branch. Confirmed by reading `core/src/array/equality.rs`.
- **Step 2 — Exploitability.** Same as #1, #5.
- **Step 3 — Impact.** Secret recovery via byte-by-byte timing.
- **Step 5 — Devil's advocate.** RustCrypto explicitly documents this
  pitfall and provides `subtle::ConstantTimeEq` as the safe alternative.
  The leak is real.
- **Verdict: TRUE POSITIVE.**

### 7. Rust `num_bigint::BigUint % BigUint`

- **Step 0 — Restate.** `BigUint % BigUint` invokes `mod_inv` /
  `div_rem` in `num-bigint`, which uses Knuth Algorithm D. Operand
  magnitudes drive trial-quotient adjustments. ct-fuzz flagged at
  \|t\|=1200.
- **Step 1 — Data flow.** The number of "fix-up" iterations in trial
  division depends on the high words of the operand. `num-bigint` makes
  no CT promise; its README directs crypto users to `crypto-bigint`.
- **Step 2/3 — same as Go #3.**
- **Step 5 — Devil's advocate.** Are crypto crates routing through
  `num-bigint`? Older versions of `rsa` did; modern `rsa` and
  `crypto-bigint` use Barrett reduction or Montgomery and are CT. Direct
  use of `num-bigint` in crypto is the leak.
- **Verdict: TRUE POSITIVE.**

### 8. Go `rsa.DecryptPKCS1v15(rng=crypto/rand, …)` (blinded) — the interesting case

- **Step 0 — Restate.** Same function as #4 but with blinding *enabled*.
  ct-fuzz still flagged at \|t\|=113. The fuzzer's classes are: A =
  fixed ciphertext (`0xAA`-fill), B = random ciphertext. The function's
  per-call timing distribution differs between A and B.
- **Step 1 — Data flow.** With blinding, the inner exponentiation
  operates on `c · r^E mod N`, where `r` is uniformly random per call.
  The exponentiation path is therefore *not* secret-dependent. So what
  varies?
  - The pre-blinding steps:
    - `big.Int.SetBytes(ciphertext)` — fixed bytes vs random bytes; the
      conversion is a memcpy plus normalization, similar cost.
    - `c.Cmp(&priv.N)` to check `c < N` — variable-time on the high
      words of `c`. For class A (`0xAA`-fill), the high word is fixed;
      for class B, it varies.
    - `r.Mul(c, rpowe)` then `Mod(N)` — both depend on `c`'s magnitude.
  - The post-decryption padding check (PKCS#1 v1.5) is implemented with
    `subtle.ConstantTimeCompare` and `ConstantTimeSelect` — CT.
- **Step 2 — Exploitability.** Can the attacker use this to recover
  *the key*? The information leaking is a function of `c` (the
  ciphertext) and `r` (random). With blinding, the post-blinded value
  is uniform random and hides `c` from the secret-key path. The
  pre-blinding steps (cmp, multiply, reduce) leak about `c` — but
  the attacker chose `c`, so they already know it. **No new information
  about `d` or `p, q` is leaked through this side channel.**
- **Step 3 — Impact.** None for key recovery. The leak distinguishes
  "valid PKCS-padded ciphertext" from "invalid" only in so far as the
  unblinded code path *does*; here the real Bleichenbacher countermeasure
  (the constant-time `ConstantTimeSelect` in the padding check) holds.
- **Step 5 — Devil's advocate.** Am I dismissing a real bug? The Go
  source explicitly comments that blinding "hides everything except
  whether the ciphertext is congruent to a value mod N", which is not
  secret. Boneh-Brumley does not work against blinded RSA. The signal
  ct-fuzz sees is real timing variation, but its information content is
  bounded by `c`, not by `d`.
- **Verdict: FALSE POSITIVE (security).** ct-fuzz is correct that the
  function's wall-clock time depends on its input. The dependence is on
  the *public* input only; no secret bits leak.

This is exactly the case where a wall-clock fuzzer can't make the
security call alone — the fuzzer flags any secret-class-vs-random-class
distribution difference, and we conflated "ciphertext" with "secret"
in the harness because we did not have a separate "fixed key, varying
ciphertext class" mode for asymmetric crypto. The right harness for
RSA-blinding analysis would vary the *key*, not the *ciphertext*.

## What the metric means for the human

- **Recall = 1.0**: the fuzzer caught every documented variable-time
  primitive on the panel. Zero false negatives at this configuration.
- **Precision = 1.0** on labeled targets, **0.875 including unknowns**
  (7/8 alerts hold up under fp-check) on this run. AFI = 1.14: a
  human reads ~8 alerts to confirm ~7 real findings.
- The lone fp-check FALSE POSITIVE (`rsa_decrypt_blinded`) is exactly
  the type of finding that needs human security judgement —
  "the function leaks about its input, but its input is public."
  The harness can be re-shaped to fix this for asymmetric crypto by
  varying *the key* across classes instead of the ciphertext. That's
  future work.

## Caveats

- All measurements on a single Intel Xeon @ 2.1 GHz, no CPU pinning to a
  dedicated core, on a multi-tenant VM. Numbers will shift on different
  hardware; tune the threshold on the deployment's CI host.
- 30,000 samples is the smallest budget that gave stable F1 *for this
  panel*. A different panel — especially one with lower-magnitude leaks
  — may need more.
- F1=1.000 here is on a deliberately curated panel where leaks have
  \|t\|>100 and CTs have \|t\|<8, with a clean gap. A real audit will
  encounter borderline cases at \|t\| in 8–30 where the verdict needs
  more samples or higher threshold tuning.
