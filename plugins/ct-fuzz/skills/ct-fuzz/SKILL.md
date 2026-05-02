---
name: ct-fuzz
description: "Flags non-constant-time crypto code by dudect-style statistical timing analysis on Go and Rust targets. Use when investigating runtime timing leakage in cryptographic implementations, when MSan/ctgrind cannot reach the language (Go), or when complementing static constant-time analysis with empirical evidence."
---

# ct-fuzz

Dudect-style fuzzer that flags functions whose execution time depends
measurably on a secret input.

## When to Use

- Auditing a Go or Rust crypto implementation and you want empirical
  evidence of timing dependence on secret input.
- The static `constant-time-analysis` skill flagged a candidate and you
  want runtime confirmation before triage.
- The target uses Go (no usable MSan/ctgrind path) or Rust FFI to C
  primitives that MSan can't see.

## When NOT to Use

- Cache-line-resident lookup tables (e.g. AES T-tables that fit in L1).
  Wall-clock dudect cannot resolve sub-cache-line effects; use FLUSH+RELOAD
  or PRIME+PROBE methodology.
- Code paths where the secret never reaches a branch or memory address —
  static analysis already gives you a definitive answer.
- A noisy CI runner. Statistical methods need a quiet machine; expect
  false negatives (and occasional false positives) on shared hardware.
- Confirming exploitability. ct-fuzz says "timing depends on secret"; it
  does not say "the leak is exploitable." Pair with the `fp-check` skill.

## Quick Start

```bash
# Build harnesses
(cd {baseDir}/../../harness/go && go build -o {baseDir}/../../ct-fuzz-go .)
(cd {baseDir}/../../harness/rust && cargo build --release && \
    cp target/release/ctfuzz-rust {baseDir}/../../ct-fuzz-rust)

# Run the labeled panel once
python3 {baseDir}/../../ct_fuzz/run_panel.py --samples 100000 --threshold 4.5

# Iterate hyperparameters until the metric stabilizes
python3 {baseDir}/../../ct_fuzz/iterate.py --repeats 3 \
    --samples 50000,100000 --thresholds 4.5,6.0,8.0,10.0 \
    --second-order on,off
```

## How to add a new target

1. **Go**: register in `harness/go/targets.go` with
   `register("name", secretLen, publicLen, innerLoop, func(pub, sec []byte) {...})`.
   Pre-allocate any temporary buffers outside the closure to keep allocation
   out of the timed region.
2. **Rust**: add to `harness/rust/src/targets.rs` via the `TargetSpec`
   builder. Same rules: no allocation inside the timed function.
3. Add an entry to `panel/panel.json` with one of `ct | leaky | microarch | unknown`.
4. Rebuild and re-run.

## Interpreting results

- **|t1|** — first-order Welch's |t| (mean shift). > 4.5 ⇒ timing-mean
  depends on secret.
- **|t2|** — second-order |t| (variance shift). > 4.5 ⇒ timing-variance
  depends on secret. Many real leaks (predictor, branch jitter) show up
  here without a mean shift.
- **AFI** — alarm-fatigue index = (TP+FP)/TP. Reading 1 means every alert
  is real; 5 means an analyst reads 5 alerts to confirm one bug.

## Verifying findings

Treat any flagged target as a hypothesis, not a verdict. Use the `fp-check`
skill on each non-`leaky` flagged target. fp-check produces a documented
TRUE-POSITIVE / FALSE-POSITIVE verdict with data-flow evidence.

## Limitations

- One CPU. A leak detectable on one microarchitecture may hide on another.
- Wall-clock only. Cache-line and branch-predictor leaks below the
  measurement noise floor are invisible.
- Black-box. We can flag a function but cannot point at the offending line.
- Single-target framework. We cannot detect cross-call leaks (e.g. a key
  schedule that leaks into a subsequent encrypt) without a tailored harness.

## See also

- `constant-time-analysis` — static (assembly-level) detection. Use first
  to find candidates, then ct-fuzz to confirm with runtime evidence.
- `fp-check` — verification workflow for any flagged finding.
- Reparaz, Balasch, Verbauwhede, *Dude, is my code constant time?*, USENIX 2017.
