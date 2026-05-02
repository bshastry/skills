# ct-fuzz: design

A dudect-style timing-leak fuzzer for Go and Rust cryptographic code.

## Goal

Flag functions whose execution time depends measurably on a secret input,
without instrumentation, taint-tracking, or bytecode rewriting. The intended
consumer is a security analyst who wants a short, low-fatigue list of
candidates worth investigating with the existing static `constant-time-analysis`
skill or with formal tools (MSan, ctgrind).

## Approach

Black-box statistical timing measurement, after Reparaz/Balasch/Verbauwhede,
"dude, is my code constant time?", USENIX 2017.

For each registered target the harness runs many calls split into two classes:

- **Class A** ("fixed"): the secret input is held at a fixed value (`0xAA` repeats).
- **Class B** ("random"): the secret input is freshly random each call.

The public input is held constant (`0xAA` repeats) for the entire run. We
record per-call wall-clock duration and apply a **percentile-cropped Welch's
t-test** to the two distributions, in two flavors:

- **First-order** (raw timings): catches mean differences.
- **Second-order** (squared deviations from per-class mean): catches variance
  differences that have no mean shift.

A target is flagged when `max(|t1|, |t2|)` exceeds a threshold (4.5 by default).

### Why dudect over MSan / ctgrind

| | MSan / ctgrind | dudect |
|---|---|---|
| Mechanism | Mark secrets uninitialized; instrument loads/branches | Measure cycles, t-test distributions |
| Catches | Information flow from secret → branch/address | Timing differences measurable on this CPU |
| Misses | Microarchitectural leaks invisible at IR level | Sub-noise leaks; leaks specific to architectures we don't test |
| Toolchain | LLVM (MSan) or Valgrind (ctgrind) | Anything callable via FFI |
| Go | No usable story (Go runtime is opaque to MSan/Valgrind) | Works directly |
| Rust | MSan via nightly `-Z sanitizer=memory`; doesn't cover all unsafe / FFI | Works directly |
| Determinism | Deterministic | Probabilistic; needs enough samples |

We picked dudect because the target set spans Go and Rust crypto, and Go has
no working MSan/ctgrind path. The cost is statistical noise — the metric
design below is the consequence.

## Architecture

```
plugins/ct-fuzz/
├── ct_fuzz/               Python driver (statistics, panel, metric, iteration)
│   └── ct_fuzz/
│       ├── stats.py       Welford / Welch / percentile crop / 2nd-order preprocess
│       ├── runner.py      Subprocess driver — feeds (target, N) to harness, reads samples
│       ├── panel.py       Loader for the labeled panel
│       ├── metrics.py     Verdict, classifier, P/R/F1/AFI, stability
│       └── driver.py      End-to-end evaluate-panel
├── harness/
│   ├── go/                Go harness binary; one process per `run-target` invocation,
│   │                      one inner loop per timed sample, GC disabled, OS thread
│   │                      pinned, public input fixed, secrets pre-generated.
│   └── rust/              Same shape, Rust release build.
├── panel/panel.json       Labeled panel of (target, label, rationale)
└── results/               Per-run JSON output
```

The harness reads `<target> <N>` on stdin, emits `<class> <ns>\n` × N then
`DONE`. The Python driver reads, classifies, scores, persists.

### Per-target inner loop

The harness wraps each timed sample in an inner loop of `inner` calls. This
amortizes `time.Now()` / `Instant::now()` overhead (~30–50 ns) over the
operation under test. Without this, ns-fast operations (`subtle.ConstantTimeCompare`)
have a measurement window dominated by the timer itself, producing noise-level
"leaks" against the timer rather than the function. Inner counts are tuned
per-target: 2000 for byte-level operations, 200 for SHA-256, 5 for big-int
modular reduction, 1 for scalar multiplication.

### Public input held fixed

The standard dudect setup fixes the public input. With *fresh-random* public,
both class A and class B exit early on byte 0 (probability 255/256) of an
early-exit comparison — burying the leak. Fixing public to `0xAA` makes
class A (secret = `0xAA` repeat → full match) take a different code path
than class B (random → first-byte mismatch with high probability). The
attacker model is "secret-dependent timing for a fixed adversary input,"
which matches reality.

### Why the second-order test

A target can leak through *variance* differences without any mean shift —
e.g. a constant-time-mean operation whose branch predictor state diverges
between secret bit patterns. The second-order test (subtract per-class mean,
square residuals, t-test) catches this. In practice it adds recall on
table-lookup-like patterns at the cost of some precision; the iteration
loop decides whether to keep it on.

## Threats to validity

1. **Single architecture.** A leak detectable on AMD Zen may hide on Intel
   Ice Lake and vice versa. We measure on one CPU; we report what we see there.
2. **System noise.** Other processes on the host shift the timing distribution
   for both classes and inflate variance. Cropping the upper percentiles
   (the dudect technique) mitigates but does not eliminate this. CI runners
   are particularly bad; running on a dedicated machine narrows the noise
   floor.
3. **Cache-resident tables don't surface.** `table_lookup_secret_index`
   uses a 256-entry table that fits in L1; per-call timing has no
   measurable difference. We labeled this `microarch` and excluded it from
   the F1 metric. Detecting cache leaks needs a different methodology
   (FLUSH+RELOAD, PRIME+PROBE, or the dudect "fenced cache" variant).
4. **Statistical, not semantic.** A finding from this fuzzer is "something
   in this function's timing depends on secret bits." Whether that constitutes
   an exploitable side channel still requires the standard fp-check workflow.

## Limitations relative to the existing skill

The static `constant-time-analysis` skill flags every `DIV`, every secret-
dependent branch instruction in the as-built binary, regardless of whether
the operand is actually secret-derived. It over-reports.

ct-fuzz is the inverse: it under-reports. It only flags what produces a
measurable cycle difference *on this machine*. The two are complementary —
static for "where to look", dynamic for "this actually leaks."
