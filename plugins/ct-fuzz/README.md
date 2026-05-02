# ct-fuzz

A dudect-style timing-leak fuzzer for Go and Rust crypto code.

## What it does

Runs each registered target many times, splits calls into a fixed-secret
class and a random-secret class, and applies a percentile-cropped Welch's
t-test (first- and second-order) to the per-call wall-clock timings. Flags
a target when timing distributions differ.

The intended consumer is a security analyst — the metric is **alarm fatigue
index (AFI)**, the number of alerts a human reads per real finding. See
[METRICS.md](METRICS.md).

## Layout

| Path | Purpose |
|---|---|
| `harness/go/` | Go harness binary; one process per target, GC off, OS thread pinned |
| `harness/rust/` | Rust harness binary, release build |
| `ct_fuzz/ct_fuzz/` | Python driver: stats, runner, panel, metrics, classifier |
| `ct_fuzz/run_panel.py` | One-shot panel run with verdicts |
| `ct_fuzz/iterate.py` | Hyperparameter sweep until σ(F1) < 0.05 |
| `panel/panel.json` | Labeled panel of targets (`ct` / `leaky` / `microarch` / `unknown`) |
| `results/` | Per-run JSON output |
| `skills/ct-fuzz/SKILL.md` | Skill manifest |
| `DESIGN.md` | Architecture and rationale |
| `METRICS.md` | Metric definitions |

## Quick start

```bash
# Build harnesses
(cd harness/go && go build -o ../../ct-fuzz-go .)
(cd harness/rust && cargo build --release && cp target/release/ctfuzz-rust ../../ct-fuzz-rust)

# Single panel run
python3 ct_fuzz/run_panel.py --samples 100000 --threshold 4.5

# Iterate hyperparameters
python3 ct_fuzz/iterate.py --repeats 3 --samples 50000,100000 \
    --thresholds 4.5,6.0,8.0,10.0 --second-order on,off
```

## Why dudect

The existing `constant-time-analysis` skill scans assembly statically; it
flags every potentially-leaky instruction and over-reports. ct-fuzz is the
empirical complement: it only flags what produces a measurable cycle
difference *on this CPU*. Use static first to find candidates, dudect to
confirm with runtime evidence. See [DESIGN.md](DESIGN.md) for the comparison
to MSan / ctgrind and why we don't use those.
