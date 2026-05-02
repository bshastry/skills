# ct-fuzz: metric definitions

## Goal of the metric

Make decisions about classifier hyperparameters: threshold, sample budget,
whether to include the second-order test. The user said precision, recall,
and alarm fatigue are what matter — those are what this metric scores.

## Definitions

The fuzzer is run on a **labeled panel** of targets. Each target carries
one of four labels:

| Label | Meaning | Counts toward |
|---|---|---|
| `ct` | Documented constant-time, expected not flagged | precision (FP if flagged) |
| `leaky` | Documented variable-time, expected flagged | recall (FN if not flagged) |
| `microarch` | Real but sub-cache-line leak, beyond dudect's reach | excluded |
| `unknown` | Production target whose true label we want to discover | reported separately |

For every target on the panel:

- **TP** — labeled `leaky`, flagged
- **FN** — labeled `leaky`, not flagged
- **FP** — labeled `ct`, flagged
- **TN** — labeled `ct`, not flagged

From which:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2·P·R / (P + R)
- **AFI (Alarm-Fatigue Index)** = (TP + FP) / max(TP, 1)

## Why AFI is the headline metric for human consumption

Precision is "what fraction of alerts are real." But the cost an analyst
actually pays is "how many alerts must I read to confirm one real bug?"
That's `(TP + FP) / TP`, which we call AFI.

- AFI = 1.0 → every alert is real (perfect)
- AFI = 5.0 → analyst reads 5 alerts to find each real bug (4 wasted reads)
- AFI = ∞ → no real bugs found and at least one false alarm (worst)

A precision of 0.80 sounds good but with 4 leaks and 1 FP gives AFI = 1.25
(analyst reads ~5 alerts, finds ~4 leaks). Same precision with 1 leak and
4 FPs gives AFI = 5 — same number, very different operational experience.

A tool with **high recall but low precision is a fatigue generator**. A
tool with **low recall but high precision is a confidence builder**. AFI
quantifies which way the tool is failing.

## Stability

Run the same configuration R times (R=3 by default). Compute σ(F1)
across runs. A configuration is **stabilized** when σ(F1) < 0.05.

This is "iterate until metric stabilizes" in the user's request: pick the
hyperparameter setting with the highest mean F1 whose run-to-run variance
is below the bar. Higher F1 with high variance is not preferred; it means
the tool's verdict can flip on the same panel from one run to the next,
which is operationally worse than a slightly lower but consistent score.

## Iteration sweep

`iterate.py` runs each `(samples, repeat)` pair once, captures raw `(t1, t2)`
per target, then re-classifies for every `(threshold, second_order)` combo
*from the cached samples* — so the cost is dominated by the harness runs,
not the classifier. Sweep:

- samples ∈ {50000, 100000, 200000}
- threshold ∈ {4.5, 6.0, 8.0, 10.0}
- second_order ∈ {on, off}

For each cell: report mean F1, σ(F1), mean AFI, and whether stabilized.
The selected configuration is the highest-F1 stabilized cell, ties broken
by lower AFI.

## Reporting on the unknown column

`unknown` targets are reported separately. For each unknown that gets
flagged with the chosen configuration, run the existing `fp-check` skill
to produce a TRUE-POSITIVE / FALSE-POSITIVE verdict. The fp-check verdicts
are tabulated alongside the labeled-panel scores so a reader can see both
the calibration on the known panel and the substantive output on the
production targets.

## What the metric does *not* measure

- **Time-to-detect.** We hold sample budget fixed at the configured N; we
  don't measure "how few samples until first-flag." That's a useful
  operational metric but a separate exercise.
- **Cross-CPU portability.** All measurements are on one host CPU. A real
  release would re-tune on the deployment's CI hardware.
- **Microarchitectural leaks.** Excluded by construction (`microarch` label).
- **Causality.** A flagged finding says "timing depends on secret"; it does
  not say "the leak is exploitable." That's what fp-check is for.
