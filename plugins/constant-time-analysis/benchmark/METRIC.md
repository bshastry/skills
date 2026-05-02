# CT-Score: Quality Metric for Constant-Time Static Analysis

## Motivation

The original analyzer scores well on recall (it flags any DIV/IDIV/SDIV/UDIV/FDIV/FSQRT it sees) but performs poorly on **precision** because:

1. Modern x86 (Ice Lake+) and AMD Zen 3+ ship DOITM (Data-Operand Independent Timing Mode), making DIV constant-time when enabled.
2. ARMv8.4 DIT bit affects many but **not** SDIV/UDIV — flagging SDIV on ARMv8.4-with-DIT is still correct, but flagging FP arithmetic with DIT is over-cautious for adds/subs/muls.
3. Division by **public compile-time constants** is harmless but indistinguishable from the secret-divisor case at the instruction level.
4. FP **denormals** are a real variable-time channel that the current analyzer **completely ignores** (FN).
5. **Embedded** Cortex-M0/M3 cores have variable-time MUL — also ignored.

A binary "PASSED/FAILED" verdict treats all alarms as equal cost. In practice an analyst's review budget is finite; every false alarm has a concrete cost (alarm fatigue), and every missed bug has a much larger cost.

## Metric: CT-Score

We score the analyzer per benchmark profile (legacy / modern-x86 / modern-arm / embedded). For a fixed profile:

```
TP = real vulnerabilities the analyzer flagged
FP = non-vulnerabilities the analyzer flagged
FN = real vulnerabilities the analyzer missed
TN = non-vulnerabilities the analyzer correctly did not flag

Precision   P = TP / (TP + FP)
Recall      R = TP / (TP + FN)
F_beta      F_b = (1 + b^2) * P * R / (b^2 * P + R)

Alarm-Density AD = (TP + FP) / N_cases       # alarms raised per benchmark case
Fatigue-Penalty f(AD) = exp(-lambda * max(0, AD - 1))   # 1 alarm/case is "free"

CT-Score    S = F_0.5 * f(AD)
```

### Why F_0.5?

`F_0.5` weights precision 4x more than recall. This matches how analysts actually triage: missing one bug among 50 alarms is bad, but **drowning the analyst in 200 alarms guarantees that real bugs get skipped**. Standard `F_1` treats them equally, which underweights alarm fatigue. `F_0.5` is the standard precision-favored F-score.

We **floor** recall at 0.95 in the final score: any drop in recall below 95 % is treated as a critical regression. Crypto bug detectors must catch the bugs; alarm fatigue is the secondary dimension to optimize.

### Why the multiplicative fatigue penalty?

`F_0.5` already rewards precision, but two analyzers with identical (P, R) can still differ in raw alarm volume — e.g. one flags every operation including TNs that happen to share a mnemonic, another flags only suspicious functions. The exponential penalty `exp(-lambda * (AD - 1))` (with `lambda = 0.1`) gives a small additional preference to the lower-volume analyzer when their P/R are tied.

### Reporting

Each iteration logs:

```json
{
  "iter": 3,
  "timestamp": "...",
  "profiles": {
    "legacy":      {"P": 0.71, "R": 1.00, "F1": 0.83, "F0.5": 0.76, "AD": 1.4, "S": 0.70},
    "modern-x86":  {"P": 0.92, "R": 1.00, "F1": 0.96, "F0.5": 0.93, "AD": 1.1, "S": 0.92},
    "modern-arm":  {"P": 0.85, "R": 1.00, "F1": 0.92, "F0.5": 0.87, "AD": 1.2, "S": 0.85},
    "embedded":    {"P": 0.80, "R": 0.95, "F1": 0.87, "F0.5": 0.82, "AD": 1.3, "S": 0.80}
  },
  "macro_S": 0.82
}
```

`macro_S` is the mean of per-profile `S`. Iteration is considered successful if `macro_S` increases AND no profile's recall drops below 0.95.

## Baseline (current main-branch analyzer)

Filled in by the evaluator on the first run. See `benchmark/results/baseline.json`.

## Termination Criterion

Iteration stops when **two consecutive iterations** show `|delta macro_S| < 0.01` (stabilized) or the iteration budget is exhausted (1 hour).
