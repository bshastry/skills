"""Metric definitions and classifier for ct-fuzz.

Classifier
----------
A target is flagged "leaky" if the cropped Welch's |t| (max over crop
percentiles, max over first-order and second-order distributions) exceeds
the threshold. dudect's recommended threshold is 4.5, corresponding to
p ≈ 1e-5 under the null.

Metrics on a labeled panel
--------------------------
Labels: "ct" (known constant-time), "leaky" (known variable-time),
"microarch" (real leak but out of dudect's scope), "unknown" (production).

We compute precision, recall, F1 over targets labeled "ct" and "leaky".
"microarch" targets are excluded from the metric (dudect's wall-clock
methodology cannot reach them).

- precision = TP / (TP + FP)        — fraction of alerts that are real
- recall    = TP / (TP + FN)        — fraction of leaks we catch
- F1        = 2 * P * R / (P + R)
- alarm_fatigue_index (AFI) = (TP + FP) / max(TP, 1)
                            — alerts a human reads per real finding (lower is better;
                              AFI=1 is perfect, AFI=5 means 4 wasted reads per find)
- stability = standard deviation of F1 across N independent runs of the
  same configuration. A configuration is "stabilized" when σ(F1) < 0.05.

Why AFI specifically: precision treats every false positive equally, but
the cost an analyst actually pays is "how many alerts do I have to read
to find one real bug." That is (TP+FP)/TP, not 1-precision. With 1 TP
and 4 FP, precision is 0.20 but the human reads 5 alerts to confirm 1 —
the AFI of 5 is the operational cost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Verdict:
    target: str
    label: str  # ct | leaky | microarch | unknown
    flagged: bool
    t_stat: float  # max(|t1|, |t2|)
    t1: float
    t2: float
    crop_p: float
    n_samples_a: int
    n_samples_b: int


def classify(t1: float, t2: float, threshold: float = 4.5) -> bool:
    return max(abs(t1), abs(t2)) > threshold


@dataclass
class PanelMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    afi: float
    flagged_unknown: int
    total_unknown: int
    excluded_microarch: int


def compute(verdicts: list[Verdict]) -> PanelMetrics:
    tp = fp = tn = fn = 0
    flagged_unknown = total_unknown = 0
    microarch = 0
    for v in verdicts:
        if v.label == "microarch":
            microarch += 1
            continue
        if v.label in ("unknown", "production"):
            total_unknown += 1
            if v.flagged:
                flagged_unknown += 1
            continue
        is_leak = v.label == "leaky"
        if is_leak and v.flagged:
            tp += 1
        elif is_leak and not v.flagged:
            fn += 1
        elif not is_leak and v.flagged:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    afi = (tp + fp) / tp if tp else float("inf") if fp else 1.0
    return PanelMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=p,
        recall=r,
        f1=f1,
        afi=afi,
        flagged_unknown=flagged_unknown,
        total_unknown=total_unknown,
        excluded_microarch=microarch,
    )


def stability(f1_runs: list[float]) -> tuple[float, float]:
    """Return (mean F1, std F1) across runs."""
    n = len(f1_runs)
    if n == 0:
        return 0.0, 0.0
    mu = sum(f1_runs) / n
    if n < 2:
        return mu, 0.0
    var = sum((x - mu) ** 2 for x in f1_runs) / (n - 1)
    return mu, var**0.5
