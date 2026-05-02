"""Online statistics for dudect-style t-test.

Welford's algorithm for streaming mean/variance, plus a percentile-cropped
Welch's t-test that follows the original dudect approach: compute |t| at
several upper-tail crop percentiles and report the maximum.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class Welford:
    """Online mean/variance via Welford's algorithm."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0


def welch_t(a: Welford, b: Welford) -> float:
    """Welch's t-statistic for unequal variances. Returns 0.0 if undefined."""
    if a.n < 2 or b.n < 2:
        return 0.0
    va, vb = a.variance, b.variance
    denom = math.sqrt(va / a.n + vb / b.n)
    if denom == 0.0:
        return 0.0
    return (a.mean - b.mean) / denom


def cropped_welch_t(
    samples_a: list[float],
    samples_b: list[float],
    crop_percentiles: tuple[float, ...] = (1.0, 0.99, 0.97, 0.95, 0.90, 0.80, 0.60, 0.50),
) -> tuple[float, float]:
    """Compute |t| at multiple upper-tail crop thresholds; return max |t| and the
    crop that achieved it.

    `crop_percentiles` are the fraction of samples kept (1.0 = no crop). Cropping
    keeps low values and discards high outliers — preempts and page faults manifest
    as huge positive timing tails that can dominate the mean.

    Cropping is applied per-class on the per-class distribution. This matches
    dudect's `prepare_percentiles`.
    """
    best_abs = 0.0
    best_p = 1.0
    if len(samples_a) < 2 or len(samples_b) < 2:
        return 0.0, 1.0

    sa = sorted(samples_a)
    sb = sorted(samples_b)
    for p in crop_percentiles:
        ka = max(2, int(len(sa) * p))
        kb = max(2, int(len(sb) * p))
        wa = Welford()
        wb = Welford()
        for x in sa[:ka]:
            wa.add(x)
        for x in sb[:kb]:
            wb.add(x)
        t = abs(welch_t(wa, wb))
        if t > best_abs:
            best_abs = t
            best_p = p
    return best_abs, best_p


def higher_order_preprocessing(
    samples_a: list[float], samples_b: list[float]
) -> tuple[list[float], list[float]]:
    """Apply dudect's 'second-order' preprocessing: subtract the per-class mean
    and square the residuals. This catches *variance* differences that the raw
    t-test misses (e.g. branch predictor jitter that has same mean but wider tail).
    """
    if not samples_a or not samples_b:
        return samples_a, samples_b
    ma = sum(samples_a) / len(samples_a)
    mb = sum(samples_b) / len(samples_b)
    return [(x - ma) ** 2 for x in samples_a], [(x - mb) ** 2 for x in samples_b]


def t_threshold(level: str = "default") -> float:
    """Decision thresholds.

    - 'loose'  = 3.5  (more recall, more false positives)
    - 'default'= 4.5  (dudect's recommended)
    - 'strict' = 5.0  (more precision, fewer false positives)
    """
    return {"loose": 3.5, "default": 4.5, "strict": 5.0}[level]
