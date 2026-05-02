#!/usr/bin/env python3
"""Smoke test: run two targets and print t-statistics."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ct_fuzz.runner import run_target  # noqa: E402
from ct_fuzz.stats import cropped_welch_t, higher_order_preprocessing  # noqa: E402

HARNESS = str(Path(__file__).parent.parent / "ct-fuzz-go")


def evaluate(target: str, n: int) -> None:
    r = run_target(HARNESS, target, n)
    if not r.samples_a or not r.samples_b:
        print(f"{target}: no samples collected")
        return
    t1, p1 = cropped_welch_t(r.samples_a, r.samples_b)
    sa2, sb2 = higher_order_preprocessing(r.samples_a, r.samples_b)
    t2, p2 = cropped_welch_t(sa2, sb2)
    print(
        f"{target:40s}  n={len(r.samples_a)}+{len(r.samples_b):<6d}  "
        f"|t1|={t1:7.2f} crop={p1:.2f}  |t2|={t2:7.2f} crop={p2:.2f}"
    )


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    targets = sys.argv[2:] if len(sys.argv) > 2 else [
        "subtle_ConstantTimeCompare_32",
        "naive_eq_32",
        "bytes_Equal_32",
        "table_lookup_secret_index",
        "bigint_mod_secret",
    ]
    for t in targets:
        evaluate(t, n)
