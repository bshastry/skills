#!/usr/bin/env python3
"""Run the full labeled panel once. Use this for iteration during tuning."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ct_fuzz"))

from ct_fuzz.driver import evaluate_target, save_run  # noqa: E402
from ct_fuzz.metrics import compute  # noqa: E402
from ct_fuzz.panel import load_panel  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=100_000)
    ap.add_argument("--threshold", type=float, default=4.5)
    ap.add_argument("--run-id", default="default")
    ap.add_argument("--lang", default="go,rust", help="comma-separated subset")
    args = ap.parse_args()

    panel = load_panel(ROOT / "panel" / "panel.json")
    selected_langs = set(args.lang.split(","))
    panel = [e for e in panel if e.lang in selected_langs]

    harness_for_lang = {}
    if "go" in selected_langs and (ROOT / "ct-fuzz-go").exists():
        harness_for_lang["go"] = str(ROOT / "ct-fuzz-go")
    if "rust" in selected_langs and (ROOT / "ct-fuzz-rust").exists():
        harness_for_lang["rust"] = str(ROOT / "ct-fuzz-rust")

    print(f"=== run {args.run_id}  N={args.samples}  thresh={args.threshold} ===", flush=True)
    print(
        f"{'target':40s}  {'label':10s}  {'flagged':>7s}  {'|t1|':>8s}  {'|t2|':>8s}  {'maxT':>8s}",
        flush=True,
    )
    verdicts = []
    for e in panel:
        if e.lang not in harness_for_lang:
            continue
        v = evaluate_target(harness_for_lang[e.lang], e, args.samples, args.threshold)
        flag = "LEAK" if v.flagged else "ok"
        print(
            f"{v.target:40s}  {v.label:10s}  {flag:>7s}  "
            f"{abs(v.t1):8.2f}  {abs(v.t2):8.2f}  {v.t_stat:8.2f}",
            flush=True,
        )
        verdicts.append(v)
    metrics = compute(verdicts)

    print(
        f"\n=== run {args.run_id}  N={args.samples}  thresh={args.threshold} ==="
    )
    print(f"{'target':40s}  {'label':10s}  {'flagged':>7s}  {'|t1|':>8s}  {'|t2|':>8s}  {'maxT':>8s}")
    for v in verdicts:
        flag = "LEAK" if v.flagged else "ok"
        print(
            f"{v.target:40s}  {v.label:10s}  {flag:>7s}  "
            f"{abs(v.t1):8.2f}  {abs(v.t2):8.2f}  {v.t_stat:8.2f}"
        )
    print(
        f"\nTP={metrics.tp} FP={metrics.fp} TN={metrics.tn} FN={metrics.fn}  "
        f"P={metrics.precision:.3f} R={metrics.recall:.3f} F1={metrics.f1:.3f}  AFI={metrics.afi:.2f}  "
        f"unknown_flagged={metrics.flagged_unknown}/{metrics.total_unknown}"
    )

    save_run(
        ROOT / "results",
        args.run_id,
        {"samples": args.samples, "threshold": args.threshold, "lang": args.lang},
        verdicts,
        metrics,
    )


if __name__ == "__main__":
    main()
