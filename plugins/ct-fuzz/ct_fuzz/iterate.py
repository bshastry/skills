#!/usr/bin/env python3
"""Iteration loop: sweep hyperparameters, find configuration with best F1
that has stabilized (low std-dev across runs).

Configurations swept:
- samples: 50k, 100k, 200k
- threshold: 4.5, 6.0, 8.0, 10.0
- second_order: with / without

For each (config), we run the full labeled panel R times and report
mean F1 and std-dev. A config is "stabilized" when sigma(F1) < 0.05.

We pick the configuration that maximizes mean F1 subject to the
stability bar — the simplest definition of "metric stabilizes".
"""

import argparse
import json
import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ct_fuzz"))

from ct_fuzz.driver import evaluate_target, save_run  # noqa: E402
from ct_fuzz.metrics import Verdict, classify, compute, stability  # noqa: E402
from ct_fuzz.panel import load_panel  # noqa: E402
from ct_fuzz.runner import run_target  # noqa: E402
from ct_fuzz.stats import cropped_welch_t, higher_order_preprocessing  # noqa: E402


def evaluate_one(harness: str, target: str, n: int) -> tuple[float, float]:
    """Return (|t1|, |t2|)."""
    r = run_target(harness, target, n)
    if not r.samples_a or not r.samples_b:
        return 0.0, 0.0
    t1, _ = cropped_welch_t(r.samples_a, r.samples_b)
    sa2, sb2 = higher_order_preprocessing(r.samples_a, r.samples_b)
    t2, _ = cropped_welch_t(sa2, sb2)
    return abs(t1), abs(t2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--samples", default="50000,100000")
    ap.add_argument("--thresholds", default="4.5,6.0,8.0,10.0")
    ap.add_argument("--second-order", default="on,off")
    ap.add_argument("--lang", default="go,rust")
    args = ap.parse_args()

    samples_list = [int(x) for x in args.samples.split(",")]
    thresholds = [float(x) for x in args.thresholds.split(",")]
    so_modes = args.second_order.split(",")

    selected_langs = set(args.lang.split(","))
    panel = load_panel(ROOT / "panel" / "panel.json")
    panel = [e for e in panel if e.lang in selected_langs]

    harness_for_lang = {}
    if "go" in selected_langs and (ROOT / "ct-fuzz-go").exists():
        harness_for_lang["go"] = str(ROOT / "ct-fuzz-go")
    if "rust" in selected_langs and (ROOT / "ct-fuzz-rust").exists():
        harness_for_lang["rust"] = str(ROOT / "ct-fuzz-rust")

    # Cache raw (t1, t2) per (samples, run, target). Then we don't have
    # to re-run for each threshold/SO combo — just re-classify.
    raw: dict[tuple[int, int, str], tuple[float, float]] = {}
    for samples in samples_list:
        for run_idx in range(args.repeats):
            print(f"[run] N={samples} repeat={run_idx+1}/{args.repeats}")
            for e in panel:
                if e.lang not in harness_for_lang:
                    continue
                t1, t2 = evaluate_one(harness_for_lang[e.lang], e.target, samples)
                raw[(samples, run_idx, e.target)] = (t1, t2)
                print(f"    {e.target:40s}  |t1|={t1:8.2f}  |t2|={t2:8.2f}")

    # Now sweep classifier configs.
    results = []
    for samples, threshold, so in product(samples_list, thresholds, so_modes):
        f1s = []
        afis = []
        for run_idx in range(args.repeats):
            verdicts: list[Verdict] = []
            for e in panel:
                key = (samples, run_idx, e.target)
                if key not in raw:
                    continue
                t1, t2 = raw[key]
                if so == "off":
                    flagged = abs(t1) > threshold
                else:
                    flagged = max(abs(t1), abs(t2)) > threshold
                verdicts.append(
                    Verdict(
                        target=e.target,
                        label=e.label,
                        flagged=flagged,
                        t_stat=max(abs(t1), abs(t2)),
                        t1=t1,
                        t2=t2,
                        crop_p=1.0,
                        n_samples_a=samples // 2,
                        n_samples_b=samples // 2,
                    )
                )
            m = compute(verdicts)
            f1s.append(m.f1)
            afis.append(m.afi if m.afi != float("inf") else 99.0)
        mu_f1, sd_f1 = stability(f1s)
        mu_afi = sum(afis) / len(afis)
        results.append(
            {
                "samples": samples,
                "threshold": threshold,
                "second_order": so,
                "f1_mean": mu_f1,
                "f1_std": sd_f1,
                "afi_mean": mu_afi,
                "f1_runs": f1s,
            }
        )

    # Sort by F1, ascending stability.
    results.sort(key=lambda r: (-r["f1_mean"], r["f1_std"], r["afi_mean"]))

    print("\n=== iteration sweep results (sorted by F1 desc) ===")
    print(
        f"{'N':>8s} {'thresh':>6s} {'SO':>3s}  "
        f"{'F1_mu':>6s} {'F1_sd':>6s}  {'AFI':>6s}  stable?"
    )
    for r in results:
        stable = "yes" if r["f1_std"] < 0.05 else "no"
        print(
            f"{r['samples']:>8d} {r['threshold']:>6.1f} {r['second_order']:>3s}  "
            f"{r['f1_mean']:>6.3f} {r['f1_std']:>6.3f}  {r['afi_mean']:>6.2f}  {stable}"
        )

    # Best: highest F1 with sd < 0.05, breaking ties by lower AFI.
    stabilized = [r for r in results if r["f1_std"] < 0.05]
    if stabilized:
        best = max(stabilized, key=lambda r: (r["f1_mean"], -r["afi_mean"]))
        print(
            f"\nStabilized best: N={best['samples']} thresh={best['threshold']} "
            f"SO={best['second_order']}  "
            f"F1={best['f1_mean']:.3f}±{best['f1_std']:.3f}  AFI={best['afi_mean']:.2f}"
        )
    else:
        print("\nNo configuration achieved σ(F1) < 0.05; consider more samples or repeats.")

    out = ROOT / "results" / "iterate.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"raw": {f"{k[0]}|{k[1]}|{k[2]}": v for k, v in raw.items()}, "results": results}, indent=2))
    print(f"\nSaved sweep to {out}")


if __name__ == "__main__":
    main()
