#!/usr/bin/env python3
"""Re-classify cached iteration data with current panel labels.

Reads results/iterate.json (raw t1/t2 per (samples, run, target)) and
re-applies the current panel labels to compute updated metrics. Useful
when panel labels change after the data was collected.
"""

import argparse
import json
import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ct_fuzz"))

from ct_fuzz.metrics import Verdict, compute, stability  # noqa: E402
from ct_fuzz.panel import load_panel  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="results/iterate.json")
    ap.add_argument("--thresholds", default="4.5,6.0,8.0,10.0,15.0")
    ap.add_argument("--second-order", default="on,off")
    args = ap.parse_args()

    src = ROOT / args.source
    data = json.loads(src.read_text())
    raw = data["raw"]

    # Determine sample sizes and repeat counts from raw keys.
    samples_set = set()
    repeats_per_samples: dict[int, int] = {}
    targets_set = set()
    for key in raw:
        n_str, run_str, target = key.split("|")
        n = int(n_str)
        r = int(run_str)
        samples_set.add(n)
        repeats_per_samples[n] = max(repeats_per_samples.get(n, 0), r + 1)
        targets_set.add(target)

    panel = load_panel(ROOT / "panel" / "panel.json")
    label_for = {e.target: e.label for e in panel}

    thresholds = [float(x) for x in args.thresholds.split(",")]
    so_modes = args.second_order.split(",")

    print("=== reclassified sweep (sorted by F1 desc, then stability) ===")
    print(
        f"{'N':>8s} {'thresh':>6s} {'SO':>3s}  "
        f"{'F1_mu':>6s} {'F1_sd':>6s}  {'AFI':>6s}  {'TP':>2s} {'FP':>2s} {'FN':>2s} {'TN':>2s}  unk_flag stable?"
    )
    rows = []
    for samples in sorted(samples_set):
        for threshold, so in product(thresholds, so_modes):
            f1s = []
            afis = []
            tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "uf": 0, "ut": 0}
            for run_idx in range(repeats_per_samples[samples]):
                verdicts: list[Verdict] = []
                for target in targets_set:
                    if target not in label_for:
                        continue
                    key = f"{samples}|{run_idx}|{target}"
                    if key not in raw:
                        continue
                    t1, t2 = raw[key]
                    if so == "off":
                        flagged = abs(t1) > threshold
                    else:
                        flagged = max(abs(t1), abs(t2)) > threshold
                    verdicts.append(
                        Verdict(
                            target=target,
                            label=label_for[target],
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
                tot["tp"] += m.tp
                tot["fp"] += m.fp
                tot["fn"] += m.fn
                tot["tn"] += m.tn
                tot["uf"] += m.flagged_unknown
                tot["ut"] += m.total_unknown
            mu_f1, sd_f1 = stability(f1s)
            mu_afi = sum(afis) / len(afis)
            n_runs = len(f1s)
            avg_tp = tot["tp"] / n_runs
            avg_fp = tot["fp"] / n_runs
            avg_fn = tot["fn"] / n_runs
            avg_tn = tot["tn"] / n_runs
            stable = "yes" if sd_f1 < 0.05 else "no"
            row = {
                "samples": samples,
                "threshold": threshold,
                "second_order": so,
                "f1_mean": mu_f1,
                "f1_std": sd_f1,
                "afi_mean": mu_afi,
                "tp": avg_tp,
                "fp": avg_fp,
                "fn": avg_fn,
                "tn": avg_tn,
                "unknown_flagged_per_run": tot["uf"] / n_runs,
                "unknown_total_per_run": tot["ut"] / n_runs,
                "stable": stable,
            }
            rows.append(row)

    rows.sort(key=lambda r: (-r["f1_mean"], r["f1_std"], r["afi_mean"]))
    for r in rows:
        unk = f"{r['unknown_flagged_per_run']:.0f}/{r['unknown_total_per_run']:.0f}"
        print(
            f"{r['samples']:>8d} {r['threshold']:>6.1f} {r['second_order']:>3s}  "
            f"{r['f1_mean']:>6.3f} {r['f1_std']:>6.3f}  {r['afi_mean']:>6.2f}  "
            f"{r['tp']:>2.0f} {r['fp']:>2.0f} {r['fn']:>2.0f} {r['tn']:>2.0f}  {unk:>8s}  {r['stable']}"
        )

    stabilized = [r for r in rows if r["stable"] == "yes"]
    if stabilized:
        best = max(stabilized, key=lambda r: (r["f1_mean"], -r["afi_mean"]))
        print(
            f"\nStabilized best: N={best['samples']} thresh={best['threshold']} SO={best['second_order']}  "
            f"F1={best['f1_mean']:.3f}±{best['f1_std']:.3f}  AFI={best['afi_mean']:.2f}"
        )

    out = ROOT / "results" / "reclassified.json"
    out.write_text(json.dumps({"rows": rows}, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
