"""Driver: run a labeled panel, return verdicts and metrics."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from .metrics import Verdict, classify, compute, PanelMetrics
from .panel import PanelEntry, load_panel
from .runner import run_target
from .stats import cropped_welch_t, higher_order_preprocessing


def evaluate_target(harness: str, entry: PanelEntry, n_samples: int, threshold: float) -> Verdict:
    r = run_target(harness, entry.target, n_samples)
    if not r.samples_a or not r.samples_b:
        return Verdict(
            target=entry.target,
            label=entry.label,
            flagged=False,
            t_stat=0.0,
            t1=0.0,
            t2=0.0,
            crop_p=1.0,
            n_samples_a=0,
            n_samples_b=0,
        )
    t1, p1 = cropped_welch_t(r.samples_a, r.samples_b)
    sa2, sb2 = higher_order_preprocessing(r.samples_a, r.samples_b)
    t2, p2 = cropped_welch_t(sa2, sb2)
    flagged = classify(t1, t2, threshold)
    return Verdict(
        target=entry.target,
        label=entry.label,
        flagged=flagged,
        t_stat=max(abs(t1), abs(t2)),
        t1=t1,
        t2=t2,
        crop_p=p1 if abs(t1) > abs(t2) else p2,
        n_samples_a=len(r.samples_a),
        n_samples_b=len(r.samples_b),
    )


def evaluate_panel(
    harness_for_lang: dict[str, str],
    panel: list[PanelEntry],
    n_samples: int,
    threshold: float,
) -> tuple[list[Verdict], PanelMetrics]:
    verdicts: list[Verdict] = []
    for e in panel:
        if e.lang not in harness_for_lang:
            continue
        v = evaluate_target(harness_for_lang[e.lang], e, n_samples, threshold)
        verdicts.append(v)
    return verdicts, compute(verdicts)


def save_run(out_dir: Path, run_id: str, config: dict, verdicts: list[Verdict], metrics: PanelMetrics) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"run-{run_id}.json"
    p.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "ts": time.time(),
                "config": config,
                "verdicts": [asdict(v) for v in verdicts],
                "metrics": asdict(metrics),
            },
            indent=2,
        )
    )
    return p
