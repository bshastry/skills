#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
CT-Score evaluator for the constant-time analysis benchmark.

Runs the analyzer over `benchmark/cases/*.c` under each CPU profile, compares
the alarm pattern against `ground_truth.json`, and prints a CT-Score report.
The CT-Score metric is defined in `benchmark/METRIC.md`.

Profiles:
    legacy       — pre-Ice Lake / pre-Zen3 / pre-DIT (default; current behavior)
    modern-x86   — Ice Lake+ / Zen3+ with DOITM available
    modern-arm   — ARMv8.4+ with DIT bit set
    embedded     — Cortex-M0/M3 / variable-time MUL CPUs

Usage:
    uv run benchmark/evaluator.py
    uv run benchmark/evaluator.py --iter 3 --note "added FTZ heuristic"
    uv run benchmark/evaluator.py --baseline   # write to results/baseline.json
"""
from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANALYZER = ROOT / "ct_analyzer" / "analyzer.py"
CASES_DIR = ROOT / "benchmark" / "cases"
GT_FILE = ROOT / "benchmark" / "ground_truth.json"
MEASURED_FILE = ROOT / "benchmark" / "measure" / "measured.json"
RESULTS_DIR = ROOT / "benchmark" / "results"

PROFILES = ["legacy", "modern-x86", "modern-arm", "embedded"]

# Map profile -> analyzer arch. We pick a canonical arch per profile so the
# benchmark is deterministic across machines. The analyzer's --cpu-profile flag
# (added in iteration 1) modulates the rules.
PROFILE_ARCH = {
    "legacy":     "x86_64",
    "modern-x86": "x86_64",
    "modern-arm": "arm64",
    "embedded":   "arm",
}

LAMBDA = 0.1   # alarm-density penalty rate
BETA = 0.5     # F-score precision weight
RECALL_FLOOR = 0.95


def run_analyzer(case_path: Path, profile: str) -> dict:
    """Run the analyzer on a case and return parsed JSON."""
    arch = PROFILE_ARCH[profile]
    cmd = [
        sys.executable,
        str(ANALYZER),
        "--arch", arch,
        "--opt-level", "O0",     # O0 surfaces explicit DIV instructions reliably
        "--warnings",
        "--json",
    ]
    # Pass profile if supported. The analyzer ignores unknown flags via subparse;
    # we tolerate the legacy analyzer too by retrying without --cpu-profile.
    cmd_with_profile = cmd + ["--cpu-profile", profile, str(case_path)]
    cmd_legacy = cmd + [str(case_path)]

    for c in (cmd_with_profile, cmd_legacy):
        try:
            r = subprocess.run(c, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "violations": [], "_cmd": " ".join(c)}
        # exit code 1 just means violations were found; that's fine
        try:
            data = json.loads(r.stdout)
            return data
        except json.JSONDecodeError:
            # likely "unrecognized argument: --cpu-profile" — retry without it
            if "--cpu-profile" in c:
                continue
            return {"error": r.stderr.strip(), "violations": [], "_cmd": " ".join(c)}
    return {"error": "all attempts failed", "violations": []}


def category_match(mnemonic: str, category: str, gt: dict) -> bool:
    cats = gt["_categories"]
    return mnemonic.lower() in cats.get(category, [])


def evaluate_case(case_file: str, profile: str, expected: dict, gt: dict) -> dict:
    """Return per-case verdict: {tp, fp, fn, tn, alarms}."""
    case_path = CASES_DIR / case_file
    result = run_analyzer(case_path, profile)
    if "error" in result and not result.get("violations"):
        # Compilation error — count as FN if alarm expected, else neutral
        return {
            "tp": 0, "fp": 0, "fn": 1 if expected["expected_alarm"] else 0,
            "tn": 0 if expected["expected_alarm"] else 1,
            "alarms": 0, "warnings": 0,
            "error": result.get("error"),
        }

    violations = result.get("violations", [])
    errors = [v for v in violations if v.get("severity") == "error"]
    warnings = [v for v in violations if v.get("severity") == "warning"]

    expected_alarm = expected["expected_alarm"]
    expected_warning = expected.get("expected_warning", False)
    category = expected["category"]

    # Did the analyzer raise an ERROR for the expected category?
    fired_error = any(
        category_match(v["mnemonic"], category, gt) for v in errors
    )
    # Errors in *other* categories on a TN case are also FPs (extra noise)
    extra_errors = [v for v in errors
                    if not category_match(v["mnemonic"], category, gt)]

    tp = fp = fn = tn = 0
    if expected_alarm:
        if fired_error:
            tp = 1
        else:
            fn = 1
    else:
        # Should NOT alarm
        if fired_error or extra_errors:
            fp = 1
        else:
            tn = 1

    # Warning expectation (case 13): we want warning, not error
    if expected_warning:
        if warnings and not errors:
            tp = 1
            fn = 0
            tn = 0
            fp = 0
        elif errors:
            # Over-classified branch as ERROR — count as FP (over-severity)
            fp = 1
            tp = 0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "alarms": len(errors),
        "warnings": len(warnings),
    }


def f_beta(p: float, r: float, beta: float) -> float:
    if p + r == 0:
        return 0.0
    return (1 + beta * beta) * p * r / (beta * beta * p + r)


def score_profile(rows: list[dict], n_cases: int) -> dict:
    tp = sum(r["tp"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows)
    tn = sum(r["tn"] for r in rows)
    total_alarms = sum(r["alarms"] for r in rows)

    p = tp / (tp + fp) if (tp + fp) else 1.0   # vacuously perfect if no alarms at all
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = f_beta(p, r, 1.0)
    f05 = f_beta(p, r, BETA)
    ad = total_alarms / max(n_cases, 1)
    fatigue = math.exp(-LAMBDA * max(0.0, ad - 1.0))
    s = f05 * fatigue
    if r < RECALL_FLOOR:
        # Hard penalty: drop score proportional to how far below floor
        s *= (r / RECALL_FLOOR)
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "P": round(p, 3), "R": round(r, 3),
        "F1": round(f1, 3), "F0.5": round(f05, 3),
        "AD": round(ad, 2),
        "fatigue": round(fatigue, 3),
        "S": round(s, 3),
    }


def evaluate_measurement_grounding() -> dict:
    """Score how well the analyzer's per-profile rule set matches measured
    variable-time behavior on the host CPU.

    For each (profile, mnemonic in measured table), compare:
        analyzer_would_flag(profile, mnemonic)   <—>   measured_variable_time
    Compute precision, recall, and a grounding F0.5 per profile.
    """
    if not MEASURED_FILE.exists():
        return {"available": False,
                "note": "run benchmark/measure/run_measurements.py to populate"}
    m = json.loads(MEASURED_FILE.read_text())
    by_mnem = m["by_mnemonic"]

    # Determine, for each profile, which mnemonics the analyzer would treat
    # as ERROR. We re-import the rule tables directly.
    import importlib.util
    spec = importlib.util.spec_from_file_location("ct_analyzer", ANALYZER)
    ana = importlib.util.module_from_spec(spec); spec.loader.exec_module(ana)

    # Each profile is paired with the guards a careful developer SHOULD use.
    # The grounding score then reflects how well the analyzer + recommended
    # guards match measured CPU behavior.
    profile_guards = {
        "legacy":     set(),                                       # no guards available
        "modern-x86": {"CT_DOITM_ENABLED", "CT_FTZ_DAZ"},
        "modern-arm": {"CT_ARM_DIT_ENABLED", "CT_FTZ_DAZ"},
        "embedded":   {"CT_FTZ_DAZ"},                              # FTZ available; no DOITM/DIT
    }

    def analyzer_flags(profile: str, arch: str, mnem: str) -> bool:
        # Reproduce the parser's rule construction with the recommended guards.
        rules = dict(ana.DANGEROUS_INSTRUCTIONS.get(arch, {}).get("errors", {}))
        guards = profile_guards.get(profile, set())
        for m in ana.suppression_set(arch, profile, guards):
            rules.pop(m, None)
        if "CT_FTZ_DAZ" not in guards:
            for m, reason in ana.DENORMAL_RISK_INSTRUCTIONS.get(arch, {}).items():
                rules.setdefault(m, reason)
        if profile == "embedded":
            for m, reason in ana.EMBEDDED_MUL_INSTRUCTIONS.get(arch, {}).items():
                rules.setdefault(m, reason)
        return mnem.lower() in rules

    profiles = ["legacy", "modern-x86", "modern-arm", "embedded"]
    arch_for = {"legacy": "x86_64", "modern-x86": "x86_64",
                "modern-arm": "arm64", "embedded": "arm"}
    # Mnemonics are arch-specific; classify each by inspecting which arch's
    # rule tables it appears in.
    arch_mnems: dict[str, set[str]] = {a: set() for a in ana.DANGEROUS_INSTRUCTIONS}
    for a, tab in ana.DANGEROUS_INSTRUCTIONS.items():
        arch_mnems[a].update(tab.get("errors", {}).keys())
    for a, tab in ana.DENORMAL_RISK_INSTRUCTIONS.items():
        arch_mnems.setdefault(a, set()).update(tab.keys())
    for a, tab in ana.EMBEDDED_MUL_INSTRUCTIONS.items():
        arch_mnems.setdefault(a, set()).update(tab.keys())

    out = {"host_cpu": m.get("host_cpu", "?"), "by_profile": {}}
    for prof in profiles:
        arch = arch_for[prof]
        relevant_arch_mnems = arch_mnems.get(arch, set())
        # Only score mnemonics that BOTH belong to this arch's rule space
        # AND have a measurement record (skip documented-only entries that
        # belong to a different arch).
        candidate = []
        for mnem, info in by_mnem.items():
            if info["source"] == "measured" and mnem in relevant_arch_mnems:
                candidate.append(mnem)
            elif info["source"] == "documented" and mnem in relevant_arch_mnems:
                candidate.append(mnem)

        tp = fp = fn = tn = 0
        confusion = []
        for mnem in sorted(candidate):
            measured_info = by_mnem[mnem]
            measured_vt = measured_info["measured_variable_time"]
            flagged = analyzer_flags(prof, arch, mnem)
            if measured_vt and flagged:    tp += 1
            elif measured_vt and not flagged: fn += 1
            elif not measured_vt and flagged: fp += 1
            else: tn += 1
            confusion.append({
                "mnemonic": mnem,
                "measured_variable_time": measured_vt,
                "analyzer_flags": flagged,
                "source": measured_info["source"],
            })
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else 1.0
        f05 = (1.25 * p * r) / (0.25 * p + r) if (p + r) else 0
        out["by_profile"][prof] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "P": round(p, 3), "R": round(r, 3),
            "F0.5": round(f05, 3),
            "confusion": confusion,
        }
    return out


def evaluate_all() -> dict:
    gt = json.loads(GT_FILE.read_text())
    cases = gt["cases"]
    n = len(cases)

    report = {"profiles": {}, "per_case": {}}
    macro = []
    for profile in PROFILES:
        rows = []
        per_case = {}
        for case_file, info in cases.items():
            expected = info["profiles"][profile]
            row = evaluate_case(case_file, profile, expected, gt)
            row["expected_alarm"] = expected["expected_alarm"]
            rows.append(row)
            per_case[case_file] = row
        scores = score_profile(rows, n)
        report["profiles"][profile] = scores
        report["per_case"][profile] = per_case
        macro.append(scores["S"])

    report["macro_S"] = round(sum(macro) / len(macro), 3)

    # Measurement-grounded mnemonic-level metric.
    mg = evaluate_measurement_grounding()
    report["measurement_grounding"] = mg
    if mg.get("by_profile"):
        mg_macro = sum(p["F0.5"] for p in mg["by_profile"].values()) / len(mg["by_profile"])
        report["mg_macro_F05"] = round(mg_macro, 3)
        # Combined CT-Score: 0.6 * case-level + 0.4 * measurement-grounded
        report["combined_S"] = round(0.6 * report["macro_S"] + 0.4 * mg_macro, 3)
    else:
        report["mg_macro_F05"] = None
        report["combined_S"] = report["macro_S"]
    return report


def print_report(report: dict, verbose: bool = False) -> None:
    print("=" * 78)
    if report.get("combined_S") is not None and report.get("mg_macro_F05") is not None:
        print(f"CT-Score Report   combined_S = {report['combined_S']:.3f}   "
              f"(case macro_S = {report['macro_S']:.3f}, "
              f"measurement F0.5 = {report['mg_macro_F05']:.3f})")
    else:
        print(f"CT-Score Report   macro_S = {report['macro_S']:.3f}")
    print("=" * 78)
    for profile, s in report["profiles"].items():
        flag = "" if s["R"] >= RECALL_FLOOR else "   <-- RECALL FLOOR VIOLATION"
        print(
            f"  {profile:<12} P={s['P']:.2f} R={s['R']:.2f} "
            f"F1={s['F1']:.2f} F0.5={s['F0.5']:.2f} "
            f"AD={s['AD']:.2f} S={s['S']:.3f}"
            f"   [TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}]{flag}"
        )
    if report.get("measurement_grounding", {}).get("by_profile"):
        mg = report["measurement_grounding"]
        print()
        print(f"Measurement grounding (host: {mg.get('host_cpu', '?')}):")
        for prof, s in mg["by_profile"].items():
            print(f"  {prof:<12} P={s['P']:.2f} R={s['R']:.2f} F0.5={s['F0.5']:.2f}"
                  f"   [TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}]")
    if verbose:
        print()
        print("Per-case detail (showing FP/FN only):")
        for profile in PROFILES:
            for case, row in report["per_case"][profile].items():
                if row["fp"] or row["fn"]:
                    kind = "FP" if row["fp"] else "FN"
                    print(f"  [{profile:<12}] {kind} {case}: alarms={row['alarms']} warns={row['warnings']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iter", type=int, default=0)
    ap.add_argument("--note", default="")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report = evaluate_all()
    report["iter"] = args.iter
    report["note"] = args.note
    report["timestamp"] = datetime.now(timezone.utc).isoformat()

    print_report(report, verbose=args.verbose)

    if args.baseline:
        out = RESULTS_DIR / "baseline.json"
    else:
        out = RESULTS_DIR / f"iter_{args.iter:02d}.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\nWritten: {out.relative_to(ROOT)}")

    # Append concise line to history.jsonl
    hist = RESULTS_DIR / "history.jsonl"
    with hist.open("a") as f:
        line = {
            "iter": args.iter, "macro_S": report["macro_S"],
            "note": args.note, "timestamp": report["timestamp"],
            "profiles": {k: {"P": v["P"], "R": v["R"], "S": v["S"]}
                         for k, v in report["profiles"].items()},
        }
        f.write(json.dumps(line) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
