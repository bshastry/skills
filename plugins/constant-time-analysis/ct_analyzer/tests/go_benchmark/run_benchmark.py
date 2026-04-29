#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Go crypto side-channel benchmark runner.

Validates that the ct_analyzer Go support detects every known-bad pattern in
``vulnerable/`` and produces no ERROR-level findings on the patterns in
``safe/`` (apart from a small set of documented expected false positives).

The benchmark is the production gate for shipping this tool to crypto teams.
We aim for these properties:

* Zero false negatives on the ``vulnerable/`` corpus on x86_64 and arm64.
* Zero unexpected ERROR-level findings on the ``safe/`` corpus.
* Total runtime < 30 s on a developer laptop.

Usage:
    uv run run_benchmark.py [--arch x86_64,arm64] [--analyzer PATH]

Exit codes:
    0  benchmark passed
    1  one or more expectations failed
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
# .../ct_analyzer/tests/go_benchmark -> .../ct_analyzer/analyzer.py
DEFAULT_ANALYZER = BENCH_DIR.parents[1] / "analyzer.py"

# Map a mnemonic (as reported by ct_analyzer) to a coarse class so the
# expectations file can describe "any kind of integer divide" without
# enumerating every architecture's spelling.
MNEMONIC_CLASSES: dict[str, str] = {
    # Integer divide
    "DIV": "INTEGER_DIVIDE",
    "DIVQ": "INTEGER_DIVIDE",
    "DIVL": "INTEGER_DIVIDE",
    "DIVW": "INTEGER_DIVIDE",
    "DIVB": "INTEGER_DIVIDE",
    "IDIV": "INTEGER_DIVIDE",
    "IDIVQ": "INTEGER_DIVIDE",
    "IDIVL": "INTEGER_DIVIDE",
    "IDIVW": "INTEGER_DIVIDE",
    "IDIVB": "INTEGER_DIVIDE",
    "UDIV": "INTEGER_DIVIDE",
    "SDIV": "INTEGER_DIVIDE",
    "UDIVW": "INTEGER_DIVIDE",
    "SDIVW": "INTEGER_DIVIDE",
    "DIVU": "INTEGER_DIVIDE",
    "DIVUW": "INTEGER_DIVIDE",
    "DIVDU": "INTEGER_DIVIDE",
    # Integer modulo (Go reports REMW etc.)
    "REM": "INTEGER_MODULO",
    "REMU": "INTEGER_MODULO",
    "REMW": "INTEGER_MODULO",
    "REMUW": "INTEGER_MODULO",
    "MODD": "INTEGER_MODULO",
    "MODW": "INTEGER_MODULO",
    "MODWU": "INTEGER_MODULO",
    "MODDU": "INTEGER_MODULO",
    # FP divide / sqrt
    "DIVSS": "FP_DIVIDE",
    "DIVSD": "FP_DIVIDE",
    "DIVPS": "FP_DIVIDE",
    "DIVPD": "FP_DIVIDE",
    "FDIV": "FP_DIVIDE",
    "FDIVS": "FP_DIVIDE",
    "FDIVD": "FP_DIVIDE",
    "FDIV.S": "FP_DIVIDE",
    "FDIV.D": "FP_DIVIDE",
    "VDIVSD": "FP_DIVIDE",
    "VDIVSS": "FP_DIVIDE",
    "SQRTSS": "FP_SQRT",
    "SQRTSD": "FP_SQRT",
    "FSQRT": "FP_SQRT",
    "FSQRTS": "FP_SQRT",
    "FSQRTD": "FP_SQRT",
    # Conditional branches (warnings)
    "JE": "CONDITIONAL_BRANCH",
    "JNE": "CONDITIONAL_BRANCH",
    "JZ": "CONDITIONAL_BRANCH",
    "JNZ": "CONDITIONAL_BRANCH",
    "JG": "CONDITIONAL_BRANCH",
    "JL": "CONDITIONAL_BRANCH",
    "JLE": "CONDITIONAL_BRANCH",
    "JGE": "CONDITIONAL_BRANCH",
    "JA": "CONDITIONAL_BRANCH",
    "JAE": "CONDITIONAL_BRANCH",
    "JB": "CONDITIONAL_BRANCH",
    "JBE": "CONDITIONAL_BRANCH",
    "JS": "CONDITIONAL_BRANCH",
    "JNS": "CONDITIONAL_BRANCH",
    "JC": "CONDITIONAL_BRANCH",
    "JNC": "CONDITIONAL_BRANCH",
    # Plan 9 / Go-amd64 mnemonics
    "JEQ": "CONDITIONAL_BRANCH",
    "JLT": "CONDITIONAL_BRANCH",
    "JGT": "CONDITIONAL_BRANCH",
    "JHI": "CONDITIONAL_BRANCH",
    "JLS": "CONDITIONAL_BRANCH",
    "JMI": "CONDITIONAL_BRANCH",
    "JPL": "CONDITIONAL_BRANCH",
    "JCS": "CONDITIONAL_BRANCH",
    "JCC": "CONDITIONAL_BRANCH",
    "JOS": "CONDITIONAL_BRANCH",
    "JOC": "CONDITIONAL_BRANCH",
    "JPS": "CONDITIONAL_BRANCH",
    "JPC": "CONDITIONAL_BRANCH",
    "BEQ": "CONDITIONAL_BRANCH",
    "BNE": "CONDITIONAL_BRANCH",
    "B.EQ": "CONDITIONAL_BRANCH",
    "B.NE": "CONDITIONAL_BRANCH",
    "B.LT": "CONDITIONAL_BRANCH",
    "B.LE": "CONDITIONAL_BRANCH",
    "B.GT": "CONDITIONAL_BRANCH",
    "B.GE": "CONDITIONAL_BRANCH",
    "B.HI": "CONDITIONAL_BRANCH",
    "B.LS": "CONDITIONAL_BRANCH",
    "CBZ": "CONDITIONAL_BRANCH",
    "CBNZ": "CONDITIONAL_BRANCH",
    "TBZ": "CONDITIONAL_BRANCH",
    "TBNZ": "CONDITIONAL_BRANCH",
}


def classify(mnemonic: str) -> str:
    return MNEMONIC_CLASSES.get(mnemonic.upper(), "OTHER")


def short_func(name: str) -> str:
    """Strip the package path so users can write 'EqualSafe' not 'github.com/...EqualSafe'."""
    return name.rsplit(".", 1)[-1]


@dataclass
class Result:
    file: str
    arch: str
    label: str
    passed: bool
    detail: str
    elapsed: float


def run_analyzer(analyzer: Path, source: Path, arch: str, with_warnings: bool) -> dict:
    # We invoke analyzer.py directly via python3 (its imports are stdlib-only)
    # so the benchmark does not interact with uv's environment management.
    # Going through `uv run` from inside another uv process produces noisy
    # VIRTUAL_ENV mismatch warnings that pollute stdout in some setups.
    cmd = [
        sys.executable,
        str(analyzer),
        "--arch",
        arch,
        "--json",
    ]
    if with_warnings:
        cmd.append("--warnings")
    cmd.append(str(source))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        return {"error": proc.stderr or "no output", "violations": []}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output", "stdout": proc.stdout, "violations": []}


def evaluate(report: dict, expectations: dict, with_warnings: bool) -> tuple[bool, list[str]]:
    """Returns (passed, list_of_failure_messages)."""
    failures: list[str] = []
    if "error" in report and not report.get("violations"):
        failures.append(f"analyzer error: {report['error'][:200]}")
        return False, failures

    violations = report.get("violations", [])
    # Normalize for matching
    seen: set[tuple[str, str]] = set()
    for v in violations:
        seen.add((short_func(v["function"]), classify(v["mnemonic"])))

    # must_detect (errors only)
    expected = expectations.get("must_detect", [])
    if not with_warnings:
        for fact in expected:
            key = (fact["function"], fact["mnemonic_class"])
            if key not in seen:
                failures.append(
                    f"missing required ERROR finding: {fact['function']} / {fact['mnemonic_class']}"
                )

    # must_detect_with_warnings (run with --warnings)
    expected_w = expectations.get("must_detect_with_warnings", [])
    if with_warnings:
        for fact in expected_w:
            key = (fact["function"], fact["mnemonic_class"])
            if key not in seen:
                failures.append(
                    f"missing required WARN finding: {fact['function']} / {fact['mnemonic_class']}"
                )

    # must_not_detect_errors
    forbidden = set(expectations.get("must_not_detect_errors", []))
    if forbidden and not with_warnings:
        for v in violations:
            if v["severity"] != "error":
                continue
            if short_func(v["function"]) in forbidden:
                failures.append(
                    f"unexpected ERROR finding on safe code: "
                    f"{short_func(v['function'])} / {v['mnemonic']}"
                )

    return not failures, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", default="x86_64,arm64", help="comma-separated archs")
    ap.add_argument("--analyzer", default=str(DEFAULT_ANALYZER))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    archs = args.arch.split(",")
    analyzer = Path(args.analyzer)
    expectations = json.loads((BENCH_DIR / "expectations.json").read_text())

    results: list[Result] = []
    for rel_path, spec in expectations.items():
        if rel_path.startswith("_"):
            continue
        source = BENCH_DIR / rel_path
        for arch in archs:
            arch_spec = spec.get(arch)
            if not arch_spec:
                continue

            # Errors-only pass
            t0 = time.time()
            report = run_analyzer(analyzer, source, arch, with_warnings=False)
            ok, fails = evaluate(report, arch_spec, with_warnings=False)
            elapsed = time.time() - t0
            results.append(
                Result(
                    file=rel_path,
                    arch=arch,
                    label="errors",
                    passed=ok,
                    detail="; ".join(fails) if fails else "OK",
                    elapsed=elapsed,
                )
            )

            # Warnings pass (only if expectations refer to warnings)
            if "must_detect_with_warnings" in arch_spec:
                t0 = time.time()
                report_w = run_analyzer(analyzer, source, arch, with_warnings=True)
                ok_w, fails_w = evaluate(report_w, arch_spec, with_warnings=True)
                elapsed = time.time() - t0
                results.append(
                    Result(
                        file=rel_path,
                        arch=arch,
                        label="warnings",
                        passed=ok_w,
                        detail="; ".join(fails_w) if fails_w else "OK",
                        elapsed=elapsed,
                    )
                )

    # Print report
    width = max(len(r.file) for r in results) + 2
    print("=" * 90)
    print(f"{'FILE':<{width}}  {'ARCH':<7}  {'PASS':<8}  {'TIME':<6}  {'DETAIL'}")
    print("-" * 90)
    for r in results:
        status = "OK" if r.passed else "FAIL"
        label = f"{r.label}"
        time_s = f"{r.elapsed:.1f}s"
        print(f"{r.file:<{width}}  {r.arch:<7}  {status:<4}{label:>4}  {time_s:<6}  {r.detail}")
    print("=" * 90)

    n_fail = sum(1 for r in results if not r.passed)
    n_total = len(results)
    print(f"Result: {n_total - n_fail}/{n_total} passed.")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
