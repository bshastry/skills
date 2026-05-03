#!/usr/bin/env python3
"""Run frida_drive.py multiple times across multiple symbols and aggregate."""

import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CASES = [
    # (target,                                              symbol,                                       samples)
    ("ring_aes128gcm_seal_vary_key_split", "ring_core_0_17_14__aesni_gcm_encrypt",        15000),
    ("ring_aes128gcm_seal_vary_key_split", "ring_core_0_17_14__aes_hw_set_encrypt_key_base", 15000),
    ("ring_aes128gcm_seal_vary_key",       "ring_core_0_17_14__aesni_gcm_encrypt",        15000),
]
REPEATS = 3


def run_one(target: str, symbol: str, samples: int) -> tuple[float, float]:
    """Returns (inner_t1, outer_t1)."""
    proc = subprocess.run(
        [
            sys.executable, str(ROOT / "ct_fuzz" / "frida_drive.py"),
            "--target", target,
            "--symbol", symbol,
            "--samples", str(samples),
        ],
        capture_output=True, text=True, timeout=300,
    )
    inner_t = outer_t = float("nan")
    for line in proc.stdout.splitlines():
        if "inner-fn dudect" in line:
            for tok in line.split():
                if tok.startswith("|t1|="):
                    inner_t = float(tok.split("=", 1)[1])
        if "outer (harness)" in line:
            for tok in line.split():
                if tok.startswith("|t1|="):
                    outer_t = float(tok.split("=", 1)[1])
    return inner_t, outer_t


def main():
    print(f"{'target':45s} {'hooked symbol':50s} {'inner |t1|':>13s}  {'outer |t1|':>13s}")
    for target, symbol, samples in CASES:
        inner_runs, outer_runs = [], []
        for _ in range(REPEATS):
            i, o = run_one(target, symbol, samples)
            inner_runs.append(i)
            outer_runs.append(o)
        import math
        clean_i = [x for x in inner_runs if not math.isnan(x)]
        clean_o = [x for x in outer_runs if not math.isnan(x)]
        i_mu = statistics.mean(clean_i) if clean_i else float("nan")
        i_sd = statistics.stdev(clean_i) if len(clean_i) > 1 else 0
        o_mu = statistics.mean(clean_o) if clean_o else float("nan")
        o_sd = statistics.stdev(clean_o) if len(clean_o) > 1 else 0
        sym_short = symbol.replace("ring_core_0_17_14__", "ring::")
        ihit = f"{len(clean_i)}/{len(inner_runs)}"
        print(
            f"{target[:45]:45s} {sym_short[:50]:50s} "
            f"{i_mu:6.2f}±{i_sd:5.2f} ({ihit})  {o_mu:6.2f}±{o_sd:5.2f}"
        )


if __name__ == "__main__":
    main()
