#!/usr/bin/env python3
"""v6 binary-instrumented sweep over the production crypto panel.

For each (target, hot-symbol) pair, run frida_drive.py with 3 repeats
× 5000 samples each, and aggregate into a single top-N table.
"""

import math
import re
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SWEEP = [
    # (label, target, hooked_symbol)
    ("ring AES-128-GCM seal (whole)",
     "ring_aes128gcm_seal_vary_key",
     "ring_core_0_17_14__aesni_gcm_encrypt"),
    ("ring AES-128-GCM seal (split)",
     "ring_aes128gcm_seal_vary_key_split",
     "ring_core_0_17_14__aesni_gcm_encrypt"),
    ("ring AES-128-GCM open invalid (whole)",
     "ring_aes128gcm_open_invalid_vary_key",
     "ring_core_0_17_14__aesni_gcm_decrypt"),
    ("ring Ed25519 sign — SHA-512 inner",
     "ring_ed25519_sign_vary_key",
     "ring_core_0_17_14__sha512_block_data_order_avx"),
    ("ring Ed25519 sign — basepoint scalar mult",
     "ring_ed25519_sign_vary_key",
     "ring_core_0_17_14__x25519_ge_scalarmult_base_adx"),
    ("ring ChaCha20-Poly1305 seal (whole)",
     "ring_chacha20poly1305_seal_vary_key",
     "ring_core_0_17_14__chacha20_poly1305_seal_avx2"),
    ("ring ChaCha20-Poly1305 seal (split)",
     "ring_chacha20poly1305_seal_vary_key_split",
     "ring_core_0_17_14__chacha20_poly1305_seal_avx2"),
    ("RustCrypto aes-gcm seal — AES-NI key expand",
     "rustcrypto_aes128gcm_seal_vary_key",
     "_ZN3aes2ni6aes12810expand_key17h483e7d139bfa29f7E"),
    ("RustCrypto chacha20poly1305 seal — chacha20 AVX2 inner",
     "rustcrypto_chacha20poly1305_seal_vary_key",
     "_ZN8chacha208backends4avx25inner17h8631f625e032d209E"),
    ("RustCrypto chacha20poly1305 seal — poly1305 AVX2 process",
     "rustcrypto_chacha20poly1305_seal_vary_key",
     "_ZN8poly13057backend4avx25State14process_blocks17hc3314ea1ffc2fde2E"),
    ("ed25519-dalek sign — EdwardsPoint::mul_base",
     "ed25519_dalek_sign_vary_key",
     "_ZN16curve25519_dalek7edwards12EdwardsPoint8mul_base17hef7ab5d03a8c646dE"),
]
REPEATS = 3
SAMPLES = 5000


def run(target: str, symbol: str) -> tuple[float, float, int]:
    """Returns (inner |t1|, outer |t1|, inner_call_count)."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "ct_fuzz" / "frida_drive.py"),
         "--target", target, "--symbol", symbol, "--samples", str(SAMPLES)],
        capture_output=True, text=True, timeout=180,
    )
    inner = outer = float("nan")
    n_inner = 0
    for line in proc.stdout.splitlines():
        m = re.search(r"frida inner-fn calls: (\d+)", line)
        if m:
            n_inner = int(m.group(1))
        if "inner-fn dudect" in line:
            m = re.search(r"\|t1\|=\s*([\d.]+)", line)
            if m:
                inner = float(m.group(1))
        if "outer (harness)" in line:
            m = re.search(r"\|t1\|=\s*([\d.]+)", line)
            if m:
                outer = float(m.group(1))
    return inner, outer, n_inner


def main():
    print(f"\n{'#':>2}  {'label':50s}  {'inner |t1|':>14s}  {'outer |t1|':>14s}  hits")
    print("-" * 95)
    results = []
    for i, (label, target, symbol) in enumerate(SWEEP, 1):
        inner_runs, outer_runs, hits = [], [], 0
        for _ in range(REPEATS):
            inner, outer, n = run(target, symbol)
            inner_runs.append(inner)
            outer_runs.append(outer)
            hits = n
        clean_i = [x for x in inner_runs if not math.isnan(x)]
        clean_o = [x for x in outer_runs if not math.isnan(x)]
        if clean_i:
            i_mu, i_sd = statistics.mean(clean_i), (
                statistics.stdev(clean_i) if len(clean_i) > 1 else 0)
            i_str = f"{i_mu:5.2f}±{i_sd:4.2f} ({len(clean_i)}/{REPEATS})"
        else:
            i_str = "no calls"
        if clean_o:
            o_mu, o_sd = statistics.mean(clean_o), (
                statistics.stdev(clean_o) if len(clean_o) > 1 else 0)
            o_str = f"{o_mu:5.2f}±{o_sd:4.2f}"
        else:
            o_str = "n/a"
        print(f"{i:>2}  {label[:50]:50s}  {i_str:>14s}  {o_str:>14s}  {hits}")
        results.append({
            "label": label, "target": target, "symbol": symbol,
            "inner_runs": inner_runs, "outer_runs": outer_runs, "inner_call_count": hits,
        })

    import json
    out = ROOT / "results" / "frida_sweep.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
