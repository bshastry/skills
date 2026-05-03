#!/usr/bin/env python3
"""Run a focused re-test of just the production targets, multiple repeats,
applying the stabilized SO-off classifier on |t1|."""

import sys, statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ct_fuzz"))

from ct_fuzz.runner import run_target  # noqa: E402
from ct_fuzz.stats import cropped_welch_t  # noqa: E402

GO = str(ROOT / "ct-fuzz-go")
RUST = str(ROOT / "ct-fuzz-rust")

PROD = [
    # Whole-pipeline (prep+measure inside timing window)
    ("go", GO, "aes128gcm_seal_vary_key"),
    ("go", GO, "aes128gcm_open_invalid_vary_key"),
    ("go", GO, "ed25519_sign_vary_key"),
    ("go", GO, "ecdsa_p256_sign_vary_key"),
    ("rust", RUST, "ring_aes128gcm_seal_vary_key"),
    ("rust", RUST, "ring_aes128gcm_open_invalid_vary_key"),
    ("rust", RUST, "ring_ed25519_sign_vary_key"),
    # Split (prep outside timing window — only the actual op timed)
    ("go", GO, "aes128gcm_seal_vary_key_split"),
    ("go", GO, "aes128gcm_open_invalid_vary_key_split"),
    ("go", GO, "ed25519_sign_vary_key_split"),
    ("go", GO, "ecdsa_p256_sign_vary_key_split"),
    ("rust", RUST, "ring_aes128gcm_seal_vary_key_split"),
    ("rust", RUST, "ring_aes128gcm_open_invalid_vary_key_split"),
    ("rust", RUST, "ring_ed25519_sign_vary_key_split"),
]

SAMPLES = 60_000
REPEATS = 3
THRESHOLD = 8.0


def main():
    results: dict[str, list[float]] = {}
    for repeat in range(REPEATS):
        print(f"\n--- repeat {repeat+1}/{REPEATS} ---", flush=True)
        for lang, harness, target in PROD:
            r = run_target(harness, target, SAMPLES)
            t1, _ = cropped_welch_t(r.samples_a, r.samples_b)
            results.setdefault(target, []).append(abs(t1))
            print(f"  {target:42s}  |t1|={abs(t1):8.2f}", flush=True)

    print("\n=== production targets, 3 repeats, SO=off, threshold=8 ===")
    print(f"{'target':42s}  {'mean':>8s}  {'min':>8s}  {'max':>8s}  {'n>8':>3s}")
    for target, ts in results.items():
        mu = statistics.mean(ts)
        mn = min(ts)
        mx = max(ts)
        flagged_count = sum(1 for t in ts if t > THRESHOLD)
        verdict = "LEAK" if flagged_count >= REPEATS // 2 + 1 else "CT  "
        print(f"{target:42s}  {mu:8.2f}  {mn:8.2f}  {mx:8.2f}  {flagged_count}/{REPEATS}  {verdict}")


if __name__ == "__main__":
    main()
