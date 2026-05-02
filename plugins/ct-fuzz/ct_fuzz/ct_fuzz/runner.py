"""Spawn a harness binary, run a target, collect timing samples per class."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class TimingRun:
    target: str
    samples_a: list[float]
    samples_b: list[float]


def run_target(harness: str, target: str, n_samples: int, timeout_s: int = 600) -> TimingRun:
    """Run `target` for `n_samples` iterations on the given harness binary.

    The harness emits one line per call: "<class> <ns>\\n", terminated by "DONE".
    """
    proc = subprocess.Popen(
        [harness],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    samples_a: list[float] = []
    samples_b: list[float] = []
    try:
        assert proc.stdin and proc.stdout
        proc.stdin.write(f"{target} {n_samples}\n")
        proc.stdin.flush()
        proc.stdin.close()

        for line in proc.stdout:
            line = line.strip()
            if line == "DONE":
                break
            if not line:
                continue
            cls, _, val = line.partition(" ")
            try:
                v = float(val)
            except ValueError:
                continue
            if cls == "A":
                samples_a.append(v)
            elif cls == "B":
                samples_b.append(v)
        proc.wait(timeout=timeout_s)
    finally:
        if proc.poll() is None:
            proc.kill()
    return TimingRun(target=target, samples_a=samples_a, samples_b=samples_b)


def list_targets(harness: str) -> list[str]:
    out = subprocess.run([harness, "list"], capture_output=True, text=True, check=True)
    targets = []
    for line in out.stdout.splitlines():
        if line.strip():
            targets.append(line.split()[0])
    return targets
