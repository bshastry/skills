#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Run timing_probe for every supported op, repeat for stability, and write a
measured-ground-truth JSON file.

The output maps each x86_64 mnemonic to:
  - measured_variable_time: bool          (the verdict)
  - cv_varying / cv_fixed:   float        (raw CVs)
  - mean_cycles_varying / fixed: float
  - n_runs:                   int         (repetitions)

For mnemonics we couldn't measure (ARM-only, RISC-V, ...) we fall back to a
"documented" verdict, marked separately so callers can prefer measured data.
"""
from __future__ import annotations
import json
import statistics
import subprocess
import sys
import platform
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE / "timing_probe"
OUT = HERE / "measured.json"

# Measured ops -> the assembly mnemonic(s) they certify behaviour for.
# Several mnemonics share a behaviour family; e.g. divq covers div/idiv/divl/idivl.
OP_TO_MNEMONICS = {
    # Integer DIV / MUL
    "divq":         ["div", "divq", "divl", "divw", "divb"],
    "idivq":        ["idiv", "idivq", "idivl", "idivw", "idivb"],
    "mulq":         ["mul", "mulq", "mull", "imul", "imulq", "imull"],
    # Scalar FP single
    "divss":        ["divss"],
    "mulss":        ["mulss"],
    "addss":        ["addss"],
    "subss":        ["subss"],
    "sqrtss":       ["sqrtss"],
    # Scalar FP double
    "divsd":        ["divsd"],
    "mulsd":        ["mulsd"],
    "addsd":        ["addsd"],
    "subsd":        ["subsd"],
    "sqrtsd":       ["sqrtsd"],
    # Packed FP
    "divps":        ["divps"],
    "divpd":        ["divpd"],
    "sqrtps":       ["sqrtps"],
    "sqrtpd":       ["sqrtpd"],
    # AVX scalar
    "vdivss":       ["vdivss"],
    "vdivsd":       ["vdivsd"],
    "vmulss":       ["vmulss"],
    "vsqrtss":      ["vsqrtss"],
    # FMA
    "vfmadd231ss":  ["vfmadd231ss", "vfmadd132ss", "vfmadd213ss"],
    "vfmadd231sd":  ["vfmadd231sd", "vfmadd132sd", "vfmadd213sd"],
    # Denormal-input variants — these reuse the base mnemonic so we DON'T
    # remap them; instead the measured.json has them as standalone ops only.
    "mulss_denorm": [],
    "addss_denorm": [],
    "mulsd_denorm": [],
    "addsd_denorm": [],
    # Suspect not-currently-flagged instructions (FN candidates)
    "bsf":          ["bsf", "bsfq", "bsfl"],
    "bsr":          ["bsr", "bsrq", "bsrl"],
    "lzcnt":        ["lzcnt", "lzcntq", "lzcntl"],
    "tzcnt":        ["tzcnt", "tzcntq", "tzcntl"],
    "popcnt":       ["popcnt", "popcntq", "popcntl"],
    "cmov":         ["cmovbq", "cmoveq", "cmovaq", "cmov"],
    "pclmulqdq":    ["pclmulqdq"],
    "aesenc":       ["aesenc", "aesenclast", "aesdec", "aesdeclast"],
    "rep_movsb":    ["rep movsb"],
}

# For non-measurable architectures, use documented verdicts. These come from
# vendor architecture reference manuals and Agner Fog's instruction tables.
DOCUMENTED = {
    # ARM64
    "udiv":    {"variable_time": True,  "source": "ARM ARM (DIT does not cover SDIV/UDIV)"},
    "sdiv":    {"variable_time": True,  "source": "ARM ARM (DIT does not cover SDIV/UDIV)"},
    "fdiv":    {"variable_time": True,  "source": "ARM ARM"},
    "fsqrt":   {"variable_time": True,  "source": "ARM ARM"},
    "fadd":    {"variable_time": False, "source": "ARM ARM (DIT-covered)"},
    "fsub":    {"variable_time": False, "source": "ARM ARM (DIT-covered)"},
    "fmul":    {"variable_time": False, "source": "ARM ARM (DIT-covered)"},
    "fmadd":   {"variable_time": False, "source": "ARM ARM (DIT-covered)"},
    # ARM 32 (no hw division on Cortex-M0/M3)
    "vdiv.f32":  {"variable_time": True, "source": "ARM ARM"},
    "vdiv.f64":  {"variable_time": True, "source": "ARM ARM"},
    "vsqrt.f32": {"variable_time": True, "source": "ARM ARM"},
    # Cortex-M0/M3 multiplications — variable time per ARM Cortex-M docs
    "smmul":   {"variable_time": True, "source": "Cortex-M3 TRM (32-cycle MUL)"},
    "umull":   {"variable_time": True, "source": "Cortex-M3 TRM (32-cycle MUL)"},
    "smull":   {"variable_time": True, "source": "Cortex-M3 TRM (32-cycle MUL)"},
}


def run_probe(op: str, n: int = 3) -> dict:
    cv_var, cv_fix, mean_var, mean_fix = [], [], [], []
    verdicts = []
    for _ in range(n):
        r = subprocess.run([str(PROBE), op], capture_output=True, text=True, check=True)
        d = json.loads(r.stdout.strip())
        cv_var.append(d["cv_varying"])
        cv_fix.append(d["cv_fixed"])
        mean_var.append(d["mean_cycles_varying"])
        mean_fix.append(d["mean_cycles_fixed"])
        verdicts.append(d["variable_time"])
    return {
        "op": op,
        "n_runs": n,
        "cv_varying":  round(statistics.median(cv_var), 6),
        "cv_fixed":    round(statistics.median(cv_fix), 6),
        "cv_varying_max": round(max(cv_var), 6),
        "mean_cycles_varying": round(statistics.median(mean_var), 3),
        "mean_cycles_fixed":   round(statistics.median(mean_fix), 3),
        # majority vote
        "measured_variable_time": sum(verdicts) > n // 2,
    }


def main() -> int:
    if not PROBE.exists():
        print(f"Build the probe first: cc -O2 -o {PROBE} {PROBE}.c -lm", file=sys.stderr)
        return 1

    cpu = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip(); break
    except OSError:
        cpu = platform.processor()

    measured = {}
    by_mnemonic: dict[str, dict] = {}
    for op in OP_TO_MNEMONICS:
        print(f"  measuring {op} ...", file=sys.stderr)
        m = run_probe(op)
        measured[op] = m
        for mnem in OP_TO_MNEMONICS[op]:
            by_mnemonic[mnem] = {
                "measured_variable_time": m["measured_variable_time"],
                "cv_varying": m["cv_varying"],
                "cv_fixed":   m["cv_fixed"],
                "mean_cycles_varying": m["mean_cycles_varying"],
                "source": "measured",
                "host_cpu": cpu,
                "from_op": op,
            }

    # Add documented entries for non-measured architectures.
    for mnem, info in DOCUMENTED.items():
        if mnem not in by_mnemonic:
            by_mnemonic[mnem] = {
                "measured_variable_time": info["variable_time"],
                "source": "documented",
                "doc_source": info["source"],
            }

    out = {
        "host_cpu": cpu,
        "host_arch": platform.machine(),
        "raw_measurements": measured,
        "by_mnemonic": by_mnemonic,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"Wrote {OUT.relative_to(HERE.parent.parent)}")
    print(f"\nVariable-time on this host: "
          + ", ".join(m for m, v in by_mnemonic.items()
                      if v["measured_variable_time"] and v["source"] == "measured"))
    print(f"Constant-time on this host: "
          + ", ".join(m for m, v in by_mnemonic.items()
                      if not v["measured_variable_time"] and v["source"] == "measured"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
