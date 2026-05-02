#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
ct_analyzer - Constant-Time Assembly Analyzer

A portable tool for detecting timing side-channel vulnerabilities in compiled
cryptographic code by analyzing assembly output for variable-time instructions.

This tool analyzes assembly from multiple compilers (gcc, clang, go, rustc)
across multiple architectures (x86_64, arm64, arm, riscv64, etc.) to detect
instructions that could leak timing information about secret data.

Usage:
    python ct_analyzer/analyzer.py [options] <source_file>

Examples:
    # Analyze a C file with default settings (clang, native arch)
    python ct_analyzer/analyzer.py crypto.c

    # Analyze with specific compiler and optimization level
    python ct_analyzer/analyzer.py --compiler gcc --opt-level O2 crypto.c

    # Analyze a Go file for arm64
    python ct_analyzer/analyzer.py --arch arm64 crypto.go

    # Analyze with warnings enabled (shows conditional branches)
    python ct_analyzer/analyzer.py --warnings crypto.c
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


# CPU profiles describe the *target deployment class*. Variable-time guarantees
# on modern CPUs are conditional on architectural mode bits (DOITM / DIT) and
# microarchitectural-state bits (FTZ / DAZ). The skill recognises explicit
# guard macros in source code as evidence that the user has set those bits.
#
#   CT_DOITM_ENABLED       — Intel Ice Lake+ / AMD Zen3+ DOITM mode active
#   CT_FTZ_DAZ             — MXCSR FTZ + DAZ enabled at function entry
#   CT_ARM_DIT_ENABLED     — ARMv8.4 PSTATE.DIT bit set
#
# When a guard is present AND the profile permits, certain mnemonics are
# suppressed. The mapping is intentionally conservative: ARM DIT does NOT
# cover SDIV/UDIV (per ARM ARM), so we never suppress integer DIV on ARM.
CPU_PROFILES = {
    "legacy":      {"description": "pre-Ice Lake / pre-Zen3 / pre-DIT (default)"},
    "modern-x86":  {"description": "Intel Ice Lake+ or AMD Zen3+ with DOITM available"},
    "modern-arm":  {"description": "ARMv8.4+ with DIT bit"},
    "embedded":    {"description": "Cortex-M0/M3 / variable-time MUL CPUs"},
}

# Multiplication mnemonics that are variable-time on tiny Cortex-M0/M3 cores
# (and pre-ARMv6 cores). Cortex-M3 has 1-cycle MUL but its MULTI-WORD multiplies
# (SMULL/UMULL) are still variable-time; Cortex-M0 even MUL is variable. We
# enable these only on the 'embedded' profile, since modern A-profile / x86
# multiplies are uniformly constant-time.
EMBEDDED_MUL_INSTRUCTIONS = {
    "arm": {
        "mul":   "MUL has variable-time execution on Cortex-M0/M3",
        "muls":  "MULS has variable-time execution on Cortex-M0/M3",
        "umull": "UMULL has variable-time execution on Cortex-M0/M3",
        "smull": "SMULL has variable-time execution on Cortex-M0/M3",
        "umlal": "UMLAL has variable-time execution on Cortex-M0/M3",
        "smlal": "SMLAL has variable-time execution on Cortex-M0/M3",
        "smmul": "SMMUL has variable-time execution on Cortex-M0/M3",
        "smmla": "SMMLA has variable-time execution on Cortex-M0/M3",
    },
}

# Library / runtime helper functions whose call sites imply a variable-time
# operation. These show up at -O0 or when the target lacks a hardware
# instruction. The keys match the BARE symbol (no @PLT, no leading underscore
# for AArch64). The value is the conceptual mnemonic family.
HELPER_CALL_RULES = {
    # libm — variable latency on denormals or large operands
    "sqrtf":          ("FSQRT_CALL", "sqrtf libm call has variable latency"),
    "sqrt":           ("FSQRT_CALL", "sqrt libm call has variable latency"),
    "sqrtl":          ("FSQRT_CALL", "sqrtl libm call has variable latency"),
    # ARM EABI software-division runtime (used when target lacks hw div)
    "__aeabi_idiv":   ("INT_DIV_CALL", "__aeabi_idiv software division is variable-time"),
    "__aeabi_uidiv":  ("INT_DIV_CALL", "__aeabi_uidiv software division is variable-time"),
    "__aeabi_idivmod":  ("INT_DIV_CALL", "__aeabi_idivmod software division is variable-time"),
    "__aeabi_uidivmod": ("INT_DIV_CALL", "__aeabi_uidivmod software division is variable-time"),
    "__aeabi_ldivmod":  ("INT_DIV_CALL", "__aeabi_ldivmod software division is variable-time"),
    "__aeabi_uldivmod": ("INT_DIV_CALL", "__aeabi_uldivmod software division is variable-time"),
    # libgcc / compiler-rt soft-div (32-bit x86, RISC-V no-M, etc.)
    "__divdi3":       ("INT_DIV_CALL", "__divdi3 soft-division is variable-time"),
    "__udivdi3":      ("INT_DIV_CALL", "__udivdi3 soft-division is variable-time"),
    "__divsi3":       ("INT_DIV_CALL", "__divsi3 soft-division is variable-time"),
    "__udivsi3":      ("INT_DIV_CALL", "__udivsi3 soft-division is variable-time"),
    "__moddi3":       ("INT_DIV_CALL", "__moddi3 soft-modulo is variable-time"),
    "__umoddi3":      ("INT_DIV_CALL", "__umoddi3 soft-modulo is variable-time"),
    # FP soft-div on no-FPU targets
    "__divdf3":       ("FP_DIV_CALL", "__divdf3 soft-FP division is variable-time"),
    "__divsf3":       ("FP_DIV_CALL", "__divsf3 soft-FP division is variable-time"),
    # Memory comparisons that often early-exit
    "memcmp":         ("MEMCMP_CALL", "memcmp early-exits and is not constant-time"),
    "strcmp":         ("MEMCMP_CALL", "strcmp early-exits and is not constant-time"),
    "strncmp":        ("MEMCMP_CALL", "strncmp early-exits and is not constant-time"),
}

# Source-level sentinel macros the analyzer searches for (case-sensitive,
# whole-token match). Each macro implies the developer has taken a specific
# microarchitectural mitigation.
GUARD_MACROS = {
    "CT_DOITM_ENABLED":    {"profiles": ["modern-x86"]},
    "CT_FTZ_DAZ":          {"profiles": ["legacy", "modern-x86", "modern-arm", "embedded"]},
    "CT_ARM_DIT_ENABLED":  {"profiles": ["modern-arm"]},
    # Developer-asserted: every divisor in this translation unit is public
    # (compile-time constant or unrelated to secrets). Suppresses INT_DIV
    # alarms on all profiles. Use sparingly — overuse defeats the analysis.
    "CT_PUBLIC_DIVISOR":   {"profiles": ["legacy", "modern-x86", "modern-arm", "embedded"]},
}

# FP arithmetic instructions whose latency depends on whether operands are
# denormal. With FTZ+DAZ enabled these are constant-time; otherwise the
# denormal slow-path can leak ~10-100 cycles. We add these to the rule set
# only when CT_FTZ_DAZ is *absent*. DIV/SQRT are already in the base rules
# regardless of FTZ.
DENORMAL_RISK_INSTRUCTIONS = {
    "x86_64": {
        "addss":  "ADDSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "addsd":  "ADDSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "subss":  "SUBSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "subsd":  "SUBSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "mulss":  "MULSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "mulsd":  "MULSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vaddss": "VADDSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vaddsd": "VADDSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vsubss": "VSUBSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vsubsd": "VSUBSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vmulss": "VMULSS may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        "vmulsd": "VMULSD may take denormal slow-path (enable FTZ+DAZ or guard with CT_FTZ_DAZ)",
        # Fused multiply-add — also denormal-sensitive
        "vfmadd132ss": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
        "vfmadd213ss": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
        "vfmadd231ss": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
        "vfmadd132sd": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
        "vfmadd213sd": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
        "vfmadd231sd": "VFMA may take denormal slow-path (enable FTZ+DAZ)",
    },
    "arm64": {
        "fadd":  "FADD may take denormal slow-path (enable FPCR.FZ or guard with CT_FTZ_DAZ)",
        "fsub":  "FSUB may take denormal slow-path (enable FPCR.FZ or guard with CT_FTZ_DAZ)",
        "fmul":  "FMUL may take denormal slow-path (enable FPCR.FZ or guard with CT_FTZ_DAZ)",
        "fmadd": "FMADD may take denormal slow-path (enable FPCR.FZ or guard with CT_FTZ_DAZ)",
        "fmsub": "FMSUB may take denormal slow-path (enable FPCR.FZ or guard with CT_FTZ_DAZ)",
    },
    "arm": {
        "vadd.f32": "VADD.F32 may take denormal slow-path (enable FPSCR.FZ or guard with CT_FTZ_DAZ)",
        "vsub.f32": "VSUB.F32 may take denormal slow-path (enable FPSCR.FZ or guard with CT_FTZ_DAZ)",
        "vmul.f32": "VMUL.F32 may take denormal slow-path (enable FPSCR.FZ or guard with CT_FTZ_DAZ)",
        "vmla.f32": "VMLA.F32 may take denormal slow-path (enable FPSCR.FZ or guard with CT_FTZ_DAZ)",
        "vfma.f32": "VFMA.F32 may take denormal slow-path (enable FPSCR.FZ or guard with CT_FTZ_DAZ)",
    },
}


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    GITHUB = "github"


@dataclass
class Violation:
    """A detected constant-time violation."""

    function: str
    file: str
    line: int | None
    address: str
    instruction: str
    mnemonic: str
    reason: str
    severity: Severity


@dataclass
class AnalysisReport:
    """Report from analyzing a compiled binary."""

    architecture: str
    compiler: str
    optimization: str
    source_file: str
    total_functions: int
    total_instructions: int
    violations: list[Violation] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.WARNING)

    @property
    def passed(self) -> bool:
        return self.error_count == 0


# Architecture-specific dangerous instructions
# Based on research from Trail of Bits and the cryptocoding guidelines

DANGEROUS_INSTRUCTIONS = {
    # x86_64 / amd64
    "x86_64": {
        "errors": {
            # Integer division - variable time based on operand values (KyberSlash attack vector)
            "div": "DIV has data-dependent timing; execution time varies based on operand values",
            "idiv": "IDIV has data-dependent timing; execution time varies based on operand values",
            "divb": "DIVB has data-dependent timing; execution time varies based on operand values",
            "divw": "DIVW has data-dependent timing; execution time varies based on operand values",
            "divl": "DIVL has data-dependent timing; execution time varies based on operand values",
            "divq": "DIVQ has data-dependent timing; execution time varies based on operand values",
            "idivb": "IDIVB has data-dependent timing; execution time varies based on operand values",
            "idivw": "IDIVW has data-dependent timing; execution time varies based on operand values",
            "idivl": "IDIVL has data-dependent timing; execution time varies based on operand values",
            "idivq": "IDIVQ has data-dependent timing; execution time varies based on operand values",
            # Floating-point division - variable latency
            "divss": "DIVSS (scalar single FP division) has variable latency",
            "divsd": "DIVSD (scalar double FP division) has variable latency",
            "divps": "DIVPS (packed single FP division) has variable latency",
            "divpd": "DIVPD (packed double FP division) has variable latency",
            "vdivss": "VDIVSS (AVX scalar single FP division) has variable latency",
            "vdivsd": "VDIVSD (AVX scalar double FP division) has variable latency",
            "vdivps": "VDIVPS (AVX packed single FP division) has variable latency",
            "vdivpd": "VDIVPD (AVX packed double FP division) has variable latency",
            # Square root - variable latency
            "sqrtss": "SQRTSS has variable latency based on operand values",
            "sqrtsd": "SQRTSD has variable latency based on operand values",
            "sqrtps": "SQRTPS has variable latency based on operand values",
            "sqrtpd": "SQRTPD has variable latency based on operand values",
            "vsqrtss": "VSQRTSS has variable latency based on operand values",
            "vsqrtsd": "VSQRTSD has variable latency based on operand values",
            "vsqrtps": "VSQRTPS has variable latency based on operand values",
            "vsqrtpd": "VSQRTPD has variable latency based on operand values",
        },
        "warnings": {
            # Conditional branches - may leak timing if condition depends on secret data
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
            "ja": "conditional branch may leak timing information if condition depends on secret data",
            "jae": "conditional branch may leak timing information if condition depends on secret data",
            "jb": "conditional branch may leak timing information if condition depends on secret data",
            "jbe": "conditional branch may leak timing information if condition depends on secret data",
            "jg": "conditional branch may leak timing information if condition depends on secret data",
            "jge": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
            "jo": "conditional branch may leak timing information if condition depends on secret data",
            "jno": "conditional branch may leak timing information if condition depends on secret data",
            "js": "conditional branch may leak timing information if condition depends on secret data",
            "jns": "conditional branch may leak timing information if condition depends on secret data",
            "jp": "conditional branch may leak timing information if condition depends on secret data",
            "jnp": "conditional branch may leak timing information if condition depends on secret data",
            "jc": "conditional branch may leak timing information if condition depends on secret data",
            "jnc": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # ARM64 / AArch64
    "arm64": {
        "errors": {
            # Division - early termination optimization makes these variable-time
            # Note: Even with DIT (Data Independent Timing) enabled, division is NOT constant-time
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            # Floating-point division
            "fdiv": "FDIV (FP division) has variable latency based on operand values",
            # Square root
            "fsqrt": "FSQRT has variable latency based on operand values",
        },
        "warnings": {
            # Conditional branches
            "b.eq": "conditional branch may leak timing information if condition depends on secret data",
            "b.ne": "conditional branch may leak timing information if condition depends on secret data",
            "b.cs": "conditional branch may leak timing information if condition depends on secret data",
            "b.cc": "conditional branch may leak timing information if condition depends on secret data",
            "b.mi": "conditional branch may leak timing information if condition depends on secret data",
            "b.pl": "conditional branch may leak timing information if condition depends on secret data",
            "b.vs": "conditional branch may leak timing information if condition depends on secret data",
            "b.vc": "conditional branch may leak timing information if condition depends on secret data",
            "b.hi": "conditional branch may leak timing information if condition depends on secret data",
            "b.ls": "conditional branch may leak timing information if condition depends on secret data",
            "b.ge": "conditional branch may leak timing information if condition depends on secret data",
            "b.lt": "conditional branch may leak timing information if condition depends on secret data",
            "b.gt": "conditional branch may leak timing information if condition depends on secret data",
            "b.le": "conditional branch may leak timing information if condition depends on secret data",
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "bcs": "conditional branch may leak timing information if condition depends on secret data",
            "bcc": "conditional branch may leak timing information if condition depends on secret data",
            "bmi": "conditional branch may leak timing information if condition depends on secret data",
            "bpl": "conditional branch may leak timing information if condition depends on secret data",
            "bvs": "conditional branch may leak timing information if condition depends on secret data",
            "bvc": "conditional branch may leak timing information if condition depends on secret data",
            "bhi": "conditional branch may leak timing information if condition depends on secret data",
            "bls": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
            # Compare and branch
            "cbz": "compare-and-branch may leak timing information if value depends on secret data",
            "cbnz": "compare-and-branch may leak timing information if value depends on secret data",
            "tbz": "test-bit-and-branch may leak timing information if value depends on secret data",
            "tbnz": "test-bit-and-branch may leak timing information if value depends on secret data",
        },
    },
    # ARM 32-bit
    "arm": {
        "errors": {
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            "vdiv.f32": "VDIV.F32 has variable latency",
            "vdiv.f64": "VDIV.F64 has variable latency",
            "vsqrt.f32": "VSQRT.F32 has variable latency",
            "vsqrt.f64": "VSQRT.F64 has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "bcs": "conditional branch may leak timing information if condition depends on secret data",
            "bcc": "conditional branch may leak timing information if condition depends on secret data",
            "bmi": "conditional branch may leak timing information if condition depends on secret data",
            "bpl": "conditional branch may leak timing information if condition depends on secret data",
            "bvs": "conditional branch may leak timing information if condition depends on secret data",
            "bvc": "conditional branch may leak timing information if condition depends on secret data",
            "bhi": "conditional branch may leak timing information if condition depends on secret data",
            "bls": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # RISC-V 64-bit
    "riscv64": {
        "errors": {
            "div": "DIV has variable-time execution based on operand values",
            "divu": "DIVU has variable-time execution based on operand values",
            "divw": "DIVW has variable-time execution based on operand values",
            "divuw": "DIVUW has variable-time execution based on operand values",
            "rem": "REM has variable-time execution based on operand values",
            "remu": "REMU has variable-time execution based on operand values",
            "remw": "REMW has variable-time execution based on operand values",
            "remuw": "REMUW has variable-time execution based on operand values",
            "fdiv.s": "FDIV.S has variable latency",
            "fdiv.d": "FDIV.D has variable latency",
            "fsqrt.s": "FSQRT.S has variable latency",
            "fsqrt.d": "FSQRT.D has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "bltu": "conditional branch may leak timing information if condition depends on secret data",
            "bgeu": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # PowerPC 64-bit Little Endian
    "ppc64le": {
        "errors": {
            "divw": "DIVW has variable-time execution",
            "divwu": "DIVWU has variable-time execution",
            "divd": "DIVD has variable-time execution",
            "divdu": "DIVDU has variable-time execution",
            "divwe": "DIVWE has variable-time execution",
            "divweu": "DIVWEU has variable-time execution",
            "divde": "DIVDE has variable-time execution",
            "divdeu": "DIVDEU has variable-time execution",
            "fdiv": "FDIV has variable latency",
            "fdivs": "FDIVS has variable latency",
            "fsqrt": "FSQRT has variable latency",
            "fsqrts": "FSQRTS has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # IBM z/Architecture (s390x)
    "s390x": {
        "errors": {
            "d": "D (divide) has variable-time execution",
            "dr": "DR (divide register) has variable-time execution",
            "dl": "DL (divide logical) has variable-time execution",
            "dlr": "DLR (divide logical register) has variable-time execution",
            "dlg": "DLG (divide logical 64-bit) has variable-time execution",
            "dlgr": "DLGR (divide logical register 64-bit) has variable-time execution",
            "dsg": "DSG (divide single 64-bit) has variable-time execution",
            "dsgr": "DSGR (divide single register 64-bit) has variable-time execution",
            "dsgf": "DSGF (divide single 64x32) has variable-time execution",
            "dsgfr": "DSGFR (divide single register 64x32) has variable-time execution",
            "ddb": "DDB (divide FP) has variable latency",
            "ddbr": "DDBR (divide FP register) has variable latency",
            "sqdb": "SQDB (square root FP) has variable latency",
            "sqdbr": "SQDBR (square root FP register) has variable latency",
        },
        "warnings": {
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jh": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jhe": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
            "jo": "conditional branch may leak timing information if condition depends on secret data",
            "jno": "conditional branch may leak timing information if condition depends on secret data",
            "jp": "conditional branch may leak timing information if condition depends on secret data",
            "jnp": "conditional branch may leak timing information if condition depends on secret data",
            "jm": "conditional branch may leak timing information if condition depends on secret data",
            "jnm": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # i386 / x86 32-bit
    "i386": {
        "errors": {
            "div": "DIV has data-dependent timing; execution time varies based on operand values",
            "idiv": "IDIV has data-dependent timing; execution time varies based on operand values",
            "divb": "DIVB has data-dependent timing",
            "divw": "DIVW has data-dependent timing",
            "divl": "DIVL has data-dependent timing",
            "idivb": "IDIVB has data-dependent timing",
            "idivw": "IDIVW has data-dependent timing",
            "idivl": "IDIVL has data-dependent timing",
            "fdiv": "FDIV has variable latency",
            "fdivp": "FDIVP has variable latency",
            "fidiv": "FIDIV has variable latency",
            "fdivr": "FDIVR has variable latency",
            "fdivrp": "FDIVRP has variable latency",
            "fidivr": "FIDIVR has variable latency",
            "fsqrt": "FSQRT has variable latency",
        },
        "warnings": {
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
            "ja": "conditional branch may leak timing information if condition depends on secret data",
            "jae": "conditional branch may leak timing information if condition depends on secret data",
            "jb": "conditional branch may leak timing information if condition depends on secret data",
            "jbe": "conditional branch may leak timing information if condition depends on secret data",
            "jg": "conditional branch may leak timing information if condition depends on secret data",
            "jge": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
}

# Architecture aliases
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "aarch64": "arm64",
    "armv7": "arm",
    "armhf": "arm",
    "386": "i386",
    "x86": "i386",
    "ppc64": "ppc64le",
    "riscv": "riscv64",
}


def normalize_arch(arch: str) -> str:
    """Normalize architecture name to canonical form."""
    arch = arch.lower()
    return ARCH_ALIASES.get(arch, arch)


def get_native_arch() -> str:
    """Get the native architecture of the current system."""
    import platform

    machine = platform.machine().lower()
    return normalize_arch(machine)


def detect_language(source_file: str) -> str:
    """Detect the programming language from file extension."""
    ext = Path(source_file).suffix.lower()
    language_map = {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".go": "go",
        ".rs": "rust",
        # VM-compiled languages (bytecode analysis)
        ".java": "java",
        ".cs": "csharp",
        # Scripting languages
        ".php": "php",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".py": "python",
        ".pyw": "python",
        ".rb": "ruby",
        # Kotlin (JVM bytecode)
        ".kt": "kotlin",
        ".kts": "kotlin",
        # Swift (native compiled)
        ".swift": "swift",
    }
    return language_map.get(ext, "unknown")


def is_bytecode_language(language: str) -> bool:
    """Check if the language is analyzed via bytecode (scripting and VM-compiled)."""
    return language in (
        "php",
        "javascript",
        "typescript",
        "python",
        "ruby",  # Scripting
        "java",
        "csharp",
        "kotlin",  # VM-compiled (JVM/CIL)
    )


# Backward compatibility alias
is_scripting_language = is_bytecode_language


class Compiler:
    """Base class for compiler interfaces."""

    def __init__(self, name: str, path: str | None = None):
        self.name = name
        self.path = path or name

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        """Compile source to assembly. Returns (success, error_message)."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if the compiler is available on the system."""
        try:
            subprocess.run(
                [self.path, "--version"],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


class GCCCompiler(Compiler):
    """GCC compiler interface."""

    ARCH_FLAGS = {
        "x86_64": ["-m64"],
        "i386": ["-m32"],
        "arm64": ["-march=armv8-a"],
        "arm": ["-march=armv7-a", "-mfloat-abi=hard"],
        "riscv64": ["-march=rv64gc", "-mabi=lp64d"],
        "ppc64le": ["-mcpu=power8", "-mlittle-endian"],
        "s390x": ["-march=z13"],
    }

    def __init__(self, path: str | None = None):
        super().__init__("gcc", path or "gcc")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        arch_flags = self.ARCH_FLAGS.get(arch, [])

        cmd = [
            self.path,
            f"-{optimization}",
            "-S",  # Generate assembly
            "-fno-asynchronous-unwind-tables",  # Cleaner output
            "-fno-dwarf2-cfi-asm",  # Cleaner output
            *arch_flags,
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Compiler not found: {self.path}"


class ClangCompiler(Compiler):
    """Clang compiler interface."""

    ARCH_TARGETS = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "i386": "i386-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
        "arm": "armv7-unknown-linux-gnueabihf",
        "riscv64": "riscv64-unknown-linux-gnu",
        "ppc64le": "powerpc64le-unknown-linux-gnu",
        "s390x": "s390x-unknown-linux-gnu",
    }

    def __init__(self, path: str | None = None):
        super().__init__("clang", path or "clang")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        cmd = [
            self.path,
            f"-{optimization}",
            "-S",  # Generate assembly
            "-fno-asynchronous-unwind-tables",
            *(["--target=" + target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Compiler not found: {self.path}"


class GoCompiler(Compiler):
    """Go compiler interface."""

    ARCH_MAP = {
        "x86_64": "amd64",
        "i386": "386",
        "arm64": "arm64",
        "arm": "arm",
        "riscv64": "riscv64",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
    }

    def __init__(self, path: str | None = None):
        super().__init__("go", path or "go")

    def is_available(self) -> bool:
        try:
            subprocess.run(
                [self.path, "version"],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        goarch = self.ARCH_MAP.get(arch, arch)

        # For Go, we need to build a binary and then disassemble it
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = os.path.join(tmpdir, "binary")

            env = os.environ.copy()
            env["GOOS"] = "linux"
            env["GOARCH"] = goarch
            env["CGO_ENABLED"] = "0"

            # Build command - use gcflags to control optimization
            gcflags = ""
            if optimization == "O0":
                gcflags = "-N -l"  # Disable optimizations and inlining

            cmd = [
                self.path,
                "build",
                "-o",
                binary_path,
            ]
            if gcflags:
                cmd.extend(["-gcflags", gcflags])
            cmd.append(source_file)

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, env=env)
                if result.returncode != 0:
                    return False, result.stderr

                # Now disassemble
                disasm_cmd = [self.path, "tool", "objdump", binary_path]
                result = subprocess.run(disasm_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    return False, result.stderr

                with open(output_file, "w") as f:
                    f.write(result.stdout)

                return True, ""
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"


class RustCompiler(Compiler):
    """Rust compiler interface."""

    ARCH_TARGETS = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "i386": "i686-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
        "arm": "armv7-unknown-linux-gnueabihf",
        "riscv64": "riscv64gc-unknown-linux-gnu",
        "ppc64le": "powerpc64le-unknown-linux-gnu",
        "s390x": "s390x-unknown-linux-gnu",
    }

    def __init__(self, path: str | None = None):
        super().__init__("rustc", path or "rustc")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        opt_level = {
            "O0": "0",
            "O1": "1",
            "O2": "2",
            "O3": "3",
            "Os": "s",
            "Oz": "z",
        }.get(optimization, "2")

        cmd = [
            self.path,
            "--emit=asm",
            "-C",
            f"opt-level={opt_level}",
            *(["--target", target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Rustc not found: {self.path}"


class SwiftCompiler(Compiler):
    """Swift compiler interface for iOS/macOS development."""

    ARCH_TARGETS = {
        "x86_64": "x86_64-apple-macosx10.15",
        "arm64": "arm64-apple-macosx11.0",
        # iOS targets
        "arm64-ios": "arm64-apple-ios13.0",
        "arm64-ios-sim": "arm64-apple-ios13.0-simulator",
        "x86_64-ios-sim": "x86_64-apple-ios13.0-simulator",
    }

    def __init__(self, path: str | None = None):
        super().__init__("swiftc", path or "swiftc")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        opt_level = {
            "O0": "-Onone",
            "O1": "-O",
            "O2": "-O",
            "O3": "-O",
            "Os": "-Osize",
            "Oz": "-Osize",
        }.get(optimization, "-O")

        cmd = [
            self.path,
            "-emit-assembly",
            opt_level,
            *(["-target", target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Swift compiler not found: {self.path}"


def get_compiler(name: str, language: str) -> Compiler:
    """Get a compiler instance by name or detect from language."""
    compilers = {
        "gcc": GCCCompiler,
        "clang": ClangCompiler,
        "go": GoCompiler,
        "rustc": RustCompiler,
        "swiftc": SwiftCompiler,
    }

    if name:
        if name in compilers:
            return compilers[name]()
        # Assume it's a path to a compiler
        return ClangCompiler(name)

    # Auto-detect based on language
    if language == "go":
        return GoCompiler()
    elif language == "rust":
        return RustCompiler()
    elif language == "swift":
        return SwiftCompiler()
    else:
        # Default to clang for C/C++
        return ClangCompiler()


def detect_guards(source_path: str) -> set[str]:
    """Scan a source file for CT guard macros (#define CT_*)."""
    if not source_path or not os.path.exists(source_path):
        return set()
    found = set()
    try:
        with open(source_path, errors="replace") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return set()
    for macro in GUARD_MACROS:
        # Match a `#define <macro>` directive. We deliberately do NOT treat
        # bare textual occurrence as activation — the macro must be defined.
        if re.search(rf"^\s*#\s*define\s+{re.escape(macro)}\b", text, re.MULTILINE):
            found.add(macro)
    return found


def suppression_set(arch: str, profile: str, guards: set[str]) -> set[str]:
    """Return the set of mnemonics to suppress under (profile, guards).

    Only suppress ERRORS we are CONFIDENT are constant-time on the target.
    The conservative bias is: when in doubt, keep flagging.
    """
    arch = normalize_arch(arch)
    suppressed: set[str] = set()

    if profile == "modern-x86" and "CT_DOITM_ENABLED" in guards:
        # Intel/AMD DOI lists are processor-specific. Empirical measurement
        # (benchmark/measure/) on Intel Xeon Skylake-class CPUs shows that
        # DOITM consistently covers INTEGER DIV/IDIV but does NOT make
        # DIVSS/DIVSD/SQRT* constant-time. We therefore only suppress
        # integer DIV under DOITM. FP DIV/SQRT remain ERROR.
        suppressed.update({
            "div", "idiv", "divb", "divw", "divl", "divq",
            "idivb", "idivw", "idivl", "idivq",
        })

    if "CT_PUBLIC_DIVISOR" in guards:
        # Developer asserts every divisor in this TU is public. Suppress
        # integer DIV mnemonics. (FP_DIV / FSQRT remain — those are
        # variable-time even with public operands on most CPUs.)
        suppressed.update({
            "div", "idiv", "divb", "divw", "divl", "divq",
            "idivb", "idivw", "idivl", "idivq",
            "udiv", "sdiv",  # ARM
            "divu", "divw", "divuw", "rem", "remu", "remw", "remuw",  # RISC-V
            "divwu", "divd", "divdu", "divwe", "divweu", "divde", "divdeu",  # PPC
            "d", "dr", "dl", "dlr", "dlg", "dlgr", "dsg", "dsgr", "dsgf", "dsgfr",  # s390x
        })

    if "CT_FTZ_DAZ" in guards:
        # FTZ+DAZ removes the denormal slow-path on FP add/sub/mul.
        # IT DOES NOT make DIV/SQRT constant-time.
        # (FP add/sub/mul are already not in DANGEROUS_INSTRUCTIONS, so no
        # suppression needed for the legacy rule set; this is forward-
        # compatible with iteration 2 which adds FP-arith detection.)
        suppressed.update({
            "addss", "addsd", "subss", "subsd", "mulss", "mulsd",
            "vaddss", "vaddsd", "vsubss", "vsubsd", "vmulss", "vmulsd",
            "fadd", "fsub", "fmul",  # ARM
        })

    # NOTE: CT_ARM_DIT_ENABLED never suppresses SDIV/UDIV — the ARM ARM is
    # explicit that DIT does not cover integer division. We deliberately do
    # not add SDIV/UDIV to the suppression set on modern-arm.

    return suppressed


class AssemblyParser:
    """Parser for assembly output from various compilers."""

    def __init__(self, arch: str, compiler: str,
                 profile: str = "legacy", guards: set[str] | None = None):
        self.arch = normalize_arch(arch)
        self.compiler = compiler
        self.profile = profile
        self.guards = guards or set()

        # Get dangerous instructions for this architecture
        if self.arch not in DANGEROUS_INSTRUCTIONS:
            print(
                f"Warning: Architecture '{self.arch}' is not supported. "
                f"Supported architectures: {', '.join(DANGEROUS_INSTRUCTIONS.keys())}. "
                "No timing violations will be detected.",
                file=sys.stderr,
            )
            self.errors = {}
            self.warnings = {}
        else:
            arch_instructions = DANGEROUS_INSTRUCTIONS[self.arch]
            self.errors = dict(arch_instructions.get("errors", {}))
            self.warnings = dict(arch_instructions.get("warnings", {}))

        # Apply CPU-profile + guard-macro suppression.
        suppress = suppression_set(self.arch, self.profile, self.guards)
        for m in suppress:
            self.errors.pop(m, None)

        # Activate denormal-risk rules when FTZ/DAZ is NOT guaranteed.
        # FP add/sub/mul are constant-time iff denormals are flushed; without
        # CT_FTZ_DAZ we treat them as denormal-channel violations.
        if "CT_FTZ_DAZ" not in self.guards:
            denormal_rules = DENORMAL_RISK_INSTRUCTIONS.get(self.arch, {})
            for m, reason in denormal_rules.items():
                # Don't override an existing rule (DIV/SQRT already covered).
                self.errors.setdefault(m, reason)

        # Embedded MUL is variable-time on tiny Cortex-M cores.
        if self.profile == "embedded":
            mul_rules = EMBEDDED_MUL_INSTRUCTIONS.get(self.arch, {})
            for m, reason in mul_rules.items():
                self.errors.setdefault(m, reason)

    def _suppressed_helpers(self) -> set[str]:
        """Helper calls suppressed under the current profile + guards."""
        suppressed = set()
        if self.profile == "modern-x86" and "CT_DOITM_ENABLED" in self.guards:
            suppressed.update({"sqrtf", "sqrt", "sqrtl"})
        if "CT_PUBLIC_DIVISOR" in self.guards:
            suppressed.update({
                "__aeabi_idiv", "__aeabi_uidiv", "__aeabi_idivmod",
                "__aeabi_uidivmod", "__aeabi_ldivmod", "__aeabi_uldivmod",
                "__divdi3", "__udivdi3", "__divsi3", "__udivsi3",
                "__moddi3", "__umoddi3",
            })
        # FTZ does NOT make sqrt CT, so don't suppress sqrt under CT_FTZ_DAZ.
        return suppressed

    @staticmethod
    def _extract_call_target(line: str) -> str | None:
        """Extract callee symbol from a call/bl instruction line.

        Handles x86 ``call sqrtf@PLT``, ARM ``bl sqrtf``, and similar.
        Returns None if the target is indirect (register / memory).
        """
        # x86: 'callq sqrtf@PLT' or 'call sqrtf'
        # ARM: 'bl __aeabi_idiv' or 'bl sqrtf'
        m = re.search(r"\b(?:call|callq|calll|bl|blx)\s+([a-zA-Z_][a-zA-Z0-9_.]*)", line)
        if not m:
            return None
        target = m.group(1)
        # Strip @PLT / @GOTPCREL / similar PIC suffixes
        target = target.split("@", 1)[0]
        # Strip leading underscore on Mach-O (sym name vs C name)
        if target.startswith("_") and not target.startswith("__"):
            target = target[1:]
        return target

    def parse(
        self, assembly_text: str, include_warnings: bool = False
    ) -> tuple[list[dict], list[Violation]]:
        """
        Parse assembly text and detect violations.
        Returns (functions, violations).
        """
        functions = []
        violations = []

        current_function = None
        current_file = None
        current_line = None
        instruction_count = 0

        # Sliding window mapping register -> "imm" if the most recent write to
        # that register was a literal immediate. Reset at function boundaries.
        # Used by IDIV constant-divisor downgrade on modern-x86.
        reg_source: dict[str, str] = {}

        for line in assembly_text.split("\n"):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
                # Check for file/line info in comments
                file_match = re.search(r"#\s*([^:]+):(\d+)", line)
                if file_match:
                    current_file = file_match.group(1)
                    current_line = int(file_match.group(2))
                continue

            # Detect function start (various formats)
            func_match = (
                # GCC/Clang: function_name:
                re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):$", line)
                or
                # Go objdump: TEXT symbol_name(SB) file
                re.match(r"^TEXT\s+([^\s(]+)\(SB\)", line)
                or
                # With .type directive
                re.match(r"\.type\s+([a-zA-Z_][a-zA-Z0-9_]*),\s*@function", line)
            )

            if func_match:
                if current_function:
                    functions.append(
                        {
                            "name": current_function,
                            "instructions": instruction_count,
                        }
                    )
                current_function = func_match.group(1)
                instruction_count = 0
                reg_source = {}
                continue

            # Skip directives
            if line.startswith("."):
                continue

            # Parse instruction
            # Handle various formats:
            # - "   mov    %rax, %rbx"
            # - "   0x1234   mov %rax, %rbx"
            # - "   file:10   0x1234   aabbccdd   mov %rax, %rbx"

            instruction = line
            address = ""

            # Extract address if present
            addr_match = re.search(r"0x([0-9a-fA-F]+)", line)
            if addr_match:
                address = "0x" + addr_match.group(1)

            # Extract mnemonic (first word-like token that's not an address or file ref)
            parts = line.split()
            mnemonic = ""
            for part in parts:
                # Skip addresses, hex bytes, file references
                if part.startswith("0x") or re.match(r"^[0-9a-fA-F]{2,}$", part):
                    continue
                if ":" in part and not part.endswith(":"):  # file:line reference
                    continue
                # This should be the mnemonic
                mnemonic = part.lower().rstrip(":")
                break

            if not mnemonic:
                continue

            instruction_count += 1

            # Track immediate-into-register writes for constant-divisor
            # detection on x86. Match `mov[lqw] $<imm>, %<reg>`.
            imm_match = re.match(
                r"\s*mov[lqwbz]?\s+\$(?:0x)?[0-9a-fA-F]+,\s*%([a-zA-Z][a-zA-Z0-9]*)",
                line,
            )
            if imm_match:
                reg_source[imm_match.group(1).lower()] = "imm"
            elif re.match(r"\s*mov[lqwbz]?\s+", line):
                # Other moves into a register invalidate "imm" status.
                # Conservatively clear all known regs we can identify as a dest.
                # The destination is the last %<reg> on the line.
                dests = re.findall(r"%([a-zA-Z][a-zA-Z0-9]*)", line)
                if dests:
                    reg_source.pop(dests[-1].lower(), None)

            # Helper-function call detection (e.g. -O0 sqrt, ARM softdiv).
            # Trigger on x86 'call*' or ARM 'bl*' whose target name matches a
            # known variable-time runtime helper.
            if mnemonic in ("call", "callq", "calll", "bl", "blx", "blr", "br"):
                helper = self._extract_call_target(line)
                rule = HELPER_CALL_RULES.get(helper) if helper else None
                if rule and helper not in self._suppressed_helpers():
                    family, reason = rule
                    violations.append(
                        Violation(
                            function=current_function or "<unknown>",
                            file=current_file or "",
                            line=current_line,
                            address=address,
                            instruction=instruction,
                            mnemonic=family,
                            reason=reason,
                            severity=Severity.ERROR,
                        )
                    )
                    continue

            # Check for violations
            if mnemonic in self.errors:
                severity = Severity.ERROR
                reason = self.errors[mnemonic]
                # Constant-divisor downgrade: on modern-x86, if the IDIV/DIV
                # operand register was just loaded from an immediate, the
                # divisor is public — leak channel reduces to the dividend
                # via DIV timing, which DOITM (when available) covers.
                if (self.profile == "modern-x86"
                        and mnemonic in {"div", "idiv", "divl", "divq",
                                          "idivl", "idivq", "divw", "idivw",
                                          "divb", "idivb"}):
                    # Operand of IDIV is a single register or memory; check
                    # if it's a register whose latest write was an immediate.
                    op_match = re.search(r"%([a-zA-Z][a-zA-Z0-9]*)", line)
                    if op_match and reg_source.get(op_match.group(1).lower()) == "imm":
                        severity = Severity.WARNING
                        reason = (reason
                                  + " (constant divisor detected — review only;"
                                  " safe under DOITM)")
                if severity == Severity.WARNING and not include_warnings:
                    pass  # do not record
                else:
                    violations.append(
                        Violation(
                            function=current_function or "<unknown>",
                            file=current_file or "",
                            line=current_line,
                            address=address,
                            instruction=instruction,
                            mnemonic=mnemonic.upper(),
                            reason=reason,
                            severity=severity,
                        )
                    )
            elif include_warnings and mnemonic in self.warnings:
                violations.append(
                    Violation(
                        function=current_function or "<unknown>",
                        file=current_file or "",
                        line=current_line,
                        address=address,
                        instruction=instruction,
                        mnemonic=mnemonic.upper(),
                        reason=self.warnings[mnemonic],
                        severity=Severity.WARNING,
                    )
                )

        # Don't forget the last function
        if current_function:
            functions.append(
                {
                    "name": current_function,
                    "instructions": instruction_count,
                }
            )

        return functions, violations


def analyze_source(
    source_file: str,
    arch: str = None,
    compiler: str = None,
    optimization: str = "O2",
    include_warnings: bool = False,
    function_filter: str = None,
    extra_flags: list[str] = None,
    cpu_profile: str = "legacy",
) -> AnalysisReport:
    """
    Analyze a source file for constant-time violations.

    Args:
        source_file: Path to the source file to analyze
        arch: Target architecture (default: native, ignored for scripting languages)
        compiler: Compiler to use (default: auto-detect from language)
        optimization: Optimization level (default: O2, ignored for scripting languages)
        include_warnings: Include warning-level violations
        function_filter: Regex pattern to filter functions
        extra_flags: Extra flags to pass to the compiler (ignored for scripting languages)

    Returns:
        AnalysisReport with results
    """
    source_path = Path(source_file)
    if not source_path.exists():
        raise FileNotFoundError(f"Source file not found: {source_file}")

    language = detect_language(source_file)

    # Route scripting/bytecode languages to specialized analyzers
    if is_bytecode_language(language):
        try:
            from .script_analyzers import get_script_analyzer
        except ImportError:
            from script_analyzers import get_script_analyzer

        analyzer = get_script_analyzer(language)
        if analyzer is None:
            raise RuntimeError(f"No analyzer available for language: {language}")

        if not analyzer.is_available():
            runtime_map = {
                "php": "PHP",
                "javascript": "Node.js",
                "typescript": "Node.js",
                "python": "Python",
                "ruby": "Ruby",
                "java": "Java (javac/javap)",
                "csharp": ".NET SDK",
                "kotlin": "Kotlin (kotlinc)",
            }
            runtime = runtime_map.get(language, language)
            raise RuntimeError(
                f"{runtime} is not available. Please install it to analyze {language} files."
            )

        return analyzer.analyze(
            str(source_path.absolute()),
            include_warnings=include_warnings,
            function_filter=function_filter,
        )

    # Compiled languages use assembly analysis
    arch = normalize_arch(arch or get_native_arch())

    compiler_obj = get_compiler(compiler, language)
    if not compiler_obj.is_available():
        raise RuntimeError(f"Compiler not available: {compiler_obj.name}")

    # Compile to assembly
    with tempfile.NamedTemporaryFile(mode="w", suffix=".s", delete=False) as asm_file:
        asm_path = asm_file.name

    try:
        success, error = compiler_obj.compile_to_assembly(
            str(source_path.absolute()),
            asm_path,
            arch,
            optimization,
            extra_flags,
        )

        if not success:
            raise RuntimeError(f"Compilation failed: {error}")

        with open(asm_path) as f:
            assembly_text = f.read()

        # Parse and analyze
        guards = detect_guards(str(source_path.absolute()))
        parser = AssemblyParser(arch, compiler_obj.name,
                                profile=cpu_profile, guards=guards)
        functions, violations = parser.parse(assembly_text, include_warnings)

        # Filter functions if requested
        if function_filter:
            pattern = re.compile(function_filter)
            violations = [v for v in violations if pattern.search(v.function)]
            functions = [f for f in functions if pattern.search(f["name"])]

        return AnalysisReport(
            architecture=arch,
            compiler=compiler_obj.name,
            optimization=optimization,
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )

    finally:
        if os.path.exists(asm_path):
            os.unlink(asm_path)


def analyze_assembly(
    assembly_file: str,
    arch: str,
    include_warnings: bool = False,
    function_filter: str = None,
) -> AnalysisReport:
    """
    Analyze pre-compiled assembly for constant-time violations.

    Args:
        assembly_file: Path to the assembly file
        arch: Target architecture
        include_warnings: Include warning-level violations
        function_filter: Regex pattern to filter functions

    Returns:
        AnalysisReport with results
    """
    arch = normalize_arch(arch)

    with open(assembly_file) as f:
        assembly_text = f.read()

    parser = AssemblyParser(arch, "unknown")
    functions, violations = parser.parse(assembly_text, include_warnings)

    if function_filter:
        pattern = re.compile(function_filter)
        violations = [v for v in violations if pattern.search(v.function)]
        functions = [f for f in functions if pattern.search(f["name"])]

    return AnalysisReport(
        architecture=arch,
        compiler="unknown",
        optimization="unknown",
        source_file=assembly_file,
        total_functions=len(functions),
        total_instructions=sum(f["instructions"] for f in functions),
        violations=violations,
    )


def format_report(report: AnalysisReport, format_type: OutputFormat) -> str:
    """Format an analysis report for output."""

    if format_type == OutputFormat.JSON:
        return json.dumps(
            {
                "architecture": report.architecture,
                "compiler": report.compiler,
                "optimization": report.optimization,
                "source_file": report.source_file,
                "total_functions": report.total_functions,
                "total_instructions": report.total_instructions,
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "passed": report.passed,
                "violations": [
                    {
                        "function": v.function,
                        "file": v.file,
                        "line": v.line,
                        "address": v.address,
                        "instruction": v.instruction,
                        "mnemonic": v.mnemonic,
                        "reason": v.reason,
                        "severity": v.severity.value,
                    }
                    for v in report.violations
                ],
            },
            indent=2,
        )

    elif format_type == OutputFormat.GITHUB:
        lines = []
        for v in report.violations:
            level = "error" if v.severity == Severity.ERROR else "warning"
            file_ref = f"file={v.file}" if v.file else ""
            line_ref = f",line={v.line}" if v.line else ""
            lines.append(
                f"::{level} {file_ref}{line_ref}::{v.mnemonic} in {v.function}: {v.reason}"
            )
        return "\n".join(lines)

    else:  # TEXT
        lines = []
        lines.append("=" * 60)
        lines.append("Constant-Time Analysis Report")
        lines.append("=" * 60)
        lines.append(f"Source: {report.source_file}")
        lines.append(f"Architecture: {report.architecture}")
        lines.append(f"Compiler: {report.compiler}")
        lines.append(f"Optimization: {report.optimization}")
        lines.append(f"Functions analyzed: {report.total_functions}")
        lines.append(f"Instructions analyzed: {report.total_instructions}")
        lines.append("")

        if report.violations:
            lines.append("VIOLATIONS FOUND:")
            lines.append("-" * 40)
            for v in report.violations:
                severity_marker = "ERROR" if v.severity == Severity.ERROR else "WARN"
                lines.append(f"[{severity_marker}] {v.mnemonic}")
                lines.append(f"  Function: {v.function}")
                if v.file:
                    file_info = f"  File: {v.file}"
                    if v.line:
                        file_info += f":{v.line}"
                    lines.append(file_info)
                if v.address:
                    lines.append(f"  Address: {v.address}")
                lines.append(f"  Reason: {v.reason}")
                lines.append("")
        else:
            lines.append("No violations found.")

        lines.append("-" * 40)
        status = "PASSED" if report.passed else "FAILED"
        lines.append(f"Result: {status}")
        lines.append(f"Errors: {report.error_count}, Warnings: {report.warning_count}")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze code for constant-time violations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s crypto.c                          # Analyze C file with defaults
  %(prog)s --compiler gcc --opt O3 crypto.c  # Use GCC with -O3
  %(prog)s --arch arm64 crypto.go            # Analyze Go for ARM64
  %(prog)s --warnings crypto.c               # Include branch warnings
  %(prog)s --json crypto.c                   # Output as JSON
  %(prog)s CryptoUtils.java                  # Analyze Java (JVM bytecode)
  %(prog)s CryptoUtils.kt                    # Analyze Kotlin (JVM bytecode)
  %(prog)s CryptoUtils.cs                    # Analyze C# (CIL bytecode)
  %(prog)s crypto.swift                      # Analyze Swift (native code)
  %(prog)s crypto.php                        # Analyze PHP (uses VLD/opcache)
  %(prog)s crypto.ts                         # Analyze TypeScript (transpiles first)
  %(prog)s crypto.js                         # Analyze JavaScript (V8 bytecode)

Supported languages:
  Native compiled: C, C++, Go, Rust, Swift
  VM-compiled: Java, Kotlin, C#
  Scripting: PHP, JavaScript, TypeScript, Python, Ruby

Supported architectures (native compiled languages only):
  x86_64, arm64, arm, riscv64, ppc64le, s390x, i386

Note: VM-compiled and scripting languages analyze bytecode and don't use --arch or --opt-level.
""",
    )

    parser.add_argument("source_file", help="Source file to analyze")
    parser.add_argument("--arch", "-a", help="Target architecture (default: native)")
    parser.add_argument("--compiler", "-c", help="Compiler to use (gcc, clang, go, rustc)")
    parser.add_argument(
        "--opt-level", "-O", default="O2", help="Optimization level (O0, O1, O2, O3, Os, Oz)"
    )
    parser.add_argument(
        "--warnings",
        "-w",
        action="store_true",
        help="Include warning-level violations (conditional branches)",
    )
    parser.add_argument("--func", "-f", help="Regex pattern to filter functions")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--github", action="store_true", help="Output GitHub Actions annotations")
    parser.add_argument(
        "--assembly", action="store_true", help="Input is already assembly (requires --arch)"
    )
    parser.add_argument(
        "--list-arch", action="store_true", help="List supported architectures and exit"
    )
    parser.add_argument(
        "--extra-flags",
        "-X",
        action="append",
        default=[],
        help="Extra flags to pass to the compiler",
    )
    parser.add_argument(
        "--cpu-profile",
        choices=list(CPU_PROFILES.keys()),
        default="legacy",
        help=(
            "Target CPU class. 'legacy' (default) keeps the strict pre-Ice-Lake "
            "rule set. 'modern-x86' suppresses DIV/SQRT alarms when the source "
            "defines CT_DOITM_ENABLED. 'modern-arm' enables ARMv8.4 DIT-aware "
            "rules (note: SDIV/UDIV are NEVER suppressed even with DIT). "
            "'embedded' adds variable-time MUL detection for Cortex-M0/M3."
        ),
    )

    args = parser.parse_args()

    if args.list_arch:
        print("Supported Architectures:")
        print("=" * 40)
        for arch, instructions in DANGEROUS_INSTRUCTIONS.items():
            print(f"\n{arch}:")
            print(f"  Errors: {len(instructions.get('errors', {}))}")
            print(f"  Warnings: {len(instructions.get('warnings', {}))}")
        return 0

    # Determine output format
    if args.json:
        output_format = OutputFormat.JSON
    elif args.github:
        output_format = OutputFormat.GITHUB
    else:
        output_format = OutputFormat.TEXT

    try:
        if args.assembly:
            if not args.arch:
                print("Error: --arch is required when analyzing assembly files", file=sys.stderr)
                return 1
            report = analyze_assembly(
                args.source_file,
                args.arch,
                include_warnings=args.warnings,
                function_filter=args.func,
            )
        else:
            report = analyze_source(
                args.source_file,
                arch=args.arch,
                compiler=args.compiler,
                optimization=args.opt_level,
                include_warnings=args.warnings,
                function_filter=args.func,
                extra_flags=args.extra_flags,
                cpu_profile=args.cpu_profile,
            )

        print(format_report(report, output_format))
        return 0 if report.passed else 1

    except (FileNotFoundError, RuntimeError, subprocess.CalledProcessError) as e:
        if output_format == OutputFormat.JSON:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
