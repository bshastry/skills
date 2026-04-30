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
            # Go's Plan 9 amd64 assembler uses different conditional-jump
            # mnemonics; these alias to the AT&T forms above.
            "jeq": "conditional branch may leak timing information if condition depends on secret data",
            "jlt": "conditional branch may leak timing information if condition depends on secret data",
            "jgt": "conditional branch may leak timing information if condition depends on secret data",
            "jhi": "conditional branch may leak timing information if condition depends on secret data",
            "jls": "conditional branch may leak timing information if condition depends on secret data",
            "jmi": "conditional branch may leak timing information if condition depends on secret data",
            "jpl": "conditional branch may leak timing information if condition depends on secret data",
            "jcs": "conditional branch may leak timing information if condition depends on secret data",
            "jcc": "conditional branch may leak timing information if condition depends on secret data",
            "jos": "conditional branch may leak timing information if condition depends on secret data",
            "joc": "conditional branch may leak timing information if condition depends on secret data",
            "jps": "conditional branch may leak timing information if condition depends on secret data",
            "jpc": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # ARM64 / AArch64
    "arm64": {
        "errors": {
            # Division - early termination optimization makes these variable-time
            # Note: Even with DIT (Data Independent Timing) enabled, division is NOT constant-time
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            # Go's ARM64 assembler uses a 'W' suffix for 32-bit forms, and
            # spells modulo as REM*. These are the same hardware operations
            # and have the same variable-time behavior.
            "udivw": "UDIV has early termination optimization; execution time depends on operand values",
            "sdivw": "SDIV has early termination optimization; execution time depends on operand values",
            "remw": "REM/MOD via SDIV+MSUB; execution time depends on operand values",
            "uremw": "UREM/UMOD via UDIV+MSUB; execution time depends on operand values",
            "rem": "REM/MOD via SDIV+MSUB; execution time depends on operand values",
            "urem": "UREM/UMOD via UDIV+MSUB; execution time depends on operand values",
            # Floating-point division
            "fdiv": "FDIV (FP division) has variable latency based on operand values",
            "fdivd": "FDIV (FP double division) has variable latency based on operand values",
            "fdivs": "FDIV (FP single division) has variable latency based on operand values",
            # Square root
            "fsqrt": "FSQRT has variable latency based on operand values",
            "fsqrtd": "FSQRT (double) has variable latency based on operand values",
            "fsqrts": "FSQRT (single) has variable latency based on operand values",
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
            # Go's ARM assembler uses these mnemonics. Older ARMv5/v6 has no
            # hardware divide; Go emits CALL runtime.udiv / runtime._udiv etc.
            # Those calls are flagged separately in the parser.
            "divf": "DIVF (FP single division) has variable latency",
            "divd": "DIVD (FP double division) has variable latency",
            "sqrtf": "SQRTF has variable latency",
            "sqrtd": "SQRTD has variable latency",
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
            # Go's RISC-V assembler omits the dot in FP mnemonics
            "fdivs": "FDIV.S has variable latency",
            "fdivd": "FDIV.D has variable latency",
            "fsqrts": "FSQRT.S has variable latency",
            "fsqrtd": "FSQRT.D has variable latency",
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
            # Go's s390x assembler uses these mnemonics
            "divw": "DIVW (32-bit divide) has variable-time execution",
            "divwu": "DIVWU (32-bit unsigned divide) has variable-time execution",
            "divd": "DIVD (64-bit divide) has variable-time execution",
            "divdu": "DIVDU (64-bit unsigned divide) has variable-time execution",
            "modw": "MODW (32-bit modulo) has variable-time execution",
            "modwu": "MODWU (32-bit unsigned modulo) has variable-time execution",
            "modd": "MODD (64-bit modulo) has variable-time execution",
            "moddu": "MODDU (64-bit unsigned modulo) has variable-time execution",
            "fdiv": "FDIV (FP division) has variable latency",
            "fdivs": "FDIVS (FP single division) has variable latency",
            "fsqrt": "FSQRT has variable latency",
            "fsqrts": "FSQRTS has variable latency",
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
    """Go compiler interface.

    Strategy: emit assembly via ``go build -gcflags=-S`` from the source file's
    package directory. This is significantly better than ``go build`` followed
    by ``go tool objdump`` because:

    1. It emits assembly for every function in the package, including
       non-exported library functions that the linker would dead-code-eliminate
       in a non-main package. The old objdump path silently reported "PASSED"
       on real crypto libraries because their functions were stripped.
    2. It does not include the entire Go runtime (gc, scheduler, maps), which
       previously produced 60+ false positives that drowned out user code.
    3. It resolves imports from the surrounding go.mod, so files importing
       ``crypto/subtle`` and other stdlib packages work correctly.
    4. It is faster (single compile pass, no link, no disassembly).

    For files with no go.mod and no imports we fall back to ``go tool compile -S``.
    """

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

    @staticmethod
    def _find_module_root(start: Path) -> Path | None:
        """Walk up from start looking for go.mod. Returns the directory or None."""
        cur = start.resolve()
        if cur.is_file():
            cur = cur.parent
        while True:
            if (cur / "go.mod").exists():
                return cur
            if cur.parent == cur:
                return None
            cur = cur.parent

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

        env = os.environ.copy()
        env["GOOS"] = env.get("GOOS", "linux")
        env["GOARCH"] = goarch
        env["CGO_ENABLED"] = "0"

        # -N disables optimizations, -l disables inlining (important for analysis).
        # -S emits human-readable assembly to stderr.
        gcflag_parts = ["-S"]
        if optimization == "O0":
            gcflag_parts.extend(["-N", "-l"])
        gcflags = " ".join(gcflag_parts)

        src_path = Path(source_file).resolve()
        pkg_dir = src_path.parent
        module_root = self._find_module_root(src_path)

        if module_root is not None:
            # Build the package this file lives in. Using the package import
            # path would also work, but `.` (relative to cwd) is simplest and
            # still produces assembly for all files in the package. We compile
            # the whole package because Go semantics require it: the file may
            # reference other files in the same package.
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    bin_path = os.path.join(tmpdir, "discard")
                    cmd = [
                        self.path,
                        "build",
                        "-o",
                        bin_path,
                        "-gcflags",
                        gcflags,
                        *(extra_flags or []),
                        ".",
                    ]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        env=env,
                        cwd=str(pkg_dir),
                    )
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"

            # `go build -gcflags=-S` writes assembly to stderr (the gc
            # compiler's diagnostic stream). `go build` for a non-main
            # package may exit non-zero with "no Go files" or similar;
            # -S still emits to stderr if compile succeeded. Heuristic:
            # if stderr contains TEXT directives, the compile succeeded
            # enough for analysis.
            asm_text = result.stderr
            if "TEXT\t" not in asm_text and "STEXT" not in asm_text:
                if result.returncode != 0:
                    return False, asm_text or result.stdout
                return False, "go build produced no assembly (empty package?)"
        else:
            # No go.mod: fall back to `go tool compile -S`. This works for
            # self-contained files but cannot resolve stdlib imports.
            cmd = [self.path, "tool", "compile", "-S"]
            if optimization == "O0":
                cmd.extend(["-N", "-l"])
            cmd.extend(extra_flags or [])
            cmd.append(str(src_path))
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        env=env,
                        cwd=tmpdir,  # avoid littering the source dir with .o
                    )
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"

            # `go tool compile -S` writes the assembly listing to stdout
            # (unlike `go build`, which routes -S through stderr).
            asm_text = result.stdout
            if "TEXT\t" not in asm_text and "STEXT" not in asm_text:
                msg = result.stderr or result.stdout
                if "could not import" in msg or "file not found" in msg:
                    msg += (
                        "\n\nHint: this file imports a package but is not part "
                        "of a Go module. Place it under a directory containing "
                        "go.mod (run `go mod init <name>`) and re-run."
                    )
                return False, msg

        # Tag the assembly so the parser knows this came from `go -S` (which
        # has a distinct line format) vs. objdump or gcc/clang assembly.
        with open(output_file, "w") as f:
            f.write("# ct_analyzer:format=go-gcflags-S\n")
            f.write(f"# ct_analyzer:source={src_path}\n")
            f.write(asm_text)

        return True, ""


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


# Go variable-time runtime helpers. On platforms without hardware divide
# (notably ARMv5/v6 and some pre-Go-1.23 386 paths), Go inserts CALLs to these
# software routines. They operate by bit-by-bit subtraction/shift, so their
# execution time depends on the magnitude of the operands. They are exactly
# as dangerous as a hardware divide for constant-time purposes.
GO_VARTIME_RUNTIME_CALLS = {
    "runtime.udiv": "CALL to runtime.udiv (software unsigned divide); execution time depends on operand magnitudes",
    "runtime._udiv": "CALL to runtime._udiv (software unsigned divide); execution time depends on operand magnitudes",
    "runtime.uidivmod": "CALL to runtime.uidivmod (software unsigned divmod); execution time depends on operand magnitudes",
    "runtime._uidiv": "CALL to runtime._uidiv (software unsigned divide); execution time depends on operand magnitudes",
    "runtime._uidivmod": "CALL to runtime._uidivmod (software unsigned divmod); execution time depends on operand magnitudes",
    "runtime._sidiv": "CALL to runtime._sidiv (software signed divide); execution time depends on operand magnitudes",
    "runtime._sidivmod": "CALL to runtime._sidivmod (software signed divmod); execution time depends on operand magnitudes",
}

# Go standard library packages whose internals we do NOT want to flag when
# building user code with `go build -gcflags=-S`. The current go-build path
# already restricts compilation to the user's package, so this is mostly
# defensive in case someone passes an objdump-style binary.
GO_STDLIB_FUNCTION_PREFIXES = (
    "runtime.",
    "internal/",
    "sync.",
    "sync/atomic.",
    "reflect.",
    "syscall.",
    "os.",
    "io.",
    "bytes.",
    "strings.",
    "strconv.",
    "fmt.",
    "errors.",
    "math.",
    "math/bits.",
    "math/rand.",
    "sort.",
    "encoding/",
    "unicode.",
    "unicode/utf8.",
    "type:.",
    "go:.",
    "type..",
    "go..",
    "gclocals",
)


class AssemblyParser:
    """Parser for assembly output from various compilers."""

    def __init__(
        self,
        arch: str,
        compiler: str,
        source_file: str | None = None,
        include_runtime: bool = False,
    ):
        self.arch = normalize_arch(arch)
        self.compiler = compiler
        # When set, restrict violations to functions defined in this source
        # file (matched by the file path embedded in Go's -S line tuples).
        self.restrict_to_source = source_file
        # When False (default), drop violations from Go stdlib / runtime code.
        self.include_runtime = include_runtime

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
            self.errors = arch_instructions.get("errors", {})
            self.warnings = arch_instructions.get("warnings", {})

    @staticmethod
    def _is_stdlib_function(name: str) -> bool:
        """True if this looks like a Go stdlib/runtime symbol."""
        return any(name.startswith(p) for p in GO_STDLIB_FUNCTION_PREFIXES)

    def _drop_violation(self, func: str, file_path: str | None) -> bool:
        """Decide whether to suppress a violation for noise reasons.

        Suppression rules:
        * Stdlib/runtime symbols are dropped unless ``include_runtime`` is set.
        * If a source file restriction is active (Go's -S path), drop
          violations whose ``(file:line)`` tuple points at a different file —
          this filters out anything dragged in via inlining from other
          packages.
        """
        if not self.include_runtime and self._is_stdlib_function(func):
            return True
        if self.restrict_to_source and file_path:
            try:
                if Path(file_path).resolve() != Path(self.restrict_to_source).resolve():
                    return True
            except OSError:
                # If we can't resolve, fall through and keep the violation —
                # better a false positive than a silent miss on crypto code.
                pass
        return False

    # -- Go `-S` format helpers ------------------------------------------------
    #
    # The `go build -gcflags=-S` and `go tool compile -S` formats differ from
    # gcc/clang/objdump output. A function header looks like:
    #
    #     pkgpath.FuncName STEXT nosplit size=38 args=0x8 locals=0x8 ...
    #
    # and instruction lines look like:
    #
    #     \t0x0018 00024 (/abs/path/file.go:8)\tIDIVL\tBX
    #
    # The leading address+offset pair is constant; the parenthesised tuple is
    # the source location, and the mnemonic always follows the closing paren.
    # We special-case this format so we can extract reliable file:line info
    # for filtering and reporting.
    GO_INSTR_RE = re.compile(
        r"^\s*0x[0-9a-fA-F]+\s+\d+\s+\(([^)]+):(\d+)\)\s+([A-Za-z][\w.]*)\b(.*)$"
    )
    # A function header line like:
    #     pkgpath.FuncName STEXT nosplit size=38 args=0x8 ...
    # The package path may include slashes (e.g. "example.com/foo/bar.Func")
    # and the function name may contain dots (method receivers, lambdas).
    # We require at least one dot in the symbol so we don't grab every random
    # token that precedes a TEXT-like word.
    #
    # The "S...TEXT" word has several flavors:
    #   STEXT       - normal Go function
    #   SNOPTRTEXT  - function the gc compiler annotated as no-pointer
    #   STEXTFIPS   - functions in crypto/internal/fips140/* (FIPS 140 module)
    # All of them mark a function header, so we accept any S<word>TEXT prefix.
    GO_FUNC_HEADER_RE = re.compile(
        r"^([\w./<>$\-]*\.[\w<>$]+)\s+S\w*TEXT\w*\b"
    )
    GO_TEXT_DIRECTIVE_RE = re.compile(
        r"^\s*0x[0-9a-fA-F]+\s+\d+\s+\([^)]+\)\s+TEXT\s+([\w./<>$\-]*\.[\w<>$]+)\s*\(SB\)"
    )

    def _parse_go_format(
        self, assembly_text: str, include_warnings: bool
    ) -> tuple[list[dict], list[Violation]]:
        functions: list[dict] = []
        violations: list[Violation] = []
        current_function: str | None = None
        instruction_count = 0

        for line in assembly_text.split("\n"):
            # Function header line
            header = self.GO_FUNC_HEADER_RE.match(line)
            if header:
                if current_function is not None:
                    functions.append(
                        {"name": current_function, "instructions": instruction_count}
                    )
                current_function = header.group(1)
                instruction_count = 0
                continue

            instr = self.GO_INSTR_RE.match(line)
            if not instr:
                continue
            file_path = instr.group(1)
            line_no = int(instr.group(2))
            mnemonic_raw = instr.group(3)
            operands = instr.group(4).strip()
            mnemonic = mnemonic_raw.lower()

            # Skip pseudo-ops that aren't real instructions
            if mnemonic in ("text", "funcdata", "pcdata", "rel"):
                # TEXT directive can also carry the function name
                if mnemonic == "text":
                    text_match = self.GO_TEXT_DIRECTIVE_RE.match(line)
                    if text_match and current_function is None:
                        current_function = text_match.group(1)
                continue

            instruction_count += 1

            # Extract address if any (we already know the line matches)
            addr_match = re.search(r"0x[0-9a-fA-F]+", line)
            address = addr_match.group(0) if addr_match else ""

            severity: Severity | None = None
            reason: str | None = None
            if mnemonic in self.errors:
                severity = Severity.ERROR
                reason = self.errors[mnemonic]
            elif include_warnings and mnemonic in self.warnings:
                severity = Severity.WARNING
                reason = self.warnings[mnemonic]
            elif mnemonic == "call":
                # Detect calls to Go's variable-time software divide helpers.
                # Operand looks like "runtime.udiv(SB)".
                callee = operands.split("(", 1)[0].strip()
                if callee in GO_VARTIME_RUNTIME_CALLS:
                    severity = Severity.ERROR
                    reason = GO_VARTIME_RUNTIME_CALLS[callee]
                    mnemonic = callee  # Report the callee, not just "CALL"

            if severity is None:
                continue

            func_name = current_function or "<unknown>"
            if self._drop_violation(func_name, file_path):
                continue

            violations.append(
                Violation(
                    function=func_name,
                    file=file_path,
                    line=line_no,
                    address=address,
                    instruction=line.strip(),
                    mnemonic=mnemonic.upper(),
                    reason=reason,
                    severity=severity,
                )
            )

        if current_function is not None:
            functions.append(
                {"name": current_function, "instructions": instruction_count}
            )
        return functions, violations

    def parse(
        self, assembly_text: str, include_warnings: bool = False
    ) -> tuple[list[dict], list[Violation]]:
        """
        Parse assembly text and detect violations.
        Returns (functions, violations).
        """
        # Detect Go's `-S` output by sentinel comment we inject in GoCompiler,
        # or by the characteristic STEXT-family directive in the first ~8 KB.
        # Go uses STEXT for normal functions, SNOPTRTEXT for no-pointer
        # variants, and STEXTFIPS for symbols inside crypto/internal/fips140.
        head = assembly_text[:8192]
        is_go = "ct_analyzer:format=go-gcflags-S" in head or re.search(
            r"\bS\w*TEXT\w*\b", head
        )
        if is_go:
            return self._parse_go_format(assembly_text, include_warnings)

        functions = []
        violations = []

        current_function = None
        current_file = None
        current_line = None
        instruction_count = 0

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

            # Check for violations
            severity: Severity | None = None
            reason: str | None = None
            if mnemonic in self.errors:
                severity = Severity.ERROR
                reason = self.errors[mnemonic]
            elif include_warnings and mnemonic in self.warnings:
                severity = Severity.WARNING
                reason = self.warnings[mnemonic]

            if severity is None:
                continue

            func_name = current_function or "<unknown>"
            if self._drop_violation(func_name, current_file):
                continue

            violations.append(
                Violation(
                    function=func_name,
                    file=current_file or "",
                    line=current_line,
                    address=address,
                    instruction=instruction,
                    mnemonic=mnemonic.upper(),
                    reason=reason,
                    severity=severity,
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
    include_runtime: bool = False,
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
        include_runtime: For Go, do not filter out stdlib/runtime functions
            (off by default; flagging runtime divisions buries user findings)

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

        # Parse and analyze. For Go, restrict reporting to functions defined
        # in the source file the user asked about: `go build -gcflags=-S`
        # emits assembly for the entire package, but the user's intent is
        # almost always to audit one file at a time.
        restrict_source = str(source_path.absolute()) if language == "go" else None
        parser = AssemblyParser(
            arch,
            compiler_obj.name,
            source_file=restrict_source,
            include_runtime=include_runtime,
        )
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
        "--include-runtime",
        action="store_true",
        help=(
            "Go only: include violations from Go stdlib/runtime functions. "
            "Off by default because runtime code contains many divisions that "
            "are unrelated to the user's crypto code and bury real findings."
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
                include_runtime=args.include_runtime,
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
