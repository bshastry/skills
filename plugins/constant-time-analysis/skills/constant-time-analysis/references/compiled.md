# Constant-Time Analysis: Compiled Languages

Analysis guidance for C, C++, Go, and Rust. These languages compile to native assembly, where timing side-channels are detected by scanning for variable-time CPU instructions.

## Running the Analyzer

```bash
# C/C++ (default: clang, native architecture)
uv run {baseDir}/ct_analyzer/analyzer.py crypto.c

# Go
uv run {baseDir}/ct_analyzer/analyzer.py crypto.go

# Rust
uv run {baseDir}/ct_analyzer/analyzer.py crypto.rs

# Cross-architecture testing (RECOMMENDED)
uv run {baseDir}/ct_analyzer/analyzer.py --arch x86_64 crypto.c
uv run {baseDir}/ct_analyzer/analyzer.py --arch arm64 crypto.c

# Multiple optimization levels
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O0 crypto.c
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O3 crypto.c

# Include conditional branch warnings
uv run {baseDir}/ct_analyzer/analyzer.py --warnings crypto.c

# Filter to specific functions
uv run {baseDir}/ct_analyzer/analyzer.py --func 'sign|verify|decrypt' crypto.c

# CI-friendly JSON output
uv run {baseDir}/ct_analyzer/analyzer.py --json crypto.c
```

## Supported Compilers

| Language | Compiler | Flag |
|----------|----------|------|
| C/C++ | gcc | `--compiler gcc` |
| C/C++ | clang (default) | `--compiler clang` |
| Go | go | `--compiler go` |
| Rust | rustc | `--compiler rustc` |

## Supported Architectures

x86_64, arm64, arm, riscv64, ppc64le, s390x, i386

## Dangerous Instructions by Architecture

| Architecture | Integer Division | Floating-Point | Embedded MUL (Cortex-M0/M3) |
|-------------|----------|----------------|-----|
| x86_64 | DIV, IDIV, DIVQ, IDIVQ | DIVSS, DIVSD, SQRTSS, SQRTSD, MULSS/ADDSS (denormals) | n/a |
| ARM64 | UDIV, SDIV | FDIV, FSQRT, FADD/FMUL/FMADD (denormals) | n/a |
| ARM | UDIV, SDIV, `__aeabi_idiv` (call) | VDIV, VSQRT, VADD/VMUL (denormals) | MUL, MULS, UMULL, SMULL, SMMUL |
| RISC-V | DIV, DIVU, REM, REMU | FDIV.S, FDIV.D, FSQRT | n/a |
| PowerPC | DIVW, DIVD | FDIV, FSQRT | n/a |
| s390x | D, DR, DL, DLG, DSG | DDB, SQDB | n/a |

## CPU Profile Selection

```bash
# Defensive default — assumes worst-case CPU
uv run {baseDir}/ct_analyzer/analyzer.py --cpu-profile legacy crypto.c

# Modern x86 with DOITM (Ice Lake+, Zen3+) — INT DIV suppressed if
# CT_DOITM_ENABLED is defined in source. FP DIV/SQRT still flagged.
uv run {baseDir}/ct_analyzer/analyzer.py --cpu-profile modern-x86 --arch x86_64 crypto.c

# Modern ARM with DIT — note SDIV/UDIV are NOT covered by DIT.
uv run {baseDir}/ct_analyzer/analyzer.py --cpu-profile modern-arm --arch arm64 crypto.c

# Cortex-M0/M3 — adds variable-time MUL detection.
uv run {baseDir}/ct_analyzer/analyzer.py --cpu-profile embedded --arch arm crypto.c
```

## Source-Level Guard Macros

The analyzer scans the source for `#define` of:

- **`CT_DOITM_ENABLED`** — suppresses INT DIV/IDIV under `modern-x86` (developer asserts process enables Intel/AMD DOITM via MSR at runtime).
- **`CT_FTZ_DAZ`** — suppresses MULSS/ADDSS/FMUL/FADD denormal-channel ERRORs (developer asserts MXCSR FTZ+DAZ is set; FP DIV/SQRT remain ERROR).
- **`CT_PUBLIC_DIVISOR`** — suppresses every INT DIV in the file (developer asserts every divisor is public).
- **`CT_ARM_DIT_ENABLED`** — currently informational; ARMv8.4 DIT does not cover SDIV/UDIV.

## Constant-Time Patterns

### Replace Division

```c
// VULNERABLE: Compiler emits DIV instruction
int32_t q = a / divisor;

// SAFE: Barrett reduction (precompute mu = ceil(2^32 / divisor))
uint32_t q = (uint32_t)(((uint64_t)a * mu) >> 32);
```

### Replace Branches

```c
// VULNERABLE: Branch timing reveals secret
if (secret) { result = a; } else { result = b; }

// SAFE: Constant-time selection
uint32_t mask = -(uint32_t)(secret != 0);
result = (a & mask) | (b & ~mask);
```

### Replace Comparisons

```c
// VULNERABLE: memcmp returns early on mismatch
if (memcmp(a, b, len) == 0) { ... }

// SAFE: Constant-time comparison
if (CRYPTO_memcmp(a, b, len) == 0) { ... }  // OpenSSL
if (subtle.ConstantTimeCompare(a, b) == 1) { ... }  // Go
```

## Common Mistakes

1. **Testing only one optimization level** - Compilers make different decisions at O0 vs O3. A clean O2 build may have divisions at O0.

2. **Testing only one architecture** - ARM and x86 have different division behavior. Test your deployment targets.

3. **Ignoring warnings** - Conditional branches on secrets are exploitable. Use `--warnings` and review each branch.

4. **Assuming the tool catches everything** - This tool detects instruction-level issues only. It cannot detect:
   - Cache timing from memory access patterns
   - Microarchitectural attacks (Spectre, etc.)
   - Whether flagged code actually processes secrets

5. **Fixing symptoms, not causes** - If compiler introduces division, understand why. Sometimes the algorithm itself needs redesign.

## Go-Specific Notes

Go compiles to native code, so the analyzer builds a binary and disassembles it using `go tool objdump`. The analyzer:
- Sets `CGO_ENABLED=0` for pure Go analysis
- Supports cross-compilation via `GOARCH` environment variable
- Uses `-N -l` gcflags for O0 (disable optimizations)

## Rust-Specific Notes

Rust uses `rustc --emit=asm` for assembly generation. The analyzer:
- Maps optimization levels to rustc's `-C opt-level` flag
- Supports cross-compilation via `--target` flag
- Analyzes the emitted assembly for timing-unsafe instructions

## CI Integration

```yaml
- name: Check constant-time properties
  run: |
    uv run ct_analyzer/analyzer.py --json src/crypto/*.c
    # Exit code 1 = violations found
```
