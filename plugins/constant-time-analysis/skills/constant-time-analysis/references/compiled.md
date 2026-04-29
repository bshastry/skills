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

| Architecture | Division | Floating-Point |
|-------------|----------|----------------|
| x86_64 | DIV, IDIV, DIVQ, IDIVQ | DIVSS, DIVSD, SQRTSS, SQRTSD |
| ARM64 | UDIV, SDIV | FDIV, FSQRT |
| ARM | UDIV, SDIV | VDIV, VSQRT |
| RISC-V | DIV, DIVU, REM, REMU | FDIV.S, FDIV.D, FSQRT |
| PowerPC | DIVW, DIVD | FDIV, FSQRT |
| s390x | D, DR, DL, DLG, DSG | DDB, SQDB |

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

Go compiles to native code, but the analyzer does NOT build-then-disassemble. Instead, it runs `go build -gcflags=-S` from the source file's package directory and parses the compiler's assembly listing. This matters because:

- **Library packages work.** A previous version of this tool relied on `go build` + `go tool objdump`. For non-`main` packages the linker dead-code-eliminated user functions, so the analyzer reported "PASSED" on real crypto libraries. The current tool emits assembly for every defined function, exported or not.
- **No runtime noise.** `-gcflags=-S` covers only the user's package, so reports are not buried under hundreds of `runtime.*` divisions. Pass `--include-runtime` to opt back in.
- **Imports are resolved through `go.mod`.** Place crypto libraries inside a real Go module (run `go mod init` if needed) so stdlib imports like `crypto/subtle` work.

Other behavior:
- Sets `CGO_ENABLED=0` and respects `GOOS`/`GOARCH` for cross-compilation.
- `--opt-level O0` adds `-N -l` (disable optimization and inlining).
- Standalone files with no `go.mod` and no imports fall back to `go tool compile -S`.

**Go-specific patterns to know about:**

| Pattern | What the analyzer sees | Why |
|---------|------------------------|-----|
| `x / 3329` (constant divisor) | No `IDIV` reported | Go's SSA rewrites compile-time constant divides into multiply-by-magic-number. This is constant-time, but it also means a textbook port of vulnerable C code may *accidentally* be safe. Test with a runtime divisor to validate detection. |
| `x / params.Q` (runtime divisor) | `IDIVL` (amd64), `SDIVW`+`REMW` (arm64) | True hardware divide; data-dependent timing. |
| `bytes.Equal(mac, expected)` | Branch warnings | Use `subtle.ConstantTimeCompare` instead. |
| Older ARMv5/v6 | `CALL runtime.udiv` | Software bit-by-bit divide; flagged. |
| Plan-9 amd64 mnemonics | `JEQ`/`JCC`/`JLT` etc. | Equivalent to AT&T `JE`/`JNC`/`JL`; the analyzer knows both forms. |

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
