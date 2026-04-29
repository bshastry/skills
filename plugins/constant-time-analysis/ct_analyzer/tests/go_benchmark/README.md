# Go Crypto Side-Channel Benchmark

A validation suite for the Go support in `ct_analyzer`. Used as a release gate:
the tool must detect every known-bad pattern in `vulnerable/` and produce no
unexpected ERROR-level findings on the patterns in `safe/`.

## Running

```bash
# From this directory:
python3 run_benchmark.py

# Restrict to one architecture:
python3 run_benchmark.py --arch x86_64
```

Exit code is `0` if all expectations are met, `1` otherwise.

## Layout

```
go_benchmark/
  go.mod                       # makes this a real Go module so imports resolve
  expectations.json            # golden findings the analyzer must produce
  run_benchmark.py             # runner that compares observed vs expected
  vulnerable/
    kyberslash_division.go     # KyberSlash: integer divide on secret
    mldsa_decompose.go         # ML-DSA decompose with hardware divide
    timing_compare.go          # Lucky-Thirteen-style early-exit memcmp
    montgomery_branch.go       # Square-and-multiply scalar leak
    rsa_decrypt_branch.go      # Bleichenbacher / Manger padding oracle
    fp_division.go             # DIVSD / FDIV on secret operand
  safe/
    constant_time_compare.go   # subtle.ConstantTimeCompare wrapper
    barrett_reduction.go       # multiply-by-magic replacement for divide
    bitmask_select.go          # branchless selection
    montgomery_ladder.go       # cswap-based scalar multiplication
    public_data_division.go    # divide on public lengths (expected FP)
```

## What this benchmark validates

* **No false negatives** on the `vulnerable/` corpus. Every CVE-class
  pattern (KyberSlash, Lucky Thirteen, Bleichenbacher, square-and-multiply,
  FP-divide-on-secret) is caught on x86_64 and arm64.
* **Low false positives** on the `safe/` corpus. The standard hardening
  patterns (`crypto/subtle`, Barrett reduction, bitmask selection, Montgomery
  ladder) produce zero ERROR-level findings. Conditional-branch warnings
  may still appear; users triage those manually because the analyzer does
  not perform data-flow analysis.
* **Architecture coverage.** Each test runs against x86_64 and arm64 (the
  two production targets at Google scale), so cross-compile mnemonics like
  `SDIVW`, `REMW`, `JCC`, and `TBNZ` are exercised.

## Why these patterns?

Each `vulnerable/*.go` file ports a real-world CVE class into Go:

| File | Real-world precedent |
|------|----------------------|
| `kyberslash_division.go` | [KyberSlash, 2023](https://kyberslash.cr.yp.to/) — divide-by-public-modulus on secret coefficient. |
| `mldsa_decompose.go` | [Bernstein & Lange, 2024](https://cr.yp.to/papers.html) — ML-DSA decompose without Barrett. |
| `timing_compare.go` | [Lucky Thirteen, 2013](https://www.isg.rhul.ac.uk/tls/Lucky13.html) — early-exit MAC comparison. |
| `montgomery_branch.go` | [Kocher, 1996](https://www.paulkocher.com/doc/TimingAttacks.pdf) — bit-by-bit branch in scalar mul. |
| `rsa_decrypt_branch.go` | [Bleichenbacher, 1998](https://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf) — PKCS#1 v1.5 padding oracle. |
| `fp_division.go` | Multiple BigNum implementations have been bitten by FP division latency on secret data. |

## Go-specific subtleties this suite documents

1. **Compile-time-constant divisors get optimized away.** Go's SSA rewrites
   `x / 3329` to multiply-by-magic-number. A naive port of a vulnerable C
   reference into Go can be *accidentally* constant-time. To trigger a true
   KyberSlash detection in Go, the divisor must be a runtime value (parameter
   or struct field). `kyberslash_division.go` uses `*KyberParams` exactly
   for this reason.

2. **Plan-9 mnemonics on amd64.** Go's amd64 assembler emits `JCC`/`JLT`/
   `JEQ` instead of `JNC`/`JL`/`JE`. The analyzer recognises both forms.

3. **ARM64 emits `SDIVW` and `REMW`** (the 32-bit suffixed forms),
   not bare `SDIV`/`REM`. The analyzer recognises both.

4. **Go's runtime is stripped from the report by default.** The old objdump
   path included the entire runtime in user findings; the new
   `go build -gcflags=-S` path emits only the user package's assembly, and
   the parser additionally drops anything in `runtime.*`, `sync.*`,
   `internal/*`, etc. Pass `--include-runtime` to opt back in.

## Adding a new vulnerable pattern

1. Add `vulnerable/<name>.go` with a documented real-world precedent.
2. Add the corresponding entry to `expectations.json` listing the
   `must_detect` (or `must_detect_with_warnings`) facts.
3. Run `python3 run_benchmark.py` — the new file should show `OK`.
4. Open a PR; CI runs the benchmark on every change.
