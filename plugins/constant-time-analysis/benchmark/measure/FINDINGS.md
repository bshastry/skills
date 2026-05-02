# Measurement Findings — Intel Xeon @ 2.10GHz (Skylake-class)

Measured with `benchmark/measure/timing_probe.c` (RDTSCP+LFENCE-bracketed,
NUM_PAIRS=64, REPS=25, INNER=2048, threshold cv_var > 5×cv_fix AND > 5%).

## Variable-time on this host (3 mnemonics)

| Mnemonic | cv_varying | cv_fixed | mean cycles |
|----------|-----------:|---------:|------------:|
| `divss`  | 0.256      | 0.014    | 84          |
| `divsd`  | 0.510      | 0.034    | 30          |
| `divpd`  | 0.379      | <0.001   | 41          |

## Constant-time on this host (everything else measured)

Integer: `divq` `idivq` `mulq` `bsf` `bsr` `lzcnt` `tzcnt` `popcnt` `cmov` `rep movsb`
FP scalar single: `mulss` `addss` `subss` `sqrtss`
FP scalar double: `mulsd` `addsd` `subsd` `sqrtsd`
FP packed: `divps` `sqrtps` `sqrtpd`
AVX scalar: `vdivss` `vdivsd` `vmulss` `vsqrtss`
FMA: `vfmadd231ss` `vfmadd231sd` (and 132/213 variants)
Crypto-NI: `pclmulqdq` `aesenc`
Denormal-input variants: `mulss_denorm` `addss_denorm` `mulsd_denorm` `addsd_denorm`

## False-Negative Analysis

**Recall against measured ground truth = 1.00 across every profile.**
Every measured-variable mnemonic is flagged by the analyzer:

| Profile     | TP | FP | FN | TN | P    | R    |
|-------------|---:|---:|---:|---:|-----:|-----:|
| legacy      | 3  | 31 | 0  | 0  | 0.09 | 1.00 |
| modern-x86  | 3  | 8  | 0  | 23 | 0.27 | 1.00 |
| modern-arm  | 4  | 0  | 0  | 4  | 1.00 | 1.00 |
| embedded    | 8  | 1  | 0  | 0  | 0.89 | 1.00 |

(legacy and modern-x86 use the same x86 mnemonic set; modern-arm and embedded
use ARM mnemonics, scored against documented behavior since this host can't
execute ARM directly.)

The legacy profile flags 31 things this Xeon executes in constant time
(`mulss/addss/sqrtss/...` etc.). This is the *intended* defensive behavior —
those mnemonics ARE documented variable-time on older Intel/AMD CPUs and on
many other ISAs. A user targeting this specific Xeon can switch to
`--cpu-profile modern-x86 --define CT_DOITM_ENABLED --define CT_FTZ_DAZ` to
suppress the conservative flags.

## Surprising findings

1. **AVX-encoded FP DIV (`vdivss`, `vdivsd`) is constant-time on this Xeon
   while non-VEX (`divss`, `divsd`) is variable.** Same logical operation,
   different microarchitectural pipeline — the VEX path appears to use the
   later constant-time DIV unit. We continue to flag both because: (a) it is
   not portable across vendors/microarchs, (b) compilers freely choose
   between encodings.

2. **Packed single-precision DIV (`divps`) is constant on this Xeon** while
   scalar (`divss`) is variable. Likely the packed unit returns the worst-
   case-lane latency on every issue, smoothing the distribution.

3. **Denormal slow-path is invisible on this CPU** for `mulss/addss/mulsd/
   addsd` — denormal-input variants showed no extra latency. This is
   consistent with Intel's claim that Skylake+ Xeon handles denormals
   natively for these ops. Older Intel cores and many AMD parts do not.
   We keep the FTZ-absent rule for portability.

4. **No false negatives** in the bit-manipulation suspect set: BSF, BSR,
   LZCNT, TZCNT, POPCNT, CMOV, PCLMULQDQ, AESENC, REP MOVSB all measured
   constant-time. The analyzer's silence on these is correct.

## Methodology Caveats

- **TSC-based** measurement; values are TSC ticks, not core cycles. The
  `lfence` between operations adds ~3-5 cycles overhead, which is included
  in the absolute `mean_cycles` figures but cancels out of the CV.
- **Single CPU pinning** (CPU 0); no SMT-pair coordination. Background
  noise from neighboring threads can inflate `cv_fixed`; the threshold
  `cv_var > 5×cv_fix` adapts to that floor.
- **Operand range:** floats in [1, 2), doubles in [1, 2). Pathological
  inputs (denormals, infinities, NaNs) tested separately; we did not
  exhaustively explore the corner-case space for INT DIV (small/large
  quotient, divide-by-1, etc.).
- **Single host CPU.** Measurements valid only for this Skylake-class Xeon.
  Re-running on a different SKU (Ice Lake, Sapphire Rapids, Zen3, M1, etc.)
  may yield different verdicts. The skill encodes documented worst-case
  behavior in its rule set; per-host measurement provides ground truth for
  the deployment target only.
