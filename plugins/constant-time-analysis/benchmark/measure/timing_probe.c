/* timing_probe.c — measure cycle-count distribution of suspected
 * variable-time x86_64 instructions, then emit a JSON record describing
 * whether the timing is data-dependent.
 *
 *   $ ./timing_probe <op>
 *
 * <op> selects the micro-benchmark. Each benchmark runs INNER repetitions of
 * the target instruction inside a tight loop, surrounded by RDTSCP fences,
 * then records the per-iteration cycle count. We do this NUM_PAIRS times
 * with different operand values (varying) and NUM_PAIRS times with the same
 * operand value (fixed). The coefficient of variation of the per-pair
 * MEDIANS tells us whether the instruction's timing depends on its inputs.
 *
 * Verdict:  variable_time = (cv_varying > 5*cv_fixed) AND (cv_varying > 0.05)
 *
 * Compile:  cc -O2 -o timing_probe timing_probe.c -lm
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <math.h>
#include <sys/mman.h>

#define INNER       2048    /* repetitions per timed loop */
#define NUM_PAIRS   64      /* distinct input pairs */
#define REPS        25      /* timed runs per pair (we take median) */

static inline uint64_t rdtscp(void) {
    uint32_t lo, hi, aux;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline void serialize(void) {
    /* CPUID is the standard serializing fence used to bracket RDTSC blocks. */
    uint32_t a = 0, b, c, d;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a) : "memory");
}

/* Pseudo-random 64-bit (xorshift64*). */
static uint64_t prng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t prng(void) {
    uint64_t x = prng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    prng_state = x;
    return x * 2685821657736338717ULL;
}

/* Comparator for qsort. */
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Median of REPS samples. */
static uint64_t median_u64(uint64_t *v, int n) {
    qsort(v, n, sizeof(*v), cmp_u64);
    return v[n / 2];
}

/* CV (coefficient of variation) of a double array. */
static double cv(double *v, int n) {
    double s = 0;
    for (int i = 0; i < n; i++) s += v[i];
    double mean = s / n;
    if (mean == 0) return 0;
    double ss = 0;
    for (int i = 0; i < n; i++) ss += (v[i] - mean) * (v[i] - mean);
    return sqrt(ss / n) / mean;
}

/* ---------- per-op kernels ---------- */

/* LFENCE between successive ops serializes dispatch on Intel/AMD, exposing
 * per-op latency rather than throughput. Without it, OoO execution overlaps
 * independent DIVs and we'd measure 6 cycles instead of 21-83. */
static uint64_t bench_divq(uint64_t a, uint64_t b) {
    uint64_t q, r;
    if (b == 0) b = 1;
    if (a < b) a |= b;          /* prevent early-exit q=0 */
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        uint64_t lo = a, hi = 0;
        __asm__ __volatile__("divq %4\n\tlfence"
            : "=a"(q), "=d"(r)
            : "0"(lo), "1"(hi), "r"(b)
            : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_mulq(uint64_t a, uint64_t b) {
    uint64_t hi, lo;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("mulq %3\n\tlfence"
            : "=a"(lo), "=d"(hi)
            : "0"(a), "r"(b)
            : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_idivq(int64_t a, int64_t b) {
    int64_t q, r;
    if (b == 0) b = 1;
    if (a >= 0 && a < b) a |= b;
    if (a < 0 && a > -b) a = -((int64_t)((uint64_t)(-a) | (uint64_t)b));
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        int64_t lo = a, hi = a >> 63;
        __asm__ __volatile__("idivq %4\n\tlfence"
            : "=a"(q), "=d"(r)
            : "0"(lo), "1"(hi), "r"(b)
            : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_divss(float a, float b) {
    if (b == 0.0f) b = 1.0f;
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("divss %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_divsd(double a, double b) {
    if (b == 0.0) b = 1.0;
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("divsd %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_sqrtss(float a) {
    if (a < 0) a = -a;
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("sqrtss %1, %0\n\tlfence" : "+x"(r) : "x"(a));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_mulss(float a, float b) {
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("mulss %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_addss(float a, float b) {
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("addss %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* Same as mulss but with denormal operands. */
static uint64_t bench_mulss_denorm(uint32_t bits_a, uint32_t bits_b) {
    /* Force into the denormal range: exponent = 0, mantissa nonzero. */
    bits_a = (bits_a & 0x007fffffU) | 0;            /* exp=0 → denormal */
    bits_b = (bits_b & 0x007fffffU) | 0;
    if ((bits_a & 0x007fffffU) == 0) bits_a = 1;
    if ((bits_b & 0x007fffffU) == 0) bits_b = 1;
    float a, b;
    memcpy(&a, &bits_a, 4); memcpy(&b, &bits_b, 4);
    return bench_mulss(a, b);
}

static uint64_t bench_addss_denorm(uint32_t bits_a, uint32_t bits_b) {
    bits_a = (bits_a & 0x007fffffU) | 0;
    bits_b = (bits_b & 0x007fffffU) | 0;
    if ((bits_a & 0x007fffffU) == 0) bits_a = 1;
    if ((bits_b & 0x007fffffU) == 0) bits_b = 1;
    float a, b;
    memcpy(&a, &bits_a, 4); memcpy(&b, &bits_b, 4);
    return bench_addss(a, b);
}

/* ---- Scalar-double-precision FP variants ---- */

static uint64_t bench_mulsd(double a, double b) {
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("mulsd %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_addsd(double a, double b) {
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("addsd %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_subss(float a, float b) {
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("subss %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_subsd(double a, double b) {
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("subsd %1, %0\n\tlfence" : "+x"(r) : "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_sqrtsd(double a) {
    if (a < 0) a = -a;
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("sqrtsd %1, %0\n\tlfence" : "+x"(r) : "x"(a));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* Denormal variants for double */
static uint64_t bench_mulsd_denorm(uint32_t bits_a, uint32_t bits_b) {
    uint64_t da = (uint64_t)bits_a & 0x000fffffffffffffULL;
    uint64_t db = (uint64_t)bits_b & 0x000fffffffffffffULL;
    if (da == 0) da = 1;
    if (db == 0) db = 1;
    double a, b;
    memcpy(&a, &da, 8); memcpy(&b, &db, 8);
    return bench_mulsd(a, b);
}

static uint64_t bench_addsd_denorm(uint32_t bits_a, uint32_t bits_b) {
    uint64_t da = (uint64_t)bits_a & 0x000fffffffffffffULL;
    uint64_t db = (uint64_t)bits_b & 0x000fffffffffffffULL;
    if (da == 0) da = 1;
    if (db == 0) db = 1;
    double a, b;
    memcpy(&a, &da, 8); memcpy(&b, &db, 8);
    return bench_addsd(a, b);
}

/* ---- Packed FP (4 floats / 2 doubles per op) ---- */

static uint64_t bench_divps(float a, float b) {
    if (b == 0.0f) b = 1.0f;
    float va[4] = {a, a*1.1f, a*1.3f, a*1.7f};
    float vb[4] = {b, b*1.2f, b*1.5f, b*1.9f};
    typedef float v4f __attribute__((vector_size(16)));
    v4f x, y;
    memcpy(&x, va, 16); memcpy(&y, vb, 16);
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("divps %1, %0\n\tlfence" : "+x"(x) : "x"(y));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_divpd(double a, double b) {
    if (b == 0.0) b = 1.0;
    typedef double v2d __attribute__((vector_size(16)));
    double va[2] = {a, a * 1.3}, vb[2] = {b, b * 1.7};
    v2d x, y;
    memcpy(&x, va, 16); memcpy(&y, vb, 16);
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("divpd %1, %0\n\tlfence" : "+x"(x) : "x"(y));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_sqrtps(float a) {
    if (a < 0) a = -a;
    typedef float v4f __attribute__((vector_size(16)));
    float va[4] = {a, a*1.3f, a*1.7f, a*2.1f};
    v4f x; memcpy(&x, va, 16); v4f y = x;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("sqrtps %1, %0\n\tlfence" : "+x"(x) : "x"(y));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_sqrtpd(double a) {
    if (a < 0) a = -a;
    typedef double v2d __attribute__((vector_size(16)));
    double va[2] = {a, a * 1.3};
    v2d x; memcpy(&x, va, 16); v2d y = x;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("sqrtpd %1, %0\n\tlfence" : "+x"(x) : "x"(y));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* ---- AVX (VEX-encoded) scalar variants ---- */

static uint64_t bench_vdivss(float a, float b) {
    if (b == 0.0f) b = 1.0f;
    float r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("vdivss %2, %1, %0\n\tlfence"
                             : "=x"(r) : "x"(a), "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_vdivsd(double a, double b) {
    if (b == 0.0) b = 1.0;
    double r = a;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("vdivsd %2, %1, %0\n\tlfence"
                             : "=x"(r) : "x"(a), "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_vmulss(float a, float b) {
    float r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("vmulss %2, %1, %0\n\tlfence"
                             : "=x"(r) : "x"(a), "x"(b));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_vsqrtss(float a) {
    if (a < 0) a = -a;
    float r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("vsqrtss %1, %1, %0\n\tlfence"
                             : "=x"(r) : "x"(a));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* ---- FMA ---- */

static uint64_t bench_vfmadd231ss(float a, float b) {
    float r = a, c = b * 0.5f;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        /* r = r + a*c */
        __asm__ __volatile__("vfmadd231ss %2, %1, %0\n\tlfence"
                             : "+x"(r) : "x"(a), "x"(c));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_vfmadd231sd(double a, double b) {
    double r = a, c = b * 0.5;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("vfmadd231sd %2, %1, %0\n\tlfence"
                             : "+x"(r) : "x"(a), "x"(c));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* ---- Suspect instructions NOT currently flagged (FN candidates) ---- */

static uint64_t bench_bsf(uint64_t a, uint64_t b) {
    (void)b;
    if (a == 0) a = 1;            /* BSF undefined on 0 */
    uint64_t r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("bsfq %1, %0\n\tlfence" : "=r"(r) : "r"(a) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_bsr(uint64_t a, uint64_t b) {
    (void)b;
    if (a == 0) a = 1;
    uint64_t r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("bsrq %1, %0\n\tlfence" : "=r"(r) : "r"(a) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_lzcnt(uint64_t a, uint64_t b) {
    (void)b;
    uint64_t r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("lzcntq %1, %0\n\tlfence" : "=r"(r) : "r"(a) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_tzcnt(uint64_t a, uint64_t b) {
    (void)b;
    uint64_t r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("tzcntq %1, %0\n\tlfence" : "=r"(r) : "r"(a) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_popcnt(uint64_t a, uint64_t b) {
    (void)b;
    uint64_t r;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("popcntq %1, %0\n\tlfence" : "=r"(r) : "r"(a) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_cmov(uint64_t a, uint64_t b) {
    /* CMOV's whole purpose is constant-time selection; verify. */
    uint64_t r = 0;
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__(
            "cmpq %2, %1\n\t"
            "cmovbq %2, %0\n\t"
            "lfence"
            : "+r"(r) : "r"(a), "r"(b) : "cc");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_pclmulqdq(uint64_t a, uint64_t b) {
    /* GF(2^64) carry-less multiply — used in AES-GCM, should be CT. */
    typedef uint64_t v2u __attribute__((vector_size(16)));
    v2u x = {a, a}, y = {b, b};
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("pclmulqdq $0, %1, %0\n\tlfence" : "+x"(x) : "x"(y));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

static uint64_t bench_aesenc(uint64_t a, uint64_t b) {
    typedef uint64_t v2u __attribute__((vector_size(16)));
    v2u x = {a, a}, k = {b, b};
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER; i++) {
        __asm__ __volatile__("aesenc %1, %0\n\tlfence" : "+x"(x) : "x"(k));
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* REP MOVSB — variable-time by length. We test with FIXED length so this
 * detects only data-dependent variation (which there should be ~none of). */
static uint64_t bench_rep_movsb(uint64_t a, uint64_t b) {
    static char buf_src[256], buf_dst[256];
    /* Make timing depend on the data PATTERN by writing a/b into buf_src */
    for (int i = 0; i < 256; i += 16) {
        memcpy(buf_src + i, &a, 8);
        memcpy(buf_src + i + 8, &b, 8);
    }
    serialize();
    uint64_t t0 = rdtscp();
    for (int i = 0; i < INNER / 32; i++) {  /* 32 bytes per inner iter */
        const char *src = buf_src;
        char *dst = buf_dst;
        unsigned long n = 32;
        __asm__ __volatile__(
            "rep movsb\n\tlfence"
            : "+S"(src), "+D"(dst), "+c"(n) :: "memory");
    }
    uint64_t t1 = rdtscp();
    serialize();
    return t1 - t0;
}

/* ---------- uniform dispatch ----------
 * Every kernel below has signature (uint64_t a_bits, uint64_t b_bits)->cycles.
 * Bit-pattern interpretation (float/double/int) happens inside each wrapper. */

static float fbits_to_norm(uint32_t bits) {
    /* Build a finite-non-denormal float in [1, 2) from bits. */
    uint32_t u = 0x3f800000U | (bits & 0x007fffffU);
    float f; memcpy(&f, &u, 4); return f;
}
static double dbits_to_norm(uint64_t bits) {
    uint64_t u = 0x3ff0000000000000ULL | (bits & 0x000fffffffffffffULL);
    double d; memcpy(&d, &u, 8); return d;
}

#define WRAP_FP_BIN_F(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { \
        return bench_##name(fbits_to_norm((uint32_t)a), fbits_to_norm((uint32_t)b)); }
#define WRAP_FP_BIN_D(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { \
        return bench_##name(dbits_to_norm(a), dbits_to_norm(b)); }
#define WRAP_FP_UN_F(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { \
        (void)b; return bench_##name(fbits_to_norm((uint32_t)a)); }
#define WRAP_FP_UN_D(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { \
        (void)b; return bench_##name(dbits_to_norm(a)); }
#define WRAP_DENORM(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { \
        return bench_##name((uint32_t)a, (uint32_t)b); }
#define WRAP_INT(name) \
    static uint64_t w_##name(uint64_t a, uint64_t b) { return bench_##name(a, b); }

WRAP_INT(divq)
WRAP_INT(mulq)
static uint64_t w_idivq(uint64_t a, uint64_t b) { return bench_idivq((int64_t)a, (int64_t)b); }
WRAP_FP_BIN_F(divss)
WRAP_FP_BIN_D(divsd)
WRAP_FP_BIN_F(mulss)
WRAP_FP_BIN_F(addss)
WRAP_FP_UN_F(sqrtss)
WRAP_DENORM(mulss_denorm)
WRAP_DENORM(addss_denorm)
WRAP_FP_BIN_D(mulsd)
WRAP_FP_BIN_D(addsd)
WRAP_FP_BIN_F(subss)
WRAP_FP_BIN_D(subsd)
WRAP_FP_UN_D(sqrtsd)
WRAP_DENORM(mulsd_denorm)
WRAP_DENORM(addsd_denorm)
WRAP_FP_BIN_F(divps)
WRAP_FP_BIN_D(divpd)
WRAP_FP_UN_F(sqrtps)
WRAP_FP_UN_D(sqrtpd)
WRAP_FP_BIN_F(vdivss)
WRAP_FP_BIN_D(vdivsd)
WRAP_FP_BIN_F(vmulss)
WRAP_FP_UN_F(vsqrtss)
WRAP_FP_BIN_F(vfmadd231ss)
WRAP_FP_BIN_D(vfmadd231sd)
WRAP_INT(bsf)
WRAP_INT(bsr)
WRAP_INT(lzcnt)
WRAP_INT(tzcnt)
WRAP_INT(popcnt)
WRAP_INT(cmov)
WRAP_INT(pclmulqdq)
WRAP_INT(aesenc)
WRAP_INT(rep_movsb)

typedef uint64_t (*kfn)(uint64_t, uint64_t);

static const struct { const char *name; kfn fn; } OPS[] = {
    /* Originally measured */
    {"divq", w_divq}, {"mulq", w_mulq}, {"idivq", w_idivq},
    {"divss", w_divss}, {"divsd", w_divsd},
    {"mulss", w_mulss}, {"addss", w_addss}, {"sqrtss", w_sqrtss},
    {"mulss_denorm", w_mulss_denorm}, {"addss_denorm", w_addss_denorm},
    /* Newly added: missing FP scalar/double */
    {"mulsd", w_mulsd}, {"addsd", w_addsd},
    {"subss", w_subss}, {"subsd", w_subsd},
    {"sqrtsd", w_sqrtsd},
    {"mulsd_denorm", w_mulsd_denorm}, {"addsd_denorm", w_addsd_denorm},
    /* Packed FP */
    {"divps", w_divps}, {"divpd", w_divpd},
    {"sqrtps", w_sqrtps}, {"sqrtpd", w_sqrtpd},
    /* AVX scalar */
    {"vdivss", w_vdivss}, {"vdivsd", w_vdivsd},
    {"vmulss", w_vmulss}, {"vsqrtss", w_vsqrtss},
    /* FMA */
    {"vfmadd231ss", w_vfmadd231ss}, {"vfmadd231sd", w_vfmadd231sd},
    /* False-negative candidates: NOT currently in the analyzer rule set */
    {"bsf", w_bsf}, {"bsr", w_bsr},
    {"lzcnt", w_lzcnt}, {"tzcnt", w_tzcnt},
    {"popcnt", w_popcnt}, {"cmov", w_cmov},
    {"pclmulqdq", w_pclmulqdq}, {"aesenc", w_aesenc},
    {"rep_movsb", w_rep_movsb},
    {0, 0}
};

static double run_one(int op_idx, int varying, double *cv_out) {
    uint64_t a_in[NUM_PAIRS], b_in[NUM_PAIRS];
    uint64_t fix_a = prng(), fix_b = prng();
    for (int i = 0; i < NUM_PAIRS; i++) {
        a_in[i] = varying ? prng() : fix_a;
        uint64_t b = varying ? prng() : fix_b;
        b_in[i] = b ? b : 1;   /* avoid divide-by-zero for INT div */
    }

    kfn fn = OPS[op_idx].fn;
    double medians[NUM_PAIRS];
    for (int i = 0; i < NUM_PAIRS; i++) {
        uint64_t samples[REPS];
        for (int r = 0; r < REPS; r++) samples[r] = fn(a_in[i], b_in[i]);
        medians[i] = (double)median_u64(samples, REPS) / (double)INNER;
    }
    *cv_out = cv(medians, NUM_PAIRS);
    double s = 0; for (int i = 0; i < NUM_PAIRS; i++) s += medians[i];
    return s / NUM_PAIRS;
}

int main(int argc, char **argv) {
    /* Pin to CPU 0 to reduce scheduling jitter. */
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <op>\n  available:", argv[0]);
        for (int i = 0; OPS[i].name; i++) fprintf(stderr, " %s", OPS[i].name);
        fprintf(stderr, "\n");
        return 1;
    }
    int op_idx = -1;
    for (int i = 0; OPS[i].name; i++) {
        if (strcmp(argv[1], OPS[i].name) == 0) { op_idx = i; break; }
    }
    if (op_idx < 0) { fprintf(stderr, "unknown op: %s\n", argv[1]); return 1; }

    /* Warm-up. */
    for (int i = 0; i < 5; i++) (void)bench_mulq(prng(), prng());

    double cv_var = 0, cv_fix = 0;
    double mean_var = run_one(op_idx, 1, &cv_var);
    double mean_fix = run_one(op_idx, 0, &cv_fix);

    int variable_time = (cv_var > 5.0 * cv_fix) && (cv_var > 0.05);

    printf("{\"op\":\"%s\","
           "\"mean_cycles_varying\":%.3f,"
           "\"mean_cycles_fixed\":%.3f,"
           "\"cv_varying\":%.6f,"
           "\"cv_fixed\":%.6f,"
           "\"variable_time\":%s}\n",
           OPS[op_idx].name, mean_var, mean_fix, cv_var, cv_fix,
           variable_time ? "true" : "false");
    return 0;
}
