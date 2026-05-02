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

/* ---------- driver ---------- */

typedef struct { const char *name; int kind; } op_t;

enum { OP_INT2, OP_FP2, OP_FP1, OP_INT_DENORM };

static const struct {
    const char *name;
    uint64_t (*intfn)(uint64_t, uint64_t);
    uint64_t (*fpfn)(float, float);
    uint64_t (*fpfn1)(float);
    uint64_t (*fpfnd)(double, double);
    uint64_t (*denormfn)(uint32_t, uint32_t);
    int    is_int;
    int    is_double;
    int    is_unary;
    int    denorm;
} OPS[] = {
    { .name="divq",         .intfn=bench_divq,                                           .is_int=1 },
    { .name="mulq",         .intfn=bench_mulq,                                           .is_int=1 },
    { .name="idivq",        .intfn=(uint64_t(*)(uint64_t,uint64_t))bench_idivq,          .is_int=1 },
    { .name="divss",        .fpfn=bench_divss },
    { .name="divsd",        .fpfnd=bench_divsd,                                          .is_double=1 },
    { .name="mulss",        .fpfn=bench_mulss },
    { .name="addss",        .fpfn=bench_addss },
    { .name="sqrtss",       .fpfn1=bench_sqrtss,                                         .is_unary=1 },
    { .name="mulss_denorm", .denormfn=bench_mulss_denorm,                                .denorm=1 },
    { .name="addss_denorm", .denormfn=bench_addss_denorm,                                .denorm=1 },
    { .name=0 }
};

static double run_one(int op_idx, int varying, double *cv_out) {
    /* Generate NUM_PAIRS input pairs. If varying=0, all pairs are identical. */
    uint64_t a_int[NUM_PAIRS], b_int[NUM_PAIRS];
    float    a_f[NUM_PAIRS],   b_f[NUM_PAIRS];
    double   a_d[NUM_PAIRS],   b_d[NUM_PAIRS];
    uint32_t a_b[NUM_PAIRS],   b_b[NUM_PAIRS];

    uint64_t fix_a = prng(), fix_b = prng();
    for (int i = 0; i < NUM_PAIRS; i++) {
        uint64_t ra = varying ? prng() : fix_a;
        uint64_t rb = varying ? prng() : fix_b;
        a_int[i] = ra; b_int[i] = rb ? rb : 1;
        /* Floats: random in [1, 1e6] for normal, denormal handled separately. */
        uint32_t ua = (uint32_t)ra, ub = (uint32_t)rb;
        ua = 0x3f800000U | (ua & 0x007fffffU);  /* in [1,2) */
        ub = 0x3f800000U | (ub & 0x007fffffU);
        memcpy(&a_f[i], &ua, 4);  memcpy(&b_f[i], &ub, 4);
        uint64_t da = 0x3ff0000000000000ULL | (ra & 0x000fffffffffffffULL);
        uint64_t db = 0x3ff0000000000000ULL | (rb & 0x000fffffffffffffULL);
        memcpy(&a_d[i], &da, 8); memcpy(&b_d[i], &db, 8);
        a_b[i] = (uint32_t)ra; b_b[i] = (uint32_t)rb;
    }

    double medians[NUM_PAIRS];
    for (int i = 0; i < NUM_PAIRS; i++) {
        uint64_t samples[REPS];
        for (int r = 0; r < REPS; r++) {
            uint64_t cyc;
            if (OPS[op_idx].denorm) {
                cyc = OPS[op_idx].denormfn(a_b[i], b_b[i]);
            } else if (OPS[op_idx].is_int) {
                cyc = OPS[op_idx].intfn(a_int[i], b_int[i]);
            } else if (OPS[op_idx].is_unary) {
                cyc = OPS[op_idx].fpfn1(a_f[i]);
            } else if (OPS[op_idx].is_double) {
                cyc = OPS[op_idx].fpfnd(a_d[i], b_d[i]);
            } else {
                cyc = OPS[op_idx].fpfn(a_f[i], b_f[i]);
            }
            samples[r] = cyc;
        }
        medians[i] = (double)median_u64(samples, REPS) / (double)INNER;
    }
    *cv_out = cv(medians, NUM_PAIRS);
    /* return mean cycles/op */
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
