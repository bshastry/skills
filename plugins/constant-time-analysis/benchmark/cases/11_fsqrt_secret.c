/* TP across all profiles: FSQRT on secret is variable-time on all known CPUs,
 * including FTZ-enabled and DOITM-enabled configurations.
 * (DOITM does cover SQRT on Ice Lake, but only some variants — keep flagging
 *  conservatively and let the user prove their CPU+config OK in review.) */

float __builtin_sqrtf(float);   /* GCC/Clang built-in */

float secret_norm(float secret_x) {
    return __builtin_sqrtf(secret_x);
}
