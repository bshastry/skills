/* TP across all profiles: floating-point arithmetic on secret values without
 * FTZ/DAZ enabled. Denormal operands cause variable-time execution.
 * Current analyzer MISSES this (FN). */

float secret_score(float secret_x, float coef) {
    /* No _MM_SET_FLUSH_ZERO_MODE / DAZ enabled in this TU.
     * Secret-derived float; ADDSS on denormal -> variable timing. */
    return secret_x * coef + 1.0f;
}
