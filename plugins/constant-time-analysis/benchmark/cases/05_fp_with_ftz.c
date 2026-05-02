/* TN: same FP code but with FTZ/DAZ enabled. Sentinel macro CT_FTZ_DAZ
 * tells the analyzer denormals are flushed and FP add/sub/mul are CT.
 * Note: DIV/SQRT remain variable-time even with FTZ — only flag those. */

#define CT_FTZ_DAZ 1   /* FTZ + DAZ enabled at function entry */

float secret_score(float secret_x, float coef) {
    return secret_x * coef + 1.0f;  /* MULSS/ADDSS — CT under FTZ */
}
