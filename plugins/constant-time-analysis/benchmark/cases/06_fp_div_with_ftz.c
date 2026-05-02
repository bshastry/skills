/* TP across all profiles: FP division is variable-time even with FTZ enabled.
 * This catches the over-suppression bug if the FTZ logic is too aggressive. */

#define CT_FTZ_DAZ 1

float secret_ratio(float secret_a, float secret_b) {
    return secret_a / secret_b;  /* DIVSS — still variable even with FTZ */
}
