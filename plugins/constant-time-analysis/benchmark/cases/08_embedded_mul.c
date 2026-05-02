/* TP on embedded only (Cortex-M0/M3 have variable-time MUL).
 * On x86/arm64/modern-arm this is TN. */

unsigned mul_secret(unsigned a, unsigned secret_b) {
    return a * secret_b;  /* MUL — variable-time on Cortex-M0/M3 */
}
