/* TP across all profiles: double-precision FP division on secret.
 * Catches DIVSD specifically (vs DIVSS in case 6). */

double secret_div(double secret_a, double secret_b) {
    return secret_a / secret_b;
}
