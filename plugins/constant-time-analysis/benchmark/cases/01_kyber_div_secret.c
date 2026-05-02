/* TP across all profiles: division by secret-derived value (KyberSlash pattern).
 * Expected: ERROR-level violation in `decompose`. */

void decompose(int r, int gamma2_secret, int *r1) {
    /* gamma2_secret comes from a secret-derived parameter set */
    *r1 = r / gamma2_secret;
}
