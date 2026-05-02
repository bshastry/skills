/* TN: constant-time selection via bit-masking. No DIV, no FP, no branches
 * on the secret. Should be silent across all profiles (no warnings). */

unsigned ct_select(unsigned a, unsigned b, unsigned secret_cond) {
    unsigned mask = -(unsigned)(secret_cond != 0);  /* CMOV via mask */
    return (a & mask) | (b & ~mask);
}
