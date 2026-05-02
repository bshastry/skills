/* TP on modern-arm even with DIT: SDIV is NOT covered by DIT on ARMv8.4.
 * The skill must keep flagging integer DIV on ARM modern profile. */

#define CT_ARM_DIT_ENABLED 1

int reduce(int a, int secret_q) {
    return a / secret_q;  /* SDIV — NOT protected by DIT */
}
