/* TP on modern-arm: CT_DOITM_ENABLED is an x86 mitigation; on ARM it is
 * meaningless. The analyzer must NOT suppress SDIV here. */

#define CT_DOITM_ENABLED 1   /* irrelevant on ARM */

int reduce(int r, int secret_q) {
    return r / secret_q;
}
