/* TP on legacy, TN on modern-x86 (with DOITM): explicit DOITM enable annotation.
 * The skill should recognise the CT_DOITM_ENABLED guard macro in source and
 * suppress DIV alarms on x86 modern profile. */

/* Sentinel macro the analyzer scans for: indicates DOITM is enabled. */
#define CT_DOITM_ENABLED 1

void poly_reduce(int r, int secret_q, int *out) {
    *out = r / secret_q;  /* DIV — OK on Ice Lake+ with DOITM enabled */
}
