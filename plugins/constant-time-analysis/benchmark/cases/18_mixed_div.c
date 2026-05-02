/* TP: function performs a secret-divisor division alongside a public-const
 * one. Without CT_PUBLIC_DIVISOR (which would suppress BOTH), the analyzer
 * must flag at least one DIV. */

int compute(int r, int secret_q) {
    int a = r / 16;            /* public divisor — not the leak */
    int b = r / secret_q;      /* secret divisor — KyberSlash */
    return a + b;
}
