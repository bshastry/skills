/* FP: at -O0 the compiler emits IDIV with a *literal* immediate / register
 * loaded from a constant. Even if the dividend is secret, dividing by a
 * public compile-time constant on DOITM-capable CPUs is fine, and on legacy
 * CPUs it still leaks only the *quotient* timing — but the divisor is public.
 *
 * This case is HARD: the analyzer cannot tell secret-vs-public from asm
 * alone. We mark this as FP under modern-x86 (where DOITM is presumed) and
 * allow it to remain TP under legacy. */

#define MODULUS 8380417  /* public ML-DSA prime, compile-time constant */

int reduce_pub(int secret_a) {
    return secret_a % MODULUS;
}
