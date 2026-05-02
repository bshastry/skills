/* TP: real-world ML-DSA decompose pattern. Multiple DIVs, modulo, and
 * branches on secret. The analyzer must flag the integer DIVs. */

#define Q 8380417

void decompose(int r, int gamma2, int *r1_out, int *r0_out) {
    int two_g = 2 * gamma2;
    int r1 = r / two_g;
    int r0 = r % two_g;
    if (r0 > gamma2) { r0 -= two_g; r1 += 1; }
    *r1_out = r1; *r0_out = r0;
}

int use_hint(int r, int hint, int gamma2) {
    int r1, r0;
    decompose(r, gamma2, &r1, &r0);
    if (hint == 0) return r1;
    if (r0 > 0) return (r1 + 1) % ((Q - 1) / (2 * gamma2) + 1);
    return (r1 - 1) % ((Q - 1) / (2 * gamma2) + 1);
}
