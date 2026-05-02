/* TN across all profiles: XOR/AND/OR/SHIFT chain on secret. Should
 * produce zero alarms even though the function clearly handles secrets. */

unsigned mix(unsigned secret_a, unsigned secret_b) {
    unsigned t = secret_a ^ secret_b;
    t = (t << 7) | (t >> 25);
    t &= 0x0f0f0f0fu;
    return t;
}
