/* TN: pure arithmetic, no DIV/MUL/branch on secret. Should produce no alarms
 * on any profile. Tests for spurious detections. */

unsigned add_const(unsigned secret) {
    return secret ^ 0xdeadbeefU;
}
