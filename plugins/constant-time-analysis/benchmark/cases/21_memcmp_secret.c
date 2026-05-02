/* TP: memcmp on secret bytes early-exits and is timing-leaking. The
 * analyzer should detect the call site. */

int memcmp(const void *, const void *, unsigned long);

int verify_tag(const unsigned char *tag, const unsigned char *expected, unsigned long n) {
    return memcmp(tag, expected, n) == 0;
}
