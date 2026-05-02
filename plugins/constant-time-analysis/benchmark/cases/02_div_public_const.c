/* TN: division by public compile-time constant. Developer asserts via
 * CT_PUBLIC_DIVISOR that the divisor is public; analyzer suppresses INT_DIV. */

#define CT_PUBLIC_DIVISOR 1
#define BLOCK_SIZE 16

unsigned num_blocks(unsigned length) {
    /* length is public input size, not secret */
    return length / BLOCK_SIZE;
}
