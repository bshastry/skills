/* TN: division between two public quantities (memory total and page size).
 * Developer asserts public-divisor with CT_PUBLIC_DIVISOR. */

#define CT_PUBLIC_DIVISOR 1

unsigned long pages_required(unsigned long total_bytes, unsigned long page_size) {
    /* Both args are public: total memory size and page size. */
    return (total_bytes + page_size - 1) / page_size;
}
