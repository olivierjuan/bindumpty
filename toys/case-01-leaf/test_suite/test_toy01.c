/* test_toy01.c — the program's own test suite (toys/README convention).
 *
 * The recomposed binary (original functions replaced by reimplementations)
 * must pass this suite — that is the global acceptance criterion for the toy.
 *
 * Vectors:
 *  - fnv1a: published FNV-1a 32-bit spec test vectors (independent of the
 *    reference build).
 *  - digit_sum_u32: hand-computed.
 *  - checksum_block (the parent): computed from the reference build
 *    (sources/toy01_impl.h) — this is the known-source ground truth.
 */
#include <stdint.h>
#include <stdio.h>

#include "../sources/toy01_impl.h"

static int failures = 0;

#define CHECK_EQ(actual, expected, name)                                      \
    do {                                                                      \
        unsigned long long a_ = (unsigned long long)(actual);                 \
        unsigned long long e_ = (unsigned long long)(expected);               \
        if (a_ != e_) {                                                       \
            fprintf(stderr, "FAIL %s: got 0x%llx expected 0x%llx\n", name,   \
                    a_, e_);                                                  \
            failures++;                                                       \
        } else {                                                              \
            printf("ok %s\n", name);                                          \
        }                                                                     \
    } while (0)

int main(void) {
    /* --- fnv1a: FNV-1a 32-bit test vectors. ""/a/foobar are the canonical
     * spec values (isthe.com/chongo/tech/comp/fnv); aa/aaa verified against
     * an independent Python reference. */
    CHECK_EQ(fnv1a((const uint8_t *)"", 0), 0x811C9DC5u, "fnv1a(empty)");
    CHECK_EQ(fnv1a((const uint8_t *)"a", 1), 0xE40C292Cu, "fnv1a(a)");
    CHECK_EQ(fnv1a((const uint8_t *)"aa", 2), 0x4C250437u, "fnv1a(aa)");
    CHECK_EQ(fnv1a((const uint8_t *)"aaa", 3), 0x3445D362u, "fnv1a(aaa)");
    CHECK_EQ(fnv1a((const uint8_t *)"foobar", 6), 0xBF9CF968u, "fnv1a(foobar)");

    /* --- digit_sum_u32 --------------------------------------------------- */
    CHECK_EQ(digit_sum_u32(0), 0, "dsum(0)");
    CHECK_EQ(digit_sum_u32(7), 7, "dsum(7)");
    CHECK_EQ(digit_sum_u32(10), 1, "dsum(10)");
    CHECK_EQ(digit_sum_u32(1234), 10, "dsum(1234)");
    CHECK_EQ(digit_sum_u32(9999), 36, "dsum(9999)");
    /* 0xFFFFFFFF = 4294967295; digit sum = 4+2+9+4+9+6+7+2+9+5 = 57 */
    CHECK_EQ(digit_sum_u32(0xFFFFFFFFu), 57, "dsum(0xFFFFFFFF)");

    /* --- checksum_block (parent) — reference-build vectors -------------- */
    CHECK_EQ(checksum_block((const uint8_t *)"", 0), 0xC7B2AFD4u, "csum(empty)");
    CHECK_EQ(checksum_block((const uint8_t *)"ab", 2), 0x5743D15Cu, "csum(ab)");
    CHECK_EQ(checksum_block((const uint8_t *)"abc", 3), 0x9A8DCB48u, "csum(abc)");
    CHECK_EQ(checksum_block((const uint8_t *)"aabb", 4), 0x0CF377E9u, "csum(aabb)");
    {
        uint8_t data[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        CHECK_EQ(checksum_block(data, 16), 0x08E02E5Du, "csum(0..15)");
    }

    if (failures) {
        fprintf(stderr, "%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
