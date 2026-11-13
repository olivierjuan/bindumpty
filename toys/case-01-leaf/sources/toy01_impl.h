/* toy01_impl.h — the functions under reconstruction, shared by the binary
 * (toy01.c, which adds main) and the test suite (test_suite/test_toy01.c).
 *
 * Shape: one parent (checksum_block) over two pure deterministic leaves
 * (fnv1a, digit_sum_u32). No globals, no time, no RNG, no containers — fully
 * deterministic by construction (FR-16 not even needed).
 *
 *   checksum_block ──< fnv1a          (two call sites)
 *                  └─< digit_sum_u32
 */
#ifndef TOY01_IMPL_H
#define TOY01_IMPL_H

#include <stddef.h>
#include <stdint.h>

/* Leaf 1: FNV-1a 32-bit. Pure, loop with running state — the M1 CEGIS target.
 * Test vectors: see test_suite/test_toy01.c.
 */
__attribute__((noinline))
uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u; /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= 16777619u;       /* FNV prime */
    }
    return h;
}

/* Leaf 2: sum of base-10 digits. Pure, trivially verifiable.
 * digit_sum_u32(0) == 0 by convention.
 */
__attribute__((noinline))
int digit_sum_u32(uint32_t x) {
    int s = 0;
    do {
        s += (int)(x % 10u);
        x /= 10u;
    } while (x != 0u);
    return s;
}

/* Parent: two fnv1a calls (halved input) combined with a digit-sum fold.
 * M2 target: exercises hybrid harness (validated leaves) + memory-state diff.
 */
__attribute__((noinline))
uint32_t checksum_block(const uint8_t *data, size_t len) {
    size_t half = len / 2;
    uint32_t h1 = fnv1a(data, half);
    uint32_t h2 = fnv1a(data + half, len - half);
    uint32_t mix = h1 ^ (h2 * 2654435761u); /* Knuth 32-bit hash constant */
    return mix ^ (uint32_t)digit_sum_u32(mix);
}

#endif /* TOY01_IMPL_H */
