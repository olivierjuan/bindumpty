/* horse_original.c — the ORIGINAL functions, from the ground-truth source.
 *
 * M1 rule (FR-6): the oracle is the real original, not a re-typed reference.
 * We link the ground-truth source directly so the ELF the harness compares
 * against is byte-identical to the binary the traces were recorded on.
 * (fnv1a is pulled verbatim from toys/case-01-leaf/sources/toy01.c.)
 */
#include <stdint.h>
#include <stddef.h>

uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t hash = 2166136261u; /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)data[i];
        hash *= 16777619u; /* FNV prime */
    }
    return hash;
}

/* Leaf 2 (M2): sum of base-10 digits — verbatim from the ground-truth
 * source (toys/case-01-leaf/sources/toy01_impl.h). */
int digit_sum_u32(uint32_t x) {
    int s = 0;
    do {
        s += (int)(x % 10u);
        x /= 10u;
    } while (x != 0u);
    return s;
}

/* Parent (M2 oracle): checksum_block verbatim. */
uint32_t checksum_block(const uint8_t *data, size_t len) {
    size_t half = len / 2;
    uint32_t h1 = fnv1a(data, half);
    uint32_t h2 = fnv1a(data + half, len - half);
    uint32_t mix = h1 ^ (h2 * 2654435761u);
    return mix ^ (uint32_t)digit_sum_u32(mix);
}
