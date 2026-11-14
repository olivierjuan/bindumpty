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
