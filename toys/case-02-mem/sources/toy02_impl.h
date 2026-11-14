/* toy02_impl.h — case-02: void-shaped parent with an out-parameter.
 *
 * M2's second shape (WHITEPAPERS FR-9): functions whose *effect* is memory
 * they write, not a return value. The parent fills a caller-provided buffer
 * with a keystream derived from two leaves; validation is a byte-exact
 * memory diff (m2_memdiff.c) of the candidate's writes vs the original's.
 *
 *   fill_keystream ──< fnv1a           (counter re-keyed per block)
 *                   └─< digit_sum_u32  (parity byte appended)
 *
 * Same determinism rules as case-01: no globals, no time, no RNG.
 */
#ifndef TOY02_IMPL_H
#define TOY02_IMPL_H

#include <stddef.h>
#include <stdint.h>

#include "toy01_impl.h" /* the validated M1 leaves */

/* Writes `len` keystream bytes to out[0..len). For each 4-byte block i:
 *   block = fnv1a(seed_bytes || counter, 5)
 * where counter is the little-endian block index. Then out[len] = parity
 * (sum of digit_sum over all bytes, mod 2)... kept simple: out[0] is the
 * digit_sum of the first keystream byte. Caller guarantees capacity
 * len + 1. Returns nothing (void) — the effect IS the buffer.
 */
__attribute__((noinline))
void fill_keystream(const uint8_t *seed, size_t seed_len,
                    uint8_t *out, size_t len) {
    uint8_t buf[8];
    size_t n = seed_len < 7 ? seed_len : 7;
    for (size_t i = 0; i < n; i++) buf[i] = seed[i];
    for (size_t block = 0; block * 4 < len; block++) {
        buf[n] = (uint8_t)(block & 0xFF);
        buf[n + 1] = (uint8_t)((block >> 8) & 0xFF);
        uint32_t k = fnv1a(buf, n + 2);
        for (int j = 0; j < 4 && block * 4 + (size_t)j < len; j++) {
            out[block * 4 + j] = (uint8_t)(k >> (8 * j));
        }
    }
    out[len] = (uint8_t)(digit_sum_u32(out[0]) & 1);
}

#endif /* TOY02_IMPL_H */
