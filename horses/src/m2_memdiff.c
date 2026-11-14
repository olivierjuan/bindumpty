/* m2_memdiff.c — FR-9: memory state diff for void functions.
 *
 * The M2 exit needs void/pointer-out functions validated on *effects*, not
 * just return values. Mechanism: the harness snapshots a shadow buffer
 * before the call, lets the function write through the out-pointers, then
 * compares candidate-written bytes vs original-written bytes sector by
 * sector. First differing sector is the counterexample (with offset, both
 * byte runs).
 *
 * Used by the toy's void-shaped function (future case-03) and by any leaf
 * with an out-parameter. Kept as a library (call into your LLVMFuzzer*
 * driver), not its own fuzzer binary.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MEMDIFF_MAX_SECTORS 64
#define SECTOR 64

typedef struct {
    size_t len;
    uint8_t cand[MEMDIFF_MAX_SECTORS * SECTOR];
    uint8_t orig[MEMDIFF_MAX_SECTORS * SECTOR];
} memdiff_t;

void memdiff_init(memdiff_t *d, size_t len) {
    if (len > sizeof d->cand) len = sizeof d->cand;
    memset(d, 0, sizeof *d);
    d->len = len;
}

void memdiff_mark(memdiff_t *d, int who, void *base, const void *snapshot,
                  size_t n) {
    (void)base;
    if (n > d->len) n = d->len;
    memcpy(who == 0 ? d->cand : d->orig, snapshot, n);
}

int memdiff_compare(const memdiff_t *d, size_t *bad_off,
                    uint8_t *cand_byte, uint8_t *orig_byte) {
    for (size_t i = 0; i < d->len; i++) {
        if (d->cand[i] != d->orig[i]) {
            if (bad_off) *bad_off = i;
            if (cand_byte) *cand_byte = d->cand[i];
            if (orig_byte) *orig_byte = d->orig[i];
            return 1;
        }
    }
    return 0;
}

void memdiff_report(size_t off, uint8_t c, uint8_t o) {
    fprintf(stderr,
            "HORSE MEMDIFF at offset %zu: candidate=0x%02X original=0x%02X\n",
            off, c, o);
}
