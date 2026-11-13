/* toy01.c — the binary: includes the impl header and adds a file-reading
 * main so the program is runnable on real input (record-replay needs a driver
 * that feeds valid inputs to the functions).
 *
 * Build (see build.sh): clang -O1, noinline, x86-64, stripped. The unstripped
 * build is used to extract the ground-truth call graph (ground_truth/);
 * addresses are identical after strip --strip-all (only the symbol table is
 * removed).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "toy01_impl.h"

/* Reads the file named in argv[1] and prints its checksum as 8 hex digits.
 *
 * Testability hook (not part of the program under reconstruction): with
 * FUZ_HOLD set, the process parks immediately after loading so a tracer can
 * attach and drive the functions directly (record-replay, FR-3; hooking, FR-7).
 * Normal operation (no env var) is unchanged.
 */
int main(int argc, char **argv) {
    if (getenv("FUZ_HOLD") != NULL) {
        for (;;) pause(); /* park until killed by the tracer */
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }
    uint8_t buf[4096];
    size_t total = 0;
    size_t n;
    uint32_t acc[2] = {0, 0};
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        acc[0] ^= checksum_block(buf, n);
        acc[1] += (uint32_t)n;
        total += n;
    }
    int err = ferror(f);
    fclose(f);
    if (err) {
        fprintf(stderr, "fread error\n");
        return 1;
    }
    printf("%08x %08x %zu\n", acc[0], acc[1], total);
    return 0;
}
