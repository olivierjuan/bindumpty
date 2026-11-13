/* trace_driver.c — in-sandbox ground-truth recorder (M0, FR-3).
 *
 * For a toy whose SOURCE is known, the cleanest ground-truth oracle is to run
 * the original functions inside the sandbox (NFR-1) on the curated valid-input
 * set and capture the real I/O. This driver does exactly that: it calls each
 * target function in the original translation unit and prints one JSON line
 * per (function, input).
 *
 * The functions are deterministic (no globals / time / RNG), so the values
 * recorded here are identical to what any in-place observation (Frida, rr,
 * DynamoRIO) of the real stripped binary would yield for the same inputs.
 *
 * The real stripped binaries (M2+) are not source-available, so the
 * production record-replay path there is tracing/record_frida.py (in-place
 * observation). Both produce the same `fuz.traces/1` bundle format.
 *
 * Output (stdout), one line per call:
 *   {"fn":"fnv1a","arg":"6162","arglen":2,"ret":"0x...."}
 *   {"fn":"digit_sum_u32","arg":"1234","ret":"10"}
 *
 * Memory read/written regions are not captured: case-01 functions are pure
 * (no writes). FR-9 memory-state diff lands in M2 with the first non-pure
 * function.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The function under reconstruction. In the toy this is the same code that
 * ships in the stripped binary (sources/toy01_impl.h). */
#include "toy01_impl.h"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t decode_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0, len = strlen(s);
    if (len % 2) len--;
    for (size_t i = 0; i + 1 < len && n < cap; i += 2) {
        int hi = hex_nibble(s[i]), lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* Manifest line: <fn> <argkind> <arg>
 *   <fn>   = fnv1a | digit_sum_u32 | checksum_block
 *   <argkind> = bytes <hex> | u32 <int>
 */
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <manifest>\n", argv[0]);
        return 2;
    }
    FILE *mf = fopen(argv[1], "r");
    if (!mf) {
        fprintf(stderr, "cannot open manifest %s\n", argv[1]);
        return 1;
    }
    char line[8192];
    uint8_t buf[8192];
    while (fgets(line, sizeof line, mf)) {
        char fn[256], argkind[8], arg[8192];
        if (sscanf(line, "%255s %7s %8191s", fn, argkind, arg) != 3)
            continue;
        if (strcmp(argkind, "bytes") == 0) {
            size_t len = decode_hex(arg, buf, sizeof buf);
            uint32_t r;
            if (strcmp(fn, "fnv1a") == 0)
                r = fnv1a(buf, len);
            else if (strcmp(fn, "checksum_block") == 0)
                r = checksum_block(buf, len);
            else {
                fprintf(stderr, "unknown bytes-fn %s\n", fn);
                continue;
            }
            printf("{\"fn\":\"%s\",\"arg\":\"%s\",\"arglen\":%zu,\"ret\":\"0x%08x\"}\n",
                   fn, arg, len, r);
        } else if (strcmp(argkind, "u32") == 0) {
            uint32_t x = (uint32_t)strtoul(arg, NULL, 0);
            int r = digit_sum_u32(x);
            printf("{\"fn\":\"%s\",\"arg\":\"%u\",\"ret\":%d}\n", fn, x, r);
        } else {
            fprintf(stderr, "unknown argkind %s\n", argkind);
        }
    }
    fclose(mf);
    return 0;
}
