/* m1_harness.c — M1 differential harness (FR-6 base, FR-9 v0).
 *
 * DUT topology (NO hooks — hooks are M2/FR-7):
 *   - The ORIGINAL functions are linked directly from horse_original.c, which
 *     includes the ground-truth source unmodified (same ELF, same ABI).
 *   - The CANDIDATE is built as a SEPARATE shared library (horse_candidate.so)
 *     whose leaf function symbol-collides... no — cleaner: the candidate .so
 *     exposes the same symbol name; the harness dlopens it with RTLD_LOCAL
 *     and resolves the candidate's fnv1a by dlsym. The candidate .so is
 *     regenerable by a developer agent without touching the harness.
 *
 * libFuzzer drives LLVMFuzzerTestOneInput: every input is decoded as a byte
 * string and passed to BOTH implementations. First divergence is reported as
 * a reproducible counterexample (input hex + both results) and aborts the run
 * (exit non-zero) so the orchestrator (FR-15) can persist it.
 *
 * Anti-flake (NFR-2): fnv1a is pure; memory diff (FR-9) has nothing to
 * observe for a pure leaf, so return-value comparison is the full oracle
 * here. Global-state reset hooks (FR-16) exist for future stateful leaves.
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Original, linked from horse_original.c */
uint32_t fnv1a(const uint8_t *data, size_t len);

/* Candidate resolved from the .so */
typedef uint32_t (*cand_fn_t)(const uint8_t *, size_t);

static cand_fn_t g_cand;
static const char *g_so_path = NULL;

static const char *env_or(const char *k, const char *d) {
    const char *v = getenv(k);
    return v ? v : d;
}

static void init_candidate(void) {
    g_so_path = env_or("HORSE_CANDIDATE_SO", "horses/libfuzzer/horse_candidate.so");
    void *h = dlopen(g_so_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "HARNESS: dlopen(%s) failed: %s\n", g_so_path, dlerror());
        exit(2);
    }
    void *sym = dlsym(h, "fnv1a");
    if (!sym) {
        fprintf(stderr, "HARNESS: dlsym(fnv1a) in %s failed: %s\n", g_so_path, dlerror());
        exit(2);
    }
    g_cand = (cand_fn_t)sym;
}

/* FR-16: reset any global state so each input is independent. The fnv1a leaf
 * has none; future stateful leaves override these weak symbols. */
__attribute__((weak)) void horse_reset_before(void) {}
__attribute__((weak)) void horse_reset_after(void) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    horse_reset_before();
    uint32_t got = g_cand(data, size);
    uint32_t want = fnv1a(data, size);
    horse_reset_after();
    if (got != want) {
        /* Counterexample: hex-encoded input + both results. Deterministic,
         * replayable, persisted by the orchestrator (FR-15). */
        fprintf(stderr, "HORSE DIVERGENCE len=%zu input=", size);
        for (size_t i = 0; i < size && i < 4096; i++) fprintf(stderr, "%02x", data[i]);
        fprintf(stderr, " got=0x%08X want=0x%08X\n", got, want);
        abort(); /* hard stop so libFuzzer reports the failing input path */
    }
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    init_candidate();
    return 0;
}
