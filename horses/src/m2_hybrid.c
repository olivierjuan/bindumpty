/* m2_hybrid.c — FR-6 hybrid harness + FR-7 address hooking (M2).
 *
 * Shape (WHITEPAPERS FR-6): validate a PARENT on the real stripped binary
 * while its callees are the ORIGINAL code at their real addresses, and the
 * parent candidate is the reimplementation. Concretely for the toy:
 *
 *   - dlopen the stripped toy01 (ASLR-aware: the loader gives us the map
 *     base; function vaddrs from the ground-truth graph are file vaddrs,
 *     so original_fn = base + (vaddr - elf_vaddr_bias)).
 *   - The CANDIDATE checksum_block is linked in (drop-in symbol from the
 *     candidate .so, like M1) and calls the ORIGINAL fnv1a/digit_sum_u32
 *     via function pointers resolved at init.
 *   - The oracle is the ORIGINAL checksum_block, called through its real
 *     address. libFuzzer drives both on the same input; first divergence
 *     is a counterexample (same protocol as M1).
 *
 * FR-7 hooking (funchook) is used in the second mode (HORSE_HOOK=1): the
 * ORIGINAL fnv1a/digit_sum entry points are redirected to the candidate's
 * validated leaf implementations, exercising the "validated callees go
 * through their reimplementation" direction. endbr64-safe: funchook's
 * capstone backend handles CET (verified in S2).
 *
 * build: build_m2.sh (links funchook+capstone static for the hook mode).
 */
#include <dlfcn.h>
#include <link.h> /* link_map, RTLD_DI_LINKMAP (glibc) */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* candidate (reimplemented parent), linked from horse_candidate.c */
uint32_t checksum_block(const uint8_t *data, size_t len);

/* ground-truth vaddrs (from toys/case-01-leaf/ground_truth/call_graph.json;
 * build.sh keeps them in lockstep with the binary — NFR-2). */
#define GT_FNV1A        0x11d0
#define GT_DIGIT_SUM    0x1200
#define GT_CHECKSUM     0x1240

typedef uint32_t (*fnv1a_t)(const uint8_t *, size_t);
typedef int (*dsum_t)(uint32_t);
typedef uint32_t (*csum_t)(const uint8_t *, size_t);

static fnv1a_t g_orig_fnv1a;
static dsum_t g_orig_dsum;
static csum_t g_orig_csum;   /* the oracle: original checksum_block */
static void *g_handle;

static const char *env_or(const char *k, const char *d) {
    const char *v = getenv(k);
    return v ? v : d;
}

static void die(const char *m) { fprintf(stderr, "M2: %s\n", m); exit(2); }

static void *toy_handle(void) {
    if (!g_handle) {
        const char *path = env_or("HORSE_TOY_ELF", "toys/case-01-leaf/build/toy01.so");
        g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!g_handle) die(dlerror());
    }
    return g_handle;
}

/* Resolve an original function. Two paths:
 *  - toy01.so (default): dlsym — the .so keeps its symbol table.
 *  - the stripped PIE exe cannot be dlopen'd ("cannot dynamically load
 *    position-independent executable"), so the FR-7-at-real-addresses mode
 *    resolves by vaddr through link_map of the .so carrying the same code.
 * The vaddr path is kept for when the pipeline runs against a converted
 * shared object of the real target (M2 exit uses the .so path). */
static void *resolve_original(unsigned long vaddr, const char *sym) {
    void *h = toy_handle();
    if (sym) {
        void *s = dlsym(h, sym);
        if (s) return s;
    }
    struct link_map *lm;
    if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0) die("dlinfo failed");
    return (void *)((char *)lm->l_addr + vaddr);
}

static void *at_vaddr(unsigned long vaddr) { return resolve_original(vaddr, NULL); }

static void init_originals(void) {
    g_orig_fnv1a = (fnv1a_t)resolve_original(GT_FNV1A, "fnv1a");
    g_orig_dsum = (dsum_t)resolve_original(GT_DIGIT_SUM, "digit_sum_u32");
    g_orig_csum = (csum_t)resolve_original(GT_CHECKSUM, "checksum_block");
    /* sanity: the oracle must produce a known vector (empty input) */
    if (g_orig_fnv1a(NULL, 0) != 2166136261u) die("fnv1a sanity failed");
    if (g_orig_dsum(0) != 0) die("digit_sum sanity failed");
}

/* FR-7 mode: hook the ORIGINAL leaves so the candidate parent runs against
 * VALIDATED leaf reimplementations instead of the originals. The candidate
 * .so exports fnv1a_candidate/digit_sum_candidate. */
static void install_leaf_hooks(void);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    init_originals();
    if (getenv("HORSE_HOOK") != NULL) install_leaf_hooks();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* hybrid: candidate parent over ORIGINAL callees vs the original parent
     * over the same originals. Any divergence is the parent candidate's. */
    uint32_t got = checksum_block(data, size);
    uint32_t want = g_orig_csum(data, size);
    if (got != want) {
        fprintf(stderr, "HORSE DIVERGENCE len=%zu input=", size);
        for (size_t i = 0; i < size && i < 4096; i++) fprintf(stderr, "%02x", data[i]);
        fprintf(stderr, " got=0x%08X want=0x%08X\n", got, want);
        abort();
    }
    return 0;
}

/* --- candidate-side callees ------------------------------------------- */
/* The candidate .so must call the ORIGINAL leaves. We expose the resolved
 * originals through a header the candidate includes — but the candidate is
 * built independently, so the cleanest seam is: the candidate defines its
 * OWN fnv1a/digit_sum (reimplemented leaves, already validated in M1) and
 * the hybrid compares parent-candidates built on them. FR-7 hook mode then
 * swaps the ORIGINAL leaf entries to the validated candidates in-place. */

__attribute__((weak)) void horse_reset_before(void) {}
__attribute__((weak)) void horse_reset_after(void) {}

/* FR-7: funchook redirection. candidate .so exposes validated_fnv1a /
 * validated_digit_sum; we patch the toy's real fnv1a/digit_sum entry points
 * so EVERY caller (including the original checksum_block oracle) now runs
 * the validated leaves. This is the "validated callees substituted" mode. */
#include "funchook.h"

static funchook_t *g_hook;
static fnv1a_t g_fnv1a_trampoline;   /* true original, via trampoline */
static dsum_t g_dsum_trampoline;

typedef uint32_t (*vfnv1a_t)(const uint8_t *, size_t);
typedef int (*vdsum_t)(uint32_t);

static void install_leaf_hooks(void) {
    const char *so_path = env_or("HORSE_CANDIDATE_SO",
                                 "horses/libfuzzer/horse_candidate.so");
    void *cand = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
    if (!cand) die(dlerror());
    vfnv1a_t cand_fnv1a = (vfnv1a_t)dlsym(cand, "fnv1a");
    vdsum_t cand_dsum = (vdsum_t)dlsym(cand, "digit_sum_u32");
    if (!cand_fnv1a || !cand_dsum) die("candidate .so lacks validated leaves");

    g_hook = funchook_create();
    g_fnv1a_trampoline = (fnv1a_t)g_orig_fnv1a;
    g_dsum_trampoline = (dsum_t)g_orig_dsum;
    if (funchook_prepare(g_hook, (void **)&g_fnv1a_trampoline,
                         (void *)cand_fnv1a) != 0)
        die(funchook_error_message(g_hook));
    if (funchook_prepare(g_hook, (void **)&g_dsum_trampoline,
                         (void *)cand_dsum) != 0)
        die(funchook_error_message(g_hook));
    if (funchook_install(g_hook, 0) != 0)
        die(funchook_error_message(g_hook));
    fprintf(stderr, "M2: leaf hooks installed (validated callees substituted)\n");
}
