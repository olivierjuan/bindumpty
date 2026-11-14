/* spike_s2.c — M0 spike S2 (FR-7): redirect a function to a reimplementation
 * with funchook, from a libFuzzer harness.
 *
 * Topology: `original_add` lives in s2_original.so (a loaded module — the M2
 * shape, where the stripped binary is loaded and its functions are redirected).
 * `candidate_add` is the "reimplementation", deliberately wrong for a==0xff so
 * the fuzzer has a real counterexample to find.
 *
 * funchook mechanics (verified against funchook's own suite):
 *   g_entry = dlsym(so, "original_add")        // the symbol entry point
 *   g_orig  = g_entry
 *   funchook_prepare(h, &g_orig, candidate)    // *g_orig <- TRAMPOLINE (true
 *                                              //   original); records g_entry
 *   funchook_install(h, 0)                     // patches g_entry to jump to
 *                                              //   candidate (the reimpl.)
 * After install:
 *   g_entry(a,b)  ->  runs candidate_add  (the reimplementation)
 *   g_orig (a,b)  ->  runs the true original (via the trampoline)
 * The harness calls both and diffs them. A mismatch is a DIVERGENCE (a
 * counterexample). This is exactly the M2 hybrid-harness mechanics.
 *
 * Discriminating signal: without the hook, g_entry == g_orig (both run the
 * original) and no divergence is ever found; with it, the fuzzer finds a==0xff.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "funchook.h"

/* "Reimplementation" the LLM would produce.
 *  - default (buggy): wrong when a==0xff  -> the fuzzer MUST find a divergence.
 *  - -DS2_CORRECT:    identical to the original -> expect ZERO divergences
 *    (the "trusted" path / clean negative control). */
__attribute__((noinline))
static int candidate_add(int a, int b) {
#ifndef S2_CORRECT
    if (a == 0xff) return a - b; /* the bug the fuzzer must find */
#endif
    return a + b;
}

static void *g_handle;
static int (*g_entry)(int, int); /* symbol entry point -> reimplementation after install */
static int (*g_orig)(int, int);  /* trampoline -> true original */

static void die(const char *m) { fprintf(stderr, "S2: %s\n", m); exit(2); }

static void install_hook(void) {
    g_handle = dlopen("./s2_original.so", RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) die(dlerror());
    g_entry = dlsym(g_handle, "original_add");
    if (!g_entry) die("dlsym original_add");
    g_orig = g_entry; /* same address until funchook rewrites it */

    funchook_t *hook = funchook_create();
    if (!hook) die("funchook_create");
    if (funchook_prepare(hook, (void **)&g_orig, (void *)candidate_add) != 0)
        die(funchook_error_message(hook));
    if (funchook_install(hook, 0) != 0) die(funchook_error_message(hook));
    fprintf(stderr, "S2: hook installed  original_add (s2_original.so) -> candidate_add\n");
}

__attribute__((constructor))
static void s2_ctor(void) { install_hook(); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int a = size > 0 ? (int)data[0] : 0;
    int b = size > 1 ? (int)data[1] : 0;
    int via_reimpl = g_entry(a, b); /* patched entry point -> candidate_add */
    int via_orig   = g_orig(a, b);  /* trampoline -> true original          */
    if (via_reimpl != via_orig) {
        fprintf(stderr, "S2 DIVERGENCE: original_add(%d,%d) reimpl=%d original=%d\n",
                a, b, via_reimpl, via_orig);
        return 1;
    }
    return 0;
}
