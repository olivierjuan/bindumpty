/* original.so — the "original" stripped-binary stand-in for S2 (FR-7).
 *
 * A small shared object holding the function we will hook. Using a .so makes
 * the hook target an exported symbol in a loaded module — the same topology as
 * M2, where the original stripped binary is loaded and its functions are
 * redirected to reimplementations. (A minimal main-executable target hit a
 * capstone 5.0.1 decoder edge-case in this environment; see NOTES.md.)
 */
__attribute__((noinline))
int original_add(int a, int b) { return a + b; }
