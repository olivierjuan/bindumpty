/* dr_edges.cpp — bindumpty's DynamoRIO edge-pass client (RFC §5.2).
 *
 * Records every RESOLVED indirect call as a fuz.call-graph-delta/1 edge.
 *
 * This is a SEPARATE client from libdr_bindumpty.so on purpose: with
 * DynamoRIO 11.91, inserting clean calls before indirect calls while the
 * drwrap extension is loaded (even when it wraps nothing) hangs the
 * process — validated by bisection. The edge pass therefore runs in its
 * own process invocation with a raw-BB client: no drmgr, no drwrap, no
 * drreg — exactly the configuration proven to work.
 *
 * Runtime:
 *   drrun -c libdr_edges.so --out_dir /tmp/bindumpty_dr -- ./lpex2 model.mps
 * Output:
 *   indirect_edges.json  ({"caller_offset", "callee_offset",
 *                          "kind": "indirect_resolved", "call_count"})
 */
#include "dr_api.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

struct Edge {
    uint64_t call_site_rva = 0;
    uint64_t target_rva = 0;
    uint32_t hit_count = 0;
};

std::mutex g_edge_lock;
std::map<std::pair<uint64_t, uint64_t>, Edge *> g_edges;

app_pc g_module_base = nullptr;
app_pc g_module_end = nullptr;
std::string g_out_dir = "/tmp/bindumpty_dr";

inline uint64_t to_rva(app_pc pc) {
    return g_module_base ? (uint64_t)(pc - g_module_base) : (uint64_t)pc;
}

void on_indirect_call(app_pc call_site, app_pc target) {
    if (g_module_base == nullptr) return;
    if (target < g_module_base || target >= g_module_end) return;
    std::lock_guard<std::mutex> g(g_edge_lock);
    auto key = std::make_pair(to_rva(call_site), to_rva(target));
    Edge *&e = g_edges[key];
    if (e == nullptr) e = new Edge{key.first, key.second, 1};
    else e->hit_count++;
}

dr_emit_flags_t event_bb(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating) {
    app_pc pc = dr_fragment_app_pc(tag);
    if (g_module_base != nullptr &&
        (pc < g_module_base || pc >= g_module_end))
        return DR_EMIT_DEFAULT;

    for (instr_t *i = instrlist_first_app(bb); i != nullptr;
         i = instr_get_next_app(i)) {
        if (instr_is_call_indirect(i)) {
            dr_insert_clean_call(drcontext, bb, i, (void *)on_indirect_call,
                                 false, 2,
                                 OPND_CREATE_INTPTR(instr_get_app_pc(i)),
                                 instr_get_target(i));
        }
    }
    return DR_EMIT_DEFAULT;
}

void on_module_load(void *drcontext, const module_data_t *data, bool loaded) {
    if (g_module_base != nullptr || data->start == nullptr) return;
    /* only the main module (the target binary) */
    module_data_t *main_mod = dr_get_main_module();
    bool is_main = main_mod != nullptr && main_mod->start == data->start;
    if (main_mod != nullptr) dr_free_module_data(main_mod);
    if (!is_main) return;
    g_module_base = data->start;
    g_module_end = data->end;
}

void on_exit(void) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/indirect_edges.json", g_out_dir.c_str());
    if (FILE *f = fopen(path, "w")) {
        fprintf(f, "{\"format\": \"fuz.call-graph-delta/1\", \"edges\": [\n");
        bool first = true;
        std::lock_guard<std::mutex> g(g_edge_lock);
        for (auto &kv : g_edges) {
            if (!first) fprintf(f, ",\n");
            first = false;
            fprintf(f, "  {\"caller_offset\": \"0x%llx\", "
                       "\"callee_offset\": \"0x%llx\", "
                       "\"kind\": \"indirect_resolved\", "
                       "\"call_count\": %u}",
                    (unsigned long long)kv.second->call_site_rva,
                    (unsigned long long)kv.second->target_rva,
                    kv.second->hit_count);
        }
        fprintf(f, "\n]}\n");
        fclose(f);
    }
}

} /* namespace */

DR_EXPORT void dr_init(client_id_t id) {
    dr_set_client_name("bindumpty-edges", "http://localhost");

    int argc = 0;
    const char **argv = nullptr;
    dr_get_option_array(id, &argc, &argv);
    for (int i = 0; i < argc; i++) {
        std::string a(argv[i]);
        if (a.rfind("--out_dir=", 0) == 0)
            g_out_dir = a.substr(strlen("--out_dir="));
    }
    dr_create_dir(g_out_dir.c_str());

    dr_register_module_load_event(on_module_load);
    dr_register_bb_event(event_bb);
    dr_register_exit_event(on_exit);

    /* main module is pre-loaded: run the handler once for it */
    module_data_t *m = dr_get_main_module();
    if (m != nullptr) {
        on_module_load(nullptr, m, true);
        dr_free_module_data(m);
    }
}
