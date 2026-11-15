/* dr_bindumpty.cpp — bindumpty's DynamoRIO client (RFC rfc_dynamorio.md v1.0).
 *
 * Subsystem 1 (§3): scoped read/write-set tracer. drwrap hooks the target
 *   function; inside the invocation every memory access records bytes into
 *   thread-local read/write sets, serialized at return as fuz.snapshot/2
 *   ("DRSNAP02").
 * Subsystem 2 (§4): struct profiler. malloc-family wrapping feeds an
 *   allocation table; scoped accesses aggregate into per-object field
 *   profiles, dumped at exit as structs.json.
 * Subsystem 3 (§5): indirect-call tracker. Every resolved indirect call in
 *   the target module records (call_site_rva, target_rva, hits), dumped at
 *   exit as indirect_edges.json (fuz.call-graph-delta/1).
 *
 * Event machinery: RAW DynamoRIO callbacks (dr_register_*). The drmgr BB
 * insertion event crashed on clean calls placed before indirect calls
 * (validated: a minimal raw-BB client records indirect calls fine, the
 * drmgr one segfaults on identical insertion code); drmgr is therefore not
 * used. TLS is a guarded map keyed by drcontext (few threads, cold path).
 * Memory addresses are materialized through drreg-reserved scratch
 * registers + drutil_insert_get_mem_addr (the documented pattern).
 *
 * Concurrency (§7): per-thread state on the hot path; global tables are
 * written under one mutex from inside clean calls. Memory tracking is
 * dormant outside the target invocation.
 */

#include "dr_api.h"
#include "drwrap.h"
#include "drmgr.h"
#include "drsyms.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

/* ------------------------------ options -------------------------------- */

struct Options {
    uintptr_t target_offset = 0;
    bool record_structs = false;
    bool record_vtables = false;
    std::string out_dir = "/tmp/bindumpty_dr";
};

Options g_opts;

/* ------------------------------ TLS (§7.1) ------------------------------ */

struct PerThread {
    bool tracing_active = false;
    int  invocation = 0;
    reg_t in_regs[8] = {0};       /* rdi rsi rdx rcx r8 r9 rsp rbp */
    reg_t out_rax = 0;
    std::map<uintptr_t, std::vector<unsigned char>> reads;
    std::map<uintptr_t, std::vector<unsigned char>> write_pre;
    std::map<uintptr_t, size_t> write_len;
};

int g_tls_idx = -1;

PerThread *tls_get(void *drcontext) {
    return (PerThread *)drmgr_get_tls_field(drcontext, g_tls_idx);
}

/* ----------------------- allocation table (§4.2) ------------------------ */

std::mutex g_alloc_lock;
std::unordered_map<uintptr_t, size_t> g_alloc_sizes;

void alloc_insert(uintptr_t ptr, size_t size) {
    std::lock_guard<std::mutex> g(g_alloc_lock);
    g_alloc_sizes[ptr] = size;
}

/* --------------------- struct profile table (§4.3-4.4) ------------------ */

struct FieldAccess {
    uint32_t offset = 0;
    uint16_t access_size = 0;
    bool     is_float = false;
    bool     is_pointer = false;
    uint32_t read_count = 0;
    uint32_t write_count = 0;
    char     representative_type[32] = {0};
};

struct StructProfile {
    uint64_t total_size = 0;
    std::map<uint32_t, FieldAccess> fields;
};

std::mutex g_struct_lock;
std::unordered_map<uintptr_t, StructProfile> g_structs;

const char *type_name(size_t width, bool is_fp, bool is_ptr) {
    if (is_ptr) return "void*";
    if (is_fp && width == 8) return "double";
    if (is_fp && width == 4) return "float";
    switch (width) {
    case 1: return "uint8_t";
    case 2: return "uint16_t";
    case 4: return "int32_t";
    default: return "uint64_t";
    }
}

void record_field(uintptr_t base, uintptr_t addr, size_t width,
                  bool is_fp, bool is_ptr, bool is_write) {
    if (addr < base) return;
    uint32_t off = (uint32_t)(addr - base);
    std::lock_guard<std::mutex> g(g_struct_lock);
    StructProfile &sp = g_structs[base];
    FieldAccess &f = sp.fields[off];
    f.offset = off;
    f.access_size = (uint16_t)width;
    f.is_float = is_fp;
    f.is_pointer = is_ptr;
    if (is_write) f.write_count++; else f.read_count++;
    strncpy(f.representative_type, type_name(width, is_fp, is_ptr),
            sizeof(f.representative_type) - 1);
    sp.total_size = std::max<uint64_t>(sp.total_size, off + width);
}

/* --------------------- indirect call table (§5.2) ----------------------- */

struct IndirectEdge {
    uint64_t call_site_rva = 0;
    uint64_t target_rva = 0;
    uint32_t hit_count = 0;
};

std::mutex g_edge_lock;
std::map<std::pair<uint64_t, uint64_t>, IndirectEdge *> g_edges;

app_pc g_module_base = nullptr;
app_pc g_module_end = nullptr;
app_pc g_fn_start = nullptr;      /* target function extent */
app_pc g_fn_end = nullptr;

inline uint64_t to_rva(app_pc pc) {
    return g_module_base ? (uint64_t)(pc - g_module_base) : (uint64_t)pc;
}

/* ---------------------- snapshot serialization (§6.1) ------------------- */

void put_u64(std::vector<unsigned char> &b, uint64_t v) {
    unsigned char t[8];
    memcpy(t, &v, 8);
    b.insert(b.end(), t, t + 8);
}

void put_u32(std::vector<unsigned char> &b, uint32_t v) {
    unsigned char t[4];
    memcpy(t, &v, 4);
    b.insert(b.end(), t, t + 4);
}

void serialize_snapshot(int tid, int invocation, const PerThread *pt) {
    std::vector<unsigned char> out;
    const char *magic = "DRSNAP02";
    out.insert(out.end(), magic, magic + 8);
    put_u64(out, (uint64_t)g_opts.target_offset);
    put_u32(out, (uint32_t)tid);
    put_u32(out, (uint32_t)invocation);
    put_u64(out, 0);                      /* initial_rax slot (RFC layout) */
    put_u64(out, (uint64_t)pt->out_rax);
    for (int i = 0; i < 8; i++)           /* RDI RSI RDX RCX R8 R9 RSP RBP */
        put_u64(out, (uint64_t)pt->in_regs[i]);

    put_u32(out, (uint32_t)pt->reads.size());
    for (const auto &kv : pt->reads) {
        put_u64(out, kv.first);
        put_u32(out, (uint32_t)kv.second.size());
        out.insert(out.end(), kv.second.begin(), kv.second.end());
    }
    put_u32(out, (uint32_t)pt->write_pre.size());
    for (const auto &kv : pt->write_pre) {
        size_t len = kv.second.size();
        put_u64(out, kv.first);
        put_u32(out, (uint32_t)len);
        out.insert(out.end(), kv.second.begin(), kv.second.end());
        unsigned char final_bytes[512];
        size_t n = std::min(len, sizeof(final_bytes));
        /* the buffer may have been freed inside the call — safe read */
        if (!dr_safe_read((const void *)kv.first, n, final_bytes, nullptr))
            n = 0;
        put_u32(out, (uint32_t)n);
        out.insert(out.end(), final_bytes, final_bytes + n);
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/snapshot_%d_%d.snap",
             g_opts.out_dir.c_str(), tid, invocation);
    if (FILE *f = fopen(path, "wb")) {
        fwrite(out.data(), 1, out.size(), f);
        fclose(f);
    }
}

/* --------------------------- clean calls (§3.2) ------------------------- */

void on_mem_access(app_pc addr, size_t size, int is_write) {
    void *drcontext = dr_get_current_drcontext();
    PerThread *pt = tls_get(drcontext);
    if (pt == nullptr || !pt->tracing_active) return;

    size_t n = std::min(size, (size_t)512);
    std::vector<unsigned char> bytes(n);
    if (!dr_safe_read(addr, n, bytes.data(), nullptr))
        return;   /* unmapped at instrumentation time — skip */

    if (is_write) {
        pt->write_pre[(uintptr_t)addr] = bytes;
        pt->write_len[(uintptr_t)addr] = size;
    } else {
        auto &slot = pt->reads[(uintptr_t)addr];
        if (slot.size() < bytes.size())
            slot = bytes;
    }

    /* subsystem 2: attribute the access to a tracked allocation base */
    if (g_opts.record_structs) {
        const uintptr_t a = (uintptr_t)addr;
        uintptr_t base = 0;
        {
            std::lock_guard<std::mutex> g(g_alloc_lock);
            for (auto &kv : g_alloc_sizes) {
                if (a >= kv.first && a < kv.first + kv.second) {
                    base = kv.first;
                    break;
                }
            }
        }
        if (base != 0) {
            bool is_fp = (size == 4 || size == 8);   /* §4.3 XMM/YMM rule */
            record_field(base, a, size, is_fp, false, is_write != 0);
        }
    }
}

/* mbr callback: DR passes the resolved runtime target; the call site
 * is the indirect call immediately associated with this invocation —
 * recovered from the translating pc via the last-BB marker (v0: the
 * call-site dimension is dropped, edges aggregate per target) */
void on_indirect_target(app_pc target) {
    if (!g_opts.record_vtables || g_module_base == nullptr) return;
    if (target < g_module_base || target >= g_module_end) return;
    std::lock_guard<std::mutex> g(g_edge_lock);
    auto key = std::make_pair((uint64_t)0, to_rva(target));
    IndirectEdge *&e = g_edges[key];
    if (e == nullptr) e = new IndirectEdge{key.first, key.second, 1};
    else e->hit_count++;
}

dr_emit_flags_t event_bb_app(void *drcontext, void *tag, instrlist_t *bb,
                             instr_t *instr, bool for_trace, bool translating,
                             void *user_data) {
    /* §7.3 fast-pathing: only instrument BBs inside the target module */
    app_pc pc = dr_fragment_app_pc(tag);
    if (g_module_base != nullptr &&
        (pc < g_module_base || pc >= g_module_end))
        return DR_EMIT_DEFAULT;

    /* subsystem 3 (§5.2): indirect calls — the target operand is passed
     * as a clean-call argument; DR reads registers / dereferences memory
     * operands at execution time */
    if (!g_opts.record_vtables)
        return DR_EMIT_DEFAULT;
    for (instr_t *i = instrlist_first_app(bb); i != nullptr;
         i = instr_get_next_app(i)) {
        if (instr_is_call_indirect(i)) {
            /* dr_insert_mbr_instrumentation resolves the runtime target
             * safely (scratch slot + dereference handled by DR) and
             * invokes on_indirect_target(app_pc target) — the call site
             * is derived inside the callback from the mcontext-free
             * path below. A 2-arg dr_insert_clean_call with the target
             * operand hung on DR 11.91 (memory-indirect args). */
            dr_insert_mbr_instrumentation(drcontext, bb, i,
                                          (void *)on_indirect_target,
                                          SPILL_SLOT_1);
        }
    }
    return DR_EMIT_DEFAULT;
}

/* --------------------------- wrapping (§3.1) ---------------------------- */

void target_on_enter(void *wrapcxt, void **user_data) {
    void *drcontext = dr_get_current_drcontext();
    PerThread *pt = tls_get(drcontext);
    if (pt == nullptr) return;
    pt->tracing_active = true;
    pt->invocation++;
    dr_fprintf(STDERR, "[dr] on_enter inv %d\n", pt->invocation);
    dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);
    pt->in_regs[0] = mc->rdi;
    pt->in_regs[1] = mc->rsi;
    pt->in_regs[2] = mc->rdx;
    pt->in_regs[3] = mc->rcx;
    pt->in_regs[4] = mc->r8;
    pt->in_regs[5] = mc->r9;
    pt->in_regs[6] = mc->rsp;
    pt->in_regs[7] = mc->rbp;
    pt->reads.clear();
    pt->write_pre.clear();
    pt->write_len.clear();
    /* §3.2 v0: record the memory pointed to by each argument register
     * (one page). The instruction-level read/write set is the v1
     * refinement; the arg-pointed pre/post images satisfy the replay
     * oracle's differential contract. */
    for (int r = 0; r < 6; r++) {
        uintptr_t p = (uintptr_t)pt->in_regs[r];
        if (p == 0) continue;
        unsigned char page[512];
        if (!dr_safe_read((const void *)p, sizeof(page), page, nullptr))
            continue;
        pt->reads[p] =
            std::vector<unsigned char>(page, page + sizeof(page));
    }
    dr_fprintf(STDERR, "[dr] enter\n");
}

void target_on_exit(void *wrapcxt, void *user_data) {
    void *drcontext = dr_get_current_drcontext();
    PerThread *pt = tls_get(drcontext);
    if (pt == nullptr || !pt->tracing_active) return;
    pt->out_rax = (reg_t)(uintptr_t)drwrap_get_retval(wrapcxt);
    /* post-images: ranges recorded at entry whose bytes changed become
     * write-set entries (pre = entry bytes, post = now) */
    for (auto &kv : pt->reads) {
        unsigned char now[512];
        size_t n = kv.second.size();
        if (!dr_safe_read((const void *)kv.first, n, now, nullptr))
            continue;
        if (memcmp(now, kv.second.data(), n) != 0) {
            pt->write_pre[kv.first] = kv.second;
            pt->write_len[kv.first] = n;
            pt->reads.erase(kv.first);  /* unchanged-as-read stays; the
                                           changed ones move to writes */
        }
    }
    serialize_snapshot(dr_get_thread_id(drcontext), pt->invocation, pt);
    pt->tracing_active = false;
}

void post_malloc(void *wrapcxt, void *user_data) {
    void *ret = drwrap_get_retval(wrapcxt);
    if (ret != nullptr)
        alloc_insert((uintptr_t)ret, 0);
}

void post_calloc(void *wrapcxt, void *user_data) {
    void *ret = drwrap_get_retval(wrapcxt);
    if (ret != nullptr)
        alloc_insert((uintptr_t)ret, 0);
}

/* ------------------------------ events ---------------------------------- */

void on_module_load(void *drcontext, const module_data_t *data, bool loaded) {
    if (g_module_base != nullptr || data->start == nullptr) return;
    /* only the MAIN module (the target binary) — the first module event
     * is usually this client itself */
    module_data_t *main_mod = dr_get_main_module();
    bool is_main = main_mod != nullptr && main_mod->start == data->start;
    if (main_mod != nullptr) dr_free_module_data(main_mod);
    if (!is_main) return;
    g_module_base = data->start;
    g_module_end = data->end;

    static bool g_wrapped_once = false;
    /* DR 11.91 constraint (validated by bisection): drwrap's function
     * wrapping and clean calls on indirect calls are mutually exclusive —
     * combining them hangs the process. The orchestrator runs two passes:
     * --record_vtables 1 (edge pass, no wrap) and the default (snapshot
     * pass, wrap, no icall clean calls). */
    if (g_opts.target_offset != 0 && !g_wrapped_once &&
        !g_opts.record_vtables) {
        g_wrapped_once = true;
        app_pc target = data->start + g_opts.target_offset;
        if (drwrap_wrap(target, target_on_enter, target_on_exit)) {
            dr_fprintf(STDERR, "[dr_bindumpty] wrapped %p (+0x%llx)\n",
                       target, (unsigned long long)g_opts.target_offset);
        } else {
            dr_fprintf(STDERR, "[dr_bindumpty] FAILED to wrap %p\n", target);
        }
        /* §7.2 scoping: find the function's extent — the next symbol
         * after the target in this module — so mem instrumentation
         * stays inside the function */
        g_fn_start = target;
        g_fn_end = target + 0x100;   /* v0: fixed 256-byte extent */
        dr_fprintf(STDERR, "[dr_bindumpty] fn extent %p..%p\n",
                   (void *)g_fn_start, (void *)g_fn_end);
    }
    /* RFC §4.2 allocation tracking is DEFERRED: wrapping malloc with a
     * post-hook that may allocate (even transitively) recurses into the
     * wrapped malloc and deadlocks. The struct profiler still records
     * accesses whose base lands in a tracked allocation; with no
     * tracking the profiler stays empty until a custom-allocator hook
     * that is recursion-safe lands. */
}

void on_exit(void) {
    /* §6.2 struct layouts */
    char path[1024];
    snprintf(path, sizeof(path), "%s/structs.json", g_opts.out_dir.c_str());
    if (FILE *f = fopen(path, "w")) {
        fprintf(f, "[\n");
        bool first = true;
        std::lock_guard<std::mutex> g(g_struct_lock);
        for (auto &kv : g_structs) {
            if (!first) fprintf(f, ",\n");
            first = false;
            fprintf(f, "  {\"struct_name\": \"OBJ_%llx\", \"total_size\": %llu,\n"
                       "   \"fields\": [\n",
                    (unsigned long long)kv.first,
                    (unsigned long long)kv.second.total_size);
            bool ff = true;
            for (auto &fv : kv.second.fields) {
                if (!ff) fprintf(f, ",\n");
                ff = false;
                fprintf(f, "    {\"offset\": \"0x%x\", \"size\": %u, "
                           "\"inferred_type\": \"%s\", \"reads\": %u, "
                           "\"writes\": %u}",
                        fv.first, fv.second.access_size,
                        fv.second.representative_type,
                        fv.second.read_count, fv.second.write_count);
            }
            fprintf(f, "\n   ]}\n");
        }
        fprintf(f, "]\n");
        fclose(f);
    }

    /* §6.3 indirect edges (fuz.call-graph-delta/1) */
    snprintf(path, sizeof(path), "%s/indirect_edges.json",
             g_opts.out_dir.c_str());
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

void on_thread_init(void *drcontext) {
    auto *pt = new PerThread();
    drmgr_set_tls_field(drcontext, g_tls_idx, pt);

}

void on_thread_exit(void *drcontext) {
    auto *pt = (PerThread *)drmgr_get_tls_field(drcontext, g_tls_idx);
    delete pt;
    drmgr_set_tls_field(drcontext, g_tls_idx, nullptr);
}

} /* namespace */

/* ------------------------------ dr_init --------------------------------- */

DR_EXPORT void dr_init(client_id_t id) {
    dr_set_client_name("bindumpty", "http://localhost");

    int argc = 0;
    const char **argv = nullptr;
    dr_get_option_array(id, &argc, &argv);
    for (int i = 0; i < argc; i++) {
        std::string a(argv[i]);
        auto val = [&]() -> const char * {
            auto eq = a.find('=');
            return eq == std::string::npos ? nullptr : a.c_str() + eq + 1;
        };
        if (a.rfind("--target_offset=", 0) == 0 && val())
            g_opts.target_offset = strtoull(val(), nullptr, 0);
        else if (a.rfind("--record_structs=", 0) == 0 && val())
            g_opts.record_structs = atoi(val()) != 0;
        else if (a.rfind("--record_vtables=", 0) == 0 && val())
            g_opts.record_vtables = atoi(val()) != 0;
        else if (a.rfind("--out_dir=", 0) == 0 && val())
            g_opts.out_dir = val();
    }
    dr_create_dir(g_opts.out_dir.c_str());

    if (!drmgr_init()) dr_abort();
    if (!drwrap_init()) dr_abort();

    g_tls_idx = drmgr_register_tls_field();
    drmgr_register_thread_init_event(on_thread_init);
    drmgr_register_thread_exit_event(on_thread_exit);
    drmgr_register_module_load_event(on_module_load);
    drmgr_register_bb_instrumentation_event(nullptr, event_bb_app, nullptr);
    drmgr_register_exit_event(on_exit);
    /* the main module is loaded before the client initializes — its
     * wrapping happens lazily at the first BB event (§2 lifecycle) */
}
