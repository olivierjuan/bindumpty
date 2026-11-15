Technical Specification: DynamoRIO Instrumentation Engine for bindumpty

  Document Version: 1.0  
  Target Architecture: Linux x86-64  
  Target Framework: DynamoRIO Client Library (libdr_bindumpty.so)  
  Host Integration: bindumpty / humpty.analyze.dynamorio  

  ---

  1. Executive Summary & Purpose

  The purpose of this specification is to define a high-performance, dynamic binary instrumentation (DBI) client using DynamoRIO for bindumpty. 

  While static analysis tools (Ghidra, Kuna) recover control-flow graphs and raw assembly offsets, they cannot definitively resolve:
   1. Exact Read/Write memory footprints across function boundaries.
   2. Dynamic indirect call targets (vtables, runtime function dispatch tables).
   3. Concrete structure layouts and field data types from opaque pointers.

  This DynamoRIO client executes alongside the target binary (e.g., lpex2 solving a real .mps model) with minimal overhead (≈ 2×--5×), full
  multi-threaded concurrency (up to 32 threads), and zero kernel modifications.

    1                     ┌──────────────────────────────────────────────┐
    2                     │            Target Binary (e.g. lpex2)        │
    3                     │               32 Worker Threads              │
    4                     └───────────────────────┬──────────────────────┘
    5                                             │
    6                                             ▼
    7                     ┌──────────────────────────────────────────────┐
    8                     │      DynamoRIO Engine (`drrun`)              │
    9                     │      JIT Basic Block Cache + TLS Manager     │
   10                     └───────────────────────┬──────────────────────┘
   11                                             │
   12                                             ▼
   13                     ┌──────────────────────────────────────────────┐
   14                     │      `libdr_bindumpty.so` Client Plugin      │
   15                     ├──────────────────────────────────────────────┤
   16                     │ • Module 1: Scoped Read/Write Set Tracer     │
   17                     │ • Module 2: Struct Access & Type Profiler    │
   18                     │ • Module 3: Indirect Call / VTable Tracker   │
   19                     └───────────────────────┬──────────────────────┘
   20                                             │
   21                  ┌──────────────────────────┼──────────────────────────┐
   22                  ▼                          ▼                          ▼
   23       `snapshot_<id>.snap`        `structs_<id>.json`         `vtables_<id>.json`
   24        (Exact memory delta)     (Offsets, widths, types)     (Edges for CallGraph)
   25                  │                          │                          │
   26                  └──────────────────────────┼──────────────────────────┘
   27                                             │
   28                                             ▼
   29                     ┌──────────────────────────────────────────────┐
   30                     │         `bindumpty` Orchestrator (Python)    │
   31                     │  • Feed LLM prompt with typed struct layouts │
   32                     │  • Drive differential replay oracle          │
   33                     │  • Enrich DB call_edges table                │
   34                     └──────────────────────────────────────────────┘

  ---

  2. Architecture & Plugin Lifecycle

  The client is built as an out-of-tree dynamic shared library (libdr_bindumpty.so) loaded by DynamoRIO's launcher:

   1 drrun -c libdr_bindumpty.so \
   2       --target_offset 0x8aba20 \
   3       --record_structs 1 \
   4       --record_vtables 1 \
   5       --out_dir /tmp/bindumpty_dr \
   6       -- ./lpex2 model.mps

  2.1 Dependencies & DynamoRIO Extensions
  The client utilizes official DynamoRIO extension libraries:
   * drmgr: Multi-component control flow and basic block instrumentation manager.
   * drwrap: Function wrapping and argument/return value extraction.
   * drreg: Safe register spill and restore manager for clean inlined calls.
   * drutil: Address calculation helpers (drutil_insert_get_mem_addr).

  ---

  3. Subsystem 1: Scoped Memory Read/Write Set Capture

  3.1 Problem Statement
  When validating a candidate function against the original, passing random fuzz bytes to pointer arguments causes crashes. We need the exact
  byte-level memory delta produced by an execution of the original function during a valid run.

  3.2 Mechanism
   1. Activation via drwrap:
      * When thread T enters the target function address:
        - Set a thread-local flag tls->tracing_active = true.
        - Record entry argument registers: RDI, RSI, RDX, RCX, R8, R9 (or RCX, RDX, R8, R9 under MS ABI).
        - Initialize two fast hash-maps or bit-vectors: tls->read_set and tls->write_set.
   2. Instruction-Level Memory Monitoring:
      * In drmgr_register_bb_instrumentation_event:
        - Inspect every instruction instr_t *instr.
        - If instr_reads_memory(instr): insert an inlined clean call to record the memory address range [addr, addr + size).
        - If instr_writes_memory(instr):
          - Before the store executes: read and record the pre-image bytes (the original value).
          - After the store executes: mark the range in write_set.
   3. Function Return (on_leave):
      * Record return register RAX.
      * Capture post-image bytes for all ranges in write_set.
      * Set tls->tracing_active = false.
      * Serialize the snapshot to snapshot_<fn>_<invocation>.snap.

  ---

  4. Subsystem 2: Dynamic Structure Layout Recovery

  4.1 Problem Statement
  In stripped C/C++ binaries, structure members are accessed as offsets from a base pointer (*(double*)(rdi + 0x28)). Static analysis alone
  cannot always determine:
   - Total structure allocation size.
   - Exact primitive field types (distinguishing integer uint64_t from floating-point double).
   - Whether an offset represents a primitive field, a nested pointer, or an embedded array.

  4.2 Allocation Tracking
   * Intercept malloc, calloc, realloc, and custom allocators (e.g. cpxalloc):

   1   void post_malloc(void *wrap_ctx, void *user_data) {
   2       size_t size = (size_t)drwrap_get_arg(wrap_ctx, 0);
   3       void *ptr = drwrap_get_retval(wrap_ctx);
   4       allocation_table_insert(ptr, size);
   5   }
   * When an argument pointer P is passed into a function, look up P in the allocation table to determine sizeof(struct).

  4.3 Field Typology Classification
  For every instruction accessing memory [P + offset]:

  ┌───────────────────────────────────────────────────────────┬──────────────────┬─────────────────────────┐
  │ Observation                                               │ Inference Rule   │ Inferred C Type         │
  ├───────────────────────────────────────────────────────────┼──────────────────┼─────────────────────────┤
  │ Read/Write into XMM / YMM / ZMM                           │ Width = 8 bytes  │ double                  │
  │ Read/Write into XMM / YMM / ZMM                           │ Width = 4 bytes  │ float                   │
  │ Value at [P + offset] points to a valid heap/mmap block   │ Ptr check = True │ void* or struct_*       │
  │ Read/Write into General Purpose Register (EAX, EBX, etc.) │ Width = 4 bytes  │ int / uint32_t          │
  │ Bitwise operations (test, and, or, bts)                   │ Bitwise opcode   │ unsigned int (bitflags) │
  │ Consecutive scalar writes with stride S                   │ P + base + i * S │ double[N] or int[N]     │
  └───────────────────────────────────────────────────────────┴──────────────────┴─────────────────────────┘

  4.4 Structure Layout Aggregation
  The client maintains a global thread-safe table aggregating access patterns per base object:

    1 struct FieldAccess {
    2     uint32_t offset;
    3     uint16_t access_size;
    4     bool is_float;
    5     bool is_pointer;
    6     uint32_t read_count;
    7     uint32_t write_count;
    8     char representative_type[32]; // e.g. "double", "int32_t", "char*"
    9 };
   10
   11 struct StructProfile {
   12     char struct_id[64];
   13     uint32_t allocated_size;
   14     std::map<uint32_t, FieldAccess> fields;
   15 };

  ---

  5. Subsystem 3: Indirect Call & VTable Resolution

  5.1 Problem Statement
  Static analyzers like Ghidra and objdump cannot resolve dynamic indirect call sites:

   1 mov 0x28(%rax), %rdx
   2 call *%rdx             ; Which concrete function is called?
  In CPLEX, API functions and solver steps are dispatched through virtual method tables containing hundreds of slots.

  5.2 Dynamic Resolution Rule
   1. During basic block inspection, identify indirect calls:

   1    if (instr_is_call_indirect(instr)) {
   2        // Insert clean call before instruction executes
   3        dr_insert_clean_call(drcontext, bb, instr, (void *)record_indirect_call,
   4                             false /* save fp */, 2,
   5                             OPND_CREATE_INTPTR(instr_get_app_pc(instr)),
   6                             instr_get_target(instr));
   7    }
   2. In record_indirect_call(app_pc call_site, app_pc target_addr):
      * Record the tuple (call_site_rva, target_function_rva, hit_count).
      * Resolve target address to function symbol (or offset relative to the binary's image base).
   3. At program termination, dump all resolved dynamic edges.

  ---

  6. Output Protocols and File Formats

  To ensure seamless integration with bindumpty's Python pipelines, all outputs are written using structured binary or JSON formats.

  6.1 Snapshot Format (fuz.snapshot/2)
  Binary format for maximum speed and compact footprint:

    1 [Header: 8 bytes]       "DRSNAP02"
    2 [Metadata: 32 bytes]    uint64_t target_vaddr
    3                         uint32_t thread_id
    4                         uint32_t invocation_index
    5                         uint64_t initial_rax
    6                         uint64_t return_rax
    7 [Register State: 8*8]   RDI, RSI, RDX, RCX, R8, R9, RSP, RBP
    8 [Read Set Count]        uint32_t n_read_ranges
    9   [Read Ranges]         Array of { uint64_t start, uint32_t len, uint8_t bytes[len] }
   10 [Write Set Count]       uint32_t n_write_ranges
   11   [Write Ranges]        Array of { uint64_t start, uint32_t len, uint8_t initial_bytes[len], uint8_t final_bytes[len] }

  6.2 Struct Layout Format (structs.json)
  Structured JSON consumed directly by humpty/men/prompts/templates.py:

    1 {
    2   "struct_name": "BARRIER_CTX_0x8aba20",
    3   "total_size": 424,
    4   "fields": [
    5     {
    6       "offset": "0x00",
    7       "size": 8,
    8       "inferred_type": "double*",
    9       "confidence": 0.95,
   10       "reads": 1420,
   11       "writes": 0,
   12       "semantic_hint": "primal vector array (passed to DAXPY/DDOT)"
   13     },
   14     {
   15       "offset": "0x28",
   16       "size": 8,
   17       "inferred_type": "double",
   18       "confidence": 1.0,
   19       "reads": 22,
   20       "writes": 22,
   21       "semantic_hint": "norm_primal accumulator"
   22     }
   23   ]
   24 }

  6.3 VTable / Call Graph Delta Format (indirect_edges.json)
  Consumed directly by load_call_graph:

    1 {
    2   "format": "fuz.call-graph-delta/1",
    3   "edges": [
    4     {
    5       "caller": "barrier_iteration_driver",
    6       "caller_offset": "0x0027f120",
    7       "callee": "barengin_engine_step",
    8       "callee_offset": "0x008aba20",
    9       "kind": "indirect_resolved",
   10       "call_count": 22
   11     }
   12   ]
   13 }

  ---

  7. Performance & Concurrency Controls

  Because CPLEX operates with high thread counts (up to 32 threads) and intensive numerical loops, the instrumentation must avoid contention:

   1. Thread-Local Buffering (Zero Lock Contention):
      * Each thread writes memory access events into an unshared, thread-local memory buffer (dr_get_dr_context() + TLS).
      * Buffers are flushed to disk in 64 KB blocks using asynchronous double-buffering.
   2. Selective Instrumentation Scoping:
      * Memory tracking is dormant by default.
      * Tracking is enabled dynamically only when the execution enters the target function address, and disabled immediately upon return
        (drwrap_wrap).
      * Calls to standard libraries (libc, libm, libpthread) are filtered out to avoid tracking irrelevant instructions.
   3. Instruction Fast-Pathing:
      * Basic blocks outside the module of interest are not instrumented (dr_module_contains_addr).

  ---

  8. Integration Plan into bindumpty

    1 ┌────────────────────────────────────────────────────────────────────────┐
    2 │                        CLI / ORCHESTRATOR SEAM                         │
    3 └───────────────────────────────────┬────────────────────────────────────┘
    4                                     │
    5        1. Record Mode:              │          2. Replay Mode:
    6        `bindumpty dr-record`        │          `snapshot_replay.py`
    7                                     │
    8                                     ▼
    9        ┌─────────────────────────────────────────────────────────┐
   10        │ Launches binary under DynamoRIO:                        │
   11        │ `drrun -c libdr_bindumpty.so --target <fn> -- ./lpex2`   │
   12        └────────────────────────────┬────────────────────────────┘
   13                                     │
   14                                     ▼
   15        ┌─────────────────────────────────────────────────────────┐
   16        │ Ingestion of Artifacts:                                 │
   17        │  a) Update `call_edges` in DB with resolved vtables     │
   18        │  b) Generate `structs_<fn>.h` and save to `--types-dir` │
   19        │  c) Save `snapshot_<fn>.snap` to counterexample store   │
   20        └────────────────────────────┬────────────────────────────┘
   21                                     │
   22                                     ▼
   23        ┌─────────────────────────────────────────────────────────┐
   24        │ LLM Developer Prompt (`templates.py`):                  │
   25        │  • Passes reconstructed struct headers into spec        │
   26        │  • LLM writes code using fields instead of raw offsets  │
   27        └────────────────────────────┬────────────────────────────┘
   28                                     │
   29                                     ▼
   30        ┌─────────────────────────────────────────────────────────┐
   31        │ Differential Replay Verification:                       │
   32        │  • Replay candidate function against memory snapshot    │
   33        │  • Zero-diff check validates candidate in milliseconds  │
   34        └─────────────────────────────────────────────────────────┘

  Next Steps for Implementation
   1. Add analysis/dynamorio/ containing CMakeLists.txt and dr_bindumpty.cpp.
   2. Wrap DynamoRIO execution in Python under humpty/analyze/dynamorio.py.
   3. Connect indirect_edges.json directly into humpty/ingest/__init__.py.
   4. Connect structs.json directly into types_registry.py and the --types-dir pipeline.