// S1 spike: export the call graph of an ELF binary as fuz.call-graph/1 JSON
// using Ghidra headless. This is the M0 ingestion path (FR-1) — the same
// script the production ingestor will run.
//
// Run (see spike_s1.sh):
//   java -jar support/analyzeHeadless <project> <folder> -import <binary> \
//        -scriptPath <this dir> -postScript ExportCallGraph.java <out.json>
//
// Output: one JSON document per the fuz.call-graph/1 format (see
// toys/case-01-leaf/ground_truth/call_graph.json for a reference instance):
//   { "format", "binary": {sha256,arch,kind,is_pie,is_stripped},
//     "functions": [{name,address,size,demangled_sig,has_rtti,scc_id,is_library}],
//     "edges":     [{caller,callee,kind}],
//     "sccs":      [...], "topological_order": [...] }
//
// "name": demangled if present, else Ghidra's label, else "fn_<vaddr>".
//   (A stripped binary has no export names — that is the real M2 case.)
// "kind": direct | indirect | virtual.
//
// Library functions (is_library=true) are those whose code lives outside the
// primary load module — they are FR-2 fingerprinting candidates, not LLM
// targets.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.DataType;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.*;

public class ExportCallGraph extends GhidraScript {

    private static void jso(StringBuilder sb, String s) {
        sb.append(s == null ? "null" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\t", "\\t") + "\"");
    }

    @Override
    public void run() throws Exception {
        TaskMonitor mon = getMonitor();
        // output path is the (single) script arg
        String[] sargs = getScriptArgs();
        String outPath = sargs.length >= 1 ? sargs[0] : "call_graph.json";
        // D1.3: subtree-scoped export — rootSymbol restricts the graph to
        // the transitive callee tree from that function; maxDepth bounds it
        String rootSymbol = sargs.length >= 3 ? sargs[2] : null;
        int maxDepth = sargs.length >= 4 ? Integer.parseInt(sargs[3])
                                         : Integer.MAX_VALUE;

        // --- binary metadata ---------------------------------------------
        // 12.2 API: getExecutablePath/getExecutableSHA256 on Program.
        File binFile = new File(currentProgram.getExecutablePath());
        String sha256 = currentProgram.getExecutableSHA256();
        if (sha256 == null || sha256.isEmpty()) sha256 = "PENDING_BUILD_SHA";
        String arch = currentProgram.getLanguage().getLanguageID().getIdAsString();
        boolean isPie = !currentProgram.getMemory().isBigEndian() &&
                String.valueOf(currentProgram.getImageBase()).startsWith("0x");
        boolean isStripped = hasOnlyAutoLabels();
        // Source-language detection (FR-1 aux): Ghidra's own analysis is the
        // authority. Itanium-mangled symbols / C++ runtime imports / demangled
        // names prove C++; their absence (with plain symbols) means C.
        // Verdict feeds the pipeline adapter (humpty/analyze/detect_lang.py).
        String srcLang = detectSourceLang();
        // Also emit the standalone verdict JSON when an output path is given
        // (second script arg), so the two-tier detector can cross-check.
        String langOutPath = sargs.length >= 2 ? sargs[1] : null;
        if (langOutPath != null) {
            try (FileWriter lw = new FileWriter(langOutPath)) {
                lw.write(langVerdictJson);
            }
        }

        // --- collect functions -------------------------------------------
        // D1.3: subtree-scoped export — if rootSymbol is set, BFS the call
        // tree from that function up to maxDepth and collect only reachable
        // functions (instead of serializing all 17k+ binary symbols).
        List<Function> fns = new ArrayList<>();
        if (rootSymbol != null) {
            // BFS from root through direct call targets
            java.util.Map<String, List<Address>> callTargets = new HashMap<>();
            Function rootFn = null;
            for (FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                 it.hasNext(); ) {
                Function f = it.next();
                if (f.getName().equals(rootSymbol)) {
                    rootFn = f;
                    break;
                }
            }
            if (rootFn == null) {
                println("ExportCallGraph: root symbol '" + rootSymbol + "' not found, exporting all");
            } else {
                // BFS: start with root, follow direct call targets
                java.util.Set<String> visited = new java.util.HashSet<>();
                java.util.List<Function> frontier = new ArrayList<>();
                frontier.add(rootFn);
                visited.add(rootFn.getName());
                fns.add(rootFn);
                int depth = 0;
                while (!frontier.isEmpty() && depth < maxDepth) {
                    java.util.List<Function> next = new ArrayList<>();
                    for (Function caller : frontier) {
                        // find callees via references from the caller's body
                        for (Instruction ins : currentProgram.getListing().getInstructions(caller.getBody(), true)) {
                            for (Reference ref : ins.getReferencesFrom()) {
                                if (!ref.getReferenceType().isCall()) continue;
                                Address tgt = ref.getToAddress();
                                Function callee = currentProgram.getFunctionManager().getFunctionContaining(tgt);
                                if (callee == null) continue;
                                if (visited.contains(callee.getName())) continue;
                                visited.add(callee.getName());
                                fns.add(callee);
                                next.add(callee);
                            }
                        }
                    }
                    frontier = next;
                    depth++;
                }
                mon.setMessage("subtree from " + rootSymbol + ": " + fns.size() + " fns, depth " + depth);
            }
        }
        if (fns.isEmpty()) {
            // full export (no root symbol or root not found)
            for (FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                 it.hasNext(); ) {
                fns.add(it.next());
            }
        }
        mon.setMessage("functions: " + fns.size());

        // primary module (the binary itself, not linked libraries)
        MemoryBlock primary = null;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.isRead() && b.isExecute() && b.getSize() > 0) {
                if (primary == null || b.getStart().compareTo(primary.getStart()) < 0)
                    primary = b;
            }
        }
        Address imgBase = currentProgram.getImageBase();

        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"format\": \"fuz.call-graph/1\",\n");
        sb.append("  \"binary\": {\"sha256\": \"").append(sha256).append("\",")
          .append("\"arch\": \"").append(arch).append("\",")
          .append("\"kind\": \"elf\",")
          .append("\"is_pie\": ").append(isPie).append(",")
          .append("\"is_stripped\": ").append(isStripped).append(",")
          .append("\"source_lang\": "); jso(sb, srcLang); sb.append("},\n");

        // --- functions array ---------------------------------------------
        sb.append("  \"functions\": [\n");
        Map<Function, String> id = new IdentityHashMap<>();
        Map<String, Address> seenNames = new HashMap<>();
        boolean first = true;
        for (Function f : fns) {
            String baseName = demangledOrLabel(f);
            Address a = f.getEntryPoint();
            String name = baseName;
            if (seenNames.containsKey(baseName) && !seenNames.get(baseName).equals(a)) {
                name = baseName + "@0x" + Long.toHexString(a.getOffset());
            } else {
                seenNames.put(baseName, a);
            }
            id.put(f, name);
            boolean inPrimary = primary != null && a.compareTo(primary.getStart()) >= 0
                    && a.compareTo(primary.getEnd()) <= 0;
            sb.append((first ? "" : ",\n") + "    {")
              .append("\"name\": "); jso(sb, name);
              sb.append(",\"address\": \"0x").append(Long.toHexString(a.getOffset())).append("\",");
              sb.append("\"size\": ").append(f.getBody().getNumAddresses()).append(",");
              sb.append("\"demangled_sig\": "); jso(sb, demangledSig(f));
              sb.append(",\"has_rtti\": false,");
              sb.append("\"scc_id\": null,");
              sb.append("\"is_library\": ").append(!inPrimary).append("}");
            first = false;
        }
        sb.append("\n  ],\n");

        // --- edges --------------------------------------------------------
        sb.append("  \"edges\": [\n");
        List<String[]> edgeRows = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        for (Function caller : fns) {
            InstructionIterator ii = listing.getInstructions(caller.getBody(), true);
            for (; ii.hasNext(); ) {
                Instruction ins = ii.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Address tgt = ref.getToAddress();
                    Function cf = currentProgram.getFunctionManager().getFunctionContaining(tgt);
                    String kind;
                    // 12.2 RefType has no isIndirectCall; COMPUTED_CALL == indirect
                    String rt = ref.getReferenceType().getName();
                    kind = rt.contains("COMPUTED") ? "indirect" : "direct";
                    // callee name: the function at the target, or a raw address
                    String calleeName;
                    if (cf != null) calleeName = id.getOrDefault(cf, demangledOrLabel(cf));
                    else calleeName = "0x" + Long.toHexString(tgt.getOffset());
                    edgeRows.add(new String[]{id.get(caller), calleeName, kind});
                }
            }
        }
        edgeRows.sort(Comparator.comparing((String[] e) -> e[0]).thenComparing(e -> e[1]));
        first = true;
        for (String[] e : edgeRows) {
            sb.append((first ? "" : ",\n") + "    {")
              .append("\"caller\": "); jso(sb, e[0]);
              sb.append(",\"callee\": "); jso(sb, e[1]);
              sb.append(",\"kind\": "); jso(sb, e[2]);
            sb.append("}");
            first = false;
        }
        sb.append("\n  ],\n");

        // --- SCCs (Tarjan) + topological order ----------------------------
        Map<String, List<String>> adj = new HashMap<>();
        Set<String> nodes = new LinkedHashSet<>();
        for (String e[] : edgeRows) {
            nodes.add(e[0]); nodes.add(e[1]);
            adj.computeIfAbsent(e[0], k -> new ArrayList<>()).add(e[1]);
        }
        List<List<String>> sccs = tarjan(nodes, adj, mon);
        Map<String, Integer> sccOf = new HashMap<>();
        for (int i = 0; i < sccs.size(); i++) for (String n : sccs.get(i)) sccOf.put(n, i);

        sb.append("  \"sccs\": [");
        for (int i = 0; i < sccs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("[");
            for (int j = 0; j < sccs.get(i).size(); j++) {
                if (j > 0) sb.append(",");
                jso(sb, sccs.get(i).get(j));
            }
            sb.append("]");
        }
        sb.append("],\n");

        // topological order of the condensation graph (Kahn)
        List<String> topo = topological(nodes, adj, sccOf, mon);
        sb.append("  \"topological_order\": [");
        for (int i = 0; i < topo.size(); i++) {
            if (i > 0) sb.append(",");
            jso(sb, topo.get(i));
        }
        sb.append("]\n}\n");

        // --- write --------------------------------------------------------
        File out = new File(outPath);
        if (out.getParentFile() != null) out.getParentFile().mkdirs();
        try (FileWriter w = new FileWriter(out)) {
            w.write(sb.toString());
        }
        println("ExportCallGraph: wrote " + outPath +
                " (" + fns.size() + " functions, " + edgeRows.size() + " edges, "
                + sccs.size() + " sccs)");
    }

    private boolean hasOnlyAutoLabels() {
        // heuristic: if the function manager has only auto + default labels,
        // the binary is likely stripped. 12.2: name provenance lives on the
        // Symbol (getSource() -> SourceType).
        int total = 0, named = 0;
        for (FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function f = it.next();
            total++;
            Symbol sym = f.getSymbol();
            SourceType st = sym != null ? sym.getSource() : SourceType.DEFAULT;
            if (st != SourceType.DEFAULT && st != SourceType.ANALYSIS) named++;
        }
        return total > 0 && named == 0;
    }

    private String demangledOrLabel(Function f) {
        String name = f.getName();
        // 12.2 API: DemanglerUtil.demangle(String) -> DemangledObject (null if
        // the name is not a recognized mangling).
        if (name != null && name.startsWith("_Z")) {
            try {
                ghidra.app.util.demangler.DemangledObject d =
                    ghidra.app.util.demangler.DemanglerUtil.demangle(name);
                if (d != null && d.getName() != null && !d.getName().isEmpty())
                    return d.getName();
            } catch (Exception ignore) { }
        }
        if (name != null && name.startsWith("$")) // Ghidra's default "FUN_x" style
            return "fn_" + Long.toHexString(f.getEntryPoint().getOffset());
        return name;
    }

    private String demangledSig(Function f) {
        try {
            // 12.2: Signature.getSignatureString() is gone; getPrototypeString
            // (with the library-generic namespace stripped) is the equivalent.
            String s = f.getPrototypeString(true, false);
            return s != null && !s.isEmpty() ? s : f.getName();
        } catch (Exception e) {
            return f.getName();
        }
    }

    // --- source-language detection (FR-1 aux) ------------------------------
    // Field set by detectSourceLang(); consumed by the JSON emitter and the
    // standalone verdict writer.
    private String langVerdictJson = "{}";

    private String detectSourceLang() {
        double score = 0.0;
        List<String> ev = new ArrayList<>();

        // 1. Itanium-mangled symbols anywhere in the program's symbol space.
        int mangled = 0;
        String example = null;
        for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
            String n = s.getName();
            if (n != null && (n.startsWith("_Z") || n.startsWith("__Z"))) {
                mangled++;
                if (example == null) example = n;
                if (mangled >= 100) break;
            }
        }
        if (mangled >= 1) {
            score += 3.0;
            ev.add("mangled_itanium_symbols:" + mangled + " e.g." + example);
        } else {
            score -= 0.5;
            ev.add("no_itanium_mangled_symbols");
        }

        // 2. C++ runtime imports (undefined external symbols).
        int cxxImports = 0;
        for (Symbol s : currentProgram.getSymbolTable().getExternalSymbols()) {
            String n = s.getName();
            if (n == null) continue;
            if (n.startsWith("__gxx") || n.startsWith("__cxa_")
                    || n.startsWith("_ZT") || n.startsWith("_Zn")
                    || n.startsWith("_Zd")) {
                cxxImports++;
            }
        }
        if (cxxImports >= 2) {
            score += 2.0;
            ev.add("cxx_runtime_imports:" + cxxImports);
        } else {
            score -= 0.5;
            ev.add("no_cxx_runtime_imports:" + cxxImports);
        }

        // 3. RTTI recovery artifacts (Ghidra creates these only for C++).
        int rtti = 0;
        for (java.util.Iterator<DataType> it =
                 currentProgram.getDataTypeManager().getAllDataTypes(); it.hasNext(); ) {
            String path = it.next().getCategoryPath().getPath();
            if (path != null && path.contains("TypeRecovery")) {
                rtti++;
                if (rtti >= 10) break;
            }
        }
        if (rtti >= 10) {
            score += 3.0;
            ev.add("ghidra_rtti_recovery_types:" + rtti);
        }

        String verdict = score >= 2.0 ? "cpp"
                : score > 0.0 ? "lean_cpp" : "c";
        String confidence = Math.abs(score) >= 2.0 ? "high"
                : Math.abs(score) >= 1.0 ? "medium" : "low";
        StringBuilder json = new StringBuilder();
        json.append("{\"verdict\":\"").append(verdict)
            .append("\",\"score\":").append(score)
            .append(",\"confidence\":\"").append(confidence)
            .append("\",\"evidence\":[");
        for (int i = 0; i < ev.size(); i++) {
            if (i > 0) json.append(",");
            jso(json, ev.get(i));
        }
        json.append("]}");
        langVerdictJson = json.toString();
        return verdict;
    }

    // --- Tarjan SCC -------------------------------------------------------
    private List<List<String>> tarjan(Set<String> nodes, Map<String, List<String>> adj,
                                      TaskMonitor mon) {
        Map<String, Integer> index = new HashMap<>(), low = new HashMap<>();
        Deque<String> stack = new ArrayDeque<>();
        Map<String, Boolean> onStack = new HashMap<>();
        List<List<String>> out = new ArrayList<>();
        int[] idx = {0};

        for (String v : nodes) {
            if (!index.containsKey(v)) {
                strong(v, nodes, adj, index, low, stack, onStack, out, idx, mon);
            }
        }
        return out;
    }

    private void strong(String v, Set<String> nodes, Map<String, List<String>> adj,
                        Map<String, Integer> index, Map<String, Integer> low,
                        Deque<String> stack, Map<String, Boolean> onStack,
                        List<List<String>> out, int[] idx, TaskMonitor mon) {
        index.put(v, idx[0]);
        low.put(v, idx[0]);
        idx[0]++;
        stack.push(v);
        onStack.put(v, true);
        for (String w : adj.getOrDefault(v, List.of())) {
            if (!index.containsKey(w)) {
                strong(w, nodes, adj, index, low, stack, onStack, out, idx, mon);
                low.put(v, Math.min(low.get(v), low.get(w)));
            } else if (onStack.getOrDefault(w, false)) {
                low.put(v, Math.min(low.get(v), index.get(w)));
            }
        }
        if (low.get(v).equals(index.get(v))) {
            List<String> comp = new ArrayList<>();
            String w;
            do {
                w = stack.pop();
                onStack.put(w, false);
                comp.add(w);
            } while (!w.equals(v));
            out.add(comp);
        }
    }

    // --- topological order of the condensation ---------------------------
    private List<String> topological(Set<String> nodes, Map<String, List<String>> adj,
                                     Map<String, Integer> sccOf, TaskMonitor mon) {
        int nScc = sccOf.values().stream().mapToInt(Integer::intValue).max().orElse(-1) + 1;
        List<List<Integer>> sccAdj = new ArrayList<>();
        int[] inDeg = new int[nScc];
        for (int i = 0; i < nScc; i++) sccAdj.add(new ArrayList<>());
        Set<String> seen = new HashSet<>();
        for (String v : nodes) {
            for (String w : adj.getOrDefault(v, List.of())) {
                int a = sccOf.get(v), b = sccOf.get(w);
                if (a != b && seen.add(a + ":" + b)) {
                    sccAdj.get(a).add(b);
                    inDeg[b]++;
                }
            }
        }
        ArrayDeque<Integer> q = new ArrayDeque<>();
        for (int i = 0; i < nScc; i++) if (inDeg[i] == 0) q.add(i);
        List<Integer> order = new ArrayList<>();
        while (!q.isEmpty()) {
            int u = q.poll();
            order.add(u);
            for (int w : sccAdj.get(u)) if (--inDeg[w] == 0) q.add(w);
        }
        // emit one representative (first) node per SCC in condensation order
        List<String> out = new ArrayList<>();
        Map<Integer, String> rep = new HashMap<>();
        for (String n : nodes) rep.computeIfAbsent(sccOf.get(n), k -> n);
        for (int s : order) out.add(rep.get(s));
        return out;
    }
}
