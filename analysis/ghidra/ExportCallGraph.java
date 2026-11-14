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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.DemanglerManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.References;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.*;

public class ExportCallGraph extends GhidraScript {

    private static void jso(String sb, String s) {
        sb.append(s == null ? "null" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\t", "\\t") + "\"");
    }

    @Override
    public void run() throws Exception {
        TaskMonitor mon = getMonitor();
        // output path is the (single) script arg
        String outPath = state.length >= 1 ? state[0] : "call_graph.json";

        // --- binary metadata ---------------------------------------------
        File binFile = new File(currentProgram.getImagePath());
        String sha256 = "PENDING_BUILD_SHA";
        if (binFile.exists()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (var is = new java.io.FileInputStream(binFile)) {
                byte[] b = new byte[1 << 16];
                int n;
                while ((n = is.read(b)) > 0) md.update(b, 0, n);
            }
            sha256 = String.format("%064x", md.digest());
        }
        String arch = currentProgram.getLanguage().getShortName();
        boolean isPie = currentProgram.getLanguage().isLittleEndian() &&
                String.valueOf(currentProgram.getImageBase()).startsWith("0x");
        boolean isStripped = hasOnlyAutoLabels();

        // --- collect functions -------------------------------------------
        List<Function> fns = new ArrayList<>();
        for (FunctionIterator it = getProgram().getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            fns.add(it.next());
        }
        mon.setMessage("functions: " + fns.size());

        // primary module (the binary itself, not linked libraries)
        MemoryBlock primary = null;
        for (MemoryBlock b : getProgram().getMemory().getBlocks()) {
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
          .append("\"is_stripped\": ").append(isStripped).append("},\n");

        // --- functions array ---------------------------------------------
        sb.append("  \"functions\": [\n");
        Map<Function, String> id = new IdentityHashMap<>();
        boolean first = true;
        for (Function f : fns) {
            String name = demangledOrLabel(f);
            id.put(f, name);
            Address a = f.getEntryPoint();
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
        for (Function caller : fns) {
            for (InstructionIterator ii = caller.getInstructions(true); ii.hasNext(); ) {
                Instruction ins = ii.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Address tgt = ref.getToAddress();
                    Function cf = getProgram().getFunctionManager().getFunctionContaining(tgt);
                    String kind;
                    if (ref.getReferenceType().isIndirectCall()) {
                        kind = "indirect";
                    } else {
                        kind = "direct";
                    }
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
        // the binary is likely stripped
        int total = 0, named = 0;
        for (FunctionIterator it = getProgram().getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function f = it.next();
            total++;
            if (f.getNameSource() != SourceType.DEFAULT &&
                f.getNameSource() != SourceType.AUTO) named++;
        }
        return total > 0 && named == 0;
    }

    private String demangledOrLabel(Function f) {
        String name = f.getName();
        DemanglerManager dm = getProgram().getDemanglerManager();
        if (dm != null && dm.isNameMangled(name)) {
            try {
                String d = dm.demangle(name).getName();
                if (d != null && !d.isEmpty()) return d;
            } catch (Exception ignore) { }
        }
        if (name.startsWith("$")) // Ghidra's default "FUN_x" style
            return "fn_" + Long.toHexString(f.getEntryPoint().getOffset());
        return name;
    }

    private String demangledSig(Function f) {
        try {
            return f.getSignature().getSignatureString();
        } catch (Exception e) {
            return f.getName();
        }
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
        List<List<String>> sccAdj = new ArrayList<>();
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
