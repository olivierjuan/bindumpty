// DetectSourceLang.java — FR-1 aux: detect whether the imported binary was
// built from C or C++ sources, using Ghidra's own analysis (the authority —
// it infers compiler characteristics from the binary itself).
//
// Ghidra signals used (in order of authority):
//   1. program.getLanguage()... compilerSpec / sourceFormat hints
//   2. presence of mangled symbols demangling as Itanium C++ (DemanglerManager)
//   3. RTTI type records in memory (Ghidra creates TypeRecovery datatypes)
//   4. vtable layouts / __vftable symbols from class recovery
//   5. C++-runtime imports (__cxa_throw, __gxx_personality_v0, _Z* symbols)
//
// Output: JSON {verdict, confidence, evidence:[...]}, one line.
//   verdict: "c" | "cpp" | "lean_cpp"  (lean_cpp = C++ without RTTI/exceptions
//            and with hidden visibility — the hardest case)
//
// The Python side (humpty/analyze/detect_lang.py) cross-checks with a cheap
// pre-Ghidra ELF scan; when both agree, confidence is high. The Ghidra
// verdict wins when they disagree (it sees what ELF headers cannot).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.util.*;

public class DetectSourceLang extends GhidraScript {

    private final StringBuilder out = new StringBuilder();

    private void jstr(String s) {
        out.append("\"").append(s == null ? "" :
            s.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
    }

    @Override
    public void run() throws Exception {
        TaskMonitor mon = getMonitor();
        String[] sargs = getScriptArgs();
        String outPath = sargs.length >= 1 ? sargs[0] : "lang_verdict.json";
        Program p = currentProgram;

        double score = 0.0;
        List<String> evidence = new ArrayList<>();

        // 1. Mangled C++ symbols (Itanium ABI) — the strongest signal.
        //    Ghidra demangles as part of analysis; symbols whose display name
        //    differs from their raw name and looks like C++ (contains "::",
        //    "operator", or template brackets) are C++ evidence.
        SymbolIterator syms = p.getSymbolTable().getAllSymbols(true);
        int cxxNamed = 0, checked = 0, mangledRaw = 0;
        String example = null;
        while (syms.hasNext() && checked < 20000) {
            Symbol s = syms.next();
            String raw = s.getName();
            if (raw == null || raw.isEmpty()) continue;
            checked++;
            if (raw.startsWith("_Z") || raw.startsWith("__Z")) {
                mangledRaw++;
                if (cxxNamed == 0) example = raw;
            }
            String dn = s.getName(true); // demangled / display
            if (dn != null && (dn.contains("::") || dn.contains("operator")
                    || dn.contains("<") && dn.contains(">"))) {
                cxxNamed++;
            }
        }
        if (mangledRaw >= 1) {
            score += 3.0;
            evidence.add("mangled_itanium_symbols:" + mangledRaw
                + " e.g." + example);
        } else {
            evidence.add("no_itanium_mangled_symbols");
        }
        if (cxxNamed >= 3) {
            score += 2.0;
            evidence.add("demangled_cxx_names:" + cxxNamed);
        }

        // 2. RTTI recovery artifacts — Ghidra creates these only for C++
        //    binaries with RTTI. Look for the class-recovery category.
        int rttiTypes = 0;
        for (java.util.Iterator<DataType> it = p.getDataTypeManager().getAllDataTypes();
             it.hasNext(); ) {
            DataType dt = it.next();
            CategoryPath cp = dt.getCategoryPath();
            String path = cp.getPath();
            if (path != null && (path.contains("TypeRecovery")
                    || path.contains("RTTI") || path.contains("Vtable"))) {
                rttiTypes++;
                if (rttiTypes >= 10) break;
            }
        }
        if (rttiTypes >= 10) {
            score += 3.0;
            evidence.add("ghidra_rtti_recovery_types:" + rttiTypes);
        }

        // 3. C++ runtime imports in the dynamic symbol table.
        int cxxImports = 0;
        for (Symbol s : p.getSymbolTable().getExternalSymbols()) {
            String n = s.getName();
            if (n.startsWith("__gxx") || n.startsWith("__cxa_")
                    || n.startsWith("_ZT") || n.startsWith("_Zd")
                    || n.startsWith("_Zn")) {
                cxxImports++;
            }
        }
        if (cxxImports >= 2) {
            score += 2.0;
            evidence.add("cxx_runtime_imports:" + cxxImports);
        } else if (cxxImports == 0) {
            score -= 0.5;
            evidence.add("no_cxx_runtime_imports");
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
        for (int i = 0; i < evidence.size(); i++) {
            if (i > 0) json.append(",");
            jstr(evidence.get(i));
        }
        json.append("]}\n");

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(json.toString());
        }
        println("DetectSourceLang: " + json);
    }
}
