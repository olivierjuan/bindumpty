// DecompileFunction.java — D2.2: on-demand decompilation via Ghidra.
//
// Script args: [0]=output JSON path, [1]=function name (optional — without
// it decompiles ALL functions). Uses Ghidra's DecompInterface to produce
// C pseudo-code per function. Output: JSON {name: decompiled_code}.
//
// Run inside a persistent project (D1.1) so analysis is already done.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.util.*;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] sargs = getScriptArgs();
        String outPath = sargs.length >= 1 ? sargs[0] : "decompiled.json";
        String target = sargs.length >= 2 ? sargs[1] : null;

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        di.setSimplificationStyle("decompile");

        StringBuilder json = new StringBuilder("{\n");
        boolean first = true;
        int count = 0;

        for (FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function f = it.next();
            String name = f.getName();
            if (target != null && !name.equals(target)) continue;

            DecompileResults results = di.decompileFunction(f, 30, getMonitor());
            String code;
            if (results != null && results.decompileCompleted()) {
                code = results.getDecompiledFunction() != null
                        ? results.getDecompiledFunction().getC()
                        : "// decompilation produced no output";
            } else {
                code = "// decompilation failed: " +
                        (results != null ? results.getErrorMessage() : "unknown");
            }
            if (!first) json.append(",\n");
            first = false;
            json.append("\"").append(name.replace("\\", "\\\\")
                    .replace("\"", "\\\"")).append("\": ")
                .append("\"").append(code.replace("\\", "\\\\")
                    .replace("\"", "\\\"").replace("\n", "\\n")).append("\"");
            count++;
            if (target != null) break;
        }
        json.append("\n}\n");

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(json.toString());
        }
        println("DecompileFunction: " + count + " functions → " + outPath);
    }
}
