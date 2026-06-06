// Ghidra headless script for read-only function listing and decompilation.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;

public class GhidraDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String queryFile = args.length >= 1 ? args[0] : "/tmp/ghidra_query.txt";
        String outputFile = args.length >= 2 ? args[1] : "/tmp/ghidra_output.txt";

        String query;
        try (BufferedReader reader = new BufferedReader(new FileReader(queryFile))) {
            query = reader.readLine();
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            if (query == null || query.trim().isEmpty()) {
                writer.println("Empty query file");
                return;
            }

            query = query.trim();
            if ("LIST_FUNCS".equals(query)) {
                FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
                for (Function func : funcs) {
                    writer.printf("0x%08x  %s%n", func.getEntryPoint().getOffset(), func.getName());
                }
                return;
            }

            Address addr = currentProgram.getAddressFactory().getAddress(query);
            if (addr == null) {
                writer.printf("Invalid address: %s%n", query);
                return;
            }

            Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (func == null) {
                writer.printf("No function found at address: %s%n", query);
                return;
            }

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            if (result.decompileCompleted()) {
                writer.print(result.getDecompiledFunction().getC());
            } else {
                writer.printf("Decompilation error: %s%n", result.getErrorMessage());
            }
        }
    }
}
