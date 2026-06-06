from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import FileReader, FileWriter, BufferedReader, PrintWriter

args = getScriptArgs()
if len(args) >= 2:
    QUERY_FILE = args[0]
    OUTPUT_FILE = args[1]
else:
    QUERY_FILE = "/tmp/ghidra_query.txt"
    OUTPUT_FILE = "/tmp/ghidra_output.txt"

monitor = ConsoleTaskMonitor()

reader = BufferedReader(FileReader(QUERY_FILE))
addr_str = reader.readLine()
reader.close()

if addr_str is None:
    raise RuntimeError("Empty query file")

addr_str = addr_str.strip()

writer = PrintWriter(FileWriter(OUTPUT_FILE))

if addr_str == "LIST_FUNCS":
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    for func in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
        entry = func.getEntryPoint()
        name = func.getName()
        writer.println("0x%08x  %s" % (entry.getOffset(), name))
else:
    try:
        addr = currentProgram.getAddressFactory().getAddress(addr_str)
    except Exception as e:
        writer.println("Invalid address: %s (%s)" % (addr_str, str(e)))
        writer.close()
        raise RuntimeError("Bad address")

    func = currentProgram.getFunctionManager().getFunctionContaining(addr)

    if func is None:
        writer.println("No function found at address: %s" % addr_str)
    else:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, 30, monitor)

        if result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            writer.print(c_code)
        else:
            writer.println("Decompilation error: %s" % result.getErrorMessage())

writer.close()
