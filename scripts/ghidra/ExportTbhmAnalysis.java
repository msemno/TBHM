// TBHM v3.9.7.5 universal Ghidra export. Static analysis only.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class ExportTbhmAnalysis extends GhidraScript {
    private String esc(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.toString();
    }

    private String q(String value) { return "\"" + esc(value) + "\""; }

    private String varnodeJson(Varnode node) {
        if (node == null) return "null";
        String space = node.getAddress() == null ? "" : node.getAddress().getAddressSpace().getName();
        String address = node.getAddress() == null ? "" : node.getAddress().toString();
        return "{\"address\":" + q(address) +
            ",\"space\":" + q(space) +
            ",\"size\":" + node.getSize() +
            ",\"constant\":" + node.isConstant() +
            ",\"register\":" + node.isRegister() +
            ",\"unique\":" + node.isUnique() +
            ",\"address_tied\":" + node.isAddrTied() + "}";
    }

    private String variableJson(Variable variable) {
        return "{\"name\":" + q(variable.getName()) +
            ",\"type\":" + q(variable.getDataType() == null ? "" : variable.getDataType().getDisplayName()) +
            ",\"length\":" + variable.getLength() +
            ",\"storage\":" + q(variable.getVariableStorage() == null ? "" : variable.getVariableStorage().toString()) + "}";
    }

    private String parameterJson(Parameter parameter) {
        return "{\"name\":" + q(parameter.getName()) +
            ",\"ordinal\":" + parameter.getOrdinal() +
            ",\"type\":" + q(parameter.getDataType() == null ? "" : parameter.getDataType().getDisplayName()) +
            ",\"length\":" + parameter.getLength() +
            ",\"storage\":" + q(parameter.getVariableStorage() == null ? "" : parameter.getVariableStorage().toString()) + "}";
    }

    private String pcodeJson(PcodeOpAST op) {
        StringBuilder row = new StringBuilder();
        row.append("{\"address\":").append(q(op.getSeqnum().getTarget().toString()));
        row.append(",\"order\":").append(op.getSeqnum().getTime());
        row.append(",\"opcode\":").append(op.getOpcode());
        row.append(",\"mnemonic\":").append(q(op.getMnemonic()));
        row.append(",\"output\":").append(varnodeJson(op.getOutput()));
        row.append(",\"inputs\":[");
        for (int i = 0; i < op.getNumInputs(); i++) {
            if (i > 0) row.append(',');
            row.append(varnodeJson(op.getInput(i)));
        }
        row.append(']');
        if ((op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) && op.getNumInputs() > 0) {
            row.append(",\"callee\":").append(q(op.getInput(0).getAddress().toString()));
        }
        row.append('}');
        return row.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("output JSON path required");
        File output = new File(args[0]);
        int maxFunctions = args.length > 1 ? Math.max(1, Integer.parseInt(args[1])) : 20000;
        int timeoutSeconds = args.length > 2 ? Math.max(1, Integer.parseInt(args[2])) : 60;

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler failed to open program: " + decompiler.getLastMessage());
        }

        Listing listing = currentProgram.getListing();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(
            new FileOutputStream(output), StandardCharsets.UTF_8));
        try {
            writer.print("{\"schema\":\"ghidra-tbhm/2.0\"");
            writer.print(",\"tool\":\"ghidra\"");
            writer.print(",\"program\":" + q(currentProgram.getName()));
            writer.print(",\"path\":" + q(currentProgram.getExecutablePath()));
            writer.print(",\"format\":" + q(currentProgram.getExecutableFormat()));
            writer.print(",\"language\":" + q(currentProgram.getLanguageID().toString()));
            writer.print(",\"architecture\":" + q(currentProgram.getLanguage().getProcessor().toString()));
            writer.print(",\"endianness\":" + q(currentProgram.getLanguage().isBigEndian() ? "big" : "little"));
            writer.print(",\"compiler\":" + q(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            writer.print(",\"image_base\":" + q(currentProgram.getImageBase().toString()));
            writer.print(",\"functions\":[");

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            boolean firstFunction = true;
            int count = 0;
            while (functions.hasNext() && !monitor.isCancelled() && count < maxFunctions) {
                Function function = functions.next();
                count++;
                if (!firstFunction) writer.print(',');
                firstFunction = false;

                Address start = function.getEntryPoint();
                Address end = function.getBody().getMaxAddress();
                writer.print("{\"name\":" + q(function.getName()));
                writer.print(",\"namespace\":" + q(function.getParentNamespace().getName(true)));
                writer.print(",\"address\":" + q(start.toString()));
                writer.print(",\"end\":" + q(end == null ? start.toString() : end.toString()));
                writer.print(",\"size\":" + function.getBody().getNumAddresses());
                writer.print(",\"external\":" + function.isExternal());
                writer.print(",\"thunk\":" + function.isThunk());
                writer.print(",\"calling_convention\":" + q(function.getCallingConventionName()));
                writer.print(",\"return_type\":" + q(function.getReturnType() == null ? "" : function.getReturnType().getDisplayName()));

                writer.print(",\"parameters\":[");
                Parameter[] parameters = function.getParameters();
                for (int i = 0; i < parameters.length; i++) {
                    if (i > 0) writer.print(',');
                    writer.print(parameterJson(parameters[i]));
                }
                writer.print(']');

                writer.print(",\"locals\":[");
                Variable[] locals = function.getLocalVariables();
                for (int i = 0; i < locals.length; i++) {
                    if (i > 0) writer.print(',');
                    writer.print(variableJson(locals[i]));
                }
                writer.print(']');

                writer.print(",\"calls\":[");
                boolean firstCall = true;
                for (Function called : function.getCalledFunctions(monitor)) {
                    if (!firstCall) writer.print(',');
                    firstCall = false;
                    writer.print("{\"name\":" + q(called.getName()) +
                        ",\"address\":" + q(called.getEntryPoint().toString()) + "}");
                }
                writer.print(']');

                writer.print(",\"callers\":[");
                boolean firstCaller = true;
                for (Function caller : function.getCallingFunctions(monitor)) {
                    if (!firstCaller) writer.print(',');
                    firstCaller = false;
                    writer.print("{\"name\":" + q(caller.getName()) +
                        ",\"address\":" + q(caller.getEntryPoint().toString()) + "}");
                }
                writer.print(']');

                writer.print(",\"basic_blocks\":[");
                boolean firstBlock = true;
                CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
                while (blocks.hasNext() && !monitor.isCancelled()) {
                    CodeBlock block = blocks.next();
                    if (!firstBlock) writer.print(',');
                    firstBlock = false;
                    writer.print("{\"start\":" + q(block.getFirstStartAddress().toString()) +
                        ",\"end\":" + q(block.getMaxAddress().toString()) +
                        ",\"size\":" + block.getNumAddresses() + "}");
                }
                writer.print(']');

                writer.print(",\"strings\":[");
                boolean firstString = true;
                writer.print("");
                InstructionIterator instructionIterator = listing.getInstructions(function.getBody(), true);
                while (instructionIterator.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructionIterator.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        Data data = listing.getDataAt(reference.getToAddress());
                        if (data != null && data.hasStringValue()) {
                            if (!firstString) writer.print(',');
                            firstString = false;
                            Object value = data.getValue();
                            writer.print("{\"address\":" + q(reference.getToAddress().toString()) +
                                ",\"from\":" + q(instruction.getAddress().toString()) +
                                ",\"value\":" + q(value == null ? "" : value.toString()) + "}");
                        }
                    }
                }
                writer.print(']');

                writer.print(",\"globals\":[");
                boolean firstGlobal = true;
                instructionIterator = listing.getInstructions(function.getBody(), true);
                while (instructionIterator.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructionIterator.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        if (reference.getReferenceType().isData()) {
                            if (!firstGlobal) writer.print(',');
                            firstGlobal = false;
                            writer.print("{\"from\":" + q(instruction.getAddress().toString()) +
                                ",\"address\":" + q(reference.getToAddress().toString()) +
                                ",\"type\":" + q(reference.getReferenceType().toString()) + "}");
                        }
                    }
                }
                writer.print(']');

                DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);
                writer.print(",\"decompile_completed\":" + results.decompileCompleted());
                writer.print(",\"decompile_message\":" + q(results.getErrorMessage()));
                String cCode = "";
                if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                    cCode = results.getDecompiledFunction().getC();
                }
                writer.print(",\"decompiled_c\":" + q(cCode));

                writer.print(",\"pcode\":[");
                boolean firstPcode = true;
                HighFunction highFunction = results.getHighFunction();
                if (highFunction != null) {
                    Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
                    int pcodeCount = 0;
                    while (operations.hasNext() && !monitor.isCancelled() && pcodeCount < 200000) {
                        PcodeOpAST operation = operations.next();
                        if (!firstPcode) writer.print(',');
                        firstPcode = false;
                        writer.print(pcodeJson(operation));
                        pcodeCount++;
                    }
                }
                writer.print("]}");
                writer.flush();
            }

            writer.print("],\"imports\":[");
            SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
            boolean first = true;
            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();
                if (!first) writer.print(',');
                first = false;
                writer.print("{\"name\":" + q(symbol.getName()) +
                    ",\"address\":" + q(symbol.getAddress().toString()) +
                    ",\"namespace\":" + q(symbol.getParentNamespace().getName(true)) + "}");
            }
            writer.print("],\"export_complete\":" + (!monitor.isCancelled()) + "}");
        }
        finally {
            writer.close();
            decompiler.dispose();
        }
    }
}
