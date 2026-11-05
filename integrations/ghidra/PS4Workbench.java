import java.net.URI;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.io.IOException;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.Color;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.ImproperUseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;

public class PS4Workbench extends GhidraScript {
    private Broker broker;

    private static class Broker implements AutoCloseable {
        private final URI endpoint;
        private final String token;
        private final String client;
        private final HttpClient http;
        private String fingerprint;

        Broker(String url, Path tokenPath, String client) throws Exception {
            URI uri = URI.create(url);
            if (!"http".equals(uri.getScheme()) || !"127.0.0.1".equals(uri.getHost()) ||
                uri.getPort() < 1 || uri.getRawUserInfo() != null || uri.getQuery() != null ||
                uri.getFragment() != null || !(uri.getPath().isEmpty() || "/".equals(uri.getPath()))) {
                throw new IllegalArgumentException("Use http://127.0.0.1:PORT");
            }
            if (Files.size(tokenPath) > 1024) {
                throw new IllegalArgumentException("Token file is oversized");
            }
            token = Files.readString(tokenPath).trim();
            if (!token.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid broker token file");
            }
            endpoint = URI.create("http://127.0.0.1:" + uri.getPort() + "/rpc");
            this.client = client;
            ProxySelector direct = new ProxySelector() {
                public List<Proxy> select(URI requested) { return List.of(Proxy.NO_PROXY); }
                public void connectFailed(URI requested, SocketAddress address, IOException error) { }
            };
            http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).proxy(direct).build();
            fingerprint = request("state", new JsonObject()).getAsJsonObject().get("profile_sha256").getAsString();
        }

        JsonElement request(String operation, JsonObject arguments) throws Exception {
            JsonObject envelope = new JsonObject();
            envelope.addProperty("operation", operation);
            envelope.add("arguments", arguments);
            if (fingerprint != null) {
                envelope.addProperty("profile_sha256", fingerprint);
            }
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token).header("X-PS4-Client", client)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(envelope.toString())).build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.body().length() > 8388608) {
                throw new IOException("Broker response exceeds limit");
            }
            JsonObject body = JsonParser.parseString(response.body()).getAsJsonObject();
            if (response.statusCode() != 200 || body.has("error")) {
                throw new IOException(body.has("error") ? body.get("error").getAsString() : "Broker request failed");
            }
            return body.get("result");
        }

        JsonElement call(String name, JsonObject arguments) throws Exception {
            JsonObject request = new JsonObject();
            request.addProperty("name", name);
            request.add("arguments", arguments);
            return request("call", request);
        }

        public void close() {
            http.close();
        }
    }

    private JsonObject fields(String... values) {
        JsonObject result = new JsonObject();
        for (int index = 0; index < values.length; index += 2) {
            result.addProperty(values[index], values[index + 1]);
        }
        return result;
    }

    private String bounded(String value, int maximum) {
        return value.substring(0, Math.min(value.length(), maximum));
    }

    private JsonElement analyze(String operation, JsonObject arguments) throws Exception {
        if (currentProgram == null || currentProgram.isClosed()) {
            throw new IllegalStateException("Open the correct static program first");
        }
        if ("functions".equals(operation)) {
            int offset = arguments.has("offset") ? arguments.get("offset").getAsInt() : 0;
            int limit = arguments.has("limit") ? arguments.get("limit").getAsInt() : 100;
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            JsonArray result = new JsonArray();
            for (int index = 0; iterator.hasNext() && result.size() < limit; index++) {
                Function function = iterator.next();
                if (index >= offset) {
                    result.add(fields("address", "0x" + function.getEntryPoint(), "name", bounded(function.getName(), 256)));
                }
            }
            return result;
        }
        if (operation.startsWith("apply_")) {
            int transaction = currentProgram.startTransaction("PS4 " + operation);
            boolean committed = false;
            try {
                JsonObject report = apply(operation, arguments);
                committed = true;
                return report;
            }
            finally {
                currentProgram.endTransaction(transaction, committed);
            }
        }
        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(arguments.get("address").getAsString());
        if ("xrefs".equals(operation)) {
            int limit = arguments.has("limit") ? arguments.get("limit").getAsInt() : 100;
            JsonArray result = new JsonArray();
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(address);
            while (references.hasNext() && result.size() < limit) {
                Reference reference = references.next();
                result.add(fields("from", "0x" + reference.getFromAddress(), "to", "0x" + reference.getToAddress(),
                                  "type", bounded(reference.getReferenceType().toString(), 64)));
            }
            return result;
        }
        if (!"decompile".equals(operation)) {
            throw new IllegalArgumentException("Unsupported read-only static operation");
        }
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            throw new IllegalArgumentException("No function at static address");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler open failed");
            }
            DecompileResults result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY);
            if (!result.decompileCompleted()) {
                throw new IllegalStateException(result.getErrorMessage());
            }
            String text = result.getDecompiledFunction().getC();
            JsonObject reply = fields("address", "0x" + function.getEntryPoint(), "text", bounded(text, 32768));
            reply.addProperty("truncated", text.length() > 32768);
            return reply;
        }
        finally {
            decompiler.dispose();
        }
    }

    // ---- analysis_apply_* (local database only; batches validated and rebased by the broker) ----------

    private static final String COVERAGE_COMMENT = "PS4 coverage hits=";

    private static final class ApplyReport {
        int applied;
        int skipped;
        int failed;
        final JsonArray errors = new JsonArray();
        final JsonArray unsupported = new JsonArray();

        void error(String where, Exception error) {
            failed++;
            if (errors.size() < 20) {
                JsonObject entry = new JsonObject();
                entry.addProperty("at", where);
                entry.addProperty("error", String.valueOf(error.getMessage()));
                errors.add(entry);
            }
        }

        void unsupported(String feature) {
            JsonElement value = new com.google.gson.JsonPrimitive(feature);
            if (!unsupported.contains(value)) {
                unsupported.add(value);
            }
        }

        boolean lacks(String feature) {
            return unsupported.contains(new com.google.gson.JsonPrimitive(feature));
        }

        JsonObject result() {
            if (applied == 0 && unsupported.size() > 0) {
                throw new UnsupportedOperationException(unsupported + " unsupported by the Ghidra Java agent");
            }
            JsonObject result = new JsonObject();
            result.addProperty("applied", applied);
            result.addProperty("skipped", skipped);
            result.addProperty("failed", failed);
            result.add("errors", errors);
            result.add("unsupported", unsupported);
            return result;
        }
    }

    private Address itemAddress(JsonObject item) {
        if (item.has("address")) {
            return toAddr(Long.parseUnsignedLong(item.get("address").getAsString().replaceFirst("^0x", ""), 16));
        }
        long rva = Long.parseUnsignedLong(item.get("rva").getAsString().replaceFirst("^0x", ""), 16);
        return currentProgram.getImageBase().addWrap(rva);
    }

    private static boolean isDefaultName(Symbol symbol) {
        return symbol == null || symbol.getSource() == SourceType.DEFAULT;
    }

    private boolean flag(JsonObject arguments, String key) {
        return arguments.has(key) && arguments.get(key).getAsBoolean();
    }

    private JsonObject apply(String operation, JsonObject arguments) throws Exception {
        ApplyReport report = new ApplyReport();
        switch (operation) {
            case "apply_symbols": applySymbols(arguments, report); break;
            case "apply_prototypes": applyPrototypes(arguments, report); break;
            case "apply_struct": applyStruct(arguments, report); break;
            case "apply_coverage": applyCoverage(arguments, report); break;
            default: throw new IllegalArgumentException("Unsupported apply operation");
        }
        return report.result();
    }

    private void applySymbols(JsonObject arguments, ApplyReport report) {
        boolean overwrite = flag(arguments, "overwrite");
        for (JsonElement element : arguments.getAsJsonArray("symbols")) {
            JsonObject item = element.getAsJsonObject();
            boolean changed = false;
            try {
                Address address = itemAddress(item);
                if (item.has("name")) {
                    String name = item.get("name").getAsString();
                    Symbol current = currentProgram.getSymbolTable().getPrimarySymbol(address);
                    boolean keep = (current != null && current.getName().equals(name)) ||
                        (!isDefaultName(current) && (flag(item, "only_if_unnamed") || !overwrite));
                    if (!keep) {
                        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                        if (function != null) {
                            function.setName(name, SourceType.USER_DEFINED);
                        }
                        else {
                            currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                        }
                        changed = true;
                    }
                }
                if (item.has("comment")) {
                    setEOLComment(address, item.get("comment").getAsString());
                    changed = true;
                }
            }
            catch (Exception error) {
                report.error(item.toString(), error);
                continue;
            }
            if (changed) {
                report.applied++;
            }
            else {
                report.skipped++;
            }
        }
    }

    private Function findFunction(String name) {
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            Object target = symbol.getObject();
            if (target instanceof Function) {
                return (Function) target;
            }
            Function function = currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (function != null) {
                return function;
            }
        }
        return null;
    }

    private void applyPrototypes(JsonObject arguments, ApplyReport report) {
        boolean overwrite = flag(arguments, "overwrite");
        FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
        for (JsonElement element : arguments.getAsJsonArray("prototypes")) {
            JsonObject item = element.getAsJsonObject();
            String name = item.get("name").getAsString();
            Function function = findFunction(name);
            if (function == null && item.has("nid")) {
                function = findFunction(item.get("nid").getAsString());
            }
            if (function == null || (!overwrite && function.getSignatureSource() == SourceType.USER_DEFINED)) {
                report.skipped++;
                continue;
            }
            try {
                FunctionDefinitionDataType signature = parser.parse(function.getSignature(), item.get("declaration").getAsString());
                ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED);
                if (command.applyTo(currentProgram, monitor)) {
                    report.applied++;
                }
                else {
                    report.error(name, new IllegalStateException(String.valueOf(command.getStatusMsg())));
                }
            }
            catch (Exception error) {
                report.error(name, error);
            }
        }
    }

    private static DataType fieldType(String kind, int size) {
        String text = kind == null ? "" : kind.replace(" ", "").toLowerCase();
        if (text.contains("*") && size == 8) {
            return new PointerDataType();
        }
        if (text.equals("float") && size == 4) {
            return new FloatDataType();
        }
        if (text.equals("double") && size == 8) {
            return new DoubleDataType();
        }
        switch (size) {
            case 1: return new ByteDataType();
            case 2: return new WordDataType();
            case 4: return new DWordDataType();
            case 8: return new QWordDataType();
            default: return new ArrayDataType(new ByteDataType(), size, 1);
        }
    }

    private void applyStruct(JsonObject arguments, ApplyReport report) {
        JsonObject definition = arguments.getAsJsonObject("struct");
        String name = definition.get("name").getAsString();
        DataTypeManager manager = currentProgram.getDataTypeManager();
        if (!flag(arguments, "overwrite") && manager.getDataType("/" + name) != null) {
            report.skipped++;
            return;
        }
        try {
            StructureDataType structure = new StructureDataType(name, definition.get("size").getAsInt());
            for (JsonElement element : definition.getAsJsonArray("fields")) {
                JsonObject field = element.getAsJsonObject();
                int size = field.get("size").getAsInt();
                String kind = field.has("type") ? field.get("type").getAsString() : null;
                String comment = field.has("comment") ? field.get("comment").getAsString() : null;
                structure.replaceAtOffset(field.get("offset").getAsInt(), fieldType(kind, size), size,
                                          field.get("name").getAsString(), comment);
            }
            manager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER);
            report.applied++;
        }
        catch (Exception error) {
            report.error(name, error);
        }
    }

    private void applyCoverage(JsonObject arguments, ApplyReport report) {
        boolean clear = flag(arguments, "clear");
        boolean comment = flag(arguments, "comment");
        int rgb = Integer.parseInt(arguments.get("color").getAsString().replaceFirst("^0x", ""), 16);
        Color color = new Color((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
        for (JsonElement element : arguments.getAsJsonArray("blocks")) {
            JsonObject block = element.getAsJsonObject();
            boolean changed = false;
            try {
                Address start = itemAddress(block);
                Address end = start.addWrap(Math.max(block.get("size").getAsLong(), 1) - 1);
                if (!report.lacks("color")) {
                    try {
                        if (clear) {
                            clearBackgroundColor(new AddressSet(start, end));
                        }
                        else {
                            setBackgroundColor(new AddressSet(start, end), color);
                        }
                        changed = true;
                    }
                    catch (ImproperUseException headless) {
                        report.unsupported("color");
                    }
                }
                if (comment) {
                    String existing = getEOLComment(start);
                    if (clear && existing != null && existing.startsWith(COVERAGE_COMMENT)) {
                        setEOLComment(start, null);
                        changed = true;
                    }
                    else if (!clear) {
                        long hits = block.has("hits") ? block.get("hits").getAsLong() : 1;
                        setEOLComment(start, COVERAGE_COMMENT + hits);
                        changed = true;
                    }
                }
            }
            catch (Exception error) {
                report.error(block.toString(), error);
                continue;
            }
            if (changed) {
                report.applied++;
            }
            else {
                report.skipped++;
            }
        }
    }

    private void serveAgent(boolean once) throws Exception {
        JsonObject registration = fields("target", "ghidra", "program", currentProgram.getExecutableSHA256());
        broker.request("agent_register", registration);
        println("Ghidra analysis agent ready. Cancel this script to stop; no PS4 attach performed.");
        try {
            while (!monitor.isCancelled() && !currentProgram.isClosed()) {
                JsonElement pending = broker.request("agent_poll", fields("target", "ghidra"));
                if (pending.isJsonNull()) {
                    Thread.sleep(200);
                    continue;
                }
                JsonObject job = pending.getAsJsonObject();
                JsonObject completion = fields("identifier", job.get("id").getAsString());
                try {
                    completion.add("result", analyze(job.get("operation").getAsString(), job.getAsJsonObject("arguments")));
                }
                catch (Exception error) {
                    completion.addProperty("error", error.toString());
                }
                broker.request("agent_result", completion);
                if (once) {
                    return;
                }
            }
        }
        finally {
            broker.request("agent_unregister", fields("target", "ghidra"));
        }
    }

    private JsonObject processArguments() throws Exception {
        JsonObject arguments = new JsonObject();
        int pid = askInt("PS4 process", "Observed process PID");
        if (pid < 1) {
            throw new IllegalArgumentException("PID must be positive");
        }
        arguments.addProperty("pid", pid);
        return arguments;
    }

    @Override
    protected void run() throws Exception {
        try {
            runWorkbench();
        }
        finally {
            if (broker != null) {
                broker.close();
            }
        }
    }

    private void runWorkbench() throws Exception {
        String[] options = getScriptArgs();
        if (options.length >= 3 && "--agent".equals(options[0])) {
            broker = new Broker(options[1], Path.of(options[2]), "ghidra-agent-" + UUID.randomUUID());
            serveAgent(options.length > 3 && "--once".equals(options[3]));
            return;
        }
        String action = askChoice("PS4 Workbench", "Choose explicit operation", List.of(
            "Serve static-analysis MCP agent", "Session status", "List PS4 processes", "Peek runtime memory",
            "Refresh local static shadow", "Extract PS4 file", "Send qualified BIN payload",
            "Attach process", "Detach process", "List threads", "Read registers", "Halt", "Resume", "Step thread"), "Session status");
        String url = askString("Broker", "Loopback broker URL", "http://127.0.0.1:8765");
        Path tokenPath = askFile("Select profiles/broker-token.local", "Connect").toPath();
        broker = new Broker(url, tokenPath, action.equals("Serve static-analysis MCP agent") ?
                            "ghidra-agent-" + UUID.randomUUID() : "ghidra-console");
        if (action.equals("Serve static-analysis MCP agent")) {
            if (currentProgram == null) {
                throw new IllegalStateException("Open a static module first");
            }
            serveAgent(false);
            return;
        }
        if (action.equals("Session status")) {
            println(broker.request("state", new JsonObject()).toString());
            return;
        }
        String tool;
        JsonObject arguments = new JsonObject();
        switch (action) {
            case "List PS4 processes": tool = "process_list"; break;
            case "Extract PS4 file":
                tool = "ftp_download";
                arguments.addProperty("path", askString("Extract", "Absolute PS4 POSIX file path"));
                break;
            case "Send qualified BIN payload":
                if (!askYesNo("Execute code on PS4?", "Only locally hardware-qualified, hash-allowlisted BINs are accepted. Never retry an uncertain transfer.")) {
                    return;
                }
                tool = "payload_execute";
                arguments = fields("manifest", askString("Payload", "Imported manifest artifact path"),
                                   "sha256", askString("Payload", "Exact tested BIN SHA-256"));
                break;
            case "Attach process":
                tool = "debug_attach";
                arguments = processArguments();
                arguments.addProperty("listen_address", askString("Callback", "PC IPv4 reachable by PS4 on TCP 755"));
                break;
            case "Detach process": tool = "debug_detach"; break;
            case "List threads": tool = "debug_threads"; break;
            case "Read registers":
                tool = "debug_registers";
                arguments.addProperty("thread_id", askInt("Registers", "Observed thread ID"));
                break;
            case "Halt": case "Resume": case "Step thread":
                tool = "debug_control";
                arguments.addProperty("action", action.equals("Halt") ? "halt" : action.equals("Resume") ? "resume" : "step_thread");
                if (action.equals("Step thread")) {
                    arguments.addProperty("thread_id", askInt("Step", "Observed thread ID"));
                }
                break;
            default:
                arguments = processArguments();
                int length = askInt("Memory", "Byte count, 1-8192");
                if (length < 1 || length > 8192) {
                    throw new IllegalArgumentException("Invalid byte count");
                }
                arguments.addProperty("length", length);
                if (action.equals("Peek runtime memory")) {
                    tool = "memory_peek";
                    arguments.addProperty("address", askString("Memory", "Runtime address, e.g. 0x400100"));
                    break;
                }
                if (currentProgram == null || currentAddress == null) {
                    throw new IllegalStateException("Select a static address first");
                }
                String expectedHash = askString("Module identity", "Expected original module SHA-256");
                if (!expectedHash.matches("[0-9a-f]{64}") || !expectedHash.equals(currentProgram.getExecutableSHA256())) {
                    throw new IllegalArgumentException("Static module SHA-256 mismatch");
                }
                long base = Long.parseUnsignedLong(askString("Runtime mapping", "Verified runtime image base, hexadecimal").replaceFirst("^0x", ""), 16);
                long rva = currentAddress.subtract(currentProgram.getImageBase());
                if (rva < 0) {
                    throw new IllegalArgumentException("Selected address is below static image base");
                }
                arguments.addProperty("address", "0x" + Long.toUnsignedString(Math.addExact(base, rva), 16));
                JsonObject capture = broker.call("memory_peek", arguments).getAsJsonObject();
                println(capture.toString());
                if (!askYesNo("Update local analysis only?", "This changes the open Ghidra database, not the PS4 or original binary.")) {
                    return;
                }
                MemoryBlock block = currentProgram.getMemory().getBlock(currentAddress);
                if (block == null || !block.contains(currentAddress.addNoWrap(length - 1))) {
                    throw new IllegalArgumentException("Capture crosses a static memory block");
                }
                byte[] bytes = java.util.HexFormat.of().parseHex(capture.get("hex").getAsString());
                int transaction = currentProgram.startTransaction("PS4 live static shadow");
                boolean committed = false;
                try {
                    currentProgram.getMemory().setBytes(currentAddress, bytes);
                    committed = true;
                }
                finally {
                    currentProgram.endTransaction(transaction, committed);
                }
                return;
        }
        println(broker.call(tool, arguments).toString());
    }
}
