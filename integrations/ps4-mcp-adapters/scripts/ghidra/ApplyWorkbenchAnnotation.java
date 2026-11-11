import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ApplyWorkbenchAnnotation extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open the exact analyzed module first");
        }
        File input = askFile("Select workbench annotation JSON (not its metadata sidecar)", "Open");
        if (Files.size(input.toPath()) > 32768) {
            throw new IllegalArgumentException("Annotation exceeds 32 KiB");
        }
        JsonObject annotation = JsonParser.parseString(
            Files.readString(input.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();
        String expectedHash = annotation.get("module_sha256").getAsString();
        if (!expectedHash.matches("[0-9a-f]{64}") ||
            !expectedHash.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Module SHA-256 differs from loaded program; no edit applied");
        }
        String relative = annotation.get("rva").getAsString();
        if (!relative.matches("0x[0-9a-fA-F]{1,16}")) {
            throw new IllegalArgumentException("Invalid RVA");
        }
        long offset = Long.parseLong(relative.substring(2), 16);
        Address address = currentProgram.getImageBase().addNoWrap(offset);
        if (!currentProgram.getMemory().contains(address)) {
            throw new IllegalArgumentException("RVA is outside the loaded module");
        }
        String symbol = annotation.has("symbol") ? annotation.get("symbol").getAsString() : "";
        if (!symbol.isEmpty() && !symbol.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) {
            throw new IllegalArgumentException("Symbol must be a simple identifier");
        }
        String comment = annotation.get("comment").getAsString();
        if (comment.length() > 8192) {
            throw new IllegalArgumentException("Comment exceeds 8192 characters");
        }
        if (!askYesNo("Apply workbench annotation?", "Address: " + address + "\nSymbol: " + symbol +
                      "\nThis updates the open analysis project, not the console.")) {
            return;
        }
        int transaction = currentProgram.startTransaction("Apply workbench annotation");
        boolean applied = false;
        try {
            String existing = getEOLComment(address);
            if (!setEOLComment(address, (existing == null || existing.isEmpty()) ? comment : existing + "\n" + comment)) {
                throw new IllegalStateException("Ghidra could not apply the comment");
            }
            if (!symbol.isEmpty()) {
                createLabel(address, symbol, true);
            }
            applied = true;
        }
        finally {
            currentProgram.endTransaction(transaction, applied);
        }
        println("Applied annotation at " + address + "; module SHA-256 matched");
    }
}
