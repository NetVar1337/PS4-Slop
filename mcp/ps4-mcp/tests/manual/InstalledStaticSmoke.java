import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class InstalledStaticSmoke extends GhidraScript {
    @Override
    protected void run() throws Exception {
        JsonObject report = new JsonObject();
        DecompInterface decompiler = new DecompInterface();
        try {
            Function function = currentProgram.getFunctionManager().getFunctions(true).next();
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Could not open test program");
            }
            DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
            if (!result.decompileCompleted()) {
                throw new IllegalStateException(result.getErrorMessage());
            }
            report.addProperty("passed", true);
            report.addProperty("sha256", currentProgram.getExecutableSHA256());
            report.addProperty("function", function.getName());
            report.addProperty("address", function.getEntryPoint().toString());
            report.addProperty("decompilation", result.getDecompiledFunction().getC());
        }
        catch (Exception error) {
            report.addProperty("passed", false);
            report.addProperty("error", error.toString());
        }
        finally {
            decompiler.dispose();
        }
        Files.writeString(Path.of(getScriptArgs()[0]), report.toString(), StandardCharsets.UTF_8);
    }
}
