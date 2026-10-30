#pragma once

// The sparse RAW adapter consumes one hashed, frozen snapshot. It never reads
// the target process or infers an entry from the selected byte.
namespace ks::ui::detail
{
inline constexpr const char FrozenRawGhidraScript[] = R"KSWORD_RAW_JAVA(// KSword frozen sparse RAW pseudocode adapter. Original implementation.
// @category KSword
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.InputStream;
import java.util.*;

public class GhidraPseudocode extends GhidraScript {
    private static final int MAX_CODE_BYTES = 1024 * 1024;
    private static final int MAX_CAPTURE_BYTES = 1024 * 1024;
    private static final int MAX_BODY_BYTES = 65536;
    private static final int MAX_INSTRUCTIONS = 4096;
    private String progressToken;
    private long capturedBytes;
    private int decodedInstructions;
    private void progress(String stage) { progress(stage, -1, -1); }
    private void progress(String stage, long completed, long total) {
        println("KSWORD_PROGRESS:" + progressToken + ":" + stage + ":" + completed + ":" + total);
    }
    private static String hash(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file)) {
            byte[] block = new byte[65536];
            int count;
            while ((count = input.read(block)) != -1) digest.update(block, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private Address address(String value) {
        if (value == null || value.isEmpty() || value.length() > 16 || !value.matches("[0-9a-fA-F]+"))
            throw new IllegalArgumentException("invalid_address");
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(value, 16));
    }
    private static String hex(Address value) { return Long.toUnsignedString(value.getOffset(), 16); }
    private static String error(Exception failure) {
        String value = failure.getMessage();
        return value != null && Set.of("unsupported_architecture", "invalid_address", "entry_unknown", "snapshot_unreadable",
            "incomplete_control_flow", "analysis_budget_exceeded", "invalid_instruction_data", "timeout",
            "output_limit", "decompilation_failed").contains(value) ? value : "decompilation_failed";
    }
    private JsonObject snapshot(Path file) throws Exception {
        if (Files.size(file) > 2 * 1024 * 1024) throw new IllegalArgumentException("analysis_budget_exceeded");
        JsonObject value = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
        if (value.get("schemaVersion").getAsInt() != 2) throw new IllegalArgumentException("invalid_instruction_data");
        int bits = value.get("addressBits").getAsInt();
        if ((bits != 32 && bits != 64) || bits != currentProgram.getLanguage().getDefaultSpace().getSize() ||
            !currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86"))
            throw new IllegalArgumentException("unsupported_architecture");
        return value;
    }
    private AddressSet body(JsonObject snapshot) throws Exception {
        AddressSet result = new AddressSet();
        long bytes = 0;
        JsonArray ranges = snapshot.getAsJsonArray("bodyRanges");
        if (ranges.size() == 0) throw new IllegalArgumentException("incomplete_control_flow");
        if (ranges.size() > MAX_INSTRUCTIONS) throw new IllegalArgumentException("analysis_budget_exceeded");
        Address previousEnd = null;
        for (JsonElement value : ranges) {
            JsonObject row = value.getAsJsonObject();
            Address start = address(row.get("address").getAsString());
            long length = row.get("length").getAsLong();
            if (length <= 0 || length > MAX_BODY_BYTES || bytes + length > MAX_BODY_BYTES)
                throw new IllegalArgumentException("analysis_budget_exceeded");
            Address end = start.addNoWrap(length - 1);
            if (previousEnd != null && start.compareTo(previousEnd) <= 0)
                throw new IllegalArgumentException("invalid_instruction_data");
            result.add(start, end);
            bytes += length;
            previousEnd = end;
        }
        return result;
    }
)KSWORD_RAW_JAVA"
R"KSWORD_RAW_JAVA(    private boolean dynamicSegment(Instruction instruction) throws Exception {
        for (byte raw : instruction.getBytes()) {
            int value = raw & 255;
            if (value == 0x64 || value == 0x65) return true;
            if (value == 0xf0 || value == 0xf2 || value == 0xf3 || value == 0x66 || value == 0x67 ||
                value == 0x2e || value == 0x36 || value == 0x3e || value == 0x26 ||
                (currentProgram.getLanguage().getDefaultSpace().getSize() == 64 && value >= 0x40 && value <= 0x4f)) continue;
            break;
        }
        return false;
    }
    private void prepare(Path file) throws Exception {
        JsonObject spec = snapshot(file);
        if (!spec.has("entryAddress")) throw new IllegalArgumentException("entry_unknown");
        Address entry = address(spec.get("entryAddress").getAsString());
        Address selected = address(spec.get("selectedAddress").getAsString());
        AddressSet plannedBody = body(spec);
        if (!plannedBody.contains(entry) || !plannedBody.contains(selected))
            throw new IllegalArgumentException("invalid_address");
        var memory = currentProgram.getMemory();
        for (var old : memory.getBlocks()) memory.removeBlock(old, monitor);
        JsonArray segments = spec.getAsJsonArray("segments");
        if (segments.size() == 0) throw new IllegalArgumentException("snapshot_unreadable");
        if (segments.size() > 512) throw new IllegalArgumentException("analysis_budget_exceeded");
        Address previousEnd = null;
        int index = 0;
        for (JsonElement value : segments) {
            monitor.checkCancelled();
            JsonObject row = value.getAsJsonObject();
            Address start = address(row.get("address").getAsString());
            byte[] data = Base64.getDecoder().decode(row.get("bytes").getAsString());
            if (data.length == 0 || capturedBytes + data.length > MAX_CAPTURE_BYTES)
                throw new IllegalArgumentException("analysis_budget_exceeded");
            Address end = start.addNoWrap(data.length - 1);
            if (previousEnd != null && start.compareTo(previousEnd) <= 0)
                throw new IllegalArgumentException("invalid_instruction_data");
            try (var input = new java.io.ByteArrayInputStream(data)) {
                var block = memory.createInitializedBlock("raw_capture_" + index++, start, input, data.length, monitor, false);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(plannedBody.intersects(start, end));
            }
            capturedBytes += data.length;
            previousEnd = end;
        }
        if (!memory.getLoadedAndInitializedAddressSet().contains(plannedBody))
            throw new IllegalArgumentException("snapshot_unreadable");
        // All captured blocks exist before constructing the disassembler, whose
        // executable-memory set is fixed at creation. No target reads occur here.
        Disassembler decoder = Disassembler.getDisassembler(currentProgram, monitor, null);
        var listing = currentProgram.getListing();
        Set<Address> starts = new HashSet<Address>();
        var ranges = plannedBody.getAddressRanges();
        while (ranges.hasNext()) {
            var range = ranges.next();
            Address at = range.getMinAddress();
            while (at != null && at.compareTo(range.getMaxAddress()) <= 0) {
                monitor.checkCancelled();
                if (++decodedInstructions > MAX_INSTRUCTIONS)
                    throw new IllegalArgumentException("analysis_budget_exceeded");
                Instruction containing = listing.getInstructionContaining(at);
                if (containing != null && !containing.getAddress().equals(at))
                    throw new IllegalArgumentException("invalid_instruction_data");
                if (listing.getInstructionAt(at) == null) decoder.disassemble(at, plannedBody, false);
                Instruction instruction = listing.getInstructionAt(at);
                if (instruction == null || instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0)
                    throw new IllegalArgumentException("invalid_instruction_data");
                starts.add(at);
                if (instruction.getMaxAddress().equals(range.getMaxAddress())) break;
                at = instruction.getMaxAddress().next();
            }
        }
        if (!starts.contains(entry)) throw new IllegalArgumentException("invalid_instruction_data");
        // Selected may be any byte within an instruction. Only entry is a seed.
        Instruction selectedInstruction = listing.getInstructionContaining(selected);
        if (selectedInstruction == null || !plannedBody.contains(selectedInstruction.getAddress()))
            throw new IllegalArgumentException("invalid_instruction_data");
        Set<Address> reached = new HashSet<Address>();
        ArrayDeque<Address> queue = new ArrayDeque<Address>();
        queue.add(entry);
        while (!queue.isEmpty()) {
            monitor.checkCancelled();
            Address at = queue.removeFirst();
            if (!reached.add(at)) continue;
            if (!starts.contains(at)) throw new IllegalArgumentException("incomplete_control_flow");
            Instruction instruction = listing.getInstructionAt(at);
            var flow = instruction.getFlowType();
            if (flow.isJump()) {
                if (flow.isComputed() || instruction.getFlows().length == 0)
                    throw new IllegalArgumentException("incomplete_control_flow");
                for (Address target : instruction.getFlows()) {
                    if (!starts.contains(target)) throw new IllegalArgumentException("incomplete_control_flow");
                    queue.add(target);
                }
            }
            Address fallthrough = instruction.getFallThrough();
            if (fallthrough != null) {
                if (!starts.contains(fallthrough)) throw new IllegalArgumentException("incomplete_control_flow");
                queue.add(fallthrough);
            }
            // Direct/static data references are separate captured evidence. Calls
            // are external boundaries and their targets never enter the worklist.
            if (!instruction.getMnemonicString().equalsIgnoreCase("LEA") && !dynamicSegment(instruction))
            for (var reference : instruction.getReferencesFrom()) {
                if (reference.isMemoryReference() && reference.getReferenceType().isData() && reference.getReferenceType().isRead() &&
                    !memory.getLoadedAndInitializedAddressSet().contains(reference.getToAddress()))
                    throw new IllegalArgumentException("snapshot_unreadable");
            }
        }
        if (reached.size() != starts.size()) throw new IllegalArgumentException("incomplete_control_flow");
        currentProgram.getFunctionManager().createFunction(null, entry, plannedBody, SourceType.ANALYSIS);
    }
)KSWORD_RAW_JAVA"
R"KSWORD_RAW_JAVA(    private Address statementAddress(ClangToken token, Function function) {
        ClangNode node = token;
        while (node != null) {
            if (node instanceof ClangStatement) {
                Address value = node.getMinAddress();
                if (value != null && function.getBody().contains(value)) return value;
            }
            node = node.Parent();
        }
        Address value = token.getMinAddress();
        return value != null && function.getBody().contains(value) ? value : null;
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 3 && args[0].equals("prepare")) {
            Path file = Paths.get(args[1]);
            progressToken = args[2];
            JsonObject receipt = new JsonObject();
            receipt.addProperty("snapshotSha256", hash(file));
            try {
                progress("analyzing");
                prepare(file);
                receipt.addProperty("success", true);
            } catch (Exception failure) {
                receipt.addProperty("success", false);
                receipt.addProperty("error", error(failure));
                printerr(error(failure));
            }
            receipt.addProperty("decodedInstructions", decodedInstructions);
            receipt.addProperty("capturedBytes", capturedBytes);
            Files.writeString(Paths.get(file.toString() + ".analysis.json"), receipt.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return;
        }
        if (args.length != 6 || !args[0].equals("decompile")) throw new IllegalArgumentException("invalid_arguments");
        Path file = Paths.get(args[1]), output = Paths.get(args[4]);
        progressToken = args[5];
        Address selected = address(args[2]);
        String digest = hash(file);
        JsonObject json = new JsonObject();
        json.addProperty("schemaVersion", 1);
        json.addProperty("selectedAddress", args[2]);
        json.addProperty("snapshotSha256", digest);
        DecompInterface decompiler = new DecompInterface();
        try {
            progress("locating_function");
            JsonObject receipt = JsonParser.parseString(Files.readString(Paths.get(file.toString() + ".analysis.json"))).getAsJsonObject();
            if (!digest.equals(receipt.get("snapshotSha256").getAsString())) throw new IllegalStateException("decompilation_failed");
            decodedInstructions = receipt.get("decodedInstructions").getAsInt();
            capturedBytes = receipt.get("capturedBytes").getAsLong();
            if (!receipt.get("success").getAsBoolean()) throw new IllegalStateException(receipt.get("error").getAsString());
            JsonObject spec = snapshot(file);
            Address entry = address(spec.get("entryAddress").getAsString());
            if (!selected.equals(address(spec.get("selectedAddress").getAsString()))) throw new IllegalArgumentException("invalid_address");
            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getBody().equals(body(spec)) || !function.getBody().contains(selected))
                throw new IllegalStateException("incomplete_control_flow");
            DecompileOptions options = new DecompileOptions();
            options.setMaxPayloadMBytes(8);
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("decompilation_failed");
            progress("decompiling");
            DecompileResults result = decompiler.decompileFunction(function, Integer.parseInt(args[3]), monitor);
            if (!result.decompileCompleted() || result.getCCodeMarkup() == null)
                throw new IllegalStateException(result.isTimedOut() ? "timeout" : "decompilation_failed");
            if (result.getErrorMessage() != null && !result.getErrorMessage().isEmpty()) printerr(result.getErrorMessage());
            PrettyPrinter printer = new PrettyPrinter(function, result.getCCodeMarkup(), null);
            StringBuilder code = new StringBuilder();
            JsonArray addresses = new JsonArray();
            int rendered = 0;
            progress("rendering", 0, printer.getLines().size());
            for (ClangLine line : printer.getLines()) {
                monitor.checkCancelled();
                code.append(PrettyPrinter.getText(line)).append('\n');
                if (code.length() > MAX_CODE_BYTES) throw new IllegalStateException("output_limit");
                Address minimum = null;
                for (ClangToken token : line.getAllTokens()) {
                    if (token instanceof ClangCommentToken &&
                        (token.getText().contains("Control flow encountered bad instruction data") ||
                         token.getText().contains("Bad instruction - Truncating control flow")))
                        throw new IllegalStateException("invalid_instruction_data");
                    Address value = statementAddress(token, function);
                    if (value != null && (minimum == null || value.compareTo(minimum) < 0)) minimum = value;
                }
                addresses.add(minimum == null ? JsonNull.INSTANCE : new JsonPrimitive(hex(minimum)));
                ++rendered;
                if ((rendered % 16) == 0 || rendered == printer.getLines().size()) progress("rendering", rendered, printer.getLines().size());
            }
            if (code.toString().getBytes(StandardCharsets.UTF_8).length > MAX_CODE_BYTES) throw new IllegalStateException("output_limit");
            json.addProperty("success", true);
            json.addProperty("code", code.toString());
            json.addProperty("functionName", function.getName());
            json.addProperty("functionAddress", hex(entry));
            json.addProperty("boundaryInferred", true);
            json.addProperty("rawControlFlow", true);
            json.addProperty("controlFlowComplete", true);
            json.addProperty("selectedCovered", true);
            json.add("lineAddresses", addresses);
        } catch (Exception failure) {
            json.addProperty("success", false);
            json.addProperty("error", error(failure));
            printerr(error(failure));
        } finally {
            decompiler.dispose();
        }
        json.addProperty("decodedInstructions", decodedInstructions);
        json.addProperty("capturedBytes", capturedBytes);
        Files.writeString(output, json.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
)KSWORD_RAW_JAVA";
}
