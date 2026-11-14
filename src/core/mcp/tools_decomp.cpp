// src/core/mcp/tools_decomp.cpp
// tool: decomp (hyperion decompiler)

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

json tool_decomp(const json& args) {
    const std::string action = require_action(args);
    if (action != "function") fail("decomp: unknown action");

    const uint64_t va = parse_addr(args, "addr");

    // wait for analysis without holding the lock, fail soft so the agent can poll
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(10);
        for (;;) {
            {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                if (!bin0.ready)
                    fail("no image loaded in reverse-slop (see disasm.loaded)");
                if (!bin0.hype) fail("hyperion engine unavailable for this image");
                if (bin0.hype->ready()) break;
                // cancelled or failed means waiting is pointless
                const std::string herr = bin0.hype->error();
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                const std::string herr =
                    bin0.hype ? bin0.hype->error() : std::string{};
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
                fail("hyperion analysis in progress (" +
                     std::to_string(static_cast<int>(bin0.hype
                         ? bin0.hype->progress() * 100 : 0)) +
                     "%), retry shortly");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::lock_guard lk(ds::state_mutex());
    auto& bin = ds::get();
    if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
    if (!bin.hype) fail("hyperion engine unavailable for this image");

    // Fast reject: an unmapped VA can never decompile. Without this the
    // request falls into function lookup + full p-code/SSA lifting on
    // whatever the interval index returns, which wedged the engine.
    // The pe view keeps the ELF link base (often 0) while the session base is
    // where the image actually sits, so translate through the session base;
    // for PE/Mach-O it equals pe.image_base and this is the identity.
    if (!bin.pe.rva_to_offset(static_cast<uint32_t>(va - bin.base)))
        fail("addr 0x" + hex64(va) +
             " is not mapped in the loaded image (base 0x" + hex64(bin.base) +
             ", size_of_image 0x" + hex64(bin.pe.size_of_image) +
             "); pass a VA inside the image (see disasm.pe sections)");

    const bool annotate_bytes = args.value("annotate_bytes", false);

    const hype::Function* f = bin.hype->function_at(va);
    if (!f) fail("no hyperion function contains address " + hex64(va));
    const uint64_t entry = f->entry;

    std::vector<hype::PseudoLine> lines;
    std::string err;
    if (!bin.hype->decompile(va, lines, err)) fail(err);

    // rebuild the stack var table since the emitter inlines them into expressions
    struct var_rec { int64_t off; std::string name; uint32_t width; };
    std::map<int64_t, var_rec> vars;
    for (const auto& [bstart, bb] : f->blocks) {
        (void)bstart;
        for (const auto& in : bb.insns) {
            for (uint8_t i = 0; i < in.op_count; ++i) {
                const auto& op = in.ops[i];
                if (op.type != hype::OpType::Mem) continue;
                const bool x86_stack = bin.is_x86() &&
                    (op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_RBP);
                const bool arm64_stack = bin.arch == disasm::image_arch_t::arm64 &&
                    (op.mem.base == ARM64_REG_SP || op.mem.base == ARM64_REG_X29);
                if (!x86_stack && !arm64_stack) continue;
                const auto it = vars.find(op.mem.disp);
                if (it == vars.end()) {
                    const bool arg = x86_stack && op.mem.base == ZYDIS_REGISTER_RSP &&
                                     op.mem.disp > 0;
                    vars.emplace(op.mem.disp, var_rec{
                        op.mem.disp,
                        (arg ? "arg_" : "var_") +
                            std::to_string(std::abs(op.mem.disp)),
                        op.size});
                }
            }
        }
    }

    json jvars = json::array();
    for (const auto& [off, v] : vars)
        jvars.push_back({{"name", v.name}, {"stack_offset", off},
                         {"width", v.width}});

    // name precedence is user symbol, hyperion name, then the canonical
    // sub_<VA> (disasm::default_function_name)
    std::string fname;
    if (const auto* sym = ds::symbol_for(entry); sym && *sym)
        fname = sym;
    else {
        const auto nit = bin.hype->db().names.find(entry);
        if (nit != bin.hype->db().names.end()) fname = nit->second;
    }
    const std::string sub_name = disasm::default_function_name(entry);
    if (fname.empty()) fname = sub_name;

    // rename the body to match the signature so they agree
    const std::string emitter_name = [&] {
        const auto nit = bin.hype->db().names.find(entry);
        return nit != bin.hype->db().names.end() ? nit->second : sub_name;
    }();
    auto rename_fn = [&](const std::string& text) {
        if (emitter_name.size() < 3 || sub_name.size() < 3)
            return text;
        std::string out = text;
        const auto idch = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        };
        for (const std::string& from : {emitter_name, sub_name}) {
            if (from == fname || from.size() < 3) continue;
            size_t pos = 0;
            while ((pos = out.find(from, pos)) != std::string::npos) {
                const size_t end = pos + from.size();
                const bool word = (pos == 0 || !idch(out[pos - 1])) &&
                                  (end >= out.size() || !idch(out[end]));
                if (word) {
                    out.replace(pos, from.size(), fname);
                    pos += fname.size();
                } else {
                    pos = end;
                }
            }
        }
        return out;
    };

    json jlines = json::array();
    size_t insn_count = 0;
    for (const auto& l : lines) {
        if (l.addr) ++insn_count;
        if (annotate_bytes && l.addr) {
            // prefix each line with its va
            std::ostringstream text;
            text << std::hex << std::uppercase << l.addr << std::dec << ": "
                 << rename_fn(l.text);
            jlines.push_back({{"va", l.addr}, {"text", text.str()}});
        } else {
            jlines.push_back({{"va", l.addr},
                              {"text", std::string(l.indent * 2, ' ') +
                                           rename_fn(l.text)}});
        }
    }

    std::string signature;
    {
        const auto it = bin.hype->db().signatures.find(entry);
        if (it != bin.hype->db().signatures.end()) {
            const auto& s = it->second;
            signature = s.return_type + " " + fname + "(";
            for (size_t i = 0; i < s.param_names.size(); ++i) {
                if (i) signature += ", ";
                signature += s.param_types[i] + " " + s.param_names[i];
            }
            signature += ")";
        } else {
            signature = "void " + fname + "()";
        }
    }

    // one level of inter-procedural types: the callee's parameter types at
    // each direct call site (AnalysisDB::call_arg_types)
    json jcalls = json::array();
    for (const auto& [bstart, bb] : f->blocks) {
        (void)bstart;
        for (const auto& in : bb.insns) {
            if (!in.is_call() || jcalls.size() >= 64) continue;
            const auto cit = bin.hype->db().call_arg_types.find(in.addr);
            if (cit == bin.hype->db().call_arg_types.end()) continue;
            jcalls.push_back({{"va", in.addr}, {"arg_types", cit->second}});
        }
    }

    return {{"ok", true},
            {"engine", "hyperion"},
            {"signature", signature},
            {"callconv", hype::callconv_name(f->callconv)},
            {"function_va", entry},
            {"insn_count", insn_count},
            {"vars", jvars},
            {"call_sites", jcalls},
            {"types_generation", re::type_catalog::generation()},
            {"lines", jlines}};
}

} // namespace slop::core::mcp::detail
