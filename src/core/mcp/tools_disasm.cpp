// src/core/mcp/tools_disasm.cpp
// tool: disasm (load/decode/functions/xrefs/strings/assemble)

#include "core/mcp/tools_common.hpp"
#include "core/compat/portable.hpp"

namespace slop::core::mcp::detail {

namespace {


const char* disasm_flow_name(disasm::flow_t f) {
    switch (f) {
    case disasm::flow_t::none: return "none";
    case disasm::flow_t::call: return "call";
    case disasm::flow_t::jmp:  return "jmp";
    case disasm::flow_t::jcc:  return "jcc";
    case disasm::flow_t::ret:  return "ret";
    }
    return "unknown";
}

const char* xref_kind_name(disasm::xref_kind_t k) {
    switch (k) {
    case disasm::xref_kind_t::call: return "call";
    case disasm::xref_kind_t::jmp:  return "jmp";
    case disasm::xref_kind_t::data: return "data";
    }
    return "unknown";
}

const char* xref_kind_name_hype(hype::XrefType t) {
    switch (t) {
    case hype::XrefType::CodeCall:  return "call";
    case hype::XrefType::CodeJump:  return "jump";
    case hype::XrefType::DataRead:  return "read";
    case hype::XrefType::DataWrite: return "write";
    case hype::XrefType::DataOffset: return "offset";
    default:                         return "other";
    }
}

// turns text like mov rax, [rbx+8] into an encoder request
std::string assemble_one(const std::string& text, uint64_t addr,
                         ZydisEncoderRequest& out) {
    out = {};
    out.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    out.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;

    // split on spaces, commas and mem-operand operators so
    // "[rbx+8]", "[rax+rcx*4-0x10]" tokenize into separate atoms
    std::vector<std::string> tokens;
    std::string cur;
    auto flush = [&] {
        // strip stray statement terminators/label colons agents paste in
        while (!cur.empty() && (cur.back() == ';' || cur.back() == ':'))
            cur.pop_back();
        if (!cur.empty()) tokens.push_back(cur);
        cur.clear();
    };
    for (char ch : text + ",") {
        if (ch == ' ' || ch == ',' || ch == '\t' || ch == ';' || ch == ':') {
            flush();
        } else if (ch == '[' || ch == ']' || ch == '+' || ch == '-' || ch == '*') {
            flush();
            tokens.push_back(std::string(1, ch));
        } else {
            cur += static_cast<char>(std::tolower(
                static_cast<unsigned char>(ch)));
        }
    }
    if (tokens.empty()) return "empty instruction";

    // mnemonic lookup
    bool mn_found = false;
    for (int m = 1; m < ZYDIS_MNEMONIC_MAX_VALUE; ++m) {
        const auto mm = static_cast<ZydisMnemonic>(m);
        const char* s = ZydisMnemonicGetString(mm);
        if (s && _stricmp(s, tokens[0].c_str()) == 0) {
            out.mnemonic = mm;
            mn_found = true;
            break;
        }
    }
    if (!mn_found) return "unknown mnemonic '" + tokens[0] + "'";

    // register lookup
    auto find_reg = [](const std::string& n, ZydisRegister* r) {
        for (int i = 1; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
            const auto rr = static_cast<ZydisRegister>(i);
            const char* s = ZydisRegisterGetString(rr);
            if (s && _stricmp(s, n.c_str()) == 0) { *r = rr; return true; }
        }
        return false;
    };

    size_t ti = 1;
    while (ti < tokens.size() &&
           out.operand_count < ZYDIS_MAX_OPERAND_COUNT) {
        const std::string& t = tokens[ti];
        if (t == "[") {
            // memory operand like [base + index*scale + disp]
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_MEMORY;
            op.mem.base = ZYDIS_REGISTER_NONE;
            op.mem.index = ZYDIS_REGISTER_NONE;
            op.mem.scale = 1;
            op.mem.displacement = 0;
            ++ti;
            while (ti < tokens.size() && tokens[ti] != "]") {
                ZydisRegister r = ZYDIS_REGISTER_NONE;
                int64_t sign = 1;
                if (tokens[ti] == "+") { sign = 1; ti++; }
                else if (tokens[ti] == "-") { sign = -1; ti++; }
                if (ti >= tokens.size()) break;
                if (find_reg(tokens[ti], &r)) {
                    if (r == ZYDIS_REGISTER_RIP) {
                        op.mem.base = ZYDIS_REGISTER_RIP;
                        op.mem.displacement =
                            static_cast<int64_t>(addr);
                    } else if (op.mem.base == ZYDIS_REGISTER_NONE)
                        op.mem.base = r;
                    else {
                        op.mem.index = r;
                    }
                    ti++;
                } else {
                    char* end = nullptr;
                    const uint64_t v =
                        std::strtoull(tokens[ti].c_str(), &end, 0);
                    if (end == tokens[ti].c_str())
                        return "bad memory operand '" + tokens[ti] + "'";
                    op.mem.displacement +=
                        sign * static_cast<int64_t>(v);
                    ti++;
                }
                if (ti < tokens.size() && tokens[ti] == "*") {
                    ti++;
                    if (ti < tokens.size())
                        op.mem.scale = static_cast<ZyanU8>(
                            std::strtoul(tokens[ti++].c_str(), nullptr, 0));
                }
            }
            if (ti < tokens.size()) ++ti;   // consume ']'
            continue;
        }

        if (t == "+" || t == "-" || t == "*") {
            // stray operator outside [...] (e.g. signed immediates split
            // by the tokenizer) -- fold a leading sign into the next atom
            if ((t == "+" || t == "-") && ti + 1 < tokens.size() &&
                tokens[ti + 1] != "]" && tokens[ti + 1] != "[" &&
                tokens[ti + 1] != "+" && tokens[ti + 1] != "-" &&
                tokens[ti + 1] != "*") {
                ZydisRegister rr = ZYDIS_REGISTER_NONE;
                const std::string& nx = tokens[ti + 1];
                if (!find_reg(nx, &rr)) {
                    ZydisEncoderOperand& op =
                        out.operands[out.operand_count++];
                    op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                    char* end = nullptr;
                    const int64_t sv = std::strtoll(
                        (t + nx).c_str(), &end, 0);
                    if (end == (t + nx).c_str())
                        return "bad immediate '" + t + nx + "'";
                    op.imm.s = sv;
                    op.imm.u = static_cast<uint64_t>(sv);
                    ti += 2;
                    continue;
                }
            }
            return "unexpected '" + t + "' outside memory operand";
        }

        ZydisRegister r = ZYDIS_REGISTER_NONE;
        if (find_reg(t, &r)) {
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_REGISTER;
            op.reg.value = r;
            ++ti;
            continue;
        }

        // immediate
        ZydisEncoderOperand& op = out.operands[out.operand_count++];
        op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

        {
            char* end = nullptr;
            const uint64_t uv = std::strtoull(t.c_str(), &end, 0);
            if (end == t.c_str()) return "bad operand '" + t + "'";
            op.imm.u = uv;
            op.imm.s = static_cast<int64_t>(uv);
        }
        ++ti;
    }

    // the encoder picks the visibility defaults

    return "";
}

} // namespace

namespace {

// tool: disasm

json insn_to_json(const disasm::insn_t& in) {
    json o = {{"va", in.va}, {"len", in.length}, {"text", in.text},
              {"flow", disasm_flow_name(in.flow)}};
    if (in.has_rel_target) o["target"] = in.rel_target;
    if (in.has_rip_rel)    o["rip_rel"] = in.rip_rel_target;
    return o;
}

} // namespace


json tool_disasm(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no image loaded, a typo isnt a missing binary
    {
        static const char* kKnown[] = {
            "assemble", "disassemble", "loaded", "pe", "functions", "xrefs",
            "strings", "symbols", "symbol_set", "blocks", "globals", "vtables",
            "load", "load_self", "unload", "analyze_stop", "managed",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
                 "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|"
                 "load_self|unload|analyze_stop|managed)");
    }

    if (action == "disassemble") {
        const uint64_t addr = parse_addr(args, "addr");
        const size_t count = std::min<size_t>(args.value("count", 32u), 512u);
        std::vector<uint8_t> buf(count * 16 + 16);
        size_t have = 0;
        hype::Arch arch = hype::Arch::X64;

        // live target first, else the loaded file so you can read with nothing attached
        if (auto s = process::active_session(); s && s->valid()) {
            auto io = s->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (!io.ok) fail("cannot read code range");
            have = io.bytes;
        } else {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (!bin.ready) fail("no target attached and no image loaded in reverse-slop");
            arch = disasm::hype_arch(bin.arch);
            auto off = bin.pe.va_to_offset(addr);
            if (!off) fail("address not mapped in loaded image (base may differ)");
            have = std::min(buf.size(), bin.file.size() - *off);
            std::memcpy(buf.data(), bin.file.data() + *off, have);
        }

        // match the loaded image architecture; live targets keep the x86/x64 path
        const size_t resync_step = (arch == hype::Arch::X86 || arch == hype::Arch::X64)
            ? 1 : 4;
        json arr = json::array();
        size_t off = 0;
        size_t resync_skip = 0;
        disasm::insn_t insn;
        for (size_t i = 0; i < count && off + 1 < have; ++i) {
            if (!hs::session_t::decode(addr + off, buf.data() + off,
                                       have - off, insn, arch)) {
                off += resync_step;
                resync_skip += resync_step;
                if (resync_skip >= 64) break;  // too much garbage, bail
                --i;  // resync bytes arent instructions
                continue;
            }
            resync_skip = 0;
            arr.push_back(insn_to_json(insn));
            off += insn.length ? insn.length : resync_step;
        }
        return {{"instructions", arr}, {"count", arr.size()},
                {"engine", "hyperion"}};
    }

    if (action == "assemble") {
        {
            std::lock_guard lk(ds::state_mutex());
            const auto& bin = ds::get();
            if (bin.ready) require_x86_image(bin.arch, bin.format, "disasm.assemble");
        }
        // one or more instructions, separated by ';' or newlines:
        // "xor eax, eax; ret"
        if (!args.contains("text") || !args.at("text").is_string())
            fail("missing text (instruction mnemonic + operands)");
        const std::string all_text = args.at("text").get<std::string>();
        const uint64_t base_va = args.contains("base")
            ? parse_addr(args, "base") : 0x400000;

        // split into statements on ';' and newlines, drop empties/comments
        std::vector<std::string> stmts;
        {
            std::string cur;
            for (char ch : all_text) {
                if (ch == ';' || ch == '\n' || ch == '\r') {
                    // strip // comments
                    auto cpos = cur.find("//");
                    if (cpos != std::string::npos) cur.resize(cpos);
                    size_t b = cur.find_first_not_of(" \t");
                    size_t e = cur.find_last_not_of(" \t");
                    if (b != std::string::npos)
                        stmts.push_back(cur.substr(b, e - b + 1));
                    cur.clear();
                } else {
                    cur.push_back(ch);
                }
            }
            auto cpos = cur.find("//");
            if (cpos != std::string::npos) cur.resize(cpos);
            size_t b = cur.find_first_not_of(" \t");
            size_t e = cur.find_last_not_of(" \t");
            if (b != std::string::npos)
                stmts.push_back(cur.substr(b, e - b + 1));
        }
        if (stmts.empty()) fail("empty instruction");
        if (stmts.size() > 64) fail("too many instructions (max 64 per call)");

        std::vector<uint8_t> out_bytes;
        json lines = json::array();
        for (size_t si = 0; si < stmts.size(); ++si) {
            ZydisEncoderRequest req{};
            std::string parse_err = assemble_one(stmts[si], base_va + out_bytes.size(), req);
            if (!parse_err.empty())
                fail("statement " + std::to_string(si + 1) + " '" + stmts[si] +
                     "': " + parse_err);
            uint8_t buf[16];
            ZyanUSize encoded_len = sizeof(buf);
            if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf,
                                                          &encoded_len)))
                fail("statement " + std::to_string(si + 1) + " '" + stmts[si] +
                     "': encode failed (" + std::string(ZydisMnemonicGetString(req.mnemonic) ?
                         ZydisMnemonicGetString(req.mnemonic) : "?") +
                     " with " + std::to_string(req.operand_count) + " operands)");
            out_bytes.insert(out_bytes.end(), buf, buf + encoded_len);
            lines.push_back({{"text", stmts[si]},
                             {"bytes", to_hex(buf, static_cast<size_t>(encoded_len))},
                             {"length", static_cast<uint64_t>(encoded_len)}});
        }
        json out = {{"bytes", to_hex(out_bytes.data(), out_bytes.size())},
                    {"length", static_cast<uint64_t>(out_bytes.size())},
                    {"count", stmts.size()}};
        if (stmts.size() > 1) out["lines"] = lines;
        return out;
    }

    if (action == "loaded") {
        json out = loaded_image_json();
        if (!out.value("ready", false)) {
            out["hint"] = "open a binary in the Disassembly view, attach a target and "
                          "use target.modules to find one, or pass an explicit 'path'";
        }
        out["target"] = attached_target_json();
        return out;
    }

    if (action == "symbols") {
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
        // User renames win; Hyperion analyzer names (RTTI/vtable/thunk/sig)
        // fill the rest so this matches analyze.signatures' named_functions
        // instead of reporting 0 on a fresh image.
        std::map<uint64_t, std::pair<std::string, std::string>> merged;
        {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                for (const auto& [va, name] : bin.hype->db().names) {
                    if (name.find("j_") == 0 || name.find("__imp_") == 0) continue;
                    merged[va] = {name, "hyperion"};
                }
            }
        }
        for (const auto& [va, name] : ds::symbols_snapshot())
            merged[va] = {name, "user"};
        json arr = json::array();
        for (const auto& [va, pr] : merged) {
            if (arr.size() >= limit) break;
            arr.push_back({{"va", va}, {"name", pr.first}, {"source", pr.second}});
        }
        json out = {{"symbols", arr}, {"count", arr.size()},
                    {"total", merged.size()},
                    {"note", "user renames (source=user) override hyperion analyzer "
                             "names (source=hyperion); same source as "
                             "analyze.signatures named_functions"}};
        if (merged.size() > arr.size()) out["truncated"] = true;
        return out;
    }

    if (action == "symbol_set") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("name") || !args.at("name").is_string())
            fail("missing 'name' string (empty clears)");
        const std::string name = args.at("name").get<std::string>();
        if (!ds::has_binary()) fail("no image loaded in reverse-slop");
        ds::set_symbol(addr, name);   // saved, the ui sees it instantly
        return {{"va", addr}, {"name", name}, {"cleared", name.empty()}};
    }

    if (action == "load") {
        // same as opening a file in the ui, kicks off the background analysis
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path");
        const std::string path = args.at("path").get<std::string>();
        const uint64_t base_override = args.contains("base") ? parse_addr(args, "base") : 0;
        // ELF/SELF files are unrelocated on disk; memory dumps are not
        const bool relocate = args.value("relocate", true);
        if (!ds::load_file(path, base_override, relocate))
            fail("failed to load " + path + ": " + ds::last_load_error());
        json out                = loaded_image_json();
        out["ok"]               = true;
        {
            std::lock_guard lk(ds::state_mutex());
            const auto& bin = ds::get();
            if (bin.format == disasm::image_format_t::elf ||
                bin.format == disasm::image_format_t::self)
                out["relocations_applied"] = bin.relocations_applied;
        }
        out["hype_wait_hint"]   = "poll disasm.loaded -> hype.ready for the "
                                  "decompiler/analyzer DB";
        return out;
    }
    if (action == "load_self") {
        // PS4 SELF: retail eboot.bin/.sprx carry encrypted segments whose keys
        // never leave the console. The loadable source is the decrypted image
        // (target.ps4_dump_module from live memory, or fpkg tooling); this
        // action either loads that dump or explains exactly how to get one.
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path (the SELF to inspect, e.g. eboot.bin)");
        const std::string path = args.at("path").get<std::string>();
        const std::string dump = args.value("decrypted_dump", std::string{});
        const uint64_t base_override = args.contains("base") ? parse_addr(args, "base") : 0;
        const bool relocate = args.value("relocate", true);
        const std::string source = dump.empty() ? path : dump;

        if (!ds::load_file(source, base_override, relocate)) {
            const std::string err = ds::last_load_error();
            if (err.find("encrypted SELF") != std::string::npos)
                fail("cannot load " + path + ": " + err +
                     ". Pass decrypted_dump=<decrypted ELF> after dumping the module "
                     "from live console memory with target.ps4_dump_module "
                     "{name:'eboot.bin', path:'C:/dumps/eboot.bin', load:false}, or "
                     "extract it from an fpkg with a decrypted eboot (see "
                     "docs/encrypted-self.md)");
            fail("failed to load " + source + ": " + err);
        }
        json out = loaded_image_json();
        out["ok"]           = true;
        out["loaded_from"]  = source;
        out["decrypted_dump_used"] = !dump.empty();
        out["hype_wait_hint"] = "poll disasm.loaded -> hype.ready for the "
                                "decompiler/analyzer DB";
        return out;
    }

    if (action == "unload") {
        ds::unload();
        return {{"ok", true}, {"ready", false}};
    }

    if (action == "analyze_stop") {
        // cooperative cancel, the analyzer checks between phases so this returns fast
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded (see disasm.loaded)");
        if (!bin.hype)  fail("hyperion engine unavailable for this image");
        if (bin.hype->ready())
            return {{"stopped", false}, {"ready", true},
                    {"note", "analysis already complete"}};
        const std::string herr = bin.hype->error();
        if (!herr.empty())
            return {{"stopped", false}, {"ready", false},
                    {"reason", herr},
                    {"note", "analysis is not running, " + herr +
                     " (re-run disasm.load to restart)"}};
        const float at = bin.hype->progress();
        bin.hype->stop();
        return {{"stopped", true}, {"progress_at_stop", at},
                {"note", "analysis cancelled, decompiler/analyzer actions "
                 "report not-ready; re-run disasm.load to restart analysis"}};
    }

    if (action == "managed") {
        // .NET/CLI model of the loaded image, populated by hyperion when the
        // PE carries a COR20 header (see hype.managed in disasm.loaded)
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded (see disasm.loaded)");
        if (!bin.hype)  fail("hyperion engine unavailable for this image");
        if (!bin.hype->ready())
            fail("analysis still running (poll disasm.loaded -> hype.ready)");
        if (!bin.hype->is_dotnet())
            return {{"managed", false},
                    {"note", "loaded image is not a .NET/CLI assembly (no COR20 header)"}};
        const auto& dn = bin.hype->dotnet().image();
        json out = {{"managed", true},
                    {"runtime_version", dn.runtime_version},
                    {"assembly", dn.assembly_name},
                    {"il_only", dn.il_only},
                    {"entry_point_token", dn.entry_point_token},
                    {"types", dn.types.size()},
                    {"methods", dn.methods.size()},
                    {"fields", dn.fields.size()},
                    {"properties", dn.properties.size()},
                    {"events", dn.events.size()}};
        const uint64_t method_token =
            args.contains("method_token") ? parse_addr(args, "method_token") : 0;
        const std::string want_type = args.value("type", std::string{});
        if (method_token != 0) {
            const auto* m = dn.method_by_token(static_cast<uint32_t>(method_token));
            if (!m) fail("method_token is not in the MethodDef table");
            out["method"] = {{"token", m->token}, {"full_name", m->full_name},
                             {"signature", m->signature}, {"entry", m->entry}};
            out["il"] = bin.hype->dotnet().render_method(*m);
        } else if (!want_type.empty()) {
            const hype::DnType* t = nullptr;
            for (const auto& c : dn.types)
                if (icontains(c.full_name, want_type) || icontains(c.name, want_type)) {
                    t = &c;
                    break;
                }
            if (!t) fail("no TypeDef matches '" + want_type + "' (see types_list)");
            out["type"] = {{"token", t->token}, {"full_name", t->full_name},
                           {"kind", t->kind}, {"base_type", t->base_type},
                           {"methods", t->method_tokens.size()},
                           {"fields", t->field_tokens.size()},
                           {"properties", t->property_tokens.size()},
                           {"events", t->event_tokens.size()}};
            out["csharp"] = bin.hype->dotnet().render_type_csharp(*t);
        } else {
            const std::string filter = args.value("type_filter", std::string{});
            const size_t limit = std::min<size_t>(args.value("limit", 200u), 2000u);
            json arr = json::array();
            for (const auto& t : dn.types) {
                if (!filter.empty() && !icontains(t.full_name, filter) &&
                    !icontains(t.name, filter))
                    continue;
                arr.push_back({{"token", t.token},
                               {"full_name", t.full_name},
                               {"kind", t.kind},
                               {"base_type", t.base_type},
                               {"methods", t.method_tokens.size()},
                               {"fields", t.field_tokens.size()}});
                if (arr.size() >= limit) break;
            }
            out["types_list"] = arr;
            out["count"]      = arr.size();
            if (dn.types.size() > arr.size()) out["truncated"] = true;
        }
        return out;
    }

    // static actions over an image file

    // explicit path parses into the private cache, otherwise the app session
    const bool have_path = args.contains("path") && args.at("path").is_string();

    // keep the session pinned while we poke the indexes
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*       pe      = nullptr;
    const std::vector<uint8_t>*     file    = nullptr;
    disasm::function_index_t*       fidx    = nullptr;
    disasm::xref_index_t*           xidx    = nullptr;
    bool*                           fidx_ok = nullptr;   // null => always built
    bool*                           xidx_ok = nullptr;
    const std::unordered_map<uint64_t, std::string>* syms = nullptr;
    const hype::AnalysisDB* hdb = nullptr;   // session analyzer DB when ready
    uint64_t default_base = 0;
    disasm::image_format_t format = disasm::image_format_t::pe;
    disasm::image_arch_t arch = disasm::image_arch_t::x64;
    std::string                     img_name, img_path;

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        if (action == "functions" || action == "xrefs")
            require_x86_image(img.arch, img.format, "disasm." + action, true);
        format = img.format;
        arch = img.arch;
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        fidx_ok = &img.fidx_ok; xidx_ok = &img.xidx_ok;
        img_path = img.path;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
        default_base = img.pe.image_base;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready) fail("no image: pass 'path' or load a binary in reverse-slop "
                             "(see disasm.loaded)");
        // patches dirty the indexes so rebuild them lazily
        if (bin.indexes_dirty &&
            (action == "functions" || action == "xrefs" || action == "strings")) {
            ds::rebuild_indexes_locked(bin);
        }
        // one function set: Hyperion's analysis results fold into the index
        // once it is ready (deduped, marked source=hyperion)
        if (action == "functions" || action == "xrefs" || action == "blocks")
            ds::merge_hype_functions_locked(bin);
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        format = bin.format;
        arch = bin.arch;
        syms = &bin.symbols;
        if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
        img_name = bin.name; img_path = bin.path;
        default_base = bin.base;   // VA base the whole session was built with
    }
    const bool is_x86 = arch == disasm::image_arch_t::x86 ||
                        arch == disasm::image_arch_t::x64;

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : default_base;

    if (action == "pe") {
        json secs = json::array();
        for (const auto& sec : pe->sections) {
            // raw characteristics too so it matches the packer output
            secs.push_back({{"name", sec.name}, {"rva", sec.rva},
                            {"vsize", sec.virtual_size}, {"raw_size", sec.raw_size},
                            {"exec", sec.is_executable()},
                            {"writable", (sec.characteristics & 0x80000000u) != 0},
                            {"characteristics", sec.characteristics}});
        }
        json imps = json::array();
        for (const auto& dll : pe->imports) {
            json fns = json::array();
            for (const auto& fn : dll.functions) fns.push_back(fn.name);
            imps.push_back({{"dll", dll.dll}, {"functions", fns}});
        }
        json exps = json::array();
        for (const auto& e : pe->exports)
            exps.push_back({{"name", e.name}, {"rva", e.rva}, {"ordinal", e.ordinal}});
        return {{"ok", true}, {"image", img_name}, {"pe32plus", pe->pe32plus},
                {"format", disasm::image_format_name(format)},
                {"arch", disasm::image_arch_name(arch)},
                {"image_base", pe->image_base}, {"entry_rva", pe->entry_rva},
                {"size_of_image", pe->size_of_image},
                {"sections", secs}, {"imports", imps}, {"exports", exps}};
    }

    if (action == "functions") {
        if (fidx_ok && !*fidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!fidx->build(*pe, *file, eng, base)) fail("function index build failed");
            *fidx_ok = true;
        }
        const size_t limit  = std::min<size_t>(args.value("limit", 1000u), 10000u);
        const size_t offset = args.value("offset", size_t{0});
        std::string filter  = args.value("filter", std::string{});
        for (char& c : filter) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        // "0x4DDA48" and "4dda48" both match by address
        std::string filter_hex = filter;
        if (filter_hex.rfind("0x", 0) == 0) filter_hex.erase(0, 2);

        const auto& fns = fidx->functions();
        // hyperion adds names and cfg stats on the same rows (hdb from the
        // session setup above)

        // One row per function: the index's starts plus anything only the
        // analyzer recovered (stripped exports, TLS-only entry, packed
        // headers: Hyperion still finds functions via RTTI/vtables/tables)
        struct row_t { uint64_t va; uint64_t size; bool from_index; const char* source; };
        std::vector<row_t> rows;
        rows.reserve(fns.size() + (hdb ? hdb->funcs.size() : 0));
        std::unordered_set<uint64_t> seen;
        for (const auto& fn : fns) {
            rows.push_back({fn.va, fn.size, true,
                            fn.source == disasm::fn_source_t::hyperion
                                ? "hyperion" : "index"});
            seen.insert(fn.va);
        }
        size_t hype_extra = 0;
        if (hdb) {
            for (const auto& [va, hf] : hdb->funcs) {
                (void)hf;
                if (seen.insert(va).second) {
                    rows.push_back({va, 0, false, "hyperion"});
                    ++hype_extra;
                }
            }
        }
        std::sort(rows.begin(), rows.end(),
                  [](const row_t& a, const row_t& b) { return a.va < b.va; });

        // display name: user symbol, then analyzer name, then sub_<VA>
        auto name_of = [&](uint64_t va, const char** source) -> std::string {
            if (syms) {
                const auto it = syms->find(va);
                if (it != syms->end()) { *source = "user"; return it->second; }
            }
            if (hdb) {
                const auto it = hdb->names.find(va);
                if (it != hdb->names.end() && !it->second.empty()) {
                    *source = "hyperion";
                    return it->second;
                }
            }
            *source = "default";
            return disasm::default_function_name(va);
        };
        auto matches = [&](uint64_t va, const std::string& name) {
            if (filter.empty()) return true;
            std::string lname = name;
            for (char& c : lname) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lname.find(filter) != std::string::npos) return true;
            if (filter_hex.empty()) return false;
            char hexbuf[24];
            std::snprintf(hexbuf, sizeof(hexbuf), "%llx", static_cast<unsigned long long>(va));
            return std::string_view(hexbuf).find(filter_hex) != std::string_view::npos;
        };

        json arr = json::array();
        size_t matched = 0;
        for (const auto& r : rows) {
            const char* source = "default";
            std::string name = name_of(r.va, &source);
            if (!matches(r.va, name)) continue;
            const size_t idx = matched++;
            if (idx < offset || arr.size() >= limit) continue;
            json o = {{"va", r.va}, {"name", std::move(name)}, {"name_source", source},
                      {"source", r.source}};
            if (r.from_index) o["size"] = r.size;
            if (std::string_view(source) == "user") o["symbol"] = o["name"];
            if (hdb) {
                const auto fit = hdb->funcs.find(r.va);
                if (fit != hdb->funcs.end()) {
                    const auto& hf = fit->second;
                    o["blocks"]   = hf.blocks.size();
                    o["callconv"] = hype::callconv_name(hf.callconv);
                    if (!hf.loops.empty()) o["loops"] = hf.loops.size();
                    if (hf.noreturn) o["noreturn"] = true;
                }
            }
            arr.push_back(std::move(o));
        }
        const size_t returned = arr.size();
        json out = {{"image", img_name}, {"functions", std::move(arr)},
                    {"total", rows.size()},
                    {"matched", matched},
                    {"returned", returned},
                    {"offset", offset},
                    {"index_total", fns.size()},
                    {"stats", {{"seeds", fidx->stats().seeds},
                               {"recursive_descent", fidx->stats().rd_functions},
                               {"heuristic", fidx->stats().heuristic_fns},
                               {"hyperion", fidx->stats().hype_functions}}}};
        if (!filter.empty()) out["filter"] = filter;
        // explicit either way: total counts every function, so returned < total
        // alone says nothing about this filtered page
        out["truncated"] = offset + returned < matched;
        if (offset + returned < matched) out["next_offset"] = offset + returned;
        if (hdb) {
            out["hype"] = {{"engine", "hyperion"},
                           {"functions", hdb->funcs.size()},
                           {"rtti_classes", [&] {
                               auto& bin = ds::get();
                               return bin.hype ? bin.hype->rtti().classes().size() : 0;
                           }()}};
            if (fns.empty() && hype_extra)
                out["note"] = "function-start index found no functions; rows with "
                              "source=hyperion come from the analyzer DB";
        }
        return out;
    }

    if (action == "xrefs") {
        const uint64_t addr = parse_addr_alias(args, {"addr", "base", "va", "address"});
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
        auto& eng = shared_engine();
        if (is_x86 && !eng.ok() && !eng.init()) fail("zydis engine init failed");

        // hyperion DB is the source on every architecture. For x86/x64, augment
        // it with the legacy index and a RIP-relative LEA sweep: the DB models
        // recognized data, and the legacy index skips high-entropy sections.
        std::map<uint64_t, std::pair<int, std::string>> best; // from -> rank, kind
        std::string engines;
        auto note_engine = [&](const char* e) {
            if (engines.find(e) == std::string::npos) {
                if (!engines.empty()) engines += "+";
                engines += e;
            }
        };

        if (!have_path) {
            auto& bin = ds::get();
            if (bin.hype && bin.hype->ready()) {
                const auto& db = bin.hype->db();
                const auto  it = db.xrefs_to.find(addr);
                // a call emits two records for one instruction, keep the strongest kind
                auto kind_rank = [](hype::XrefType t) {
                    switch (t) {
                    case hype::XrefType::CodeCall:  return 5;
                    case hype::XrefType::CodeJump:  return 4;
                    case hype::XrefType::DataWrite: return 3;
                    case hype::XrefType::DataRead:  return 2;
                    default:                        return 1;
                    }
                };
                if (it != db.xrefs_to.end()) {
                    for (const auto& x : it->second) {
                        const char* k = xref_kind_name_hype(x.type);
                        const int   r = kind_rank(x.type);
                        const auto  b = best.find(x.from);
                        if (b == best.end() || b->second.first < r)
                            best[x.from] = {r, k};
                    }
                    note_engine("hyperion");
                }
            }
        }

        if (is_x86 && xidx_ok && !*xidx_ok) {
            if (!xidx->build(*pe, *file, eng, base)) fail("xref index build failed");
            *xidx_ok = true;
        }
        if (is_x86) {
            bool any = false;
            for (const auto& r : xidx->refs_to(addr)) {
                any = true;
                int rank = 2;
                const char* k = xref_kind_name(r.kind);
                if (r.kind == disasm::xref_kind_t::call) rank = 5;
                else if (r.kind == disasm::xref_kind_t::jmp) rank = 4;
                const auto b = best.find(r.from);
                if (b == best.end() || b->second.first < rank)
                    best[r.from] = {rank, k};
            }
            if (any) note_engine("index");
        }

        // Fallback/augment: decode-sweep executable sections for
        // RIP-relative operands resolving exactly to addr. Catches LEA
        // string/data refs both indexes can miss (unrecognized strings,
        // entropy-skipped packed code). Bounded: 32MB scan, stops at limit.
        size_t scan_hits = 0;
        if (is_x86 && best.size() < limit) {
            size_t scanned = 0;
            constexpr size_t kMaxScan = 32u << 20;
            for (const auto& sec : pe->sections) {
                if (best.size() >= limit || scanned >= kMaxScan) break;
                if (!sec.is_executable() || sec.raw_size == 0) continue;
                auto soff = pe->rva_to_offset(sec.rva);
                if (!soff || *soff + sec.raw_size > file->size()) continue;
                const size_t n = std::min<size_t>(
                    sec.raw_size, kMaxScan - scanned);
                size_t off = 0;
                while (off < n && best.size() < limit) {
                    const uint64_t va = base + sec.rva + off;
                    uint8_t buf[16];
                    const size_t avail = std::min<size_t>(sizeof(buf), n - off);
                    std::memcpy(buf, file->data() + *soff + off, avail);
                    auto in = eng.decode(va, buf, avail, false);
                    if (!in || in->length == 0) { ++off; continue; }
                    if (in->has_rip_rel && in->rip_rel_target == addr &&
                        !best.count(va)) {
                        best[va] = {2, "data"};
                        ++scan_hits;
                    }
                    off += in->length ? in->length : 1;
                }
                scanned += n;
            }
            if (scan_hits) note_engine("lea_scan");
        }

        json arr = json::array();
        for (const auto& [from, rk] : best) {
            if (arr.size() >= limit) break;
            arr.push_back({{"from", from}, {"kind", rk.second}});
        }
        json out = {{"image", img_name}, {"engine", engines.empty() ? "none" : engines},
                    {"refs_to", arr}, {"count", arr.size()},
                    {"total", best.size()}};
        if (best.size() > arr.size()) out["truncated"] = true;
        if (best.empty())
            out["note"] = is_x86
                ? "no refs from hyperion, linear index, or LEA sweep; the address may "
                  "be unreferenced, in an unscanned region, or reached only indirectly (register)"
                : "no refs in the hyperion DB; wait for disasm.loaded hype.ready, or the "
                  "address may be unreferenced or reached only indirectly (register)";
        return out;
    }

    if (action == "strings") {
        const size_t min_chars = std::min<size_t>(args.value("min_chars", 4u), 256u);
        const size_t limit = std::min<size_t>(args.value("limit", 1000u), 10000u);
        // exec sections are garbage on packed code so theyre skipped unless asked for
        const bool include_exec = args.value("include_exec", false);
        // decode: preview high-entropy blobs the code references
        const bool decode = args.value("decode", false);
        json arr = json::array();
        json decoded = json::array();
        disasm::string_stats_t stats{};
        for (const auto& sec : pe->sections) {
            if (sec.virtual_size == 0) continue;
            if (!include_exec && sec.is_executable()) continue;
            auto soff = pe->rva_to_offset(sec.rva);
            if (!soff) continue;
            const size_t len = std::min<uint32_t>(sec.raw_size, sec.virtual_size);
            if (*soff + len > file->size()) continue;
            auto hits = disasm::extract_strings(file->data() + *soff, len,
                                                base + sec.rva, min_chars, limit, &stats);
            for (const auto& h : hits) {
                if (arr.size() >= limit) break;
                arr.push_back({{"va", static_cast<uint64_t>(h.va)},
                               {"text", h.text}, {"utf16", h.utf16}});
            }
            if (arr.size() >= limit) break;

            if (!decode || decoded.size() >= limit) continue;
            // 512-byte windows: only high-entropy blobs, only when some
            // instruction references an address inside the window
            for (size_t boff = 0; boff + 64 <= len; boff += 512) {
                const size_t blen = std::min<size_t>(512, len - boff);
                const uint8_t* bp = file->data() + *soff + boff;
                if (disasm::shannon_entropy(bp, blen) < 7.0) continue;
                const uint64_t bva = base + sec.rva + boff;
                bool referenced = false;
                // xidx is empty for non-x86 sessions and unbuilt path images,
                // in which case refs_to is empty and the hdb check below runs
                for (size_t k = 0; k < blen && !referenced; k += 8)
                    referenced = !xidx->refs_to(bva + k).empty();
                if (!referenced && hdb) {
                    for (size_t k = 0; k < blen && !referenced; k += 8)
                        referenced = hdb->xrefs_to.count(bva + k) != 0;
                }
                if (!referenced) continue;
                for (const auto& c : disasm::decode_candidates(bp, blen, 4)) {
                    decoded.push_back({{"va", bva}, {"scheme", c.scheme},
                                       {"text", c.text}, {"score", c.score}});
                    if (decoded.size() >= limit) break;
                }
                if (decoded.size() >= limit) break;
            }
        }
        json out = {{"image", img_name}, {"strings", arr},
                    {"total_scanned", stats.scanned}, {"truncated", stats.truncated}};
        if (decode) {
            out["decoded"] = decoded;
            out["decoded_count"] = decoded.size();
        }
        return out;
    }

    // hyperion backed actions, shared session only
    // these read the analyzer db which only exists for the app loaded image

    if (action == "blocks" || action == "globals" || action == "vtables") {
        if (have_path)
            fail(action + " requires the app-loaded image (no 'path' support, "
                 "load the binary in reverse-slop first)");
        // the lock above still guards the session
        auto& bin = ds::get();
        if (!bin.hype) fail("hyperion engine unavailable for this image");
        if (!bin.hype->ready()) {
            const std::string herr = bin.hype->error();
            if (!herr.empty())
                fail("hyperion analysis not running, " + herr +
                     " (re-run disasm.load to restart)");
            fail("hyperion analysis in progress (" +
                 std::to_string(static_cast<int>(bin.hype->progress() * 100)) +
                 "%), retry shortly");
        }
        const auto& db = bin.hype->db();

        if (action == "blocks") {
            const uint64_t addr = parse_addr(args, "addr");
            const hype::Function* f = bin.hype->function_at(addr);
            if (!f) fail("no hyperion function contains address " + hex64(addr));
            json arr = json::array();
            // Graph shape for the UI canvas: nodes carry the address range and
            // an instruction summary, edges the successor kind
            // (fallthrough when the target is the block's own end, else branch)
            json nodes = json::array(), edges = json::array();
            for (const auto& [start, bb] : f->blocks) {
                json succs = json::array(), preds = json::array();
                for (auto s : bb.succs) succs.push_back(s);
                for (auto p : bb.preds) preds.push_back(p);
                arr.push_back({{"start", start}, {"end", bb.end},
                               {"size", bb.end - start},
                               {"insn_count", bb.insns.size()},
                               {"succs", succs}, {"preds", preds}});
                std::string summary;
                if (!bb.insns.empty()) {
                    const auto& first = bb.insns.front();
                    summary = first.mnemonic;
                    if (first.op_str[0]) summary += std::string(" ") + first.op_str;
                    if (bb.insns.size() > 1)
                        summary += " ... (" + std::to_string(bb.insns.size()) + " insns)";
                }
                nodes.push_back({{"id", start}, {"start", start}, {"end", bb.end},
                                 {"size", bb.end - start},
                                 {"insn_count", bb.insns.size()},
                                 {"summary", summary}});
                for (auto s : bb.succs)
                    edges.push_back({{"from", start}, {"to", s},
                                     {"kind", s == bb.end ? "fallthrough" : "branch"}});
            }
            json loops = json::array();
            for (const auto& lp : f->loops)
                loops.push_back({{"header", lp.header},
                                 {"back_edge_src", lp.back_edge_src}});
            return {{"ok", true}, {"entry", f->entry},
                    {"name", bin.hype->db().names.count(f->entry)
                                  ? bin.hype->db().names.at(f->entry)
                                  : disasm::default_function_name(f->entry)},
                    {"blocks", arr}, {"count", arr.size()},
                    {"graph", {{"nodes", nodes}, {"edges", edges}}},
                    {"loops", loops}};
        }

        if (action == "vtables") {
            const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
            json arr = json::array();
            for (size_t i = 0; i < db.vtables.size() && arr.size() < limit; ++i) {
                const auto& vt = db.vtables[i];
                json entries = json::array();
                for (auto e : vt.entries) entries.push_back(e);
                arr.push_back({{"va", vt.addr}, {"entries", entries},
                               {"count", vt.entries.size()}});
            }
            json out = {{"ok", true}, {"vtables", arr}, {"count", arr.size()},
                        {"total", db.vtables.size()}};
            if (db.vtables.size() > arr.size()) out["truncated"] = true;
            return out;
        }

        // globals
        {
            const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
            json arr = json::array();
            for (const auto& [va, g] : db.globals) {
                if (arr.size() >= limit) break;
                arr.push_back({{"va", va}, {"size", g.size}, {"name", g.name}});
            }
            json out = {{"ok", true}, {"globals", arr}, {"count", arr.size()},
                        {"total", db.globals.size()}};
            if (db.globals.size() > arr.size()) out["truncated"] = true;
            return out;
        }
    }

    fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
         "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|load_self|"
         "unload|analyze_stop|managed)");
}

} // namespace slop::core::mcp::detail
