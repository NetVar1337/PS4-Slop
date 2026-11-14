// src/core/mcp/tools_re.cpp
// tool: re (rtti, vtables, danger imports, libsig, symbols)

#include "core/mcp/tools_common.hpp"

#include "core/loader/elf_loader.h"

#include <cstring>

namespace slop::core::mcp::detail {


// tool: re

json tool_re(const json& args) {
    const std::string action = require_action(args);

    // app loaded binary unless a path is given
    std::optional<ds::binary_lock_t> shared_lock;
    disasm::pe_image_t const*   pe   = nullptr;
    std::vector<uint8_t> const* file = nullptr;
    disasm::function_index_t*   fidx = nullptr;
    disasm::xref_index_t*       xidx = nullptr;
    uint64_t                    session_base = 0;   // VA base of the source
    const hype::AnalysisDB*     hdb  = nullptr;     // hyperion DB when analyzed
    disasm::image_format_t format = disasm::image_format_t::pe;
    disasm::image_arch_t arch = disasm::image_arch_t::x64;
    const bool have_path = args.contains("path") && args.at("path").is_string();

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        format = img.format;
        arch = img.arch;
        if (action == "danger")
            require_x86_image(arch, format, "re.danger", true);
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        session_base = pe->image_base;
        // signature matching needs bounds, not decoding; import callsites
        // need the legacy x86 xref index when there is no hyperion session
        if (action == "libsig" && !img.fidx_ok) {
            if (arch == disasm::image_arch_t::x86 || arch == disasm::image_arch_t::x64) {
                auto& eng = shared_engine();
                if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
                if (!fidx->build(*pe, *file, eng, session_base))
                    fail("function index build failed");
            } else if (!fidx->build_from_bounds(*pe, *file, session_base)) {
                fail("function bounds index build failed");
            }
            img.fidx_ok = true;
        }
        if (action == "danger" && !img.xidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!xidx->build(*pe, *file, eng, session_base))
                fail("xref index build failed");
            img.xidx_ok = true;
        }
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        format = bin.format;
        arch = bin.arch;
        if (bin.indexes_dirty && (action == "danger" || action == "libsig"))
            ds::rebuild_indexes_locked(bin);
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        session_base = bin.base;
        if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
    }
    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : session_base;
    (void)base;

    if (action == "rtti_scan") {
        // MSVC RTTI on x86/x64 PE; Itanium (clang/gcc) RTTI on ELF/SELF of any
        // arch the hyperion loader maps
        const bool itanium = format == disasm::image_format_t::elf ||
                             format == disasm::image_format_t::self;
        if (!itanium) {
            require_x86_image(arch, format, "re.rtti_scan", have_path);
            require_pe_image(arch, format, "re.rtti_scan", have_path);
        }
        // Case-insensitive substring filter over mangled + demangled names,
        // plus limit/total so 600-class dumps stop truncating the session.
        const std::string filter = args.value("filter", std::string{});
        auto match_filter = [&](const std::string& a, const std::string& b) {
            return filter.empty() || icontains(a, filter) || icontains(b, filter);
        };
        const size_t rtti_limit =
            std::min<size_t>(args.value("limit", 500u), 10000u);
        const char* abi = itanium ? "itanium" : "msvc";
        // hyperion rtti beats the quick scanner when its ready
        // the lock above already pins the session
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                const auto& classes = bin.hype->rtti().classes();
                json arr = json::array();
                size_t matched = 0;
                for (const auto& c : classes) {
                    const std::string shown = c.demangled_name.empty()
                                                  ? c.mangled_name
                                                  : c.demangled_name;
                    if (!match_filter(shown, c.mangled_name)) continue;
                    ++matched;
                    if (arr.size() >= rtti_limit) continue;
                    json methods = json::array();
                    for (auto m : c.methods) methods.push_back(m);
                    json e = {{"name", shown},
                              {"mangled", c.mangled_name},
                              {"td_va", c.type_descriptor},
                              {"vtable_va", c.vtable},
                              {"methods", methods},
                              {"method_count", c.methods.size()}};
                    if (itanium) e["bases"] = c.bases;
                    arr.push_back(std::move(e));
                }
                json out = {{"engine", "hyperion"}, {"abi", abi}, {"classes", arr},
                            {"count", arr.size()}, {"total", matched}};
                if (!filter.empty()) out["filter"] = filter;
                if (matched > arr.size()) out["truncated"] = true;
                return out;
            }
        }
        re::rtti_result_t r;
        if (itanium) {
            const unsigned ptr_size = (arch == disasm::image_arch_t::x64 ||
                                       arch == disasm::image_arch_t::arm64) ? 8 : 4;
            if (have_path && file->size() >= 4 && std::memcmp(file->data(), "\x7F" "ELF", 4) == 0) {
                // the path cache holds the ELF as read (a SELF's extracted
                // ELF too); vtable and type_info pointers only exist once
                // its relocations are applied
                std::vector<uint8_t> relocated = *file;
                hype::ELFLoader::apply_relocations(relocated, pe->image_base);
                r = re::rtti_scan_itanium(*pe, relocated, ptr_size);
            } else {
                r = re::rtti_scan_itanium(*pe, *file, ptr_size);
            }
        } else {
            r = re::rtti_scan(*pe, *file);
        }
        json arr = json::array();
        size_t matched = 0;
        for (const auto& c : r.classes) {
            if (!match_filter(c.name, c.mangled.empty() ? c.name : c.mangled)) continue;
            ++matched;
            if (arr.size() >= rtti_limit) continue;
            json vfs = json::array();
            for (auto v : c.vftables) vfs.push_back(v);
            json e = {{"name", c.name}, {"td_va", c.td_va}, {"vftables", vfs}};
            if (itanium) {
                e["mangled"] = c.mangled;
                e["bases"] = c.bases;
                e["methods"] = c.methods;
                e["method_count"] = c.methods.size();
            }
            arr.push_back(std::move(e));
        }
        json rout = {{"abi", abi}, {"classes", arr}, {"count", arr.size()},
                     {"total", matched},
                     {"scanned_bytes", r.scanned_bytes}};
        if (!filter.empty()) rout["filter"] = filter;
        if (matched > arr.size()) rout["truncated"] = true;
        return rout;
    }
    if (action == "vftable") {
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                // serve from the db when the address is indexed
                const uint64_t vva = parse_addr(args, "addr");
                for (const auto& vt : bin.hype->db().vtables) {
                    if (vt.addr != vva) continue;
                    json arr = json::array();
                    for (auto e : vt.entries) arr.push_back(e);
                    return {{"engine", "hyperion"}, {"vftable_va", vva},
                            {"targets", arr}, {"count", arr.size()}};
                }
                // raw read for everything else
            }
        }
        if (!args.contains("addr")) fail("missing addr");
        const uint64_t va = parse_addr(args, "addr");
        auto slots = re::read_vftable(
            *pe, *file, va,
            static_cast<size_t>(std::min<uint64_t>(
                args.contains("slots") ? parse_addr(args, "slots") : 32,
                256)));
        if (!slots) fail("vftable not readable in image");
        json arr = json::array();
        for (auto v : *slots) arr.push_back(v);
        return {{"vftable_va", va}, {"targets", arr},
                {"count", arr.size()}};
    }
    if (action == "danger") {
        if (arch != disasm::image_arch_t::x86 && arch != disasm::image_arch_t::x64 && !hdb)
            fail("re.danger requires completed hyperion analysis for this image; "
                 "wait for disasm.loaded hype.ready");
        // hyperion knows the iat refs, the legacy index covers explicit paths
        auto hits = analysis::danger_scan(
            *pe,
            [xidx, hdb](uint64_t target_va) {
                std::vector<uint64_t> out;
                if (hdb) {
                    // one instruction can emit two records, dedupe by from
                    std::set<uint64_t> seen;
                    const auto it = hdb->xrefs_to.find(target_va);
                    if (it != hdb->xrefs_to.end())
                        for (const auto& x : it->second)
                            if (seen.insert(x.from).second)
                                out.push_back(x.from);
                    return out;
                }
                for (const auto& r : xidx->refs_to(target_va))
                    out.push_back(r.from);
                return out;
            },
            session_base);
        json arr = json::array();
        for (const auto& h : hits) {
            json cs = json::array();
            for (auto c : h.callsites) cs.push_back(c);
            arr.push_back({{"function", h.function},
                           {"category", h.category},
                           {"iat_va", h.iat_va},
                           {"callsites", cs},
                           {"count", cs.size()}});
        }
        return {{"hits", arr}, {"count", arr.size()}};
    }
    if (action == "libsig") {
        std::vector<analysis::libsig_t> sigs;
        json out = json::object();
        if (args.contains("sig_path") && args.at("sig_path").is_string()) {
            // IDA FLIRT .sig import: parsed into the same pattern matcher
            const std::string sig_path = args.at("sig_path").get<std::string>();
            std::ifstream f(sig_path, std::ios::binary);
            if (!f) fail("cannot open signature file " + sig_path);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                       std::istreambuf_iterator<char>{});
            std::string sig_err;
            auto parsed = analysis::parse_flirt_sig(bytes.data(), bytes.size(), &sig_err);
            if (!parsed) fail(sig_err.empty() ? "bad FLIRT signature file" : sig_err);
            sigs = std::move(parsed->sigs);
            out["library"]       = parsed->library;
            out["ctype"]         = parsed->ctype;
            out["flirt_version"] = parsed->version;
        } else {
            if (!args.contains("sigset")) fail("missing sigset JSON or sig_path");
            std::string sig_err;
            auto parsed = analysis::parse_sig_set(
                args.at("sigset").get<std::string>(), &sig_err);
            if (!parsed) fail(sig_err.empty() ? "bad sigset" : sig_err);
            sigs = std::move(*parsed);
        }
        auto hits = analysis::libsig_scan(*pe, *file, *fidx, sigs);
        json arr = json::array();
        for (const auto& h : hits) {
            json o = {{"name", h.sig_name}, {"va", h.va}};
            if (h.function_va) o["function_va"] = *h.function_va;
            arr.push_back(std::move(o));
        }
        out["hits"]      = arr;
        out["count"]     = arr.size();
        out["requested"] = sigs.size();
        return out;
    }

    fail("re: unknown action (rtti_scan|vftable|danger|libsig)");
}

} // namespace slop::core::mcp::detail
