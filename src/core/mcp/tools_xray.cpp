// src/core/mcp/tools_xray.cpp
// tool: xray

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {


// tool: xray

json tool_xray(const json& args) {
    const std::string action = require_action(args);
    const bool needs_x86 = action != "entropy" && action != "apihash";
    // anti_analysis looks for Windows debug/VM APIs; syscalls knows the NT
    // and the Orbis/FreeBSD (ELF) numbering
    const bool needs_pe = action == "anti_analysis";

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    uint64_t default_base = 0;
    disasm::image_format_t format = disasm::image_format_t::pe;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        if (needs_x86) require_x86_image(cache.arch, cache.format, "xray." + action, true);
        if (needs_pe) require_pe_image(cache.arch, cache.format, "xray." + action, true);
        pe = &cache.pe; file = &cache.file;
        format = cache.format;
        default_base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
        // reuse the path cache; byte-only queries never build an x86 index
        if (needs_x86 && !cache.fidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!cache.fidx.build(cache.pe, cache.file, eng, default_base))
                fail("function index build failed");
            cache.fidx_ok = true;
        }
        img.fns = &cache.fidx;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        if (needs_x86) require_x86_image(bin.arch, bin.format, "xray." + action);
        if (needs_pe) require_pe_image(bin.arch, bin.format, "xray." + action);
        pe = &bin.pe; file = &bin.file;
        format = bin.format;
        default_base = bin.base;
        img_name = bin.name;
        img.fns = &bin.fns;
    }
    if (action == "syscalls" && format == disasm::image_format_t::macho)
        fail("xray.syscalls knows the Windows NT and PS4 (Orbis/FreeBSD) syscall numbering; "
             "the image is Mach-O. Load the PE or PS4 ELF to scan");
    img.pe = pe; img.file = file; img.base = default_base;
    const bool orbis = format == disasm::image_format_t::elf ||
                       format == disasm::image_format_t::self;
    img.abi = orbis ? xray::syscall_abi_t::ps4 : xray::syscall_abi_t::windows;

    if (needs_x86) {
        auto& engine = shared_engine();
        if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
        img.eng = &engine;
    }

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base") : default_base;
    (void)base;

    json out;
    out["image"] = img_name;

    if (action == "cfg" || action == "complexity" || action == "cff" ||
        action == "obfuscation" || action == "strings_recon" ||
        action == "indirect_calls" || action == "anti_analysis") {
        const uint64_t fn_va = parse_addr(args, "addr");

        if (action == "cfg" || action == "complexity") {
            auto r = xray::build_cfg(img, fn_va);
            if (!r.ok) fail(r.error);
            if (action == "cfg") {
                json blocks = json::array();
                json nodes = json::array(), edges = json::array();
                for (const auto& b : r.blocks) {
                    blocks.push_back({{"start", b.start}, {"end", b.end},
                                      {"instructions", b.instructions},
                                      {"successors", b.successors}});
                    nodes.push_back({{"id", b.start}, {"start", b.start},
                                     {"end", b.end}, {"size", b.end - b.start},
                                     {"insn_count", b.instructions}});
                    for (uint64_t s : b.successors)
                        edges.push_back({{"from", b.start}, {"to", s},
                                         {"kind", s == b.end ? "fallthrough" : "branch"}});
                }
                out["blocks"] = blocks;
                out["block_count"] = r.blocks.size();
                out["graph"] = {{"nodes", nodes}, {"edges", edges}};
            } else {
                auto c = xray::function_complexity(img, fn_va);
                out["instruction_count"]  = c.instruction_count;
                out["basic_block_count"]  = c.basic_block_count;
                out["edge_count"]         = c.edge_count;
                out["cyclomatic_complexity"] = c.cyclomatic;
                out["call_count"]      = c.call_count;
                out["branch_count"]    = c.branch_count;
                out["return_count"]    = c.return_count;
                out["arithmetic_ops"]  = c.arithmetic_ops;
                out["memory_accesses"] = c.memory_accesses;
                out["string_operations"] = c.string_operations;
                out["unique_operators"] = c.unique_operators;
                out["unique_operands"]  = c.unique_operands;
                out["complexity_rating"] = c.rating;
            }
            out["edge_count"] = r.edge_count;
            out["back_edges"] = r.back_edges;
            out["cyclomatic_complexity"] = r.cyclomatic;
            return out;
        }

        if (action == "cff") {
            auto r = xray::detect_cff(img, fn_va);
            out["flattened"] = r.flattened;
            out["block_count"] = r.block_count;
            if (r.flattened) {
                out["dispatcher"] = r.dispatcher;
                out["dispatcher_backedges"] = r.dispatcher_backedges;
                out["state_variable"] = r.state_var_desc;
                json sbs = json::array();
                for (const auto& sb : r.state_blocks)
                    sbs.push_back({{"start", sb.start}, {"end", sb.end},
                                   {"next_state", sb.has_next ? json(sb.next_state) : json()},
                                   {"assign_addr", sb.assign_addr}});
                out["state_blocks"] = sbs;
                out["state_block_count"] = r.state_blocks.size();
            }
            return out;
        }

        if (action == "obfuscation") {
            // report a diagnostic when nothing decodes instead of a wall of zeros
            auto r = xray::detect_obfuscation(img, fn_va);
            json pats = json::array();
            for (const auto& p : r.patterns)
                pats.push_back({{"type", p.type}, {"address", p.address},
                                {"detail", p.detail}});
            out["patterns"] = pats;
            out["opaque_predicates"] = r.opaque_predicates;
            out["dead_heads"] = r.dead_heads;
            out["junk_sequences"] = r.junk_sequences;
            out["indirect_jumps"] = r.indirect_jumps;
            out["push_ret"] = r.push_ret;
            out["privileged"] = r.privileged;
            out["obfuscation_score_pct"] = r.score_pct;
            // check it actually decoded
            auto probe = xray::decode_range(img, fn_va, 4);
            if (probe.empty()) {
                out["warning"] = "no instructions decoded at addr, region may be "
                                 "compressed/encrypted data; obfuscation analysis "
                                 "requires decodable code";
            }
            return out;
        }

        if (action == "strings_recon") {
            auto hits = xray::string_decrypt_recon(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"type", h.type}, {"address", h.address}};
                if (!h.reconstructed.empty()) o["reconstructed"] = h.reconstructed;
                if (h.xor_key) o["xor_key"] = h.xor_key;
                o["length"] = h.length;
                arr.push_back(std::move(o));
            }
            out["candidates"] = arr;
            out["count"] = arr.size();
            return out;
        }

        if (action == "indirect_calls") {
            auto hits = xray::indirect_calls(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"address", h.address}, {"text", h.text},
                          {"classification", h.classification}};
                if (!h.base_register.empty()) {
                    o["base_register"] = h.base_register;
                    o["offset"] = h.offset;
                }
                if (h.target) o["target"] = h.target;
                arr.push_back(std::move(o));
            }
            out["indirect_calls"] = arr;
            out["total"] = arr.size();
            return out;
        }

        // anti_analysis
        auto r = xray::detect_anti_analysis(img, fn_va);
        json dets = json::array();
        for (const auto& d : r.detections)
            dets.push_back({{"type", d.type}, {"address", d.address},
                            {"detail", d.detail}});
        out["detections"] = dets;
        out["anti_debug"] = r.anti_debug;
        out["anti_vm"] = r.anti_vm;
        out["timing_checks"] = r.timing_checks;
        out["traps"] = r.traps;
        out["anti_analysis_score_pct"] = r.score_pct;
        return out;
    }

    if (action == "hooks") {
        const size_t maxf = std::min<size_t>(args.value("max_functions", 500u), 10000u);
        const size_t indexed = img.fns ? img.fns->functions().size() : 0;
        std::vector<xray::hook_hit_t> hits;
        size_t checked = 0;
        std::string source = "index";
        if (indexed > 0) {
            hits = xray::detect_hooks(img, maxf);
            checked = std::min(indexed, maxf);
        } else if (shared_lock) {
            // Legacy index empty (stripped/packed headers): fall back to
            // Hyperion's recovered functions so hooks still get checked.
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                std::vector<uint64_t> vas;
                vas.reserve(bin.hype->db().funcs.size());
                for (const auto& [va, hf] : bin.hype->db().funcs) {
                    (void)hf;
                    vas.push_back(va);
                }
                std::sort(vas.begin(), vas.end());
                hits = xray::detect_hooks_at(img, vas, maxf);
                checked = std::min(vas.size(), maxf);
                source = "hyperion";
            }
        }
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"address", h.address}, {"hook_type", h.hook_type},
                           {"target", h.target}, {"prologue_bytes", h.prologue_hex}});
        out["functions_checked"] = checked;
        out["hooks_found"] = hits.size();
        out["hooks"] = arr;
        out["source"] = source;
        if (checked == 0)
            out["note"] = "no functions available: legacy index empty and "
                          "hyperion not ready (wait for hype.ready or pass path)";
        return out;
    }

    if (action == "syscalls") {
        uint64_t va = args.contains("addr") ? parse_addr(args, "addr") : 0;
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size")) : 0;
        auto hits = xray::detect_syscalls(img, va, size);
        const bool ps4 = img.abi == xray::syscall_abi_t::ps4;
        json arr = json::array();
        for (const auto& h : hits) {
            json e = {{"address", h.address}, {"syscall_number", h.ssn},
                      {"pattern", h.pattern}};
            if (ps4) e["name"] = h.name.empty() ? json(nullptr) : json(h.name);
            arr.push_back(std::move(e));
        }
        out["abi"] = ps4 ? "ps4" : "windows";
        out["syscalls_found"] = hits.size();
        out["syscalls"] = arr;
        if (!ps4)
            out["note"] = "Windows SSNs differ per build; resolve them against the "
                          "matching ntdll export order";
        return out;
    }

    if (action == "apihash") {
        std::string algo = args.value("algorithm", std::string{"ror13"});
        if (algo != "ror13" && algo != "djb2" && algo != "crc32" &&
            algo != "fnv1a" && algo != "sdbm")
            fail("bad algorithm (ror13|djb2|crc32|fnv1a|sdbm)");
        // Accept both integer hashes ("0x..."/decimal/number) and plain API
        // names ("LoadLibraryA", "kernel32!CreateFileW"). Names are hashed
        // with the requested algorithm so callers never need to pre-hash.
        std::vector<uint64_t> hashes;
        json name_echo = json::array();
        auto push_hash = [&](std::vector<uint64_t>& v, const json& h) {
            if (h.is_string()) {
                const std::string s = h.get<std::string>();
                try {
                    size_t pos = 0;
                    const uint64_t num = std::stoull(s, &pos, 0);
                    if (pos == s.size()) {
                        v.push_back(num);
                        return;
                    }
                } catch (...) {}
                // not numeric: treat as an API name
                const uint32_t hv = xray::hash_api(s, algo, s.find('!') != std::string::npos);
                v.push_back(hv);
                name_echo.push_back({{"name", s}, {"hash", hv}});
                return;
            }
            if (h.is_number_unsigned()) v.push_back(h.get<uint64_t>());
            else if (h.is_number_integer() && h.get<int64_t>() >= 0)
                v.push_back(static_cast<uint64_t>(h.get<int64_t>()));
            else if (h.is_number_float())
                v.push_back(static_cast<uint64_t>(h.get<double>()));
            else fail("bad hash value (string name, hex, or integer)");
        };
        if (args.contains("hashes") && args.at("hashes").is_array())
            for (const auto& h : args.at("hashes")) push_hash(hashes, h);
        else {
            if (!args.contains("hash")) fail("missing hash/hashes");
            push_hash(hashes, args.at("hash"));
        }
        auto hits = xray::resolve_api_hashes(img, hashes, algo);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"hash", h.hash}, {"api", h.api}, {"dll", h.dll}});
        out["algorithm"] = algo;
        out["total_queried"] = hashes.size();
        out["resolved_count"] = arr.size();
        out["resolved"] = arr;
        if (!name_echo.empty()) out["name_inputs"] = name_echo;
        if (hits.empty() && !hashes.empty())
            out["hint"] = "no import matched; pass algorithm=ror13|djb2|crc32|fnv1a|sdbm "
                          "matching the sample, or pass plain API names (they are hashed for you)";
        return out;
    }

    if (action == "entropy" || action == "pages" || action == "crypto_range") {
        // accept base/va/address aliases: agents naturally say base=.
        // No address at all scans from the image base (a limit-only call
        // like pages limit=10 then works instead of erroring).
        const uint64_t va = has_any(args, {"addr", "base", "va", "address"})
            ? parse_addr_alias(args, {"addr", "base", "va", "address"})
            : default_base;
        const size_t size = has_any(args, {"size", "len", "length"})
            ? static_cast<size_t>(parse_addr_alias(args, {"size", "len", "length"})) : 4096;
        out["scan_base"] = va;
        out["scan_size"] = size;

        if (action == "entropy") {
            const size_t window = has_any(args, {"window_size", "window"})
                ? static_cast<size_t>(parse_addr_alias(args, {"window_size", "window"})) : 256;
            // honor limit as well as window_limit (zero means summary only)
            size_t win_limit = args.value("window_limit", size_t{64});
            if (args.contains("limit") && !args.contains("window_limit")) {
                const json& lv = args.at("limit");
                if (lv.is_number_unsigned()) win_limit = lv.get<size_t>();
                else if (lv.is_number_integer() && lv.get<int64_t>() >= 0)
                    win_limit = static_cast<size_t>(lv.get<int64_t>());
                else if (lv.is_string()) {
                    try { win_limit = static_cast<size_t>(std::stoull(lv.get<std::string>(), nullptr, 0)); }
                    catch (...) {}
                }
            }
            win_limit = std::min(win_limit, size_t{4096});
            auto r = xray::entropy_scan(img, va, size, window);
            out["overall_entropy"] = r.overall;
            out["min_window_entropy"] = r.min_window;
            out["max_window_entropy"] = r.max_window;
            out["window_size"] = window;
            out["verdict"] = r.verdict;
            out["truncated"] = r.truncated;
            out["total_windows"] = r.windows.size();
            json wins = json::array();
            if (win_limit > 0) {
                for (size_t i = 0; i < r.windows.size() && i < win_limit; ++i) {
                    const auto& w = r.windows[i];
                    wins.push_back({{"offset", w.offset}, {"entropy", w.entropy},
                                    {"verdict", w.verdict}});
                }
            }
            out["windows"] = wins;
            return out;
        }
        if (action == "pages") {
            const size_t ps = has_any(args, {"page_size", "window_size", "window"})
                ? static_cast<size_t>(parse_addr_alias(args, {"page_size", "window_size", "window"})) : 4096;
            const size_t page_limit = std::min<size_t>(args.value("limit", 1024u), 10000u);
            auto pages = xray::classify_pages(img, va, size, ps);
            json arr = json::array();
            json summary = {{"code", 0}, {"data", 0}, {"encrypted", 0},
                            {"padding", 0}, {"mixed", 0}};
            auto bump = [&summary](const char* k) {
                summary[k] = summary[k].get<int>() + 1;
            };
            for (size_t i = 0; i < pages.size() && arr.size() < page_limit; ++i) {
                const auto& p = pages[i];
                arr.push_back({{"address", p.address}, {"size", p.size},
                               {"class", p.klass}, {"entropy", p.entropy},
                               {"insn_ratio", p.insn_ratio},
                               {"zero_ratio", p.zero_ratio},
                               {"string_ratio", p.string_ratio}});
                const std::string k = p.klass;
                if (k == "code") bump("code");
                else if (k == "padding") bump("padding");
                else if (k == "encrypted_or_compressed" ||
                         k == "single_byte_encrypted") bump("encrypted");
                else if (k == "mixed") bump("mixed");
                else bump("data");
            }
            out["total_pages"] = pages.size();
            out["summary"] = summary;
            out["pages"] = arr;
            out["count"] = arr.size();
            out["truncated"] = pages.size() > arr.size();
            return out;
        }
        // crypto_range
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);
        auto hits = xray::crypto_range(img, va, size, limit);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"va", h.va}, {"algorithm", h.algorithm},
                           {"constant", h.constant_name}, {"value", h.value},
                           {"source", h.source}});
        out["matches"] = arr;
        out["count"] = arr.size();
        return out;
    }

    if (action == "gadgets") {
        const size_t limit = std::min<size_t>(args.value("limit", 200u), 2000u);
        auto hits = xray::rop_gadgets(img, limit);
        json arr = json::array();
        for (const auto& g : hits)
            arr.push_back({{"address", g.address}, {"text", g.text}});
        out["gadgets"] = arr;
        out["count"] = arr.size();
        return out;
    }

    fail("xray: unknown action (cfg|complexity|cff|obfuscation|strings_recon|"
         "indirect_calls|anti_analysis|hooks|syscalls|apihash|entropy|pages|"
         "crypto_range|gadgets)");
}

} // namespace slop::core::mcp::detail
