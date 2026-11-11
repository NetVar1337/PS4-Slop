// src/core/mcp/tools_memory.cpp
// tool: memory (read/write/scan/aob/pointer scan/snapshots/watch)

#include "core/mcp/tools_common.hpp"

#include "core/memory/console_scan.hpp"
#include "core/memory/session_reader.hpp"

namespace slop::core::mcp::detail {

namespace {

using memory::session_reader_t;

// optional numeric argument through the shared parser, so "0x1000" strings
// work everywhere and bad input fails with a readable message
uint64_t opt_u64(const json& args, const char* key, uint64_t def) {
    return args.contains(key) ? parse_addr(args, key) : def;
}

// signed variant for offsets: accepts -0x10 / "-16" / -16
int64_t opt_i64(const json& args, const char* key, int64_t def) {
    if (!args.contains(key)) return def;
    const json& v = args.at(key);
    if (v.is_number_integer()) return v.get<int64_t>();
    if (v.is_string()) {
        std::string t = v.get<std::string>();
        const size_t b = t.find_first_not_of(" \t");
        const bool neg = b != std::string::npos && t[b] == '-';
        if (neg) t.erase(b, 1);
        const uint64_t mag = parse_addr(json{{key, t}}, key);
        if (mag > static_cast<uint64_t>(INT64_MAX))
            fail(std::string("bad numeric argument '") + key + "': out of range");
        return neg ? -static_cast<int64_t>(mag) : static_cast<int64_t>(mag);
    }
    fail(std::string("bad numeric argument '") + key + "': expected a signed integer");
}

bool opt_bool(const json& args, const char* key, bool def) {
    if (!args.contains(key)) return def;
    const json& v = args.at(key);
    if (v.is_boolean()) return v.get<bool>();
    if (v.is_number_integer()) return v.get<int64_t>() != 0;
    fail(std::string("bad argument '") + key + "': expected true/false");
}

json io_hints_json(const memory::reader_hints_t& h) {
    return {{"remote", h.max_workers == 1},
            {"max_workers", h.max_workers},
            {"chunk_bytes", h.chunk_bytes ? h.chunk_bytes : infra::limits::scan_chunk_bytes},
            {"read_ahead", h.read_ahead},
            {"coalesce_gap", h.coalesce_gap}};
}

// last pointer scan result, the input of pointerscan_verify
struct ptr_list_t {
    bool                                         valid = false;
    uint32_t                                     pid = 0;
    uintptr_t                                    target = 0;
    std::vector<memory::pointer_chain_result_t>  chains;
};
ptr_list_t g_ptr_last;

json chains_json(const std::vector<memory::pointer_chain_result_t>& chains, size_t limit) {
    json arr = json::array();
    for (size_t i = 0; i < chains.size() && i < limit; ++i) {
        json addrs = json::array();
        json offs  = json::array();
        for (uintptr_t a : chains[i].addresses) addrs.push_back(static_cast<uint64_t>(a));
        for (int64_t o : chains[i].offsets)     offs.push_back(o);
        arr.push_back({{"addresses", addrs}, {"offsets", offs},
                       {"base_hex", addr_hex_str(chains[i].addresses.empty()
                                                     ? 0 : chains[i].addresses.front())},
                       {"depth", chains[i].depth()}});
    }
    return arr;
}

std::vector<uintptr_t> committed_ranges(runtime::session_t& s) {
    std::vector<uintptr_t> out;
    auto res = runtime::active().enum_regions(s.handle());
    if (!res.ok) return out;
    out.reserve(res.items.size() * 2);
    for (const auto& r : res.items) {
        const bool commit = (r.state & 0x1000) != 0;   // MEM_COMMIT
        if (!commit || r.size == 0) continue;
        const bool guard = (r.protect & 0x100) != 0;   // PAGE_GUARD
        if (guard) continue;
        out.push_back(r.base);
        out.push_back(r.base + r.size);
    }
    return out;
}

// string argument with a readable error instead of a json type_error
std::string opt_str(const json& args, const char* key, const char* def) {
    if (!args.contains(key)) return def;
    const json& v = args.at(key);
    if (!v.is_string()) fail(std::string("bad argument '") + key + "': expected a string");
    return v.get<std::string>();
}

memory::value_width_t parse_width(const json& args) {
    // byte counts (1/2/4/8) map to the unsigned widths
    if (args.contains("width") && args.at("width").is_number_integer()) {
        switch (args.at("width").get<int64_t>()) {
        case 1: return memory::value_width_t::u8;
        case 2: return memory::value_width_t::u16;
        case 4: return memory::value_width_t::u32;
        case 8: return memory::value_width_t::u64;
        default: fail("bad width: byte widths are 1, 2, 4 or 8");
        }
    }
    const std::string w = opt_str(args, "width", "i32");
    if (w == "i8")  return memory::value_width_t::i8;
    if (w == "u8")  return memory::value_width_t::u8;
    if (w == "i16") return memory::value_width_t::i16;
    if (w == "u16") return memory::value_width_t::u16;
    if (w == "i32") return memory::value_width_t::i32;
    if (w == "u32") return memory::value_width_t::u32;
    if (w == "i64") return memory::value_width_t::i64;
    if (w == "u64") return memory::value_width_t::u64;
    if (w == "f32") return memory::value_width_t::f32;
    if (w == "f64") return memory::value_width_t::f64;
    if (w == "all") return memory::value_width_t::u32; // handled via scan_all_types
    fail("bad width '" + w + "' (i8|u8|i16|u16|i32|u32|i64|u64|f32|f64|all, or 1/2/4/8 bytes)");
}

memory::scan_type_t parse_scan_kind(const json& args) {
    const std::string k = opt_str(args, "kind", "exact");
    if (k == "exact")        return memory::scan_type_t::exact_value;
    if (k == "between")      return memory::scan_type_t::between;
    if (k == "bigger")       return memory::scan_type_t::bigger_than;
    if (k == "smaller")      return memory::scan_type_t::smaller_than;
    if (k == "unknown")      return memory::scan_type_t::unknown_initial;
    if (k == "increased")    return memory::scan_type_t::increased;
    if (k == "increased_by") return memory::scan_type_t::increased_by;
    if (k == "increased_percent") return memory::scan_type_t::increased_percent;
    if (k == "decreased")    return memory::scan_type_t::decreased;
    if (k == "decreased_by") return memory::scan_type_t::decreased_by;
    if (k == "decreased_percent") return memory::scan_type_t::decreased_percent;
    if (k == "changed")      return memory::scan_type_t::changed;
    if (k == "unchanged")    return memory::scan_type_t::unchanged;
    fail("bad scan kind '" + k + "' (exact|between|bigger|smaller|unknown|increased|"
         "increased_by|increased_percent|decreased|decreased_by|decreased_percent|"
         "changed|unchanged)");
}

memory::rounding_t parse_rounding(const json& args) {
    const std::string r = opt_str(args, "rounding", "exact");
    if (r == "exact")     return memory::rounding_t::exact;
    if (r == "rounded")   return memory::rounding_t::rounded;
    if (r == "truncated") return memory::rounding_t::truncated;
    if (r == "extreme")   return memory::rounding_t::extreme;
    fail("bad rounding (exact|rounded|truncated|extreme)");
}

memory::region_pref_t parse_region_pref(const json& args, const char* key) {
    if (args.contains(key) && args.at(key).is_boolean()) return memory::region_pref_t::any;
    const std::string pref = opt_str(args, key, "any");
    if (pref == "any")     return memory::region_pref_t::any;
    if (pref == "include") return memory::region_pref_t::include;
    if (pref == "exclude") return memory::region_pref_t::exclude;
    fail(std::string("bad ") + key + " preference (any|include|exclude)");
}

const char* width_name(memory::value_width_t w) noexcept {
    switch (w) {
    case memory::value_width_t::i8:  return "i8";
    case memory::value_width_t::u8:  return "u8";
    case memory::value_width_t::i16: return "i16";
    case memory::value_width_t::u16: return "u16";
    case memory::value_width_t::i32: return "i32";
    case memory::value_width_t::u32: return "u32";
    case memory::value_width_t::i64: return "i64";
    case memory::value_width_t::u64: return "u64";
    case memory::value_width_t::f32: return "f32";
    case memory::value_width_t::f64: return "f64";
    }
    return "unknown";
}

json hits_json(const std::vector<memory::scan_result_t>& hits, size_t limit) {
    json arr = json::array();
    const size_t n = std::min(hits.size(), limit);
    for (size_t i = 0; i < n; ++i) {
        arr.push_back({
            {"addr", static_cast<uint64_t>(hits[i].address)},
            {"bits", hits[i].bits},
            {"value", hits[i].bits},
            {"formatted", memory::format_value_text(hits[i].matched, hits[i].bits)},
            {"type", width_name(hits[i].matched)}
        });
    }
    return arr;
}

} // namespace


// tool: memory

json tool_memory(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no target attached, a typo isnt a missing target
    {
        static const char* kKnown[] = {
            "read", "write", "scan", "rescan", "scan_state", "scan_reset",
            "aob", "pointerscan", "pointerscan_verify", "snapshot", "snapshots", "diff",
            "snapshot_free", "protect", "alloc", "free", "siggen",
            "live_crypto", "watch_list", "watch_add", "watch_remove",
            "watch_clear", "watch_set",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("memory: unknown action (read|write|scan|rescan|scan_state|scan_reset|"
                 "aob|pointerscan|pointerscan_verify|snapshot|snapshots|diff|snapshot_free|"
                 "protect|alloc|free|siggen|live_crypto|watch_list|watch_add|watch_remove|"
                 "watch_clear|watch_set)");
    }

    // watchlist
    // the app tick services these at 10hz so the ui never polls
    if (action.rfind("watch", 0) == 0) {
        auto entries_json = [] {
            json arr = json::array();
            for (const auto& e : memory::watch::list())
                arr.push_back({{"id", e.id},
                               {"addr", e.addr},
                               {"width", width_name(e.width)},
                               {"label", e.label},
                               {"freeze", e.freeze},
                               {"frozen_bits", e.frozen_bits}});
            return arr;
        };

        if (action == "watch_list") {
            json vals = json::array();
            size_t failing = 0;
            for (const auto& v : memory::watch::values()) {
                if (v.hold_failed) ++failing;
                vals.push_back({{"id", v.id},
                                {"addr", v.addr},
                                {"ok", v.ok},
                                {"held", v.held},
                                {"hold_failed", v.hold_failed},
                                {"bits", v.bits},
                                {"text", v.text}});
            }
            return {{"entries", entries_json()}, {"values", std::move(vals)},
                    {"hold_failures", failing}};
        }

        if (action == "watch_add") {
            if (!args.contains("addr")) fail("memory.watch_add: missing addr");
            const uint64_t addr = parse_addr(args, "addr");
            const auto width = parse_width(args);
            std::string label = opt_str(args, "label", "");
            if (label.empty()) label = infra::fmt::format_address(addr);
            const bool freeze = opt_bool(args, "freeze", false);
            const uint64_t id = memory::watch::add(addr, width, std::move(label));
            if (id == 0) fail("memory.watch_add: watch list is full");
            if (freeze) memory::watch::set_freeze(id, true);
            return {{"id", id}, {"addr_hex", addr_hex_str(addr)}, {"entries", entries_json()}};
        }

        if (action == "watch_remove") {
            if (!args.contains("id")) fail("memory.watch_remove: missing id");
            const bool ok = memory::watch::remove(parse_addr(args, "id"));
            if (!ok) fail("memory.watch_remove: no such id");
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_clear") {
            memory::watch::clear();
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_set") {
            if (!args.contains("id")) fail("memory.watch_set: missing id");
            const uint64_t id = parse_addr(args, "id");
            bool touched = false;
            if (args.contains("freeze") && args.at("freeze").is_boolean()) {
                if (!memory::watch::set_freeze(id, args.at("freeze").get<bool>()))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("width")) {
                if (!memory::watch::set_width(id, parse_width(args)))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("label") && args.at("label").is_string()) {
                if (!memory::watch::set_label(id, args.at("label").get<std::string>()))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("value")) {
                // text form so floats and signed widths round trip like the value box
                const auto entries = memory::watch::list();
                auto it = std::find_if(entries.begin(), entries.end(),
                                       [id](const memory::watch::entry_t& e) {
                                           return e.id == id;
                                       });
                if (it == entries.end()) fail("memory.watch_set: no such id");
                uint64_t bits = 0;
                const auto& v = args.at("value");
                if (v.is_string()) {
                    if (!memory::parse_value_text(it->width, v.get<std::string>(), bits))
                        fail("memory.watch_set: cannot parse value for width");
                } else if (v.is_number_float()) {
                    bits = memory::value_from_double(it->width, v.get<double>());
                } else if (v.is_number()) {
                    bits = v.get<uint64_t>();
                } else {
                    fail("memory.watch_set: value must be string or number");
                }
                std::string err;
                if (!memory::watch::poke(id, bits, &err))
                    fail("memory.watch_set: " + err);
                touched = true;
            }
            if (!touched) fail("memory.watch_set: nothing to change");
            return {{"ok", true}, {"entries", entries_json()}};
        }

        fail("memory: unknown watch action");
    }

    if (action == "scan_reset") {
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        return {{"reset", true}};
    }

    if (action == "scan_state") {
        const auto stats = g_scan.engine.stats();
        return {{"active", g_scan.used},
                {"pid", g_scan.pid},
                {"width", g_scan.width},
                {"engine_width", width_name(g_scan.engine.last_width())},
                {"kind", g_scan.kind},
                {"total", g_scan.engine.results().size()},
                {"region_scan_active", g_scan.engine.region_scan_active()},
                {"regions", stats.regions},
                {"regions_scanned", stats.regions_scanned},
                {"bytes_scanned", stats.bytes_scanned},
                {"slots_scanned", stats.slots_scanned},
                {"slots_tracked", stats.slots_tracked},
                {"truncated", stats.truncated},
                {"cancelled", stats.cancelled}};
    }

    // snapshot actions work without a target, everything below needs one
    if (action == "snapshots") {
        json arr = json::array();
        for (const auto& rec : g_snaps) {
            arr.push_back({{"id", rec.id},
                           {"addr", static_cast<uint64_t>(rec.snap.base)},
                           {"size", rec.snap.size},
                           {"bytes", rec.snap.bytes.size()},
                           {"complete", rec.snap.complete}});
        }
        return {{"snapshots", arr}, {"count", arr.size()}};
    }

    if (action == "snapshot_free") {
        if (opt_bool(args, "all", false)) {
            g_snaps.clear();
            return {{"freed", "all"}};
        }
        if (!args.contains("id")) fail("missing id (or all:true)");
        const uint64_t id = parse_addr(args, "id");
        for (auto it = g_snaps.begin(); it != g_snaps.end(); ++it) {
            if (it->id == id) {
                g_snaps.erase(it);
                return {{"freed", id}};
            }
        }
        fail("unknown snapshot id");
    }

    // reads fall back to the loaded image when no target is attached
    if (action == "read") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = parse_addr(args.contains("len") ? args : json{{"len", 256}}, "len");
        if (len == 0) len = 256;
        if (len > (1ull << 20)) fail("read len capped at 1 MiB");
        std::vector<uint8_t> buf(static_cast<size_t>(len));
        size_t got = 0;

        // live target first, a failed live read is a real error worth seeing
        if (auto sess = process::active_session(); sess && sess->valid()) {
            auto io = sess->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (io.ok) got = io.bytes;
            else fail("live read failed at " + addr_hex_str(addr) + ": " +
                      runtime::ps4::io_error_str(io.error));
        }
        // fall back to the file image only when nothing is attached
        if (got == 0) {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (!bin.ready) fail("no target attached and no image loaded");
            auto off = bin.pe.va_to_offset(addr);
            if (!off) fail("address not mapped in loaded image");
            got = std::min(buf.size(), bin.file.size() - *off);
            std::memcpy(buf.data(), bin.file.data() + *off, got);
        }

        json out = {{"addr", addr}, {"len", got}};
        const std::string fmt = opt_str(args, "format", "hex");
        if (fmt == "hex") {
            out["hex"] = to_hex(buf.data(), got);
        } else if (fmt == "utf8") {
            std::string text(reinterpret_cast<const char*>(buf.data()), got);
            text.erase(std::find(text.begin(), text.end(), '\0'), text.end());
            out["text"] = text;
        } else if (fmt == "u8" || fmt == "u32" || fmt == "u64" || fmt == "f32" || fmt == "f64") {
            json arr = json::array();
            const size_t w = fmt == "u8" ? 1 : fmt == "u32" ? 4 : fmt == "f32" ? 4 : 8;
            for (size_t off = 0; off + w <= got; off += w) {
                if (fmt == "u8")  arr.push_back(buf[off]);
                if (fmt == "u32") { uint32_t v; memcpy(&v, buf.data() + off, 4); arr.push_back(v); }
                if (fmt == "u64") { uint64_t v; memcpy(&v, buf.data() + off, 8); arr.push_back(v); }
                if (fmt == "f32") { float v;    memcpy(&v, buf.data() + off, 4); arr.push_back(v); }
                if (fmt == "f64") { double v;   memcpy(&v, buf.data() + off, 8); arr.push_back(v); }
            }
            out["values"] = arr;
        } else {
            fail("bad format (hex|utf8|u8|u32|u64|f32|f64)");
        }
        return out;
    }

    const auto s_hold = need_session();
    auto& s = *s_hold;

    if (action == "write") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("hex") || !args.at("hex").is_string()) fail("missing hex payload");
        auto bytes = hex_decode(args.at("hex").get<std::string>());
        if (bytes.empty()) fail("empty payload");
        if (bytes.size() > (1ull << 20)) fail("write capped at 1 MiB");
        auto io = s.write(static_cast<uintptr_t>(addr), bytes.data(), bytes.size());
        if (!io.ok) fail("write failed at " + addr_hex_str(addr) + ": " +
                         runtime::ps4::io_error_str(io.error));
        return {{"addr", addr}, {"written", io.bytes}};
    }

    if (action == "scan" || action == "rescan") {
        session_reader_t reader(s);

        // scan config straight from the request
        memory::scan_config_t cfg;
        cfg.type  = parse_scan_kind(args);
        cfg.width = parse_width(args);
        cfg.scan_all_types = args.contains("width") && args.at("width").is_string() &&
                             args.at("width").get<std::string>() == "all";
        cfg.rounding = parse_rounding(args);
        cfg.max_results = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "max_results", infra::limits::max_scan_hits),
            infra::limits::max_scan_hits));
        // threads/chunk_bytes left at 0 let the reader decide: a console
        // (one serialized socket) gets one worker, 8 MiB chunks, read-ahead
        cfg.threads = static_cast<uint32_t>(std::min<uint64_t>(opt_u64(args, "threads", 0), 64));
        cfg.chunk_bytes = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "chunk_bytes", 0),
            reader.hints().max_workers == 1 ? memory::kRemoteMaxChunkBytes : (64u << 20)));
        if (args.contains("begin") && args.contains("end")) {
            cfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            cfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        // fastscan is alignment or the ends with hex digits mode
        if (args.contains("tail")) {
            std::string tail = opt_str(args, "tail", "");
            if (tail.rfind("0x", 0) == 0 || tail.rfind("0X", 0) == 0)
                tail.erase(0, 2);
            if (tail.empty() || tail.size() > 8 ||
                tail.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                fail("bad tail (1..8 hex digits)");
            uint64_t tv = 0;
            if (!memory::parse_value_text(memory::value_width_t::u64, "0x" + tail, tv))
                fail("bad tail (hex digits)");
            cfg.fast = memory::fastscan_method_t::ends_with;
            cfg.fast_digits = static_cast<uint32_t>(tail.size());
            cfg.fast_tail   = tv;
        } else {
            cfg.fast = memory::fastscan_method_t::alignment;
            cfg.fast_alignment = static_cast<uint32_t>(
                std::min<uint64_t>(opt_u64(args, "alignment", 4), 4096));
            if (cfg.fast_alignment == 0) cfg.fast = memory::fastscan_method_t::off;
        }
        // region prefs, the old boolean flags still work
        cfg.writable = parse_region_pref(args, "writable");
        cfg.executable = parse_region_pref(args, "executable");
        cfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            cfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        if (opt_bool(args, "read_only", false)) cfg.writable = memory::region_pref_t::exclude;
        if (opt_bool(args, "no_exec", false)) cfg.executable = memory::region_pref_t::exclude;
        cfg.mem_private = opt_bool(args, "mem_private", true);
        cfg.mem_image = opt_bool(args, "mem_image", true);
        cfg.mem_mapped = opt_bool(args, "mem_mapped", true);

        const auto needs_value1 = [](memory::scan_type_t type) {
            return type == memory::scan_type_t::exact_value ||
                   type == memory::scan_type_t::between ||
                   type == memory::scan_type_t::bigger_than ||
                   type == memory::scan_type_t::smaller_than ||
                   type == memory::scan_type_t::increased_by ||
                   type == memory::scan_type_t::decreased_by ||
                   type == memory::scan_type_t::increased_percent ||
                   type == memory::scan_type_t::decreased_percent;
        };
        const auto needs_value2 = [](memory::scan_type_t type) {
            return type == memory::scan_type_t::between ||
                   type == memory::scan_type_t::increased_percent ||
                   type == memory::scan_type_t::decreased_percent;
        };
        if (needs_value1(cfg.type) && !args.contains("value"))
            fail("scan kind requires value");
        if (needs_value2(cfg.type) && !args.contains("value2"))
            fail("scan kind requires value2");

        // text values keep the float accuracy
        std::string v1_text, v2_text;
        if (args.contains("value")) {
            const json& v = args.at("value");
            v1_text = v.is_string() ? v.get<std::string>() : v.dump();
            uint64_t bits = 0;
            if (!memory::parse_value_text(cfg.width, v1_text, bits))
                fail("bad value for width");
            cfg.value1 = memory::value_to_double(cfg.width, bits);
            cfg.float_accuracy = memory::float_accuracy_from_text(v1_text);
        }
        if (args.contains("value2")) {
            const json& v = args.at("value2");
            v2_text = v.is_string() ? v.get<std::string>() : v.dump();
            uint64_t bits = 0;
            if (!memory::parse_value_text(cfg.width, v2_text, bits))
                fail("bad value2 for width");
            cfg.value2 = memory::value_to_double(cfg.width, bits);
        }
        if (cfg.type == memory::scan_type_t::increased_percent ||
            cfg.type == memory::scan_type_t::decreased_percent) {
            // 5 means five percent, same as the cheat engine ui
            cfg.value1 /= 100.0;
            cfg.value2 /= 100.0;
        }

        // region set comes from the active backend
        auto regions = runtime::target_scan_regions(s.handle());

        infra::cancel_token_t tok;
        std::string err;

        if (action == "scan") {
            // scan starts fresh, rescan refines what the last one found
            g_scan.engine.reset();
            if (!g_scan.engine.first_scan(reader, std::move(regions), cfg, tok, &err))
                fail(err.empty() ? "first scan failed" : err);
            g_scan.used = true;
            g_scan.pid = s.pid();
        } else {
            if (!g_scan.used)
                fail("no previous scan to rescan (run memory.scan first)");
            if (g_scan.pid != s.pid())
                fail("scan belongs to another target (run memory.scan first)");
            if (!g_scan.engine.next_scan(reader, cfg, tok, &err))
                fail(err.empty() ? "rescan failed" : err);
        }
        const std::string width_label = cfg.scan_all_types ? std::string("all")
                                                           : std::string(width_name(cfg.width));
        g_scan.width = width_label;
        g_scan.kind = opt_str(args, "kind", "exact");

        const auto& out = g_scan.engine.results();
        const auto stats = g_scan.engine.stats();
        const size_t limit = static_cast<size_t>(std::min<uint64_t>(opt_u64(args, "limit", 100), 10000));
        return {
            {"hits", hits_json(out, limit)},
            {"total", out.size()},
            {"truncated", stats.truncated},
            {"cancelled", stats.cancelled},
            {"bytes_scanned", stats.bytes_scanned},
            {"slots_scanned", stats.slots_scanned},
            {"regions_scanned", stats.regions_scanned},
            {"region_scan_active", g_scan.engine.region_scan_active()},
            {"slots_tracked", stats.slots_tracked},
            {"width", width_label},
            {"io", io_hints_json(reader.hints())}
        };
    }

    if (action == "aob") {
        if (!args.contains("pattern") || !args.at("pattern").is_string()) fail("missing pattern");
        std::string err;
        auto pat = memory::aob_compile(args.at("pattern").get<std::string>(), err);
        if (!pat) fail("bad pattern: " + err);
        session_reader_t reader(s);

        memory::scan_config_t rcfg; // region preference carrier
        if (args.contains("begin") && args.contains("end")) {
            rcfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            rcfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        rcfg.writable = parse_region_pref(args, "writable");
        rcfg.executable = parse_region_pref(args, "executable");
        rcfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            rcfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        rcfg.mem_private = opt_bool(args, "mem_private", true);
        rcfg.mem_image = opt_bool(args, "mem_image", true);
        rcfg.mem_mapped = opt_bool(args, "mem_mapped", true);
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), rcfg);
        if (regions.empty()) fail("no committed ranges");

        const uint32_t alignment = static_cast<uint32_t>(
            std::min<uint64_t>(opt_u64(args, "alignment", 1), 4096));
        const size_t max_results = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "max_results", infra::limits::max_aob_matches),
            infra::limits::max_aob_matches));
        const size_t limit = static_cast<size_t>(std::min<uint64_t>(opt_u64(args, "limit", 256), 10000));
        auto result = [&](const std::vector<uintptr_t>& matches, const json& extra) -> json {
            json arr = json::array();
            for (size_t i = 0; i < matches.size() && i < limit; ++i)
                arr.push_back(static_cast<uint64_t>(matches[i]));
            json out = {{"matches", arr}, {"total", matches.size()},
                        {"listed_truncated", matches.size() > limit}};
            for (auto it = extra.begin(); it != extra.end(); ++it) out[it.key()] = *it;
            return out;
        };

        // console target: run the search on the PS4 itself (memory speed,
        // one roundtrip per hit) instead of streaming all memory over TCP.
        // Needs the payload's scan family (auth bit 1) and byte-granular
        // wildcards; otherwise the host-side wire scan below runs
        std::string console_note;
        const std::string engine_pref = opt_str(args, "engine", "auto");
        if (engine_pref != "auto" && engine_pref != "console" && engine_pref != "host")
            fail("bad engine (auto|console|host)");
        auto* p4 = runtime::registry_ps4_active()
            ? dynamic_cast<runtime::backend_ps4_t*>(&runtime::active()) : nullptr;
        if (engine_pref == "console" && !p4)
            fail("engine=console needs a connected PS4 (target.ps4_connect)");
        if (p4 && engine_pref != "host") {
            const bool byte_wildcards = std::all_of(
                pat->nibble_mask.begin(), pat->nibble_mask.end(),
                [](uint8_t m) { return m == 0x00 || m == 0xFF; });
            if (!byte_wildcards) {
                console_note = "nibble wildcards need host-side matching";
            } else if (!p4->ps4_authed()) {
                console_note = "console scan family locked (debugger.ps4_auth)";
            } else {
                std::vector<uint8_t> cpat(pat->bytes.begin(), pat->bytes.end());
                std::vector<uint8_t> cmask(pat->size());
                for (size_t i = 0; i < pat->size(); ++i)
                    cmask[i] = pat->nibble_mask[i] == 0xFF ? 1 : 0;
                const uint32_t pid = s.pid();
                uint32_t last_error = 0;
                auto find = [&](uint64_t a, uint32_t len, uint64_t& hit) {
                    auto io = p4->ps4_scan_aob(pid, a, len, cpat, cmask, 1, 0, hit);
                    if (!io.ok) last_error = io.error;
                    return io.ok;
                };
                memory::console_aob_options_t copt;
                copt.pattern_len = pat->size();
                copt.alignment   = alignment;
                copt.max_results = max_results;
                memory::console_aob_stats_t cst{};
                infra::cancel_token_t tok;
                auto hits = memory::console_aob_all(find, regions, copt, tok, &cst);
                if (!cst.failed) {
                    std::vector<uintptr_t> matches(hits.begin(), hits.end());
                    return result(matches, {{"engine", "console"},
                                            {"truncated", cst.truncated},
                                            {"cancelled", cst.cancelled},
                                            {"bytes_scanned", cst.bytes},
                                            {"console_calls", cst.calls}});
                }
                // a scan that never produced anything falls back to the wire
                // scan; a mid-walk failure keeps the partial list and says so
                const std::string why = cst.bad_reply
                    ? std::string("payload answered outside the requested window")
                    : runtime::ps4::io_error_str(last_error);
                if (!hits.empty() || engine_pref == "console") {
                    if (hits.empty())
                        fail("console aob failed at " + addr_hex_str(cst.failed_at) + ": " + why);
                    std::vector<uintptr_t> matches(hits.begin(), hits.end());
                    return result(matches, {{"engine", "console"},
                                            {"truncated", true},
                                            {"partial", true},
                                            {"error", why},
                                            {"failed_at", addr_hex_str(cst.failed_at)},
                                            {"bytes_scanned", cst.bytes},
                                            {"console_calls", cst.calls}});
                }
                console_note = "console aob failed (" + why + "), used the wire scan";
            }
            if (engine_pref == "console") fail("engine=console unavailable: " + console_note);
        }

        memory::aob_scan_options_t opt;
        opt.alignment = alignment;
        opt.max_results = max_results;
        opt.chunk_bytes = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "chunk_bytes", 0),
            reader.hints().max_workers == 1 ? memory::kRemoteMaxChunkBytes : (64u << 20)));
        opt.threads = static_cast<uint32_t>(std::min<uint64_t>(opt_u64(args, "threads", 0), 64));
        infra::cancel_token_t tok;
        memory::aob_stats_t stats{};
        auto matches = memory::aob_scan(reader, regions, *pat, opt, tok, &stats);
        json extra = {{"engine", "host"},
                      {"truncated", stats.truncated}, {"cancelled", stats.cancelled},
                      {"bytes_scanned", stats.bytes_scanned},
                      {"io", io_hints_json(reader.hints())}};
        if (!console_note.empty()) extra["console_note"] = console_note;
        return result(matches, std::move(extra));
    }

    if (action == "protect") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len  = parse_addr(args.contains("len") ? args : json{{"len", 4096}}, "len");
        const uint32_t prot = static_cast<uint32_t>(parse_addr(args, "prot"));
        uint32_t old = 0;
        auto io = runtime::active().protect_memory(s.handle(), static_cast<uintptr_t>(addr),
                                                   static_cast<size_t>(len), prot, &old);
        if (!io.ok) fail("protect failed: " + runtime::ps4::io_error_str(io.error));
        return {{"addr", addr}, {"len", len}, {"old_protect", old}};
    }

    if (action == "alloc") {
        const uint64_t len = parse_addr(args, "len");
        if (len == 0 || len > (64ull << 20)) fail("alloc len out of range (1 byte .. 64 MiB)");
        uintptr_t out = 0;
        auto io = runtime::active().allocate_memory(s.handle(), 0, static_cast<size_t>(len),
                                                    0x40 /*PAGE_EXECUTE_READWRITE*/, &out);
        if (!io.ok) fail("alloc failed: " + runtime::ps4::io_error_str(io.error));
        return {{"addr", static_cast<uint64_t>(out)}, {"len", len}};
    }

    if (action == "free") {
        const uint64_t addr = parse_addr(args, "addr");
        auto io = runtime::active().free_memory(s.handle(), static_cast<uintptr_t>(addr));
        if (!io.ok) fail("free failed: " + runtime::ps4::io_error_str(io.error));
        return {{"freed", true}};
    }

    if (action == "pointerscan") {
        if (!args.contains("target")) fail("missing target address");
        memory::pointer_scan_options_t opt;
        opt.target = static_cast<uintptr_t>(parse_addr(args, "target"));
        opt.depth  = static_cast<uint32_t>(std::min<uint64_t>(
            opt_u64(args, "depth", 3), infra::limits::max_pointer_depth));
        const int64_t min_off = opt_i64(args, "min_offset", -4096);
        const int64_t max_off = opt_i64(args, "max_offset",  4096);
        if (min_off < INT32_MIN || min_off > INT32_MAX || max_off < INT32_MIN || max_off > INT32_MAX)
            fail("min_offset/max_offset must fit in 32 bits");
        opt.min_offset = static_cast<int32_t>(min_off);
        opt.max_offset = static_cast<int32_t>(max_off);
        opt.alignment  = static_cast<uint32_t>(std::min<uint64_t>(opt_u64(args, "alignment", 4), 4096));
        opt.only_module_backed = opt_bool(args, "static_roots", false);
        opt.frontier_cap = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "frontier_cap", 100'000), infra::limits::max_pointer_chains));

        // region set is explicit bounds or committed memory, capped since pointer sweeps scale with range
        bool range_truncated = false;
        memory::scan_config_t rcfg;
        if (args.contains("begin") && args.contains("end")) {
            rcfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            rcfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        rcfg.writable = parse_region_pref(args, "writable");
        rcfg.executable = parse_region_pref(args, "executable");
        rcfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            rcfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        rcfg.mem_private = opt_bool(args, "mem_private", true);
        rcfg.mem_image = opt_bool(args, "mem_image", true);
        rcfg.mem_mapped = opt_bool(args, "mem_mapped", true);
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), rcfg);
        if (regions.empty()) fail("no committed ranges");

        if (!args.contains("begin") || !args.contains("end")) {
            const uint64_t lo = regions.front().base;
            uint64_t hi = regions.back().base + regions.back().size;
            const uint64_t span_cap = std::min<uint64_t>(
                args.contains("max_bytes") ? parse_addr(args, "max_bytes")
                                           : (256ull << 20),
                infra::limits::max_region_scan_bytes);
            if (hi - lo > span_cap) {
                hi = lo + span_cap;
                range_truncated = true;
                // clip regions to the window
                for (auto it = regions.begin(); it != regions.end();) {
                    if (it->base >= hi) it = regions.erase(it);
                    else {
                        if (it->base + it->size > hi)
                            it->size = static_cast<size_t>(hi - it->base);
                        ++it;
                    }
                }
            }
        }

        session_reader_t reader(s);
        infra::cancel_token_t tok;
        memory::pointer_scan_stats_t stats{};
        auto chains = memory::pointer_scan(reader, regions, opt, tok, &stats);

        const size_t limit = static_cast<size_t>(std::min<uint64_t>(opt_u64(args, "limit", 100), 1000));
        json out = {{"chains", chains_json(chains, limit)}, {"total", chains.size()},
                    {"truncated", stats.truncated}, {"range_truncated", range_truncated},
                    {"edges_explored", stats.edges_explored},
                    {"io", io_hints_json(reader.hints())},
                    {"next", "memory.pointerscan_verify re-reads these chains over several "
                             "samples and keeps the ones that still land on target"}};
        // the full list (not just the listed page) feeds pointerscan_verify
        g_ptr_last.valid  = true;
        g_ptr_last.pid    = s.pid();
        g_ptr_last.target = opt.target;
        g_ptr_last.chains = std::move(chains);
        return out;
    }

    if (action == "pointerscan_verify") {
        // chains: explicit list or the last pointerscan of this target
        std::vector<memory::pointer_chain_result_t> chains;
        std::string source;
        if (args.contains("chains")) {
            const json& arr = args.at("chains");
            if (!arr.is_array() || arr.empty())
                fail("chains must be a non-empty array of {addresses|base, offsets}");
            if (arr.size() > infra::limits::max_pointer_chains)
                fail("too many chains (max " +
                     std::to_string(infra::limits::max_pointer_chains) + ")");
            for (size_t i = 0; i < arr.size(); ++i) {
                const json& c = arr[i];
                const std::string where = "chains[" + std::to_string(i) + "]";
                if (!c.is_object() || !c.contains("offsets") || !c.at("offsets").is_array())
                    fail(where + ": needs offsets[] and addresses[] (or base)");
                memory::pointer_chain_result_t pc;
                const json& offs = c.at("offsets");
                for (size_t k = 0; k < offs.size(); ++k)
                    pc.offsets.push_back(opt_i64(json{{"offset", offs[k]}}, "offset", 0));
                if (c.contains("addresses") && c.at("addresses").is_array() &&
                    !c.at("addresses").empty()) {
                    const json& addrs = c.at("addresses");
                    if (addrs.size() != offs.size())
                        fail(where + ": addresses and offsets differ in length");
                    for (size_t k = 0; k < addrs.size(); ++k)
                        pc.addresses.push_back(static_cast<uintptr_t>(
                            parse_addr(json{{"address", addrs[k]}}, "address")));
                } else if (c.contains("base")) {
                    // only the root matters when re-resolving; pad the rest
                    pc.addresses.assign(offs.size(), 0);
                    if (!pc.addresses.empty())
                        pc.addresses[0] = static_cast<uintptr_t>(parse_addr(c, "base"));
                } else {
                    fail(where + ": needs addresses[] or base");
                }
                if (pc.offsets.empty()) fail(where + ": empty chain");
                chains.push_back(std::move(pc));
            }
            source = "args";
        } else {
            if (!g_ptr_last.valid || g_ptr_last.chains.empty())
                fail("no pointer list to verify (run memory.pointerscan first or pass chains)");
            if (g_ptr_last.pid != s.pid())
                fail("the last pointer list belongs to another target (run memory.pointerscan)");
            chains = g_ptr_last.chains;
            source = "last_pointerscan";
        }

        memory::pointer_verify_options_t vo;
        if (args.contains("target")) vo.target = static_cast<uintptr_t>(parse_addr(args, "target"));
        else if (source == "last_pointerscan") vo.target = g_ptr_last.target;
        else fail("missing target (the address every chain must land on)");
        vo.samples     = static_cast<uint32_t>(std::min<uint64_t>(opt_u64(args, "samples", 3), 64));
        vo.interval_ms = static_cast<uint32_t>(
            std::min<uint64_t>(opt_u64(args, "interval_ms", 250), 60'000));
        if (vo.samples == 0) fail("samples must be >= 1");

        session_reader_t reader(s);
        infra::cancel_token_t tok;
        memory::pointer_verify_stats_t vst{};
        auto kept = memory::pointer_verify(reader, std::move(chains), vo, tok, &vst);

        const size_t limit = static_cast<size_t>(std::min<uint64_t>(opt_u64(args, "limit", 100), 1000));
        json out = {{"chains", chains_json(kept, limit)},
                    {"kept", vst.kept},
                    {"checked", vst.checked},
                    {"dropped_unreadable", vst.dropped_unreadable},
                    {"dropped_mismatch", vst.dropped_mismatch},
                    {"samples", vst.samples_done},
                    {"reads", vst.reads},
                    {"cancelled", vst.cancelled},
                    {"target", static_cast<uint64_t>(vo.target)},
                    {"target_hex", addr_hex_str(vo.target)},
                    {"source", source}};
        // the survivors become the list the next verify refines (CE workflow:
        // restart the game, find the value again, verify against the new address)
        g_ptr_last.valid  = true;
        g_ptr_last.pid    = s.pid();
        g_ptr_last.target = vo.target;
        g_ptr_last.chains = std::move(kept);
        return out;
    }

    if (action == "snapshot") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = parse_addr(args.contains("len") ? args : json{{"len", 4096}}, "len");
        if (len == 0 || len > infra::limits::max_snapshot_region_bytes)
            fail("bad snapshot len");
        const uint64_t max_bytes = std::min<uint64_t>(
            args.contains("max_bytes") ? parse_addr(args, "max_bytes") : (16ull << 20),
            infra::limits::max_snapshot_region_bytes);

        session_reader_t reader(s);
        infra::cancel_token_t tok;
        mcp_snapshot_t rec;
        rec.id  = g_snap_next_id++;
        rec.snap = memory::snapshot_capture(reader, static_cast<uintptr_t>(addr),
                                            static_cast<size_t>(len), tok, max_bytes);
        json out = {{"id", rec.id}, {"addr", addr}, {"len", len},
                    {"complete", rec.snap.complete}, {"bytes", rec.snap.bytes.size()}};
        if (g_snaps.size() >= kMaxMcpSnapshots) g_snaps.erase(g_snaps.begin());
        g_snaps.push_back(std::move(rec));
        return out;
    }

    if (action == "diff") {
        if (!args.contains("a") || !args.contains("b")) fail("missing snapshot ids a/b");
        mcp_snapshot_t* ra = find_snapshot(parse_addr(args, "a"));
        mcp_snapshot_t* rb = find_snapshot(parse_addr(args, "b"));
        if (!ra || !rb) fail("unknown snapshot id (run memory.snapshots)");
        auto d = memory::snapshot_diff(ra->snap, rb->snap);
        if (!d.valid) fail("snapshots cover different regions (base/size mismatch)");
        const size_t limit = static_cast<size_t>(std::min<uint64_t>(
            opt_u64(args, "limit", 512), infra::limits::max_diff_ranges));
        json arr = json::array();
        for (size_t i = 0; i < d.changed.size() && i < limit; ++i)
            arr.push_back({{"offset", d.changed[i].offset},
                           {"length", d.changed[i].length}});
        return {{"changed", arr}, {"count", d.changed.size()},
                {"truncated", d.changed.size() > limit}};
    }

    if (action == "siggen") {
        // wildcard the relocatable bytes so the pattern survives a rebase
        const uint64_t addr = parse_addr(args, "addr");
        size_t len = args.contains("len")
            ? static_cast<size_t>(parse_addr(args, "len")) : 32;
        if (len == 0 || len > 256) fail("siggen len must be 1..256");
        auto& eng = shared_engine();
        if (!eng.ok() && !eng.init()) fail("zydis engine init failed");

        std::vector<uint8_t> buf(len);
        auto io = s.read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
        if (!io.ok || io.bytes < len) fail("cannot read signature region");

        std::string pat;
        std::string mask;
        size_t off = 0, insns = 0;
        while (off < len) {
            auto in = eng.decode(addr + off, buf.data() + off, len - off);
            if (!in || in->length == 0) break;
            ++insns;
            for (size_t b = 0; b < in->length; ++b) {
                bool wild = false;
                // rip relative and rel32 bytes move on a rebase
                const bool is_branch =
                    in->flow != disasm::flow_t::none &&
                    in->flow != disasm::flow_t::ret;
                if (in->has_rip_rel && in->length >= 6 && b >= in->length - 4 &&
                    !is_branch)
                    wild = true;
                else if (is_branch && in->length == 5 && b >= 1)
                    wild = true;
                else if (is_branch && in->length == 6 && in->bytes[0] == 0x0F &&
                         b >= 2)
                    wild = true;

                char hex[4];
                std::snprintf(hex, sizeof(hex), "%02X ", buf[off + b]);
                if (!wild) { pat += hex; mask += 'x'; }
                else       { pat += "?? "; mask += '?'; }
            }
            off += in->length;
        }
        while (!pat.empty() && pat.back() == ' ') pat.pop_back();
        if (pat.empty()) fail("nothing decodable at that address");

        // check the pattern is unique across memory
        session_reader_t reader(s);
        infra::cancel_token_t tok;
        memory::aob_stats_t stats{};
        uint64_t hits_total = 0;
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), memory::scan_config_t{});
        if (!regions.empty()) {
            constexpr uint64_t kSpanCap = 512ull << 20;
            const uint64_t lo = regions.front().base;
            uint64_t hi = regions.back().base + regions.back().size;
            if (hi - lo > kSpanCap) {
                hi = lo + kSpanCap;
                for (auto it = regions.begin(); it != regions.end();) {
                    if (it->base >= hi) it = regions.erase(it);
                    else {
                        if (it->base + it->size > hi)
                            it->size = static_cast<size_t>(hi - it->base);
                        ++it;
                    }
                }
            }
            std::string compile_err;
            auto pat2 = memory::aob_compile(pat, compile_err);
            if (pat2) {
                auto matches = memory::aob_scan(reader, regions, *pat2,
                                                memory::aob_scan_options_t{},
                                                tok, &stats);
                hits_total = matches.size();
            }
        }

        json out = {{"addr", addr}, {"pattern", pat}, {"mask", mask},
                    {"length", off}, {"instructions", insns},
                    {"unique", hits_total == 1},
                    {"occurrences", hits_total}};
        out["yara"] = "$a = { " + pat + " }\ncondition: $a";
        return out;
    }

    if (action == "live_crypto") {
        // defaults to the loaded image since thats what youre reversing
        uint64_t begin = args.contains("begin") ? parse_addr(args, "begin") : 0;
        uint64_t end   = args.contains("end")   ? parse_addr(args, "end")   : 0;
        if (!begin) {
            {
                std::lock_guard lk(ds::state_mutex());
                auto& bin = ds::get();
                if (bin.ready && bin.pe.size_of_image) {
                    begin = bin.base;
                    end   = bin.base + bin.pe.size_of_image;
                }
            }
            if (!begin) {
                auto ranges = committed_ranges(s);
                if (ranges.empty()) fail("no committed ranges and no loaded image");
                begin = ranges.front();
                end   = ranges.back();
                constexpr uint64_t kDefault = 1u << 20;
                end = std::min<uint64_t>(begin + kDefault, end);
            }
        }
        const uint64_t cap = std::min<uint64_t>(
            end <= begin ? 4096 : end - begin, 1ull << 20);

        auto& eng = shared_engine();
        std::vector<uint8_t> buf(static_cast<size_t>(cap));
        auto io = s.read(static_cast<uintptr_t>(begin), buf.data(), buf.size());
        if (!io.ok || io.bytes == 0) fail("cannot read target range");
        const size_t limit = static_cast<size_t>(std::min<uint64_t>(opt_u64(args, "limit", 256), 1000));
        auto hits = xray::crypto_range_bytes(begin, buf.data(), io.bytes,
                                             eng.ok() ? &eng : nullptr, limit);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"va", h.va}, {"algorithm", h.algorithm},
                           {"constant", h.constant_name}, {"value", h.value},
                           {"source", h.source}});
        return {{"range_begin", begin}, {"bytes", io.bytes},
                {"matches", arr}, {"count", arr.size()}};
    }

    fail("memory: unknown action (read|write|scan|rescan|scan_state|scan_reset|"
         "aob|pointerscan|pointerscan_verify|snapshot|snapshots|diff|snapshot_free|protect|alloc|"
         "free|siggen|live_crypto|watch_list|watch_add|watch_remove|watch_clear|"
         "watch_set)");
}

} // namespace slop::core::mcp::detail
