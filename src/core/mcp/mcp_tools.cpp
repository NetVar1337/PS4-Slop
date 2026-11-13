// src/core/mcp/mcp_tools.cpp
// tool schemas, tools/list, dispatch and shutdown; the handlers live in tools_*.cpp
// every tool call is serialized through g_tool_mu and the response is enriched

#include "core/mcp/tools_common.hpp"
#include "core/mcp/mcp_server.hpp"
#include "core/runtime/broker.hpp"
#include "core/runtime/gdb_rsp.hpp"

namespace slop::core::mcp {

using namespace detail;

namespace {

// ---- audit trail + confirm gate (ps4debug-mcp safety model) ----
// every tool call is appended as one JSONL line to the audit log; when the
// mcp_require_confirm setting is on, mutating console/target actions refuse
// to run without "confirm": true in the args

bool ps4_action_readonly(const std::string& a) {
    static const std::unordered_set<std::string> ro = {
        "status", "ps4_status", "ps4_console_info", "ps4_regs", "ps4_dbregs",
        "ps4_fpregs", "ps4_fsgs", "ps4_events", "ps4_callstack", "ps4_stack",
        "ps4_bp_list", "ps4_watch_list", "ps4_disasm", "ps4_xrefs", "ps4_xrefs_to",
        "ps4_modules", "ps4_snapshot", "ps4_assemble", "ps4_wait",
        "ps4_scan", "ps4_rescan", "ps4_scan_all", "ps4_scan_aob", "ps4_scan_state",
        "ps4_turbo_caps", "ps4_turbo_scan", "ps4_turbo_rescan", "ps4_turbo_results",
        "ps4_turbo_regions", "ps4_turbo_cancel"
    };
    return ro.count(a) != 0;
}

bool action_mutating(const std::string& tool, const std::string& action) {
    if (tool == "debugger") {
        if (action.rfind("ps4_", 0) == 0) return !ps4_action_readonly(action);
        static const std::unordered_set<std::string> ro = {
            "status", "regs", "callstack", "events", "wait", "bp_list", "watch_list"
        };
        return ro.count(action) == 0;
    }
    if (tool == "memory") {
        static const std::unordered_set<std::string> ro = {
            "read", "scan", "rescan", "scan_state", "aob", "pointerscan",
            "pointerscan_verify", "snapshot", "snapshots", "diff", "siggen",
            "live_crypto", "watch_list"
        };
        return ro.count(action) == 0;
    }
    if (tool == "target") {
        static const std::unordered_set<std::string> ro = {
            "list", "status", "modules", "threads", "regions", "handles",
            "heaps", "heap_blocks", "icon", "ps4_connect", "ps4_discover",
            "ps4_dump_module"
        };
        return ro.count(action) == 0;
    }
    if (tool == "patch" || tool == "persist" || tool == "notes" || tool == "types" ||
        tool == "script")
        return true;
    if (tool == "host")
        return action != "status" && action != "files" && action != "manifest";
    if (tool == "gdb")
        return action != "status";
    if (tool == "proxy")
        // replay re-sends captured POST/PUT/DELETE requests, so it is a write
        return action != "status" && action != "entries" && action != "entry";
    if (tool == "fs")
        // reads and walks are safe; create/write/delete are host mutations
        return action != "read_file" && action != "list_directory" &&
               action != "search_files" && action != "grep_in_files";
    if (tool == "network")
        return action != "packets" && action != "dns" && action != "stats" &&
               action != "connections" && action != "streams" &&
               action != "stream_data";
    return false;
}

std::mutex g_audit_mu;

// The audit log is a plaintext file on disk; bearer tokens, proxy credentials
// and cookies must never land in it. Redact by key before the dump, including
// nested objects (host.start returns a token, app.rotate_token returns the new
// primary bearer, proxy.entry returns captured Authorization/Cookie headers).
bool audit_sensitive_key(const std::string& key) {
    std::string k;
    k.reserve(key.size());
    for (char c : key) k.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    static const char* kSensitive[] = {
        "token", "authorization", "cookie", "password", "secret", "api_key",
        "apikey", "credential"
    };
    for (const char* s : kSensitive)
        if (k.find(s) != std::string::npos) return true;
    return false;
}

void audit_redact(json& v) {
    if (v.is_object()) {
        for (auto it = v.begin(); it != v.end(); ++it) {
            if (audit_sensitive_key(it.key())) it.value() = "<redacted>";
            else audit_redact(it.value());
        }
    } else if (v.is_array()) {
        for (auto& e : v) audit_redact(e);
    }
}

void audit_log(const std::string& tool, const json& args, const json& out,
               bool is_error) {
    if (!infra::settings::mcp_audit_enabled()) return;
    const std::string path = infra::settings::mcp_audit_path();
    if (path.empty()) return;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    // memory reads can hand back junk bytes, so never let the audit sink throw
    // on invalid utf8 (that would turn a good tool call into a 500)
    json args_safe = args;
    json out_safe  = out;
    audit_redact(args_safe);
    audit_redact(out_safe);
    const std::string args_dump = args_safe.dump(-1, ' ', false, json::error_handler_t::replace);
    const std::string out_dump  = out_safe.dump(-1, ' ', false, json::error_handler_t::replace);
    constexpr size_t kCap = 2048;
    json line = {{"ts_ms", ms},
                 {"tool", tool},
                 {"action", args.is_object() ? args.value("action", std::string{})
                                             : std::string{}},
                 {"ok", !is_error}};
    if (args_dump.size() <= kCap) line["args"] = args_safe;
    else line["args_truncated"] = args_dump.substr(0, kCap);
    if (is_error) {
        if (out_safe.is_object() && out_safe.contains("error")) line["error"] = out_safe["error"];
        else line["error"] = out_dump.substr(0, kCap);
    } else if (out_dump.size() <= kCap) {
        line["result"] = out_safe;
    } else {
        line["result_truncated"] = out_dump.substr(0, kCap);
    }
    std::lock_guard lk(g_audit_mu);
    std::ofstream f(path, std::ios::app);
    if (f) f << line.dump(-1, ' ', false, json::error_handler_t::replace) << "\n";
}

// ---- AI-rich output enrichment (additive only, never removes keys) ----
// Every VA the server returns is a decimal u64. Agents copy/paste hex, need
// symbol context, units, enum meanings, and next-step guidance to stay
// accurate. The helpers below mirror every address as 0x-hex, resolve known
// symbols, decode raw Windows/network constants, and attach per-action hints.
// All enrichment is best-effort and exception-free: it must never fail a call.



std::string mem_protect_str(uint32_t p) {
    const uint32_t base = p & 0xFFu;
    std::string s;
    switch (base) {
    case 0x01: s = "NOACCESS"; break;
    case 0x02: s = "R--"; break;
    case 0x04: s = "RW-"; break;
    case 0x08: s = "RW-COPY"; break;
    case 0x10: s = "--X"; break;
    case 0x20: s = "R-X"; break;
    case 0x40: s = "RWX"; break;
    case 0x80: s = "RX-COPY"; break;
    default:   s = "UNKNOWN"; break;
    }
    if (p & 0x100u) s += "+GUARD";
    if (p & 0x200u) s += "+NOCACHE";
    if (p & 0x400u) s += "+WRITECOMBINE";
    return s;
}

std::string mem_state_str(uint32_t st) {
    if (st & 0x1000u)  return "COMMIT";
    if (st & 0x2000u)  return "RESERVE";
    if (st & 0x10000u) return "FREE";
    return "UNKNOWN";
}

std::string mem_type_str(uint32_t t) {
    if (t & 0x1000000u) return "IMAGE";
    if (t & 0x40000u)   return "MAPPED";
    if (t & 0x20000u)   return "PRIVATE";
    return "UNKNOWN";
}

const char* net_proto_str(uint32_t p) {
    switch (p) {
    case 6:  return "tcp";
    case 17: return "udp";
    case 1:  return "icmp";
    default: return "other";
    }
}

const char* net_dir_str(uint32_t d) {
    // traffic_store: 0 = outbound, 1 = inbound
    return d == 0 ? "outbound" : "inbound";
}

const char* hw_type_str(uint32_t t) {
    switch (t) {
    case 0: return "exec";
    case 1: return "write";
    case 3: return "read_write";
    default: return "unknown";
    }
}

std::string rflags_str(uint64_t f) {
    // set-flag mnemonics only, so the agent can read ZF/SF/etc at a glance
    static const char* kNames[22] = {
        "CF", nullptr, "PF", nullptr, "AF", nullptr, "ZF", "SF",
        "TF", "IF", "DF", "OF", "IOPL1", "IOPL2", "NT", nullptr,
        "RF", "VM", "AC", "VIF", "VIP", "ID",
    };
    std::string s;
    for (int i = 0; i < 22; ++i) {
        if (!kNames[i]) continue;
        if (f & (1ull << i)) {
            if (!s.empty()) s += "+";
            s += kNames[i];
        }
    }
    return s.empty() ? "none" : s;
}

struct enrich_ctx_t {
    std::unordered_map<uint64_t, std::string> syms;        // user renames
    std::unordered_map<uint64_t, std::string> hype_names;  // analyzer names
    std::string image_name;
    uint64_t    image_base = 0;
    uint64_t    image_size = 0;
    bool        have_image = false;
};

enrich_ctx_t snapshot_enrich_ctx() {
    enrich_ctx_t ctx;
    try {
        auto snaps = ds::symbols_snapshot();
        ctx.syms.reserve(snaps.size());
        for (auto& [va, nm] : snaps) ctx.syms.emplace(va, nm);
    } catch (...) {}
    try {
        // caller holds g_tool_mu; take the binary lock in the same order as
        // loaded_image_json (tool mutex -> state mutex) so this cannot deadlock
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (bin.ready) {
            ctx.have_image = true;
            ctx.image_name = bin.name;
            ctx.image_base = bin.base;
            ctx.image_size = bin.pe.size_of_image;
            if (bin.hype && bin.hype->ready()) {
                const auto& nm = bin.hype->db().names;
                ctx.hype_names.reserve(nm.size());
                for (const auto& [va, s] : nm) ctx.hype_names.emplace(va, s);
            }
        }
    } catch (...) {}
    return ctx;
}

std::string resolve_enrich_name(uint64_t va, const enrich_ctx_t& ctx) {
    auto it = ctx.syms.find(va);
    if (it != ctx.syms.end() && !it->second.empty()) return it->second;
    auto jt = ctx.hype_names.find(va);
    if (jt != ctx.hype_names.end()) return jt->second;
    return {};
}

std::string modoff_str(uint64_t va, const enrich_ctx_t& ctx) {
    char buf[32] = "";
    if (ctx.have_image && !ctx.image_name.empty() && va >= ctx.image_base &&
        (!ctx.image_size || va < ctx.image_base + ctx.image_size)) {
        std::snprintf(buf, sizeof(buf), "+0x%llX",
                      static_cast<unsigned long long>(va - ctx.image_base));
        return ctx.image_name + buf;
    }
    // outside the loaded image: resolve through the attached target's module
    // table (warmed by target.modules / target.attach)
    if (const auto* m = process::va_to_module(static_cast<uintptr_t>(va))) {
        std::snprintf(buf, sizeof(buf), "+0x%llX",
                      static_cast<unsigned long long>(va - m->base));
        return std::string(m->name) + buf;
    }
    return {};
}

bool is_addr_key(const std::string& k) {
    // decimal-u64 VA fields the server emits; keep in sync with handlers
    static const char* kKeys[] = {
        "va", "addr", "from", "base", "entry", "entry_va", "function_va",
        "vftable_va", "td_va", "vtable_va", "target", "dispatcher",
        "image_base", "module_base", "ntos_base", "lstar", "service_table",
        "peb_address", "ldr_address", "process_heap", "teb_address",
        "handler", "frame", "ret_addr", "frame_ptr", "rip", "rsp", "rbp",
        "start", "end", "header", "back_edge_src", "address", "slot_va",
        "assign_addr", "vftable", "module", "func", "fn_va",
    };
    for (const char* c : kKeys)
        if (k == c) return true;
    return false;
}

bool is_addr_array_key(const std::string& k) {
    static const char* kKeys[] = {
        "targets", "entries", "matches", "references", "callsites",
        "methods", "successors", "preds", "succs", "slots",
    };
    for (const char* c : kKeys)
        if (k == c) return true;
    return false;
}

// decode raw constants on region-like / packet-like / bp-like objects
void decode_enrich_object(json& o) {
    try {
        // memory region: {base,size,protect,state,type}
        if (o.contains("base") && o.contains("size") && o.contains("protect") &&
            (o.at("protect").is_number_unsigned() || o.at("protect").is_number_integer())) {
            const uint32_t p = static_cast<uint32_t>(o.at("protect").get<int64_t>());
            if (!o.contains("protect_str")) o["protect_str"] = mem_protect_str(p);
            if (o.contains("state") &&
                (o.at("state").is_number_unsigned() || o.at("state").is_number_integer()) &&
                !o.contains("state_str"))
                o["state_str"] = mem_state_str(static_cast<uint32_t>(o.at("state").get<int64_t>()));
            if (o.contains("type") && !o.at("type").is_string() &&
                (o.at("type").is_number_unsigned() || o.at("type").is_number_integer()) &&
                !o.contains("type_str"))
                o["type_str"] = mem_type_str(static_cast<uint32_t>(o.at("type").get<int64_t>()));
            if (!o.contains("units"))
                o["units"] = {{"base", "VA decimal, see base_hex"},
                              {"size", "bytes"},
                              {"protect/state/type", "raw Windows constants, see *_str"}};
        }
        // network packet / held intercept: {protocol,direction,...}
        if (o.contains("protocol") &&
            (o.at("protocol").is_number_unsigned() || o.at("protocol").is_number_integer()) &&
            (o.contains("direction") || o.contains("local") || o.contains("remote"))) {
            if (!o.contains("protocol_str"))
                o["protocol_str"] = net_proto_str(static_cast<uint32_t>(o.at("protocol").get<int64_t>()));
            if (o.contains("direction") &&
                (o.at("direction").is_number_unsigned() || o.at("direction").is_number_integer()) &&
                !o.contains("direction_str"))
                o["direction_str"] = net_dir_str(static_cast<uint32_t>(o.at("direction").get<int64_t>()));
        }
        // standalone direction (block_ip/port/process echo the int back)
        if (o.contains("direction") &&
            (o.at("direction").is_number_unsigned() || o.at("direction").is_number_integer()) &&
            !o.contains("direction_str") &&
            (o.contains("blocked") || o.contains("rule_id"))) {
            o["direction_str"] = net_dir_str(static_cast<uint32_t>(o.at("direction").get<int64_t>()));
        }
        // hardware breakpoint record: {slot,type,len,hardware}
        if (o.contains("slot") && o.contains("len") && o.contains("type") &&
            (o.at("type").is_number_unsigned() || o.at("type").is_number_integer()) &&
            !o.contains("type_str")) {
            o["type_str"] = hw_type_str(static_cast<uint32_t>(o.at("type").get<int64_t>()));
            if (!o.contains("type_help"))
                o["type_help"] = "0=exec 1=write 3=read_write; len is 1/2/4/8";
        }
        // register state: {rip,flags,...}
        if (o.contains("rip") && o.contains("flags") &&
            (o.at("flags").is_number_unsigned() || o.at("flags").is_number_integer()) &&
            !o.contains("flags_str")) {
            const uint64_t fl = o.at("flags").is_number_unsigned()
                ? o.at("flags").get<uint64_t>()
                : static_cast<uint64_t>(o.at("flags").get<int64_t>());
            o["flags_str"] = rflags_str(fl);
        }
        // xray complexity rating scale
        if (o.contains("complexity_rating") && o.at("complexity_rating").is_string() &&
            !o.contains("complexity_rating_help")) {
            o["complexity_rating_help"] =
                "branch-count scale: simple<=5 branches, moderate<=10, complex<=20, "
                "very_complex<=50, extremely_complex>50";
        }
        // xray entropy verdict vocabulary
        if (o.contains("overall_entropy") && o.contains("verdict") &&
            !o.contains("verdict_help")) {
            o["verdict_help"] =
                "window verdicts: low_entropy|normal|high_entropy|encrypted_or_compressed "
                "(window entropy>7.0); overall>7.5 means almost certainly packed/encrypted";
        }
        // obfuscation / anti-analysis scores are 0-100
        if (o.contains("obfuscation_score_pct") && !o.contains("score_help"))
            o["score_help"] = "0-100; higher means more obfuscated (junk/opaque/indirect patterns)";
        if (o.contains("anti_analysis_score_pct") && !o.contains("score_help"))
            o["score_help"] = "0-100; higher means more anti-debug/VM/timing/trap detections";
    } catch (...) {}
}

void enrich_json_value(json& v, const enrich_ctx_t& ctx, int depth) {
    if (depth > 14) return;
    try {
        if (v.is_object()) {
            std::vector<std::string> keys;
            keys.reserve(v.size());
            for (auto it = v.begin(); it != v.end(); ++it) keys.push_back(it.key());
            for (const auto& k : keys) {
                // NOTE: never hold v.at(k) across a v[...] insertion below;
                // object insertion may rehash and invalidate the reference.
                bool addr_num = false;
                int64_t addr_sv = 0;
                {
                    const json& cur = v.at(k);
                    if ((cur.is_number_unsigned() || cur.is_number_integer()) &&
                        is_addr_key(k)) {
                        addr_num = true;
                        addr_sv = cur.is_number_unsigned()
                            ? static_cast<int64_t>(cur.get<uint64_t>())
                            : cur.get<int64_t>();
                    }
                }
                if (addr_num && addr_sv >= 0) {
                    const uint64_t va = static_cast<uint64_t>(addr_sv);
                    const std::string hk = k + "_hex";
                    if (!v.contains(hk)) v[hk] = addr_hex_str(va);
                    if (va != 0) {
                        const std::string nm = resolve_enrich_name(va, ctx);
                        if (!nm.empty() && !v.contains("symbol") &&
                            !v.contains("name") && !v.contains(k + "_name"))
                            v[k + "_name"] = nm;
                        const std::string mo = modoff_str(va, ctx);
                        if (!mo.empty()) {
                            const std::string mk = k + "_modoff";
                            if (!v.contains(mk)) v[mk] = mo;
                        }
                    }
                } else {
                    const json& cur = v.at(k);
                    if (cur.is_array() && is_addr_array_key(k) && !cur.empty() &&
                        cur.size() <= 20000) {
                        bool all_ints = true;
                        for (const auto& e : cur) {
                            if (!e.is_number_unsigned() && !e.is_number_integer()) {
                                all_ints = false;
                                break;
                            }
                        }
                        if (all_ints) {
                            const std::string hk = k + "_hex";
                            if (!v.contains(hk)) {
                                json hx = json::array();
                                for (const auto& e : cur) {
                                    int64_t sv = e.is_number_unsigned()
                                        ? static_cast<int64_t>(e.get<uint64_t>())
                                        : e.get<int64_t>();
                                    hx.push_back(addr_hex_str(
                                        sv < 0 ? 0 : static_cast<uint64_t>(sv)));
                                }
                                v[hk] = std::move(hx);
                            }
                        }
                    }
                }
                enrich_json_value(v.at(k), ctx, depth + 1);
            }
            decode_enrich_object(v);
        } else if (v.is_array()) {
            if (v.size() > 20000) return;
            for (auto& e : v) enrich_json_value(e, ctx, depth + 1);
        }
    } catch (...) {}
}

const char* hint_for_tool_action(const std::string& tool, const std::string& action) {
    // one-line next-step guidance so the agent chains calls correctly
    if (tool == "target") {
        if (action == "list") return "Pick a pid, then target.attach {pid}. Use target.status to confirm backend first.";
        if (action == "attach") return "Next: target.modules + memory.regions to map the target; disasm.loaded shows whether the image auto-loaded at its runtime base.";
        if (action == "status") return "attached=false means all memory/debugger actions will refuse; image.ready=false means static tools need disasm.load or an explicit path.";
        if (action == "modules") return "Bases are runtime VAs (ASLR). Pass a module base to dump_module, or an address inside it to memory.read / debugger.bp_set.";
        if (action == "regions") return "size is bytes; protect/state/type are raw Windows constants, read *_str. COMMIT+RWX regions are the usual scan targets.";
        if (action == "dump_module") return "complete=false means unreadable spans were zero-filled (strict=false); verify imports with disasm.pe on the dumped file.";
        if (action == "threads") return "start is a VA (see start_hex); resolve owner function with disasm.functions or decomp.function.";
        if (action == "handles") return "count is returned rows, total is the full table; granted_access is a raw mask.";
        if (action == "heaps") return "Local targets only. base is the heap base for heap_blocks; size is the heap segment size.";
        if (action == "heap_blocks") return "heap_base comes from target.heaps; blocks are allocation records (address/size/flags), capped by max_blocks.";
        if (action == "ps4_connect") return "Connected to the console: target.list lists PS4 processes, then target.attach {pid}. Memory/disasm tools then read the console over ps4debug-NG.";
        if (action == "ps4_disconnect") return "Console connection dropped; backend is local again. Use target.list/attach for local processes.";
        if (action == "ps4_reconnect") return "After a dropped connection (target.status ps4.lost=true): re-runs the handshake+auth, re-attaches the debug session and re-arms every breakpoint/watchpoint; the attached session keeps working. Check debug_restored and *_lost counts.";
        if (action == "ps4_dump_module") return "format=raw is the mapped span (gaps zero-filled); format=elf (default with load=true) rebuilds an ELF64 with one PT_LOAD per console segment at its runtime VA, so disasm.* works on the dump. complete=false means unreadable pages were zero-filled.";
    } else if (tool == "memory") {
        if (action == "read") return "len is bytes actually returned (may be short on partial reads). Use format u32/u64 for pointers, utf8 for strings. Values carry addr_hex for copy/paste.";
        if (action == "scan") return "Refine with rescan (same width/kind), inspect scan_state, release with scan_reset. Hits carry addr_hex; read them with memory.read. io.remote=true: console target, one worker with 8 MiB read-ahead chunks; leave threads/chunk_bytes unset.";
        if (action == "rescan") return "Narrowing only: rescan filters the previous hit set. Start over with scan + scan_reset for a new value type.";
        if (action == "aob") return "Pattern is IDA-style hex with ?? wildcards. On a PS4 engine=console returns every hit searched on-device (needs ps4_auth); engine=host streams memory. total is all hits, listed_truncated means raise limit.";
        if (action == "pointerscan") return "chains[].addresses are the pointer path (see *_hex); depth/offsets are in bytes. Next: memory.pointerscan_verify {samples,interval_ms} drops chains that stop landing on target.";
        if (action == "pointerscan_verify") return "Keeps chains that land on target every sample; survivors replace the stored list, so after a restart pass the new target address to refine again.";
        if (action == "siggen") return "pattern/mask use x/? wildcards; yara is ready to reuse. unique=false means occurrences>1, widen the range.";
        if (action == "live_crypto") return "Scans committed live memory (default is the loaded module range). Matches carry va_hex; cross-check constants with analyze.signatures.";
        if (action == "watch_add" || action == "watch_list") return "addr accepts hex strings; width is a type name or 1/2/4/8 bytes. Poll watch_list; hold_failed=true means the freeze write was rejected (ok=false).";
    } else if (tool == "disasm") {
        if (action == "loaded") return "image.ready=false: load first. hype.ready=false: poll loaded until progress=1; blocks/globals/vtables/decomp all wait on it. hype.managed=true means a .NET assembly: disasm.managed lists types/methods/IL.";
        if (action == "managed") return "managed=false: not a .NET/CLI image. Otherwise types_list (type_filter narrows), type={name} renders dnSpy-style C#, method_token=0x06xxxxxx renders the IL listing.";
        if (action == "functions") return "Server-side paging: filter (case-insensitive substring of the name or hex VA), offset, limit. total = all functions, matched = after filter, returned = this page; next_offset is set while more matches remain. name is the user symbol, analyzer name, or canonical sub_<VA>. Pass a function-start va to decomp.function, xray.cfg, or disasm.xrefs.";
        if (action == "xrefs") return "from is the referencing instruction VA (see from_hex). kind call>jump>write>read>offset. Verify callers by disassembling from.";
        if (action == "strings") return "total_scanned is bytes scanned, not hits; truncated=true means limit was hit. Set include_exec=true to also scan code sections.";
        if (action == "disassemble") return "Live memory wins when attached, else the file image. count is decoded instructions; engine=hyperion uses Zydis for x86/x64 and Capstone for ARM/ARM64.";
        if (action == "pe") return "rva fields are file-relative: VA = image_base + rva (see image_base_hex). exec/writable decode characteristics.";
        if (action == "blocks") return "entry is the function start; succs/preds are block-start VAs (see *_hex). Loops list header/back_edge_src for cycle analysis.";
        if (action == "symbols") return "User renames only; analyzer names live in functions[].name. Rename with symbol_set (empty name clears).";
        if (action == "load") return "Loads PE, Mach-O (thin/FAT), an .ipa main executable, ELF (PS4 eboot/prx dumps, Linux/FreeBSD), or a PS4 SELF (fake-signed/unencrypted; an encrypted retail SELF fails and points to target.ps4_dump_module). ELF/SELF relocations are applied unless relocate=false (use false for memory dumps). Poll disasm.loaded until hype.ready=true before decomp/DB queries.";
    } else if (tool == "debugger") {
        if (action == "status") return "PS4-only build: reports the console debug state (ps4_connected, debug_attached, debug_pid, pending_events).";
        if (action.rfind("ps4_", 0) == 0) return "PS4 console tooling via ps4debug-NG. Live debugging: target.ps4_connect {host} (or ps4_auto {host}) -> ps4_attach {pid} -> ps4_bp_set {addr} / ps4_watch_set {addr,type,len} -> ps4_continue -> ps4_wait {timeout_ms} (stop event with rip/regs) -> ps4_regs/ps4_callstack/ps4_events -> ps4_step or ps4_continue again. ps4_call {addr, args} runs a function in the console process and returns rax. One-call power actions: ps4_until, ps4_find_write, ps4_trace_calls, ps4_trace_steps. Console-side game hacking: ps4_scan {addr,len,value_type,compare,value} + ps4_rescan + ps4_scan_state/reset (native on-console value scan, unlocked by ps4_auth), ps4_scan_all (whole-memory), ps4_scan_aob {addr,len,pattern} (pattern with ?? wildcards), Turbo Scan (fast, results stay on the console): ps4_turbo_caps, ps4_turbo_scan {addr,len | regions:writable, value_type, compare, value} (compare unknown -> snapshot scan, no seed value), ps4_turbo_rescan {compare, value}, ps4_turbo_results {start,count}, ps4_turbo_regions (uncached/slow region map), ps4_turbo_cancel, ps4_turbo_end, ps4_turbo_config {ram_mb, spill_path}; ps4_write_multi {writes:[{addr,hex}|{addr,value,value_type}]} applies many verified pokes in one round-trip, NetVar1337 fork extensions: ps4_modules (server-side module list), ps4_snapshot {addr,len,path} (one-round-trip region dump of any size), ps4_status shows fork_extensions/reconnects (the payload drops the client on most failures; the backend reconnects on the next command and errors carry the console's CMD_ERR_* code), ps4_disasm/ps4_xrefs/ps4_xrefs_to (on-device disasm+xrefs), ps4_stack (server-side frame walk), ps4_assemble {asm} (on-device Keystone), ps4_elf_rpc/ps4_elf_load {path} (run a payload ELF in the game), ps4_notify/ps4_print/ps4_app (console UI/log/foreground game), ps4_fpregs/ps4_set_fpregs/ps4_set_dbregs/ps4_fsgs/ps4_set_fsgs (full register sets). target.ps4_dump_module {name|base,path,load} dumps a module over the wire. ps4_* actions fail with a clear error when no console is connected.";
    } else if (tool == "xray") {
        if (action == "cfg" || action == "complexity") return "Pass a function-start VA from disasm.functions. block_count/edge_count/back_edges feed cyclomatic=edges-blocks+2. Cross-check entry with decomp.function.";
        if (action == "cff") return "flattened=false carries no dispatcher (no score). flattened=true lists dispatcher + state_blocks; recover with devirt.recover_cfg.";
        if (action == "obfuscation") return "score_pct is 0-100. warning means addr did not decode (data, not code). Confirm with disasm.disassemble first.";
        if (action == "anti_analysis") return "score_pct is 0-100; detections[].type/detail name the check. Verify INT3/timing hits by disassembling address.";
        if (action == "hooks") return "functions_checked is min(index,max_functions); hooks carry address_hex/target_hex. Compare prologue_bytes against a clean image.";
        if (action == "syscalls") return "abi=windows: syscall_number is the NT SSN, resolve it against the matching ntdll/ntoskrnl. abi=ps4 (ELF/SELF): name is the Orbis syscall (FreeBSD 9 + Sony table), null when unassigned.";
        if (action == "apihash") return "Searches THIS image's imports only (bare API and DLL!API forms), not a global dictionary. unresolved = total_queried-resolved_count.";
        if (action == "entropy") return "overall>7.5 or verdict encrypted_or_compressed suggests packing. windows[] capped by window_limit (0=summary only).";
        if (action == "gadgets") return "text is the gadget disassembly; count is capped by limit. Filter ret/jmp/call endings for ROP/JOP chains.";
        if (action == "crypto_range") return "Matches carry va_hex; constant/value name the hit. Confirm in-context with disasm.disassemble.";
    } else if (tool == "decomp") {
        return "function_va is the identity anchor (signature/body names follow user>hyperion>sub_rva precedence and may differ). lines[].va==0 marks synthetic lines. Set annotate_bytes=true for VA-prefixed text.";
    } else if (tool == "re") {
        if (action == "rtti_scan") return "abi msvc (PE) or itanium (ELF/SELF). td_va/vtable_va carry *_hex; methods[] are bare VAs, symbolize via disasm.functions. Itanium entries add mangled + bases. Fallback path (no hype) returns vftables[] (address points, primary first).";
        if (action == "vftable") return "targets[] are function VAs (see targets_hex); resolve each with decomp.function or disasm.xrefs.";
        if (action == "danger") return "iat_va is the import slot; callsites[] are call sites (see callsites_hex). Verify with disasm.xrefs on iat_va.";
        if (action == "libsig") return "hits carry va/function_va hex; requested-count is misses. Confirm matches by disassembling va.";
    } else if (tool == "analyze") {
        if (action == "packer") return "packed=false with confidence<0.5 is a clean MSVC-style build. Detections carry type/protector/detail/location; sections[] entropy>7.0 suggests packing.";
        if (action == "signatures") return "signatures[] are crypto-constant hits (offset is file offset); named_functions[] are analyzer names (RTTI/vtable/thunk included, NOT FLIRT-verified).";
        if (action == "diff") return "count is non-identical functions shown (cap 500); totals{added,removed,modified,identical} cover the full pair. similarity is 0-1.";
    } else if (tool == "emulate") {
        return "stopped_reason names the halt (return/until/count/timeout/cancelled/invalid_mem_*/invalid_insn/cpu_exception). timeout_ms caps at 30000. regs echo final state; trace[] is bounded by trace_max. Maps are extra regions beyond the code window; imports/IAT are NOT mapped.";
    } else if (tool == "patch") {
        if (action == "journal") return "patches[] carry va + before/after hex blobs. total is patch records; indexes_dirty=true means static tools rebuild on next call.";
        if (action == "full_pass") return "scores are 0-100 obfuscation ratings; score_reduction=pre-post. steps[] show per-pass success/note. dry_run=true previews without writing.";
        return "Mutates the file-image session only (not live memory; use memory.write for that). Follow write_bytes with patch.rebuild(addr) so disasm/decomp reflect the edit.";
    } else if (tool == "devirt") {
        if (action == "identify") return "confidence_pct is 0-100; likely_vm=false means no VM on this clean function. On likely_vm=true, feed table+entry_size into handlers.";
        if (action == "prove_predicates") return "predicates[] with proven_always_taken/never_taken=true are opaque; patch with patch.resolve_opaque.";
        if (action == "iat_audit") return "named/unnamed_valid/invalid count import slots; unnamed_candidates[] carry slot_va/target hex for manual repair.";
        if (action == "recover_cfg") return "flattened=false with mode=none is a normal function. corroborated=true means dynamic runs agree with the static map.";
        return "Themida jobs are async: themida_start returns id, poll themida_job until terminal, cancel with themida_cancel. Static actions need a loaded image.";
    } else if (tool == "types") {
        if (action == "declare") return "declared counts structs+enums created. Accepted: struct Name { u32 a; ... }; and packed forms struct Name {...} packed; / packed struct Name {...};. Verify with get_struct.";
        if (action == "format_at") return "rendered is display text; source=file uses the image, live=true uses attached memory. addr_hex echoes the VA.";
        if (action == "read_field") return "hex/uint/int/double are all coercions of the same bytes; source names file|target. Confirm layout with get_struct first.";
        return "Catalog persists per binary hash; load the intended binary first. Sizes/offsets are bytes; packed removes padding.";
    } else if (tool == "notes") {
        return "Annotations persist per binary hash and mirror into the UI. set_comment with empty text clears (cleared=true). bookmark_toggle flips; call twice to test direction.";
    } else if (tool == "network") {
        if (action == "packets") return "protocol/direction are raw ints, read *_str (6=tcp 17=udp; 0=outbound 1=inbound). payload_hex capped at 96B; wire_bytes > payload_bytes means the capture kept a prefix; fetch stream bytes via stream_data. tail=true returns the newest packets.";
        if (action == "stream_data") return "bytes is returned length, total is the stream's held bytes; offset/len page through it. text substitutes '.' for non-printables.";
        return "Capture flow: capture_start {host: console IP} -> packets/dns/streams/stats -> capture_stop (raw sockets with SIO_RCVALL on every interface, IPv4+IPv6, needs admin; host/port/protocol are capture filters applied before storing; there is no per-process attribution). export_pcap writes the newest stored packets. Proxy/MITM actions live in the proxy tool.";
    } else if (tool == "guide") {
        if (action == "list") return "Topics are workflow playbooks: guide get {topic} returns the exact ordered tool calls (tool/action/params/why) for that task.";
        if (action == "get") return "steps[] is a ready-to-run sequence; copy tool+action+params into real calls, filling in addresses/pids from target/memory/disasm results.";
    } else if (tool == "persist") {
        return "save returns id (data capped at 16 MiB, kv values at 1 MiB, names/keys at 256 B); load echoes id/name/created_at + data. hype_save writes a versioned .hdb dir; hype_load validates it and merges names, comments, function names, xrefs, types and applied types (merged_* counts).";
    } else if (tool == "fs") {
        return "Host filesystem, not target memory. read_file caps text at 4KB / hex at 8KB (use max_bytes). Paths should be absolute.";
    } else if (tool == "web") {
        return "Outbound GET/POST from the host. Loopback/link-local/private destinations are refused unless the web_allow_private setting is on or the host is in web_allowlist (re-checked on every redirect). Page bodies with offset/max_bytes (next_offset); binary bodies come back as base64.";
    } else if (tool == "proxy") {
        return "HTTP inspection proxy. entries[] capped by limit; entry(id) shows request/response heads; replay(id) works for http and intercepted https entries and reports complete/truncated. CONNECT tunnels are blind (SNI only) unless mitm_enable {consent:true} was called.";
    } else if (tool == "script") {
        return "Lua 5.4 over the shared session (loads/renames visible everywhere), sandboxed unless the script_unsafe setting is on. print() is captured; return values serialize as 'return: <value>'. timeout_ms clamped to 10..60000 (default 5000).";
    }
    return nullptr;
}

bool needs_enrich_symbols(const json& value, int depth = 0) {
    if (depth > 14) return false;
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (is_addr_key(it.key()) && it->is_number_integer()) return true;
            if (needs_enrich_symbols(*it, depth + 1)) return true;
        }
    } else if (value.is_array() && value.size() <= 20000) {
        for (const auto& item : value)
            if (needs_enrich_symbols(item, depth + 1)) return true;
    }
    return false;
}

void enrich_payload(const std::string& tool, const json& args, json& payload) {
    try {
        if (!payload.is_object() || payload.contains("error")) return;
        const std::string action =
            (args.contains("action") && args.at("action").is_string())
                ? args.at("action").get<std::string>()
                : std::string{};
        // Log/status/control responses usually have no addresses. Avoid copying
        // the entire loaded symbol database for those high-frequency requests.
        const bool query_context = (tool == "xray" || tool == "decomp" || tool == "devirt") &&
                                   args.contains("addr");
        enrich_ctx_t ctx = (query_context || needs_enrich_symbols(payload))
                            ? snapshot_enrich_ctx() : enrich_ctx_t{};
        enrich_json_value(payload, ctx, 0);
        // per-function context: echo queried addr + owning function + names
        try {
            if ((tool == "xray" || tool == "decomp" || tool == "devirt") &&
                args.contains("addr")) {
                uint64_t q = 0;
                const json& av = args.at("addr");
                if (av.is_number_unsigned()) q = av.get<uint64_t>();
                else if (av.is_number_integer() && av.get<int64_t>() >= 0)
                    q = static_cast<uint64_t>(av.get<int64_t>());
                else if (av.is_string())
                    q = std::stoull(av.get<std::string>(), nullptr, 0);
                if (q != 0) {
                    if (!payload.contains("queried_addr")) payload["queried_addr"] = q;
                    if (!payload.contains("queried_addr_hex"))
                        payload["queried_addr_hex"] = addr_hex_str(q);
                    const std::string qn = resolve_enrich_name(q, ctx);
                    if (!qn.empty() && !payload.contains("queried_name"))
                        payload["queried_name"] = qn;
                    const std::string qm = modoff_str(q, ctx);
                    if (!qm.empty() && !payload.contains("queried_modoff"))
                        payload["queried_modoff"] = qm;
                    // owning function start (legacy index + hype db)
                    try {
                        std::lock_guard lk(ds::state_mutex());
                        auto& bin = ds::get();
                        if (bin.ready) {
                            if (auto c = bin.fns.containing(q)) {
                                if (!payload.contains("func_start"))
                                    payload["func_start"] = *c;
                                if (!payload.contains("func_start_hex"))
                                    payload["func_start_hex"] = addr_hex_str(*c);
                                const std::string fn = resolve_enrich_name(*c, ctx);
                                if (!fn.empty() && !payload.contains("func_name"))
                                    payload["func_name"] = fn;
                                for (const auto& f : bin.fns.functions()) {
                                    if (f.va == *c) {
                                        if (!payload.contains("func_size"))
                                            payload["func_size"] = f.size;
                                        if (!payload.contains("func_size_help"))
                                            payload["func_size_help"] = "bytes of decoded extent";
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (...) {}
                }
            }
        } catch (...) {}
        // pagination surfacing: returned vs limit/total
        try {
            const char* kArrs[] = {"functions", "strings", "symbols",     "instructions",
                                   "refs_to",   "blocks",  "gadgets",     "packets",
                                   "hits",      "hooks",   "syscalls",    "matches",
                                   "entries",   "streams", "connections", "classes"};
            for (const char* k : kArrs) {
                if (payload.contains(k) && payload.at(k).is_array() &&
                    !payload.contains("returned")) {
                    payload["returned"] = payload.at(k).size();
                    break;
                }
            }
            if (args.contains("limit") &&
                (args.at("limit").is_number_unsigned() ||
                 args.at("limit").is_number_integer())) {
                const int64_t lim = args.at("limit").is_number_unsigned()
                    ? static_cast<int64_t>(args.at("limit").get<uint64_t>())
                    : args.at("limit").get<int64_t>();
                if (payload.contains("returned") && !payload.contains("truncated") &&
                    lim > 0 &&
                    payload.at("returned").get<int64_t>() >= lim)
                    payload["truncated_likely"] =
                        "returned rows hit the limit; raise limit for complete results";
            }
            if (payload.contains("total") && payload.contains("returned") &&
                !payload.contains("truncated") &&
                payload.at("total").is_number() && payload.at("returned").is_number()) {
                const int64_t tot = payload.at("total").get<int64_t>();
                const int64_t ret = payload.at("returned").get<int64_t>();
                if (ret < tot) {
                    payload["truncated"] = true;
                    // exact truncation is known: drop the heuristic flag
                    if (payload.contains("truncated_likely"))
                        payload.erase("truncated_likely");
                }
            }
        } catch (...) {}
        if (const char* h = hint_for_tool_action(tool, action)) {
            if (!payload.contains("ai_hint")) payload["ai_hint"] = h;
        }
        // units legend for the most unit-confused actions
        try {
            if ((tool == "target" && (action == "modules" || action == "regions")) ||
                (tool == "memory" &&
                 (action == "read" || action == "scan" || action == "pointerscan")) ||
                (tool == "disasm" && (action == "functions" || action == "pe")) ||
                (tool == "network" && (action == "stats" || action == "packets"))) {
                if (!payload.contains("units")) {
                    if (tool == "target" && action == "modules")
                        payload["units"] = {{"base", "VA decimal, see base_hex"},
                                            {"size", "bytes"}};
                    else if (tool == "target" && action == "regions")
                        payload["units"] = {{"base", "VA decimal, see base_hex"},
                                            {"size", "bytes"}};
                    else if (tool == "memory" && action == "read")
                        payload["units"] = {{"addr", "VA decimal, see addr_hex"},
                                            {"len", "bytes actually returned"}};
                    else if (tool == "disasm" && action == "functions")
                        payload["units"] = {{"va", "function-start VA decimal, see va_hex"},
                                            {"size", "bytes of decoded extent"}};
                }
            }
        } catch (...) {}
    } catch (...) {}
}

void enrich_error(const std::string& tool, const json& args, json& payload) {
    try {
        if (!payload.is_object() || !payload.contains("error")) return;
        if (payload.contains("remediation")) return;
        const std::string err = payload.at("error").is_string()
            ? payload.at("error").get<std::string>()
            : std::string{};
        std::string fix;
        if (err.find("no target attached") != std::string::npos)
            fix = "Call target.list to find a pid, then target.attach {pid}; confirm with target.status.";
        else if (err.find("no image") != std::string::npos ||
                 err.find("no binary") != std::string::npos ||
                 err.find("not loaded") != std::string::npos)
            fix = "Call disasm.loaded to inspect state, then disasm.load {path} (or pass an explicit path arg).";
        else if (err.find("analysis in progress") != std::string::npos ||
                 err.find("not-ready") != std::string::npos ||
                 err.find("hype.ready") != std::string::npos)
            fix = "Poll disasm.loaded until image.hype.ready=true, then retry.";
        else if (err.find("ps4") != std::string::npos)
            fix = "Connect a console first: target.ps4_connect {host} (or the one-call target.ps4_auto {host}); see guide get ps4_setup.";
        else if (err.find("debugger") != std::string::npos ||
                 err.find("paused") != std::string::npos ||
                 err.find("wait_halt") != std::string::npos)
            fix = "Live debugging is remote on the PS4: debugger ps4_attach {pid}, ps4_bp_set, ps4_continue, ps4_wait, ps4_regs, ps4_events.";
        else if (err.find("unknown action") != std::string::npos)
            fix = "The error already enumerates valid actions; retry with one of those (see tools/list schema).";
        else if (err.find("address not mapped") != std::string::npos ||
                 err.find("base may differ") != std::string::npos)
            fix = "The VA is outside the loaded image; confirm base via disasm.loaded and use target.modules for runtime (ASLR) bases.";
        if (!fix.empty()) payload["remediation"] = fix;
        (void)tool;
        (void)args;
    } catch (...) {}
}

// address-valued inputs accept integers or hex strings (parse_addr)
bool is_addr_param(const std::string& k) {
    if (is_addr_key(k)) return true;
    static const char* kExtra[] = {"file_addr", "target_addr", "watch_addr", "stack_base",
                                   "until", "sp", "heap_base", "to"};
    for (const char* c : kExtra)
        if (k == c) return true;
    return k.size() > 5 && (k.ends_with("_addr") || k.ends_with("_va"));
}

const char* param_description(const std::string& k) {
    static const std::pair<const char*, const char*> kDesc[] = {
        {"action", "operation to run; the tool description lists the parameters each action uses"},
        {"len", "byte count"},
        {"size", "byte count"},
        {"length", "byte count"},
        {"count", "number of items / instructions"},
        {"limit", "maximum number of results returned"},
        {"offset", "skip this many leading items / bytes (paging)"},
        {"max_bytes", "maximum number of bytes to read or return"},
        {"timeout_ms", "time budget in milliseconds"},
        {"pid", "process id"},
        {"lwpid", "thread (lwp) id on the console"},
        {"port", "tcp port"},
        {"host", "hostname or ip address"},
        {"id", "id returned by an earlier call of this tool"},
        {"path", "absolute host filesystem path"},
        {"paths", "absolute host filesystem paths"},
        {"hex", "bytes as hex text, e.g. \"90 90 C3\""},
        {"text", "free text"},
        {"name", "symbol / object name"},
        {"filter", "case-insensitive substring filter"},
        {"url", "absolute http(s) url"},
        {"body", "request body"},
        {"content_type", "Content-Type header for the request body"},
        {"code", "source code to run"},
        {"format", "output format"},
        {"kind", "comparison / match kind"},
        {"width", "value width"},
        {"value", "value to use"},
        {"key", "key name"},
        {"root", "directory to start from"},
        {"needle", "text to search for"},
        {"suffix", "only files whose name ends with this suffix"},
        {"append", "append instead of overwrite"},
        {"load", "load the result as the shared image when done"},
        {"dry_run", "report what would change without changing anything"},
    };
    for (const auto& [n, d] : kDesc)
        if (k == n) return d;
    return nullptr;
}


// MCP metadata every tool entry carries: annotations (readOnlyHint & co),
// a closed input schema with described properties, and an output schema for
// the structuredContent the server returns alongside the text block
void finalize_tool_entry(json& t) {
    const std::string name = t.value("name", std::string{});
    const bool ro = t.value("read_only", false);
    static const char* kOpenWorld[] = {"web", "network", "proxy", "target", "memory", "debugger"};
    bool open_world = false;
    for (const char* n : kOpenWorld) open_world = open_world || name == n;
    std::string title = name;
    if (!title.empty()) title[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(title[0])));
    t["title"] = title;
    t["annotations"] = {{"title", title},
                        {"readOnlyHint", ro},
                        {"destructiveHint", !ro},
                        {"idempotentHint", false},
                        {"openWorldHint", open_world}};

    json& schema = t["inputSchema"];
    schema["additionalProperties"] = false;
    if (schema.contains("properties") && schema.at("properties").is_object()) {
        for (auto& [k, p] : schema["properties"].items()) {
            if (!p.is_object()) continue;
            const bool addr = is_addr_param(k) && p.value("type", std::string{}) == "integer";
            if (addr) p["type"] = json::array({"integer", "string"});
            if (p.contains("description")) continue;
            if (addr)
                p["description"] = "address: integer or hex string such as \"0x140001000\"";
            else if (const char* d = param_description(k))
                p["description"] = d;
            else
                p["description"] = "see the '" + name + "' tool description";
        }
    }
    t["outputSchema"] = {
        {"type", "object"},
        {"description", "tool payload (also serialized as JSON text in content[0]); on "
                        "failure an object with 'error' and optional 'remediation'"},
        {"additionalProperties", true}};

}

} // namespace



void list_tools(json& out) {
    const char* target_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["list","attach","detach","status","modules","dump_module","threads","regions","handles","heaps","heap_blocks","icon","ps4_connect","ps4_disconnect","ps4_reconnect","ps4_auto","ps4_discover","ps4_dump_module"]},"pid":{"type":"integer"},"host":{"type":"string","description":"PS4 IP, or \"auto\"/\"discover\": UDP broadcast probe (255.255.255.255:1010, magic 0xFFFFAAAA) picks the first answering console"},"port":{"type":"integer"},"timeout_ms":{"type":"integer","description":"ps4_discover: probe listen time in ms (default 2000, max 60000)"},"confirm":{"type":"boolean","description":"required on mutating actions while the mcp_require_confirm setting is on"},"base":{"type":"integer"},"name":{"type":"string"},"path":{"type":"string"},"paths":{"type":"array","items":{"type":"string"}},"heap_base":{"type":"integer"},"max_blocks":{"type":"integer","minimum":1,"maximum":1048576},"load":{"type":"boolean"},"strict":{"type":"boolean"},"format":{"type":"string","enum":["raw","elf"],"description":"ps4_dump_module output: raw mapped span (default) or a rebuilt loadable ELF64 (default when load=true)"}},"required":["action"]})json";
    const char* memory_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["read","write","scan","rescan","scan_state","scan_reset","scan_save","scan_load","aob","pointerscan","pointerscan_verify","snapshot","snapshots","diff","snapshot_free","protect","alloc","free","siggen","live_crypto","watch_list","watch_add","watch_remove","watch_clear","watch_set","watch_undo","watch_freeze_once"]},"addr":{"type":"integer"},"len":{"type":"integer"},"format":{"type":"string","enum":["hex","utf8","u8","u32","u64","f32","f64"]},"hex":{"type":"string"},"kind":{"type":"string","enum":["exact","between","bigger","smaller","unknown","increased","increased_by","increased_percent","decreased","decreased_by","decreased_percent","changed","unchanged"]},"width":{"type":"string","enum":["i8","u8","i16","u16","i32","u32","i64","u64","f32","f64","all"],"description":"value type; byte counts 1/2/4/8 are also accepted as u8/u16/u32/u64"},"rounding":{"type":"string","enum":["exact","rounded","truncated","extreme"]},"value":{},"value2":{},"begin":{"type":"integer"},"end":{"type":"integer"},"pattern":{"type":"string"},"tail":{"type":"string"},"writable":{"oneOf":[{"type":"string","enum":["any","include","exclude"]},{"type":"boolean"}]},"executable":{"type":"string","enum":["any","include","exclude"]},"copy_on_write":{"type":"string","enum":["any","include","exclude"]},"mem_private":{"type":"boolean"},"mem_image":{"type":"boolean"},"mem_mapped":{"type":"boolean"},"read_only":{"type":"boolean"},"no_exec":{"type":"boolean"},"threads":{"type":"integer","minimum":0,"maximum":64},"chunk_bytes":{"type":"integer","minimum":1},"max_results":{"type":"integer","minimum":1},"prot":{"type":"integer"},"target":{"type":"integer"},"depth":{"type":"integer"},"min_offset":{"type":"integer"},"max_offset":{"type":"integer"},"alignment":{"type":"integer"},"static_roots":{"type":"boolean"},"frontier_cap":{"type":"integer","minimum":1},"max_bytes":{"type":"integer"},"a":{"type":"integer"},"b":{"type":"integer"},"id":{"type":"integer"},"all":{"type":"boolean"},"limit":{"type":"integer"},"label":{"type":"string"},"freeze":{"type":"boolean"},"engine":{"type":"string","enum":["auto","console","host"],"description":"aob: console runs the search on the PS4 (all hits, needs ps4_auth), host streams memory over the wire; auto prefers console"},"chains":{"type":"array","description":"pointerscan_verify: chains to re-check ({addresses[],offsets[]} or {base,offsets[]}); default is the last pointerscan list","items":{"type":"object"}},"samples":{"type":"integer","minimum":1,"maximum":64,"description":"pointerscan_verify: passes; a chain survives only if it lands on target every time"},"interval_ms":{"type":"integer","minimum":0,"maximum":60000,"description":"pointerscan_verify: wait between samples"}},"required":["action"]})json";
    const char* disasm_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["assemble","disassemble","loaded","pe","functions","xrefs","strings","symbols","symbol_set","blocks","globals","vtables","load","unload","analyze_stop","managed"]},"addr":{"type":"integer"},"va":{"type":"integer"},"address":{"type":"integer"},"count":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer","description":"load: runtime base to rebase the image to, 0 keeps its own base"},"relocate":{"type":"boolean","description":"load: apply ELF/SELF relocations at the session base, default true; pass false for memory dumps"},"name":{"type":"string"},"text":{"type":"string"},"limit":{"type":"integer"},"offset":{"type":"integer","description":"functions: index of the first matched row to return"},"filter":{"type":"string","description":"functions: case-insensitive substring of the function name or hex VA"},"min_chars":{"type":"integer"},"include_exec":{"type":"boolean"},"method_token":{"type":"integer"},"type":{"type":"string"},"type_filter":{"type":"string"}},"required":["action"]})json";
    const char* debugger_schema =

        R"json({"type":"object","properties":{"base":{"type":"integer","description":"module base used to rebase addresses for this action, default 0"},"action":{"type":"string","enum":["status","ps4_attach","ps4_detach","ps4_status","ps4_console_info","ps4_bp_set","ps4_bp_clear","ps4_watch_set","ps4_watch_clear","ps4_continue","ps4_step","ps4_suspend","ps4_resume","ps4_process_stop","ps4_regs","ps4_set_reg","ps4_dbregs","ps4_wait","ps4_events","ps4_callstack","ps4_call","ps4_bp_list","ps4_watch_list","ps4_until","ps4_find_write","ps4_trace_calls","ps4_trace_steps","ps4_auth","ps4_scan","ps4_rescan","ps4_scan_all","ps4_scan_aob","ps4_scan_state","ps4_scan_reset","ps4_turbo_caps","ps4_turbo_scan","ps4_turbo_rescan","ps4_turbo_results","ps4_turbo_end","ps4_turbo_config","ps4_turbo_regions","ps4_turbo_cancel","ps4_write_multi","ps4_modules","ps4_snapshot","ps4_disasm","ps4_xrefs","ps4_xrefs_to","ps4_stack","ps4_assemble","ps4_elf_rpc","ps4_elf_load","ps4_notify","ps4_print","ps4_app","ps4_fpregs","ps4_set_fpregs","ps4_set_dbregs","ps4_fsgs","ps4_set_fsgs"]},"pid":{"type":"integer"},"addr":{"type":"integer"},"type":{"type":"integer"},"len":{"type":"integer"},"timeout_ms":{"type":"integer"},"max_frames":{"type":"integer"},"name":{"type":"string"},"value":{},"count":{"type":"integer"},"lwpid":{"type":"integer"},"index":{"type":"integer"},"stop":{"type":"integer"},"state":{"type":"integer"},"max":{"type":"integer"},"clear":{"type":"boolean"},"depth":{"type":"integer"},"args":{"type":"array","items":{}},"value_type":{"type":"string"},"width":{"type":"string"},"compare":{"type":"string"},"kind":{"type":"string"},"hex":{"type":"string"},"pattern":{"type":"string"},"alignment":{"type":"integer"},"max_matches":{"type":"integer","description":"ps4_scan_aob legacy form: return only the max_matches-th match; omit to get every match"},"limit":{"type":"integer","description":"ps4_scan_aob: most matches to return (default 4096)"},"unique":{"type":["boolean","integer"]},"asm":{"type":"string"},"syntax":{"type":"integer","description":"Keystone syntax: 0 default/Intel, 1 Intel, 2 ATT, 3 NASM, 4 MASM, 5 GAS"},"msg":{"type":"string"},"path":{"type":"string"},"target":{"type":"integer"},"rbp":{"type":"integer"},"rsp":{"type":"integer"},"fs_base":{"type":"integer"},"gs_base":{"type":"integer"},"regions":{"type":"string"},"resident":{"type":"boolean"},"snapshot":{"type":"boolean"},"aliasing":{"type":"boolean"},"parallel":{"type":"boolean"},"keep_first":{"type":"boolean"},"keep_previous":{"type":"boolean"},"include_zeros":{"type":"boolean"},"float":{"type":"string"},"float_exponent":{"type":"integer"},"mask_hex":{"type":"string"},"start":{"type":"integer"},"ram_mb":{"type":"integer"},"spill_path":{"type":"string"},"probe_bytes":{"type":"integer"},"writes":{"type":"array","items":{"type":"object"}},"status":{"type":"boolean"},"confirm":{"type":"boolean","description":"required on mutating ps4_* actions while the mcp_require_confirm setting is on"},"condition":{"type":"string","description":"ps4_bp_set: client-side condition, register op value (== != > < >= <= &), e.g. \"rax==0x10\"; ps4_wait resumes while it is false and reports condition_skipped"}},"required":["action"]})json";

    const char* xray_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["cfg","complexity","cff","obfuscation","strings_recon","indirect_calls","anti_analysis","hooks","syscalls","apihash","entropy","pages","crypto_range","gadgets"]},"addr":{"type":"integer"},"va":{"type":"integer"},"address":{"type":"integer"},"size":{"type":"integer"},"len":{"type":"integer"},"length":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer"},"window_size":{"type":"integer"},"window":{"type":"integer"},"window_limit":{"type":"integer"},"page_size":{"type":"integer"},"max_functions":{"type":"integer"},"hash":{},"hashes":{"type":"array"},"algorithm":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})json";
    const char* patch_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["nop_junk","resolve_opaque","patch_antidebug","unpack_xor","decode_strings","write_bytes","revert_all","journal","full_pass","rebuild"]},"addr":{"type":"integer"},"size":{"type":"integer"},"hex":{"type":"string"},"aggressive":{"type":"boolean"},"nop_threshold":{"type":"integer"},"dry_run":{"type":"boolean"},"method":{"type":"string"},"key_hex":{"type":"string"},"patch_api_calls":{"type":"boolean"},"patch_int_traps":{"type":"boolean"},"patch_timing":{"type":"boolean"},"limit":{"type":"integer"}},"required":["action"]})json";
    const char* devirt_schema =
        R"json({"type":"object","properties":{"len":{"type":"integer","description":"alias of size"},"length":{"type":"integer","description":"alias of size"},"action":{"type":"string","enum":["themida_status","themida_start","themida_job","themida_cancel","identify","handlers","opcode_map","trace","lift","pseudocode","recover_cfg","prove_predicates","invariants","iat_audit"]},"addr":{"type":"integer"},"va":{"type":"integer"},"entry":{"type":"integer"},"start":{"type":"integer"},"address":{"type":"integer"},"path":{"type":"string"},"output_path":{"type":"string"},"timeout_ms":{"type":"integer","minimum":1000,"maximum":1800000},"overwrite":{"type":"boolean"},"load":{"type":"boolean"},"id":{"type":"integer","minimum":1},"runs":{"type":"integer"},"size":{"type":"integer"},"table":{"type":"integer"},"entry_size":{"type":"integer"},"stride":{"type":"integer"},"max_handlers":{"type":"integer"},"dispatcher":{"type":"integer"},"handler_table":{"type":"integer"},"handlers":{"type":"array"},"max_ops":{"type":"integer"}},"required":["action"]})json";
    const char* types_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["declare","create_struct","get_struct","list_structs","add_member","remove_struct","create_enum","get_enum","list_enums","remove_enum","read_field","format_at"]},"name":{"type":"string"},"decl":{"type":"string"},"filter":{"type":"string"},"field":{"type":"string"},"type":{"type":"string"},"underlying":{"type":"string"},"values":{"type":"array"},"array_count":{"type":"integer"},"addr":{"type":"integer"},"live":{"type":"boolean"},"struct":{"type":"string"},"size":{"type":"integer"}},"required":["action"]})json";
    const char* notes_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["set_comment","get_comment","comments","bookmark_toggle","bookmarks"]},"addr":{"type":"integer"},"text":{"type":"string"}},"required":["action"]})json";
    const char* emulate_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"hex":{"type":"string"},"arch":{"type":"string","enum":["x64","x86_64","amd64"]},"file_addr":{"type":"integer"},"target_addr":{"type":"integer"},"code_len":{"type":"integer","minimum":1,"maximum":1048576},"base":{"type":"integer"},"entry":{"type":"integer"},"abi":{"type":"string","enum":["auto","win64","sysv"]},"stack_base":{"type":"integer"},"stack_size":{"type":"integer","minimum":4096,"maximum":67108864},"sp":{"type":"integer"},"regs":{"type":"object"},"maps":{"type":"array"},"until":{"type":"integer"},"count":{"type":"integer"},"timeout_ms":{"type":"integer","minimum":1,"maximum":30000},"trace":{"type":"boolean"},"trace_max":{"type":"integer","minimum":0,"maximum":16384},"taint":{"type":"array"},"watch_addr":{"type":"integer"},"watch_len":{"type":"integer","minimum":0,"maximum":1048576},"page_in":{"type":"boolean"},"stub_imports":{"type":"boolean"},"api_ret":{"type":["integer","string"]},"api_returns":{"type":"object","additionalProperties":{"type":["integer","string"]}},"syscall_ret":{"type":["integer","string"]},"syscall_returns":{"type":"object","additionalProperties":{"type":["integer","string"]}},"dump":{"type":"array","items":{"type":"object","properties":{"addr":{"type":"integer"},"len":{"type":"integer","minimum":1,"maximum":1048576}},"required":["addr","len"]}}},"required":["action"]})json";
    const char* analyze_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["packer","signatures","diff","diff_start","diff_job","diff_cancel"]},"path":{"type":"string"},"path_a":{"type":"string"},"path_b":{"type":"string"},"limit":{"type":"integer"},"timeout_ms":{"type":"integer"},"max_pairs":{"type":"integer"},"id":{"type":"integer"}},"required":["action"]})json";
    const char* network_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["status","capture_start","capture_stop","packets","dns","stats","export_pcap","streams","stream_data","reassemble_stream","connections","deep_inspect","clear"]},"host":{"type":"string","description":"IP address. capture_start: capture only packets to/from it (e.g. the PS4); dns/connections/deep_inspect/reassemble_stream: filter by it"},"console_ip":{"type":"string","description":"alias of host"},"port":{"type":"integer","minimum":0,"maximum":65535},"protocol":{"type":["integer","string"],"description":"6|17|tcp|udp (0/any = both)"},"from":{"type":"integer","description":"packets: return ids greater than this"},"tail":{"type":"boolean","description":"packets: the newest limit packets instead of paging from 'from'"},"filter":{"type":"string","description":"packets display filter, ';'-joined: port=80, host:1.2.3.4 or host:10.0.0.0/8, text:foo, proto:tcp|udp|N, dir:in|out. Unknown predicates are errors"},"limit":{"type":"integer"},"path":{"type":"string"},"max_packets":{"type":"integer","description":"export_pcap: newest N stored packets (max 65536)"},"id":{"type":"integer"},"offset":{"type":"integer"},"len":{"type":"integer"},"src_port":{"type":"integer"},"dst_port":{"type":"integer"}},"required":["action"]})json";
    const char* proxy_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status","entries","entry","replay","clear","mitm_status","mitm_enable","mitm_disable","mitm_uninstall"]},"port":{"type":"integer","minimum":0,"maximum":65535},"bind":{"type":"string","description":"listen IP (default 127.0.0.1). A LAN bind such as 0.0.0.0 (for a console) requires the proxy_token setting or allow_clients"},"allow_hosts":{"type":"array","items":{"type":"string"},"description":"destination allowlist: host, *.suffix, IP or CIDR (empty = any)"},"allow_clients":{"type":"array","items":{"type":"string"},"description":"client IP/CIDR allowlist (e.g. the console IP)"},"max_connections":{"type":"integer","minimum":1,"maximum":1024},"limit":{"type":"integer"},"kind":{"type":"string","enum":["http","https","connect"]},"id":{"type":"integer"},"timeout_ms":{"type":"integer","minimum":1000,"maximum":60000},"consent":{"type":"boolean","description":"mitm_enable: must be true, confirming the user agreed to TLS interception"},"install_root":{"type":"boolean","description":"mitm_enable: trust the CA in CurrentUser\\ROOT (default true; Windows shows a confirmation dialog)"}},"required":["action"]})json";
    const char* persist_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["save","list","load","delete","kv_set","kv_get","hype_save","hype_load"]},"name":{"type":"string"},"data":{},"id":{"type":"integer"},"key":{"type":"string"},"value":{},"dir":{"type":"string"}},"required":["action"]})json";
    const char* re_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["rtti_scan","vftable","danger","libsig"]},"path":{"type":"string"},"base":{"type":"integer"},"addr":{"type":"integer"},"slots":{"type":"integer"},"sigset":{"type":"string"},"filter":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})json";
    const char* script_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"code":{"type":"string"},"timeout_ms":{"type":"integer","minimum":10,"maximum":60000}},"required":["action"]})json";
    const char* decomp_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["function"]},"addr":{"type":"integer"},"annotate_bytes":{"type":"boolean"}},"required":["action"]})json";
    const char* fs_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["read_file","write_file","list_directory","create_directory","delete_path","search_files","grep_in_files"]},"path":{"type":"string"},"hex":{"type":"string"},"text":{"type":"string"},"append":{"type":"boolean"},"root":{"type":"string"},"needle":{"type":"string"},"suffix":{"type":"string"},"limit":{"type":"integer"},"offset":{"type":"integer","minimum":0,"description":"read_file: byte offset to start at; page with next_offset"},"max_bytes":{"type":"integer","minimum":0,"maximum":1048576,"description":"read_file: bytes to return, default 65536, max 1048576"},"encoding":{"type":"string","enum":["auto","text","hex"],"description":"read_file: auto = text when the bytes are valid UTF-8 without NULs, else hex"}},"required":["action"]})json";
    const char* web_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["fetch","post"]},"url":{"type":"string"},"body":{"description":"post: request body (a string is sent verbatim, other JSON values are serialized)"},"content_type":{"type":"string","description":"post: Content-Type (default application/json)"},"timeout_ms":{"type":"integer","minimum":1000,"maximum":60000},"offset":{"type":"integer","minimum":0,"description":"response body byte offset; page with next_offset"},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576,"description":"body bytes returned per call (default 65536)"},"encoding":{"type":"string","enum":["auto","text","base64"],"description":"auto = text when the body is valid UTF-8, else base64"}},"required":["action"]})json";

    out.push_back({{"name", "target"},
                   {"description", "PS4 toolkit target control. Connect a console with ps4_connect {host, port=744, pid?} (ps4debug-NG running on the PS4; host \"auto\" discovers the console via UDP broadcast) or the one-call ps4_auto {host}, which connects, picks the game process (the one with /app0/ modules), attaches and debug-attaches; ps4_discover {timeout_ms} lists every console answering the broadcast probe (255.255.255.255:1010, magic 0xFFFFAAAA). Every call is appended to the JSONL audit log (mcp_audit_path setting); while mcp_require_confirm is on, mutating actions need confirm:true. Then list/attach/memory/regions/threads go over the wire. A failed send/receive drops the console socket (status ps4.connected=false, ps4.lost=true) so calls fail fast; ps4_reconnect re-opens it, re-authenticates, re-attaches the debugger and re-arms breakpoints while the session stays attached. ps4_disconnect drops the console; status reads the active backend (ps4.fw, ps4.drops). modules lists one record per console module (segments coalesced). ps4_dump_module {name|base, path, format=raw|elf, load?} dumps every segment of a module; format=elf rebuilds a loadable ELF64 from the console maps (the in-memory image has no ELF header) and load=true opens it for disasm.*. A hidden local user-mode backend remains for automated tests (list/attach/modules/threads/regions/handles/dump_module/icon); dump_module is PE-only."},
                   {"inputSchema", json::parse(target_schema)}, {"read_only", false}});
    out.push_back({{"name", "memory"},
                   {"description", "Read, search, compare, and modify memory in the process attached by target. Most actions require target.status attached=true; the active backend is chosen automatically (ps4 when a console is connected). Core actions: read/write bytes, protect/alloc/free pages, AOB pattern search, pointer scan, signature generation, and live crypto-constant search. CE-style scan creates per-PID scan state; follow it with rescan, inspect it with scan_state, and release it with scan_reset. snapshot returns an id; compare two ids with diff using a and b, list with snapshots, and release with snapshot_free. Scan filters cover numeric width/comparison/rounding, region type and protection, address bounds, alignment/tail, workers, chunks, and result caps. On a PS4 every action runs over the ps4debug-NG wire against the attached console process."},
                   {"inputSchema", json::parse(memory_schema)}, {"read_only", false}});
    out.push_back({{"name", "disasm"},
                   {"description", "Primary static-analysis and instruction tool for the shared binary session. Call action='loaded' first: image.ready means a PE, Mach-O (thin/FAT), .ipa executable, ELF (PS4 eboot/prx dump, FreeBSD/Linux) or PS4 SELF is loaded; image.format (pe|macho|elf|self)/arch describe its code, and encrypted/warning identify FairPlay-encrypted code that must be decrypted before analysis. image.hype.ready means background Hyperion analysis is complete; image.hype.progress/error explain pending or failed analysis. Use load(path, base?, relocate?) for PE, Mach-O (thin/FAT), .ipa, ELF or SELF (fake-signed/unencrypted only; an encrypted retail eboot.bin fails with a pointer to target.ps4_dump_module, which dumps the decrypted module from the console) and unload to manage the same session as the UI, and analyze_stop to cancel analysis. PS4 imports are resolved from NIDs and grouped by library; ELF/SELF relocations are applied on load (relocate=false for memory dumps). pe/strings support the shared image or an explicit path; functions/xrefs with path support x86/x64 only, so load ARM images first. functions pages server-side (filter/offset/limit -> total/matched/returned). symbols use the shared image; blocks/globals/vtables require hype.ready. disassemble reads attached-process memory first and otherwise decodes the loaded file's architecture. assemble converts x86/x64 text to bytes. symbol_set renames a VA persistently (empty name clears) and updates the UI. Strings paginate with limit and omit executable sections unless include_exec=true. Runtime-base loads make static and live VAs directly comparable."},
                   {"inputSchema", json::parse(disasm_schema)}, {"read_only", false}});
    out.push_back({{"name", "debugger"},
                   {"description", "PS4 live debugging over ps4debug-NG (connect first: target.ps4_connect / ps4_auto). status shows the console debug state; ps4_status adds fw, connected/lost, events_received/events_dropped (the event queue keeps 4096 stops); ps4_console_info pings the payload (CMD_CONSOLE_INFO) and returns branding, caps, server version, fw and the foreground app. ps4_attach {pid} attaches the payload debugger; ps4_bp_set/ps4_bp_clear arm software INT3 breakpoints (index auto-allocated 0-29); ps4_watch_set/ps4_watch_clear arm hardware DR watchpoints (type 0=exec 1=write 3=rdwr, len 1/2/4/8); slots are recorded per debug session and cleared when it ends (ps4_bp_list/ps4_watch_list). ps4_continue {stop} resumes (0=resume 1=SIGSTOP 2=SIGKILL); ps4_step {lwpid?} single-steps; ps4_suspend/ps4_resume freeze one thread; ps4_process_stop {state} signals the process; ps4_regs/ps4_set_reg/ps4_dbregs read or write register state; ps4_wait {timeout_ms} blocks for the next stop event (breakpoint, watchpoint, step, signal; signal 9 tears the session down) and ps4_events drains the queue; ps4_callstack {lwpid, depth} walks the frame chain through live memory reads; ps4_call {addr, args[6]} installs the rpc stub once per pid and calls an arbitrary address in the console process, returning rax. Power actions: ps4_until {addr} (temp bp + continue + wait for the stop at addr), ps4_find_write {addr, len} (write watchpoint, returns stop event plus writer callstack), ps4_trace_calls {addr, count} (logs arg registers at every bp hit), ps4_trace_steps {lwpid, count} (single-step + disasm each rip); these four also run on an attached local test-lab process through a Win32 debugger. Errors name the cause (connection dropped, deadline, payload status, unmapped range). Whole workflows (find health, damage source, API trace, unpacking): guide list / guide get {topic}."},
                   {"inputSchema", json::parse(debugger_schema)}, {"read_only", false}});
    out.push_back({{"name", "xray"},
                   {"description", "Run focused read-only static-analysis queries on the shared image or an explicit PE, ELF/SELF, Mach-O, or .ipa path. entropy and apihash are architecture-neutral; all other actions require x86/x64. anti_analysis requires PE; syscalls works on PE (Windows NT stubs) and ELF/SELF (PS4 Orbis numbering, each hit named from the PS4 syscall table) but not Mach-O. For cfg, complexity, cff, obfuscation, strings_recon, indirect_calls, and anti_analysis, pass addr as a function-start VA; known functions use indexed bounds and unknown addresses fall back to linear decode. Whole-image actions detect hooks, direct syscalls (mov eax/rax,n with the mov r10,rcx shuffle on either side, int 2e on Windows), imported-API hashes, entropy windows, page classes, crypto constants (including instruction immediates), and ROP gadgets. For raw crypto constants on ARM use analyze.signatures. apihash only searches imports of this image, including bare API and 'DLL!API' forms; it is not a global hash dictionary. Use disasm.loaded/functions first to establish image state and valid function VAs."},
                   {"inputSchema", json::parse(xray_schema)}, {"read_only", true}});
    out.push_back({{"name", "patch"},
                    {"description", "Mutate the currently loaded file-image analysis session; this does not patch live target memory. Use journal to inspect recorded edits and revert_all to undo them. write_bytes performs an explicit VA/hex edit on any architecture, as does unpack_xor with an explicit xor_single/xor_multi/xor_rolling key. Automatic XOR-key detection and code-rewriting/rebuild actions require x86/x64; patch_antidebug and full_pass also require PE. nop_junk, resolve_opaque, patch_antidebug, and decode_strings take a function-start addr (patch_antidebug without addr scans the entry-point function); dry_run previews opaque-predicate changes. full_pass orchestrates multiple passes and reports before/after scores. rebuild(addr) re-decodes a patched x86 function. Patched indexes and Hyperion refresh on the next disasm.functions/xrefs/strings query on any architecture. Requires disasm.loaded image.ready=true; use memory.write for live-process bytes."},
                   {"inputSchema", json::parse(patch_schema)}, {"read_only", false}});
    out.push_back({{"name", "devirt"},
                    {"description", "Deobfuscation, VM recovery, and Themida unpacking. Themida actions supervise the separate Magicmida debugger engine: call themida_status to discover x86/x64 sidecars, themida_start(path,output_path,timeout_ms,overwrite,load) to launch a cancellable job, then poll themida_job(id) or stop it with themida_cancel(id). Successful output is architecture-validated and can load into the shared analysis session. Static VM chain (each step needs the previous): identify(addr) reports likely_vm plus handler_table when found; handlers(table|addr) classifies the table; trace/lift/pseudocode(addr + handler_table|handlers) follow the bytecode -- trace/lift/pseudocode on a non-VM function fail with guidance, they never synthesize handlers. handlers also accepts addr= as a table alias. recover_cfg, prove_predicates, invariants, and iat_audit inspect the shared image without mutation."},
                    {"inputSchema", json::parse(devirt_schema)}, {"read_only", false}});
    out.push_back({{"name", "types"},
                   {"description", "Define and apply structs/enums for the current binary; the catalog persists by binary hash. declare parses C-like struct or enum declarations, while create/get/list/remove and add_member provide structured CRUD with computed natural or packed layouts. read_field reads one named field; format_at renders a complete struct or enum at addr. Reads use the mapped file image by default and attached-process memory when live=true. Accepted packed struct forms include 'struct Name { ... } packed;' and 'packed struct Name { ... };'. Load the intended binary before changing the catalog."},
                   {"inputSchema", json::parse(types_schema)}, {"read_only", false}});
    out.push_back({{"name", "notes"},
                   {"description", "Read and edit analyst annotations for the currently loaded binary. set_comment(addr,text), get_comment(addr), and comments manage per-VA comments; bookmark_toggle(addr) and bookmarks manage navigation marks. Data persists by binary hash alongside user symbols and is immediately shared with the UI. Requires a loaded image. set_comment with empty text clears the comment (response cleared=true)."},
                   {"inputSchema", json::parse(notes_schema)}, {"read_only", false}});
    out.push_back({{"name", "emulate"},
                   {"description", "Emulate x86-64 code in an isolated Unicorn VM. action='run' accepts exactly one practical code source: hex bytes, file_addr from the shared image, or target_addr from attached-process memory; code_len sets the initial slice. Every source is checked to be x86-64: file_addr needs an x64 image, target_addr an x64 target (PS4 consoles are x86-64), hex accepts arch='x64' (default) only. abi='auto' (default) picks the environment: sysv for ELF/SELF/Mach-O images, PS4 console targets and hex while a PS4 is connected or an ELF is loaded, win64 otherwise; the result reports abi. win64: a zeroed TEB/PEB sits at gs_base (self, PEB, stack bounds, ImageBaseAddress; BeingDebugged=0) unless regs sets gs_base, api args are rcx/rdx/r8/r9. sysv: a FreeBSD/PS4 TCB sits at fs_base (fs:[0] self, fs:[8] dtv, fs:[0x10] pthread, zeroed static TLS below fs) unless regs sets fs_base, api args are rdi/rsi/rdx/rcx/r8/r9. syscall instructions never enter a kernel: each is logged in syscalls (ip, num=rax, name from the PS4 syscall table on sysv runs, args rdi/rsi/rdx/r10/r8/r9, ret) and returns syscall_returns[num or name] or syscall_ret (default 0) in rax with CF clear. With file_addr/target_addr, page_in (default true) maps any other page the code touches from that same source on first use (image sections inside SizeOfImage with base relocations applied when the image is rebased, or live process/console memory; up to 16 MiB), so calls, jumps and global loads outside the slice keep running; hex runs map only the code and maps. With file_addr on a PE32+ image, stub_imports (default true) points every IAT slot at a stub that returns api_ret (default 0) in rax and logs api_calls (caller ip, return address, import name, abi argument registers); api_returns={\"InitializeCriticalSectionAndSpinCount\":1,\"kernel32.dll!CreateFileW\":-1} overrides it per import (case-insensitive, unmatched keys come back in api_returns_unmatched). Set base/entry, registers (rax..r15, rip, rflags, fs_base, gs_base), stack, and extra maps as needed. dump=[{addr,len}] (<= 1 MiB total) returns final memory as hex in memory; writes log ip/addr/len/value (low 8 bytes; truncated=true for wider vector stores). Stop with until, count (default 100000), or timeout_ms (default 5000, capped at 30000); MCP notifications/cancelled stops a run early with stopped_reason='cancelled'. Runs do not block other tools. trace enables bounded instruction history (trace_max <= 16384); taint entries mark source byte ranges (<= 1 MiB total), and watch_addr/watch_len selects the output window for byte-granular propagation results. Emulation does not modify the loaded image or live target."},
                   {"inputSchema", json::parse(emulate_schema)}, {"read_only", true}});
    out.push_back({{"name", "guide"},
                   {"description", "Task-oriented playbooks for game reverse engineering: action='list' enumerates topics, action='get' {topic} returns the exact ordered tool-call sequence (tool, action, params, why) for that workflow — PS4 setup/breakpoints/API tracing/find-writes/step traces/remote calls, Cheat-Engine style value finding, damage-source hunting, pointer chains, runtime string decryption, local API monitoring, snapshot diffs, emulation, control-flow recovery, unpacking, and hardware breakpoints. Call it whenever you are unsure which tools to combine for a task."},
                   {"inputSchema", json::parse(R"json({"type":"object","properties":{"action":{"type":"string","enum":["list","get"]},"topic":{"type":"string"}},"required":["action"]})json")}, {"read_only", true}});
    out.push_back({{"name", "analyze"},
                   {"description", "Run whole-binary read-only analysis. packer uses the shared image or path and reports protector names, entry signatures, entropy, import anomalies, W+X sections, TLS, overlay, crypto constants, and the shared Hyperion verdict when available. signatures requires the analyzed shared session and returns analyzer-derived names in named_functions; names may come from RTTI, vtables, thunks, or signature candidates and are not provenance-verified as FLIRT. diff(path_a,path_b) performs two full Hyperion analyses and reports added, removed, and modified functions with similarity scores, so expect a longer call; for huge binaries use async diff_start(path_a,path_b) then poll diff_job(id) for stage/progress and stop with diff_cancel(id). Check disasm.loaded before shared-session actions."},
                   {"inputSchema", json::parse(analyze_schema)}, {"read_only", true}});
    out.push_back({{"name", "network"},
                   {"description", "Host-side packet capture on the analysis PC: raw sockets with SIO_RCVALL on every up interface (IPv4 and IPv6, fragments reassembled; run as admin). Raw capture has no per-process attribution, so filter by host (the PS4's IP, e.g. when the console shares the PC's connection), port and protocol. Flow: capture_start {host} -> packets (from/limit/tail/filter: port=80;host:1.2.3.4 or CIDR;text:foo;proto:tcp;dir:in) | dns (queries + A/AAAA answers) | streams | stream_data (payload by id/offset/len) | stats -> capture_stop. export_pcap writes the newest stored packets as LINKTYPE_RAW pcap with true wire lengths. reassemble_stream concatenates stored TCP payloads for a host/port tuple, connections lists 4-tuples, deep_inspect classifies packets (HTTP, TLS version/SNI, DNS). Interactive HTTP(S) inspection lives in the proxy tool."},
                   {"inputSchema", json::parse(network_schema)}, {"read_only", false}});
    out.push_back({{"name", "proxy"},
                   {"description", "Built-in HTTP/1.1 inspection proxy. start {port, bind, allow_hosts, allow_clients} -> status -> entries(limit, kind) -> entry(id) -> replay(id). Plain HTTP is forwarded one request per connection and every request is logged and replayable (replay reports complete/truncated). CONNECT tunnels record SNI and are relayed blindly unless mitm_enable {consent:true} is called: it creates a local CA (and by default trusts it in CurrentUser\\ROOT behind the Windows confirmation dialog) and then decrypts each tunnel with a per-host certificate, logging every HTTPS request as kind=https. mitm_disable stops intercepting, mitm_uninstall removes the CA trust, keys and files. The proxy_token setting makes clients send Proxy-Authorization (Bearer token or Basic with the token as password). Independent of the network capture tool."},
                   {"inputSchema", json::parse(proxy_schema)}, {"read_only", false}});
    out.push_back({{"name", "persist"},
                   {"description", "Persist agent or analysis state in the app database. save(name,data) stores a JSON session snapshot (serialized data up to 16 MiB, name up to 256 bytes) and returns an id; list discovers snapshots, load(id) retrieves one, and delete(id) removes it. kv_set/kv_get store small named values such as layouts (value up to 1 MiB). hype_save(dir) writes the current Hyperion project as a versioned .hdb directory (names, comments, function names, xrefs, types, applied types); hype_load(dir) validates magic/version/record bounds and merges all of those into the live shared image (types matched by name). Persistence does not automatically restore a process attachment or debugger session."},
                   {"inputSchema", json::parse(persist_schema)}, {"read_only", false}});
    out.push_back({{"name", "re"},
                    {"description", "Run read-only reverse-engineering reconnaissance on the shared image or an explicit path. rtti_scan prefers completed Hyperion analysis and returns demangled classes, vtables, and methods: MSVC RTTI on x86/x64 PE, Itanium ABI RTTI (clang/gcc type_info + vtables, with direct bases) on ELF/SELF such as PS4 eboots; otherwise it falls back to a quick scanner (TypeDescriptor/COL for PE, type_info/vtable for ELF after applying relocations). rtti_scan accepts filter (case-insensitive substring over class names) and limit (default 500) with total/truncated. vftable(addr,slots) reads virtual-function entries and uses Hyperion metadata when addr is an indexed vtable. danger finds callsites to security-sensitive imports using Hyperion xrefs for the shared session or the legacy index for explicit paths. libsig(path,sigset) identifies libraries from a JSON byte-signature set. Check disasm.loaded and wait for hype.ready for richest results."},
                   {"inputSchema", json::parse(re_schema)}, {"read_only", true}});
    out.push_back({{"name", "decomp"},
                   {"description", "Decompile one function from the shared image (PE, Mach-O, ELF or PS4 SELF; x86/x64 and ARM64). Prerequisite: call disasm.loaded and wait for image.hype.ready=true, then obtain a function-start addr from disasm.functions. action='function' returns structured C, per-line VA mappings, reconstructed stack variables, the calling convention (win64, sysv_amd64 for PS4/ELF, aapcs64) and a recovered signature after p-code lifting, SSA, optimization, type inference, and control-flow structuring. Naming priority is user symbol, Hyperion name (PS4 imports resolved from NIDs), then sub_<VA>; RTTI and recognized STL types may appear in output. Set annotate_bytes=true to prefix emitted lines with source VAs. This tool does not accept an explicit path; load the binary first."},
                   {"inputSchema", json::parse(decomp_schema)}, {"read_only", true}});
    out.push_back({{"name", "fs"},
                   {"description", "Access the Windows host filesystem, not target-process memory. read_file(path,offset=0,max_bytes=65536 up to 1 MiB,encoding=auto|text|hex) returns exactly the requested window: {size,offset,bytes,eof,next_offset?,encoding,text|hex}; page through big files with next_offset. write_file(path,text|hex,append) creates or updates a file. list_directory and create_directory operate on path (entries flag reparse points), while delete_path removes a file or directory. search_files(root,needle,limit) finds names and grep_in_files(root,needle,suffix,limit) searches text content; both skip junctions/symlinks, stop at limit, and honor notifications/cancelled (cancelled=true in the result). fs runs outside the shared tool lock, so a long walk never blocks other tools. Paths are UTF-8; use absolute paths."},
                   {"inputSchema", json::parse(fs_schema)}, {"read_only", false}});
    out.push_back({{"name", "web"},
                   {"description", "Make outbound HTTP(S) requests from the host. fetch(url) performs GET; post(url, body, content_type) performs POST. Destinations resolving to loopback, link-local, private or reserved addresses are refused unless the web_allow_private setting is enabled or the host matches web_allowlist; each redirect hop is re-checked and the vetted address is the one connected to. Results: status, content_type, final_url, redirects, total_bytes and a page of the body (offset/max_bytes, next_offset; text or base64). Unrelated to captured traffic in network or proxy; no browser cookies."},
                   {"inputSchema", json::parse(web_schema)}, {"read_only", false}});
    out.push_back({{"name", "script"},
                   {"description", "Run a Lua 5.4 automation script inside reverse-slop, the scripting layer over static analysis, like IDAPython for IDA. action='run' requires code; timeout_ms defaults to 5000 and is clamped to 10..60000 (the result reports the effective timeout_ms; pass a higher one when waiting for analysis). print() output is captured (capped at 4 MiB, output_truncated=true past it) and returned values are serialized as 'return: <value>'. Limits: the deadline and MCP notifications/cancelled are checked every 1000 VM instructions and inside blocking calls (wait_ready, mem.scan, debugger waits are cut to the remaining budget); the Lua heap is capped at 256 MiB (peak_mem reports usage). Scripts never hold the tool lock for their whole run: each slop.* call takes it briefly, so other tools keep answering. SANDBOX (sandboxed=true, the default): only base (no dofile/loadfile; load and the script itself accept text chunks only, never bytecode), string, table, math, utf8 and os.clock/os.time/os.difftime are available - no io, os.execute, package/require, debug or coroutine, and debugger actions that read host files (elf_rpc/elf_load) are refused. Setting script_unsafe=true (app.settings_set {key:'script_unsafe',value:true}) opts into the full standard library; treat that as host code execution. Scripts operate on the SAME shared binary session as the UI and every other MCP tool, so loads, renames, and comments are visible everywhere. Static-analysis API: slop.image.{load(path[,base]),load_from_target,unload,status,wait_ready([ms])}; slop.disasm.{decode(addr[,n]),functions([limit]),function_at(va),xrefs_to(va),strings([min_len[,limit]]) -- note min-length FIRST, so strings(4,3000) not strings(2000),pe(),bytes(addr[,len]),name(va),set_name(va,name),comment(va),set_comment(va,text),bookmark_toggle(va),bookmarks()}; unnamed functions are sub_<VA uppercase hex> as everywhere else; slop.decomp.{decompile(va),blocks(va),vtables(),globals(),rtti()} (decomp.* needs slop.image.wait_ready first). Live analysis: slop.target.{list,attach,status}, slop.mem.{read_hex(addr,len) -> lowercase hex string, read_bytes(addr,len) -> raw byte string, write_hex(addr,hex), scan(cfg)}, slop.disasm.disassemble(addr,count), slop.analyze.packer. PS4 console: slop.ps4.{connect(host[,port]),auto(host[,port]),disconnect(),status()}; slop.debugger.{status,attach(pid),detach,bp_set(addr[,index]),bp_clear(addr),bp_list,watch_set(addr[,len[,type]]),watch_clear(addr),watch_list,continue([stop]),step([lwpid]),suspend(lwpid),resume(lwpid),wait([ms]),events([max]),regs([lwpid]),set_reg(lwpid,name,value),callstack([lwpid[,depth]]),call(addr[,{args}[,pid]]),run_until(addr[,ms]),find_write(addr[,len[,ms]]),trace_calls(addr[,count[,ms]]),action(name,{params})} - each runs the matching target/debugger ps4_* MCP action and returns its result table (errors raise Lua errors). Typical flow: image.load(path) -> image.wait_ready() -> disasm.functions() -> decomp.decompile(va). Use direct MCP tools when one operation is sufficient."},
                   {"inputSchema", json::parse(script_schema)}, {"read_only", false}});

    const char* host_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status","files","manifest","put"]},"port":{"type":"integer","description":"start: listen port (default 8080)"},"bind":{"type":"string","description":"start: listen address (default 127.0.0.1; a non-loopback bind requires a token)"},"dir":{"type":"string","description":"start: directory to serve (default %LOCALAPPDATA%\\reverse-slop\\payloads); created when missing"},"token":{"type":"string","description":"start: bearer token; required for non-loopback binds, else read from the host_token setting. Clients send Authorization: Bearer <token> or ?token=<token>"},"timeout_ms":{"type":"integer"},"name":{"type":"string","description":"put: relative path under the served dir"},"hex":{"type":"string","description":"put: file content as hex"},"text":{"type":"string","description":"put: file content as text"},"confirm":{"type":"boolean","description":"required on mutating actions (start/stop/put) while mcp_require_confirm is on"}},"required":["action"]})json";
    out.push_back({{"name", "host"},
                   {"description", "Serve a payload directory over HTTP (afterglow-web style payload host for a jailbroken PS4 / GoldHEN bin loader): start {port=8080, bind=127.0.0.1, dir, token?} serves GET / (index page), GET /manifest.json (auto-generated {files:[{name,size,sha256,url}]}), and GET /files/<name> (download, path-traversal guarded, 64 MiB per-file cap). A non-loopback bind always requires a token (arg or host_token setting) enforced as Authorization: Bearer / ?token=. stop ends the server; status reports the running endpoint; files/manifest return the manifest without HTTP; put {name, hex|text} drops a file into the served dir and returns its sha256. Payloads are your own homebrew files only."},
                   {"inputSchema", json::parse(host_schema)}, {"read_only", false}});

    const char* gdb_schema =
        R"json({"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status"]},"port":{"type":"integer","description":"start: listen port (default 2331)"},"bind":{"type":"string","description":"start: loopback only (default 127.0.0.1); non-loopback is refused"},"allow_writes":{"type":"boolean","description":"start: allow RSP memory/register writes (M/G/P packets); default false. Breakpoints (Z/z) are always allowed"},"confirm":{"type":"boolean","description":"required on start/stop while mcp_require_confirm is on"}},"required":["action"]})json";
    out.push_back({{"name", "gdb"},
                   {"description", "Control the GDB Remote Serial Protocol bridge (ported from PS4-MCP rsp.rs/broker): start {port=2331, bind=127.0.0.1, allow_writes=false} opens a TCP listener that speaks RSP so GDB/LLDB/Binary Ninja attach with 'target remote 127.0.0.1:2331' to the SAME console debug session the UI and MCP use (all clients serialize on the one ps4debug-NG connection via the broker gate). Supports qSupported, target.xml/memory-map/libraries qXfer, thread packets (qC/qfThreadInfo/Hg/Hc/T), register read g/p (GPRs + FPU via the debug session), memory read m, breakpoints/watchpoints Z/z (software bp + DR0-DR3 watchpoints), continue/step c/s/vCont with async T.. stop replies from the port-755 event stream, qAttached, vAttach, D (closes only the RSP connection, the shared session stays up). Writes M/G/P and kill/restart stay refused unless allow_writes=true at start. stop ends the bridge; status reports the bridge, the console debug session and the broker client list (mcp, gdb:<port>, ...). Requires debugger.ps4_attach {pid} first."},
                   {"inputSchema", json::parse(gdb_schema)}, {"read_only", false}});

    for (auto& t : out) finalize_tool_entry(t);
}

static nlohmann::json call_tool_inner(const std::string& name,
                                      const nlohmann::json& args, bool& is_error,
                                      infra::cancel_token_t cancel) {
    is_error = false;
    try {
        if (name == "devirt") {
            const std::string action = args.value("action", std::string{});
            if (action.rfind("themida_", 0) == 0) {
                json out = tool_devirt(args);
                try {
                    enrich_payload(name, args, out);
                } catch (...) {}
                return out;
            }
        }
        // analyze.diff runs two full Hyperion analyses + a quadratic compare:
        // it must NOT hold g_tool_mu or every lightweight tool (target.status,
        // disasm.loaded, analyze_stop, ...) queues behind it until the MCP
        // timeout fires. It carries its own cancel token + deadline instead.
        // The diff_start/diff_job/diff_cancel job flavor is lock-free too
        // (own mutex + jobs coordinator), so progress polling never blocks.
        if (name == "analyze") {
            const std::string act = args.value("action", std::string{});
            if (act == "diff" || act == "diff_start" || act == "diff_job" ||
                act == "diff_cancel") {
                json out = tool_analyze(args, cancel);
                try {
                    enrich_payload(name, args, out);
                } catch (...) {}
                return out;
            }
        }
        // emulate owns a private unicorn instance; it takes g_tool_mu itself
        // only while reading the shared image / attached target, then runs
        // unlocked so a long run never stalls other tools or initialize
        if (name == "emulate") {
            json out = tool_emulate(args, cancel);
            try {
                enrich_payload(name, args, out);
            } catch (...) {}
            return out;
        }
        // script runs unlocked: the lua engine takes g_tool_mu per slop.*
        // binding (tool_mutex) and the debugger/ps4 bindings call back into
        // call_tool, so holding the mutex for the whole script would both
        // stall every other tool and deadlock those bindings
        if (name == "script") {
            json out = tool_script(args, cancel);
            try {
                enrich_payload(name, args, out);
            } catch (...) {}
            return out;
        }
        // fs touches no shared state: run it unlocked with the request's cancel
        // token so a grep over a big tree neither blocks other tools nor outlives
        // the client that asked
        if (name == "fs") {
            json out = tool_fs(args, cancel);
            try {
                enrich_payload(name, args, out);
            } catch (...) {}
            return out;
        }
        // NOTE: decomp.function stays under g_tool_mu on purpose: the patch
        // tool can reanalyze() the session (replacing the analyzer mid-lift),
        // so decompile must stay serialized with it. Wedges are fixed at the
        // root instead (unmapped-VA fast reject in tool_decomp + SSA
        // termination guards), keeping slow-but-legit decompiles safe.
        std::lock_guard lk(g_tool_mu);
        json out;
        bool found = true;
        if (name == "app")      out = tool_app(args);
        else if (name == "target")   out = tool_target(args);
        else if (name == "memory")   out = tool_memory(args);
        else if (name == "disasm")   out = tool_disasm(args);
        else if (name == "debugger") out = tool_debugger(args);
        else if (name == "analyze")  out = tool_analyze(args, cancel);
        else if (name == "network")  out = tool_network(args);
        else if (name == "proxy")    out = tool_proxy(args);
        else if (name == "persist")  out = tool_persist(args);
        else if (name == "re")       out = tool_re(args);
        else if (name == "decomp")   out = tool_decomp(args);
        else if (name == "web")      out = tool_web(args);
        else if (name == "xray")     out = tool_xray(args);
        else if (name == "patch")    out = tool_patch(args);
        else if (name == "types")    out = tool_types(args);
        else if (name == "notes")    out = tool_notes(args);
        else if (name == "devirt")   out = tool_devirt(args);
        else if (name == "guide")    out = tool_guide(args);
        else if (name == "host")     out = tool_host(args);
        else if (name == "gdb")      out = tool_gdb(args);
        else found = false;
        if (!found) {
            is_error = true;
            json err = {{"error", "unknown tool: " + name}};
            try {
                enrich_error(name, args, err);
            } catch (...) {}
            return err;
        }
        try {
            enrich_payload(name, args, out);
        } catch (...) {}
        return out;
    } catch (const std::exception& e) {
        is_error = true;
        json err = {{"error", e.what()}};
        try {
            enrich_error(name, args, err);
        } catch (...) {}
        return err;
    } catch (...) {
        is_error = true;
        json err = {{"error", "unknown tool failure"}};
        try {
            enrich_error(name, args, err);
        } catch (...) {}
        return err;
    }
}

nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel,
                         bool allow_app) {
    // ps4debug-mcp safety model: when mcp_require_confirm is on, mutating
    // console/target actions need "confirm": true; every call (allowed or
    // refused) is appended to the JSONL audit log
    if (name == "app" && !allow_app) {
        is_error = true;
        json err = {{"error", "app is UI-only and not exposed over MCP"}};
        audit_log(name, args, err, true);
        return err;
    }
    const std::string action =
        args.is_object() ? args.value("action", std::string{}) : std::string{};
    if (infra::settings::mcp_require_confirm() && action_mutating(name, action) &&
        !(args.is_object() && args.value("confirm", false))) {
        is_error = true;
        json err = {{"error",
                     "mutating action " + name + "." + action +
                     " requires \"confirm\": true (mcp_require_confirm is on). "
                     "Re-call with confirm:true only after the user agreed."}};
        audit_log(name, args, err, true);
        return err;
    }
    json out;
    // broker gate: console-session actions serialize with every other console
    // client (UI, the GDB-RSP bridge) on the one console connection; purely
    // local tools (emulate/analyze/...) stay concurrent with a running call
    const bool console_action = name == "gdb" || name == "debugger" ||
        (name == "target" && action.rfind("ps4_", 0) == 0);
    if (console_action) {
        std::lock_guard rg(slop::core::runtime::broker_gate());
        out = call_tool_inner(name, args, is_error, cancel);
    } else {
        out = call_tool_inner(name, args, is_error, cancel);
    }
    audit_log(name, args, out, is_error);
    return out;
}

void shutdown_tools() {
    // a tool that ignores its cancel token must not wedge teardown: wait a bounded
    // time for the tool lock and leave shared state alone if it never frees up
    std::unique_lock lk(g_tool_mu, std::defer_lock);
    const int64_t deadline = infra::steady_ms() + 2000;
    while (!lk.try_lock()) {
        if (infra::steady_ms() >= deadline) {
            infra::diag::warn("mcp", "shutdown_tools: a tool call still holds the tool lock "
                                     "after 2 s; skipping tool state teardown");
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::lock_guard ilk(g_image_mu);
    g_proxy.stop();
    runtime::gdb_rsp().stop();
    g_scan.engine.reset();
    g_scan.used = false;
    g_snaps.clear();
    g_traffic.clear();
    g_image = {};
    magicmida::shutdown();
    memory::watch::shutdown();
}

json session_state() {
    // initialize must answer immediately: a client that reconnects while a
    // long tool holds g_tool_mu would otherwise time out the handshake
    std::unique_lock lk(g_tool_mu, std::try_to_lock);
    if (lk.owns_lock()) return app_state_unlocked();
    return {{"backend", runtime::active_badge()},
            {"target", attached_target_json()},
            {"busy", true},
            {"note", "another tool call is running; call disasm.loaded for image state"}};
}

} // namespace slop::core::mcp
