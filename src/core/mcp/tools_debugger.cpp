// src/core/mcp/tools_debugger.cpp
// tool: debugger (PS4 live debugging, composite flows on PS4 and the local
// test-lab backend, ps4 native scan)

#include "core/mcp/tools_common.hpp"

#include "core/debugger/composite.hpp"
#include "core/debugger/local_debugger.hpp"
#include "core/debugger/ps4_debug_target.hpp"
#include "core/memory/console_scan.hpp"

namespace slop::core::mcp::detail {

namespace {

namespace dbg = slop::core::debugger;

// tool: debugger - PS4 live debugging (ps4debug-NG debug session on the console)

json ps4_ctx_json(const runtime::thread_context_t& c) {
    return {{"rip", c.rip}, {"rsp", c.rsp}, {"rbp", c.rbp},
            {"rax", c.rax}, {"rbx", c.rbx}, {"rcx", c.rcx}, {"rdx", c.rdx},
            {"rsi", c.rsi}, {"rdi", c.rdi},
            {"r8", c.r8}, {"r9", c.r9}, {"r10", c.r10}, {"r11", c.r11},
            {"r12", c.r12}, {"r13", c.r13}, {"r14", c.r14}, {"r15", c.r15},
            {"flags", c.flags}};
}

json ps4_event_json(const runtime::ps4_event_t& e) {
    json o = {{"lwpid", e.lwpid}, {"signal", e.signal}, {"status", e.status},
              {"thread", e.thread_name}};
    // name the context json first: items() on a temporary dangles
    json cx = ps4_ctx_json(e.ctx);
    for (auto& kv : cx.items()) o[kv.key()] = kv.value();
    json dr = json::array();
    for (uint64_t d : e.dr) dr.push_back(d);
    o["dr"] = dr;
    return o;
}

// a generic stop (console or local) in the same shape as ps4_event_json
json stop_json(const dbg::stop_event_t& e) {
    json o = {{"lwpid", e.tid}, {"signal", e.signal}, {"status", e.status},
              {"thread", e.thread}, {"reason", e.reason}};
    json cx = ps4_ctx_json(e.ctx);
    for (auto& kv : cx.items()) o[kv.key()] = kv.value();
    o["rip_hex"] = addr_hex_str(e.ctx.rip);
    json dr = json::array();
    for (uint64_t d : e.dr) dr.push_back(d);
    o["dr"] = dr;
    return o;
}

json frames_json(const std::vector<dbg::frame_rec_t>& frames) {
    json arr = json::array();
    for (size_t i = 0; i < frames.size(); ++i)
        arr.push_back({{"index", i}, {"ret_addr", frames[i].ret_addr},
                       {"ret_addr_hex", addr_hex_str(frames[i].ret_addr)},
                       {"frame_ptr", frames[i].frame_ptr}});
    return arr;
}

[[noreturn]] void io_fail(const std::string& what, const runtime::io_result_t& io) {
    fail(what + ": " + runtime::ps4::io_error_str(io.error));
}

runtime::backend_ps4_t& need_ps4() {
    auto* p = runtime::registry_ps4();
    if (!p)
        fail("PS4 debug actions require a connected console (target.ps4_connect {host})");
    if (!p->connected())
        fail("the console connection was lost (" + p->lost_reason() +
             "); target.ps4_reconnect restores it with the debug session and breakpoints");
    return *p;
}

uint32_t ps4_pid_arg(const json& args) {
    if (args.contains("pid"))
        return static_cast<uint32_t>(parse_addr(args, "pid"));
    if (auto s = process::active_session(); s && s->valid())
        return s->pid();
    fail("missing pid (no PS4 target attached either; use target.attach {pid})");
}

// lwpid argument, or the first thread of the debuggee when omitted
uint32_t ps4_lwpid_arg(runtime::backend_ps4_t& p, const json& args) {
    if (args.contains("lwpid"))
        return static_cast<uint32_t>(parse_addr(args, "lwpid"));
    const uint32_t pid = ps4_pid_arg(args);
    auto thr = p.enum_threads(pid);
    if (thr.ok && !thr.items.empty()) return thr.items.front().tid;
    fail("missing lwpid (target.threads lists the debuggee's lwpids)");
}

std::string ps4_hex_str(const uint8_t* bytes, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[bytes[i] >> 4]);
        out.push_back(kHex[bytes[i] & 0xF]);
    }
    return out;
}

std::string ps4_hex_str(const std::vector<uint8_t>& bytes) {
    return ps4_hex_str(bytes.data(), bytes.size());
}

// ---- debug target selection for the composite flows ------------------------
// The console debugger when a PS4 is the session's backend, otherwise the
// local Win32 debugger on the attached test-lab process (so the composite
// flows run, and are tested, without a console)

dbg::local_debugger_t& local_debugger() {
    static dbg::local_debugger_t d;
    return d;
}

struct picked_target_t {
    std::shared_ptr<runtime::session_t> session;
    std::unique_ptr<dbg::ps4_debug_target_t> ps4;
    dbg::debug_target_t* t = nullptr;
    runtime::backend_ps4_t* p4 = nullptr;
};

picked_target_t pick_debug_target(const std::string& action) {
    picked_target_t pk;
    pk.session = process::active_session();
    runtime::backend_t* b = pk.session && pk.session->valid() ? pk.session->backend()
                                                              : &runtime::active();
    if (b->kind() == runtime::backend_kind_t::ps4) {
        auto& p = need_ps4();
        if (!p.ps4_debug_attached()) fail(action + " requires ps4_attach first");
        pk.p4 = &p;
        pk.ps4 = std::make_unique<dbg::ps4_debug_target_t>(p, pk.session);
        pk.t = pk.ps4.get();
        return pk;
    }
    if (!pk.session || !pk.session->valid())
        fail(action + " needs an attached target (target.attach {pid}, or target.ps4_connect)");
    auto& d = local_debugger();
    if (!d.attached() || d.pid() != pk.session->pid()) {
        std::string err;
        if (!d.attach(pk.session->pid(), err))
            fail(action + ": local debugger attach failed: " + err);
    }
    pk.t = &d;
    return pk;
}

json tool_debugger_composite(const std::string& action, const json& args) {
    auto pk = pick_debug_target(action);
    auto& t = *pk.t;

    if (action == "ps4_until") {
        // one-call "run until addr": arm a one-shot bp, continue, wait, clear
        const uint64_t addr = parse_addr(args, "addr");
        const int timeout_ms = std::min(args.value("timeout_ms", 30000), 60000);
        auto r = dbg::run_until(t, addr, timeout_ms);
        if (!r.ok) fail("ps4_until: " + r.error);
        json o = r.halted ? stop_json(r.ev) : json::object();
        o["halted"] = r.halted;
        o["until"] = addr;
        o["until_hex"] = addr_hex_str(addr);
        o["index"] = r.index;
        o["bp_was_armed"] = r.reused;
        o["skipped_stops"] = r.skipped;
        o["debugger"] = t.kind();
        if (!r.halted) {
            o["timeout_ms"] = timeout_ms;
            if (r.ev.reason == "exit") o["process_exited"] = true;
        }
        return o;
    }
    if (action == "ps4_find_write") {
        // one-call "who writes here": write watchpoint, continue, wait, callstack
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len = args.contains("len") ? parse_addr(args, "len") : 8;
        const int timeout_ms = std::min(args.value("timeout_ms", 30000), 60000);
        const size_t depth = std::min<size_t>(args.value("depth", 32u), 64u);
        auto r = dbg::find_write(t, addr, static_cast<uint32_t>(len), timeout_ms, depth);
        if (!r.ok) fail("ps4_find_write: " + r.error);
        json out = {{"halted", r.halted}, {"addr", addr}, {"addr_hex", addr_hex_str(addr)},
                    {"len", len}, {"timeout_ms", timeout_ms}, {"index", r.index},
                    {"debugger", t.kind()}};
        if (r.halted) {
            out["event"] = stop_json(r.ev);
            out["callstack"] = frames_json(r.frames);
            out["writer_rip"] = r.ev.ctx.rip;
            out["writer_rip_hex"] = addr_hex_str(r.ev.ctx.rip);
        }
        return out;
    }
    if (action == "ps4_trace_calls") {
        // breakpoint arg logger: continue+wait loop recording the 6 arg regs
        const uint64_t addr = parse_addr(args, "addr");
        const size_t count = std::min<size_t>(args.value("count", 64u), 4096u);
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        auto r = dbg::trace_calls(t, addr, count, timeout_ms);
        if (!r.ok) fail("ps4_trace_calls: " + r.error);
        json hits = json::array();
        for (size_t i = 0; i < r.hits.size(); ++i) {
            const auto& ev = r.hits[i];
            hits.push_back({{"index", i}, {"lwpid", ev.tid},
                            {"thread", ev.thread}, {"signal", ev.signal},
                            {"rip", ev.ctx.rip}, {"rdi", ev.ctx.rdi},
                            {"rsi", ev.ctx.rsi}, {"rdx", ev.ctx.rdx},
                            {"rcx", ev.ctx.rcx}, {"r8", ev.ctx.r8},
                            {"r9", ev.ctx.r9}});
        }
        return {{"addr", addr}, {"addr_hex", addr_hex_str(addr)}, {"hits", hits},
                {"hits_count", hits.size()}, {"stop_reason", r.stop_reason},
                {"skipped_stops", r.skipped}, {"debugger", t.kind()},
                {"note", "args are the SysV order rdi,rsi,rdx,rcx,r8,r9 (local Win64 targets "
                         "pass rcx,rdx,r8,r9); the target stays stopped at the last hit, "
                         "ps4_continue resumes"}};
    }
    // ps4_trace_steps: single-step execution trace with disassembly
    uint32_t tid = 0;
    if (args.contains("lwpid")) tid = static_cast<uint32_t>(parse_addr(args, "lwpid"));
    else if (pk.p4) tid = ps4_lwpid_arg(*pk.p4, args);
    const size_t count = std::min<size_t>(args.value("count", 64u), 4096u);
    const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
    auto r = dbg::trace_steps(t, tid, count, timeout_ms);
    if (!r.ok) fail("ps4_trace_steps: " + r.error);
    auto& eng = shared_engine();
    if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
    json steps = json::array();
    for (size_t i = 0; i < r.steps.size(); ++i) {
        const auto& s = r.steps[i];
        json rec = {{"index", i}, {"lwpid", s.tid}, {"rip", s.rip}, {"rip_hex", addr_hex_str(s.rip)}};
        if (s.nbytes) {
            if (auto in = eng.decode(s.rip, s.bytes, s.nbytes)) rec["text"] = in->text;
        }
        steps.push_back(std::move(rec));
    }
    return {{"lwpid", tid}, {"steps", steps}, {"steps_count", steps.size()},
            {"stop_reason", r.stop_reason}, {"debugger", t.kind()}};
}

// native ps4debug-NG scan session (one per console connection); mirrors the
// host-side memory.scan state but runs the scan on the console itself
struct ps4_scan_session_t {
    bool     used = false;
    uint32_t pid = 0;
    uint64_t base = 0;
    uint8_t  valtype = 0;
    std::vector<runtime::backend_ps4_t::ps4_scan_hit_t> hits;
};
ps4_scan_session_t& ps4_scan_sess() { static ps4_scan_session_t s; return s; }

uint8_t ps4_valtype_arg(const json& args) {
    const std::string w = args.value("value_type",
                                     args.value("width", std::string{"u32"}));
    if (w == "u8") return runtime::ps4::kValU8;
    if (w == "i8") return runtime::ps4::kValI8;
    if (w == "u16") return runtime::ps4::kValU16;
    if (w == "i16") return runtime::ps4::kValI16;
    if (w == "u32") return runtime::ps4::kValU32;
    if (w == "i32") return runtime::ps4::kValI32;
    if (w == "u64") return runtime::ps4::kValU64;
    if (w == "i64") return runtime::ps4::kValI64;
    if (w == "f32" || w == "float")  return runtime::ps4::kValF32;
    if (w == "f64" || w == "double") return runtime::ps4::kValF64;
    if (w == "bytes" || w == "array") return runtime::ps4::kValArrBytes;
    if (w == "string") return runtime::ps4::kValString;
    fail("bad value_type (u8|i8|u16|i16|u32|i32|u64|i64|f32|f64|bytes|string)");
}

uint8_t ps4_cmptype_arg(const json& args) {
    const std::string k = args.value("compare",
                                     args.value("kind", std::string{"exact"}));
    if (k == "exact") return runtime::ps4::kCmpExact;
    if (k == "fuzzy") return runtime::ps4::kCmpFuzzy;
    if (k == "bigger" || k == "bigger_than") return runtime::ps4::kCmpBigger;
    if (k == "smaller" || k == "smaller_than") return runtime::ps4::kCmpSmaller;
    if (k == "between") return runtime::ps4::kCmpBetween;
    if (k == "increased") return runtime::ps4::kCmpIncreased;
    if (k == "increased_by") return runtime::ps4::kCmpIncreasedBy;
    if (k == "decreased") return runtime::ps4::kCmpDecreased;
    if (k == "decreased_by") return runtime::ps4::kCmpDecreasedBy;
    if (k == "changed") return runtime::ps4::kCmpChanged;
    if (k == "unchanged") return runtime::ps4::kCmpUnchanged;
    if (k == "unknown") return runtime::ps4::kCmpUnknown;
    if (k == "unknown_low") return runtime::ps4::kCmpUnknownLow;
    fail("bad compare (exact|fuzzy|bigger|smaller|between|increased|increased_by|"
         "decreased|decreased_by|changed|unchanged|unknown|unknown_low)");
}

memory::value_width_t ps4_width_of(uint8_t vt) {
    using memory::value_width_t;
    switch (vt) {
        case runtime::ps4::kValU8: return value_width_t::u8;
        case runtime::ps4::kValI8: return value_width_t::i8;
        case runtime::ps4::kValU16: return value_width_t::u16;
        case runtime::ps4::kValI16: return value_width_t::i16;
        case runtime::ps4::kValU32: return value_width_t::u32;
        case runtime::ps4::kValI32: return value_width_t::i32;
        case runtime::ps4::kValU64: return value_width_t::u64;
        case runtime::ps4::kValI64: return value_width_t::i64;
        case runtime::ps4::kValF32: return value_width_t::f32;
        case runtime::ps4::kValF64: return value_width_t::f64;
        default: return value_width_t::u32;
    }
}

// encode the 'value' arg (number, numeric string, [min,max] for between, or
// 'hex' for bytes) into little-endian scan bytes
std::vector<uint8_t> ps4_value_bytes(const json& args, uint8_t vt, uint8_t ct) {
    const auto append_bits = [&](uint64_t bits, uint32_t nbytes) {
        std::vector<uint8_t> out;
        for (uint32_t i = 0; i < nbytes; ++i)
            out.push_back(static_cast<uint8_t>((bits >> (8 * i)) & 0xFF));
        return out;
    };
    if (vt == runtime::ps4::kValArrBytes || vt == runtime::ps4::kValString) {
        if (vt == runtime::ps4::kValString) {
            if (!args.contains("value") || !args.at("value").is_string())
                fail("string scan requires string 'value'");
            const std::string s = args.at("value").get<std::string>();
            return std::vector<uint8_t>(s.begin(), s.end());
        }
        if (!args.contains("hex") || !args.at("hex").is_string())
            fail("bytes scan requires 'hex'");
        return hex_decode(args.at("hex").get<std::string>());
    }
    const auto width = ps4_width_of(vt);
    const uint32_t nbytes = static_cast<uint32_t>(memory::value_size(width));
    std::vector<uint8_t> out;
    if (ct == runtime::ps4::kCmpBetween) {
        // value: [min, max] or "min,max"
        std::vector<std::string> parts;
        if (args.contains("value") && args.at("value").is_array()) {
            for (const auto& v : args.at("value")) {
                if (v.is_string()) parts.push_back(v.get<std::string>());
                else if (v.is_number()) parts.push_back(v.dump());
                else fail("between value entries must be numbers/strings");
            }
        } else if (args.contains("value") && args.at("value").is_string()) {
            const std::string s = args.at("value").get<std::string>();
            size_t pos = 0;
            while (true) {
                const size_t comma = s.find(',', pos);
                parts.push_back(s.substr(pos, comma == std::string::npos ? comma : comma - pos));
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else fail("between scan requires value: [min, max]");
        if (parts.size() != 2) fail("between scan needs exactly two values");
        for (const auto& p : parts) {
            uint64_t bits = 0;
            if (!memory::parse_value_text(width, p, bits))
                fail("bad between value '" + p + "' for the chosen value_type");
            auto b = append_bits(bits, nbytes);
            out.insert(out.end(), b.begin(), b.end());
        }
        return out;
    }
    if (!args.contains("value")) fail("scan requires 'value' (or 'hex' for bytes)");
    const json& v = args.at("value");
    std::string text;
    if (v.is_string()) text = v.get<std::string>();
    else if (v.is_number()) text = v.dump();
    else fail("value must be a number or numeric string");
    uint64_t bits = 0;
    if (!memory::parse_value_text(width, text, bits))
        fail("bad value '" + text + "' for the chosen value_type");
    return append_bits(bits, nbytes);
}

json ps4_hits_json(const std::vector<runtime::backend_ps4_t::ps4_scan_hit_t>& hits,
                   size_t cap) {
    json arr = json::array();
    for (size_t i = 0; i < hits.size() && i < cap; ++i) {
        arr.push_back({{"addr", hits[i].addr},
                       {"addr_hex", addr_hex_str(hits[i].addr)},
                       {"value_hex", ps4_hex_str(hits[i].value)}});
    }
    return arr;
}

std::string scan_hint(const runtime::backend_ps4_t& p) {
    return p.ps4_authed() ? std::string{} : " (scan family needs auth bit 1: debugger.ps4_auth)";
}

json tool_ps4_scan(const std::string& action, const json& args,
                   runtime::backend_ps4_t& p) {
    auto& ss = ps4_scan_sess();
    if (action == "ps4_scan_reset") {
        ss = ps4_scan_session_t{};
        return {{"reset", true}};
    }
    if (action == "ps4_scan_state") {
        if (!ss.used) return {{"used", false}, {"note", "no native scan running; start with debugger ps4_scan"}};
        return {{"used", true}, {"pid", ss.pid}, {"base", ss.base},
                {"base_hex", addr_hex_str(ss.base)}, {"value_type", ss.valtype},
                {"count", ss.hits.size()},
                {"hits", ps4_hits_json(ss.hits, 256)},
                {"truncated", ss.hits.size() > 256},
                {"note", "narrow with ps4_rescan; read values with memory.read"}};
    }
    if (action == "ps4_scan_all") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint8_t vt = ps4_valtype_arg(args);
        const uint8_t ct = ps4_cmptype_arg(args);
        auto data = runtime::ps4::scan_cmp_needs_value(ct)
            ? ps4_value_bytes(args, vt, ct) : std::vector<uint8_t>{};
        std::vector<uint64_t> addrs;
        bool backend_truncated = false;
        auto io = p.ps4_scan_all(pid, vt, ct, data, addrs, &backend_truncated);
        if (!io.ok) fail("ps4_scan_all failed: " + runtime::ps4::io_error_str(io.error) + scan_hint(p));
        constexpr size_t kListCap = 4096;
        const size_t cap = std::min(addrs.size(), kListCap);
        json arr = json::array();
        for (size_t i = 0; i < cap; ++i)
            arr.push_back({{"addr", addrs[i]}, {"addr_hex", addr_hex_str(addrs[i])}});
        return {{"scanned", "all readable maps"}, {"count", addrs.size()},
                {"hits", arr}, {"cap", kListCap},
                {"backend_truncated", backend_truncated},
                {"backend_cap", runtime::backend_ps4_t::kMaxScanAll},
                {"truncated", backend_truncated || addrs.size() > cap}};
    }
    if (action == "ps4_scan_aob") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len64 = parse_addr(args, "len");
        if (len64 == 0) fail("ps4_scan_aob: len must be > 0");
        if (!args.contains("pattern") || !args.at("pattern").is_string())
            fail("ps4_scan_aob requires 'pattern' hex with ?? wildcards, e.g. \"48 8B ?? ?? 90\"");
        // build pattern+mask from a hex string where ?? (or any non-hex pair) is a wildcard
        const std::string raw = args.at("pattern").get<std::string>();
        std::vector<uint8_t> pattern, mask;
        size_t i = 0;
        while (i < raw.size()) {
            if (raw[i] == '?') {   // ?? (or a lone ?) is a wildcard byte
                pattern.push_back(0);
                mask.push_back(0);
                ++i;
                if (i < raw.size() && raw[i] == '?') ++i;
                continue;
            }
            if (!std::isxdigit(static_cast<unsigned char>(raw[i]))) { ++i; continue; }
            if (i + 1 >= raw.size() || !std::isxdigit(static_cast<unsigned char>(raw[i + 1]))) {
                fail("ps4_scan_aob: pattern has an odd hex digit at offset " +
                     std::to_string(i));
            }
            pattern.push_back(static_cast<uint8_t>(std::stoul(raw.substr(i, 2), nullptr, 16)));
            mask.push_back(1);
            i += 2;
        }
        if (pattern.empty()) fail("ps4_scan_aob: empty pattern");
        if (args.contains("max_matches")) {
            // legacy single-answer form: the max_matches-th match of one call
            if (len64 > 0xFFFFFFFFull) fail("ps4_scan_aob: len above 4 GiB needs the all-matches form");
            const uint8_t max_matches = static_cast<uint8_t>(args.value("max_matches", 1u));
            uint8_t stop_flag = 0;
            if (args.contains("unique")) {
                const json& u = args.at("unique");
                stop_flag = u.is_boolean() ? (u.get<bool>() ? 1 : 0)
                                           : static_cast<uint8_t>(parse_addr(args, "unique") != 0);
            }
            uint64_t hit = 0;
            auto io = p.ps4_scan_aob(pid, addr, static_cast<uint32_t>(len64), pattern, mask,
                                     max_matches, stop_flag, hit);
            if (!io.ok) fail("ps4_scan_aob failed: " + runtime::ps4::io_error_str(io.error) + scan_hint(p));
            json matches = json::array();
            if (hit) matches.push_back({{"addr", hit}, {"addr_hex", addr_hex_str(hit)}});
            return {{"addr", hit}, {"addr_hex", addr_hex_str(hit)},
                    {"found", hit != 0}, {"matches", matches}, {"count", matches.size()},
                    {"truncated", false},
                    {"note", "returns the max_matches-th match (0 when none or invalidated "
                             "with unique=1); omit max_matches to get every match"}};
        }
        // every match: re-issue the on-device search from just past each hit
        memory::console_aob_options_t opt;
        opt.pattern_len = pattern.size();
        opt.max_results = static_cast<size_t>(args.value("limit", 4096u));
        std::vector<memory::scan_region_t> regions(1);
        regions[0].base = static_cast<uintptr_t>(addr);
        regions[0].size = static_cast<size_t>(len64);
        memory::console_aob_stats_t stats;
        const auto hits = memory::console_aob_all(
            [&](uint64_t a, uint32_t l, uint64_t& hit) {
                return p.ps4_scan_aob(pid, a, l, pattern, mask, 1, 0, hit).ok;
            },
            regions, opt, infra::cancel_token_t{}, &stats);
        if (stats.failed && hits.empty())
            fail("ps4_scan_aob failed at " + addr_hex_str(stats.failed_at) + scan_hint(p));
        json matches = json::array();
        for (uint64_t h : hits) matches.push_back({{"addr", h}, {"addr_hex", addr_hex_str(h)}});
        const uint64_t first = hits.empty() ? 0 : hits.front();
        json out = {{"addr", first}, {"addr_hex", addr_hex_str(first)}, {"found", !hits.empty()},
                    {"matches", matches}, {"count", hits.size()},
                    {"truncated", stats.truncated}, {"calls", stats.calls}};
        if (stats.failed) {
            out["partial"] = true;
            out["failed_at"] = stats.failed_at;
        }
        return out;
    }
    // ps4_scan (first) / ps4_rescan (narrow)
    const uint32_t pid = ps4_pid_arg(args);
    const uint8_t vt = action == "ps4_rescan"
        ? (ss.used ? ss.valtype : ps4_valtype_arg(args))
        : ps4_valtype_arg(args);
    const uint8_t ct = ps4_cmptype_arg(args);
    auto data = runtime::ps4::scan_cmp_needs_value(ct)
        ? ps4_value_bytes(args, vt, ct) : std::vector<uint8_t>{};
    if (action == "ps4_scan") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint32_t len = static_cast<uint32_t>(parse_addr(args, "len"));
        const uint8_t alignment = static_cast<uint8_t>(args.value("alignment", 0u));
        std::vector<runtime::backend_ps4_t::ps4_scan_hit_t> hits;
        auto io = p.ps4_scan_first(pid, addr, len, vt, ct, alignment, data, hits);
        if (!io.ok) fail("ps4_scan failed: " + runtime::ps4::io_error_str(io.error) + scan_hint(p));
        ss.used = true; ss.pid = pid; ss.base = addr; ss.valtype = vt; ss.hits = hits;
        return {{"first_scan", true}, {"pid", pid}, {"addr", addr},
                {"addr_hex", addr_hex_str(addr)}, {"len", len},
                {"count", hits.size()}, {"hits", ps4_hits_json(hits, 256)},
                {"truncated", hits.size() > 256},
                {"note", "narrow with ps4_rescan {compare, value}; state in ps4_scan_state"}};
    }
    if (!ss.used || ss.pid != pid)
        fail("ps4_rescan needs a ps4_scan for this pid first");
    std::vector<runtime::backend_ps4_t::ps4_scan_hit_t> hits;
    auto io = p.ps4_scan_next(pid, ss.base, vt, ct, ss.hits, data, hits);
    if (!io.ok) fail("ps4_rescan failed: " + runtime::ps4::io_error_str(io.error) + scan_hint(p));
    ss.hits = hits;
    return {{"rescanned", true}, {"pid", pid}, {"base", ss.base},
            {"base_hex", addr_hex_str(ss.base)}, {"count", hits.size()},
            {"hits", ps4_hits_json(hits, 256)}, {"truncated", hits.size() > 256}};
}


json slots_json(const std::vector<runtime::backend_ps4_t::ps4_slot_t>& slots, bool wp) {
    json arr = json::array();
    for (const auto& s : slots) {
        json o = {{"addr", s.addr}, {"addr_hex", addr_hex_str(s.addr)},
                  {"index", s.index}, {"armed", s.armed}};
        if (wp) { o["len"] = s.len; o["type"] = s.type; }
        arr.push_back(std::move(o));
    }
    return arr;
}

json ps4_status_json(runtime::backend_ps4_t& p) {
    const int ext = p.ps4_fork_extensions();
    return {{"attached", p.ps4_debug_attached()},
            {"pid", p.ps4_debug_pid()},
            {"connected", p.connected()},
            {"lost", p.lost()},
            {"lost_reason", p.lost_reason()},
            {"drops", p.drop_count()},
            {"fw", p.fw_string()},
            {"authed", p.ps4_authed()},
            {"pending_events", p.ps4_pending_events()},
            {"events_received", p.ps4_events_received()},
            {"events_dropped", p.ps4_events_dropped()},
            {"event_queue_cap", runtime::backend_ps4_t::kMaxQueuedEvents},
            {"breakpoints", p.ps4_breakpoints().size()},
            {"watchpoints", p.ps4_watchpoints().size()},
            {"endpoint", runtime::registry_ps4_endpoint()},
            {"branding", p.branding()},
            {"capability_level", p.ps4_capability_level()},
            {"fork_extensions", ext == 1 ? "yes" : ext == 0 ? "no (upstream payload)" : "not probed yet"},
            {"reconnects", p.ps4_connection_generation()},
            {"backend", "PS4"}};
}

json tool_ps4_turbo(const std::string& action, const json& args,
                    runtime::backend_ps4_t& p);

struct ps4_turbo_session_t {
    bool     used = false;
    uint32_t pid = 0;
    uint64_t base = 0;
    uint8_t  valtype = 0;
    uint32_t vlen = 0;
    uint32_t flags = 0;       // TS_* flags carried into rescans
    bool     resident = false;
    bool     snapshot = false;
    uint64_t count = 0;
    uint32_t passes = 0;
    uint64_t generation = 0;  // connection generation the console session lives on
    std::vector<runtime::backend_ps4_t::ps4_scan_hit_t> hits;
};
ps4_turbo_session_t& ps4_turbo_sess() { static ps4_turbo_session_t s; return s; }

std::string ps4_value_text(uint8_t vt, const std::vector<uint8_t>& bytes) {
    if (runtime::ps4::scan_value_size(vt) == 0 || bytes.size() > 8) return {};
    uint64_t bits = 0;
    for (size_t i = 0; i < bytes.size(); ++i) bits |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    return memory::format_value_text(ps4_width_of(vt), bits);
}

json ps4_turbo_records_json(uint8_t vt,
                            const std::vector<runtime::backend_ps4_t::ps4_turbo_record_t>& recs) {
    json arr = json::array();
    for (const auto& r : recs) {
        json j = {{"addr", r.addr}, {"addr_hex", addr_hex_str(r.addr)},
                  {"value_hex", ps4_hex_str(r.current)}};
        if (auto t = ps4_value_text(vt, r.current); !t.empty()) j["value"] = t;
        if (r.previous != r.current) {
            j["previous_hex"] = ps4_hex_str(r.previous);
            if (auto t = ps4_value_text(vt, r.previous); !t.empty()) j["previous"] = t;
        }
        if (!r.first.empty()) {
            j["first_hex"] = ps4_hex_str(r.first);
            if (auto t = ps4_value_text(vt, r.first); !t.empty()) j["first"] = t;
        }
        arr.push_back(std::move(j));
    }
    return arr;
}

// first `limit` survivors of the current session, from the console when
// resident or from the streamed hit list otherwise
json ps4_turbo_preview(runtime::backend_ps4_t& p, const ps4_turbo_session_t& ts,
                       uint32_t start, uint32_t limit) {
    if (!ts.resident) {
        json arr = json::array();
        for (size_t i = start; i < ts.hits.size() && i < size_t{start} + limit; ++i) {
            json j = {{"addr", ts.hits[i].addr}, {"addr_hex", addr_hex_str(ts.hits[i].addr)},
                      {"value_hex", ps4_hex_str(ts.hits[i].value)}};
            if (auto t = ps4_value_text(ts.valtype, ts.hits[i].value); !t.empty()) j["value"] = t;
            arr.push_back(std::move(j));
        }
        return arr;
    }
    if (limit == 0 || ts.count == 0) return json::array();
    std::vector<runtime::backend_ps4_t::ps4_turbo_record_t> recs;
    auto io = p.ps4_turbo_get(start, limit, ts.vlen, recs);
    if (!io.ok) fail("ps4_turbo GET failed (error " + std::to_string(io.error) + ")");
    return ps4_turbo_records_json(ts.valtype, recs);
}

// segments for "scan the whole process": every map with the requested prot,
// adjacent maps merged, each capped to the u32 segment length
std::vector<runtime::backend_ps4_t::ps4_turbo_segment_t>
ps4_turbo_segments_for(runtime::backend_ps4_t& p, uint32_t pid, const std::string& which) {
    runtime::target_handle_t th;
    th.pid = pid;
    auto regs = p.enum_regions(th);
    if (!regs.ok) fail("ps4_turbo_scan: cannot read the process maps (error " +
                       std::to_string(regs.error) + ")");
    const auto wanted = [&](uint32_t prot) {
        const bool w = prot == 0x04 || prot == 0x08 || prot == 0x40 || prot == 0x80;
        const bool r = prot != 0x01 && prot != 0x10;
        if (which == "writable") return w;
        if (which == "readable" || which == "all") return r;
        fail("regions must be writable|readable|all");
    };
    std::vector<runtime::backend_ps4_t::ps4_turbo_segment_t> out;
    for (const auto& rg : regs.items) {
        if (!wanted(rg.protect) || rg.size == 0) continue;
        uint64_t a = rg.base;
        uint64_t left = rg.size;
        if (!out.empty() && out.back().addr + out.back().len == a &&
            uint64_t{out.back().len} + left <= 0xFFFFF000ull) {
            out.back().len += static_cast<uint32_t>(left);
            continue;
        }
        while (left > 0) {
            const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(left, 0xFFFFF000ull));
            out.push_back({a, n});
            a += n;
            left -= n;
        }
    }
    if (out.empty()) fail("ps4_turbo_scan: no " + which + " regions in pid " + std::to_string(pid));
    return out;
}

uint32_t ps4_turbo_float_flags(const json& args, uint8_t vt, uint32_t engines) {
    if (vt != runtime::ps4::kValF32 && vt != runtime::ps4::kValF64) return 0;
    if (!(engines & runtime::ps4::kTseFloatPolicy)) return 0;   // older payload: plain compare
    const std::string mode = args.value("float", std::string{});
    if (mode.empty() || mode == "default") return 0;
    if (mode == "exact") return runtime::ps4::kTsFloatExact;
    if (mode == "simple") {
        uint32_t e = args.value("float_exponent", 11u);
        if (e == 0 || e > 127) fail("float_exponent must be 1..127");
        return runtime::ps4::kTsFloatSimple |
               ((e << runtime::ps4::kTsFloatExponentShift) & runtime::ps4::kTsFloatExponentMask);
    }
    fail("float must be default|exact|simple");
}

json ps4_turbo_caps_json(const runtime::backend_ps4_t::ps4_turbo_caps_t& c) {
    using namespace runtime::ps4;
    json eng = json::array();
    const std::pair<uint32_t, const char*> names[] = {
        {kTseSimdCompare, "simd_compare"}, {kTseAliasing, "aliasing"},
        {kTseServerResident, "server_resident"}, {kTseSnapshot, "snapshot"},
        {kTseSnapshotSegments, "snapshot_segments"}, {kTseSnapshotConfig, "snapshot_config"},
        {kTseSnapshotFirst, "snapshot_first"}, {kTseSnapshotPrevious, "snapshot_previous"},
        {kTseParallelCompare, "parallel_compare"}, {kTseRescanAliasing, "rescan_aliasing"},
        {kTseFloatPolicy, "float_policy"}, {kTseCompactSimpleSnapshot, "compact_simple_snapshot"}};
    for (const auto& [bit, name] : names)
        if (c.engines & bit) eng.push_back(name);
    return {{"version", c.version}, {"engines_mask", c.engines},
            {"engines", eng}, {"max_threads", c.max_threads}};
}

json tool_ps4_turbo(const std::string& action, const json& args,
                    runtime::backend_ps4_t& p) {
    using namespace runtime::ps4;
    auto& ts = ps4_turbo_sess();

    if (action == "ps4_turbo_caps") {
        runtime::backend_ps4_t::ps4_turbo_caps_t caps;
        auto io = p.ps4_turbo_caps(caps);
        if (!io.ok)
            return {{"supported", false},
                    {"note", "payload has no Turbo Scan (error " + std::to_string(io.error) +
                             "); use ps4_scan/ps4_rescan instead"}};
        json j = ps4_turbo_caps_json(caps);
        j["supported"] = true;
        j["capability_level"] = p.ps4_capability_level();
        return j;
    }

    if (action == "ps4_turbo_cancel") {
        const uint32_t pid = ps4_pid_arg(args);
        std::string err;
        auto io = p.ps4_turbo_cancel(pid, err);
        if (!io.ok) fail("ps4_turbo_cancel failed (" + err + ")");
        // the cancelled session is indeterminate; the in-flight call returns
        // partial results, so force a fresh scan
        ts.used = false;
        return {{"cancelled", true}, {"pid", pid},
                {"note", "the running scan stops early with partial results; the session "
                         "is now invalid - run ps4_turbo_end or a new ps4_turbo_scan"}};
    }

    if (action == "ps4_turbo_end") {
        auto io = p.ps4_turbo_end();
        ts = ps4_turbo_session_t{};
        if (!io.ok) fail("ps4_turbo_end failed (error " + std::to_string(io.error) + ")");
        return {{"ended", true}};
    }

    if (action == "ps4_turbo_config") {
        const uint32_t mb = args.value("ram_mb", 0u);
        const std::string dir = args.value("spill_path", std::string{});
        auto io = p.ps4_turbo_config(mb, dir);
        if (!io.ok) fail("ps4_turbo_config failed (error " + std::to_string(io.error) +
                         "; spill_path max 63 chars, needs ps4_auth)");
        return {{"ram_mb", mb ? mb : 512u}, {"spill_path", dir},
                {"note", "applies to the next snapshot scan; ram_mb 0 = payload default (512)"}};
    }

    if (action == "ps4_turbo_regions") {
        const uint32_t pid = ps4_pid_arg(args);
        std::vector<runtime::backend_ps4_t::ps4_turbo_region_t> regs;
        auto io = p.ps4_turbo_regions(pid, args.value("max", 0u), args.value("probe_bytes", 0u), regs);
        if (!io.ok) fail("ps4_turbo_regions failed (error " + std::to_string(io.error) + ")");
        json arr = json::array();
        uint64_t slow = 0;
        for (const auto& r : regs) {
            const bool uncached = (r.flags & 1u) != 0;
            if (uncached) ++slow;
            arr.push_back({{"start", r.start}, {"start_hex", addr_hex_str(r.start)},
                           {"end", r.end}, {"size", r.end - r.start}, {"prot", r.prot},
                           {"uncached", uncached}, {"mbps", r.mbps}});
        }
        return {{"pid", pid}, {"count", regs.size()}, {"uncached", slow}, {"regions", arr},
                {"note", "uncached (PCD) or low-mbps regions are slow to scan; pass the fast "
                         "ones as ps4_turbo_scan segments"}};
    }

    // a resident session dies with the connection it was created on; a NOP
    // makes the backend notice (and reopen) a connection the payload dropped
    if (ts.used && ts.resident) p.ping();
    if (ts.used && ts.resident && ts.generation != p.ps4_connection_generation()) {
        ts = ps4_turbo_session_t{};
        if (action == "ps4_turbo_results" || action == "ps4_turbo_rescan")
            fail("the console dropped the connection since the last turbo scan, which "
                 "freed its results; run ps4_turbo_scan again");
    }

    if (action == "ps4_turbo_results") {
        if (!ts.used) fail("no turbo scan session; start with ps4_turbo_scan");
        const uint32_t start = args.value("start", 0u);
        const uint32_t count = std::min(args.value("count", 256u), 65536u);
        json recs = ps4_turbo_preview(p, ts, start, count);
        return {{"pid", ts.pid}, {"total", ts.count}, {"start", start},
                {"returned", recs.size()}, {"results", recs}};
    }

    const uint32_t limit = std::min(args.value("limit", 256u), 65536u);

    if (action == "ps4_turbo_rescan") {
        if (!ts.used) fail("ps4_turbo_rescan needs a ps4_turbo_scan first");
        const uint8_t ct = ps4_cmptype_arg(args);
        auto data = scan_cmp_needs_value(ct) ? ps4_value_bytes(args, ts.valtype, ct)
                                             : std::vector<uint8_t>{};
        std::vector<uint8_t> mask;
        if (ts.valtype == kValArrBytes && args.contains("mask_hex"))
            mask = hex_decode(args.at("mask_hex").get<std::string>());
        uint32_t flags = ts.flags & (kTsServerResident | kTsFloatSimple | kTsFloatExact |
                                     kTsFloatExponentMask);
        if (ts.flags & kTsUseAliasing) flags |= kTsRescanAliasing;
        if (ts.resident) flags |= kTsServerResident;
        else flags &= ~kTsServerResident;
        runtime::backend_ps4_t::ps4_turbo_result_t res;
        auto io = p.ps4_turbo_count(ts.pid, ts.base, ts.valtype, ct, flags, data, mask,
                                    ts.hits, res);
        if (!io.ok) fail("ps4_turbo_rescan failed (error " + std::to_string(io.error) + ")");
        ts.count = res.count;
        ++ts.passes;
        if (!ts.resident) ts.hits = std::move(res.hits);
        return {{"rescanned", true}, {"pid", ts.pid}, {"pass", ts.passes},
                {"count", ts.count}, {"resident", ts.resident},
                {"results", ps4_turbo_preview(p, ts, 0, limit)},
                {"truncated", ts.count > limit}};
    }

    if (action == "ps4_turbo_scan") {
        runtime::backend_ps4_t::ps4_turbo_caps_t caps;
        if (!p.ps4_turbo_caps(caps).ok)
            fail("payload has no Turbo Scan; use ps4_scan instead");
        runtime::backend_ps4_t::ps4_turbo_start_t req;
        req.pid = ps4_pid_arg(args);
        req.valtype = ps4_valtype_arg(args);
        req.cmptype = args.contains("compare") ? ps4_cmptype_arg(args) : kCmpExact;
        req.alignment = static_cast<uint8_t>(args.value("alignment", 0u));
        if (scan_cmp_needs_value(req.cmptype))
            req.data = ps4_value_bytes(args, req.valtype, req.cmptype);
        if (req.valtype == kValArrBytes && args.contains("mask_hex"))
            req.mask = hex_decode(args.at("mask_hex").get<std::string>());

        const bool unknown = req.cmptype == kCmpUnknown || req.cmptype == kCmpUnknownLow;
        const bool snapshot = args.value("snapshot", unknown && !scan_cmp_needs_value(req.cmptype));
        if (snapshot && !(caps.engines & kTseSnapshot))
            fail("payload does not advertise snapshot scans");
        const bool resident = args.value("resident", true) && (caps.engines & kTseServerResident);
        if (resident) req.flags |= kTsServerResident;
        if (args.value("aliasing", true) && (caps.engines & kTseAliasing)) req.flags |= kTsUseAliasing;
        if (args.value("parallel", true) && (caps.engines & kTseParallelCompare))
            req.flags |= kTsParallelCompare;
        req.flags |= ps4_turbo_float_flags(args, req.valtype, caps.engines);
        if (snapshot) {
            req.flags |= kTsSnapshot;
            if (args.value("keep_first", false) && (caps.engines & kTseSnapshotFirst))
                req.flags |= kTsSnapshotKeepFirst;
            if (args.value("keep_previous", true) && (caps.engines & kTseSnapshotPrevious))
                req.flags |= kTsSnapshotKeepPrevious;
            if (args.value("include_zeros", false)) req.flags |= kTsSnapshotIncludeZeros;
        }

        if (args.contains("regions")) {
            if (!(caps.engines & kTseSnapshotSegments))
                fail("payload does not advertise segmented scans; pass addr+len");
            if (!snapshot && !resident) fail("regions needs a resident or snapshot scan");
            req.segments = ps4_turbo_segments_for(p, req.pid, args.at("regions").get<std::string>());
        } else {
            req.addr = parse_addr(args, "addr");
            req.len = static_cast<uint32_t>(parse_addr(args, "len"));
        }

        runtime::backend_ps4_t::ps4_turbo_result_t res;
        auto io = p.ps4_turbo_start(req, res);
        if (!io.ok) {
            ts = ps4_turbo_session_t{};
            if (io.error == 14)
                fail("ps4_turbo_scan: too many hits for the resident store (256 MiB); "
                     "narrow the range, add a value, or use snapshot:true");
            fail("ps4_turbo_scan failed (error " + std::to_string(io.error) +
                 (p.ps4_authed() ? ")" : "; Turbo Scan needs auth bit 1 - ps4_auth)"));
        }
        if (res.snapshot && !res.snapshot_ok) {
            ts = ps4_turbo_session_t{};
            fail("ps4_turbo_scan: the console could not build the snapshot (out of RAM/disk? "
                 "see ps4_turbo_config)");
        }
        ts = ps4_turbo_session_t{};
        ts.used = true;
        ts.pid = req.pid;
        ts.base = req.segments.empty() ? req.addr : req.segments.front().addr;
        ts.valtype = req.valtype;
        ts.vlen = scan_value_size(req.valtype)
                      ? scan_value_size(req.valtype)
                      : static_cast<uint32_t>(req.data.size());
        ts.flags = req.flags;
        ts.resident = res.resident;
        ts.snapshot = res.snapshot;
        ts.count = res.count;
        ts.passes = 1;
        ts.generation = p.ps4_connection_generation();
        ts.hits = std::move(res.hits);
        json j = {{"first_scan", true}, {"pid", ts.pid}, {"count", ts.count},
                  {"resident", ts.resident}, {"snapshot", ts.snapshot},
                  {"flags", req.flags}, {"segments", req.segments.size()},
                  {"results", ps4_turbo_preview(p, ts, 0, limit)},
                  {"truncated", ts.count > limit},
                  {"note", "narrow with ps4_turbo_rescan {compare, value}; page with "
                           "ps4_turbo_results {start,count}; free with ps4_turbo_end"}};
        if (res.snapshot) {
            j["slots"] = res.slot_count;
            j["bytes"] = res.total_bytes;
        }
        return j;
    }

    if (action == "ps4_write_multi") {
        const uint32_t pid = ps4_pid_arg(args);
        if (!args.contains("writes") || !args.at("writes").is_array() || args.at("writes").empty())
            fail("ps4_write_multi requires writes: [{addr, hex} | {addr, value, value_type}]");
        std::vector<runtime::backend_ps4_t::ps4_write_entry_t> writes;
        for (const auto& w : args.at("writes")) {
            if (!w.is_object()) fail("each write must be an object");
            runtime::backend_ps4_t::ps4_write_entry_t e;
            e.addr = parse_addr(w, "addr");
            if (w.contains("hex")) {
                e.bytes = hex_decode(w.at("hex").get<std::string>());
            } else {
                const uint8_t vt = ps4_valtype_arg(w);
                e.bytes = ps4_value_bytes(w, vt, kCmpExact);
            }
            if (e.bytes.empty()) fail("write at " + addr_hex_str(e.addr) + " has no bytes");
            writes.push_back(std::move(e));
        }
        if (writes.size() > kWriteMultiMaxCount) fail("ps4_write_multi: at most 65535 writes");
        const bool want_status = args.value("status", true);
        std::vector<uint8_t> status;
        auto io = p.ps4_write_multi(pid, writes, want_status, status);
        if (!io.ok) {
            if (io.error == 7) fail("ps4_write_multi: at least one write failed verification");
            fail("ps4_write_multi failed (error " + std::to_string(io.error) +
                 "; needs payload capability 1.0+, have '" + p.ps4_capability_level() + "')");
        }
        json failed = json::array();
        for (size_t i = 0; i < status.size(); ++i) {
            if (status[i] == kWriteStatusOk) continue;
            const char* why = status[i] == kWriteStatusInvalid ? "invalid"
                            : status[i] == kWriteStatusVerifyFailed ? "verify_failed"
                            : status[i] == kWriteStatusRwFailed ? "rw_failed" : "unknown";
            failed.push_back({{"index", i}, {"addr", writes[i].addr},
                              {"addr_hex", addr_hex_str(writes[i].addr)},
                              {"status", status[i]}, {"reason", why}});
        }
        return {{"pid", pid}, {"count", writes.size()}, {"bytes", io.bytes},
                {"ok", failed.empty()}, {"failed", failed},
                {"note", "non-atomic: each entry is written and read back independently"}};
    }

    fail("unknown turbo action");
}

uint64_t* ps4_reg_ptr(runtime::thread_context_t& c, const std::string& n) {
    if (n == "rip") return &c.rip;
    if (n == "rsp") return &c.rsp;
    if (n == "rbp") return &c.rbp;
    if (n == "rax") return &c.rax;
    if (n == "rbx") return &c.rbx;
    if (n == "rcx") return &c.rcx;
    if (n == "rdx") return &c.rdx;
    if (n == "rsi") return &c.rsi;
    if (n == "rdi") return &c.rdi;
    if (n == "r8")  return &c.r8;
    if (n == "r9")  return &c.r9;
    if (n == "r10") return &c.r10;
    if (n == "r11") return &c.r11;
    if (n == "r12") return &c.r12;
    if (n == "r13") return &c.r13;
    if (n == "r14") return &c.r14;
    if (n == "r15") return &c.r15;
    if (n == "flags" || n == "rflags") return &c.flags;
    return nullptr;
}

json tool_debugger_ps4(const std::string& action, const json& args) {
    if (action == "ps4_status") {
        // also answers while the connection is down (connected=false)
        auto* sel = runtime::registry_ps4();
        if (!sel) fail("ps4_status: no console selected (target.ps4_connect {host})");
        return ps4_status_json(*sel);
    }
    auto& p = need_ps4();

    if (action.rfind("ps4_turbo_", 0) == 0 || action == "ps4_write_multi")
        return tool_ps4_turbo(action, args, p);

    if (action == "ps4_modules") {
        const uint32_t pid = ps4_pid_arg(args);
        std::vector<runtime::module_info_t> mods;
        auto io = p.ps4_modules(pid, mods);
        if (!io.ok) {
            if (io.error == 100)
                fail("ps4_modules needs the NetVar1337 ps4debug-NG fork (CMD_PROC_MODULES); "
                     "target.modules works on any payload");
            fail("ps4_modules failed (error " + std::to_string(io.error) + ")");
        }
        json arr = json::array();
        for (const auto& m : mods)
            arr.push_back({{"name", m.name}, {"path", m.path}, {"base", static_cast<uint64_t>(m.base)},
                           {"base_hex", addr_hex_str(m.base)}, {"size", m.size}});
        return {{"pid", pid}, {"count", mods.size()}, {"modules", arr}};
    }
    if (action == "ps4_snapshot") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len = parse_addr(args, "len");
        if (!args.contains("path") || !args.at("path").is_string())
            fail("ps4_snapshot requires output 'path'");
        const std::string path = args.at("path").get<std::string>();
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) fail("cannot create " + path);
        auto io = p.ps4_snapshot(pid, addr, len, [&](const uint8_t* d, size_t n) {
            out.write(reinterpret_cast<const char*>(d), static_cast<std::streamsize>(n));
            return static_cast<bool>(out);
        });
        out.close();
        if (!io.ok) {
            std::remove(path.c_str());
            if (io.error == 100)
                fail("ps4_snapshot needs the NetVar1337 ps4debug-NG fork (CMD_PROC_SNAPSHOT); "
                     "use memory.read or target.ps4_dump_module instead");
            if (io.error == 2)
                fail("ps4_snapshot: range is not fully mapped and readable (target.regions)");
            fail("ps4_snapshot failed after " + std::to_string(io.bytes) + " bytes (error " +
                 std::to_string(io.error) + ")");
        }
        return {{"pid", pid}, {"addr", addr}, {"addr_hex", addr_hex_str(addr)},
                {"bytes", io.bytes}, {"path", path}};
    }
    if (action == "ps4_attach") {
        const uint32_t pid = ps4_pid_arg(args);
        std::string err;
        if (!p.ps4_debug_attach(pid, err)) fail("ps4_attach failed: " + err);
        return {{"attached", true}, {"pid", pid}, {"endpoint", p.endpoint()},
                {"branding", p.branding()}};
    }
    if (action == "ps4_detach") {
        const bool clean = p.ps4_debug_detach();
        return {{"attached", false}, {"detach_acknowledged", clean}};
    }
    if (action == "ps4_console_info") {
        runtime::backend_ps4_t::ps4_console_info_t ci;
        auto io = p.ps4_console_info(ci);
        if (!io.ok) io_fail("ps4_console_info failed", io);
        runtime::backend_ps4_t::ps4_app_info_t app;
        const bool app_ok = p.ps4_foreground_app(app).ok;
        json out = {{"alive", ci.alive}, {"endpoint", ci.endpoint},
                    {"branding", ci.branding}, {"caps", ci.caps},
                    {"server_version", ci.version}, {"fw", ci.fw}, {"fw_bcd", ci.fw_bcd},
                    {"platform", ci.platform == 4 ? "PS4" : std::to_string(ci.platform)},
                    {"authed", ci.authed}, {"debug_pid", ci.debug_pid},
                    {"connection_drops", ci.drops}};
        if (app_ok)
            out["foreground_app"] = {{"pid", app.pid}, {"titleid", app.titleid},
                                     {"contentid", app.contentid}, {"name", app.name},
                                     {"app_ver", app.app_ver}, {"running", app.pid != 0}};
        return out;
    }
    if (action == "ps4_bp_set") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!p.ps4_debug_attached())
            fail("ps4_bp_set requires ps4_attach first");
        const uint32_t want = args.contains("index")
            ? static_cast<uint32_t>(parse_addr(args, "index"))
            : runtime::backend_ps4_t::kAutoSlot;
        uint32_t index = 0;
        bool reused = false;
        auto io = p.ps4_bp_arm(addr, want, index, &reused);
        if (!io.ok) io_fail("ps4_bp_set failed (slot " +
                            (want == runtime::backend_ps4_t::kAutoSlot ? std::string("auto")
                                                                       : std::to_string(want)) + ")", io);
        return {{"set", true}, {"addr", addr}, {"addr_hex", addr_hex_str(addr)},
                {"index", index}, {"hw", false}, {"already_armed", reused}};
    }
    if (action == "ps4_bp_clear") {
        uint64_t addr = 0;
        uint32_t index = 0;
        runtime::io_result_t io;
        if (args.contains("addr")) {
            addr = parse_addr(args, "addr");
            io = p.ps4_bp_disarm_addr(addr, &index);
        } else if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
            io = p.ps4_bp_disarm(index, &addr);
        } else {
            fail("ps4_bp_clear requires addr or index");
        }
        if (!io.ok) io_fail("ps4_bp_clear failed", io);
        return {{"cleared", true}, {"addr", addr}, {"index", index}};
    }
    if (action == "ps4_watch_set") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len = args.contains("len") ? parse_addr(args, "len") : 8;
        const uint32_t type = static_cast<uint32_t>(args.value("type", 3u));   // 3 = read/write
        if (type != 0 && type != 1 && type != 3)
            fail("ps4_watch_set: type must be 0=exec, 1=write or 3=read_write");
        if (len != 1 && len != 2 && len != 4 && len != 8)
            fail("ps4_watch_set: len must be 1, 2, 4 or 8");
        if (!p.ps4_debug_attached())
            fail("ps4_watch_set requires ps4_attach first");
        const uint32_t want = args.contains("index")
            ? static_cast<uint32_t>(parse_addr(args, "index"))
            : runtime::backend_ps4_t::kAutoSlot;
        uint32_t index = 0;
        bool reused = false;
        auto io = p.ps4_wp_arm(addr, static_cast<uint32_t>(len), type, want, index, &reused);
        if (!io.ok) io_fail("ps4_watch_set failed", io);
        return {{"set", true}, {"addr", addr}, {"addr_hex", addr_hex_str(addr)},
                {"index", index}, {"len", len}, {"type", type}, {"hw", true},
                {"already_armed", reused}};
    }
    if (action == "ps4_watch_clear") {
        uint64_t addr = 0;
        uint32_t index = 0;
        runtime::io_result_t io;
        if (args.contains("addr")) {
            addr = parse_addr(args, "addr");
            io = p.ps4_wp_disarm_addr(addr, &index);
        } else if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
            io = p.ps4_wp_disarm(index, &addr);   // fails for a slot we never armed
        } else {
            fail("ps4_watch_clear requires addr or index");
        }
        if (!io.ok) io_fail("ps4_watch_clear failed", io);
        return {{"cleared", true}, {"addr", addr}, {"index", index}};
    }
    if (action == "ps4_continue") {
        const uint32_t stop = static_cast<uint32_t>(args.value("stop", 0u));
        if (stop > 2) fail("ps4_continue: stop must be 0=resume, 1=stop, 2=kill");
        auto io = p.ps4_continue(stop);
        if (!io.ok) io_fail("ps4_continue failed", io);
        return {{"continued", true}, {"stop", stop}};
    }
    if (action == "ps4_step") {
        const uint32_t lwpid = args.contains("lwpid")
            ? static_cast<uint32_t>(parse_addr(args, "lwpid")) : 0;   // 0 = all threads
        auto io = p.ps4_step(lwpid);
        if (!io.ok) io_fail("ps4_step failed", io);
        return {{"stepped", true}, {"lwpid", lwpid}};
    }
    if (action == "ps4_suspend" || action == "ps4_resume") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        auto io = action == "ps4_suspend" ? p.ps4_suspend_thread(lwpid)
                                          : p.ps4_resume_thread(lwpid);
        if (!io.ok) io_fail(action + " failed", io);
        return {{"ok", true}, {"lwpid", lwpid},
                {"suspended", action == "ps4_suspend"}};
    }
    if (action == "ps4_process_stop") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint32_t state = static_cast<uint32_t>(args.value("state", 1u));
        if (state > 2) fail("ps4_process_stop: state must be 0=resume, 1=stop, 2=kill");
        auto io = p.ps4_process_stop(pid, state);
        if (!io.ok) io_fail("ps4_process_stop failed", io);
        return {{"ok", true}, {"pid", pid}, {"state", state}};
    }
    if (action == "ps4_regs") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        runtime::thread_context_t ctx{};
        auto io = p.get_thread_context(lwpid, ctx);
        if (!io.ok) io_fail("ps4_regs failed (thread stopped?)", io);
        json o = ps4_ctx_json(ctx);
        o["lwpid"] = lwpid;
        return o;
    }
    if (action == "ps4_set_reg") {
        if (!args.contains("name") || !args.contains("value"))
            fail("ps4_set_reg requires name and value");
        const std::string name = args.at("name").get<std::string>();
        const uint64_t value = parse_addr(args, "value");
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        runtime::thread_context_t ctx{};
        auto gio = p.get_thread_context(lwpid, ctx);
        if (!gio.ok) io_fail("ps4_set_reg: cannot read regs of lwpid " + std::to_string(lwpid), gio);
        auto* slot = ps4_reg_ptr(ctx, name);
        if (!slot) fail("ps4_set_reg: unknown register '" + name +
                        "' (rax..r15, rip, rsp, rbp, flags)");
        *slot = value;
        auto sio = p.set_thread_context(lwpid, ctx);
        if (!sio.ok) io_fail("ps4_set_reg failed writing lwpid " + std::to_string(lwpid), sio);
        return {{"set", true}, {"lwpid", lwpid}, {"register", name}, {"value", value}};
    }
    if (action == "ps4_dbregs") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        uint64_t dr[16]{};
        auto io = p.ps4_get_dbregs(lwpid, dr);
        if (!io.ok) io_fail("ps4_dbregs failed", io);
        json arr = json::array();
        for (uint64_t d : dr) arr.push_back(d);
        return {{"lwpid", lwpid}, {"dr", arr}};
    }
    if (action == "ps4_wait") {
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        runtime::ps4_event_t ev{};
        if (!p.ps4_wait_event(ev, timeout_ms))
            return {{"halted", false}, {"timeout_ms", timeout_ms},
                    {"pending", p.ps4_pending_events()},
                    {"events_dropped", p.ps4_events_dropped()}};
        json o = ps4_event_json(ev);
        o["halted"] = true;
        o["pending"] = p.ps4_pending_events();
        return o;
    }
    if (action == "ps4_events") {
        const size_t max = std::min<size_t>(args.value("max", 64u), 4096u);
        const bool clear = args.value("clear", true);
        auto evs = p.ps4_drain_events(max, clear);
        json arr = json::array();
        for (const auto& e : evs) arr.push_back(ps4_event_json(e));
        return {{"events", arr}, {"count", arr.size()},
                {"pending", p.ps4_pending_events()},
                {"events_dropped", p.ps4_events_dropped()}};
    }
    if (action == "ps4_callstack") {
        const auto s_hold = need_session();
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        const size_t depth = std::min<size_t>(args.value("depth", 32u), 64u);
        runtime::thread_context_t ctx{};
        auto io = p.get_thread_context(lwpid, ctx);
        if (!io.ok) io_fail("ps4_callstack: cannot read regs of lwpid " + std::to_string(lwpid), io);
        dbg::ps4_debug_target_t t(p, s_hold);
        json arr = frames_json(dbg::rbp_frames(t, ctx, depth));
        return {{"lwpid", lwpid}, {"frames", arr}, {"count", arr.size()}};
    }
    if (action == "ps4_bp_list" || action == "ps4_watch_list") {
        const bool bp = action == "ps4_bp_list";
        json arr = bp ? slots_json(p.ps4_breakpoints(), false) : slots_json(p.ps4_watchpoints(), true);
        return {{bp ? "breakpoints" : "watchpoints", arr},
                {"count", arr.size()},
                {"note", "client-side record of slots armed through this backend (the payload "
                         "has no query command); cleared when the debug session ends, armed="
                         "false while the connection is down (ps4_reconnect re-arms them)"}};
    }
    if (action == "ps4_call") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint32_t pid = ps4_pid_arg(args);
        uint64_t fargs[6]{};
        if (args.contains("args")) {
            const json& a = args.at("args");
            if (!a.is_array() || a.size() > 6)
                fail("ps4_call: args must be an array of at most 6 numbers");
            for (size_t i = 0; i < a.size(); ++i) {
                if (a[i].is_string())
                    fargs[i] = parse_addr(json{{"v", a[i]}}, "v");
                else if (a[i].is_number())
                    fargs[i] = a[i].get<uint64_t>();
                else
                    fail("ps4_call: args[" + std::to_string(i) + "] is not a number");
            }
        }
        uint64_t stub = 0;
        auto iio = p.ps4_install(pid, stub);   // cached per pid by the backend
        if (!iio.ok || stub == 0) io_fail("ps4_call: CMD_PROC_INTALL failed", iio);
        uint64_t rax = 0;
        auto io = p.ps4_call(pid, stub, addr, fargs, rax);
        if (!io.ok) io_fail("ps4_call failed", io);
        return {{"called", true}, {"pid", pid}, {"addr", addr},
                {"rpcstub", stub}, {"rax", rax}};
    }

    // ---- console-side tooling (ps4debug-NG native scan / disasm / elf / console) ----

    if (action == "ps4_auth") {
        std::string aerr;
        const bool ok = p.ps4_auth(0x3, aerr);
        return {{"authed", ok}, {"scan_unlocked", ok},
                {"error", ok ? std::string{} : aerr},
                {"note", "auth is per-connection and runs automatically on "
                         "ps4_connect/ps4_reconnect; bit 1 unlocks the CMD_PROC_SCAN* family"}};
    }

    if (action == "ps4_scan" || action == "ps4_rescan" ||
        action == "ps4_scan_state" || action == "ps4_scan_reset" ||
        action == "ps4_scan_all" || action == "ps4_scan_aob") {
        return tool_ps4_scan(action, args, p);
    }

    if (action == "ps4_disasm") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint64_t addr = parse_addr(args, "addr");
        const uint32_t len = static_cast<uint32_t>(parse_addr(args, "len"));
        const uint32_t max = static_cast<uint32_t>(args.value("max", 4096u));
        std::vector<runtime::backend_ps4_t::ps4_disasm_entry_t> ents;
        bool truncated = false;
        auto io = p.ps4_disasm_region(pid, addr, len, max, ents, &truncated);
        if (!io.ok) io_fail("ps4_disasm failed", io);
        json arr = json::array();
        for (const auto& e : ents) {
            json kinds = json::array();
            if (e.kind & 0x01) kinds.push_back("call");
            if (e.kind & 0x02) kinds.push_back("ret");
            if (e.kind & 0x04) kinds.push_back("jmp");
            if (e.kind & 0x08) kinds.push_back("jcc");
            if (e.kind & 0x10) kinds.push_back("mem");
            if (e.kind & 0x20) kinds.push_back("rip-rel");
            if (e.kind & 0x40) kinds.push_back("read");
            if (e.kind & 0x80) kinds.push_back("write");
            json o = {{"addr", e.addr}, {"addr_hex", addr_hex_str(e.addr)},
                      {"len", e.length}, {"kind", kinds},
                      {"mnemonic_lo", e.mnemonic_lo}};
            if (e.kind & 0x10)
                o["mem"] = {{"base", e.mem_base_reg}, {"index", e.mem_index_reg},
                            {"scale", e.mem_scale}, {"disp", e.mem_disp}};
            if (e.kind & 0x20) {
                o["rip_rel_target"] = e.rip_rel_target;
                o["rip_rel_target_hex"] = addr_hex_str(e.rip_rel_target);
            }
            arr.push_back(o);
        }
        return {{"addr", addr}, {"len", len}, {"count", arr.size()},
                {"instructions", arr}, {"truncated", truncated},
                {"note", "decoded on-console by the payload's Zydis; mnemonic_lo is "
                         "the low byte of the Zydis mnemonic enum - read the code "
                         "bytes with memory.read and disasm.disassemble for full text"}};
    }

    if (action == "ps4_xrefs" || action == "ps4_xrefs_to") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint64_t addr = parse_addr(args, "addr");
        const uint32_t len = static_cast<uint32_t>(parse_addr(args, "len"));
        json arr = json::array();
        bool truncated = false;
        if (action == "ps4_xrefs") {
            const uint32_t max = static_cast<uint32_t>(args.value("max", 1000000u));
            std::vector<uint64_t> targets;
            auto io = p.ps4_extract_xrefs(pid, addr, len, max, targets, &truncated);
            if (!io.ok) io_fail("ps4_xrefs failed", io);
            for (uint64_t t : targets) {
                arr.push_back({{"target", t}, {"target_hex", addr_hex_str(t)}});
            }
            return {{"addr", addr}, {"len", len}, {"count", arr.size()},
                    {"targets", arr}, {"truncated", truncated},
                    {"note", "deduplicated RIP-relative call/branch targets inside the range"}};
        }
        const uint64_t target = parse_addr(args, "target");
        std::vector<uint64_t> addrs;
        auto io = p.ps4_find_xrefs_to(pid, addr, len, target, addrs, &truncated);
        if (!io.ok) io_fail("ps4_xrefs_to failed", io);
        for (uint64_t a : addrs)
            arr.push_back({{"addr", a}, {"addr_hex", addr_hex_str(a)}});
        return {{"addr", addr}, {"len", len}, {"target", target},
                {"target_hex", addr_hex_str(target)}, {"count", arr.size()},
                {"xrefs", arr}, {"truncated", truncated}};
    }

    if (action == "ps4_stack") {
        const uint32_t pid = ps4_pid_arg(args);
        uint32_t lwpid = 0;
        if (args.contains("lwpid")) lwpid = static_cast<uint32_t>(parse_addr(args, "lwpid"));
        else {
            auto thr = p.enum_threads(pid);
            if (!thr.ok || thr.items.empty())
                fail("ps4_stack: cannot list threads (need lwpid): " +
                     runtime::ps4::io_error_str(thr.error));
            lwpid = thr.items.front().tid;
        }
        uint64_t rbp = 0, rsp = 0;
        if (args.contains("rbp")) rbp = parse_addr(args, "rbp");
        if (args.contains("rsp")) rsp = parse_addr(args, "rsp");
        if (rbp == 0 || rsp == 0) {
            runtime::thread_context_t ctx{};
            auto io = p.get_thread_context(lwpid, ctx);
            if (!io.ok) io_fail("ps4_stack: cannot read thread context for lwpid " +
                                std::to_string(lwpid), io);
            if (rbp == 0) rbp = ctx.rbp;
            if (rsp == 0) rsp = ctx.rsp;
        }
        const uint32_t depth = static_cast<uint32_t>(args.value("depth", 16u));
        std::vector<runtime::backend_ps4_t::ps4_stack_frame_t> frames;
        auto io = p.ps4_read_stack(pid, rbp, rsp, depth, frames);
        // a truncated bundle still returns the frames that parsed
        if (!io.ok && frames.empty()) io_fail("ps4_stack failed", io);
        json arr = json::array();
        for (size_t i = 0; i < frames.size(); ++i) {
            const auto& f = frames[i];
            arr.push_back({{"index", i},
                           {"rbp", f.rbp}, {"rsp", f.rsp},
                           {"saved_rbp", f.saved_rbp},
                           {"ret_addr", f.ret_addr},
                           {"ret_addr_hex", addr_hex_str(f.ret_addr)},
                           {"locals_omitted", (f.flags & 1) != 0},
                           {"locals_hex", ps4_hex_str(f.locals)},
                           {"code_hex", ps4_hex_str(f.code)}});
        }
        json out = {{"pid", pid}, {"lwpid", lwpid}, {"rbp", rbp}, {"rsp", rsp},
                    {"count", arr.size()}, {"frames", arr}, {"complete", io.ok},
                    {"note", "server-side rbp-chain walk on the console; code is the "
                             "200-byte window at ret_addr-10"}};
        if (!io.ok) out["warning"] = "the payload's frame bundle was truncated: " +
                                     runtime::ps4::io_error_str(io.error);
        return out;
    }

    if (action == "ps4_assemble") {
        if (!args.contains("asm") || !args.at("asm").is_string())
            fail("ps4_assemble requires 'asm' (x86-64 text, Intel syntax by default)");
        const std::string text = args.at("asm").get<std::string>();
        const uint64_t base = args.contains("base") ? parse_addr(args, "base") : 0;
        const uint32_t syntax = static_cast<uint32_t>(args.value("syntax", 0u));
        std::vector<uint8_t> bytes;
        uint32_t count = 0;
        std::string aerr;
        auto io = p.ps4_assemble(base, syntax, text, bytes, count, aerr);
        if (!io.ok)
            fail("ps4_assemble failed: " +
                 (aerr.empty() ? runtime::ps4::io_error_str(io.error) : aerr));
        return {{"assembled", true}, {"bytes_hex", ps4_hex_str(bytes)},
                {"byte_len", bytes.size()}, {"insn_count", count},
                {"note", "assembled on-console by the payload's Keystone; patch with "
                         "memory.write (ps4debug-NG writes are unauthenticated)"}};
    }

    if (action == "ps4_elf_rpc" || action == "ps4_elf_load") {
        const uint32_t pid = ps4_pid_arg(args);
        if (!args.contains("path") || !args.at("path").is_string())
            fail("ps4_elf_* requires 'path' to a local ELF file");
        const std::string path = args.at("path").get<std::string>();
        std::ifstream f(path, std::ios::binary);
        if (!f) fail("cannot open " + path);
        std::vector<uint8_t> elf((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
        if (elf.size() < 4 || std::memcmp(elf.data(), "\x7f""ELF", 4) != 0)
            fail("not an ELF file (PS4 payloads must be raw ELF64, not SELF)");
        if (action == "ps4_elf_rpc") {
            uint64_t entry = 0;
            auto io = p.ps4_elf_rpc(pid, elf, entry);
            if (!io.ok) io_fail("ps4_elf_rpc failed", io);
            return {{"loaded", true}, {"pid", pid}, {"entry", entry},
                    {"entry_hex", addr_hex_str(entry)},
                    {"note", "ELF loaded+relocated in the console process; call its "
                             "entry with ps4_call or run it with ps4_elf_load"}};
        }
        auto io = p.ps4_elf_load(pid, elf);
        if (!io.ok) io_fail("ps4_elf_load failed", io);
        return {{"executed", true}, {"pid", pid},
                {"note", "the payload jumped into the ELF entry point"}};
    }

    if (action == "ps4_notify" || action == "ps4_print") {
        if (!args.contains("msg") || !args.at("msg").is_string())
            fail("ps4_notify/ps4_print requires 'msg'");
        const std::string msg = args.at("msg").get<std::string>();
        if (action == "ps4_notify") {
            const uint32_t type = static_cast<uint32_t>(args.value("type", 222u));
            auto io = p.ps4_console_notify(type, msg);
            if (!io.ok) io_fail("ps4_notify failed", io);
            return {{"notified", true}, {"type", type},
                    {"note", "system notification shown on the PS4 UI"}};
        }
        auto io = p.ps4_console_print(msg);
        if (!io.ok) io_fail("ps4_print failed", io);
        return {{"printed", true}, {"note", "written to the console kernel log ([ps4debug-ng] prefix in dmesg)"}};
    }

    if (action == "ps4_app") {
        runtime::backend_ps4_t::ps4_app_info_t app;
        auto io = p.ps4_foreground_app(app);
        if (!io.ok) io_fail("ps4_app failed", io);
        return {{"pid", app.pid}, {"titleid", app.titleid}, {"contentid", app.contentid},
                {"name", app.name}, {"app_ver", app.app_ver},
                {"running", app.pid != 0}};
    }

    if (action == "ps4_fpregs" || action == "ps4_set_fpregs" ||
        action == "ps4_set_dbregs" || action == "ps4_fsgs" || action == "ps4_set_fsgs") {
        if (!p.ps4_debug_attached())
            fail("ps4 register actions require ps4_attach first");
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        if (action == "ps4_fpregs") {
            uint8_t buf[runtime::ps4::kFpregsSize]{};
            auto io = p.ps4_get_fpregs(lwpid, buf);
            if (!io.ok) io_fail("ps4_fpregs failed", io);
            return {{"lwpid", lwpid}, {"hex", ps4_hex_str(buf, sizeof(buf))},
                    {"size", sizeof(buf)}};
        }
        if (action == "ps4_set_fpregs" || action == "ps4_set_dbregs") {
            if (!args.contains("hex") || !args.at("hex").is_string())
                fail("ps4_set_fpregs/ps4_set_dbregs requires 'hex'");
            auto bytes = hex_decode(args.at("hex").get<std::string>());
            if (action == "ps4_set_fpregs") {
                if (bytes.empty() || bytes.size() > 848)
                    fail("ps4_set_fpregs: hex must decode to 1..848 bytes");
                auto io = p.ps4_set_fpregs(lwpid, bytes.data(),
                                           static_cast<uint32_t>(bytes.size()));
                if (!io.ok) io_fail("ps4_set_fpregs failed", io);
            } else {
                if (bytes.size() != runtime::ps4::kDbregsSize)
                    fail("ps4_set_dbregs: hex must decode to exactly 128 bytes");
                auto io = p.ps4_set_dbregs(lwpid, bytes.data());
                if (!io.ok) io_fail("ps4_set_dbregs failed", io);
            }
            return {{"ok", true}, {"lwpid", lwpid}};
        }
        if (action == "ps4_fsgs") {
            uint64_t fs = 0, gs = 0;
            auto io = p.ps4_get_fsgsbase(lwpid, fs, gs);
            if (!io.ok) io_fail("ps4_fsgs failed", io);
            return {{"lwpid", lwpid}, {"fs_base", fs}, {"fs_base_hex", addr_hex_str(fs)},
                    {"gs_base", gs}, {"gs_base_hex", addr_hex_str(gs)}};
        }
        const uint64_t fs = parse_addr(args, "fs_base");
        const uint64_t gs = parse_addr(args, "gs_base");
        auto io = p.ps4_set_fsgsbase(lwpid, fs, gs);
        if (!io.ok) io_fail("ps4_set_fsgs failed", io);
        return {{"ok", true}, {"lwpid", lwpid}, {"fs_base", fs}, {"gs_base", gs}};
    }

    fail("debugger: unknown ps4 action (ps4_attach|ps4_detach|ps4_status|ps4_console_info|"
         "ps4_bp_set|ps4_bp_clear|ps4_bp_list|ps4_watch_set|ps4_watch_clear|"
         "ps4_watch_list|ps4_continue|ps4_step|ps4_suspend|ps4_resume|"
         "ps4_process_stop|ps4_regs|ps4_set_reg|ps4_dbregs|ps4_wait|"
         "ps4_events|ps4_callstack|ps4_call|ps4_until|ps4_find_write|"
         "ps4_trace_calls|ps4_trace_steps|ps4_auth|ps4_scan|ps4_rescan|"
         "ps4_scan_state|ps4_scan_reset|ps4_scan_all|ps4_scan_aob|"
         "ps4_disasm|ps4_xrefs|ps4_xrefs_to|ps4_stack|ps4_assemble|"
         "ps4_elf_rpc|ps4_elf_load|ps4_notify|ps4_print|ps4_app|"
         "ps4_fpregs|ps4_set_fpregs|ps4_set_dbregs|ps4_fsgs|ps4_set_fsgs)");
}

bool is_composite(const std::string& action) {
    return action == "ps4_until" || action == "ps4_find_write" ||
           action == "ps4_trace_calls" || action == "ps4_trace_steps";
}

} // namespace


// tool: debugger

json tool_debugger(const json& args) {
    const std::string action = require_action(args);
    // the composite flows run on the console debugger, or on the local
    // Win32 debugger when the attached session is a local test-lab process
    if (is_composite(action)) return tool_debugger_composite(action, args);
    if (action == "ps4_detach" && !runtime::registry_ps4()) {
        // local debugger session (composites on a test-lab process)
        auto& d = local_debugger();
        const bool was = d.attached();
        d.detach();
        return {{"attached", false}, {"debugger", "user"}, {"was_attached", was}};
    }
    if (action.rfind("ps4_", 0) == 0) {
        // append the console's own status word (CMD_ERR_* from the
        // NetVar1337 fork, CMD_DATA_NULL, ...) to failures so callers see
        // why, and say when the payload dropped and the backend reconnected
        auto* p4 = runtime::registry_ps4();
        uint64_t gen = 0;
        if (p4) {
            p4->ps4_take_last_status();
            gen = p4->ps4_connection_generation();
        }
        try {
            return tool_debugger_ps4(action, args);
        } catch (const std::runtime_error& ex) {
            std::string msg = ex.what();
            if (p4) {
                if (const char* n = runtime::ps4::status_name(p4->ps4_take_last_status()); n[0])
                    msg += std::string(" [console: ") + n + "]";
                if (p4->ps4_connection_generation() != gen)
                    msg += " [the console dropped the connection; reconnected - debug and "
                           "turbo scan sessions were reset]";
            }
            throw std::runtime_error(msg);
        }
    }
    if (action == "status") {
        auto* p = runtime::registry_ps4();
        json out;
        out["backend"]        = runtime::active_badge();
        out["ps4_connected"]  = p ? p->connected() : false;
        out["ps4_lost"]       = p ? p->lost() : false;
        out["debug_attached"] = p ? p->ps4_debug_attached() : false;
        out["debug_pid"]      = p ? p->ps4_debug_pid() : 0;
        out["pending_events"] = p ? static_cast<uint64_t>(p->ps4_pending_events()) : 0;
        out["events_dropped"] = p ? p->ps4_events_dropped() : 0;
        out["fw"]             = p ? p->fw_string() : std::string{};
        auto& d = local_debugger();
        out["local_debugger"] = {{"attached", d.attached()}, {"pid", d.pid()},
                                 {"stopped", d.stopped()}};
        out["note"] = "PS4 toolkit: live debugging is remote over ps4debug-NG - use ps4_* actions "
                      "(ps4_attach, ps4_bp_set, ps4_continue, ps4_until, ps4_find_write, "
                      "ps4_trace_calls, ps4_trace_steps, ps4_regs, ps4_call, ps4_wait, ps4_events); "
                      "the four composite flows also run on a local test-lab process; playbooks: guide list";
        return out;
    }
    fail("debugger: use ps4_* actions (see guide get ps4_setup); the composite flows "
         "ps4_until/ps4_find_write/ps4_trace_calls/ps4_trace_steps also run on a local "
         "test-lab process");
}

} // namespace slop::core::mcp::detail
