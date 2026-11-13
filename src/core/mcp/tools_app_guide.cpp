// src/core/mcp/tools_app_guide.cpp
// tools: app (ui-only plumbing on /api) and guide

#include "core/mcp/tools_common.hpp"

#include "core/infra/lifecycle.hpp"
#include "core/infra/mcp_onboard.hpp"

namespace slop::core::mcp::detail {

namespace {

// tool: app
// app plumbing for the ui, stays off tools/list and lives on /api only

const int64_t g_app_start_ms = infra::steady_ms();

const char* diag_level_name(infra::diag::level_t l) noexcept {
    switch (l) {
    case infra::diag::level_t::trace: return "trace";
    case infra::diag::level_t::info:  return "info";
    case infra::diag::level_t::warn:  return "warn";
    case infra::diag::level_t::error: return "error";
    }
    return "?";
}

// typed keys the engine reads; anything else is stored as given
void validate_setting(const std::string& key, const json& v) {
    if (key.empty()) fail("app.settings_set: missing key");
    if (key == "mcp_token")
        fail("app.settings_set: mcp_token is not settable, use app.rotate_token");
    if (v.is_null()) return;   // erase
    if (key == "mcp_enabled" || key == "mcp_onboarded" || key == "script_unsafe" ||
        key == "web_allow_private") {
        if (!v.is_boolean()) fail("app.settings_set: " + key + " must be a boolean");
    } else if (key == "mcp_port") {
        if (!v.is_number_integer() || v.get<int64_t>() < 1 || v.get<int64_t>() > 65535)
            fail("app.settings_set: mcp_port must be an integer in 1..65535");
    } else if (key == "web_allowlist") {
        if (!v.is_array()) fail("app.settings_set: web_allowlist must be an array of strings");
        for (const auto& e : v)
            if (!e.is_string()) fail("app.settings_set: web_allowlist must be an array of strings");
    } else if (key == "proxy_token") {
        if (!v.is_string()) fail("app.settings_set: proxy_token must be a string");
    }
}

json redacted_settings() {
    json s = infra::settings::snapshot();
    const std::string tok = s.value("mcp_token", std::string{});
    s["mcp_token"] = tok.empty() ? "unset" : "set";
    if (s.contains("proxy_token") && s.at("proxy_token").is_string())
        s["proxy_token"] = s.at("proxy_token").get_ref<const std::string&>().empty() ? "unset" : "set";
    return s;
}

} // namespace


json tool_app(const json& args) {
    const std::string action = require_action(args);

    if (action == "status" || action == "ping") {
        json out = app_state_unlocked();
        out["uptime_ms"]   = infra::steady_ms() - g_app_start_ms;
        out["mcp"]         = {{"running", running()}, {"port", port()}};
        out["subscribers"] = infra::event_bus::subscriber_count();
        out["output_revision"] = infra::event_bus::output_revision();
        out["diag_revision"]   = infra::diag::revision();
        out["watch_entries"]   = memory::watch::size();
        out["quit_requested"]  = infra::app_control::quit_requested();
        return out;
    }

    if (action == "output") {
        const uint64_t since = args.value("since", uint64_t{0});
        auto lines = infra::event_bus::output_since(since);
        json arr = json::array();
        for (const auto& l : lines)
            arr.push_back({{"seq", l.seq}, {"ms", l.ms}, {"text", l.text}});
        return {{"revision", infra::event_bus::output_revision()},
                {"count", arr.size()},
                {"lines", std::move(arr)}};
    }

    if (action == "output_clear") {
        infra::event_bus::output_clear();
        return {{"ok", true}};
    }

    if (action == "log") {
        const std::string text = args.value("text", std::string{});
        if (text.empty()) fail("app.log: missing text");
        infra::event_bus::output(text);
        return {{"ok", true}, {"revision", infra::event_bus::output_revision()}};
    }

    if (action == "diag") {
        const uint64_t since = args.value("since_revision", uint64_t{0});
        const size_t   limit = std::min<size_t>(args.value("limit", size_t{2000}), 8192);
        auto snap = infra::diag::snapshot(since, limit);
        json arr = json::array();
        const size_t begin = snap.entries.size() > limit ? snap.entries.size() - limit : 0;
        for (size_t i = begin; i < snap.entries.size(); ++i) {
            const auto& e = snap.entries[i];
            arr.push_back({{"ms", e.timestamp_ms},
                           {"level", diag_level_name(e.level)},
                           {"tag", e.tag},
                           {"message", e.message}});
        }
        return {{"revision", snap.revision},
                {"count", arr.size()},
                {"entries", std::move(arr)}};
    }

    if (action == "shutdown") {
        infra::app_control::request_quit(
            args.value("reason", std::string{"front end requested shutdown"}));
        return {{"ok", true}, {"reason", infra::app_control::quit_reason()}};
    }

    if (action == "settings_get") return redacted_settings();

    if (action == "settings_set") {
        const std::string key = args.value("key", std::string{});
        const json value = args.contains("value") ? args.at("value") : json(nullptr);
        validate_setting(key, value);
        if (!infra::settings::set(key, value))
            fail("app.settings_set: could not write " + infra::settings::file());
        json out = {{"ok", true}, {"key", key}, {"value", value}};
        if (key == "mcp_port" || key == "mcp_enabled") out["restart_required"] = true;
        if (key == "proxy_token" && value.is_string()) out["value"] = "set";
        return out;
    }

    if (action == "events_ticket") return {{"ticket", issue_events_ticket()}, {"ttl_ms", 60000}};

    if (action == "rotate_token") {
        // the in-flight request already passed auth, so its response still arrives;
        // every later request needs the new token (the per-launch SLOP_MCP_TOKEN
        // supervisor token is unaffected). The Tauri supervisor and the UI use a
        // per-launch extra token, so rotation must stay available to it; the new
        // bearer is returned only in this response and never via settings_get.
        const bool caller_primary = request_used_primary_token();
        const std::string tok = infra::settings::generate_token();
        if (tok.empty()) fail("app.rotate_token: random generator failed");
        if (!infra::settings::set("mcp_token", tok))
            fail("app.rotate_token: could not write " + infra::settings::file());
        set_primary_token(tok);
        infra::lifecycle::refresh_endpoint();
        json updated = json::array();
        for (const auto& r : infra::mcp_onboard::refresh_existing(port(), tok))
            if (r.installed) updated.push_back(r.client);
        return {{"rotated", true},
                {"token", tok},   // shown once; never readable via settings_get
                {"caller_must_switch", caller_primary},
                {"clients_updated", std::move(updated)}};
    }

    if (action == "register_token") {
        if (!request_used_primary_token())
            fail("app.register_token: requires the primary bearer token");
        const std::string tok = args.value("token", std::string{});
        if (tok.size() < 32) fail("app.register_token: token must be at least 32 characters");
        add_extra_token(tok);
        return {{"ok", true}};
    }
    fail("app: unknown action");
    return {};
}


// tool: guide — task-oriented recipes so an agent (or user) can drive whole
// game-RE workflows instead of discovering tool combinations one by one

json tool_guide(const json& args) {
    struct step_t { const char* tool; const char* action; const char* params; const char* why; };
    struct topic_t {
        const char* id; const char* title; const char* summary;
        std::vector<step_t> steps;
    };
    static const std::vector<topic_t> kTopics = {
        {"ps4_setup", "Connect to a PS4 and start debugging the game in one call",
         "ps4_auto connects, finds the game process (the one with /app0/ modules), attaches a session and the ps4debug debugger, and returns modules+threads. Everything else (memory, disasm, debugger ps4_*) then works against the console.",
         {{"target", "ps4_auto", R"({"host":"192.168.1.50"})", "one-call console setup: connect + pick game + attach + debug attach"},
          {"target", "modules", "{}", "see the game's modules and runtime bases"},
          {"target", "threads", "{}", "lwpids for ps4_regs/ps4_step"},
          {"debugger", "ps4_status", "{}", "confirm the debug session"}}},
        {"ps4_breakpoint", "Break at an address on the PS4 and inspect the stop",
         "Arm a software breakpoint, continue, wait for the 0x4A0 event on port 755, then read registers and the callstack. ps4_until does all of it in one call.",
         {{"debugger", "ps4_bp_set", R"({"addr":4198912})", "arm INT3 bp (index auto-allocated)"},
          {"debugger", "ps4_continue", R"({"stop":0})", "resume the debuggee"},
          {"debugger", "ps4_wait", R"({"timeout_ms":10000})", "block for the stop event (rip/regs/signal)"},
          {"debugger", "ps4_regs", R"({"lwpid":101})", "full register set of the stopped thread"},
          {"debugger", "ps4_callstack", R"({"lwpid":101})", "rbp frame chain via live reads"},
          {"debugger", "ps4_bp_clear", R"({"addr":4198912})", "remove the bp"},
          {"debugger", "ps4_until", R"({"addr":4198912,"timeout_ms":30000})", "all of the above in one call"}}},
        {"ps4_api_trace", "Log every call to a function/import on the PS4 (args in, hit count)",
         "ps4_trace_calls arms a bp, then loops continue+wait and records rdi/rsi/rdx/rcx/r8/r9 at every hit. Use it on an import stub or any function entry to see who calls it with what.",
         {{"debugger", "ps4_trace_calls", R"({"addr":4202496,"count":200,"timeout_ms":5000})", "returns hits[] with rip + 6 arg registers per hit"},
          {"debugger", "ps4_bp_list", "{}", "see armed slots"},
          {"disasm", "disassemble", R"({"addr":4202496,"count":8})", "what the traced code looks like (live memory)"}}},
        {"ps4_find_write", "Find what code writes to an address on the PS4",
         "ps4_find_write arms a hardware write watchpoint (DR slot), continues, and on the trap returns the event plus the callstack of the writer — the answer to 'who changed this value'.",
         {{"debugger", "ps4_find_write", R"({"addr":2147483648,"len":8,"timeout_ms":30000})", "watchpoint + continue + wait + callstack in one call"},
          {"debugger", "ps4_callstack", R"({"lwpid":101})", "walk frames yourself"},
          {"debugger", "ps4_bp_set", R"({"addr":4198912})", "then break on the writer"}}},
        {"ps4_step_trace", "Single-step execution trace on the PS4",
         "ps4_trace_steps loops step+wait and records rip plus the disassembled instruction at each step — a console-side equivalent of local trace_run.",
         {{"debugger", "ps4_trace_steps", R"({"lwpid":101,"count":64,"timeout_ms":5000})", "steps[] with rip + insn text"},
          {"debugger", "ps4_step", R"({"lwpid":101})", "manual single step"},
          {"debugger", "ps4_wait", R"({"timeout_ms":3000})", "catch the step event"}}},
        {"ps4_remote_call", "Call any function in the console process and get rax back",
         "ps4_call installs the payload RPC stub once per process (CMD_PROC_INTALL) and calls addr with up to 6 args (rdi,rsi,rdx,rcx,r8,r9). Use it to invoke game functions, resolve exports via module base + offset, or run shellcode you wrote with memory.write+alloc.",
         {{"memory", "alloc", R"({"len":4096,"prot":64})", "RWX page on the console for shellcode"},
          {"memory", "write", R"({"addr":<alloc>,"hex":"..."})", "write shellcode"},
          {"debugger", "ps4_call", R"({"addr":<alloc>,"args":[1,2,3,0,0,0]})", "execute it, get rax"},
          {"memory", "read", R"({"addr":<alloc>+0x100,"len":16})", "read results the callee wrote"}}},
        {"find_health", "Find a game's health/ammo value in live memory (CE workflow)",
         "Classic Cheat-Engine flow: snapshot, change the value in-game, rescan for changed/decreased, narrow, then watch the address to find the code that writes it.",
         {{"memory", "snapshot", R"({"label":"before"})", "baseline all committed memory"},
          {"memory", "scan", R"({"kind":"exact","width":"u32","value":100})", "initial scan for the known value"},
          {"memory", "scan", R"({"kind":"decreased","width":"u32"})", "after taking damage, rescan narrowed set"},
          {"memory", "rescan", R"({"kind":"exact","width":"u32","value":87})", "pin the exact value"},
          {"memory", "watch_add", R"({"addr":<hit>,"width":"u32"})", "watch the address"},
          {"debugger", "ps4_watch_set", R"({"addr":<hit>,"type":1,"len":4})", "hardware DR watchpoint on the PS4; ps4_find_write returns the stop event plus the writer callstack"},
          {"debugger", "ps4_find_write", R"({"addr":<hit>})", "on PS4: watchpoint -> stop event + writer callstack in one call"}}},
        {"find_damage_source", "Find the function that applies damage",
         "Watch the health address for writes while attacking, then break on the writer and walk up the callstack to the damage logic.",
         {{"memory", "watch_add", R"({"addr":<health>,"width":"i32","freeze":false})", "track value changes over the wire"},
          {"debugger", "ps4_find_write", R"({"addr":<health>})", "watchpoint -> stop event + writer callstack in one call"},
          {"debugger", "ps4_bp_set", R"({"addr":<writer>})", "then break on the writer"},
          {"debugger", "ps4_continue", "{}", "resume on the console"},
          {"debugger", "ps4_wait", R"({"timeout_ms":60000})", "wait for the hit"},
          {"debugger", "ps4_callstack", R"({"lwpid":101})", "full stack at the hit"}}},
        {"pointer_chain", "Follow a pointer chain from a static/global to a live object",
         "pointerscan walks static roots and reads pointer chains out of live memory, returning the address path for each hit.",
         {{"memory", "pointerscan", R"({"target":<value>,"depth":5,"max_results":32})", "find chains ending at the value"},
          {"memory", "read", R"({"addr":<root>,"len":8,"format":"u64"})", "re-verify each hop"},
          {"types", "format_at", R"({"addr":<object>,"name":"<struct>"})", "render the object with a declared struct"}}},
        {"runtime_decrypt", "Catch string decryption at runtime instead of reversing the routine",
         "Games decrypt strings in place. Scan for the encrypted blob, watch the decrypted buffer region for a write, break on the writer, read the plaintext.",
         {{"memory", "aob", R"({"pattern":"48 8d 0d ?? ?? ?? ?? e8"})", "find lea+call sites referencing the blob"},
          {"memory", "watch_add", R"({"addr":<buffer>,"len":64,"width":"u8"})", "watch the destination buffer"},
          {"debugger", "ps4_trace_calls", R"({"addr":<decrypt_call>,"count":64})", "log every call to the decrypt routine with its args"},
          {"debugger", "ps4_bp_set", R"({"addr":<decrypt_call>})", "or a plain stop at the call"},
          {"debugger", "ps4_wait", "{}", "wait for the hit on the console"},
          {"memory", "read", R"({"addr":<buffer>,"len":64,"format":"utf8"})", "plaintext after the call"},
          {"patch", "decode_strings", R"({"addr":<func>})", "or statically decode in the loaded image"}}},
        {"ps4_api_monitor", "Monitor calls to any function on the PS4 (args in, hit count)",
         "Arm a breakpoint on the function entry / import stub, then loop continue+wait recording registers at every hit. ps4_trace_calls runs the whole loop in one call.",
         {{"target", "ps4_auto", R"({"host":"192.168.1.50"})", "connect + pick game + attach + debug attach"},
          {"target", "modules", "{}", "find the module base on the console"},
          {"debugger", "ps4_trace_calls", R"({"addr":<thunk>,"count":500,"timeout_ms":10000})", "hits[] with rip + rdi/rsi/rdx/rcx/r8/r9 per hit"},
          {"debugger", "ps4_bp_set", R"({"addr":<thunk>})", "or arm a manual bp"},
          {"debugger", "ps4_continue", "{}", "run"},
          {"debugger", "ps4_wait", R"({"timeout_ms":30000})", "until next stop"},
          {"debugger", "ps4_regs", R"({"lwpid":101})", "x86-64 args at the stop"}}},
        {"snapshot_diff", "See exactly what memory a game action changed",
         "snapshot before, do the action, diff the two snapshots — every changed byte with old/new values.",
         {{"memory", "snapshot", R"({"label":"a"})", "before"},
          {"memory", "snapshot", R"({"label":"b"})", "after the action"},
          {"memory", "diff", R"({"a":<id_a>,"b":<id_b>})", "changed ranges with old/new"}}},
        {"emulate_function", "Emulate a function offline with stubbed imports",
         "emulate.run executes target_addr code in Unicorn with page-in from the live source (console memory on PS4), trace and taint. The ABI is picked automatically: PS4 targets / ELF images run SysV (args rdi..r9, FreeBSD TCB at fs, syscall log with PS4 names); PE / local targets run win64 with TEB/PEB and IAT stubs returning api_ret/api_returns. Ideal for crypto, checksum, decrypt routines.",
         {{"target", "ps4_auto", R"({"host":"192.168.1.50"})", "so target_addr reads live console memory"},
          {"debugger", "ps4_regs", R"({"lwpid":101})", "grab live regs from the console first"},
          {"emulate", "run", R"({"target_addr":4202496,"code_len":256,"regs":{"rdi":1234},"trace":true,"trace_max":128})", "run the slice against live console memory"},
          {"emulate", "run", R"({"hex":"...","count":100000,"until":<ret_addr>})", "or raw bytes"}}},
        {"devirt_cflow", "Recover a flattened/obfuscated control flow",
         "xray.cff finds the dispatcher and state blocks; devirt.recover_cfg rebuilds the CFG; decomp then shows readable code.",
         {{"disasm", "functions", R"({"limit":200})", "find suspicious functions"},
          {"xray", "cff", R"({"addr":<func>})", "dispatcher + state_blocks"},
          {"devirt", "recover_cfg", R"({"addr":<func>})", "rebuild the CFG"},
          {"decomp", "function", R"({"function_va":<func>})", "decompile after recovery"}}},
        {"ps4_unpack_runtime", "Dump the unpacked game from the PS4 after it unpacks in memory",
         "Packed code unpacks itself at runtime on the console: break at the OEP (entry entropy spike), then read the whole module range over the wire and save it on the host for static analysis.",
         {{"target", "modules", "{}", "game module base + size on the console"},
          {"debugger", "ps4_bp_set", R"({"addr":<oep>})", "break at the unpacked entry"},
          {"debugger", "ps4_continue", "{}", "let it unpack"},
          {"debugger", "ps4_wait", R"({"timeout_ms":60000})", "wait for the OEP hit"},
          {"memory", "read", R"({"addr":<image_base>,"len":<module_size>,"format":"hex"})", "pull the unpacked image over the ps4debug wire"},
          {"fs", "write_file", R"({"path":"unpacked.bin","hex":"<hex>"})", "save it on the host"},
          {"analyze", "packer", R"({"path":"unpacked.bin"})", "verify it is unpacked now"}}},
        {"ps4_hw_watchpoints", "Hardware watchpoints on the PS4 without modifying code",
         "ps4debug programs the DR0-DR3 registers on the console, so watchpoints catch execution/reads/writes with no INT3 byte in memory - invisible to in-game integrity scans.",
         {{"debugger", "ps4_watch_set", R"({"addr":<addr>,"type":0,"len":8})", "type 0=exec 1=write 3=rdwr, len 1/2/4/8"},
          {"debugger", "ps4_continue", "{}", "go"},
          {"debugger", "ps4_wait", R"({"timeout_ms":30000})", "wait for the DR trap"},
          {"debugger", "ps4_watch_list", "{}", "armed slots"},
          {"debugger", "ps4_watch_clear", R"({"addr":<addr>})", "release the slot"}}},
        {"ps4_native_scan", "On-console value scan (Cheat-Engine flow running on the PS4 itself)",
         "ps4debug-NG's scan family runs inside the payload (auth bit unlocked automatically by ps4_auth), so scans read game memory through the kernel, not over TCP per byte. ps4_scan seeds a range, ps4_rescan narrows with changed/decreased/exact..., ps4_scan_aob finds byte patterns with ?? wildcards, ps4_scan_all scans all readable maps.",
         {{"debugger", "ps4_auth", "{}", "confirm the scan family is unlocked (runs on connect too)"},
          {"debugger", "ps4_scan", R"({"addr":<region>,"len":<size>,"value_type":"u32","compare":"exact","value":100})", "first scan over a range (regions via target.regions)"},
          {"debugger", "ps4_scan_state", "{}", "current hit set (addr+value hex)"},
          {"debugger", "ps4_rescan", R"({"compare":"decreased"})", "narrow after the value changed in-game"},
          {"debugger", "ps4_rescan", R"({"compare":"exact","value":87})", "pin it down"},
          {"debugger", "ps4_scan_aob", R"({"addr":<module base>,"len":<size>,"pattern":"48 8B ?? ?? 90"})", "find code by byte pattern"},
          {"debugger", "ps4_find_write", R"({"addr":<hit>})", "hardware watchpoint on the value -> writer callstack"},
          {"memory", "read", R"({"addr":<hit>,"len":8,"format":"u64"})", "verify the hit over the wire"},
          {"debugger", "ps4_scan_reset", "{}", "drop the scan session"}}},
        {"ps4_turbo_scan", "Fast on-console value scan with server-resident results (Turbo Scan)",
         "ps4debug-NG's Turbo Scan keeps survivors on the console between passes (no hit lists over TCP), reads memory through a page-table aliasing path with SIMD/parallel compares, and supports snapshot scans for unknown initial values. Prefer it over ps4_scan when ps4_turbo_caps reports supported:true.",
         {{"debugger", "ps4_turbo_caps", "{}", "check the payload advertises Turbo Scan and which engines"},
          {"debugger", "ps4_turbo_regions", "{}", "optional: spot uncached/slow regions"},
          {"debugger", "ps4_turbo_scan", R"({"regions":"writable","value_type":"u32","compare":"exact","value":100})", "known value: scan every writable map at once"},
          {"debugger", "ps4_turbo_scan", R"({"regions":"writable","value_type":"f32","compare":"unknown","keep_first":true})", "unknown value: snapshot instead (no seed)"},
          {"debugger", "ps4_turbo_rescan", R"({"compare":"decreased"})", "narrow server-side after the value changed in-game"},
          {"debugger", "ps4_turbo_rescan", R"({"compare":"exact","value":87})", "pin it down"},
          {"debugger", "ps4_turbo_results", R"({"start":0,"count":100})", "page through survivors (current/previous/first values)"},
          {"debugger", "ps4_write_multi", R"({"writes":[{"addr":<hit>,"value":999,"value_type":"u32"}]})", "poke one or many hits in a single verified round-trip"},
          {"debugger", "ps4_turbo_end", "{}", "free the console-side session"}}},
        {"ps4_dump_and_analyze", "Dump a game module from the PS4 and analyze it statically",
         "ps4_dump_module reads the module's whole mapped range over ps4debug-NG and writes the raw image; ELF dumps load straight into the disasm engine (functions, xrefs, strings) with VAs matching the live console.",
         {{"target", "ps4_dump_module", R"({"name":"eboot.bin","path":"C:/dumps/eboot.bin","load":true})", "dump + load into disasm"},
          {"target", "modules", "{}", "module bases/sizes (ASLR runtime VAs)"},
          {"disasm", "functions", R"({"limit":100})", "function index of the dumped ELF"},
          {"disasm", "xrefs", R"({"from":<va>})", "who references an address"},
          {"debugger", "ps4_disasm", R"({"addr":<va>,"len":256,"max":64})", "or disassemble live on-console (payload Zydis)"},
          {"debugger", "ps4_xrefs_to", R"({"addr":<module base>,"len":<size>,"target":<va>})", "find all callers of a function in live memory"},
          {"debugger", "ps4_assemble", R"({"asm":"mov rax, 1; ret"})", "assemble a patch on-console (Keystone)"},
          {"memory", "write", R"({"addr":<va>,"hex":"<assembled bytes>"})", "apply the patch live"}}},
    };

    const std::string action = require_action(args);
    if (action == "list") {
        json arr = json::array();
        for (const auto& t : kTopics)
            arr.push_back({{"topic", t.id}, {"title", t.title}, {"summary", t.summary}});
        return {{"topics", arr}, {"count", arr.size()},
                {"note", "call guide get {topic:<id>} for the exact tool-call sequence"}};
    }
    if (action == "get") {
        if (!args.contains("topic") || !args.at("topic").is_string())
            fail("guide get requires 'topic' (see guide list)");
        const std::string want = args.at("topic").get<std::string>();
        for (const auto& t : kTopics) {
            if (want == t.id) {
                json steps = json::array();
                for (const auto& s : t.steps) {
                    json st;
                    st["tool"] = s.tool;
                    st["action"] = s.action;
                    st["params"] = json::parse(s.params, nullptr, false);
                    st["why"] = s.why;
                    steps.push_back(std::move(st));
                }
                return {{"topic", t.id}, {"title", t.title},
                        {"summary", t.summary}, {"steps", steps}};
            }
        }
        json ids = json::array();
        for (const auto& t : kTopics) ids.push_back(t.id);
        fail("unknown guide topic '" + want + "' (available: " + ids.dump() + ")");
    }
    fail("guide: unknown action (list|get)");
}

} // namespace slop::core::mcp::detail
