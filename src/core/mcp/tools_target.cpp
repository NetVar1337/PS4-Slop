// src/core/mcp/tools_target.cpp
// tool: target (processes, attach, modules, ps4 connect)

#include "core/mcp/tools_common.hpp"

#include <list>

namespace slop::core::mcp::detail {

namespace {

const char* elevation_name(runtime::elevation_t e) {
    switch (e) {
    case runtime::elevation_t::standard: return "user";
    case runtime::elevation_t::elevated: return "admin";
    case runtime::elevation_t::system:   return "system";
    case runtime::elevation_t::unknown:  break;
    }
    return "unknown";
}

// icon cache: a busy machine is hundreds of processes sharing a handful of
// images, but rotating processes must not grow it forever; least recently
// used entries go once kIconCacheCap is reached
constexpr size_t kIconCacheCap = 256;

struct icon_cache_t {
    std::mutex mu;
    std::list<std::pair<std::string, json>> lru;   // front = most recent
    std::unordered_map<std::string, std::list<std::pair<std::string, json>>::iterator> index;

    json get_or_make(const std::string& path) {
        std::lock_guard lk(mu);
        if (auto it = index.find(path); it != index.end()) {
            lru.splice(lru.begin(), lru, it->second);
            return it->second->second;
        }
        const auto bits = process::icon_for_path(path, true);
        json entry = {{"width", bits.width}, {"height", bits.height}};
        if (!bits.empty()) entry["bgra_b64"] = infra::fmt::base64(bits.bgra);
        lru.emplace_front(path, entry);
        index[path] = lru.begin();
        while (lru.size() > kIconCacheCap) {
            index.erase(lru.back().first);
            lru.pop_back();
        }
        return entry;
    }

    size_t size() {
        std::lock_guard lk(mu);
        return lru.size();
    }
};

icon_cache_t& icon_cache() {
    static icon_cache_t c;
    return c;
}

json ps4_status_json(runtime::backend_ps4_t& p4) {
    return {{"endpoint", runtime::registry_ps4_endpoint()},
            {"branding", p4.branding()},
            {"fw", p4.fw_string()},
            {"connected", p4.connected()},
            {"lost", p4.lost()},
            {"lost_reason", p4.lost_reason()},
            {"drops", p4.drop_count()},
            {"authed", p4.ps4_authed()}};
}

} // namespace

// exposed for tests: entries currently cached by target.icon
size_t target_icon_cache_size() { return icon_cache().size(); }


// tool: target

json tool_target(const json& args) {
    const std::string action = require_action(args);

    if (action == "list") {
        process::refresh_processes(); // warm the cached snapshot the ui reads (0 = rejected, ignore)
        auto res = runtime::active().enum_processes();
        if (!res.ok) fail("process enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{4096});
        for (size_t i = 0; i < cap; ++i) {
            const auto& p = res.items[i];
            // the process table wants path and elevation too
            arr.push_back({{"pid", p.pid},
                           {"name", p.name},
                           {"arch", arch_name(p.arch)},
                           {"path", p.path},
                           {"elevation", elevation_name(p.elevation)}});
        }
        return {{"processes", arr}, {"count", arr.size()}};
    }

    if (action == "icon") {
        std::vector<std::string> paths;
        if (args.contains("paths") && args.at("paths").is_array()) {
            for (const auto& p : args.at("paths")) {
                if (p.is_string()) paths.push_back(p.get<std::string>());
                if (paths.size() >= 64) break;   // keep one requests shell work bounded
            }
        } else if (args.contains("path") && args.at("path").is_string()) {
            paths.push_back(args.at("path").get<std::string>());
        } else if (args.contains("pid")) {
            const uint32_t pid = static_cast<uint32_t>(parse_addr(args, "pid"));
            auto res = runtime::active().enum_processes();
            if (res.ok) {
                for (const auto& p : res.items)
                    if (p.pid == pid) {
                        paths.push_back(p.path);
                        break;
                    }
            }
        } else {
            fail("target.icon: need path, paths, or pid");
        }

        json icons = json::object();
        for (const auto& path : paths) {
            if (path.empty()) continue;
            icons[path] = icon_cache().get_or_make(path);
        }
        // grab the size before the move eats it
        const size_t resolved = icons.size();
        return {{"icons", std::move(icons)}, {"count", resolved}};
    }

    if (action == "attach") {
        const uint64_t pid = parse_addr(args, "pid");
        if (pid == 0 || pid > 0xFFFFFFFFull) fail("bad pid");
        if (!process::target_attach(static_cast<uint32_t>(pid)))
            fail("attach failed (process gone or access denied)");
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        auto s = process::active_session();

        // pull the targets main module into the shared session so static tools see what actually runs, a ui loaded binary never gets clobbered
        bool image_auto_loaded = false;
        if (!ds::has_binary()) image_auto_loaded = ds::load_from_target();

        json out = {{"attached", true},
                    {"pid", pid},
                    {"name", s ? s->name() : ""},
                    {"arch", s ? arch_name(s->arch()) : ""},
                    {"backend", runtime::active_badge()},
                    {"image_auto_loaded", image_auto_loaded},
                    {"image", loaded_image_json()}};
        if (!image_auto_loaded && !ds::has_binary())
            out["hint"] = "main module could not be read from disk; pass an explicit "
                          "'path' to static tools or open a binary in reverse-slop";
        return out;
    }

    if (action == "detach") {
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        process::target_detach();
        return {{"attached", false}};
    }

    if (action == "ps4_connect") {
        if (!args.contains("host") || !args.at("host").is_string())
            fail("ps4_connect requires string 'host' (the PS4 IP)");
        const std::string host = args.at("host").get<std::string>();
        if (host.empty()) fail("ps4_connect: 'host' is empty");
        const uint64_t port = args.contains("port") ? parse_addr(args, "port")
                                                    : runtime::ps4::kDefaultPort;
        if (port == 0 || port > 0xFFFF) fail("ps4_connect: bad port");
        uint32_t pid = 0;
        if (args.contains("pid")) {
            const uint64_t p = parse_addr(args, "pid");
            if (p == 0 || p > 0xFFFFFFFFull) fail("ps4_connect: bad pid");
            pid = static_cast<uint32_t>(p);
        }
        std::string err;
        if (!process::target_connect_ps4(host, static_cast<uint16_t>(port), pid, err))
            fail("ps4_connect failed: " + err);
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        json out = {{"connected", true},
                    {"host", host},
                    {"port", port},
                    {"endpoint", runtime::registry_ps4_endpoint()},
                    {"branding", runtime::registry_ps4_branding()},
                    {"fw", runtime::registry_ps4() ? runtime::registry_ps4()->fw_string() : ""},
                    {"backend", runtime::active_badge()}};
        auto s = process::active_session();
        if (pid != 0 && s && s->valid()) {
            out["attached"] = true;
            out["pid"]      = s->pid();
            out["name"]     = s->name();
            out["arch"]     = arch_name(s->arch());
            out["hint"]     = "PS4 modules are ELF/SELF, not PE: use target.ps4_dump_module to pull the "
                              "raw memory image over the wire (load=true for ELF static analysis). "
                              "Use target.modules, memory.read/write and disasm.disassemble on live "
                              "addresses instead.";
        } else {
            out["attached"] = false;
            out["hint"]     = "Console connected. Next: target.list to pick a pid, then "
                              "target.attach {pid} (or ps4_connect again with pid).";
        }
        return out;
    }

    if (action == "ps4_disconnect") {
        process::target_disconnect_ps4();
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        return {{"connected", false},
                {"backend", runtime::active_badge()}};
    }

    if (action == "ps4_reconnect") {
        // after a dropped connection (console reboot, Wi-Fi loss, payload
        // restart): handshake + auth again, re-attach the debuggee, re-arm
        // every slot this client had armed; the session survives
        runtime::backend_ps4_t::reconnect_report_t rep;
        std::string err;
        if (!process::target_reconnect_ps4(err, &rep)) fail("ps4_reconnect failed: " + err);
        auto s = process::active_session();
        auto* p4 = runtime::registry_ps4();
        json out = {{"connected", p4 && p4->connected()},
                    {"endpoint", runtime::registry_ps4_endpoint()},
                    {"branding", runtime::registry_ps4_branding()},
                    {"fw", p4 ? p4->fw_string() : std::string{}},
                    {"authed", rep.authed},
                    {"session_kept", s && s->valid()},
                    {"debug_pid", rep.debug_pid},
                    {"debug_restored", rep.debug_restored},
                    {"breakpoints_rearmed", rep.bp_rearmed},
                    {"breakpoints_lost", rep.bp_failed},
                    {"watchpoints_rearmed", rep.wp_rearmed},
                    {"watchpoints_lost", rep.wp_failed}};
        if (!rep.debug_error.empty()) out["debug_error"] = rep.debug_error;
        if (s && s->valid()) out["pid"] = s->pid();
        return out;
    }

    if (action == "ps4_auto") {
        // one-call console setup: connect, find the game process (the one with
        // /app0/ in its executable path), attach a session, debug-attach, and
        // return a full summary
        if (!args.contains("host") || !args.at("host").is_string())
            fail("ps4_auto requires string 'host' (the PS4 IP)");
        const std::string host = args.at("host").get<std::string>();
        if (host.empty()) fail("ps4_auto: 'host' is empty");
        const uint64_t port = args.contains("port") ? parse_addr(args, "port")
                                                    : runtime::ps4::kDefaultPort;
        if (port == 0 || port > 0xFFFF) fail("ps4_auto: bad port");
        std::string err;
        if (!runtime::registry_ps4_active() &&
            !process::target_connect_ps4(host, static_cast<uint16_t>(port), 0, err))
            fail("ps4_auto: connect failed: " + err);
        auto* p = dynamic_cast<runtime::backend_ps4_t*>(&runtime::active());
        if (!p || !p->connected())
            fail("ps4_auto: no PS4 console connected");

        // candidates: processes whose executable path lives under /app0/
        auto procs = p->enum_processes();
        if (!procs.ok) fail("ps4_auto: cannot list console processes: " +
                            runtime::ps4::io_error_str(procs.error));
        struct cand_t {
            uint32_t pid = 0;
            std::string name, path;
            size_t image_size = 0;
            bool game = false;
        };
        std::vector<cand_t> cands;
        uint32_t fallback_pid = 0;
        size_t fallback_size = 0;
        for (const auto& pr : procs.items) {
            auto h = p->attach(pr.pid);
            if (!h.valid()) continue;
            cand_t c;
            c.pid  = pr.pid;
            c.name = pr.name;
            auto mods = p->enum_modules(h);
            for (const auto& m : mods.items) {
                c.image_size += m.size;
                if (m.path.find("/app0/") != std::string::npos ||
                    m.path.find("\\app0\\") != std::string::npos) {
                    c.game = true;
                    if (c.path.empty()) c.path = m.path;
                }
            }
            p->detach(h);
            if (c.image_size > fallback_size) {
                fallback_size = c.image_size;
                fallback_pid  = c.pid;
            }
            cands.push_back(std::move(c));
        }
        uint32_t pick = 0;
        std::string pick_name;
        bool heuristic = false;
        for (const auto& c : cands) {
            if (!c.game) continue;
            if (pick == 0 || c.name.find("eboot") != std::string::npos) {
                pick = c.pid;
                pick_name = c.name;
                if (c.name.find("eboot") != std::string::npos) break;
            }
        }
        if (pick == 0) {
            pick = fallback_pid;
            heuristic = true;
            for (const auto& c : cands)
                if (c.pid == pick) pick_name = c.name;
        }
        if (pick == 0) fail("ps4_auto: no processes on the console");

        if (!process::target_attach(pick))
            fail("ps4_auto: attached console but session attach to pid " +
                 std::to_string(pick) + " failed");
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;

        std::string derr;
        const bool dbg_ok = p->ps4_debug_attach(pick, derr);

        auto s = process::active_session();
        json out = {{"connected", true},
                    {"endpoint", runtime::registry_ps4_endpoint()},
                    {"branding", runtime::registry_ps4_branding()},
                    {"pid", pick},
                    {"name", pick_name},
                    {"debug_attached", dbg_ok},
                    {"heuristic_pick", heuristic},
                    {"hint", "Ready: target.modules/threads, memory.*, disasm.disassemble on "
                             "live addresses, debugger ps4_* for breakpoints/steps/calls. "
                             "guide get ps4_setup shows the full flow."}};
        if (!dbg_ok) out["debug_error"] = derr;
        json cands_json = json::array();
        for (const auto& c : cands)
            cands_json.push_back({{"pid", c.pid}, {"name", c.name},
                                  {"game", c.game}, {"image_size", c.image_size},
                                  {"path", c.path}});
        out["candidates"] = cands_json;
        if (s && s->valid()) {
            auto mods = p->enum_modules(s->handle());
            json mods_json = json::array();
            for (size_t i = 0; i < mods.items.size() && i < 32; ++i)
                mods_json.push_back({{"base", static_cast<uint64_t>(mods.items[i].base)},
                                     {"size", mods.items[i].size},
                                     {"name", mods.items[i].name},
                                     {"path", mods.items[i].path}});
            out["modules"] = mods_json;
            out["module_count"] = mods.items.size();
            auto thr = p->enum_threads(pick);
            json thr_json = json::array();
            for (const auto& t : thr.items)
                thr_json.push_back({{"lwpid", t.tid}, {"priority", t.priority}, {"name", t.name}});
            out["threads"] = thr_json;
            out["thread_count"] = thr.items.size();
            auto regs = p->enum_regions(s->handle());
            out["region_count"] = regs.ok ? regs.items.size() : 0;
        }
        return out;
    }

    if (action == "status") {
        json out;
        out["backend"]  = runtime::active_badge();
        // ps4 is present whenever a console is selected, also while its
        // connection is down (connected=false, lost=true -> ps4_reconnect)
        auto* p4 = runtime::registry_ps4();
        if (p4) out["ps4"] = ps4_status_json(*p4);
        auto s = process::active_session();
        if (s && s->valid()) {
            out["attached"] = true;
            out["pid"]      = s->pid();
            out["name"]     = s->name();
            out["arch"]     = arch_name(s->arch());
        } else {
            out["attached"] = false;
        }
        if (p4) {
            out["debugger"]           = "ps4";
            out["ps4_debug_attached"] = p4->ps4_debug_attached();
            out["ps4_debug_pid"]      = p4->ps4_debug_pid();
            out["fw"]                 = p4->fw_string();
        }
        if (!out.contains("debugger"))
            out["debugger"] = "ps4 (debugger ps4_* actions; connect a console via target.ps4_connect)";
        out["image"]          = loaded_image_json();
        return out;
    }

    if (action == "modules") {
        const auto s_hold = need_session();
        auto& s = *s_hold;
        process::refresh_modules(); // warm cache for va_to_module + the ui (0 = rejected, ignore)
        // the session's own backend (a console module list is one record per
        // module, its segments coalesced)
        auto res = s.backend()->enum_modules(s.handle());
        if (!res.ok) fail("module enumeration failed: " + runtime::ps4::io_error_str(res.error));
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{2048});
        for (size_t i = 0; i < cap; ++i) {
            const auto& m = res.items[i];
            arr.push_back({{"base", static_cast<uint64_t>(m.base)},
                           {"size", m.size},
                           {"name", m.name},
                           {"path", m.path}});
        }
        return {{"modules", arr}, {"count", arr.size()}};
    }

    if (action == "dump_module") {
        const auto session_hold = need_session();
        auto& session = *session_hold;
        if (!args.contains("path") || !args.at("path").is_string())
            fail("dump_module requires output 'path'");
        const std::string output_path = args.at("path").get<std::string>();
        if (output_path.empty()) fail("dump_module output path is empty");

        const uint64_t requested_base = args.contains("base")
            ? parse_addr(args, "base") : 0;
        const std::string requested_name = args.value("name", std::string{});
        if (requested_base == 0 && requested_name.empty())
            fail("dump_module requires module 'base' or 'name'");

        auto modules = runtime::active().enum_modules(session.handle());
        if (!modules.ok) fail("module enumeration failed");

        const runtime::module_info_t* selected = nullptr;
        for (const auto& module : modules.items) {
            if ((requested_base != 0 && module.base == requested_base) ||
                (requested_base == 0 &&
                 _stricmp(module.name.c_str(), requested_name.c_str()) == 0)) {
                selected = &module;
                break;
            }
        }
        if (!selected) fail("requested module is not loaded in the target");

        process::module_dump_options_t options;
        options.strict_reads = args.value("strict", true);
        auto result = process::dump_module_pe(session, *selected, output_path, options);
        if (!result.ok) fail("module dump failed: " + result.error);

        bool loaded = false;
        if (args.value("load", false))
            loaded = ds::load_file(output_path, selected->base);

        return {{"dumped", true},
                {"complete", result.complete},
                {"path", result.output_path},
                {"bytes_written", result.bytes_written},
                {"sections", result.section_count},
                {"module", {{"base", static_cast<uint64_t>(selected->base)},
                             {"size", selected->size},
                             {"name", selected->name},
                             {"path", selected->path}}},
                {"loaded", loaded},
                {"warnings", result.warnings}};
    }

    if (action == "threads") {
        uint32_t pid = 0;
        if (args.contains("pid")) pid = static_cast<uint32_t>(parse_addr(args, "pid"));
        if (pid == 0) pid = need_session()->pid();
        process::refresh_threads(); // warm the cached snapshot the ui reads (0 = rejected, ignore)
        auto res = runtime::active().enum_threads(pid);
        if (!res.ok) fail("thread enumeration failed: " + runtime::ps4::io_error_str(res.error));
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{4096});
        for (size_t i = 0; i < cap; ++i) {
            const auto& t = res.items[i];
            json o = {{"tid", t.tid},
                      {"start", static_cast<uint64_t>(t.start_address)},
                      {"priority", t.priority}};
            if (!t.name.empty()) o["name"] = t.name;
            arr.push_back(std::move(o));
        }
        return {{"threads", arr}, {"count", arr.size()}};
    }

    if (action == "regions") {
        const auto s_hold = need_session();
        auto& s = *s_hold;
        auto res = runtime::active().enum_regions(s.handle());
        if (!res.ok) fail("region enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{8192});
        for (size_t i = 0; i < cap; ++i) {
            const auto& r = res.items[i];
            arr.push_back({{"base", static_cast<uint64_t>(r.base)},
                           {"size", r.size},
                           {"protect", r.protect},
                           {"state", r.state},
                           {"type", r.type}});
        }
        return {{"regions", arr}, {"count", arr.size()}};
    }

    if (action == "handles") {
        const auto s_hold = need_session();
        auto& s = *s_hold;
        process::refresh_handles(); // warm the cached snapshot the ui reads (0 = rejected, ignore)
        auto res = runtime::active().enum_handles(s.pid());
        if (!res.ok) fail("handle enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{2048});
        for (size_t i = 0; i < cap; ++i) {
            const auto& h = res.items[i];
            json o = {{"handle", static_cast<uint64_t>(h.handle_value)},
                      {"type", h.type_name},
                      {"granted_access", h.granted_access}};
            if (!h.object_name.empty()) o["object"] = h.object_name;
            arr.push_back(std::move(o));
        }
        return {{"handles", arr}, {"count", arr.size()}, {"total", res.items.size()}};
    }

    if (action == "heaps" || action == "heap_blocks") {
        // Toolhelp snapshots are a local user-mode API; the PS4 backend has no heaps
        if (runtime::registry_ps4_active())
            fail(action + " is local-only (Toolhelp heap snapshots); no PS4 backend support");
        const auto s_hold = need_session();
        auto& s = *s_hold;
        std::string err;
        if (action == "heaps") {
            auto heaps = process::list_heaps(s.pid(), &err);
            if (heaps.empty() && !err.empty()) fail("heap enumeration failed: " + err);
            json arr = json::array();
            for (const auto& h : heaps) {
                arr.push_back({{"base", h.base},
                               {"size", h.size},
                               {"flags", h.flags},
                               {"entries_used_hint", h.entries_used_hint}});
            }
            return {{"heaps", arr}, {"count", arr.size()}};
        }
        if (!args.contains("heap_base")) fail("heap_blocks requires heap_base (from target.heaps)");
        const uint64_t heap_base = parse_addr(args, "heap_base");
        size_t max_blocks = 4096;
        if (args.contains("max_blocks")) {
            const uint64_t mb = parse_addr(args, "max_blocks");
            if (mb == 0 || mb > 1048576) fail("max_blocks out of range (1..1048576)");
            max_blocks = static_cast<size_t>(mb);
        }
        auto blocks = process::walk_heap_blocks(s.pid(), heap_base, &err, max_blocks);
        if (blocks.empty() && !err.empty()) fail("heap block walk failed: " + err);
        json arr = json::array();
        for (const auto& b : blocks) {
            arr.push_back({{"address", b.address},
                           {"size", b.size},
                           {"flags", b.flags}});
        }
        return {{"heap_base", heap_base}, {"blocks", arr}, {"count", arr.size()}};
    }

    if (action == "ps4_dump_module") {
        // dump a whole module (every segment of it) from the console over
        // ps4debug-NG, as the raw mapped span or as a rebuilt loadable ELF
        const auto session_hold = need_session();
        auto& session = *session_hold;
        auto* p4 = dynamic_cast<runtime::backend_ps4_t*>(session.backend());
        if (!p4 || !p4->connected())
            fail("ps4_dump_module requires a connected console with an attached process "
                 "(target.ps4_connect {host, pid} or target.ps4_reconnect)");
        if (!args.contains("path") || !args.at("path").is_string())
            fail("ps4_dump_module requires output 'path'");
        const std::string output_path = args.at("path").get<std::string>();
        if (output_path.empty()) fail("ps4_dump_module output path is empty");
        const uint64_t requested_base = args.contains("base") ? parse_addr(args, "base") : 0;
        const std::string requested_name = args.value("name", std::string{});
        if (requested_base == 0 && requested_name.empty())
            fail("ps4_dump_module requires module 'base' or 'name'");
        const bool load = args.value("load", false);
        const std::string format = args.value("format", std::string(load ? "elf" : "raw"));
        if (format != "raw" && format != "elf") fail("ps4_dump_module: format must be raw or elf");
        if (load && format != "elf")
            fail("ps4_dump_module: load=true needs format=elf (a raw memory span has no ELF "
                 "headers to load)");

        auto modules = p4->ps4_modules(session.handle());
        if (!modules.ok)
            fail("module enumeration failed on the console: " +
                 runtime::ps4::io_error_str(modules.error));
        const runtime::ps4_module_t* selected = nullptr;
        for (const auto& m : modules.items) {
            const bool base_hit = requested_base != 0 &&
                (m.base == requested_base ||
                 std::any_of(m.segments.begin(), m.segments.end(),
                             [&](const runtime::ps4_segment_t& s) { return s.start == requested_base; }));
            if (base_hit ||
                (requested_base == 0 && _stricmp(m.name.c_str(), requested_name.c_str()) == 0)) {
                selected = &m;
                break;
            }
        }
        if (!selected) fail("requested module is not loaded in the console process");

        std::vector<process::mapped_segment_t> segs;
        json segs_json = json::array();
        for (const auto& s : selected->segments) {
            segs.push_back({s.start, s.end, s.prot});
            segs_json.push_back({{"start", s.start}, {"start_hex", addr_hex_str(s.start)},
                                 {"size", s.end - s.start}, {"prot", s.prot}});
        }

        process::module_dump_options_t options;
        options.chunk_size = 256u * 1024u;
        // a console module often has pages the payload cannot read; zero-fill
        // them (complete=false) unless the caller asks for a strict dump
        options.strict_reads = args.value("strict", false);
        auto read = [&session](uintptr_t a, void* dst, size_t n) { return session.read(a, dst, n); };
        std::vector<uint8_t> image;
        process::elf_rebuild_info_t info;
        auto result = format == "elf"
            ? process::reconstruct_elf_from_segments(segs, read, image, options, &info)
            : process::dump_raw_span(segs, read, image, options);
        if (!result.ok) fail("ps4_dump_module failed: " + result.error);
        std::string werr;
        if (!process::write_dump_file(output_path, image, werr)) fail("ps4_dump_module: " + werr);

        bool loaded = false;
        std::string load_note;
        if (load) {
            // p_vaddr are the console addresses and the bytes are already
            // relocated in memory: load at the module base, no relocations
            loaded = ds::load_file(output_path, selected->base, /*apply_relocs=*/false);
            if (!loaded) load_note = ds::last_load_error();
        }
        json out = {{"dumped", true},
                    {"complete", result.complete},
                    {"format", format},
                    {"path", output_path},
                    {"bytes_written", result.bytes_written},
                    {"segments", segs_json},
                    {"segment_count", segs.size()},
                    {"module", {{"base", selected->base},
                                {"base_hex", addr_hex_str(selected->base)},
                                {"size", selected->end - selected->base},
                                {"name", selected->name},
                                {"path", selected->path}}},
                    {"loaded", loaded},
                    {"warnings", result.warnings}};
        if (!load_note.empty()) out["load_note"] = load_note;
        if (format == "elf") {
            out["elf_header_in_memory"] = info.had_header;
            out["entry"] = info.entry;
            out["entry_hex"] = addr_hex_str(info.entry);
            out["note"] = info.had_header
                ? "ELF rebuilt from the console maps; entry/type taken from the in-memory header"
                : "the module's ELF header is not mapped on the console (SELF loader), so one "
                  "was rebuilt from the maps: one PT_LOAD per segment at its console address, "
                  "entry unknown, no section headers";
        } else {
            out["note"] = "raw mapped span [base, base+size): segments at their offsets from "
                          "the base, gaps zero-filled; format=elf (or load=true) rebuilds a "
                          "loadable ELF instead";
        }
        return out;
    }

    fail("target: unknown action (list|attach|detach|status|modules|"
         "dump_module|ps4_dump_module|threads|regions|handles|heaps|heap_blocks|icon|"
         "ps4_connect|ps4_disconnect|ps4_reconnect|ps4_auto)");
}

} // namespace slop::core::mcp::detail
