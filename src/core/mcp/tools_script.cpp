// src/core/mcp/tools_script.cpp
// tool: script (lua)
//
// runs outside the tool mutex (see call_tool): the lua engine takes it per
// slop.* binding and the slop.debugger / slop.ps4 bindings go back through
// call_tool, so other tools keep answering while a script runs

#include "core/mcp/tools_common.hpp"

#include "core/infra/paths.hpp"
#include "core/infra/settings.hpp"

namespace slop::core::mcp::detail {

namespace {

// run: code + timeout, with per-run consent for the unsafe stdlib
json script_run(const json& args, infra::cancel_token_t cancel) {
    std::string code;
    if (args.contains("code") && args.at("code").is_string())
        code = args.at("code").get<std::string>();
    if (code.empty()) fail("missing code string");

    // one clamp shared with the engine, small budgets are honoured as given
    int64_t timeout_ms = script::kDefaultTimeoutMs;
    if (auto it = args.find("timeout_ms"); it != args.end()) {
        if (it->is_number_integer())
            timeout_ms = it->get<int64_t>();
        else if (it->is_string())
            timeout_ms = static_cast<int64_t>(
                std::min<uint64_t>(parse_addr(args, "timeout_ms"), script::kMaxTimeoutMs));
        else
            fail("timeout_ms must be an integer");
    }

    // unsafe is per-run consent: script_unsafe stays the admin override, and
    // without it an agent must pass confirm:true, so a script can never widen
    // its own sandbox silently
    const bool admin_unsafe = infra::settings::get<bool>("script_unsafe", false);
    const bool want_unsafe  = args.value("unsafe", false);
    if (want_unsafe && !admin_unsafe && !args.value("confirm", false))
        fail("script.run unsafe:true needs confirm:true (per-run consent) "
             "unless the script_unsafe setting is on");

    script::lua_run_options_t opt;
    opt.timeout_ms = script::clamp_timeout_ms(timeout_ms);
    opt.unsafe     = want_unsafe || admin_unsafe;
    opt.cancel     = std::move(cancel);
    opt.tool_mutex = &tool_mutex();
    auto r = script::lua_run(code, opt);

    json out = {{"ok", r.ok},
                {"output", r.output},
                {"timeout_ms", r.timeout_ms},
                {"sandboxed", !r.unsafe},
                {"peak_mem", r.peak_mem}};
    if (r.output_truncated) out["output_truncated"] = true;
    if (!r.error.empty()) out["error"] = r.error;
    return out;
}

} // namespace

json tool_script(const json& args, infra::cancel_token_t cancel) {
    const std::string action = require_action(args);

    if (action == "run") return script_run(args, std::move(cancel));

    if (action == "api") {
        json entries = json::array();
        for (const auto& e : script::api_entries()) {
            const std::string name = e.group.empty()
                                         ? "slop." + e.name
                                         : "slop." + e.group + "." + e.name;
            entries.push_back({{"name", name},
                               {"group", e.group},
                               {"signature", e.signature},
                               {"doc", e.doc},
                               {"callable", e.callable}});
        }
        return {{"count", entries.size()}, {"functions", std::move(entries)}};
    }

    // snippets: named scripts under <app_data>\scripts
    std::string err;
    if (action == "list") {
        json items = json::array();
        for (const auto& s : script::snippet_list(err))
            items.push_back({{"name", s.name}, {"updated_ms", s.updated_ms}});
        if (!err.empty()) fail(err);
        return {{"snippets", std::move(items)}, {"dir", infra::paths::app_data() + "\\scripts"}};
    }

    const std::string name = args.value("name", std::string{});
    if (action == "save") {
        const std::string code = args.value("code", std::string{});
        if (code.empty()) fail("missing code string");
        if (!script::snippet_save(name, code, err)) fail(err);
        return {{"ok", true}, {"name", name}};
    }
    if (action == "load") {
        script::snippet_t s;
        if (!script::snippet_load(name, s, err)) fail(err);
        return {{"name", s.name}, {"code", s.code}, {"updated_ms", s.updated_ms}};
    }
    if (action == "delete") {
        if (!script::snippet_delete(name, err)) fail(err);
        return {{"ok", true}, {"name", name}};
    }
    fail("script: unknown action");
}

} // namespace slop::core::mcp::detail
