// src/core/mcp/tools_script.cpp
// tool: script (lua)
//
// runs outside the tool mutex (see call_tool): the lua engine takes it per
// slop.* binding and the slop.debugger / slop.ps4 bindings go back through
// call_tool, so other tools keep answering while a script runs

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

json tool_script(const json& args, infra::cancel_token_t cancel) {
    const std::string action = require_action(args);
    if (action != "run") fail("script: unknown action");

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

    script::lua_run_options_t opt;
    opt.timeout_ms = script::clamp_timeout_ms(timeout_ms);
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

} // namespace slop::core::mcp::detail
