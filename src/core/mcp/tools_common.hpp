#pragma once

// src/core/mcp/tools_common.hpp
// shared state and helpers for the per-domain tool handlers (tools_*.cpp)
// every handler and helper lives in slop::core::mcp::detail

#include <windows.h>
#include <ws2tcpip.h>

#include "core/infra/app_control.hpp"
#include "core/infra/cancel.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/deferred.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/settings.hpp"
#include "core/infra/text_format.hpp"
#include "core/analysis/danger.hpp"
#include "core/analysis/libsig.hpp"
#include "core/analysis/packer.hpp"
#include "core/analysis/signatures.hpp"
#include "core/analysis/xray.hpp"
#include "core/analysis/imgpatch.hpp"
#include "core/analysis/recover.hpp"
#include "core/analysis/devirt.hpp"
#include "core/analysis/magicmida.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/disasm/image_open.hpp"
#include "core/re/type_catalog.hpp"

#include "core/analysis/bindiff.h"
#include "core/analysis/packer_detect.h"
#include "core/database/database.h"
#include "core/emu/session.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/pointer_scan.hpp"
#include "core/memory/reader.hpp"
#include "core/memory/snapshot.hpp"
#include "core/memory/watch_service.hpp"
#include "core/network/capture_service.hpp"
#include "core/network/http_proxy.hpp"
#include "core/network/mitm_pki.hpp"
#include "core/network/traffic_store.hpp"
#include "core/persist/session_store.hpp"
#include "core/process/heap_list.hpp"
#include "core/process/handle_table.hpp"
#include "core/process/module_dump.hpp"
#include "core/process/module_table.hpp"
#include "core/process/process_icon.hpp"
#include "core/process/process_list.hpp"
#include "core/process/thread_table.hpp"
#include "core/re/rtti.hpp"
#include "core/script/lua_engine.hpp"
#include "core/util/fs_tools.hpp"
#include "core/network/web_fetch.hpp"
#include "core/debugger/callstack.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/disasm/strings.hpp"
#include "core/disasm/xrefs.hpp"
#include "core/runtime/backend.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/ps4_protocol.hpp"
#include "core/runtime/ps5_protocol.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/scan_bridge.hpp"
#include "core/runtime/session.hpp"

#include <capstone/capstone.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"

namespace slop::core::mcp {

namespace infra = slop::core::infra;
namespace ds = slop::core::disasm::binary_state;
namespace hs = slop::core::disasm::hyperion_session;
namespace xray = slop::core::analysis::xray;
namespace imgpatch = slop::core::analysis::imgpatch;
namespace recover = slop::core::analysis::recover;
namespace devirt = slop::core::analysis::devirt;
namespace magicmida = slop::core::analysis::magicmida;
namespace unwind = slop::core::debugger::unwind;

namespace detail {

using json = nlohmann::json;

// serializes every tool call (see call_tool)
extern std::mutex g_tool_mu;
std::mutex& tool_mutex();
// guards g_image so analyze.diff can run off g_tool_mu
extern std::mutex g_image_mu;

// the cheat engine style scan state, one per target
struct scan_state_t {
    memory::memscan_t         engine;  // hits plus the region stash
    bool                      used = false; // a first scan happened
    uint32_t                  pid = 0; // scan state never leaks across targets
    std::string               width = "i32";
    std::string               kind = "exact";
};
extern scan_state_t g_scan;

struct image_cache_t {
    std::string                     path;
    std::vector<uint8_t>            file;
    disasm::pe_image_t              pe;
    disasm::image_format_t          format = disasm::image_format_t::pe;
    disasm::image_arch_t            arch   = disasm::image_arch_t::x64;
    disasm::function_index_t        fidx;
    disasm::xref_index_t            xidx;
    bool                            fidx_ok = false;
    bool                            xidx_ok = false;
};
extern image_cache_t g_image;

// captured memory snapshots for the diff action
struct mcp_snapshot_t {
    uint64_t                  id = 0;
    memory::region_snapshot_t snap;
};
extern std::vector<mcp_snapshot_t> g_snaps;
extern uint64_t                    g_snap_next_id;
inline constexpr size_t            kMaxMcpSnapshots = 8;

// capture sink and proxy instance
extern network::traffic_store_t g_traffic;
extern network::http_proxy_t    g_proxy;

// helpers

[[noreturn]] void fail(std::string msg);

void require_x86_image(disasm::image_arch_t arch, disasm::image_format_t format,
                       std::string_view action, bool path_image = false);
void require_pe_image(disasm::image_arch_t arch, disasm::image_format_t format,
                      std::string_view action, bool path_image = false);

const char* arch_name(runtime::arch_t a);

// keeps the session alive for the whole call even if a detach races it
std::shared_ptr<runtime::session_t> need_session();

uint64_t parse_addr(const json& args, const char* key);
// First present key wins; used where agents naturally say base/va/address
// instead of the canonical addr, or len instead of size.
uint64_t parse_addr_alias(const json& args, std::initializer_list<const char*> keys);
bool has_any(const json& args, std::initializer_list<const char*> keys);
std::string require_action(const json& args);

std::vector<uint8_t> hex_decode(const std::string& hex);
std::string to_hex(const uint8_t* data, size_t len);
std::string hex64(uint64_t v);
std::string addr_hex_str(uint64_t v);

bool icontains(const std::string& haystack, const std::string& needle);

image_cache_t& load_image(const std::string& path);
disasm::engine_t& shared_engine();
mcp_snapshot_t* find_snapshot(uint64_t id);

// app session context, shown at initialize and in the status actions
json loaded_image_json();
json attached_target_json();
json app_state_unlocked();   // caller holds g_tool_mu

// tool handlers (one per domain)
json tool_target(const json& args);
json tool_memory(const json& args);
json tool_disasm(const json& args);
json tool_debugger(const json& args);
json tool_emulate(const json& args, infra::cancel_token_t cancel);
json tool_analyze(const json& args, const infra::cancel_token_t& cancel = {});
json tool_network(const json& args);
json tool_proxy(const json& args);
json tool_fs(const json& args, const infra::cancel_token_t& cancel = {});
json tool_web(const json& args);
json tool_decomp(const json& args);
json tool_persist(const json& args);
json tool_re(const json& args);
json tool_xray(const json& args);
json tool_patch(const json& args);
json tool_types(const json& args);
json tool_notes(const json& args);
json tool_devirt(const json& args);
json tool_script(const json& args, infra::cancel_token_t cancel);
json tool_app(const json& args);
json tool_guide(const json& args);
json tool_host(const json& args);
json tool_gdb(const json& args);

// conditional breakpoints live in tools_debugger.cpp; a console disconnect
// must drop them so stale addresses never re-arm in a new session
void clear_breakpoint_conditions();

} // namespace detail

} // namespace slop::core::mcp
