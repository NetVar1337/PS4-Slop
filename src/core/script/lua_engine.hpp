#pragma once

// src/core/script/lua_engine.hpp
// embedded lua 5.4 over the core services on the raw c api
// the static analysis surface is the lua to reverse slop as python to ida
// layer, it all operates on the shared session so renames and comments
// made from lua or mcp appear everywhere:
//
//   slop.image.load(path[, base])     load a binary into the shared session
//   slop.image.load_from_target()     load the attached target's main module
//   slop.image.unload()               tear the session down
//   slop.image.status()               {ready,name,base,entry,hype={...}}
//   slop.image.wait_ready([ms])       block until hyperion analysis lands
//
//   slop.disasm.decode(addr[, n])     {addr,len,text,bytes,target,...} rows
//   slop.disasm.functions([limit])    {va,size,name[,blocks,loops,...]} rows
//   slop.disasm.function_at(va)       owning function row (nil outside)
//   slop.disasm.xrefs_to(va)          {from,kind} rows (hyperion-enriched)
//   slop.disasm.strings([min[,lim]])  {va,text,utf16} rows
//   slop.disasm.pe()                  headers, sections, imports, exports
//   slop.disasm.bytes(addr[, len])    raw file-image bytes (binary string)
//   slop.disasm.name(va) / set_name(va, name)       persisted rename
//   slop.disasm.comment(va) / set_comment(va, text) persisted annotation
//   slop.disasm.bookmark_toggle(va) / bookmarks()
//   unnamed functions are sub_<VA uppercase hex> (disasm::default_function_name)
//
//   slop.decomp.decompile(va)        pseudo-C lines + signature (hyperion)
//   slop.decomp.blocks(va)            CFG blocks + loops for a function
//   slop.decomp.vtables() / globals() / rtti()   rich analysis DB views
//
// live target surface:
//   slop.version() / slop.api() / slop.log(msg)
//   slop.log(level, msg) / slop.log.debug|info|warn|error(msg)
//   slop.target.list() / attach(pid) / status()
//   slop.mem.read_hex(addr,len)       lowercase hex string of the bytes read
//   slop.mem.read_bytes(addr,len)     raw bytes (binary lua string)
//   slop.mem.write_hex(addr,hexstr) / scan(cfg)
//   slop.disasm.disassemble(addr,count)     live-process disassembly
//   slop.analyze.packer([path])
//
// ps4 console + debugger surface, each call runs the matching mcp action
// (target ps4_* / debugger ps4_*) so slot bookkeeping and errors are shared:
//   slop.ps4.connect(host[,port]) / disconnect() / auto(host[,port]) / status()
//   slop.debugger.status() / attach(pid) / detach()
//   slop.debugger.bp_set(addr[,index]) / bp_clear(addr) / bp_list()
//   slop.debugger.watch_set(addr[,len[,type]]) / watch_clear(addr) / watch_list()
//   slop.debugger.continue([stop]) / step([lwpid]) / suspend(lwpid) / resume(lwpid)
//   slop.debugger.wait([ms]) / events([max]) / regs(lwpid) / set_reg(lwpid,name,value)
//   slop.debugger.callstack(lwpid[,depth]) / call(addr[,args[,pid]])
//   slop.debugger.run_until(addr[,ms]) / find_write(addr[,len[,ms]])
//   slop.debugger.trace_calls(addr[,count[,ms]])
//   slop.debugger.action(name, params)     any other debugger ps4_* action
// blocking waits are clamped to the script's remaining time budget
//
// sandbox: by default only base (without dofile/loadfile, load is text-only),
// string, table, math, utf8 and os.clock/os.time/os.difftime are opened.
// the settings key "script_unsafe" (bool) restores the full standard library
// (io, os, package, debug, coroutine) and host-file debugger actions
//
// every script runs under an instruction count hook (deadline + cancel
// checks every kHookInstructions vm instructions), an allocation cap and an
// output cap; print output is captured and the return value lands in the
// output as return: ...
//
// wall-clock backstop: the hook only counts vm instructions, so a loop of
// cheap C calls (slop.mem.read_bytes) or one long native call would outrun
// it. every slop.* binding re-checks the deadline on entry, the allocator
// refuses growth past the deadline, and blocking bindings clamp their wait
// to the remaining budget. the run therefore ends within one binding call
// of timeout_ms even when the vm never executes another instruction.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/infra/cancel.hpp"

namespace slop::core::script {

// one clamp shared by the engine and the mcp layer
inline constexpr int    kMinTimeoutMs     = 10;
inline constexpr int    kMaxTimeoutMs     = 60000;
inline constexpr int    kDefaultTimeoutMs = 5000;
inline constexpr int    kHookInstructions = 1000;
inline constexpr size_t kDefaultMemLimit  = 256u << 20;   // bytes of lua heap
inline constexpr size_t kMaxOutputBytes   = 4u << 20;     // captured print stream

int clamp_timeout_ms(int64_t ms) noexcept;

struct lua_run_options_t {
    int timeout_ms = kDefaultTimeoutMs;   // clamped with clamp_timeout_ms
    // nullopt reads the "script_unsafe" setting (default false = sandboxed)
    std::optional<bool> unsafe;
    size_t mem_limit = kDefaultMemLimit;  // lua allocations past this fail
    infra::cancel_token_t cancel;         // polled by the hook and blocking bindings
    // taken around each slop.* binding that touches shared state, never
    // across the whole script; null runs the bindings unserialized
    std::mutex* tool_mutex = nullptr;
};

struct lua_run_result_t {
    bool        ok  = false;
    std::string output;   // captured print/slop.log stream
    std::string error;    // non-empty on failure
    int         timeout_ms = 0;          // effective budget after clamping
    bool        unsafe = false;          // full stdlib was opened
    size_t      peak_mem = 0;            // high-water mark of the lua heap
    bool        output_truncated = false;
};

lua_run_result_t lua_run(const std::string& code, const lua_run_options_t& opt);
lua_run_result_t lua_run(const std::string& code, int timeout_ms = kDefaultTimeoutMs);

// ---- script.api: the slop.* surface, generated from the registration tables
//
// one row per registered binding plus the top-level functions; the Scripts
// panel builds its completion list from this and the MCP script.api action
// returns it, so the docs cannot drift from what open_env() actually binds
struct api_entry_t {
    std::string group;     // "" for slop.version / slop.log / slop.api
    std::string name;      // "read_hex"
    std::string signature; // "(addr, len) -> hex string"
    std::string doc;       // one line
    bool        callable = true;   // false: a table with __call (slop.log)
};
const std::vector<api_entry_t>& api_entries();

// ---- snippets: named scripts persisted under <app_data>\scripts
//
// names are 1..64 chars of [A-Za-z0-9._-], never "." or "..", so a snippet
// name can never escape the folder

struct snippet_t {
    std::string name;
    std::string code;
    int64_t     updated_ms = 0;
};

bool snippet_name_valid(const std::string& name);
bool snippet_save(const std::string& name, const std::string& code, std::string& err);
std::vector<snippet_t> snippet_list(std::string& err);
bool snippet_load(const std::string& name, snippet_t& out, std::string& err);
bool snippet_delete(const std::string& name, std::string& err);

} // namespace slop::core::script
