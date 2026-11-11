// src/core/script/lua_engine.cpp

#include "core/script/lua_engine.hpp"

#include "core/analysis/packer.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/infra/settings.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/session_reader.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/scan_bridge.hpp"

#include <lua.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <thread>

namespace slop::core::script {

namespace {

namespace infra = slop::core::infra;
namespace memory = slop::core::memory;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace disasm = slop::core::disasm;
namespace analysis = slop::core::analysis;
namespace hs = slop::core::disasm::hyperion_session;
namespace ds = slop::core::disasm::binary_state;
using json = nlohmann::json;

// per-run state, it is also the allocator userdata so every binding reaches
// it through lua_getallocf without a registry lookup
struct script_ctx_t {
    std::string           output;
    bool                  output_truncated = false;
    int64_t               deadline_ms = 0;   // steady clock
    infra::cancel_token_t cancel;
    std::mutex*           tool_mu = nullptr;
    bool                  unsafe = false;
    size_t                mem_used  = 0;
    size_t                mem_peak  = 0;
    size_t                mem_limit = kDefaultMemLimit;
};

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

script_ctx_t* ctx_of(lua_State* L) {
    void* ud = nullptr;
    lua_getallocf(L, &ud);
    return static_cast<script_ctx_t*>(ud);
}

// milliseconds left in the script budget, 0 once spent
int64_t remaining_ms(lua_State* L) {
    const int64_t left = ctx_of(L)->deadline_ms - now_ms();
    return left > 0 ? left : 0;
}

// lua heap capped at mem_limit; growth past it fails as a lua memory error,
// shrinking never fails (lua relies on that)
void* capped_alloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    auto* c = static_cast<script_ctx_t*>(ud);
    const size_t old = ptr ? osize : 0;   // osize is a type tag when ptr is null
    if (nsize == 0) {
        c->mem_used -= old;
        std::free(ptr);
        return nullptr;
    }
    if (nsize > old && c->mem_used - old + nsize > c->mem_limit) return nullptr;
    void* p = std::realloc(ptr, nsize);
    if (!p) return nullptr;
    c->mem_used = c->mem_used - old + nsize;
    c->mem_peak = std::max(c->mem_peak, c->mem_used);
    return p;
}

void out_append(lua_State* L, const std::string& s) {
    script_ctx_t* c = ctx_of(L);
    if (c->output_truncated) return;
    if (c->output.size() + s.size() > kMaxOutputBytes) {
        c->output.append(s, 0, kMaxOutputBytes - c->output.size());
        c->output += "\n[output truncated]\n";
        c->output_truncated = true;
        return;
    }
    c->output += s;
}

uint64_t to_addr(lua_State* L, int idx) {
    if (lua_type(L, idx) == LUA_TSTRING) {
        const char* s = lua_tostring(L, idx);
        return std::strtoull(s, nullptr, 0);
    }
    return static_cast<uint64_t>(lua_tointegerx(L, idx, nullptr));
}

int l_log(lua_State* L) {
    const int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        out_append(L, s ? std::string(s, len) : std::string("nil"));
        lua_pop(L, 1);
        if (i < n) out_append(L, "\t");
    }
    out_append(L, "\n");
    return 0;
}

int l_version(lua_State* L) {
    lua_pushstring(L, ctx_of(L)->unsafe
                          ? "reverse-slop script engine (Lua 5.4, unsafe stdlib)"
                          : "reverse-slop script engine (Lua 5.4, sandboxed)");
    return 1;
}

// helpers

// raise lua errors from a dedicated noinline frame, longjmp on x64 walks
// every frame and an inlined raise with c++ locals can crash the unwinder
// the message goes through %s so dynamic content is never a format string
__declspec(noinline) int lua_fail(lua_State* L, const char* msg) {
    return luaL_error(L, "%s", msg);
}

// Push a table of strings (array part)
void push_str_array(lua_State* L, const std::vector<std::string>& v) {
    lua_createtable(L, static_cast<int>(std::min<size_t>(v.size(), 65536)), 0);
    int i = 1;
    for (const auto& s : v) {
        if (i > 65536) break;
        lua_pushstring(L, s.c_str());
        lua_rawseti(L, -2, i++);
    }
}

// Shared-image helpers: pin the session against concurrent load/unload for
// the duration of one binding call (same contract the MCP tools use)

// Requires a loaded image; errors (Lua-level) otherwise. Returns nothing on
// failure (longjmp out of the binding)
__declspec(noinline) bool need_image(lua_State* L) {
    if (ds::has_binary()) return true;
    lua_fail(L, "no image loaded in reverse-slop (slop.image.load a binary first)");
    return false;   // unreachable
}

const char* xref_kind_name_lua(hype::XrefType t) {
    switch (t) {
    case hype::XrefType::CodeCall:   return "call";
    case hype::XrefType::CodeJump:   return "jump";
    case hype::XrefType::DataRead:   return "read";
    case hype::XrefType::DataWrite:  return "write";
    case hype::XrefType::DataOffset: return "offset";
    default:                         return "other";
    }
}

// auto names (empty, or sub_<hex> with whatever padding or rva base the
// producer used) become the canonical sub_<VA uppercase hex>, the same name
// the mcp tools and the ui show; real names pass through
std::string display_name(std::string name, uint64_t va) {
    if (name.size() > 4 && name.compare(0, 4, "sub_") == 0 &&
        std::all_of(name.begin() + 4, name.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c)) != 0;
        }))
        name.clear();
    return name.empty() ? disasm::default_function_name(va) : name;
}

// lua errors longjmp past c++ destructors so never raise while a binary
// lock is alive, capture the error, drop the lock, then raise
// and while the lock is held read bin fields directly since the helpers
// re take the same mutex
hs::session_t* pinned_hype(std::string& err) {
    auto& bin = ds::get();
    if (!bin.ready) {
        err = "no image loaded in reverse-slop (slop.image.load a binary first)";
        return nullptr;
    }
    if (!bin.hype) {
        err = "hyperion engine unavailable for this image";
        return nullptr;
    }
    if (!bin.hype->ready()) {
        const std::string herr = bin.hype->error();
        if (!herr.empty()) err = "hyperion analysis failed, " + herr;
        else err = "hyperion analysis in progress, call slop.image.wait_ready() first";
        return nullptr;
    }
    return bin.hype.get();
}

// target

const char* arch_name(runtime::arch_t a) {
    switch (a) {
    case runtime::arch_t::x64: return "x64";
    case runtime::arch_t::x86: return "x86";
    default: return "unknown";
    }
}

int l_target_list(lua_State* L) {
    auto res = runtime::active().enum_processes();
    lua_createtable(L, 0, 64);
    if (!res.ok) return 1;
    int i = 1;
    for (const auto& p : res.items) {
        if (i > 4096) break;
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, p.pid);            lua_setfield(L, -2, "pid");
        lua_pushstring(L, p.name.c_str());    lua_setfield(L, -2, "name");
        lua_pushstring(L, arch_name(p.arch)); lua_setfield(L, -2, "arch");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_target_attach(lua_State* L) {
    const uint64_t pid = to_addr(L, 1);
    if (pid == 0 || pid > 0xFFFFFFFFull)
        return lua_fail(L, "bad pid");
    const bool ok = process::target_attach(static_cast<uint32_t>(pid));
    lua_pushboolean(L, ok);
    if (!ok) { lua_pushstring(L, "attach failed"); return 2; }
    const auto s = process::active_session();
    lua_pushstring(L, s ? s->name().c_str() : "");
    return 2;
}

int l_target_status(lua_State* L) {
    lua_createtable(L, 0, 4);
    lua_pushstring(L, runtime::active_badge());
    lua_setfield(L, -2, "backend");
    const auto s = process::active_session();
    const bool attached = s && s->valid();
    lua_pushboolean(L, attached);
    lua_setfield(L, -2, "attached");
    if (attached) {
        lua_pushinteger(L, s->pid());         lua_setfield(L, -2, "pid");
        lua_pushstring(L, s->name().c_str()); lua_setfield(L, -2, "name");
    }
    return 1;
}

// memory

// the shared_ptr keeps the session alive for the whole binding call even
// when another thread detaches meanwhile; null when nothing usable is attached
std::shared_ptr<runtime::session_t> live_session() {
    auto s = process::active_session();
    if (!s || !s->valid()) return nullptr;
    return s;
}

constexpr const char* kNoTarget = "no target attached";

std::vector<uint8_t> hex_decode_str(const std::string& hex, bool* ok) {
    std::vector<uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
        else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {}
        else { *ok = false; return out; }
    }
    if (clean.size() % 2) { *ok = false; return out; }
    for (size_t i = 0; i < clean.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(
            std::strtoul(clean.substr(i, 2).c_str(), nullptr, 16)));
    }
    *ok = true;
    return out;
}

std::string hex_encode(const uint8_t* p, size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2]     = kDigits[p[i] >> 4];
        out[i * 2 + 1] = kDigits[p[i] & 0xF];
    }
    return out;
}

// read_hex pushes the bytes as a lowercase hex string, read_bytes as a raw
// binary string; a short read returns the bytes that were read
int mem_read_common(lua_State* L, bool as_hex) {
    const uint64_t addr = to_addr(L, 1);
    const uint64_t len = to_addr(L, 2);
    if (len == 0 || len > (1ull << 20)) return lua_fail(L, "bad length (1..1048576)");
    std::string err;
    {
        const auto s = live_session();
        if (!s) {
            err = kNoTarget;
        } else {
            std::vector<uint8_t> buf(static_cast<size_t>(len));
            const auto io = s->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (!io.ok || io.bytes == 0) {
                char msg[96];
                std::snprintf(msg, sizeof(msg), "read failed at 0x%llX (error %u)",
                              static_cast<unsigned long long>(addr), io.error);
                err = msg;
            } else {
                const size_t n = std::min(io.bytes, buf.size());
                if (as_hex) {
                    const std::string hex = hex_encode(buf.data(), n);
                    lua_pushlstring(L, hex.data(), hex.size());
                } else {
                    lua_pushlstring(L, reinterpret_cast<const char*>(buf.data()), n);
                }
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_mem_read_hex(lua_State* L)   { return mem_read_common(L, true); }
int l_mem_read_bytes(lua_State* L) { return mem_read_common(L, false); }

int l_mem_write(lua_State* L) {
    const uint64_t addr = to_addr(L, 1);
    size_t hex_len = 0;
    const char* hex = luaL_checklstring(L, 2, &hex_len);
    std::string err;
    {
        bool ok = false;
        const auto bytes = hex_decode_str(std::string(hex, hex_len), &ok);
        const auto s = live_session();
        if (!ok || bytes.empty()) {
            err = "bad hex payload";
        } else if (!s) {
            err = kNoTarget;
        } else {
            const auto io = s->write(static_cast<uintptr_t>(addr), bytes.data(), bytes.size());
            if (!io.ok) {
                char msg[96];
                std::snprintf(msg, sizeof(msg), "write failed at 0x%llX (error %u)",
                              static_cast<unsigned long long>(addr), io.error);
                err = msg;
            } else {
                lua_pushinteger(L, static_cast<lua_Integer>(io.bytes));
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

memory::value_width_t parse_width(const std::string& w) {
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
    return memory::value_width_t::i32;
}

// stops the scan once the script budget is spent or the call is cancelled,
// so a scan over a large console address space cannot outlive the script
struct lua_reader_t final : memory::reader_t {
    runtime::session_t&       s;
    const script_ctx_t&       ctx;
    infra::cancel_source_t&   stop;
    lua_reader_t(runtime::session_t& sess, const script_ctx_t& c, infra::cancel_source_t& st)
        : s(sess), ctx(c), stop(st) {}
    bool read(uintptr_t addr, void* dst, size_t len) override {
        if (ctx.cancel.cancelled() || now_ms() > ctx.deadline_ms) {
            stop.request();
            return false;
        }
        auto io = s.read(addr, dst, len);
        return io.ok && io.bytes == len;
    }
    // one worker + large read-ahead chunks on a console (single ps4debug socket)
    memory::reader_hints_t hints() const noexcept override {
        return memory::hints_for_backend(runtime::active_kind());
    }
};

int l_mem_scan(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    auto field_s = [&](const char* k) -> std::optional<std::string> {
        lua_getfield(L, 1, k);
        const char* v = lua_tostring(L, -1);
        const std::string out = v ? v : "";
        lua_pop(L, 1);
        if (!v) return std::nullopt;
        return out;
    };
    auto field_n = [&](const char* k) -> std::optional<uint64_t> {
        lua_getfield(L, 1, k);
        const bool is_num = lua_isnumber(L, -1) != 0;
        const uint64_t v =
            is_num ? static_cast<uint64_t>(lua_tointeger(L, -1)) : 0;
        lua_pop(L, 1);
        if (!is_num) return std::nullopt;
        return v;
    };

    memory::scan_config_t cfg;
    const auto kind  = field_s("kind").value_or("exact");
    const auto width = parse_width(field_s("width").value_or("i32"));
    cfg.width = width;
    if (auto b = field_n("begin")) cfg.begin = static_cast<uintptr_t>(*b);
    if (auto e = field_n("end"))   cfg.end   = static_cast<uintptr_t>(*e);
    cfg.fast = memory::fastscan_method_t::alignment;
    cfg.fast_alignment = static_cast<uint32_t>(field_n("alignment").value_or(4));
    if (cfg.fast_alignment == 0) cfg.fast = memory::fastscan_method_t::off;

    if      (kind == "unknown")        cfg.type = memory::scan_type_t::unknown_initial;
    else if (kind == "between")        cfg.type = memory::scan_type_t::between;
    else if (kind == "bigger")         cfg.type = memory::scan_type_t::bigger_than;
    else if (kind == "smaller")        cfg.type = memory::scan_type_t::smaller_than;
    else if (kind == "increased")      cfg.type = memory::scan_type_t::increased;
    else if (kind == "increased_by")   cfg.type = memory::scan_type_t::increased_by;
    else if (kind == "decreased")      cfg.type = memory::scan_type_t::decreased;
    else if (kind == "decreased_by")   cfg.type = memory::scan_type_t::decreased_by;
    else if (kind == "changed")        cfg.type = memory::scan_type_t::changed;
    else if (kind == "unchanged")      cfg.type = memory::scan_type_t::unchanged;
    else                               cfg.type = memory::scan_type_t::exact_value;

    if (auto v = field_n("value")) {
        cfg.value1 = memory::value_to_double(width, *v);
    }
    if (auto v2 = field_n("value2")) {
        cfg.value2 = memory::value_to_double(width, *v2);
    }

    std::string err;
    {
        const auto sess = live_session();
        if (!sess) {
            err = kNoTarget;
        } else {
            infra::cancel_source_t stop;
            lua_reader_t reader(*sess, *ctx_of(L), stop);

            // Region set from the active backend (ps4 wire reads on a console)
            auto regions = runtime::target_scan_regions(sess->handle());

            memory::memscan_t engine;
            engine.first_scan(reader, std::move(regions), cfg, stop.token(), &err);
            if (stop.requested())
                err = ctx_of(L)->cancel.cancelled()
                          ? "mem.scan cancelled"
                          : "mem.scan stopped: script execution timed out";
            if (err.empty()) {
                const auto& hits = engine.results();
                lua_createtable(L, static_cast<int>(std::min<size_t>(hits.size(), 10000)), 0);
                int i = 1;
                for (const auto& h : hits) {
                    if (i > 10000) break;
                    lua_pushinteger(L, static_cast<lua_Integer>(h.address));
                    lua_rawseti(L, -2, i++);
                }
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// live disasm

int l_disasm_disassemble(lua_State* L) {
    const uint64_t addr = to_addr(L, 1);
    const uint64_t count_req = to_addr(L, 2);
    const int count = static_cast<int>(
        std::min<uint64_t>(count_req ? count_req : 32, 512));
    // one engine per thread, concurrent scripts never share decoder state
    thread_local disasm::engine_t eng;
    std::string err;
    {
        const auto s = live_session();
        if (!s) {
            err = kNoTarget;
        } else if (!eng.ok() && !eng.init()) {
            err = "zydis init failed";
        } else {
            std::vector<uint8_t> buf(static_cast<size_t>(count) * 16 + 16);
            const auto io = s->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (!io.ok || io.bytes == 0) {
                err = "cannot read code range";
            } else {
                const size_t avail = std::min(io.bytes, buf.size());
                lua_createtable(L, count, 0);
                size_t off = 0;
                for (int i = 1; i <= count && off < avail; ++i) {
                    auto insn = eng.decode(addr + off, buf.data() + off, avail - off);
                    if (!insn) break;
                    lua_pushstring(L, insn->text.c_str());
                    lua_rawseti(L, -2, i);
                    off += insn->length;
                }
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// analyze (loaded binary)

int l_analyze_packer(lua_State* L) {
    if (!need_image(L)) return 0;
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    // section-name and PE-header heuristics, meaningless on a Mach-O
    if (bin.format != disasm::image_format_t::pe)
        return lua_fail(L, (std::string("analyze.packer requires a PE image; the loaded image is ") +
                            disasm::image_arch_name(bin.arch) + " (" +
                            disasm::image_format_name(bin.format) + ")").c_str());
    auto v = analysis::packer_analyze(bin.pe, bin.file);
    lua_createtable(L, 0, 4);
    lua_pushboolean(L, v.packed);          lua_setfield(L, -2, "packed");
    lua_pushstring(L, v.family.c_str());   lua_setfield(L, -2, "family");
    lua_pushnumber(L, v.confidence);       lua_setfield(L, -2, "confidence");
    lua_pushnumber(L, v.file_entropy);     lua_setfield(L, -2, "file_entropy");
    return 1;
}

// static analysis over the shared session, the ida style surface
// renames and comments made here show up everywhere

int l_image_status(lua_State* L);

int l_image_load(lua_State* L) {
    size_t plen = 0;
    const char* path = luaL_checklstring(L, 1, &plen);
    const uint64_t base = lua_gettop(L) >= 2 ? to_addr(L, 2) : 0;
    if (!ds::load_file(std::string(path, plen), base))
        return lua_fail(L, ("failed to load " + std::string(path, plen) + ": " +
                            ds::last_load_error()).c_str());
    return l_image_status(L);
}

int l_image_load_from_target(lua_State* L) {
    if (!ds::load_from_target())
        return lua_fail(L, "no attached target or readable main module");
    return l_image_status(L);
}

int l_image_unload(lua_State* L) {
    ds::unload();
    lua_pushboolean(L, true);
    return 1;
}

int l_image_status(lua_State* L) {
    lua_createtable(L, 0, 12);
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    lua_pushboolean(L, bin.ready);          lua_setfield(L, -2, "ready");
    lua_pushstring(L, bin.name.c_str());    lua_setfield(L, -2, "name");
    lua_pushstring(L, bin.path.c_str());    lua_setfield(L, -2, "path");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.base));
    lua_setfield(L, -2, "base");
    if (!bin.ready) return 1;

    lua_pushstring(L, disasm::image_format_name(bin.format));
    lua_setfield(L, -2, "format");
    lua_pushstring(L, disasm::image_arch_name(bin.arch));
    lua_setfield(L, -2, "arch");
    lua_pushboolean(L, bin.encrypted);      lua_setfield(L, -2, "encrypted");
    if (bin.bundle) {
        lua_pushstring(L, bin.bundle->bundle_id.c_str());
        lua_setfield(L, -2, "bundle_id");
    }
    lua_pushinteger(L, static_cast<lua_Integer>(bin.base + bin.pe.entry_rva));
    lua_setfield(L, -2, "entry");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.image_base));
    lua_setfield(L, -2, "preferred_base");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.size_of_image));
    lua_setfield(L, -2, "size_of_image");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.fns.functions().size()));
    lua_setfield(L, -2, "functions");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.xrefs.total()));
    lua_setfield(L, -2, "xrefs");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.strings.size()));
    lua_setfield(L, -2, "strings");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.symbols.size()));
    lua_setfield(L, -2, "symbols");

    // Hyperion sub-table
    lua_createtable(L, 0, 8);
    const bool has_hype = bin.hype != nullptr;
    lua_pushboolean(L, has_hype);          lua_setfield(L, -2, "available");
    if (has_hype) {
        const bool rdy = bin.hype->ready();
        lua_pushboolean(L, rdy);           lua_setfield(L, -2, "ready");
        lua_pushnumber(L, bin.hype->progress());
        lua_setfield(L, -2, "progress");
        if (rdy) {
            const auto& db = bin.hype->db();
            lua_pushinteger(L, static_cast<lua_Integer>(db.funcs.size()));
            lua_setfield(L, -2, "functions");
            lua_pushinteger(L, static_cast<lua_Integer>(db.insns.size()));
            lua_setfield(L, -2, "instructions");
            lua_pushinteger(L, static_cast<lua_Integer>(db.xrefs.size()));
            lua_setfield(L, -2, "xrefs");
            lua_pushinteger(L, static_cast<lua_Integer>(db.vtables.size()));
            lua_setfield(L, -2, "vtables");
            lua_pushinteger(L, static_cast<lua_Integer>(db.globals.size()));
            lua_setfield(L, -2, "globals");
            lua_pushinteger(L, static_cast<lua_Integer>(bin.hype->rtti().classes().size()));
            lua_setfield(L, -2, "rtti_classes");
        }
        const std::string herr = bin.hype->error();
        if (!herr.empty()) {
            lua_pushstring(L, herr.c_str());
            lua_setfield(L, -2, "error");
        }
    }
    lua_setfield(L, -2, "hype");
    return 1;
}

int l_image_wait_ready(lua_State* L) {
    // never past the script budget: the hook cannot fire while we sleep here
    const uint64_t timeout_req = lua_gettop(L) >= 1 ? to_addr(L, 1) : 30000;
    const int64_t budget = std::min<int64_t>(
        static_cast<int64_t>(std::min<uint64_t>(timeout_req, 300000)), remaining_ms(L));
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(budget);
    for (;;) {
        std::string err;
        bool ready = false;
        {
            ds::binary_lock_t lock;
            auto& bin = ds::get();
            if (!bin.ready)
                err = "no image loaded in reverse-slop";
            else if (!bin.hype)
                err = "hyperion engine unavailable for this image";
            else if (bin.hype->ready())
                ready = true;
            else {
                const std::string herr = bin.hype->error();
                if (!herr.empty()) err = "hyperion analysis failed, " + herr;
            }
        }
        if (!err.empty()) return lua_fail(L, err.c_str());
        if (ready) { lua_pushboolean(L, true); return 1; }
        if (std::chrono::steady_clock::now() >= deadline) {
            lua_pushboolean(L, false);
            return 1;
        }
        if (ctx_of(L)->cancel.cancelled()) return lua_fail(L, "script cancelled");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

// slop.disasm: static disassembly over the loaded image

int l_disasm_decode(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t addr = to_addr(L, 1);
    const uint64_t count_req = lua_gettop(L) >= 2 ? to_addr(L, 2) : 32;
    const size_t count = static_cast<size_t>(
        std::min<uint64_t>(count_req ? count_req : 32, 512));

    std::string err;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        auto off = bin.offset_of(addr);
        if (!off) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "address %llx is outside the loaded image",
                          static_cast<unsigned long long>(addr));
            err = buf;
        } else {
            const size_t avail =
                bin.file.size() > *off ? bin.file.size() - *off : 0;
            if (avail == 0)
                err = "no bytes at address";
            else {
                lua_createtable(L, 0, static_cast<int>(count));
                size_t consumed = 0;
                size_t made = 0;
                disasm::insn_t insn;
                for (size_t i = 0; i < count && consumed < avail;) {
                    if (!hs::session_t::decode(
                            addr + consumed, bin.file.data() + *off + consumed,
                            avail - consumed, insn)) {
                        // 1-byte resync (same contract as the MCP path)
                        ++consumed;
                        continue;
                    }
                    ++made;
                    lua_createtable(L, 0, 7);
                    lua_pushinteger(L, static_cast<lua_Integer>(insn.va));
                    lua_setfield(L, -2, "addr");
                    lua_pushinteger(L, insn.length);
                    lua_setfield(L, -2, "len");
                    lua_pushstring(L, insn.text.c_str());
                    lua_setfield(L, -2, "text");
                    lua_pushlstring(L, reinterpret_cast<const char*>(insn.bytes),
                                    insn.length);
                    lua_setfield(L, -2, "bytes");
                    if (insn.has_rel_target) {
                        lua_pushinteger(L, static_cast<lua_Integer>(insn.rel_target));
                        lua_setfield(L, -2, "target");
                    }
                    if (insn.has_rip_rel) {
                        lua_pushinteger(L, static_cast<lua_Integer>(insn.rip_rel_target));
                        lua_setfield(L, -2, "rip_target");
                    }
                    lua_rawseti(L, -2, static_cast<lua_Integer>(made));
                    consumed += insn.length ? insn.length : 1;
                }
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_disasm_functions(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t limit_req = lua_gettop(L) >= 1 ? to_addr(L, 1) : 0;
    const size_t limit = static_cast<size_t>(
        std::min<uint64_t>(limit_req ? limit_req : 10000, 100000));

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    const auto& fns = bin.fns.functions();
    const bool hready = bin.hype && bin.hype->ready();
    const hype::AnalysisDB* hdb = hready ? &bin.hype->db() : nullptr;

    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(fns.size(), limit)));
    size_t i = 0;
    for (const auto& f : fns) {
        if (i >= limit) break;
        lua_createtable(L, 0, 6);
        lua_pushinteger(L, static_cast<lua_Integer>(f.va));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(f.size));
        lua_setfield(L, -2, "size");
        // Name: user symbol > hyperion name > sub_<VA>
        std::string name;
        const auto sit = bin.symbols.find(f.va);
        if (sit != bin.symbols.end()) {
            name = sit->second;
        } else if (hdb) {
            const auto nit = hdb->names.find(f.va);
            if (nit != hdb->names.end()) name = nit->second;
        }
        if (name.empty() && hdb) {
            const auto fit = hdb->funcs.find(f.va);
            if (fit != hdb->funcs.end() && !fit->second.name.empty())
                name = fit->second.name;
        }
        name = display_name(std::move(name), f.va);
        lua_pushstring(L, name.c_str());
        lua_setfield(L, -2, "name");
        if (hdb) {
            const auto fit = hdb->funcs.find(f.va);
            if (fit != hdb->funcs.end()) {
                const auto& hf = fit->second;
                lua_pushinteger(L, static_cast<lua_Integer>(hf.blocks.size()));
                lua_setfield(L, -2, "blocks");
                if (!hf.loops.empty()) {
                    lua_pushinteger(L, static_cast<lua_Integer>(hf.loops.size()));
                    lua_setfield(L, -2, "loops");
                }
                if (hf.noreturn) {
                    lua_pushboolean(L, true);
                    lua_setfield(L, -2, "noreturn");
                }
            }
        }
        lua_rawseti(L, -2, static_cast<lua_Integer>(++i));
    }
    return 1;
}

int l_disasm_function_at(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    if (bin.hype && bin.hype->ready()) {
        if (const hype::Function* f = bin.hype->function_at(va); f) {
            std::string name;
            const auto sit = bin.symbols.find(f->entry);
            if (sit != bin.symbols.end()) name = sit->second;
            if (name.empty()) {
                const auto nit = bin.hype->db().names.find(f->entry);
                if (nit != bin.hype->db().names.end()) name = nit->second;
            }
            if (name.empty() && !f->name.empty()) name = f->name;
            name = display_name(std::move(name), f->entry);
            lua_createtable(L, 0, 4);
            lua_pushinteger(L, static_cast<lua_Integer>(f->entry));
            lua_setfield(L, -2, "va");
            lua_pushstring(L, name.c_str());
            lua_setfield(L, -2, "name");
            if (!f->ranges.empty()) {
                const uint64_t lo = f->ranges.front().first;
                const uint64_t hi = f->ranges.back().second;
                lua_pushinteger(L, static_cast<lua_Integer>(hi - lo));
                lua_setfield(L, -2, "size");
            }
            lua_pushboolean(L, true);
            lua_setfield(L, -2, "hype");
            return 1;
        }
    }
    if (auto owner = bin.fns.containing(va); owner) {
        const uint64_t f = *owner;
        // Find the size from the index
        size_t size = 0;
        for (const auto& fn : bin.fns.functions())
            if (fn.va == f) { size = fn.size; break; }
        // Read the symbol directly, ds::symbol_name() re-takes this mutex
        // Fall back to sub_<VA> so a function entry is never nameless
        std::string name;
        const auto sit = bin.symbols.find(f);
        if (sit != bin.symbols.end()) name = sit->second;
        name = display_name(std::move(name), f);
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(f));
        lua_setfield(L, -2, "va");
        lua_pushstring(L, name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(size));
        lua_setfield(L, -2, "size");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int l_disasm_xrefs_to(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    if (bin.hype && bin.hype->ready()) {
        const auto& db = bin.hype->db();
        const auto  it = db.xrefs_to.find(va);
        lua_createtable(L, 0, 8);
        int i = 1;
        if (it != db.xrefs_to.end()) {
            // Dedup by from-address keeping the strongest kind (a direct
            // call/jmp emits both a Code* and a DataOffset record)
            auto kind_rank = [](hype::XrefType t) {
                switch (t) {
                case hype::XrefType::CodeCall:  return 5;
                case hype::XrefType::CodeJump:  return 4;
                case hype::XrefType::DataWrite: return 3;
                case hype::XrefType::DataRead:  return 2;
                default:                        return 1;
                }
            };
            std::map<uint64_t, std::pair<int, const char*>> best;
            for (const auto& x : it->second) {
                const char* k = xref_kind_name_lua(x.type);
                const int   r = kind_rank(x.type);
                const auto  b = best.find(x.from);
                if (b == best.end() || b->second.first < r)
                    best[x.from] = {r, k};
            }
            for (const auto& [from, p] : best) {
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(from));
                lua_setfield(L, -2, "from");
                lua_pushstring(L, p.second);
                lua_setfield(L, -2, "kind");
                lua_rawseti(L, -2, i++);
            }
        }
        return 1;
    }
    const auto& refs = bin.xrefs.refs_to(va);
    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(refs.size(), 10000)));
    int i = 1;
    for (const auto& r : refs) {
        if (i > 10000) break;
        lua_createtable(L, 0, 2);
        lua_pushinteger(L, static_cast<lua_Integer>(r.from));
        lua_setfield(L, -2, "from");
        lua_pushstring(L, r.kind == disasm::xref_kind_t::call ? "call"
                       : r.kind == disasm::xref_kind_t::jmp ? "jmp"
                                                            : "data");
        lua_setfield(L, -2, "kind");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_disasm_strings(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t min_req = lua_gettop(L) >= 1 ? to_addr(L, 1) : 4;
    const size_t min_chars = static_cast<size_t>(std::min<uint64_t>(min_req, 256));
    const uint64_t limit_req = lua_gettop(L) >= 2 ? to_addr(L, 2) : 10000;
    const size_t limit = static_cast<size_t>(
        std::min<uint64_t>(limit_req ? limit_req : 10000, 100000));

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    // Pre-scanned strings (built at load) are filtered by min_chars >= 4;
    // smaller thresholds re-extract from the file image
    std::vector<disasm::string_hit_t> hits;
    if (min_chars <= 4) {
        hits = bin.strings;
    } else {
        for (const auto& sec : bin.pe.sections) {
            if (sec.is_executable() || sec.raw_size == 0) continue;
            if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bin.file.size())
                continue;
            auto part = disasm::extract_strings(
                bin.file.data() + sec.raw_offset, sec.raw_size,
                bin.base + sec.rva, min_chars, 200'000);
            hits.insert(hits.end(),
                        std::make_move_iterator(part.begin()),
                        std::make_move_iterator(part.end()));
        }
    }

    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(hits.size(), limit)));
    int i = 1;
    for (const auto& h : hits) {
        if (static_cast<size_t>(i) > limit) break;
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(h.va));
        lua_setfield(L, -2, "va");
        lua_pushstring(L, h.text.c_str());
        lua_setfield(L, -2, "text");
        lua_pushboolean(L, h.utf16);
        lua_setfield(L, -2, "utf16");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_disasm_pe(lua_State* L) {
    if (!need_image(L)) return 0;
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    lua_createtable(L, 0, 10);
    lua_pushstring(L, disasm::image_format_name(bin.format));
    lua_setfield(L, -2, "format");
    lua_pushstring(L, disasm::image_arch_name(bin.arch));
    lua_setfield(L, -2, "arch");
    lua_pushboolean(L, bin.pe.pe32plus);      lua_setfield(L, -2, "pe32plus");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.image_base));
    lua_setfield(L, -2, "image_base");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.entry_rva));
    lua_setfield(L, -2, "entry_rva");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.size_of_image));
    lua_setfield(L, -2, "size_of_image");
    lua_pushinteger(L, bin.pe.machine);       lua_setfield(L, -2, "machine");
    lua_pushinteger(L, bin.pe.subsystem);     lua_setfield(L, -2, "subsystem");

    // sections
    lua_createtable(L, 0, static_cast<int>(bin.pe.sections.size()));
    int i = 1;
    for (const auto& sec : bin.pe.sections) {
        lua_createtable(L, 0, 6);
        lua_pushstring(L, sec.name);          lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(bin.base + sec.rva));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(sec.virtual_size));
        lua_setfield(L, -2, "vsize");
        lua_pushinteger(L, static_cast<lua_Integer>(sec.raw_size));
        lua_setfield(L, -2, "raw_size");
        lua_pushboolean(L, sec.is_executable());
        lua_setfield(L, -2, "exec");
        lua_pushboolean(L, (sec.characteristics & 0x80000000u) != 0);
        lua_setfield(L, -2, "writable");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "sections");

    // imports
    lua_createtable(L, 0, static_cast<int>(bin.pe.imports.size()));
    i = 1;
    for (const auto& dll : bin.pe.imports) {
        lua_createtable(L, 0, 2);
        lua_pushstring(L, dll.dll.c_str());   lua_setfield(L, -2, "dll");
        push_str_array(L, [&] {
            std::vector<std::string> names;
            names.reserve(dll.functions.size());
            for (const auto& fn : dll.functions) names.push_back(fn.name);
            return names;
        }());
        lua_setfield(L, -2, "functions");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "imports");

    // exports
    lua_createtable(L, 0, static_cast<int>(bin.pe.exports.size()));
    i = 1;
    for (const auto& e : bin.pe.exports) {
        lua_createtable(L, 0, 3);
        lua_pushstring(L, e.name.c_str());    lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(bin.base + e.rva));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, e.ordinal);        lua_setfield(L, -2, "ordinal");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "exports");
    return 1;
}

// slop.disasm: names / comments / bookmarks (persisted, shared with UI)

int l_name_get(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    std::string name;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        // user symbol > hyperion name > sub_<VA> (same precedence as decomp)
        // bin.symbols is read directly, symbol_name() re-takes this mutex
        const auto sit = bin.symbols.find(va);
        if (sit != bin.symbols.end()) name = sit->second;
        else if (bin.hype && bin.hype->ready()) {
            const auto nit = bin.hype->db().names.find(va);
            if (nit != bin.hype->db().names.end()) name = nit->second;
        }
        if (name.empty()) {
            // a legacy-index function starting here gets the canonical sub_ name
            for (const auto& f : bin.fns.functions())
                if (f.va == va) {
                    name = disasm::default_function_name(va);
                    break;
                }
        } else {
            name = display_name(std::move(name), va);
        }
    }
    if (name.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, name.c_str());
    return 1;
}

int l_name_set(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    size_t nlen = 0;
    const char* name = luaL_checklstring(L, 2, &nlen);
    ds::set_symbol(va, std::string(name, nlen));   // persisted; UI sees it
    lua_pushboolean(L, true);
    return 1;
}

int l_comment_get(lua_State* L) {
    if (!need_image(L)) return 0;
    const auto text = ds::comment_for(to_addr(L, 1));
    if (text.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, text.c_str());
    return 1;
}

int l_comment_set(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    size_t tlen = 0;
    const char* text = luaL_checklstring(L, 2, &tlen);
    ds::set_comment(va, std::string(text, tlen));
    lua_pushboolean(L, true);
    return 1;
}

int l_bookmark_toggle(lua_State* L) {
    if (!need_image(L)) return 0;
    lua_pushboolean(L, ds::toggle_bookmark(to_addr(L, 1)));
    return 1;
}

int l_bookmarks(lua_State* L) {
    if (!need_image(L)) return 0;
    const auto marks = ds::bookmarks_snapshot();
    lua_createtable(L, static_cast<int>(std::min<size_t>(marks.size(), 10000)), 0);
    int i = 1;
    for (uint64_t va : marks) {
        if (i > 10000) break;
        lua_pushinteger(L, static_cast<lua_Integer>(va));
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// slop.disasm: raw image bytes

int l_image_bytes(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t addr = to_addr(L, 1);
    const uint64_t len = lua_gettop(L) >= 2 ? to_addr(L, 2) : 16;
    if (len == 0 || len > (1ull << 20))
        return lua_fail(L, "bad length (1..1048576)");
    std::string err;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        auto off = bin.offset_of(addr);
        if (!off) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "address %llx is outside the loaded image",
                          static_cast<unsigned long long>(addr));
            err = buf;
        } else {
            const size_t avail =
                bin.file.size() > *off ? bin.file.size() - *off : 0;
            const size_t take = std::min<size_t>(avail, static_cast<size_t>(len));
            if (take == 0)
                err = "no bytes at address";
            else
                lua_pushlstring(L,
                                reinterpret_cast<const char*>(bin.file.data() + *off),
                                take);
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// slop.decomp: hyperion decompiler + rich analysis

int l_decomp_function(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        const hype::Function* f =
            hype ? hype->function_at(va) : nullptr;
        if (hype && !f) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "no hyperion function contains address %llx",
                          static_cast<unsigned long long>(va));
            err = buf;
        }
        if (err.empty()) {
            const uint64_t entry = f->entry;

            std::vector<hype::PseudoLine> lines;
            std::string derr;
            if (!hype->decompile(va, lines, derr)) {
                err = derr.empty() ? "decompile failed" : derr;
            } else {
                auto& bin = ds::get();
                const auto& db = hype->db();

                // display name precedence, user symbol then hyperion name then
                // sub_<VA>, read directly since the helper re takes the mutex
                std::string fname;
                const auto sit = bin.symbols.find(entry);
                if (sit != bin.symbols.end()) fname = sit->second;
                if (fname.empty()) {
                    const auto nit = db.names.find(entry);
                    if (nit != db.names.end()) fname = nit->second;
                }
                fname = display_name(std::move(fname), entry);

                lua_createtable(L, 0, 5);
                lua_pushinteger(L, static_cast<lua_Integer>(entry));
                lua_setfield(L, -2, "va");
                lua_pushstring(L, fname.c_str());
                lua_setfield(L, -2, "name");

                // signature
                std::string signature;
                {
                    const auto it = db.signatures.find(entry);
                    if (it != db.signatures.end()) {
                        const auto& s = it->second;
                        signature = s.return_type + " " + fname + "(";
                        for (size_t i = 0; i < s.param_names.size(); ++i) {
                            if (i) signature += ", ";
                            signature += s.param_types[i] + " " + s.param_names[i];
                        }
                        signature += ")";
                    } else {
                        signature = "void " + fname + "()";
                    }
                }
                lua_pushstring(L, signature.c_str());
                lua_setfield(L, -2, "signature");

                // lines: {addr, indent, text}
                lua_createtable(L, 0,
                                static_cast<int>(std::min<size_t>(lines.size(), 20000)));
                int i = 1;
                for (const auto& l : lines) {
                    if (i > 20000) break;
                    lua_createtable(L, 0, 3);
                    if (l.addr) {
                        lua_pushinteger(L, static_cast<lua_Integer>(l.addr));
                        lua_setfield(L, -2, "addr");
                    }
                    lua_pushinteger(L, l.indent);
                    lua_setfield(L, -2, "indent");
                    lua_pushstring(L, l.text.c_str());
                    lua_setfield(L, -2, "text");
                    lua_rawseti(L, -2, i++);
                }
                lua_setfield(L, -2, "lines");
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_blocks(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        const hype::Function* f = hype ? hype->function_at(va) : nullptr;
        if (hype && !f) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "no hyperion function contains address %llx",
                          static_cast<unsigned long long>(va));
            err = buf;
        }
        if (err.empty()) {
            lua_createtable(L, 0, 4);
            lua_pushinteger(L, static_cast<lua_Integer>(f->entry));
            lua_setfield(L, -2, "entry");

            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(f->blocks.size(), 20000)));
            int i = 1;
            for (const auto& [start, bb] : f->blocks) {
                if (i > 20000) break;
                lua_createtable(L, 0, 6);
                lua_pushinteger(L, static_cast<lua_Integer>(start));
                lua_setfield(L, -2, "start");
                lua_pushinteger(L, static_cast<lua_Integer>(bb.end));
                lua_setfield(L, -2, "end_va");
                lua_pushinteger(L, static_cast<lua_Integer>(bb.insns.size()));
                lua_setfield(L, -2, "insns");
                lua_createtable(L, 0, 4);
                int j = 1;
                for (auto s : bb.succs) {
                    lua_pushinteger(L, static_cast<lua_Integer>(s));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "succs");
                lua_createtable(L, 0, 4);
                j = 1;
                for (auto p : bb.preds) {
                    lua_pushinteger(L, static_cast<lua_Integer>(p));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "preds");
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "blocks");

            lua_createtable(L, 0, 4);
            i = 1;
            for (const auto& lp : f->loops) {
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(lp.header));
                lua_setfield(L, -2, "header");
                lua_pushinteger(L, static_cast<lua_Integer>(lp.back_edge_src));
                lua_setfield(L, -2, "back_edge_src");
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "loops");
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_vtables(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& vts = hype->db().vtables;
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(vts.size(), 10000)));
            int i = 1;
            for (const auto& vt : vts) {
                if (i > 10000) break;
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(vt.addr));
                lua_setfield(L, -2, "va");
                lua_createtable(L, 0,
                                static_cast<int>(std::min<size_t>(vt.entries.size(), 512)));
                int j = 1;
                for (auto e : vt.entries) {
                    if (j > 512) break;
                    lua_pushinteger(L, static_cast<lua_Integer>(e));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "entries");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_globals(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& globs = hype->db().globals;
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(globs.size(), 20000)));
            int i = 1;
            for (const auto& [va, g] : globs) {
                if (i > 20000) break;
                lua_createtable(L, 0, 3);
                lua_pushinteger(L, static_cast<lua_Integer>(va));
                lua_setfield(L, -2, "va");
                lua_pushinteger(L, static_cast<lua_Integer>(g.size));
                lua_setfield(L, -2, "size");
                lua_pushstring(L, g.name.c_str());
                lua_setfield(L, -2, "name");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_rtti(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& classes = hype->rtti().classes();
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(classes.size(), 10000)));
            int i = 1;
            for (const auto& c : classes) {
                if (i > 10000) break;
                lua_createtable(L, 0, 5);
                lua_pushstring(L, c.demangled_name.empty() ? c.mangled_name.c_str()
                                                           : c.demangled_name.c_str());
                lua_setfield(L, -2, "name");
                lua_pushinteger(L, static_cast<lua_Integer>(c.type_descriptor));
                lua_setfield(L, -2, "type_descriptor");
                lua_pushinteger(L, static_cast<lua_Integer>(c.complete_locator));
                lua_setfield(L, -2, "locator");
                lua_pushinteger(L, static_cast<lua_Integer>(c.vtable));
                lua_setfield(L, -2, "vtable");
                lua_createtable(L, 0, 8);
                int j = 1;
                for (auto m : c.methods) {
                    if (j > 512) break;
                    lua_pushinteger(L, static_cast<lua_Integer>(m));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "methods");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// timeout hook

// Serialize a Lua return value into the captured output (lua-style summary;
// depth-capped so a huge table can't flood the output buffer)
void append_value(lua_State* L, int idx, int depth) {
    if (depth > 4) { out_append(L, "..."); return; }
    // normalize to an absolute index, pushes below would shift a negative
    // idx onto the wrong slots
    const int at = lua_absindex(L, idx);
    const int t = lua_type(L, at);
    switch (t) {
    case LUA_TNIL:
        out_append(L, "nil");
        break;
    case LUA_TBOOLEAN:
        out_append(L, lua_toboolean(L, at) ? "true" : "false");
        break;
    case LUA_TNUMBER:
        if (lua_isinteger(L, at))
            out_append(L, std::to_string(lua_tointeger(L, at)));
        else
            out_append(L, std::to_string(lua_tonumber(L, at)));
        break;
    case LUA_TSTRING: {
        size_t len = 0;
        const char* s = lua_tolstring(L, at, &len);
        out_append(L, "\"");
        out_append(L, std::string(s ? s : "", std::min<size_t>(len, 4096)));
        out_append(L, "\"");
        break;
    }
    case LUA_TTABLE: {
        // Render as {v1, v2, ...} over the array part first, then string
        // key/value pairs
        out_append(L, "{");
        bool first = true;
        lua_Integer n = 0;
        lua_len(L, at);
        n = lua_tointeger(L, -1);
        lua_pop(L, 1);
        int shown = 0;
        for (lua_Integer i = 1; i <= n && shown < 32; ++i, ++shown) {
            if (!first) out_append(L, ", ");
            first = false;
            lua_geti(L, at, i);
            append_value(L, -1, depth + 1);
            lua_pop(L, 1);
        }
        if (shown >= 32 && n > shown) out_append(L, ", ...");
        // String-keyed fields after the array part
        lua_pushnil(L);
        int pairs_shown = 0;
        while (lua_next(L, at) != 0) {
            if (lua_type(L, -2) == LUA_TSTRING && pairs_shown < 32) {
                if (!first) out_append(L, ", ");
                first = false;
                size_t klen = 0;
                const char* k = lua_tolstring(L, -2, &klen);
                out_append(L, std::string(k ? k : "", klen));
                out_append(L, "=");
                append_value(L, -1, depth + 1);
                ++pairs_shown;
            } else if (pairs_shown >= 32) {
                // stop scanning, enough
            }
            lua_pop(L, 1);
        }
        out_append(L, "}");
        break;
    }
    default:
        out_append(L, lua_typename(L, t));
        break;
    }
}

// count hook: every kHookInstructions vm instructions, raise once the
// budget is spent or the caller cancelled
void timeout_hook(lua_State* L, lua_Debug*) {
    const script_ctx_t* c = ctx_of(L);
    const char* why = c->cancel.cancelled()       ? "script cancelled"
                    : now_ms() > c->deadline_ms   ? "script execution timed out"
                                                  : nullptr;
    if (!why) return;
    luaL_where(L, 1);
    lua_pushstring(L, why);
    lua_concat(L, 2);
    lua_error(L);
}

// per binding serialization with the mcp tools: the tool mutex is taken for
// one binding call, never across the script. waiting for it honours the
// script deadline and cancellation, and the binding runs under lua_pcall so
// the mutex is released before any lua error propagates
bool acquire_tool_lock(const script_ctx_t* c) {
    if (!c->tool_mu) return true;
    for (;;) {
        if (c->tool_mu->try_lock()) return true;
        if (c->cancel.cancelled() || now_ms() > c->deadline_ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int locked_call(lua_State* L, lua_CFunction f) {
    const script_ctx_t* c = ctx_of(L);
    const int nargs = lua_gettop(L);
    lua_pushcfunction(L, f);
    lua_insert(L, 1);
    if (!acquire_tool_lock(c))
        return lua_fail(L, c->cancel.cancelled()
                               ? "script cancelled while waiting for the tool lock"
                               : "script execution timed out while waiting for the tool lock");
    const int st = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (c->tool_mu) c->tool_mu->unlock();
    if (st != LUA_OK) return lua_error(L);
    return lua_gettop(L);
}

template <lua_CFunction F>
int locked(lua_State* L) {
    return locked_call(L, F);
}

// json <-> lua for the bindings that run mcp actions

constexpr int kMaxJsonDepth = 32;

void push_json(lua_State* L, const json& j, int depth) {
    if (depth > kMaxJsonDepth) { lua_pushnil(L); return; }
    switch (j.type()) {
    case json::value_t::object: {
        lua_createtable(L, 0, static_cast<int>(std::min<size_t>(j.size(), 4096)));
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.value().is_null()) continue;
            push_json(L, it.value(), depth + 1);
            lua_setfield(L, -2, it.key().c_str());
        }
        return;
    }
    case json::value_t::array: {
        lua_createtable(L, static_cast<int>(std::min<size_t>(j.size(), 65536)), 0);
        lua_Integer i = 1;
        for (const auto& v : j) {
            push_json(L, v, depth + 1);
            lua_rawseti(L, -2, i++);
        }
        return;
    }
    case json::value_t::string: {
        const auto& s = j.get_ref<const std::string&>();
        lua_pushlstring(L, s.data(), s.size());
        return;
    }
    case json::value_t::boolean:
        lua_pushboolean(L, j.get<bool>());
        return;
    case json::value_t::number_unsigned:
        // addresses keep their 64-bit pattern (lua integers are signed)
        lua_pushinteger(L, static_cast<lua_Integer>(j.get<uint64_t>()));
        return;
    case json::value_t::number_integer:
        lua_pushinteger(L, static_cast<lua_Integer>(j.get<int64_t>()));
        return;
    case json::value_t::number_float:
        lua_pushnumber(L, j.get<double>());
        return;
    default:
        lua_pushnil(L);
        return;
    }
}

// a sequence 1..n becomes an array, anything else an object; integers keep
// their bit pattern as unsigned so high addresses survive. err is set for
// values json cannot carry (functions, userdata, cycles past the depth cap)
json lua_to_json(lua_State* L, int idx, int depth, std::string& err) {
    const int at = lua_absindex(L, idx);
    switch (lua_type(L, at)) {
    case LUA_TNIL:     return nullptr;
    case LUA_TBOOLEAN: return lua_toboolean(L, at) != 0;
    case LUA_TNUMBER:
        if (lua_isinteger(L, at))
            return static_cast<uint64_t>(lua_tointeger(L, at));
        return lua_tonumber(L, at);
    case LUA_TSTRING: {
        size_t len = 0;
        const char* s = lua_tolstring(L, at, &len);
        return std::string(s, len);
    }
    case LUA_TTABLE: {
        if (depth > kMaxJsonDepth) { err = "table nesting too deep"; return nullptr; }
        const lua_Unsigned n = lua_rawlen(L, at);
        size_t keys = 0;
        bool seq = true;
        lua_pushnil(L);
        while (lua_next(L, at) != 0) {
            ++keys;
            if (!lua_isinteger(L, -2) || lua_tointeger(L, -2) < 1 ||
                static_cast<lua_Unsigned>(lua_tointeger(L, -2)) > n)
                seq = false;
            lua_pop(L, 1);
        }
        if (keys > 0 && seq && keys == n) {
            json arr = json::array();
            for (lua_Unsigned i = 1; i <= n && err.empty(); ++i) {
                lua_rawgeti(L, at, static_cast<lua_Integer>(i));
                arr.push_back(lua_to_json(L, -1, depth + 1, err));
                lua_pop(L, 1);
            }
            return arr;
        }
        json obj = json::object();
        lua_pushnil(L);
        while (err.empty() && lua_next(L, at) != 0) {
            std::string key;
            if (lua_type(L, -2) == LUA_TSTRING) {
                key = lua_tostring(L, -2);
            } else if (lua_isinteger(L, -2)) {
                key = std::to_string(lua_tointeger(L, -2));
            } else {
                err = "table keys must be strings or integers";
                lua_pop(L, 2);
                break;
            }
            obj[key] = lua_to_json(L, -1, depth + 1, err);
            lua_pop(L, 1);
        }
        return obj;
    }
    default:
        err = std::string("cannot pass a ") + luaL_typename(L, at) + " to an mcp action";
        return nullptr;
    }
}

// argument access for the mcp-action bindings that never raises: problems
// land in err so no lua error fires while the json/string locals are alive
struct arg_reader_t {
    lua_State*   L;
    std::string& err;

    bool has(int idx) const { return !lua_isnoneornil(L, idx); }

    uint64_t u64(int idx, const char* what) {
        if (!has(idx)) {
            if (err.empty()) err = std::string(what) + " required";
            return 0;
        }
        return to_addr(L, idx);
    }

    std::string str(int idx, const char* what) {
        if (lua_type(L, idx) != LUA_TSTRING) {
            if (err.empty()) err = std::string(what) + " must be a string";
            return {};
        }
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        return std::string(s, len);
    }

    // a blocking wait never outlives the script: the requested timeout is
    // cut to the remaining budget, a spent budget is the timeout error
    int64_t budget(int idx, int64_t def) {
        const int64_t req = has(idx) ? static_cast<int64_t>(to_addr(L, idx)) : def;
        const int64_t left = remaining_ms(L);
        if (left <= 0 && err.empty()) err = "script execution timed out";
        return std::clamp<int64_t>(req, 1, std::max<int64_t>(1, std::min<int64_t>(left, kMaxTimeoutMs)));
    }
};

using fill_fn = void (*)(arg_reader_t&, json&);

// builds the arguments, runs one mcp tool call (call_tool takes the tool
// mutex itself, so these bindings are never wrapped in locked<>) and leaves
// either the result table (true) or the error message (false) on the stack
bool mcp_action_impl(lua_State* L, const char* tool, const char* action, fill_fn fill) {
    std::string err;
    json args = {{"action", action}};
    arg_reader_t rd{L, err};
    if (fill) fill(rd, args);
    if (err.empty()) {
        bool is_error = false;
        const json out = mcp::call_tool(tool, args, is_error, ctx_of(L)->cancel);
        if (!is_error) {
            push_json(L, out, 0);
            return true;
        }
        const auto it = out.find("error");
        err = it != out.end() && it->is_string() ? it->get<std::string>()
                                                  : std::string(tool) + " action failed";
    }
    lua_pushlstring(L, err.data(), err.size());
    return false;
}

// raises from a frame without C++ locals
__declspec(noinline) int mcp_action(lua_State* L, const char* tool, const char* action,
                                    fill_fn fill = nullptr) {
    if (mcp_action_impl(L, tool, action, fill)) return 1;
    luaL_where(L, 1);
    lua_insert(L, -2);
    lua_concat(L, 2);
    return lua_error(L);
}

// slop.ps4: console connection (target ps4_* / debugger status)

void fill_host_port(arg_reader_t& a, json& j) {
    j["host"] = a.str(1, "host");
    if (a.has(2)) j["port"] = a.u64(2, "port");
}

int l_ps4_connect(lua_State* L)    { return mcp_action(L, "target", "ps4_connect", fill_host_port); }
int l_ps4_auto(lua_State* L)       { return mcp_action(L, "target", "ps4_auto", fill_host_port); }
int l_ps4_disconnect(lua_State* L) { return mcp_action(L, "target", "ps4_disconnect"); }
int l_ps4_status(lua_State* L)     { return mcp_action(L, "debugger", "status"); }

// slop.debugger: the debugger ps4_* actions

int l_dbg_status(lua_State* L)     { return mcp_action(L, "debugger", "ps4_status"); }
int l_dbg_detach(lua_State* L)     { return mcp_action(L, "debugger", "ps4_detach"); }
int l_dbg_bp_list(lua_State* L)    { return mcp_action(L, "debugger", "ps4_bp_list"); }
int l_dbg_watch_list(lua_State* L) { return mcp_action(L, "debugger", "ps4_watch_list"); }

int l_dbg_attach(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_attach", [](arg_reader_t& a, json& j) {
        j["pid"] = a.u64(1, "pid");
    });
}

int l_dbg_bp_set(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_bp_set", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        if (a.has(2)) j["index"] = a.u64(2, "index");
    });
}

int l_dbg_bp_clear(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_bp_clear", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
    });
}

int l_dbg_watch_set(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_watch_set", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        if (a.has(2)) j["len"] = a.u64(2, "len");
        if (a.has(3)) j["type"] = a.u64(3, "type");
    });
}

int l_dbg_watch_clear(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_watch_clear", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
    });
}

int l_dbg_continue(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_continue", [](arg_reader_t& a, json& j) {
        if (a.has(1)) j["stop"] = a.u64(1, "stop");
    });
}

int l_dbg_step(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_step", [](arg_reader_t& a, json& j) {
        if (a.has(1)) j["lwpid"] = a.u64(1, "lwpid");
    });
}

int l_dbg_suspend(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_suspend", [](arg_reader_t& a, json& j) {
        j["lwpid"] = a.u64(1, "lwpid");
    });
}

int l_dbg_resume(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_resume", [](arg_reader_t& a, json& j) {
        j["lwpid"] = a.u64(1, "lwpid");
    });
}

int l_dbg_wait(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_wait", [](arg_reader_t& a, json& j) {
        j["timeout_ms"] = a.budget(1, 5000);
    });
}

int l_dbg_events(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_events", [](arg_reader_t& a, json& j) {
        if (a.has(1)) j["max"] = a.u64(1, "max");
    });
}

int l_dbg_regs(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_regs", [](arg_reader_t& a, json& j) {
        if (a.has(1)) j["lwpid"] = a.u64(1, "lwpid");
    });
}

int l_dbg_set_reg(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_set_reg", [](arg_reader_t& a, json& j) {
        j["lwpid"] = a.u64(1, "lwpid");
        j["name"]  = a.str(2, "name");
        j["value"] = a.u64(3, "value");
    });
}

int l_dbg_callstack(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_callstack", [](arg_reader_t& a, json& j) {
        if (a.has(1)) j["lwpid"] = a.u64(1, "lwpid");
        if (a.has(2)) j["depth"] = a.u64(2, "depth");
    });
}

int l_dbg_call(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_call", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        if (a.has(2)) {
            if (lua_type(a.L, 2) != LUA_TTABLE) {
                if (a.err.empty()) a.err = "debugger.call: args must be a table";
                return;
            }
            const lua_Unsigned n = lua_rawlen(a.L, 2);
            if (n > 6) {
                if (a.err.empty())
                    a.err = "debugger.call: at most 6 arguments (rdi,rsi,rdx,rcx,r8,r9)";
                return;
            }
            json args = json::array();
            for (lua_Unsigned i = 1; i <= n; ++i) {
                lua_rawgeti(a.L, 2, static_cast<lua_Integer>(i));
                args.push_back(to_addr(a.L, -1));
                lua_pop(a.L, 1);
            }
            j["args"] = std::move(args);
        }
        if (a.has(3)) j["pid"] = a.u64(3, "pid");
    });
}

int l_dbg_run_until(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_until", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        j["timeout_ms"] = a.budget(2, 30000);
    });
}

int l_dbg_find_write(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_find_write", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        if (a.has(2)) j["len"] = a.u64(2, "len");
        j["timeout_ms"] = a.budget(3, 30000);
    });
}

int l_dbg_trace_calls(lua_State* L) {
    return mcp_action(L, "debugger", "ps4_trace_calls", [](arg_reader_t& a, json& j) {
        j["addr"] = a.u64(1, "addr");
        if (a.has(2)) j["count"] = a.u64(2, "count");
        j["timeout_ms"] = a.budget(3, 5000);
    });
}

// actions that read host files are host access, not console access
bool host_file_action(const std::string& action) {
    return action == "ps4_elf_rpc" || action == "ps4_elf_load";
}

// slop.debugger.action(name, params): any debugger ps4_* action by name
// ("bp_set" and "ps4_bp_set" both work); params is a table of the mcp args.
// the action name is resolved into args["action"] by the fill step
int l_dbg_action(lua_State* L) {
    return mcp_action(L, "debugger", "", [](arg_reader_t& a, json& j) {
        std::string action = a.str(1, "action name");
        if (!a.err.empty()) return;
        if (a.has(2)) {
            if (lua_type(a.L, 2) != LUA_TTABLE) {
                a.err = "debugger.action: params must be a table";
                return;
            }
            json params = lua_to_json(a.L, 2, 0, a.err);
            if (!a.err.empty()) return;
            if (params.is_object()) j.update(params);   // {} decodes as an object too
        }
        if (action.rfind("ps4_", 0) != 0) action = "ps4_" + action;
        if (host_file_action(action) && !ctx_of(a.L)->unsafe) {
            a.err = action + " reads a host file; it needs the script_unsafe setting";
            return;
        }
        j["action"] = std::move(action);
    });
}

// sandbox

// load() with the mode forced to text: binary chunks can break out of the vm
int l_load_text(lua_State* L) {
    const int keep = lua_gettop(L) >= 4 ? 4 : 3;   // env stays absent unless passed
    lua_settop(L, keep);
    lua_pushliteral(L, "t");
    lua_replace(L, 3);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, keep, LUA_MULTRET);
    return lua_gettop(L);
}

void open_sandboxed(lua_State* L) {
    static const luaL_Reg kLibs[] = {
        {LUA_GNAME,       luaopen_base},
        {LUA_STRLIBNAME,  luaopen_string},
        {LUA_TABLIBNAME,  luaopen_table},
        {LUA_MATHLIBNAME, luaopen_math},
        {LUA_UTF8LIBNAME, luaopen_utf8},
    };
    for (const auto& lib : kLibs) {
        luaL_requiref(L, lib.name, lib.func, 1);
        lua_pop(L, 1);
    }
    // base without the file loaders, text-only load
    lua_pushnil(L);
    lua_setglobal(L, "dofile");
    lua_pushnil(L);
    lua_setglobal(L, "loadfile");
    lua_getglobal(L, "load");
    lua_pushcclosure(L, l_load_text, 1);
    lua_setglobal(L, "load");
    // os reduced to the clock functions, the module itself stays unreachable
    luaL_requiref(L, LUA_OSLIBNAME, luaopen_os, 0);
    lua_createtable(L, 0, 3);
    for (const char* fn : {"clock", "time", "difftime"}) {
        lua_getfield(L, -2, fn);
        lua_setfield(L, -2, fn);
    }
    lua_setglobal(L, "os");
    lua_pop(L, 1);
}

void set_funcs(lua_State* L, const luaL_Reg* regs) {
    for (; regs->name; ++regs) {
        lua_pushcfunction(L, regs->func);
        lua_setfield(L, -2, regs->name);
    }
}

// opens the libraries and builds the slop table; runs under lua_pcall so a
// memory-limit failure during setup is an error, not a panic
int open_env(lua_State* L) {
    if (ctx_of(L)->unsafe) luaL_openlibs(L);
    else open_sandboxed(L);

    lua_pushcfunction(L, l_log);
    lua_setglobal(L, "print");

    lua_createtable(L, 0, 12);
    lua_pushcfunction(L, l_version); lua_setfield(L, -2, "version");
    lua_pushcfunction(L, l_log);     lua_setfield(L, -2, "log");

    static const luaL_Reg kTarget[] = {
        {"list",   locked<l_target_list>},
        {"attach", locked<l_target_attach>},
        {"status", locked<l_target_status>},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 3);
    set_funcs(L, kTarget);
    lua_setfield(L, -2, "target");

    static const luaL_Reg kMem[] = {
        {"read_hex",   locked<l_mem_read_hex>},
        {"read_bytes", locked<l_mem_read_bytes>},
        {"write_hex",  locked<l_mem_write>},
        {"scan",       locked<l_mem_scan>},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 4);
    set_funcs(L, kMem);
    lua_setfield(L, -2, "mem");

    static const luaL_Reg kDisasm[] = {
        // live-target disassembly (attached process memory)
        {"disassemble",     locked<l_disasm_disassemble>},
        // static analysis over the loaded image, the IDA-style surface
        {"decode",          locked<l_disasm_decode>},
        {"functions",       locked<l_disasm_functions>},
        {"function_at",     locked<l_disasm_function_at>},
        {"xrefs_to",        locked<l_disasm_xrefs_to>},
        {"strings",         locked<l_disasm_strings>},
        {"pe",              locked<l_disasm_pe>},
        {"bytes",           locked<l_image_bytes>},
        // names/comments/bookmarks, persisted per binary hash, shared with
        // the UI and the MCP tools
        {"name",            locked<l_name_get>},
        {"set_name",        locked<l_name_set>},
        {"comment",         locked<l_comment_get>},
        {"set_comment",     locked<l_comment_set>},
        {"bookmark_toggle", locked<l_bookmark_toggle>},
        {"bookmarks",       locked<l_bookmarks>},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 14);
    set_funcs(L, kDisasm);
    lua_setfield(L, -2, "disasm");

    static const luaL_Reg kAnalyze[] = {
        {"packer", locked<l_analyze_packer>},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 1);
    set_funcs(L, kAnalyze);
    lua_setfield(L, -2, "analyze");

    // wait_ready only polls under the binary lock, holding the tool mutex
    // while it sleeps would stall every other tool
    static const luaL_Reg kImage[] = {
        {"load",             locked<l_image_load>},
        {"load_from_target", locked<l_image_load_from_target>},
        {"unload",           locked<l_image_unload>},
        {"status",           locked<l_image_status>},
        {"wait_ready",       l_image_wait_ready},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 5);
    set_funcs(L, kImage);
    lua_setfield(L, -2, "image");

    // decompiler + hyperion-rich analysis (requires analysis-ready session)
    static const luaL_Reg kDecomp[] = {
        {"decompile", locked<l_decomp_function>},
        {"blocks",    locked<l_decomp_blocks>},
        {"vtables",   locked<l_decomp_vtables>},
        {"globals",   locked<l_decomp_globals>},
        {"rtti",      locked<l_decomp_rtti>},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 5);
    set_funcs(L, kDecomp);
    lua_setfield(L, -2, "decomp");

    // console connection; each call is one mcp action (call_tool locks)
    static const luaL_Reg kPs4[] = {
        {"connect",    l_ps4_connect},
        {"disconnect", l_ps4_disconnect},
        {"auto",       l_ps4_auto},
        {"status",     l_ps4_status},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 4);
    set_funcs(L, kPs4);
    lua_setfield(L, -2, "ps4");

    static const luaL_Reg kDebugger[] = {
        {"status",      l_dbg_status},
        {"attach",      l_dbg_attach},
        {"detach",      l_dbg_detach},
        {"bp_set",      l_dbg_bp_set},
        {"bp_clear",    l_dbg_bp_clear},
        {"bp_list",     l_dbg_bp_list},
        {"watch_set",   l_dbg_watch_set},
        {"watch_clear", l_dbg_watch_clear},
        {"watch_list",  l_dbg_watch_list},
        {"continue",    l_dbg_continue},
        {"step",        l_dbg_step},
        {"suspend",     l_dbg_suspend},
        {"resume",      l_dbg_resume},
        {"wait",        l_dbg_wait},
        {"events",      l_dbg_events},
        {"regs",        l_dbg_regs},
        {"set_reg",     l_dbg_set_reg},
        {"callstack",   l_dbg_callstack},
        {"call",        l_dbg_call},
        {"run_until",   l_dbg_run_until},
        {"find_write",  l_dbg_find_write},
        {"trace_calls", l_dbg_trace_calls},
        {"action",      l_dbg_action},
        {nullptr, nullptr},
    };
    lua_createtable(L, 0, 23);
    set_funcs(L, kDebugger);
    lua_setfield(L, -2, "debugger");

    lua_setglobal(L, "slop");
    return 0;
}

// the script's return value goes into the output; protected because
// __len/__index metamethods can run lua code (and hit the hook)
int serialize_return(lua_State* L) {
    out_append(L, "return: ");
    append_value(L, 1, 0);
    out_append(L, "\n");
    return 0;
}

std::string lua_error_text(lua_State* L, int status, const script_ctx_t& ctx,
                           const char* fallback) {
    if (status == LUA_ERRMEM)
        return "script exceeded the memory limit (" +
               std::to_string(ctx.mem_limit >> 20) + " MiB)";
    const char* msg = lua_tostring(L, -1);
    return msg ? msg : fallback;
}

} // namespace

int clamp_timeout_ms(int64_t ms) noexcept {
    return static_cast<int>(std::clamp<int64_t>(ms, kMinTimeoutMs, kMaxTimeoutMs));
}

lua_run_result_t lua_run(const std::string& code, int timeout_ms) {
    lua_run_options_t opt;
    opt.timeout_ms = timeout_ms;
    return lua_run(code, opt);
}

lua_run_result_t lua_run(const std::string& code, const lua_run_options_t& opt) {
    lua_run_result_t res;

    // ctx outlives the state: lua_close still frees through capped_alloc
    script_ctx_t ctx;
    ctx.cancel    = opt.cancel;
    ctx.tool_mu   = opt.tool_mutex;
    ctx.mem_limit = opt.mem_limit ? opt.mem_limit : kDefaultMemLimit;
    ctx.unsafe    = opt.unsafe ? *opt.unsafe
                               : infra::settings::get<bool>("script_unsafe", false);
    res.timeout_ms = clamp_timeout_ms(opt.timeout_ms);
    res.unsafe     = ctx.unsafe;
    ctx.deadline_ms = now_ms() + res.timeout_ms;

    lua_State* L = lua_newstate(capped_alloc, &ctx);
    if (!L) {
        res.error = "lua_newstate failed (memory limit too small?)";
        return res;
    }

    lua_pushcfunction(L, open_env);
    int st = lua_pcall(L, 0, 0, 0);
    if (st != LUA_OK) {
        res.error = "script environment setup failed: " +
                    lua_error_text(L, st, ctx, "unknown error");
    } else {
        lua_sethook(L, timeout_hook, LUA_MASKCOUNT, kHookInstructions);
        // sandboxed runs refuse precompiled chunks for the same reason as load()
        st = luaL_loadbufferx(L, code.c_str(), code.size(), "=slop_script",
                              ctx.unsafe ? nullptr : "t");
        if (st != LUA_OK) {
            res.error = lua_error_text(L, st, ctx, "load failed");
        } else if ((st = lua_pcall(L, 0, 1, 0)) != LUA_OK) {
            // one result slot: the return value is serialized into the
            // output so return x is not lost
            res.error = lua_error_text(L, st, ctx, "runtime error");
        } else {
            res.ok = true;
            lua_pushcfunction(L, serialize_return);
            lua_insert(L, -2);
            if ((st = lua_pcall(L, 1, 0, 0)) != LUA_OK)
                out_append(L, "\n[return value not serialized: " +
                                  lua_error_text(L, st, ctx, "error") + "]\n");
        }
    }

    lua_close(L);
    res.output = std::move(ctx.output);
    res.output_truncated = ctx.output_truncated;
    res.peak_mem = ctx.mem_peak;
    return res;
}

} // namespace slop::core::script
