// src/core/mcp/mcp_tools.cpp
// every tool handler lives here, all under one mutex and response capped

#include "core/mcp/mcp_tools.hpp"
#include "core/mcp/mcp_server.hpp"

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
#include "core/process/module_dump.hpp"
#include "core/process/process_icon.hpp"
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

namespace {

using json = nlohmann::json;

std::mutex g_tool_mu;
std::mutex g_image_mu; // guards g_image so analyze.diff can run off g_tool_mu

// async bindiff jobs (analyze.diff_start/diff_job/diff_cancel)
struct diff_job_rec_t {
    std::string path_a, path_b;
    std::string stage = "queued";   // loading|analyzing_a|analyzing_b|comparing|done
    float       progress = -1.0f;   // -1 = indeterminate
    bool        done = false;
    json        result;              // full diff payload on success/partial
    std::string error;               // set when the job failed outright
};
std::mutex g_diff_mu;
std::map<uint64_t, diff_job_rec_t> g_diff_jobs;
constexpr size_t kMaxDiffJobs = 32;

// mcp side state

// the cheat engine style scan state, one per target
struct scan_state_t {
    memory::memscan_t         engine;  // hits plus the region stash
    bool                      used = false; // a first scan happened
    uint32_t                  pid = 0; // scan state never leaks across targets
    std::string               width = "i32";
    std::string               kind = "exact";
};
scan_state_t g_scan;


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
image_cache_t g_image;

// captured memory snapshots for the diff action
struct mcp_snapshot_t {
    uint64_t                  id = 0;
    memory::region_snapshot_t snap;
};
std::vector<mcp_snapshot_t> g_snaps;
uint64_t                    g_snap_next_id = 1;
constexpr size_t            kMaxMcpSnapshots = 8;

// capture sink and proxy instance
network::traffic_store_t g_traffic;
network::http_proxy_t    g_proxy;

// helpers

[[noreturn]] void fail(std::string msg) { throw std::runtime_error(std::move(msg)); }

void require_x86_image(disasm::image_arch_t arch, disasm::image_format_t format,
                       std::string_view action, bool path_image = false) {
    if (arch == disasm::image_arch_t::x86 || arch == disasm::image_arch_t::x64)
        return;
    if (path_image)
        fail(fmt::format("{} is x86/x64 only for 'path' images; the image is {} ({}); "
                         "load it with disasm.load to use the hyperion analyzer",
                         action, disasm::image_arch_name(arch),
                         disasm::image_format_name(format)));
    fail(fmt::format("{} supports x86/x64 only; the loaded image is {} ({})",
                     action, disasm::image_arch_name(arch),
                     disasm::image_format_name(format)));
}

void require_pe_image(disasm::image_arch_t arch, disasm::image_format_t format,
                      std::string_view action, bool path_image = false) {
    if (format == disasm::image_format_t::pe) return;
    fail(fmt::format("{} requires a PE image; the {} image is {} ({})",
                     action, path_image ? "'path'" : "loaded",
                     disasm::image_arch_name(arch), disasm::image_format_name(format)));
}


const char* disasm_flow_name(disasm::flow_t f) {
    switch (f) {
    case disasm::flow_t::none: return "none";
    case disasm::flow_t::call: return "call";
    case disasm::flow_t::jmp:  return "jmp";
    case disasm::flow_t::jcc:  return "jcc";
    case disasm::flow_t::ret:  return "ret";
    }
    return "unknown";
}

const char* xref_kind_name(disasm::xref_kind_t k) {
    switch (k) {
    case disasm::xref_kind_t::call: return "call";
    case disasm::xref_kind_t::jmp:  return "jmp";
    case disasm::xref_kind_t::data: return "data";
    }
    return "unknown";
}

const char* arch_name(runtime::arch_t a) {
    switch (a) {
    case runtime::arch_t::x64:    return "x64";
    case runtime::arch_t::x86:    return "x86";
    case runtime::arch_t::arm64:  return "arm64";
    case runtime::arch_t::unknown: break;
    }
    return "unknown";
}

const char* elevation_name(runtime::elevation_t e) {
    switch (e) {
    case runtime::elevation_t::standard: return "user";
    case runtime::elevation_t::elevated: return "admin";
    case runtime::elevation_t::system:   return "system";
    case runtime::elevation_t::unknown:  break;
    }
    return "unknown";
}

runtime::session_t& need_session() {
    auto s = process::active_session();
    if (!s || !s->valid()) fail("no target attached (use target.attach first)");
    return *s;
}

uint64_t parse_addr(const json& args, const char* key) {
    if (!args.contains(key))
        fail(std::string("missing numeric argument '") + key + "'");
    const json& v = args.at(key);
    if (v.is_string()) {
        const std::string s = v.get<std::string>();
        // allow surrounding whitespace; stoull throws invalid_argument on
        // names/expressions instead of leaking a bare conversion error
        size_t beg = s.find_first_not_of(" \t\r\n");
        size_t end = s.find_last_not_of(" \t\r\n");
        const std::string t =
            (beg == std::string::npos) ? std::string{} : s.substr(beg, end - beg + 1);
        if (t.empty()) fail(std::string("bad numeric argument '") + key + "': empty string");
        try {
            size_t pos = 0;
            const uint64_t val = std::stoull(t, &pos, 0);
            if (pos != t.size())
                fail(std::string("bad numeric argument '") + key +
                     "': trailing characters in '" + t + "'");
            return val;
        } catch (const std::invalid_argument&) {
            fail(std::string("bad numeric argument '") + key + "': '" + t +
                 "' is not a number (use 0x... hex or decimal)");
        } catch (const std::out_of_range&) {
            fail(std::string("bad numeric argument '") + key + "': '" + t + "' out of range");
        }
    }
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) {
        const int64_t sv = v.get<int64_t>();
        if (sv < 0) fail("negative address");
        return static_cast<uint64_t>(sv);
    }
    if (v.is_number_float()) {
        const double dv = v.get<double>();
        if (!(dv >= 0.0) || dv > 1.8446744073709552e19)
            fail(std::string("bad numeric argument '") + key + "': out of range");
        return static_cast<uint64_t>(dv);
    }
    fail(std::string("bad numeric argument '") + key + "'");
}

// First present key wins; used where agents naturally say base/va/address
// instead of the canonical addr, or len instead of size.
uint64_t parse_addr_alias(const json& args, std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        if (args.contains(k)) return parse_addr(args, k);
    }
    std::string want;
    for (const char* k : keys) {
        if (!want.empty()) want += "|";
        want += k;
    }
    fail("missing numeric argument (expected one of: " + want + ")");
}

bool has_any(const json& args, std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        if (args.contains(k)) return true;
    }
    return false;
}

std::string require_action(const json& args) {
    if (!args.contains("action") || !args.at("action").is_string())
        fail("missing 'action' string");
    return args.at("action").get<std::string>();
}

class session_reader_t final : public memory::reader_t {
public:
    explicit session_reader_t(runtime::session_t& s) : s_(s) {}
    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto io = s_.read(addr, dst, len);
        return io.ok && io.bytes == len;
    }
private:
    runtime::session_t& s_;
};

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

memory::value_width_t parse_width(const json& args) {
    const std::string w = args.value("width", std::string{"i32"});
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
    fail("bad width");
}

memory::scan_type_t parse_scan_kind(const json& args) {
    const std::string k = args.value("kind", std::string{"exact"});
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
    fail("bad scan kind");
}

memory::rounding_t parse_rounding(const json& args) {
    const std::string r = args.value("rounding", std::string{"exact"});
    if (r == "exact")     return memory::rounding_t::exact;
    if (r == "rounded")   return memory::rounding_t::rounded;
    if (r == "truncated") return memory::rounding_t::truncated;
    if (r == "extreme")   return memory::rounding_t::extreme;
    fail("bad rounding (exact|rounded|truncated|extreme)");
}

memory::region_pref_t parse_region_pref(const json& args, const char* key) {
    if (args.contains(key) && args.at(key).is_boolean()) return memory::region_pref_t::any;
    const std::string pref = args.value(key, std::string{"any"});
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

std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
        else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',') {}
        else fail("non-hex byte in payload");
    }
    if (clean.size() % 2 != 0) fail("hex payload has odd length");
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = d[data[i] >> 4];
        out[i * 2 + 1] = d[data[i] & 0xF];
    }
    return out;
}

std::string hex64(uint64_t v) {
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    return buf;
}

// ---- AI-rich output enrichment (additive only, never removes keys) ----
// Every VA the server returns is a decimal u64. Agents copy/paste hex, need
// symbol context, units, enum meanings, and next-step guidance to stay
// accurate. The helpers below mirror every address as 0x-hex, resolve known
// symbols, decode raw Windows/network constants, and attach per-action hints.
// All enrichment is best-effort and exception-free: it must never fail a call.

std::string addr_hex_str(uint64_t v) {
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

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
    if (!ctx.have_image || ctx.image_name.empty()) return {};
    if (va < ctx.image_base) return {};
    if (ctx.image_size && va >= ctx.image_base + ctx.image_size) return {};
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "+0x%llX",
                  static_cast<unsigned long long>(va - ctx.image_base));
    return ctx.image_name + buf;
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
        if (action == "ps4_connect") return "Connected to the console: target.list lists PS4 processes, then target.attach {pid}. Memory/disasm tools then read the console over ps4debug-NG.";
        if (action == "ps4_disconnect") return "Console connection dropped; backend is local again. Use target.list/attach for local processes.";
    } else if (tool == "memory") {
        if (action == "read") return "len is bytes actually returned (may be short on partial reads). Use format u32/u64 for pointers, utf8 for strings. Values carry addr_hex for copy/paste.";
        if (action == "scan") return "Refine with rescan (same width/kind), inspect scan_state, release with scan_reset. Hits carry addr_hex; read them with memory.read.";
        if (action == "rescan") return "Narrowing only: rescan filters the previous hit set. Start over with scan + scan_reset for a new value type.";
        if (action == "aob") return "Pattern is IDA-style hex with ?? wildcards. Matches carry *_hex; verify with memory.read or disasm.disassemble.";
        if (action == "pointerscan") return "chains[].addresses are the pointer path (see *_hex); depth/offsets are in bytes. Re-verify chains with memory.read u64.";
        if (action == "siggen") return "pattern/mask use x/? wildcards; yara is ready to reuse. unique=false means occurrences>1, widen the range.";
        if (action == "live_crypto") return "Scans committed live memory (default is the loaded module range). Matches carry va_hex; cross-check constants with analyze.signatures.";
        if (action == "watch_add" || action == "watch_list") return "Poll watch_list to sample values; width is bytes. frozen_bits only applies when freeze=true.";
    } else if (tool == "disasm") {
        if (action == "loaded") return "image.ready=false: load first. hype.ready=false: poll loaded until progress=1; blocks/globals/vtables/decomp all wait on it.";
        if (action == "functions") return "Pass a function-start va (see va_hex) to decomp.function, xray.cfg, or disasm.xrefs. total is the full index; returned==limit means truncated, raise limit to 10000.";
        if (action == "xrefs") return "from is the referencing instruction VA (see from_hex). kind call>jump>write>read>offset. Verify callers by disassembling from.";
        if (action == "strings") return "total_scanned is bytes scanned, not hits; truncated=true means limit was hit. Set include_exec=true to also scan code sections.";
        if (action == "disassemble") return "Live memory wins when attached, else the file image. count is decoded instructions; engine=hyperion uses Zydis for x86/x64 and Capstone for ARM/ARM64.";
        if (action == "pe") return "rva fields are file-relative: VA = image_base + rva (see image_base_hex). exec/writable decode characteristics.";
        if (action == "blocks") return "entry is the function start; succs/preds are block-start VAs (see *_hex). Loops list header/back_edge_src for cycle analysis.";
        if (action == "symbols") return "User renames only; analyzer names live in functions[].name. Rename with symbol_set (empty name clears).";
        if (action == "load") return "Loads PE, Mach-O (thin/FAT), or an .ipa main executable. Poll disasm.loaded until hype.ready=true before decomp/DB queries; encrypted images must be decrypted first.";
    } else if (tool == "debugger") {
        if (action == "status") return "state idle|running|paused. Only paused state allows regs/callstack/seh/set_register. hwbp_supported=false means hw breakpoints will refuse.";
        if (action == "bp_set") return "After continue/step actions, call wait_halt(timeout_ms) then regs/callstack. type 0=exec 1=write 3=read_write (see type_str).";
        if (action == "continue" || action == "step_into" || action == "step_over" || action == "step_out") return "This only resumes; follow with wait_halt then regs to learn where it stopped and why.";
        if (action == "wait_halt") return "halted=false is a timeout, not a stop. On halted=true read regs + callstack + events for reason.";
        if (action == "regs") return "rip is the stop VA (see rip_hex/rip_name); flags_str decodes RFLAGS. Mutate with set_register while paused.";
        if (action == "callstack") return "ret_addr entries carry *_hex/*_name; scanned=true frames are heuristic. Symbolize rip via disasm.functions first.";
        if (action == "trace_run") return "trace is bounded (256 steps); text may be absent for unreadable bytes. Disassemble rip for fuller context.";
        if (action.rfind("ps4_", 0) == 0) return "PS4 console live debugging via ps4debug-NG. Flow: target.ps4_connect {host} -> ps4_attach {pid} -> ps4_bp_set {addr} -> ps4_continue -> ps4_wait {timeout_ms} (stop event with rip/regs) -> ps4_regs/ps4_callstack -> ps4_step or ps4_continue again. ps4_call {addr, args} runs a function in the console process and returns rax. ps4_* actions fail with a clear error when no console is connected.";
    } else if (tool == "xray") {
        if (action == "cfg" || action == "complexity") return "Pass a function-start VA from disasm.functions. block_count/edge_count/back_edges feed cyclomatic=edges-blocks+2. Cross-check entry with decomp.function.";
        if (action == "cff") return "flattened=false carries no dispatcher (no score). flattened=true lists dispatcher + state_blocks; recover with devirt.recover_cfg.";
        if (action == "obfuscation") return "score_pct is 0-100. warning means addr did not decode (data, not code). Confirm with disasm.disassemble first.";
        if (action == "anti_analysis") return "score_pct is 0-100; detections[].type/detail name the check. Verify INT3/timing hits by disassembling address.";
        if (action == "hooks") return "functions_checked is min(index,max_functions); hooks carry address_hex/target_hex. Compare prologue_bytes against a clean image.";
        if (action == "syscalls") return "syscall_number is the SSN; resolve NT names via driver.symbols_lookup on ntoskrnl.";
        if (action == "apihash") return "Searches THIS image's imports only (bare API and DLL!API forms), not a global dictionary. unresolved = total_queried-resolved_count.";
        if (action == "entropy") return "overall>7.5 or verdict encrypted_or_compressed suggests packing. windows[] capped by window_limit (0=summary only).";
        if (action == "gadgets") return "text is the gadget disassembly; count is capped by limit. Filter ret/jmp/call endings for ROP/JOP chains.";
        if (action == "crypto_range") return "Matches carry va_hex; constant/value name the hit. Confirm in-context with disasm.disassemble.";
    } else if (tool == "decomp") {
        return "function_va is the identity anchor (signature/body names follow user>hyperion>sub_rva precedence and may differ). lines[].va==0 marks synthetic lines. Set annotate_bytes=true for VA-prefixed text.";
    } else if (tool == "re") {
        if (action == "rtti_scan") return "td_va/vtable_va carry *_hex; methods[] are bare VAs, symbolize via disasm.functions. Fallback path (no hype) returns vftables[] instead of methods.";
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
        if (action == "packets") return "protocol/direction are raw ints, read *_str (6=tcp 17=udp; 0=outbound 1=inbound). payload_hex capped at 96B; fetch full bytes via stream_data.";
        if (action == "stream_data") return "bytes is returned length, not the stream total; offset/len page through it. text substitutes '.' for non-printables.";
        return "Capture flow: capture_start -> packets/dns/streams/stats -> capture_stop (host raw-socket capture, needs admin for SIO_RCVALL; port/protocol filters are display-side). export_pcap writes the store. Proxy/MITM actions live in the proxy tool.";
    } else if (tool == "guide") {
        if (action == "list") return "Topics are workflow playbooks: guide get {topic} returns the exact ordered tool calls (tool/action/params/why) for that task.";
        if (action == "get") return "steps[] is a ready-to-run sequence; copy tool+action+params into real calls, filling in addresses/pids from target/memory/disasm results.";
    } else if (tool == "persist") {
        return "save returns id; load echoes id/name/created_at + data. hype_save writes a .hdb dir; hype_load merges names+comments only (not xrefs/types).";
    } else if (tool == "fs") {
        return "Host filesystem, not target memory. read_file caps text at 4KB / hex at 8KB (use max_bytes). Paths should be absolute.";
    } else if (tool == "web") {
        return "Outbound GET/POST from the host. text capped at 64KB; status is the HTTP code. Unrelated to network/proxy capture.";
    } else if (tool == "proxy") {
        return "Localhost HTTP inspection proxy. entries[] capped by limit; entry(id) shows headers; replay(id) only works for plain HTTP (CONNECT tunnels are metadata-only).";
    } else if (tool == "script") {
        return "Lua 5.4 over the shared session (loads/renames visible everywhere). print() is captured; return values serialize as 'return: <value>'. Default timeout 5s, cap 60s.";
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
        else if (err.find("kernel") != std::string::npos ||
                 err.find("driver") != std::string::npos ||
                 err.find("DTB") != std::string::npos ||
                 err.find("slopdrvr") != std::string::npos)
            fix = "Check driver.status; kernel-read actions need slopdrvr active with a resolved kernel context.";
        else if (err.find("debugger") != std::string::npos ||
                 err.find("paused") != std::string::npos ||
                 err.find("wait_halt") != std::string::npos)
            fix = "Attach with debugger.attach {pid}, continue/step, then wait_halt(timeout_ms) and regs/callstack while paused.";
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


const char* arch_from_hype(hype::Arch a) {
    switch (a) {
    case hype::Arch::X86:   return "x86";
    case hype::Arch::X64:   return "x64";
    case hype::Arch::ARM:   return "arm";
    case hype::Arch::ARM64: return "arm64";
    case hype::Arch::MIPS:  return "mips";
    case hype::Arch::PPC:   return "ppc";
    default:                return "unknown";
    }
}

const char* xref_kind_name_hype(hype::XrefType t) {
    switch (t) {
    case hype::XrefType::CodeCall:  return "call";
    case hype::XrefType::CodeJump:  return "jump";
    case hype::XrefType::DataRead:  return "read";
    case hype::XrefType::DataWrite: return "write";
    case hype::XrefType::DataOffset: return "offset";
    default:                         return "other";
    }
}

const char* callconv_name(hype::CallConv c) {
    switch (c) {
    case hype::CallConv::Cdecl:   return "cdecl";
    case hype::CallConv::Stdcall: return "stdcall";
    case hype::CallConv::Fastcall: return "fastcall";
    case hype::CallConv::Thiscall: return "thiscall";
    case hype::CallConv::X64:     return "x64";
    default:                      return "unknown";
    }
}

bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    const size_t n = needle.size(), h = haystack.size();
    if (n > h) return false;
    for (size_t i = 0; i + n <= h; ++i)
        if (_strnicmp(haystack.c_str() + i, needle.c_str(), n) == 0)
            return true;
    return false;
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

// image cache

image_cache_t& load_image(const std::string& path) {
    std::lock_guard ilk(g_image_mu);
    if (g_image.path == path && !g_image.file.empty()) return g_image;

    std::FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) fail("cannot open image file");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (256L << 20)) { fclose(f); fail("image file too large or empty"); }
    image_cache_t c;
    c.file.resize(static_cast<size_t>(size));
    const size_t rd = fread(c.file.data(), 1, c.file.size(), f);
    fclose(f);
    if (rd != c.file.size()) fail("short read on image file");

    auto opened = disasm::open_image(std::move(c.file));
    if (!opened.ok) fail(opened.error);
    if (opened.file.size() > (256u << 20)) fail("analyzed image too large (>256 MiB)");
    c.file = std::move(opened.file);
    c.pe = std::move(opened.pe);
    c.format = opened.format;
    c.arch = opened.arch;

    g_image = std::move(c);
    g_image.path = path;
    return g_image;
}

disasm::engine_t& shared_engine() {
    static disasm::engine_t eng;   // guarded by g_tool_mu
    return eng;
}

// hw bp and snapshot helpers

mcp_snapshot_t* find_snapshot(uint64_t id) {
    for (auto& rec : g_snaps)
        if (rec.id == id) return &rec;
    return nullptr;
}

// app session context
// what the app has going right now, shown at initialize and in the status actions

json loaded_image_json() {
    std::lock_guard lk(ds::state_mutex());
    auto& bin = ds::get();
    json out = {{"ready", bin.ready}};
    if (!bin.ready) return out;
    out["name"]          = bin.name;
    out["path"]          = bin.path;
    out["format"]        = disasm::image_format_name(bin.format);
    out["arch"]          = disasm::image_arch_name(bin.arch);
    out["encrypted"]     = bin.encrypted;
    if (bin.encrypted)
        out["warning"] = "FairPlay-encrypted executable: decrypt first (for example, "
                         "use a dumped/decrypted IPA); analysis of encrypted code is noise";
    if (bin.bundle) {
        const auto& bundle = *bin.bundle;
        out["bundle"] = {{"app_dir", bundle.app_dir},
                         {"executable", bundle.executable},
                         {"executable_path", bundle.executable_path},
                         {"bundle_id", bundle.bundle_id},
                         {"version", bundle.version},
                         {"build", bundle.build},
                         {"min_os", bundle.min_os}};
    }
    out["base"]          = bin.base;
    out["entry_va"]      = bin.base + bin.pe.entry_rva;
    out["size_of_image"] = bin.pe.size_of_image;
    out["sections"]      = bin.pe.sections.size();
    out["functions"]     = bin.fns.functions().size();
    out["xrefs"]         = bin.xrefs.total();
    out["strings"]       = bin.strings.size();
    out["symbols"]       = bin.symbols.size();

    // hyperion is the decompiler plus the rich analysis db
    json hype = {{"available", static_cast<bool>(bin.hype)}};
    if (bin.hype) {
        const bool rdy    = bin.hype->ready();
        hype["ready"]     = rdy;
        hype["progress"]  = bin.hype->progress();
        hype["arch"]      = arch_from_hype(bin.hype->db().arch);
        if (rdy) {
            hype["functions"]       = bin.hype->db().funcs.size();
            hype["instructions"]    = bin.hype->db().insns.size();
            hype["xrefs"]           = bin.hype->db().xrefs.size();
            hype["vtables"]         = bin.hype->db().vtables.size();
            hype["globals"]         = bin.hype->db().globals.size();
            hype["rtti_classes"]    = bin.hype->rtti().classes().size();
        }
        const std::string herr = bin.hype->error();
        if (!herr.empty()) hype["error"] = herr;
    }
    out["hype"] = hype;
    return out;
}

json attached_target_json() {
    json out = {{"attached", false}};
    if (auto s = process::active_session(); s && s->valid()) {
        out["attached"] = true;
        out["pid"]      = s->pid();
        out["name"]     = s->name();
        out["arch"]     = arch_name(s->arch());
    }
    return out;
}

// caller holds the mutex
json app_state_unlocked() {
    json out;
    out["backend"] = runtime::active_badge();
    out["target"]  = attached_target_json();
    out["image"]   = loaded_image_json();
    // surfacing a live debug session keeps an agent from stomping it
    out["debugger"] = "ps4 (debugger ps4_* actions)";
    return out;
}

// tool: target

json tool_target(const json& args) {
    const std::string action = require_action(args);

    if (action == "list") {
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
        // icons get cached since a busy machine is 200 processes sharing a handful of images
        static std::unordered_map<std::string, json> icon_cache;

        std::vector<std::string> paths;
        if (args.contains("paths") && args.at("paths").is_array()) {
            for (const auto& p : args.at("paths")) {
                if (p.is_string()) paths.push_back(p.get<std::string>());
                if (paths.size() >= 64) break;   // keep one requests shell work bounded
            }
        } else if (args.contains("path") && args.at("path").is_string()) {
            paths.push_back(args.at("path").get<std::string>());
        } else if (args.contains("pid")) {
            const uint32_t pid = args.at("pid").get<uint32_t>();
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
            auto hit = icon_cache.find(path);
            if (hit == icon_cache.end()) {
                const auto bits = process::icon_for_path(path, true);
                json entry = {{"width", bits.width}, {"height", bits.height}};
                if (!bits.empty()) entry["bgra_b64"] = infra::fmt::base64(bits.bgra);
                hit = icon_cache.emplace(path, std::move(entry)).first;
            }
            icons[path] = hit->second;
        }
        // grab the size before the move eats it
        const size_t resolved = icons.size();
        return {{"icons", std::move(icons)}, {"count", resolved}};
    }

    if (action == "attach") {
        const uint64_t pid = parse_addr(args, "pid");
        if (pid == 0 || pid > 0xFFFFFFFFull) fail("bad pid");
        if (!process::target_attach(static_cast<uint32_t>(pid)))
            fail("attach failed (process gone, access denied, or kernel DTB resolve failed)");
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
                    {"backend", runtime::active_badge()}};
        auto s = process::active_session();
        if (pid != 0 && s && s->valid()) {
            out["attached"] = true;
            out["pid"]      = s->pid();
            out["name"]     = s->name();
            out["arch"]     = arch_name(s->arch());
            out["hint"]     = "PS4 modules are ELF/SELF, not PE: dump_module writes a raw "
                              "memory image and disasm.load cannot open it. Use target.modules, "
                              "memory.read/write and disasm.disassemble on live addresses instead.";
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
        if (!procs.ok) fail("ps4_auto: cannot list console processes (error " +
                            std::to_string(procs.error) + ")");
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
                thr_json.push_back({{"lwpid", t.tid}, {"priority", t.priority}});
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
        if (runtime::registry_ps4_active()) {
            out["ps4"] = {{"endpoint", runtime::registry_ps4_endpoint()},
                         {"branding", runtime::registry_ps4_branding()}};
        }
        auto s = process::active_session();
        if (s && s->valid()) {
            out["attached"] = true;
            out["pid"]      = s->pid();
            out["name"]     = s->name();
            out["arch"]     = arch_name(s->arch());
        } else {
            out["attached"] = false;
        }
        out["debugger_state"] = g_dbg ? debugger_state_name(g_dbg->state()) : "idle";
        out["image"]          = loaded_image_json();
        return out;
    }

    if (action == "modules") {
        auto& s = need_session();
        auto res = runtime::active().enum_modules(s.handle());
        if (!res.ok) fail("module enumeration failed");
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
        auto& session = need_session();
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
        if (pid == 0) pid = need_session().pid();
        auto res = runtime::active().enum_threads(pid);
        if (!res.ok) fail("thread enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{4096});
        for (size_t i = 0; i < cap; ++i) {
            const auto& t = res.items[i];
            arr.push_back({{"tid", t.tid},
                           {"start", static_cast<uint64_t>(t.start_address)},
                           {"priority", t.priority}});
        }
        return {{"threads", arr}, {"count", arr.size()}};
    }

    if (action == "regions") {
        auto& s = need_session();
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
        auto& s = need_session();
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

    fail("target: unknown action (list|attach|detach|status|modules|"
         "dump_module|threads|regions|handles|icon|ps4_connect|ps4_disconnect|ps4_auto)");
}

// tool: memory

json tool_memory(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no target attached, a typo isnt a missing target
    {
        static const char* kKnown[] = {
            "read", "write", "scan", "rescan", "scan_state", "scan_reset",
            "aob", "pointerscan", "snapshot", "snapshots", "diff",
            "snapshot_free", "protect", "alloc", "free", "siggen",
            "live_crypto", "watch_list", "watch_add", "watch_remove",
            "watch_clear", "watch_set",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("memory: unknown action (read|write|scan|rescan|scan_state|scan_reset|"
                 "aob|pointerscan|snapshot|snapshots|diff|snapshot_free|protect|alloc|"
                 "free|siggen|live_crypto|watch_list|watch_add|watch_remove|watch_clear|"
                 "watch_set)");
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
            for (const auto& v : memory::watch::values())
                vals.push_back({{"id", v.id},
                                {"addr", v.addr},
                                {"ok", v.ok},
                                {"held", v.held},
                                {"bits", v.bits},
                                {"text", v.text}});
            return {{"entries", entries_json()}, {"values", std::move(vals)}};
        }

        if (action == "watch_add") {
            if (!args.contains("addr")) fail("memory.watch_add: missing addr");
            const uint64_t addr = args.at("addr").get<uint64_t>();
            const auto width = parse_width(args);
            std::string label = args.value("label", std::string{});
            if (label.empty()) label = infra::fmt::format_address(addr);
            const uint64_t id = memory::watch::add(addr, width, std::move(label));
            if (id == 0) fail("memory.watch_add: watch list is full");
            return {{"id", id}, {"entries", entries_json()}};
        }

        if (action == "watch_remove") {
            if (!args.contains("id")) fail("memory.watch_remove: missing id");
            const bool ok = memory::watch::remove(args.at("id").get<uint64_t>());
            if (!ok) fail("memory.watch_remove: no such id");
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_clear") {
            memory::watch::clear();
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_set") {
            if (!args.contains("id")) fail("memory.watch_set: missing id");
            const uint64_t id = args.at("id").get<uint64_t>();
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
        if (args.value("all", false)) {
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
            else fail(std::string("live read failed (error ") +
                      std::to_string(io.error) + ")");
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
        const std::string fmt = args.value("format", std::string{"hex"});
        if (fmt == "hex") {
            out["hex"] = to_hex(buf.data(), got);
        } else if (fmt == "utf8") {
            std::string text(reinterpret_cast<const char*>(buf.data()), got);
            text.erase(std::find(text.begin(), text.end(), '\0'), text.end());
            out["text"] = text;
        } else if (fmt == "u8" || fmt == "u32" || fmt == "u64" || fmt == "f32" || fmt == "f64") {
            json arr = json::array();
            const size_t w = fmt == "u8" ? 1 : fmt == "u32" ? 4 : fmt == "f32" ? 4 : fmt == "f64" ? 8 : 8;
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

    auto& s = need_session();

    if (action == "write") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("hex") || !args.at("hex").is_string()) fail("missing hex payload");
        auto bytes = hex_decode(args.at("hex").get<std::string>());
        if (bytes.empty()) fail("empty payload");
        if (bytes.size() > (1ull << 20)) fail("write capped at 1 MiB");
        auto io = s.write(static_cast<uintptr_t>(addr), bytes.data(), bytes.size());
        if (!io.ok) fail("write failed at requested range");
        return {{"addr", addr}, {"written", io.bytes}};
    }

    if (action == "scan" || action == "rescan") {
        session_reader_t reader(s);

        // scan config straight from the request
        memory::scan_config_t cfg;
        cfg.type  = parse_scan_kind(args);
        cfg.width = parse_width(args);
        cfg.scan_all_types = args.value("width", std::string{"i32"}) == "all";
        cfg.rounding = parse_rounding(args);
        cfg.max_results = std::min<size_t>(
            args.value("max_results", infra::limits::max_scan_hits),
            infra::limits::max_scan_hits);
        cfg.threads = std::min<uint32_t>(args.value("threads", 0u), 64u);
        cfg.chunk_bytes = std::min<size_t>(
            args.value("chunk_bytes", infra::limits::scan_chunk_bytes),
            64u << 20);
        if (args.contains("begin") && args.contains("end")) {
            cfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            cfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        // fastscan is alignment or the ends with hex digits mode
        if (args.contains("tail")) {
            std::string tail = args.at("tail").get<std::string>();
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
            cfg.fast_alignment = static_cast<uint32_t>(args.value("alignment", 4u));
            if (cfg.fast_alignment == 0) cfg.fast = memory::fastscan_method_t::off;
        }
        // region prefs, the old boolean flags still work
        cfg.writable = parse_region_pref(args, "writable");
        cfg.executable = parse_region_pref(args, "executable");
        cfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            cfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        if (args.value("read_only", false)) cfg.writable = memory::region_pref_t::exclude;
        if (args.value("no_exec", false)) cfg.executable = memory::region_pref_t::exclude;
        cfg.mem_private = args.value("mem_private", true);
        cfg.mem_image = args.value("mem_image", true);
        cfg.mem_mapped = args.value("mem_mapped", true);

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
        g_scan.width = args.value("width", std::string{"i32"});
        g_scan.kind = args.value("kind", std::string{"exact"});

        const auto& out = g_scan.engine.results();
        const auto stats = g_scan.engine.stats();
        const size_t limit = std::min<size_t>(args.value("limit", 100u), 10000u);
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
            {"width", args.value("width", std::string{"i32"})}
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
        rcfg.mem_private = args.value("mem_private", true);
        rcfg.mem_image = args.value("mem_image", true);
        rcfg.mem_mapped = args.value("mem_mapped", true);
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), rcfg);
        if (regions.empty()) fail("no committed ranges");

        memory::aob_scan_options_t opt;
        opt.alignment = static_cast<uint32_t>(args.value("alignment", 1u));
        opt.max_results = std::min<size_t>(
            args.value("max_results", infra::limits::max_aob_matches),
            infra::limits::max_aob_matches);
        opt.chunk_bytes = std::min<size_t>(
            args.value("chunk_bytes", infra::limits::scan_chunk_bytes),
            64u << 20);
        opt.threads = std::min<uint32_t>(args.value("threads", 0u), 64u);
        infra::cancel_token_t tok;
        memory::aob_stats_t stats{};
        auto matches = memory::aob_scan(reader, regions, *pat, opt, tok, &stats);
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 10000u);
        json arr = json::array();
        for (size_t i = 0; i < matches.size() && i < limit; ++i)
            arr.push_back(static_cast<uint64_t>(matches[i]));
        return {{"matches", arr}, {"total", matches.size()},
                {"truncated", stats.truncated}, {"cancelled", stats.cancelled},
                {"bytes_scanned", stats.bytes_scanned}};
    }

    if (action == "protect") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len  = parse_addr(args.contains("len") ? args : json{{"len", 4096}}, "len");
        const uint32_t prot = static_cast<uint32_t>(parse_addr(args, "prot"));
        uint32_t old = 0;
        auto io = runtime::active().protect_memory(s.handle(), static_cast<uintptr_t>(addr),
                                                   static_cast<size_t>(len), prot, &old);
        if (!io.ok) fail("protect failed (kernel backend required for cross-process protect)");
        return {{"addr", addr}, {"len", len}, {"old_protect", old}};
    }

    if (action == "alloc") {
        const uint64_t len = parse_addr(args, "len");
        if (len == 0 || len > (64ull << 20)) fail("alloc len out of range (1 byte .. 64 MiB)");
        uintptr_t out = 0;
        auto io = runtime::active().allocate_memory(s.handle(), 0, static_cast<size_t>(len),
                                                    0x40 /*PAGE_EXECUTE_READWRITE*/, &out);
        if (!io.ok) fail("alloc failed (kernel backend required for cross-process alloc)");
        return {{"addr", static_cast<uint64_t>(out)}, {"len", len}};
    }

    if (action == "free") {
        const uint64_t addr = parse_addr(args, "addr");
        auto io = runtime::active().free_memory(s.handle(), static_cast<uintptr_t>(addr));
        if (!io.ok) fail("free failed (kernel backend required for cross-process free)");
        return {{"freed", true}};
    }

    if (action == "pointerscan") {
        if (!args.contains("target")) fail("missing target address");
        memory::pointer_scan_options_t opt;
        opt.target = static_cast<uintptr_t>(parse_addr(args, "target"));
        opt.depth  = std::min<uint32_t>(
            static_cast<uint32_t>(args.value("depth", 3u)),
            static_cast<uint32_t>(infra::limits::max_pointer_depth));
        opt.min_offset = args.value("min_offset", -4096);
        opt.max_offset = args.value("max_offset",  4096);
        opt.alignment  = static_cast<uint32_t>(args.value("alignment", 4u));
        opt.only_module_backed = args.value("static_roots", false);
        opt.frontier_cap = std::min<size_t>(
            args.value("frontier_cap", size_t{100'000}),
            infra::limits::max_pointer_chains);

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
        rcfg.mem_private = args.value("mem_private", true);
        rcfg.mem_image = args.value("mem_image", true);
        rcfg.mem_mapped = args.value("mem_mapped", true);
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

        const size_t limit = std::min<size_t>(args.value("limit", 100u), 1000u);
        json arr = json::array();
        for (size_t i = 0; i < chains.size() && i < limit; ++i) {
            json addrs = json::array();
            json offs  = json::array();
            for (uintptr_t a : chains[i].addresses) addrs.push_back(static_cast<uint64_t>(a));
            for (int64_t o : chains[i].offsets)     offs.push_back(o);
            arr.push_back({{"addresses", addrs}, {"offsets", offs},
                           {"depth", chains[i].depth()}});
        }
        return {{"chains", arr}, {"total", chains.size()},
                {"truncated", stats.truncated}, {"range_truncated", range_truncated},
                {"edges_explored", stats.edges_explored}};
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
        const size_t limit = std::min<size_t>(args.value("limit", 512u),
                                              infra::limits::max_diff_ranges);
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
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);
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
         "aob|pointerscan|snapshot|snapshots|diff|snapshot_free|protect|alloc|"
         "free|siggen|live_crypto|watch_list|watch_add|watch_remove|watch_clear|"
         "watch_set)");
}

// tool: disasm

json insn_to_json(const disasm::insn_t& in) {
    json o = {{"va", in.va}, {"len", in.length}, {"text", in.text},
              {"flow", disasm_flow_name(in.flow)}};
    if (in.has_rel_target) o["target"] = in.rel_target;
    if (in.has_rip_rel)    o["rip_rel"] = in.rip_rel_target;
    return o;
}

std::string assemble_one(const std::string& text, uint64_t addr,
                         ZydisEncoderRequest& out);

json tool_disasm(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no image loaded, a typo isnt a missing binary
    {
        static const char* kKnown[] = {
            "assemble", "disassemble", "loaded", "pe", "functions", "xrefs",
            "strings", "symbols", "symbol_set", "blocks", "globals", "vtables",
            "load", "unload", "analyze_stop",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
                 "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|unload|"
                 "analyze_stop)");
    }

    if (action == "disassemble") {
        const uint64_t addr = parse_addr(args, "addr");
        const size_t count = std::min<size_t>(args.value("count", 32u), 512u);
        std::vector<uint8_t> buf(count * 16 + 16);
        size_t have = 0;
        hype::Arch arch = hype::Arch::X64;

        // live target first, else the loaded file so you can read with nothing attached
        if (auto s = process::active_session(); s && s->valid()) {
            auto io = s->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (!io.ok) fail("cannot read code range");
            have = io.bytes;
        } else {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (!bin.ready) fail("no target attached and no image loaded in reverse-slop");
            arch = disasm::hype_arch(bin.arch);
            auto off = bin.pe.va_to_offset(addr);
            if (!off) fail("address not mapped in loaded image (base may differ)");
            have = std::min(buf.size(), bin.file.size() - *off);
            std::memcpy(buf.data(), bin.file.data() + *off, have);
        }

        // match the loaded image architecture; live targets keep the x86/x64 path
        const size_t resync_step = (arch == hype::Arch::X86 || arch == hype::Arch::X64)
            ? 1 : 4;
        json arr = json::array();
        size_t off = 0;
        size_t resync_skip = 0;
        disasm::insn_t insn;
        for (size_t i = 0; i < count && off + 1 < have; ++i) {
            if (!hs::session_t::decode(addr + off, buf.data() + off,
                                       have - off, insn, arch)) {
                off += resync_step;
                resync_skip += resync_step;
                if (resync_skip >= 64) break;  // too much garbage, bail
                --i;  // resync bytes arent instructions
                continue;
            }
            resync_skip = 0;
            arr.push_back(insn_to_json(insn));
            off += insn.length ? insn.length : resync_step;
        }
        return {{"instructions", arr}, {"count", arr.size()},
                {"engine", "hyperion"}};
    }

    if (action == "assemble") {
        {
            std::lock_guard lk(ds::state_mutex());
            const auto& bin = ds::get();
            if (bin.ready) require_x86_image(bin.arch, bin.format, "disasm.assemble");
        }
        // one or more instructions, separated by ';' or newlines:
        // "xor eax, eax; ret"
        if (!args.contains("text") || !args.at("text").is_string())
            fail("missing text (instruction mnemonic + operands)");
        const std::string all_text = args.at("text").get<std::string>();
        const uint64_t base_va = args.contains("base")
            ? parse_addr(args, "base") : 0x400000;

        // split into statements on ';' and newlines, drop empties/comments
        std::vector<std::string> stmts;
        {
            std::string cur;
            for (char ch : all_text) {
                if (ch == ';' || ch == '\n' || ch == '\r') {
                    // strip // comments
                    auto cpos = cur.find("//");
                    if (cpos != std::string::npos) cur.resize(cpos);
                    size_t b = cur.find_first_not_of(" \t");
                    size_t e = cur.find_last_not_of(" \t");
                    if (b != std::string::npos)
                        stmts.push_back(cur.substr(b, e - b + 1));
                    cur.clear();
                } else {
                    cur.push_back(ch);
                }
            }
            auto cpos = cur.find("//");
            if (cpos != std::string::npos) cur.resize(cpos);
            size_t b = cur.find_first_not_of(" \t");
            size_t e = cur.find_last_not_of(" \t");
            if (b != std::string::npos)
                stmts.push_back(cur.substr(b, e - b + 1));
        }
        if (stmts.empty()) fail("empty instruction");
        if (stmts.size() > 64) fail("too many instructions (max 64 per call)");

        std::vector<uint8_t> out_bytes;
        json lines = json::array();
        for (size_t si = 0; si < stmts.size(); ++si) {
            ZydisEncoderRequest req{};
            std::string parse_err = assemble_one(stmts[si], base_va + out_bytes.size(), req);
            if (!parse_err.empty())
                fail("statement " + std::to_string(si + 1) + " '" + stmts[si] +
                     "': " + parse_err);
            uint8_t buf[16];
            ZyanUSize encoded_len = sizeof(buf);
            if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf,
                                                          &encoded_len)))
                fail("statement " + std::to_string(si + 1) + " '" + stmts[si] +
                     "': encode failed (" + std::string(ZydisMnemonicGetString(req.mnemonic) ?
                         ZydisMnemonicGetString(req.mnemonic) : "?") +
                     " with " + std::to_string(req.operand_count) + " operands)");
            out_bytes.insert(out_bytes.end(), buf, buf + encoded_len);
            lines.push_back({{"text", stmts[si]},
                             {"bytes", to_hex(buf, static_cast<size_t>(encoded_len))},
                             {"length", static_cast<uint64_t>(encoded_len)}});
        }
        json out = {{"bytes", to_hex(out_bytes.data(), out_bytes.size())},
                    {"length", static_cast<uint64_t>(out_bytes.size())},
                    {"count", stmts.size()}};
        if (stmts.size() > 1) out["lines"] = lines;
        return out;
    }

    if (action == "loaded") {
        json out = loaded_image_json();
        if (!out.value("ready", false)) {
            out["hint"] = "open a binary in the Disassembly view, attach a target and "
                          "use target.modules to find one, or pass an explicit 'path'";
        }
        out["target"] = attached_target_json();
        return out;
    }

    if (action == "symbols") {
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
        // User renames win; Hyperion analyzer names (RTTI/vtable/thunk/sig)
        // fill the rest so this matches analyze.signatures' named_functions
        // instead of reporting 0 on a fresh image.
        std::map<uint64_t, std::pair<std::string, std::string>> merged;
        {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                for (const auto& [va, name] : bin.hype->db().names) {
                    if (name.find("j_") == 0 || name.find("__imp_") == 0) continue;
                    merged[va] = {name, "hyperion"};
                }
            }
        }
        for (const auto& [va, name] : ds::symbols_snapshot())
            merged[va] = {name, "user"};
        json arr = json::array();
        for (const auto& [va, pr] : merged) {
            if (arr.size() >= limit) break;
            arr.push_back({{"va", va}, {"name", pr.first}, {"source", pr.second}});
        }
        json out = {{"symbols", arr}, {"count", arr.size()},
                    {"total", merged.size()},
                    {"note", "user renames (source=user) override hyperion analyzer "
                             "names (source=hyperion); same source as "
                             "analyze.signatures named_functions"}};
        if (merged.size() > arr.size()) out["truncated"] = true;
        return out;
    }

    if (action == "symbol_set") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("name") || !args.at("name").is_string())
            fail("missing 'name' string (empty clears)");
        const std::string name = args.at("name").get<std::string>();
        if (!ds::has_binary()) fail("no image loaded in reverse-slop");
        ds::set_symbol(addr, name);   // saved, the ui sees it instantly
        return {{"va", addr}, {"name", name}, {"cleared", name.empty()}};
    }

    if (action == "load") {
        // same as opening a file in the ui, kicks off the background analysis
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path");
        const std::string path = args.at("path").get<std::string>();
        if (!ds::load_file(path))
            fail("failed to load " + path + ": " + ds::last_load_error());
        json out                = loaded_image_json();
        out["ok"]               = true;
        out["hype_wait_hint"]   = "poll disasm.loaded -> hype.ready for the "
                                  "decompiler/analyzer DB";
        return out;
    }
    if (action == "unload") {
        ds::unload();
        return {{"ok", true}, {"ready", false}};
    }

    if (action == "analyze_stop") {
        // cooperative cancel, the analyzer checks between phases so this returns fast
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded (see disasm.loaded)");
        if (!bin.hype)  fail("hyperion engine unavailable for this image");
        if (bin.hype->ready())
            return {{"stopped", false}, {"ready", true},
                    {"note", "analysis already complete"}};
        const std::string herr = bin.hype->error();
        if (!herr.empty())
            return {{"stopped", false}, {"ready", false},
                    {"reason", herr},
                    {"note", "analysis is not running, " + herr +
                     " (re-run disasm.load to restart)"}};
        const float at = bin.hype->progress();
        bin.hype->stop();
        return {{"stopped", true}, {"progress_at_stop", at},
                {"note", "analysis cancelled, decompiler/analyzer actions "
                 "report not-ready; re-run disasm.load to restart analysis"}};
    }

    // static actions over an image file

    // explicit path parses into the private cache, otherwise the app session
    const bool have_path = args.contains("path") && args.at("path").is_string();

    // keep the session pinned while we poke the indexes
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*       pe      = nullptr;
    const std::vector<uint8_t>*     file    = nullptr;
    disasm::function_index_t*       fidx    = nullptr;
    disasm::xref_index_t*           xidx    = nullptr;
    bool*                           fidx_ok = nullptr;   // null => always built
    bool*                           xidx_ok = nullptr;
    const std::unordered_map<uint64_t, std::string>* syms = nullptr;
    uint64_t default_base = 0;
    disasm::image_format_t format = disasm::image_format_t::pe;
    disasm::image_arch_t arch = disasm::image_arch_t::x64;
    std::string                     img_name, img_path;

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        if (action == "functions" || action == "xrefs")
            require_x86_image(img.arch, img.format, "disasm." + action, true);
        format = img.format;
        arch = img.arch;
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        fidx_ok = &img.fidx_ok; xidx_ok = &img.xidx_ok;
        img_path = img.path;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
        default_base = img.pe.image_base;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready) fail("no image: pass 'path' or load a binary in reverse-slop "
                             "(see disasm.loaded)");
        // patches dirty the indexes so rebuild them lazily
        if (bin.indexes_dirty &&
            (action == "functions" || action == "xrefs" || action == "strings")) {
            ds::rebuild_indexes_locked(bin);
        }
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        format = bin.format;
        arch = bin.arch;
        syms = &bin.symbols;
        img_name = bin.name; img_path = bin.path;
        default_base = bin.base;   // VA base the whole session was built with
    }
    const bool is_x86 = arch == disasm::image_arch_t::x86 ||
                        arch == disasm::image_arch_t::x64;

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : default_base;

    if (action == "pe") {
        json secs = json::array();
        for (const auto& sec : pe->sections) {
            // raw characteristics too so it matches the packer output
            secs.push_back({{"name", sec.name}, {"rva", sec.rva},
                            {"vsize", sec.virtual_size}, {"raw_size", sec.raw_size},
                            {"exec", sec.is_executable()},
                            {"writable", (sec.characteristics & 0x80000000u) != 0},
                            {"characteristics", sec.characteristics}});
        }
        json imps = json::array();
        for (const auto& dll : pe->imports) {
            json fns = json::array();
            for (const auto& fn : dll.functions) fns.push_back(fn.name);
            imps.push_back({{"dll", dll.dll}, {"functions", fns}});
        }
        json exps = json::array();
        for (const auto& e : pe->exports)
            exps.push_back({{"name", e.name}, {"rva", e.rva}, {"ordinal", e.ordinal}});
        return {{"ok", true}, {"image", img_name}, {"pe32plus", pe->pe32plus},
                {"format", disasm::image_format_name(format)},
                {"arch", disasm::image_arch_name(arch)},
                {"image_base", pe->image_base}, {"entry_rva", pe->entry_rva},
                {"size_of_image", pe->size_of_image},
                {"sections", secs}, {"imports", imps}, {"exports", exps}};
    }

    if (action == "functions") {
        if (fidx_ok && !*fidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!fidx->build(*pe, *file, eng, base)) fail("function index build failed");
            *fidx_ok = true;
        }
        const size_t limit = std::min<size_t>(args.value("limit", 1000u), 10000u);
        json arr = json::array();
        const auto& fns = fidx->functions();

        // hyperion adds names and cfg stats on the same rows
        const hype::AnalysisDB* hdb = nullptr;
        if (!have_path) {
            auto& bin = ds::get();
            if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
        }

        std::unordered_set<uint64_t> seen;
        for (size_t i = 0; i < fns.size() && i < limit; ++i) {
            json o = {{"va", fns[i].va}, {"size", fns[i].size},
                      {"source", "index"}};
            seen.insert(fns[i].va);
            if (syms) {
                const auto it = syms->find(fns[i].va);
                if (it != syms->end()) o["symbol"] = it->second;
            }
            if (hdb) {
                const auto fit = hdb->funcs.find(fns[i].va);
                if (fit != hdb->funcs.end()) {
                    const auto& hf = fit->second;
                    if (!o.contains("symbol")) {
                        const auto nit = hdb->names.find(fns[i].va);
                        if (nit != hdb->names.end()) o["name"] = nit->second;
                    }
                    o["blocks"]    = hf.blocks.size();
                    o["callconv"]  = callconv_name(hf.callconv);
                    if (!hf.loops.empty()) o["loops"] = hf.loops.size();
                    if (hf.noreturn) o["noreturn"] = true;
                }
            }
            arr.push_back(std::move(o));
        }
        // The recursive-descent index can come up empty (stripped exports,
        // TLS-only entry, packed headers) while Hyperion still recovers
        // functions via RTTI/vtables/jump tables. Append those so callers
        // always see the analyzer's function set, not an empty list.
        size_t hype_extra = 0;
        if (hdb && arr.size() < limit) {
            std::vector<uint64_t> missing;
            missing.reserve(hdb->funcs.size());
            for (const auto& [va, hf] : hdb->funcs) {
                (void)hf;
                if (!seen.count(va)) missing.push_back(va);
            }
            std::sort(missing.begin(), missing.end());
            for (uint64_t va : missing) {
                if (arr.size() >= limit) break;
                const auto& hf = hdb->funcs.find(va)->second;
                json o = {{"va", va}, {"source", "hyperion"},
                          {"blocks", hf.blocks.size()},
                          {"callconv", callconv_name(hf.callconv)}};
                if (syms) {
                    const auto it = syms->find(va);
                    if (it != syms->end()) o["symbol"] = it->second;
                }
                const auto nit = hdb->names.find(va);
                if (nit != hdb->names.end() && !o.contains("symbol"))
                    o["name"] = nit->second;
                if (!hf.loops.empty()) o["loops"] = hf.loops.size();
                if (hf.noreturn) o["noreturn"] = true;
                arr.push_back(std::move(o));
                ++hype_extra;
            }
        }
        json out = {{"image", img_name}, {"functions", arr},
                    {"total", fns.size() + hype_extra},
                    {"index_total", fns.size()},
                    {"stats", {{"seeds", fidx->stats().seeds},
                               {"recursive_descent", fidx->stats().rd_functions},
                               {"heuristic", fidx->stats().heuristic_fns}}}};
        if (hdb) {
            out["hype"] = {{"engine", "hyperion"},
                           {"functions", hdb->funcs.size()},
                           {"rtti_classes", [&] {
                               auto& bin = ds::get();
                               return bin.hype ? bin.hype->rtti().classes().size() : 0;
                           }()}};
            if (fns.size() == 0 && !hdb->funcs.empty())
                out["note"] = "function-start index found no functions; rows below "
                              "with source=hyperion come from the analyzer DB";
        }
        if (arr.size() >= limit &&
            fns.size() + (hdb ? hdb->funcs.size() : 0) > arr.size())
            out["truncated"] = true;
        return out;
    }

    if (action == "xrefs") {
        const uint64_t addr = parse_addr_alias(args, {"addr", "base", "va", "address"});
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
        auto& eng = shared_engine();
        if (is_x86 && !eng.ok() && !eng.init()) fail("zydis engine init failed");

        // hyperion DB is the source on every architecture. For x86/x64, augment
        // it with the legacy index and a RIP-relative LEA sweep: the DB models
        // recognized data, and the legacy index skips high-entropy sections.
        std::map<uint64_t, std::pair<int, std::string>> best; // from -> rank, kind
        std::string engines;
        auto note_engine = [&](const char* e) {
            if (engines.find(e) == std::string::npos) {
                if (!engines.empty()) engines += "+";
                engines += e;
            }
        };

        if (!have_path) {
            auto& bin = ds::get();
            if (bin.hype && bin.hype->ready()) {
                const auto& db = bin.hype->db();
                const auto  it = db.xrefs_to.find(addr);
                // a call emits two records for one instruction, keep the strongest kind
                auto kind_rank = [](hype::XrefType t) {
                    switch (t) {
                    case hype::XrefType::CodeCall:  return 5;
                    case hype::XrefType::CodeJump:  return 4;
                    case hype::XrefType::DataWrite: return 3;
                    case hype::XrefType::DataRead:  return 2;
                    default:                        return 1;
                    }
                };
                if (it != db.xrefs_to.end()) {
                    for (const auto& x : it->second) {
                        const char* k = xref_kind_name_hype(x.type);
                        const int   r = kind_rank(x.type);
                        const auto  b = best.find(x.from);
                        if (b == best.end() || b->second.first < r)
                            best[x.from] = {r, k};
                    }
                    note_engine("hyperion");
                }
            }
        }

        if (is_x86 && xidx_ok && !*xidx_ok) {
            if (!xidx->build(*pe, *file, eng, base)) fail("xref index build failed");
            *xidx_ok = true;
        }
        if (is_x86) {
            bool any = false;
            for (const auto& r : xidx->refs_to(addr)) {
                any = true;
                int rank = 2;
                const char* k = xref_kind_name(r.kind);
                if (r.kind == disasm::xref_kind_t::call) rank = 5;
                else if (r.kind == disasm::xref_kind_t::jmp) rank = 4;
                const auto b = best.find(r.from);
                if (b == best.end() || b->second.first < rank)
                    best[r.from] = {rank, k};
            }
            if (any) note_engine("index");
        }

        // Fallback/augment: decode-sweep executable sections for
        // RIP-relative operands resolving exactly to addr. Catches LEA
        // string/data refs both indexes can miss (unrecognized strings,
        // entropy-skipped packed code). Bounded: 32MB scan, stops at limit.
        size_t scan_hits = 0;
        if (is_x86 && best.size() < limit) {
            size_t scanned = 0;
            constexpr size_t kMaxScan = 32u << 20;
            for (const auto& sec : pe->sections) {
                if (best.size() >= limit || scanned >= kMaxScan) break;
                if (!sec.is_executable() || sec.raw_size == 0) continue;
                auto soff = pe->rva_to_offset(sec.rva);
                if (!soff || *soff + sec.raw_size > file->size()) continue;
                const size_t n = std::min<size_t>(
                    sec.raw_size, kMaxScan - scanned);
                size_t off = 0;
                while (off < n && best.size() < limit) {
                    const uint64_t va = base + sec.rva + off;
                    uint8_t buf[16];
                    const size_t avail = std::min<size_t>(sizeof(buf), n - off);
                    std::memcpy(buf, file->data() + *soff + off, avail);
                    auto in = eng.decode(va, buf, avail, false);
                    if (!in || in->length == 0) { ++off; continue; }
                    if (in->has_rip_rel && in->rip_rel_target == addr &&
                        !best.count(va)) {
                        best[va] = {2, "data"};
                        ++scan_hits;
                    }
                    off += in->length ? in->length : 1;
                }
                scanned += n;
            }
            if (scan_hits) note_engine("lea_scan");
        }

        json arr = json::array();
        for (const auto& [from, rk] : best) {
            if (arr.size() >= limit) break;
            arr.push_back({{"from", from}, {"kind", rk.second}});
        }
        json out = {{"image", img_name}, {"engine", engines.empty() ? "none" : engines},
                    {"refs_to", arr}, {"count", arr.size()},
                    {"total", best.size()}};
        if (best.size() > arr.size()) out["truncated"] = true;
        if (best.empty())
            out["note"] = is_x86
                ? "no refs from hyperion, linear index, or LEA sweep; the address may "
                  "be unreferenced, in an unscanned region, or reached only indirectly (register)"
                : "no refs in the hyperion DB; wait for disasm.loaded hype.ready, or the "
                  "address may be unreferenced or reached only indirectly (register)";
        return out;
    }

    if (action == "strings") {
        const size_t min_chars = std::min<size_t>(args.value("min_chars", 4u), 256u);
        const size_t limit = std::min<size_t>(args.value("limit", 1000u), 10000u);
        // exec sections are garbage on packed code so theyre skipped unless asked for
        const bool include_exec = args.value("include_exec", false);
        json arr = json::array();
        disasm::string_stats_t stats{};
        for (const auto& sec : pe->sections) {
            if (sec.virtual_size == 0) continue;
            if (!include_exec && sec.is_executable()) continue;
            auto soff = pe->rva_to_offset(sec.rva);
            if (!soff) continue;
            const size_t len = std::min<uint32_t>(sec.raw_size, sec.virtual_size);
            if (*soff + len > file->size()) continue;
            auto hits = disasm::extract_strings(file->data() + *soff, len,
                                                base + sec.rva, min_chars, limit, &stats);
            for (const auto& h : hits) {
                if (arr.size() >= limit) break;
                arr.push_back({{"va", static_cast<uint64_t>(h.va)},
                               {"text", h.text}, {"utf16", h.utf16}});
            }
            if (arr.size() >= limit) break;
        }
        return {{"image", img_name}, {"strings", arr},
                {"total_scanned", stats.scanned}, {"truncated", stats.truncated}};
    }

    // hyperion backed actions, shared session only
    // these read the analyzer db which only exists for the app loaded image

    if (action == "blocks" || action == "globals" || action == "vtables") {
        if (have_path)
            fail(action + " requires the app-loaded image (no 'path' support, "
                 "load the binary in reverse-slop first)");
        // the lock above still guards the session
        auto& bin = ds::get();
        if (!bin.hype) fail("hyperion engine unavailable for this image");
        if (!bin.hype->ready()) {
            const std::string herr = bin.hype->error();
            if (!herr.empty())
                fail("hyperion analysis not running, " + herr +
                     " (re-run disasm.load to restart)");
            fail("hyperion analysis in progress (" +
                 std::to_string(static_cast<int>(bin.hype->progress() * 100)) +
                 "%), retry shortly");
        }
        const auto& db = bin.hype->db();

        if (action == "blocks") {
            const uint64_t addr = parse_addr(args, "addr");
            const hype::Function* f = bin.hype->function_at(addr);
            if (!f) fail("no hyperion function contains address " + hex64(addr));
            json arr = json::array();
            for (const auto& [start, bb] : f->blocks) {
                json succs = json::array(), preds = json::array();
                for (auto s : bb.succs) succs.push_back(s);
                for (auto p : bb.preds) preds.push_back(p);
                arr.push_back({{"start", start}, {"end", bb.end},
                               {"size", bb.end - start},
                               {"insn_count", bb.insns.size()},
                               {"succs", succs}, {"preds", preds}});
            }
            json loops = json::array();
            for (const auto& lp : f->loops)
                loops.push_back({{"header", lp.header},
                                 {"back_edge_src", lp.back_edge_src}});
            return {{"ok", true}, {"entry", f->entry},
                    {"name", bin.hype->db().names.count(f->entry)
                                  ? bin.hype->db().names.at(f->entry)
                                  : "sub_" + hex64(f->entry)},
                    {"blocks", arr}, {"count", arr.size()},
                    {"loops", loops}};
        }

        if (action == "vtables") {
            const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
            json arr = json::array();
            for (size_t i = 0; i < db.vtables.size() && arr.size() < limit; ++i) {
                const auto& vt = db.vtables[i];
                json entries = json::array();
                for (auto e : vt.entries) entries.push_back(e);
                arr.push_back({{"va", vt.addr}, {"entries", entries},
                               {"count", vt.entries.size()}});
            }
            json out = {{"ok", true}, {"vtables", arr}, {"count", arr.size()},
                        {"total", db.vtables.size()}};
            if (db.vtables.size() > arr.size()) out["truncated"] = true;
            return out;
        }

        // globals
        {
            const size_t limit = std::min<size_t>(args.value("limit", 500u), 10000u);
            json arr = json::array();
            for (const auto& [va, g] : db.globals) {
                if (arr.size() >= limit) break;
                arr.push_back({{"va", va}, {"size", g.size}, {"name", g.name}});
            }
            json out = {{"ok", true}, {"globals", arr}, {"count", arr.size()},
                        {"total", db.globals.size()}};
            if (db.globals.size() > arr.size()) out["truncated"] = true;
            return out;
        }
    }

    fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
         "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|unload|"
         "analyze_stop)");
}

// tool: debugger — PS4 live debugging (ps4debug-NG debug session on the console)

namespace {

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

runtime::backend_ps4_t& need_ps4() {
    auto* p = dynamic_cast<runtime::backend_ps4_t*>(&runtime::active());
    if (!p || !p->connected())
        fail("PS4 debug actions require a connected console (target.ps4_connect {host})");
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

// ps4debug-NG has no breakpoint/watchpoint query command, so slots we armed
// are tracked client-side for auto-allocation and clear-by-address
std::mutex& ps4_slot_mu() { static std::mutex m; return m; }
std::map<uint64_t, uint32_t>& ps4_bp_slots() { static std::map<uint64_t, uint32_t> m; return m; }  // addr -> index
std::map<uint64_t, uint32_t>& ps4_wp_slots() { static std::map<uint64_t, uint32_t> m; return m; }  // addr -> index
std::map<uint32_t, uint64_t>& ps4_rpc_stubs() { static std::map<uint32_t, uint64_t> m; return m; } // pid -> stub

uint32_t ps4_alloc_slot(const std::map<uint64_t, uint32_t>& used, uint32_t max) {
    for (uint32_t i = 0; i < max; ++i) {
        bool taken = false;
        for (const auto& [a, idx] : used)
            if (idx == i) { taken = true; break; }
        if (!taken) return i;
    }
    fail("no free slot (all " + std::to_string(max) + " in use)");
}

// walk the rbp frame chain through live session reads; frame 0 is rip itself
json ps4_frames_json(runtime::session_t& s, uint32_t lwpid,
                     const runtime::thread_context_t& ctx, size_t depth) {
    json arr = json::array();
    arr.push_back({{"index", 0}, {"ret_addr", ctx.rip}, {"frame_ptr", ctx.rbp}});
    uint64_t rbp = ctx.rbp;
    for (size_t i = 1; i < depth && rbp != 0; ++i) {
        uint64_t next = 0, ret = 0;
        auto io1 = s.read(static_cast<uintptr_t>(rbp), &next, sizeof(next));
        auto io2 = s.read(static_cast<uintptr_t>(rbp + 8), &ret, sizeof(ret));
        if (!io1.ok || !io2.ok) break;
        arr.push_back({{"index", i}, {"ret_addr", ret}, {"frame_ptr", rbp}});
        if (next == 0 || next <= rbp) break;   // 0 = top; chain must ascend
        rbp = next;
    }
    return arr;
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
    auto& p = need_ps4();

    if (action == "ps4_attach") {
        const uint32_t pid = ps4_pid_arg(args);
        std::string err;
        if (!p.ps4_debug_attach(pid, err)) fail("ps4_attach failed: " + err);
        return {{"attached", true}, {"pid", pid}, {"endpoint", p.endpoint()},
                {"branding", p.branding()}};
    }
    if (action == "ps4_detach") {
        p.ps4_debug_detach();
        std::lock_guard lk(ps4_slot_mu());
        ps4_bp_slots().clear();
        ps4_wp_slots().clear();
        return {{"attached", false}};
    }
    if (action == "ps4_status") {
        return {{"attached", p.ps4_debug_attached()},
                {"pid", p.ps4_debug_pid()},
                {"pending_events", p.ps4_pending_events()},
                {"endpoint", p.endpoint()},
                {"branding", p.branding()},
                {"backend", "PS4"}};
    }
    if (action == "ps4_bp_set") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!p.ps4_debug_attached())
            fail("ps4_bp_set requires ps4_attach first");
        std::lock_guard lk(ps4_slot_mu());
        uint32_t index = 0;
        if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
        } else {
            auto it = ps4_bp_slots().find(addr);
            index = it != ps4_bp_slots().end() ? it->second
                                               : ps4_alloc_slot(ps4_bp_slots(), 30);
        }
        auto io = p.ps4_set_breakpoint(index, true, static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_bp_set failed (slot " + std::to_string(index) +
                         ", error " + std::to_string(io.error) +
                         "; duplicate address or slot in use?)");
        ps4_bp_slots()[addr] = index;
        return {{"set", true}, {"addr", addr}, {"index", index}, {"hw", false}};
    }
    if (action == "ps4_bp_clear") {
        std::lock_guard lk(ps4_slot_mu());
        uint64_t addr = 0;
        uint32_t index = 0;
        bool have = false;
        if (args.contains("addr")) {
            addr = parse_addr(args, "addr");
            auto it = ps4_bp_slots().find(addr);
            if (it == ps4_bp_slots().end())
                fail("ps4_bp_clear: no breakpoint armed at that addr");
            index = it->second;
            have = true;
        } else if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
            for (const auto& [a, i] : ps4_bp_slots())
                if (i == index) { addr = a; have = true; break; }
            if (!have) fail("ps4_bp_clear: slot " + std::to_string(index) + " not armed by us");
        } else {
            fail("ps4_bp_clear requires addr or index");
        }
        auto io = p.ps4_set_breakpoint(index, false, static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_bp_clear failed (error " + std::to_string(io.error) + ")");
        ps4_bp_slots().erase(addr);
        return {{"cleared", true}, {"addr", addr}, {"index", index}};
    }
    if (action == "ps4_watch_set") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len = args.contains("len") ? parse_addr(args, "len") : 8;
        const uint32_t type = static_cast<uint32_t>(args.value("type", 3u));   // 3 = read/write
        if (type != 0 && type != 1 && type != 3)
            fail("ps4_watch_set: type must be 0=exec, 1=write or 3=read_write");
        if (!p.ps4_debug_attached())
            fail("ps4_watch_set requires ps4_attach first");
        std::lock_guard lk(ps4_slot_mu());
        uint32_t index = 0;
        if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
        } else {
            auto it = ps4_wp_slots().find(addr);
            index = it != ps4_wp_slots().end() ? it->second
                                               : ps4_alloc_slot(ps4_wp_slots(), 4);
        }
        auto io = p.ps4_set_watchpoint(index, true, static_cast<uint32_t>(len), type,
                                       static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_watch_set failed (slot " + std::to_string(index) +
                         ", error " + std::to_string(io.error) + ")");
        ps4_wp_slots()[addr] = index;
        return {{"set", true}, {"addr", addr}, {"index", index},
                {"len", len}, {"type", type}, {"hw", true}};
    }
    if (action == "ps4_watch_clear") {
        std::lock_guard lk(ps4_slot_mu());
        uint64_t addr = 0;
        uint32_t index = 0;
        if (args.contains("addr")) {
            addr = parse_addr(args, "addr");
            auto it = ps4_wp_slots().find(addr);
            if (it == ps4_wp_slots().end())
                fail("ps4_watch_clear: no watchpoint armed at that addr");
            index = it->second;
        } else if (args.contains("index")) {
            index = static_cast<uint32_t>(parse_addr(args, "index"));
            for (const auto& [a, i] : ps4_wp_slots())
                if (i == index) { addr = a; break; }
        } else {
            fail("ps4_watch_clear requires addr or index");
        }
        auto io = p.ps4_set_watchpoint(index, false, 8, 3, 0);
        if (!io.ok) fail("ps4_watch_clear failed (error " + std::to_string(io.error) + ")");
        ps4_wp_slots().erase(addr);
        return {{"cleared", true}, {"addr", addr}, {"index", index}};
    }
    if (action == "ps4_continue") {
        const uint32_t stop = static_cast<uint32_t>(args.value("stop", 0u));
        if (stop > 2) fail("ps4_continue: stop must be 0=resume, 1=stop, 2=kill");
        auto io = p.ps4_continue(stop);
        if (!io.ok) fail("ps4_continue failed (error " + std::to_string(io.error) + ")");
        return {{"continued", true}, {"stop", stop}};
    }
    if (action == "ps4_step") {
        const uint32_t lwpid = args.contains("lwpid")
            ? static_cast<uint32_t>(parse_addr(args, "lwpid")) : 0;   // 0 = all threads
        auto io = p.ps4_step(lwpid);
        if (!io.ok) fail("ps4_step failed (error " + std::to_string(io.error) + ")");
        return {{"stepped", true}, {"lwpid", lwpid}};
    }
    if (action == "ps4_suspend" || action == "ps4_resume") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        auto io = action == "ps4_suspend" ? p.ps4_suspend_thread(lwpid)
                                          : p.ps4_resume_thread(lwpid);
        if (!io.ok) fail(action + " failed (error " + std::to_string(io.error) + ")");
        return {{"ok", true}, {"lwpid", lwpid},
                {"suspended", action == "ps4_suspend"}};
    }
    if (action == "ps4_process_stop") {
        const uint32_t pid = ps4_pid_arg(args);
        const uint32_t state = static_cast<uint32_t>(args.value("state", 1u));
        if (state > 2) fail("ps4_process_stop: state must be 0=resume, 1=stop, 2=kill");
        auto io = p.ps4_process_stop(pid, state);
        if (!io.ok) fail("ps4_process_stop failed (error " + std::to_string(io.error) + ")");
        return {{"ok", true}, {"pid", pid}, {"state", state}};
    }
    if (action == "ps4_regs") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        runtime::thread_context_t ctx{};
        auto io = p.get_thread_context(lwpid, ctx);
        if (!io.ok) fail("ps4_regs failed (error " + std::to_string(io.error) +
                         "; thread stopped?)");
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
        if (!p.get_thread_context(lwpid, ctx).ok)
            fail("ps4_set_reg: cannot read regs of lwpid " + std::to_string(lwpid));
        auto* slot = ps4_reg_ptr(ctx, name);
        if (!slot) fail("ps4_set_reg: unknown register '" + name +
                        "' (rax..r15, rip, rsp, rbp, flags)");
        *slot = value;
        if (!p.set_thread_context(lwpid, ctx).ok)
            fail("ps4_set_reg failed writing lwpid " + std::to_string(lwpid));
        return {{"set", true}, {"lwpid", lwpid}, {"register", name}, {"value", value}};
    }
    if (action == "ps4_dbregs") {
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        uint64_t dr[16]{};
        auto io = p.ps4_get_dbregs(lwpid, dr);
        if (!io.ok) fail("ps4_dbregs failed (error " + std::to_string(io.error) + ")");
        json arr = json::array();
        for (uint64_t d : dr) arr.push_back(d);
        return {{"lwpid", lwpid}, {"dr", arr}};
    }
    if (action == "ps4_wait") {
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        runtime::ps4_event_t ev{};
        if (!p.ps4_wait_event(ev, timeout_ms))
            return {{"halted", false}, {"timeout_ms", timeout_ms},
                    {"pending", p.ps4_pending_events()}};
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
                {"pending", p.ps4_pending_events()}};
    }
    if (action == "ps4_callstack") {
        auto& s = need_session();
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        const size_t depth = std::min<size_t>(args.value("depth", 32u), 64u);
        runtime::thread_context_t ctx{};
        if (!p.get_thread_context(lwpid, ctx).ok)
            fail("ps4_callstack: cannot read regs of lwpid " + std::to_string(lwpid));
        json arr = ps4_frames_json(s, lwpid, ctx, depth);
        return {{"lwpid", lwpid}, {"frames", arr}, {"count", arr.size()}};
    }
    if (action == "ps4_bp_list" || action == "ps4_watch_list") {
        std::lock_guard lk(ps4_slot_mu());
        const bool bp = action == "ps4_bp_list";
        const auto& m = bp ? ps4_bp_slots() : ps4_wp_slots();
        json arr = json::array();
        for (const auto& [addr, index] : m)
            arr.push_back({{"addr", addr}, {"index", index}});
        return {{bp ? "breakpoints" : "watchpoints", arr},
                {"count", arr.size()},
                {"note", "client-side record of slots armed through this tool; the payload has no query command"}};
    }
    if (action == "ps4_until") {
        // one-call "run until addr": arm a one-shot bp, continue, wait, clear
        const uint64_t addr = parse_addr(args, "addr");
        const int timeout_ms = std::min(args.value("timeout_ms", 30000), 60000);
        if (!p.ps4_debug_attached())
            fail("ps4_until requires ps4_attach first");
        uint32_t index = 0;
        bool owned = false;
        {
            std::lock_guard lk(ps4_slot_mu());
            auto it = ps4_bp_slots().find(addr);
            if (it != ps4_bp_slots().end()) index = it->second;
            else {
                index = ps4_alloc_slot(ps4_bp_slots(), 30);
                owned = true;
            }
        }
        auto io = p.ps4_set_breakpoint(index, true, static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_until: cannot arm breakpoint (error " +
                         std::to_string(io.error) + ")");
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_bp_slots()[addr] = index;
        }
        if (!p.ps4_continue(runtime::ps4::kStopResume).ok) {
            p.ps4_set_breakpoint(index, false, static_cast<uintptr_t>(addr));
            if (owned) { std::lock_guard lk(ps4_slot_mu()); ps4_bp_slots().erase(addr); }
            fail("ps4_until: continue failed");
        }
        runtime::ps4_event_t ev{};
        const bool halted = p.ps4_wait_event(ev, timeout_ms);
        p.ps4_set_breakpoint(index, false, static_cast<uintptr_t>(addr));
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_bp_slots().erase(addr);
        }
        if (!halted)
            return {{"halted", false}, {"until", addr}, {"timeout_ms", timeout_ms}};
        json o = ps4_event_json(ev);
        o["halted"] = true;
        o["until"] = addr;
        return o;
    }
    if (action == "ps4_find_write") {
        // one-call "who writes here": write watchpoint, continue, wait, callstack
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len = args.contains("len") ? parse_addr(args, "len") : 8;
        const int timeout_ms = std::min(args.value("timeout_ms", 30000), 60000);
        if (!p.ps4_debug_attached())
            fail("ps4_find_write requires ps4_attach first");
        uint32_t index = 0;
        bool owned = false;
        {
            std::lock_guard lk(ps4_slot_mu());
            auto it = ps4_wp_slots().find(addr);
            if (it != ps4_wp_slots().end()) index = it->second;
            else {
                index = ps4_alloc_slot(ps4_wp_slots(), 4);
                owned = true;
            }
        }
        auto io = p.ps4_set_watchpoint(index, true, static_cast<uint32_t>(len),
                                       runtime::ps4::kWpWrite,
                                       static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_find_write: cannot arm watchpoint (error " +
                         std::to_string(io.error) + ")");
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_wp_slots()[addr] = index;
        }
        p.ps4_continue(runtime::ps4::kStopResume);
        runtime::ps4_event_t ev{};
        const bool halted = p.ps4_wait_event(ev, timeout_ms);
        p.ps4_set_watchpoint(index, false, 8, runtime::ps4::kWpRdWr, 0);
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_wp_slots().erase(addr);
        }
        json out = {{"halted", halted}, {"addr", addr}, {"len", len},
                    {"timeout_ms", timeout_ms}};
        if (halted) {
            out["event"] = ps4_event_json(ev);
            auto& s = need_session();
            const size_t depth = std::min<size_t>(args.value("depth", 32u), 64u);
            json frames = ps4_frames_json(s, ev.lwpid, ev.ctx, depth);
            out["callstack"] = frames;
            out["writer_rip"] = ev.ctx.rip;
        }
        return out;
    }
    if (action == "ps4_trace_calls") {
        // breakpoint arg logger: continue+wait loop recording the 6 arg regs
        const uint64_t addr = parse_addr(args, "addr");
        const size_t count = std::min<size_t>(args.value("count", 64u), 4096u);
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        if (!p.ps4_debug_attached())
            fail("ps4_trace_calls requires ps4_attach first");
        uint32_t index = 0;
        bool owned = false;
        {
            std::lock_guard lk(ps4_slot_mu());
            auto it = ps4_bp_slots().find(addr);
            if (it != ps4_bp_slots().end()) index = it->second;
            else {
                index = ps4_alloc_slot(ps4_bp_slots(), 30);
                owned = true;
            }
        }
        auto io = p.ps4_set_breakpoint(index, true, static_cast<uintptr_t>(addr));
        if (!io.ok) fail("ps4_trace_calls: cannot arm breakpoint (error " +
                         std::to_string(io.error) + ")");
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_bp_slots()[addr] = index;
        }
        json hits = json::array();
        std::string stop_reason = "count_reached";
        for (size_t i = 0; i < count; ++i) {
            if (!p.ps4_continue(runtime::ps4::kStopResume).ok) {
                stop_reason = "continue_failed";
                break;
            }
            runtime::ps4_event_t ev{};
            if (!p.ps4_wait_event(ev, timeout_ms)) {
                stop_reason = "timeout";
                break;
            }
            hits.push_back({{"index", i}, {"lwpid", ev.lwpid},
                            {"thread", ev.thread_name}, {"signal", ev.signal},
                            {"rip", ev.ctx.rip}, {"rdi", ev.ctx.rdi},
                            {"rsi", ev.ctx.rsi}, {"rdx", ev.ctx.rdx},
                            {"rcx", ev.ctx.rcx}, {"r8", ev.ctx.r8},
                            {"r9", ev.ctx.r9}});
        }
        p.ps4_set_breakpoint(index, false, static_cast<uintptr_t>(addr));
        if (owned) {
            std::lock_guard lk(ps4_slot_mu());
            ps4_bp_slots().erase(addr);
        }
        return {{"addr", addr}, {"hits", hits}, {"hits_count", hits.size()},
                {"stop_reason", stop_reason},
                {"note", "target stays stopped at the last hit; ps4_continue resumes"}};
    }
    if (action == "ps4_trace_steps") {
        // console-side single-step execution trace with disassembly
        auto& s = need_session();
        const uint32_t lwpid = ps4_lwpid_arg(p, args);
        const size_t count = std::min<size_t>(args.value("count", 64u), 4096u);
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        if (!p.ps4_debug_attached())
            fail("ps4_trace_steps requires ps4_attach first");
        auto& eng = shared_engine();
        if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
        json steps = json::array();
        std::string stop_reason = "count_reached";
        for (size_t i = 0; i < count; ++i) {
            if (!p.ps4_step(lwpid).ok) { stop_reason = "step_failed"; break; }
            runtime::ps4_event_t ev{};
            if (!p.ps4_wait_event(ev, timeout_ms)) {
                stop_reason = "timeout";
                break;
            }
            json rec = {{"index", i}, {"lwpid", ev.lwpid}, {"rip", ev.ctx.rip}};
            uint8_t buf[16]{};
            auto io = s.read(static_cast<uintptr_t>(ev.ctx.rip), buf, sizeof(buf));
            if (io.ok) {
                if (auto in = eng.decode(ev.ctx.rip, buf, sizeof(buf)))
                    rec["text"] = in->text;
            }
            steps.push_back(std::move(rec));
        }
        return {{"lwpid", lwpid}, {"steps", steps}, {"steps_count", steps.size()},
                {"stop_reason", stop_reason}};
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
        {
            std::lock_guard lk(ps4_slot_mu());
            auto it = ps4_rpc_stubs().find(pid);
            if (it != ps4_rpc_stubs().end()) stub = it->second;
        }
        if (stub == 0) {
            auto io = p.ps4_install(pid, stub);
            if (!io.ok || stub == 0)
                fail("ps4_call: CMD_PROC_INTALL failed (error " +
                     std::to_string(io.error) + ")");
            std::lock_guard lk(ps4_slot_mu());
            ps4_rpc_stubs()[pid] = stub;
        }
        uint64_t rax = 0;
        auto io = p.ps4_call(pid, stub, addr, fargs, rax);
        if (!io.ok) fail("ps4_call failed (error " + std::to_string(io.error) + ")");
        return {{"called", true}, {"pid", pid}, {"addr", addr},
                {"rpcstub", stub}, {"rax", rax}};
    }

    fail("debugger: unknown ps4 action (ps4_attach|ps4_detach|ps4_status|"
         "ps4_bp_set|ps4_bp_clear|ps4_bp_list|ps4_watch_set|ps4_watch_clear|"
         "ps4_watch_list|ps4_continue|ps4_step|ps4_suspend|ps4_resume|"
         "ps4_process_stop|ps4_regs|ps4_set_reg|ps4_dbregs|ps4_wait|"
         "ps4_events|ps4_callstack|ps4_call|ps4_until|ps4_find_write|"
         "ps4_trace_calls|ps4_trace_steps)");
}

} // namespace

// tool: debugger

json tool_debugger(const json& args) {
    const std::string action = require_action(args);
    // PS4-only build: every live-debug action drives the console's
    // ps4debug-NG session over the wire
    if (action.rfind("ps4_", 0) == 0) return tool_debugger_ps4(action, args);
    if (action == "status") {
        auto* p = dynamic_cast<runtime::backend_ps4_t*>(&runtime::active());
        json out;
        out["backend"]        = runtime::active_badge();
        out["ps4_connected"]  = runtime::registry_ps4_active();
        out["debug_attached"] = p ? p->ps4_debug_attached() : false;
        out["debug_pid"]      = p ? p->ps4_debug_pid() : 0;
        out["pending_events"] = p ? static_cast<uint64_t>(p->ps4_pending_events()) : 0;
        out["note"] = "PS4 toolkit: live debugging is remote over ps4debug-NG - use ps4_* actions (ps4_attach, ps4_bp_set, ps4_continue, ps4_until, ps4_find_write, ps4_trace_calls, ps4_trace_steps, ps4_regs, ps4_call, ps4_wait, ps4_events); playbooks: guide list";
        return out;
    }
    fail("debugger: PS4-only build - use ps4_* actions (see guide get ps4_setup); local Win32 debugging was removed");
}

emu::page_source_t image_page_source(std::shared_ptr<const image_view_t> view) {
    return [view = std::move(view)](uint64_t page, uint8_t* out) {
        std::lock_guard lk(ds::state_mutex());
        const auto& bin = ds::get();
        if (!bin.ready || bin.file_hash != view->hash || page < bin.base) return false;
        const uint64_t rva = page - bin.base;
        if (rva >= view->extent) return false;
        view->read(bin, rva, emu::kPageSize, out);
        return true;
    };
}

// api_returns values: integers (negative allowed, -1 = INVALID_HANDLE_VALUE)
// or numeric strings
uint64_t parse_api_value(const json& v, const std::string& key) {
    if (v.is_number_integer() && v.get<int64_t>() < 0)
        return static_cast<uint64_t>(v.get<int64_t>());
    const json wrap = {{key, v}};
    return parse_addr(wrap, key.c_str());
}

std::string lower_ascii(std::string s) {
    for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return s;
}

// IAT slots of a PE32+ image, for the emulator's import stubs. returns maps
// lowercase "func" or "dll!func" to a per-import return value; matched keys
// are removed so the caller can report the rest
std::vector<emu::import_slot_t> image_import_slots(const ds::binary_t& bin,
                                                   std::map<std::string, uint64_t>& returns) {
    std::vector<emu::import_slot_t> out;
    if (bin.format != disasm::image_format_t::pe || !bin.pe.pe32plus) return out;
    std::vector<std::string> used;
    for (const auto& dll : bin.pe.imports) {
        for (const auto& fn : dll.functions) {
            if (!fn.iat_rva) continue;
            if (out.size() >= emu::kMaxImports) break;
            emu::import_slot_t slot;
            slot.slot = bin.base + fn.iat_rva;
            const std::string func = fn.by_ordinal ? "#" + std::to_string(fn.ordinal) : fn.name;
            slot.name = dll.dll + "!" + func;
            for (const std::string& key : {lower_ascii(slot.name), lower_ascii(func)}) {
                if (auto it = returns.find(key); it != returns.end()) {
                    slot.has_ret = true;
                    slot.ret = it->second;
                    used.push_back(key);
                    break;
                }
            }
            out.push_back(std::move(slot));
        }
    }
    for (const auto& key : used) returns.erase(key);
    return out;
}

json tool_emulate(const json& args, infra::cancel_token_t cancel) {
    const std::string action = require_action(args);
    if (action != "run") fail("emulate: unknown action");

    // Input bounds: these all run before unicorn's timer starts (stack commit,
    // per-byte taint marking, trace growth), so an unbounded value hangs the
    // request regardless of timeout_ms
    constexpr size_t   kMaxStackSize = 64u << 20;
    constexpr size_t   kMaxTaintLen  = 1u << 20;
    constexpr size_t   kMaxTraceMax  = 16384;
    constexpr size_t   kMaxDumpLen   = 1u << 20;

    emu::run_request_t req;
    req.cancel = cancel;
    const bool page_in = args.value("page_in", true);

    // lowercase "func" or "dll!func" -> that import's stub return value
    std::map<std::string, uint64_t> api_returns;
    if (auto it = args.find("api_returns"); it != args.end()) {
        if (!it->is_object()) fail("api_returns must be an object of import name -> value");
        for (auto r = it->begin(); r != it->end(); ++r)
            api_returns[lower_ascii(r.key())] = parse_api_value(r.value(), r.key());
    }

    // Building the request reads the shared image / attached session, so it
    // runs under g_tool_mu. The run itself owns a private unicorn instance and
    // must not hold it, or every other tool (and initialize) queues behind the
    // emulation until the client times out
    std::unique_lock tool_lk(g_tool_mu);

    // hex wins over file_addr wins over target_addr, code runs at its real va unless base says otherwise
    bool have_code = false;
    if (args.contains("hex") && args.at("hex").is_string()) {
        req.code = hex_decode(args.at("hex").get<std::string>());
        have_code = !req.code.empty();
    }
    if (!have_code && args.contains("file_addr")) {
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
        require_x86_image(bin.arch, bin.format, "emulate.run");
        const uint64_t addr = parse_addr(args, "file_addr");
        uint64_t len = args.contains("code_len") ? parse_addr(args, "code_len") : 64;
        if (len == 0 || len > (1ull << 20)) fail("bad code_len");
        auto off = bin.offset_of(addr);   // session va, follows a rebased load
        if (!off) fail("file_addr not mapped in the loaded image");
        len = std::min<uint64_t>(len, bin.file.size() - *off);
        // relocated like the demand pages, or a rebased slice keeps
        // ImageBase pointers the pages around it no longer have
        auto view = image_view_t::make(bin);
        req.code.resize(static_cast<size_t>(len));
        view->read(bin, addr - bin.base, req.code.size(), req.code.data());
        req.code_base  = addr;
        req.image_base = bin.base;
        if (page_in) req.page_in = image_page_source(std::move(view));
        if (args.value("stub_imports", true))
            req.imports = image_import_slots(bin, api_returns);
        have_code = true;
    }
    if (!have_code && args.contains("target_addr")) {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached for target_addr");
        const uint64_t addr = parse_addr(args, "target_addr");
        uint64_t len = args.contains("code_len") ? parse_addr(args, "code_len") : 64;
        if (len == 0 || len > (1ull << 20)) fail("bad code_len");
        req.code.resize(static_cast<size_t>(len));
        auto io = s->read(static_cast<uintptr_t>(addr), req.code.data(),
                          req.code.size());
        if (!io.ok || io.bytes == 0) fail("cannot read target memory");
        req.code.resize(io.bytes);
        req.code_base = addr;
        if (page_in) {
            req.page_in = [s](uint64_t page, uint8_t* out) {
                if (!s->valid()) return false;
                auto rd = s->read(static_cast<uintptr_t>(page), out, emu::kPageSize);
                return rd.ok && rd.bytes == emu::kPageSize;
            };
        }
        have_code = true;
    }
    if (!have_code)
        fail("no code source: pass 'hex', 'file_addr' or 'target_addr'");

    if (args.contains("base")) req.code_base = parse_addr(args, "base");
    const uint64_t start_va = args.contains("entry")
        ? parse_addr(args, "entry")
        : req.code_base;
    if (start_va < req.code_base || start_va >= req.code_base + req.code.size())
        fail("entry outside code range");
    req.entry_absolute = true;
    req.entry          = start_va;

    if (args.contains("stack_base")) req.stack_base = parse_addr(args, "stack_base");
    if (args.contains("stack_size")) {
        const uint64_t ss = parse_addr(args, "stack_size");
        if (ss < 0x1000 || ss > kMaxStackSize)
            fail("stack_size must be 0x1000..0x4000000 (64 MiB)");
        req.stack_size = static_cast<size_t>(ss);
    }
    if (args.contains("sp")) { req.sp_set = true; req.sp = parse_addr(args, "sp"); }

    if (auto it = args.find("regs"); it != args.end() && it->is_object()) {
        for (auto r = it->begin(); r != it->end(); ++r) {
            const json& v = r.value();
            uint64_t value = 0;
            if (v.is_number_unsigned()) value = v.get<uint64_t>();
            else if (v.is_number_integer() && v.get<int64_t>() >= 0) value = static_cast<uint64_t>(v.get<int64_t>());
            else if (v.is_string()) value = std::stoull(v.get<std::string>(), nullptr, 0);
            else fail("regs values must be non-negative integers or hex strings");
            req.regs[r.key()] = value;
        }
    }

    if (auto it = args.find("maps"); it != args.end() && it->is_array()) {
        for (const auto& m : *it) {
            if (!m.contains("addr") || !m.contains("hex"))
                fail("maps entries need addr + hex");
            emu::emu_mem_region_t reg;
            reg.addr = parse_addr(m, "addr");
            reg.bytes = hex_decode(m.at("hex").is_string()
                                       ? m.at("hex").get<std::string>()
                                       : std::string{});
            if (reg.bytes.empty()) fail("empty map region");
            req.maps.push_back(std::move(reg));
        }
    }

    if (args.contains("until"))       req.until_addr       = parse_addr(args, "until");
    if (args.contains("count"))       req.max_instructions = parse_addr(args, "count");
    if (args.contains("timeout_ms"))
        req.timeout_ms = static_cast<uint32_t>(
            std::min<uint64_t>(parse_addr(args, "timeout_ms"), emu::kMaxTimeoutMs));
    if (args.contains("trace"))       req.trace            = args.value("trace", false);
    if (args.contains("trace_max"))
        req.trace_max = static_cast<size_t>(
            std::min<uint64_t>(parse_addr(args, "trace_max"), kMaxTraceMax));

    if (auto it = args.find("taint"); it != args.end() && it->is_array()) {
        uint64_t taint_total = 0;
        for (const auto& t : *it) {
            if (!t.contains("addr") || !t.contains("len"))
                fail("taint entries need addr + len");
            emu::run_request_t::taint_source_t s;
            s.addr = parse_addr(t, "addr");
            const uint64_t len = parse_addr(t, "len");
            if (len == 0) fail("taint len must be > 0");
            taint_total += len;
            if (len > kMaxTaintLen || taint_total > kMaxTaintLen)
                fail("taint ranges must total <= 1048576 bytes");
            s.len = static_cast<size_t>(len);
            req.taint_sources.push_back(s);
        }
    }
    if (args.contains("watch_addr") && args.contains("watch_len")) {
        req.watch_addr = parse_addr(args, "watch_addr");
        req.watch_len  = static_cast<size_t>(parse_addr(args, "watch_len"));
        if (req.watch_len > kMaxTaintLen) fail("watch_len must be <= 1048576");
    }
    if (auto it = args.find("dump"); it != args.end() && it->is_array()) {
        uint64_t dump_total = 0;
        for (const auto& d : *it) {
            if (!d.contains("addr") || !d.contains("len"))
                fail("dump entries need addr + len");
            emu::run_request_t::dump_range_t r;
            r.addr = parse_addr(d, "addr");
            const uint64_t len = parse_addr(d, "len");
            if (len == 0) fail("dump len must be > 0");
            dump_total += len;
            if (len > kMaxDumpLen || dump_total > kMaxDumpLen)
                fail("dump ranges must total <= 1048576 bytes");
            r.len = static_cast<size_t>(len);
            req.dumps.push_back(r);
        }
    }
    if (args.contains("api_ret")) req.api_ret = parse_api_value(args.at("api_ret"), "api_ret");
    tool_lk.unlock();

    auto r = emu::emulate_run(req);
    if (!r.ok && !r.error.empty()) fail(r.error);

    json out = {{"ok", r.ok},
                {"stopped_reason", r.stopped_reason},
                {"instructions", r.instructions}};
    if (!r.error.empty()) out["error"] = r.error;

    json regs = json::object();
    for (const auto& [name, value] : r.regs) regs[name] = value;
    out["regs"] = regs;

    if (!r.trace.empty()) {
        json arr = json::array();
        for (const auto& t : r.trace)
            arr.push_back({{"ip", t.ip}, {"text", t.text}});
        out["trace"] = arr;
    }
    {
        json arr = json::array();
        for (const auto& w : r.writes)
            arr.push_back({{"ip", w.ip}, {"addr", w.addr}, {"len", w.len},
                           {"value", w.value}});
        out["writes"] = arr;
        out["total_writes"] = r.total_writes;
    }
    if (!req.imports.empty()) {
        json arr = json::array();
        for (const auto& c : r.api_calls)
            arr.push_back({{"ip", c.ip}, {"ret", c.ret}, {"name", c.name},
                           {"args", json::array({c.args[0], c.args[1],
                                                 c.args[2], c.args[3]})}});
        out["api_calls"]       = arr;
        out["total_api_calls"] = r.total_api_calls;
    }
    if (!api_returns.empty()) {
        json keys = json::array();
        for (const auto& [key, value] : api_returns) keys.push_back(key);
        out["api_returns_unmatched"] = keys;
    }
    if (req.page_in) out["paged_in"] = r.paged_in;
    if (!req.dumps.empty()) {
        json arr = json::array();
        for (size_t i = 0; i < r.memory.size(); ++i) {
            const auto& m = r.memory[i];
            arr.push_back({{"addr", m.addr}, {"len", m.bytes.size()},
                           {"requested", req.dumps[i].len},
                           {"hex", to_hex(m.bytes.data(), m.bytes.size())}});
        }
        out["memory"] = arr;
    }
    if (r.fault) {
        out["fault"] = {{"ip", r.fault->ip}, {"addr", r.fault->addr},
                        {"access", r.fault->access}};
        if (r.page_in_exhausted)
            out["note"] = "demand paging hit its 4096-page (16 MiB) budget; "
                          "lower count or start closer to the code of interest";
        else if (req.page_in)
            out["note"] = "the address is outside the code source: file_addr "
                          "pages come from the loaded image (its sections, "
                          "inside SizeOfImage), target_addr pages from the "
                          "attached process. Map anything else (heap, other "
                          "modules, PEB.Ldr) with maps=[{addr,hex}]";
        else
            out["note"] = "only the requested code bytes (+ optional maps=) are "
                          "mapped: CALL/JMP to unmapped callees and loads from "
                          "unmapped data stop with invalid_mem_* (trace shows "
                          "<unmapped>, never synthetic ADD [rax],al). Use "
                          "file_addr/target_addr with page_in (default on) to "
                          "pull the rest on demand, or map it via "
                          "maps=[{addr,hex}]";
    }

    if (!req.taint_sources.empty()) {
        json ranges = json::array();
        for (const auto& rg : r.taint_ranges)
            ranges.push_back({{"addr", rg.addr}, {"len", rg.len}});
        json events = json::array();
        for (const auto& e : r.taint_events)
            events.push_back({{"ip", e.ip}, {"insn", e.insn},
                              {"kind", e.kind}, {"target", e.target}});
        out["taint_ranges"]   = ranges;
        out["taint_events"]   = events;
        out["output_tainted"] = r.output_tainted;
    }
    return out;
}

// tool: analyze

// Shared bindiff core for sync `diff` and the async diff_start jobs.
// Returns the FULL result (all non-identical diffs); callers slice `diffs`
// to their limit. Throws (fail) on load/analyze failure or when cancelled
// between phases. `cancelled()` is polled between phases and inside the
// compare; `report(stage, progress)` feeds job polling (-1 = indeterminate).
json run_diff_core(const std::string& pa, const std::string& pb,
                   uint32_t timeout_ms, size_t max_pairs,
                   const std::function<bool()>& cancelled,
                   const std::function<void(const std::string&, float)>& report) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    auto ms_left = [&]() -> uint64_t {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count());
    };
    auto check_cancel = [&](const char* what) {
        if (cancelled && cancelled()) fail(std::string(what) + " cancelled");
        if (ms_left() == 0)
            fail(std::string(what) + " timed out (timeout_ms exceeded)");
    };

    auto load_bytes = [](const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) fail("cannot open " + path);
        f.seekg(0, std::ios::end);
        const auto sz = f.tellg();
        if (sz <= 0) fail("empty file: " + path);
        if (sz > (256ll << 20)) fail("file too large for diff (>256MB): " + path);
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> bytes(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(bytes.data()), sz);
        if (!f) fail("short read on " + path);
        auto opened = disasm::open_image(std::move(bytes));
        if (!opened.ok) fail("cannot open " + path + ": " + opened.error);
        if (opened.file.size() > (256u << 20))
            fail("analyzed image too large for diff (>256 MiB): " + path);
        return std::move(opened.file);
    };

    report("loading", -1.0f);
    std::vector<uint8_t> bytes_a = load_bytes(pa);
    check_cancel("diff");
    std::vector<uint8_t> bytes_b = load_bytes(pb);
    check_cancel("diff");

    // NOTE: start_sync has no cancel hook, so each side can still take a
    // while on huge binaries; the deadline applies to the compare phase
    // and to the boundary between the two analyses.
    report("analyzing_a", -1.0f);
    auto sa = std::make_unique<hs::session_t>();
    if (cancelled && cancelled()) fail("diff cancelled");
    if (!sa->start_sync(bytes_a.data(), bytes_a.size(), 0)) {
        if (cancelled && cancelled()) fail("diff cancelled");
        fail("hyperion analysis failed for " + pa + ": " + sa->error());
    }
    check_cancel("diff");
    report("analyzing_b", -1.0f);
    auto sb = std::make_unique<hs::session_t>();
    if (cancelled && cancelled()) fail("diff cancelled");
    if (!sb->start_sync(bytes_b.data(), bytes_b.size(), 0)) {
        if (cancelled && cancelled()) fail("diff cancelled");
        fail("hyperion analysis failed for " + pb + ": " + sb->error());
    }
    if (cancelled && cancelled()) fail("diff cancelled");

    report("comparing", 0.0f);
    hype::BinDiff differ;
    hype::BinDiff::options_t opt;
    opt.max_pairs = max_pairs;
    opt.cancel = cancelled ? &cancelled : nullptr;
    // absolute steady-clock deadline in BinDiff::now_ms() terms
    opt.deadline_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) +
        timeout_ms;
    std::function<void(float)> progress_fn = [&](float p) {
        report("comparing", p * 0.95f + 0.05f);
    };
    opt.progress = &progress_fn;
    auto outcome = differ.compare_budgeted(sa->db(), sb->db(), opt);

    json arr = json::array();
    const char* status_name[] = {"added", "removed", "modified", "identical"};
    for (const auto& r : outcome.results) {
        if (r.status == hype::DiffResult::Identical) continue;  // noise
        arr.push_back({{"addr_a", r.addr_a}, {"addr_b", r.addr_b},
                       {"name", r.name},
                       {"similarity", r.similarity},
                       {"status", status_name[r.status]}});
    }
    size_t counts[4] = {0, 0, 0, 0};
    for (const auto& r : outcome.results) ++counts[r.status];
    json out = {{"ok", true}, {"diffs", arr}, {"count", arr.size()},
                {"totals", {{"added", counts[0]}, {"removed", counts[1]},
                            {"modified", counts[2]},
                            {"identical", counts[3]}}},
                {"funcs_a", sa->db().funcs.size()},
                {"funcs_b", sb->db().funcs.size()},
                {"pairs_evaluated", outcome.pairs_evaluated},
                {"pairs_skipped_size", outcome.pairs_skipped_size},
                {"timed_out", outcome.timed_out},
                {"cancelled", outcome.cancelled}};
    if (outcome.timed_out)
        out["note"] = "pair budget/deadline hit: results are partial "
                      "(raise max_pairs/timeout_ms for a fuller diff)";
    if (outcome.cancelled) out["note"] = "diff cancelled: results are partial";
    report("done", 1.0f);
    return out;
}

json tool_analyze(const json& args,
                  const infra::cancel_token_t& cancel = {}) {
    const std::string action = require_action(args);
    if (action != "packer" && action != "signatures" && action != "diff" &&
        action != "diff_start" && action != "diff_job" &&
        action != "diff_cancel")
        fail("analyze: unknown action "
             "(packer|signatures|diff|diff_start|diff_job|diff_cancel)");

    // diff is heavy (two full Hyperion analyses + quadratic compare), so it
    // runs WITHOUT the global tool mutex (see call_tool), honors cancel +
    // timeout_ms, and caps the pair budget instead of hanging the engine.
    // diff_start/diff_job/diff_cancel are the async job flavor with progress.
    if (action == "diff_start") {
        if (!args.contains("path_a") || !args.contains("path_b"))
            fail("missing path_a/path_b");
        const std::string pa = args.at("path_a").get<std::string>();
        const std::string pb = args.at("path_b").get<std::string>();
        const uint32_t timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 600000), 5000, 1800000));
        const size_t max_pairs = std::min<size_t>(
            args.value("max_pairs", 500000u), 10000000u);

        infra::job_desc_t desc;
        desc.label = "bindiff";
        desc.owner = "analyze.diff_start";
        desc.cancellable = true;
        // Placeholder id: replaced with the real job id after submit; the
        // body looks its record up by id captured below.
        std::shared_ptr<std::atomic<uint64_t>> job_id =
            std::make_shared<std::atomic<uint64_t>>(0);
        desc.body = [pa, pb, timeout_ms, max_pairs, job_id](
                        infra::job_context_t& ctx) {
            // submit() assigns the id after spawning us; wait for it.
            uint64_t id = 0;
            for (int i = 0; i < 5000 && id == 0 && !ctx.cancelled(); ++i) {
                id = job_id->load(std::memory_order_acquire);
                if (!id)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!id) { ctx.fail("diff job id never assigned"); return; }
            auto report = [&](const std::string& stage, float p) {
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it == g_diff_jobs.end()) return;
                it->second.stage = stage;
                it->second.progress = p;
            };
            try {
                json res = run_diff_core(
                    pa, pb, timeout_ms, max_pairs,
                    [&]() { return ctx.cancelled(); }, report);
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it != g_diff_jobs.end()) {
                    it->second.result = std::move(res);
                    it->second.stage = "done";
                    it->second.progress = 1.0f;
                    it->second.done = true;
                }
            } catch (const std::exception& e) {
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it != g_diff_jobs.end()) {
                    it->second.error = e.what();
                    it->second.stage = "done";
                    it->second.done = true;
                }
                ctx.fail(e.what());
            }
        };
        const uint64_t id = infra::jobs::submit(std::move(desc));
        if (!id) fail("diff job queue full, retry shortly");
        job_id->store(id, std::memory_order_release);
        {
            std::lock_guard lk(g_diff_mu);
            auto& rec = g_diff_jobs[id];
            rec.path_a = pa;
            rec.path_b = pb;
            rec.stage = "queued";
            while (g_diff_jobs.size() > kMaxDiffJobs)
                g_diff_jobs.erase(g_diff_jobs.begin());
        }
        return {{"ok", true}, {"job_id", id},
                {"hint", "poll analyze.diff_job(id) for stage/progress, "
                         "cancel with analyze.diff_cancel(id)"}};
    }

    if (action == "diff_job") {
        const uint64_t id = parse_addr(args, "id");
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 5000u);
        std::lock_guard lk(g_diff_mu);
        const auto it = g_diff_jobs.find(id);
        if (it == g_diff_jobs.end())
            fail("unknown diff job (expired or never submitted)");
        const auto& rec = it->second;
        if (!rec.done) {
            json out = {{"ok", true}, {"job_id", id},
                        {"state", infra::jobs::alive(id) ? "running" : "queued"},
                        {"stage", rec.stage}, {"progress", rec.progress}};
            return out;
        }
        if (!rec.error.empty()) fail(rec.error);
        json res = rec.result;
        if (res.contains("diffs") && res.at("diffs").is_array() &&
            res.at("diffs").size() > limit) {
            json sliced = json::array();
            for (size_t i = 0; i < limit; ++i)
                sliced.push_back(res.at("diffs").at(i));
            res["diffs"] = std::move(sliced);
            res["count"] = res["diffs"].size();
            res["truncated"] = true;
        }
        res["job_id"] = id;
        res["state"] = "succeeded";
        return res;
    }

    if (action == "diff_cancel") {
        const uint64_t id = parse_addr(args, "id");
        if (!infra::jobs::cancel(id)) {
            std::lock_guard lk(g_diff_mu);
            if (g_diff_jobs.find(id) == g_diff_jobs.end())
                fail("unknown diff job");
            // Known but already finished: cancel is a no-op success.
            return {{"job_id", id}, {"cancelled", false},
                    {"note", "job already finished"}};
        }
        return {{"job_id", id}, {"cancelled", true}};
    }

    if (action == "diff") {
        if (!args.contains("path_a") || !args.contains("path_b"))
            fail("missing path_a/path_b");
        const std::string pa = args.at("path_a").get<std::string>();
        const std::string pb = args.at("path_b").get<std::string>();
        const uint32_t timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 120000), 5000, 1800000));
        const size_t max_pairs = std::min<size_t>(
            args.value("max_pairs", 500000u), 10000000u);
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 5000u);
        auto noop = [](const std::string&, float) {};
        json full = run_diff_core(
            pa, pb, timeout_ms, max_pairs,
            [&]() { return cancel.cancelled(); }, noop);
        if (full.contains("diffs") && full.at("diffs").is_array() &&
            full.at("diffs").size() > limit) {
            json sliced = json::array();
            for (size_t i = 0; i < limit; ++i)
                sliced.push_back(full.at("diffs").at(i));
            full["diffs"] = std::move(sliced);
            full["count"] = full["diffs"].size();
            full["truncated"] = true;
        }
        full["hint"] = "for huge binaries prefer async "
                       "analyze.diff_start + diff_job (progress + cancel)";
        return full;
    }

    // explicit path into the private cache, else the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& img = load_image(args.at("path").get<std::string>());
        if (action == "packer") {
            require_x86_image(img.arch, img.format, "analyze.packer", true);
            require_pe_image(img.arch, img.format, "analyze.packer", true);
        }
        pe = &img.pe; file = &img.file;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop "
                 "(see disasm.loaded)");
        if (action == "packer") {
            require_x86_image(bin.arch, bin.format, "analyze.packer");
            require_pe_image(bin.arch, bin.format, "analyze.packer");
        }
        pe = &bin.pe; file = &bin.file;
        img_name = bin.name;
    }

    if (action == "packer") {
        auto v = analysis::packer_analyze(*pe, *file);
        json dets = json::array();
        for (const auto& d : v.detections)
            dets.push_back({{"type", d.type}, {"protector", d.protector},
                            {"detail", d.detail}, {"location", d.location}});
        json secs = json::array();
        for (const auto& s : v.sections)
            secs.push_back({{"name", s.name}, {"rva", s.rva},
                            {"raw_size", s.raw_size}, {"virtual_size", s.virtual_size},
                            {"entropy", s.entropy}, {"writable_exec", s.writable_exec},
                            // raw characteristics here too for consistency
                            {"exec", (s.characteristics & 0x20000000u) != 0},
                            {"writable", (s.characteristics & 0x80000000u) != 0},
                            {"characteristics", s.characteristics}});
        json out = {{"image", img_name}, {"packed", v.packed}, {"family", v.family},
                    {"confidence", v.confidence}, {"file_entropy", v.file_entropy},
                    {"detections", dets}, {"sections", secs}};

        // the hyperion packer verdict rides along when the session is analyzed
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype) {
                hype::PackerDetector det;
                auto infos = det.detect(bin.hype->image());
                json harr = json::array();
                for (const auto& i : infos)
                    harr.push_back({{"name", i.name},
                                    {"confidence", i.confidence},
                                    {"details", i.details}});
                out["hype_packer"] = harr;
            }
        }
        return out;
    }

    const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);

    // raw crypto constants plus analyzer-derived names when available
    if (!args.contains("path")) {
        auto& bin = ds::get();
        if (bin.ready && bin.hype && bin.hype->ready()) {
            auto hits = analysis::crypto_hunt(*pe, *file, limit);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"name", h.name}, {"offset", h.offset},
                          {"in_overlay", h.in_overlay}};
                if (h.va) o["va"] = h.va;
                arr.push_back(std::move(o));
            }

            // analyzer derived names, nothing here is flirt verified
            json named = json::array();
            for (const auto& [va, name] : bin.hype->db().names) {
                if (name.find("j_") == 0 || name.find("__imp_") == 0) continue;
                if (named.size() >= limit) break;
                named.push_back({{"va", va}, {"name", name}});
            }
            return {{"image", img_name}, {"signatures", arr},
                    {"count", arr.size()}, {"named_functions", named},
                    {"named_count", named.size()}};
        }
    }

    auto hits = analysis::crypto_hunt(*pe, *file, limit);
    json arr = json::array();
    for (const auto& h : hits) {
        json o = {{"name", h.name}, {"offset", h.offset},
                  {"in_overlay", h.in_overlay}};
        if (h.va) o["va"] = h.va;
        arr.push_back(std::move(o));
    }
    return {{"image", img_name}, {"signatures", arr}, {"count", arr.size()}};
}

// tool: network

json packet_to_json(const network::packet_record_t& p) {
    json o = {{"id", p.id}, {"at_ms", p.at_ms}, {"pid", p.pid},
              {"protocol", p.protocol}, {"direction", p.direction},
              {"local", p.local_addr + ":" + std::to_string(p.local_port)},
              {"remote", p.remote_addr + ":" + std::to_string(p.remote_port)},
              {"payload_bytes", p.payload.size()}};
    const size_t preview = std::min<size_t>(p.payload.size(), 96);
    if (preview)
        o["payload_hex"] = to_hex(p.payload.data(), preview);
    return o;
}

// kernel network helpers

std::string ip_to_string(const uint8_t* addr, uint32_t af) {
    char buf[64] = "";
    if (af == 23) InetNtopA(AF_INET6, addr, buf, sizeof(buf));
    else          InetNtopA(AF_INET, addr, buf, sizeof(buf));
    return buf;
}

std::string ip_port_to_string(const uint8_t* addr, uint32_t af, uint32_t port) {
    return ip_to_string(addr, af) + ":" + std::to_string(port);
}

const char* http_method_name(uint32_t m) {
    switch (m) {
        case 1: return "GET";     case 2: return "POST";
        case 3: return "PUT";     case 4: return "DELETE";
        case 5: return "HEAD";    case 6: return "OPTIONS";
        case 7: return "PATCH";   case 8: return "CONNECT";
        case 9: return "TRACE";   default: return "UNKNOWN";
    }
}

const char* tls_version_name(uint32_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3"; default: return "unknown";
    }
}

const char* tls_content_type_name(uint32_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec"; case 21: return "Alert";
        case 22: return "Handshake";        case 23: return "ApplicationData";
        default: return "other";
    }
}

json tool_network(const json& args) {
    const std::string action = require_action(args);

    if (action == "status") {
        json out;
        out["capture_running"]  = network::capture::running();
        out["store_packets"]    = g_traffic.size();
        out["proxy_running"]    = g_proxy.running();
        out["proxy_port"]       = g_proxy.port();
        return out;
    }

    if (action == "capture_start") {
        auto err = network::capture::start(
            static_cast<uint32_t>(args.value("pid", 0u)),
            static_cast<uint32_t>(args.value("port", 0u)),
            static_cast<uint32_t>(args.value("protocol", 0u)));
        if (!err.empty()) fail(err);
        return {{"capture", true}};
    }
    if (action == "capture_stop") {
        auto err = network::capture::stop();
        if (!err.empty()) fail(err);
        return {{"capture", false}};
    }
    if (action == "packets") {
        // pull fresh packets first then serve from the store
        network::capture::poll(g_traffic, 512);
        const uint64_t from = args.contains("from")
                                  ? parse_addr(args, "from") : 0;
        auto page = args.contains("filter")
                        ? g_traffic.packets_filtered(
                              from,
                              std::min<size_t>(args.value("limit", 100u), 1000u),
                              args.at("filter").get<std::string>())
                        : g_traffic.packets(
                              from,
                              std::min<size_t>(args.value("limit", 100u), 1000u));
        json arr = json::array();
        for (const auto& p : page.items) arr.push_back(packet_to_json(p));
        return {{"packets", arr}, {"count", arr.size()},
                {"truncated", page.truncated},
                {"last_id", page.items.empty() ? from
                                               : page.items.back().id}};
    }
    if (action == "dns") {
        auto rows = network::capture::dns_queries(
            static_cast<uint32_t>(args.value("pid", 0u)));
        json arr = json::array();
        for (const auto& d : rows)
            arr.push_back({{"timestamp", d.timestamp}, {"pid", d.pid},
                           {"query_type", d.query_type}, {"domain", d.domain},
                           {"resolved", d.resolved_addr},
                           {"response_code", d.response_code}, {"ttl", d.ttl}});
        return {{"dns", arr}, {"count", arr.size()}};
    }
    if (action == "stats") {
        const auto s = network::capture::stats();
        return json{{"capture_active", s.capture_active},
                    {"total_captured", s.total_captured},
                    {"total_dropped", s.total_dropped},
                    {"total_dns_logged", s.total_dns_logged},
                    {"bytes_sent", s.bytes_sent},
                    {"bytes_received", s.bytes_received},
                    {"store_packets", g_traffic.size()}};
    }
    if (action == "export_pcap") {
        if (!args.contains("path")) fail("missing path");
        auto err = network::capture::export_pcap(
            g_traffic, args.at("path").get<std::string>(),
            static_cast<uint32_t>(
                std::min<uint64_t>(args.contains("max_packets")
                                       ? parse_addr(args, "max_packets")
                                       : 4096,
                                   65536ull)));
        if (!err.empty()) fail(err);
        return {{"exported", true}, {"path", args.at("path")}};
    }
    if (action == "streams") {
        auto all = g_traffic.streams();
        json arr = json::array();
        for (const auto& s : all) {
            arr.push_back({{"id", s.id}, {"key", s.key}, {"bytes", s.bytes},
                           {"packets", s.packets}, {"first_ms", s.first_ms},
                           {"last_ms", s.last_ms}});
        }
        return {{"streams", arr}, {"count", arr.size()}};
    }
    if (action == "stream_data") {
        const uint64_t id = parse_addr(args, "id");
        const uint64_t off =
            args.contains("offset") ? parse_addr(args, "offset") : 0;
        uint64_t len = args.contains("len") ? parse_addr(args, "len") : 4096;
        len = std::min<uint64_t>(len, 1 << 20);
        auto bytes = g_traffic.stream_bytes(
            id, static_cast<size_t>(off), static_cast<size_t>(len));
        if (!bytes) fail("unknown stream id");
        json out = {{"id", id}, {"offset", off}, {"bytes", bytes->size()}};
        const size_t text_len = std::min<size_t>(bytes->size(), 4096);
        std::string text(reinterpret_cast<const char*>(bytes->data()), text_len);
        for (char& ch : text)
            if (static_cast<unsigned char>(ch) < 0x20 &&
                ch != '\n' && ch != '\r' && ch != '\t')
                ch = '.';
        out["text"] = text;
        out["hex"]  = to_hex(bytes->data(), text_len);
        return out;
    }

    // kernel network manipulation through wfp
    // everything bails with a structured error when the driver is down
    // op 0 adds or starts, op 1 removes or stops

    auto need_device = []() -> voyager::device_t& {
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        return *k->device();
    };
    auto parse_ip = [&](const json& a, const char* key,
                        std::array<uint8_t, 16>& out, uint32_t* af) {
        const std::string s2 = a.value(key, std::string{});
        if (s2.empty()) { *af = 2; return; }                 // AF_INET wildcard
        IN_ADDR v4{};
        if (InetPtonA(AF_INET, s2.c_str(), &v4) == 1) {
            std::memcpy(out.data(), &v4, 4);
            *af = 2;
            return;
        }
        IN6_ADDR v6{};
        if (InetPtonA(AF_INET6, s2.c_str(), &v6) == 1) {
            std::memcpy(out.data(), &v6, 16);
            *af = 23;                                        // AF_INET6
            return;
        }
        fail("bad ip in '" + std::string(key) + "'");
    };

    if (action == "reassemble_stream") {
        auto& dev = need_device();
        std::vector<uint8_t> data;
        uint32_t packets = 0, truncated = 0;
        const bool ok = dev.stream_reassemble_op(
            static_cast<uint32_t>(args.value("op", 0u)),
            static_cast<uint32_t>(args.value("src_port", 0u)),
            static_cast<uint32_t>(args.value("dst_port", 0u)),
            static_cast<uint32_t>(args.value("pid", 0u)),
            nullptr, nullptr, &data, &packets, &truncated);
        if (!ok) fail("stream reassemble failed");
        const size_t text_len = std::min<size_t>(data.size(), 4096);
        std::string text(reinterpret_cast<const char*>(data.data()), text_len);
        for (char& ch : text)
            if (static_cast<unsigned char>(ch) < 0x20 && ch != '\n' &&
                ch != '\r' && ch != '\t')
                ch = '.';
        return {{"bytes", data.size()}, {"packets", packets},
                {"truncated", truncated != 0},
                {"hex", to_hex(data.data(), text_len)}, {"text", text}};
    }

    // system wide network views over the driver
    // connections, dpi, callouts, socket handles, tcpip internals

    if (action == "connections") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& c : dev.enumerate_connections(
                 static_cast<uint32_t>(args.value("pid", 0u)),
                 static_cast<uint32_t>(args.value("protocol", 0u)))) {
            arr.push_back({{"pid", c.pid},
                           {"protocol", c.protocol},
                           {"state", c.state},
                           {"local", ip_port_to_string(c.local_addr,
                                                       c.address_family,
                                                       c.local_port)},
                           {"remote", ip_port_to_string(c.remote_addr,
                                                        c.address_family,
                                                        c.remote_port)},
                           {"path", c.process_path}});
        }
        return {{"connections", arr}, {"count", arr.size()}};
    }
    if (action == "deep_inspect") {
        // dpi results straight from the kernel classifier
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& d : dev.get_dpi_results(
                 static_cast<uint32_t>(args.value("pid", 0u)),
                 static_cast<uint32_t>(args.value("protocol", 0u)),
                 static_cast<uint32_t>(args.value("port", 0u)))) {
            json o = {{"timestamp", d.timestamp},
                      {"direction", d.direction},
                      {"protocol", d.protocol},
                      {"src", ip_port_to_string(d.src_addr, d.af, d.src_port)},
                      {"dst", ip_port_to_string(d.dst_addr, d.af, d.dst_port)},
                      {"pid", d.pid},
                      {"payload_size", d.payload_size}};
            if (d.protocol == 6) {
                o["tcp_flags"] = d.tcp_flags;
                o["tcp_window"] = d.tcp_window;
            }
            if (d.is_http) {
                o["app_protocol"] = "HTTP";
                o["http_method"] = http_method_name(d.http_method);
                if (!d.http_host.empty()) o["http_host"] = d.http_host;
                if (!d.http_path.empty()) o["http_path"] = d.http_path;
            }
            if (d.is_tls) {
                o["app_protocol"] = "TLS";
                o["tls_version"] = tls_version_name(d.tls_version);
                o["tls_content_type"] = tls_content_type_name(d.tls_content_type);
                if (!d.tls_sni.empty()) o["tls_sni"] = d.tls_sni;
            }
            if (d.is_dns) o["app_protocol"] = "DNS";
            arr.push_back(std::move(o));
        }
        return {{"results", arr}, {"count", arr.size()}};
    }
    fail("network: unknown action (status|capture_start|capture_stop|packets|"
         "dns|rules_add|rules_remove|rules_clear|stats|export_pcap|streams|"
         "stream_data|inject|mod_rule_add|mod_rule_remove|mod_rules_list|"
         "redirect_add|redirect_remove|redirect_rules_list|dns_spoof_add|"
         "dns_spoof_remove|dns_spoof_list|kill_conn|intercept_start|"
         "intercept_stop|intercept_list|intercept_release|bw_start|bw_stop|"
         "bw_stats|bw_processes|fingerprint_run|fingerprint_results|"
         "reassemble_stream|connections|deep_inspect|wfp_callouts|"
         "socket_handles|tcpip_dump|interfaces|block_ip|block_port|"
         "block_process)");
}

// tool: proxy

json tool_proxy(const json& args) {
    const std::string action = require_action(args);

    if (action == "start") {
        std::string err;
        const uint16_t port = static_cast<uint16_t>(args.value("port", 8888));
        if (!g_proxy.start(port, &g_traffic, &err)) fail(err);
        return {{"running", true}, {"port", g_proxy.port()}};
    }
    if (action == "stop") {
        g_proxy.stop();
        return {{"running", false}};
    }
    if (action == "status") {
        return json{{"running", g_proxy.running()}, {"port", g_proxy.port()}};
    }
    if (action == "entries") {
        auto entries = g_proxy.recent(
            std::min<size_t>(args.value("limit", 100u), 512u));
        json arr = json::array();
        for (const auto& e : entries) {
            json o = {{"id", e.id}, {"at_ms", e.at_ms}, {"kind", e.kind},
                      {"method", e.method}, {"host", e.host}, {"port", e.port},
                      {"path", e.path}, {"status", e.status},
                      {"req_bytes", e.req_bytes}, {"resp_bytes", e.resp_bytes}};
            if (!e.sni.empty()) o["sni"] = e.sni;
            arr.push_back(std::move(o));
        }
        return {{"entries", arr}, {"count", arr.size()}};
    }
    if (action == "entry") {
        const uint64_t id = parse_addr(args, "id");
        auto e = g_proxy.entry(id);
        if (!e) fail("unknown entry id");
        json o = {{"id", e->id}, {"kind", e->kind}, {"method", e->method},
                  {"host", e->host}, {"port", e->port}, {"path", e->path},
                  {"status", e->status}, {"req_bytes", e->req_bytes},
                  {"resp_bytes", e->resp_bytes}};
        if (!e->response_head.empty()) {
            const size_t n = std::min<size_t>(e->response_head.size(), 2048);
            o["response_head_text"] = std::string(
                reinterpret_cast<const char*>(e->response_head.data()), n);
        }
        if (!e->raw_request.empty())
            o["replayable"] = true;
        return o;
    }
    if (action == "replay") {
        std::string err;
        auto resp = g_proxy.replay(parse_addr(args, "id"), &err);
        if (!resp) fail(err);
        const size_t n = std::min<size_t>(resp->size(), 16384);
        return {{"bytes", resp->size()},
                {"text", std::string(reinterpret_cast<const char*>(resp->data()),
                                     n)}};
    }

    fail("proxy: unknown action (start|stop|status|entries|entry|replay)");
}

// tool: detect

json tool_fs(const json& args) {
    const std::string action = require_action(args);

    if (action == "read_file") {
        if (!args.contains("path")) fail("missing path");
        std::vector<uint8_t> bytes;
        std::string err;
        const size_t cap =
            std::min<size_t>(args.value("max_bytes", 262144u), 4u << 20);
        if (!util::read_file(args.at("path").get<std::string>(), &bytes,
                             cap, &err))
            fail(err);
        json out = {{"path", args.at("path")},
                    {"bytes", bytes.size()},
                    {"hex", to_hex(bytes.data(),
                                   std::min<size_t>(bytes.size(), 8192))}};
        // text preview when it looks printable
        std::string text(reinterpret_cast<const char*>(bytes.data()),
                         std::min<size_t>(bytes.size(), 4096));
        out["text"] = text;
        return out;
    }
    if (action == "write_file") {
        if (!args.contains("path")) fail("missing path");
        std::vector<uint8_t> bytes;
        if (args.contains("hex"))
            bytes = hex_decode(args.at("hex").get<std::string>());
        else if (args.contains("text")) {
            // bind once, two get calls make two different strings and thats ub
            const std::string text = args.at("text").get<std::string>();
            bytes.assign(text.begin(), text.end());
        }
        std::string err;
        if (!util::write_file(args.at("path").get<std::string>(), bytes,
                              args.value("append", false), &err))
            fail(err);
        return {{"written", bytes.size()}, {"path", args.at("path")}};
    }
    if (action == "list_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        auto items = util::list_directory(
            args.at("path").get<std::string>(), &err);
        if (!items.empty() || err.empty()) {
            json arr = json::array();
            for (const auto& e : items)
                arr.push_back({{"name", e.name}, {"size", e.size},
                               {"directory", e.directory}});
            return {{"entries", arr}, {"count", arr.size()}};
        }
        fail(err);
    }
    if (action == "create_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::create_directory(args.at("path").get<std::string>(),
                                    &err))
            fail(err);
        return {{"created", true}};
    }
    if (action == "delete_path") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::delete_path(args.at("path").get<std::string>(), &err))
            fail(err);
        return {{"deleted", true}};
    }
    if (action == "search_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::search_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            std::min<size_t>(args.value("limit", 200u), 2000u));
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"size", h.size},
                           {"directory", h.directory}});
        return {{"matches", arr}, {"count", arr.size()}};
    }
    if (action == "grep_in_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::grep_in_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            args.value("suffix", std::string{}),
            std::min<size_t>(args.value("limit", 200u), 2000u));
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"line", h.line},
                           {"text", h.text}});
        return {{"hits", arr}, {"count", arr.size()}};
    }

    fail("fs: unknown action (read_file|write_file|list_directory|"
         "create_directory|delete_path|search_files|grep_in_files)");
}

// tool: web

json tool_web(const json& args) {
    const std::string action = require_action(args);

    if (action == "fetch" || action == "post") {
        if (!args.contains("url")) fail("missing url");
        std::string err;
        const int timeout =
            std::min(args.value("timeout_ms", 15000), 60000);
        std::optional<util::http_response_t> resp;
        if (action == "fetch")
            resp = util::http_get(args.at("url").get<std::string>(), timeout,
                                  &err);
        else {
            if (!args.contains("body")) fail("missing body");
            resp = util::http_post(
                args.at("url").get<std::string>(),
                args.at("body").get<std::string>(),
                args.value("content_type", std::string{"application/json"}),
                timeout, &err);
        }
        if (!resp) fail(err);
        const size_t body_cap =
            std::min<size_t>(resp->body.size(), 65536);
        return {{"status", resp->status},
                {"content_type", resp->content_type},
                {"bytes", resp->body.size()},
                {"text", resp->body.substr(0, body_cap)}};
    }

    fail("web: unknown action (use fetch or post)");
}

// tool: decomp

// turns text like mov rax, [rbx+8] into an encoder request
std::string assemble_one(const std::string& text, uint64_t addr,
                         ZydisEncoderRequest& out) {
    out = {};
    out.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    out.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;

    // split on spaces, commas and mem-operand operators so
    // "[rbx+8]", "[rax+rcx*4-0x10]" tokenize into separate atoms
    std::vector<std::string> tokens;
    std::string cur;
    auto flush = [&] {
        // strip stray statement terminators/label colons agents paste in
        while (!cur.empty() && (cur.back() == ';' || cur.back() == ':'))
            cur.pop_back();
        if (!cur.empty()) tokens.push_back(cur);
        cur.clear();
    };
    for (char ch : text + ",") {
        if (ch == ' ' || ch == ',' || ch == '\t' || ch == ';' || ch == ':') {
            flush();
        } else if (ch == '[' || ch == ']' || ch == '+' || ch == '-' || ch == '*') {
            flush();
            tokens.push_back(std::string(1, ch));
        } else {
            cur += static_cast<char>(std::tolower(
                static_cast<unsigned char>(ch)));
        }
    }
    if (tokens.empty()) return "empty instruction";

    // mnemonic lookup
    bool mn_found = false;
    for (int m = 1; m < ZYDIS_MNEMONIC_MAX_VALUE; ++m) {
        const auto mm = static_cast<ZydisMnemonic>(m);
        const char* s = ZydisMnemonicGetString(mm);
        if (s && _stricmp(s, tokens[0].c_str()) == 0) {
            out.mnemonic = mm;
            mn_found = true;
            break;
        }
    }
    if (!mn_found) return "unknown mnemonic '" + tokens[0] + "'";

    // register lookup
    auto find_reg = [](const std::string& n, ZydisRegister* r) {
        for (int i = 1; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
            const auto rr = static_cast<ZydisRegister>(i);
            const char* s = ZydisRegisterGetString(rr);
            if (s && _stricmp(s, n.c_str()) == 0) { *r = rr; return true; }
        }
        return false;
    };

    size_t ti = 1;
    while (ti < tokens.size() &&
           out.operand_count < ZYDIS_MAX_OPERAND_COUNT) {
        const std::string& t = tokens[ti];
        if (t == "[") {
            // memory operand like [base + index*scale + disp]
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_MEMORY;
            op.mem.base = ZYDIS_REGISTER_NONE;
            op.mem.index = ZYDIS_REGISTER_NONE;
            op.mem.scale = 1;
            op.mem.displacement = 0;
            ++ti;
            while (ti < tokens.size() && tokens[ti] != "]") {
                ZydisRegister r = ZYDIS_REGISTER_NONE;
                int64_t sign = 1;
                if (tokens[ti] == "+") { sign = 1; ti++; }
                else if (tokens[ti] == "-") { sign = -1; ti++; }
                if (ti >= tokens.size()) break;
                if (find_reg(tokens[ti], &r)) {
                    if (r == ZYDIS_REGISTER_RIP) {
                        op.mem.base = ZYDIS_REGISTER_RIP;
                        op.mem.displacement =
                            static_cast<int64_t>(addr);
                    } else if (op.mem.base == ZYDIS_REGISTER_NONE)
                        op.mem.base = r;
                    else {
                        op.mem.index = r;
                    }
                    ti++;
                } else {
                    char* end = nullptr;
                    const uint64_t v =
                        std::strtoull(tokens[ti].c_str(), &end, 0);
                    if (end == tokens[ti].c_str())
                        return "bad memory operand '" + tokens[ti] + "'";
                    op.mem.displacement +=
                        sign * static_cast<int64_t>(v);
                    ti++;
                }
                if (ti < tokens.size() && tokens[ti] == "*") {
                    ti++;
                    if (ti < tokens.size())
                        op.mem.scale = static_cast<uint32_t>(
                            std::strtoul(tokens[ti++].c_str(), nullptr, 0));
                }
            }
            if (ti < tokens.size()) ++ti;   // consume ']'
            continue;
        }

        if (t == "+" || t == "-" || t == "*") {
            // stray operator outside [...] (e.g. signed immediates split
            // by the tokenizer) -- fold a leading sign into the next atom
            if ((t == "+" || t == "-") && ti + 1 < tokens.size() &&
                tokens[ti + 1] != "]" && tokens[ti + 1] != "[" &&
                tokens[ti + 1] != "+" && tokens[ti + 1] != "-" &&
                tokens[ti + 1] != "*") {
                ZydisRegister rr = ZYDIS_REGISTER_NONE;
                const std::string& nx = tokens[ti + 1];
                if (!find_reg(nx, &rr)) {
                    ZydisEncoderOperand& op =
                        out.operands[out.operand_count++];
                    op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                    char* end = nullptr;
                    const int64_t sv = std::strtoll(
                        (t + nx).c_str(), &end, 0);
                    if (end == (t + nx).c_str())
                        return "bad immediate '" + t + nx + "'";
                    op.imm.s = sv;
                    op.imm.u = static_cast<uint64_t>(sv);
                    ti += 2;
                    continue;
                }
            }
            return "unexpected '" + t + "' outside memory operand";
        }

        ZydisRegister r = ZYDIS_REGISTER_NONE;
        if (find_reg(t, &r)) {
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_REGISTER;
            op.reg.value = r;
            ++ti;
            continue;
        }

        // immediate
        ZydisEncoderOperand& op = out.operands[out.operand_count++];
        op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

        {
            char* end = nullptr;
            const uint64_t uv = std::strtoull(t.c_str(), &end, 0);
            if (end == t.c_str()) return "bad operand '" + t + "'";
            op.imm.u = uv;
            op.imm.s = static_cast<int64_t>(uv);
        }
        ++ti;
    }

    // the encoder picks the visibility defaults

    return "";
}

// ---- tool: dotnet ------------------------------------------------------
// Structured view over the managed (.NET/CLI) model the analyzer builds:
// the namespace/type/member tree, per-type and per-method detail, the IL
// listing and the dnSpy-style C# rendering. All actions are read-only and
// operate on the shared image; they require a managed image with completed
// Hyperion analysis (disasm.loaded -> image.hype.ready=true).

namespace {

// A metadata token as both a decimal int and the conventional 8-hex-digit form.
json token_json(uint32_t tok) {
    return {{"token", tok}, {"token_hex", fmt::format("{:08X}", tok)}};
}

// Accept a token as an integer or a hex/decimal string ("0x06000001", "06000001", 100663297).
uint32_t parse_token(const json& args) {
    if (!args.contains("token")) fail("missing 'token' (a metadata token; see dotnet.tree / dotnet.type)");
    const auto& t = args.at("token");
    if (t.is_number_unsigned()) return t.get<uint32_t>();
    if (t.is_number_integer())  return static_cast<uint32_t>(t.get<int64_t>());
    if (t.is_string()) {
        const std::string s = t.get<std::string>();
        const bool hexish = s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0 ||
                            s.find_first_of("abcdefABCDEF") != std::string::npos;
        return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, hexish ? 16 : 10));
    }
    fail("'token' must be an integer or hex string");
}

const char* il_flow_name(hype::ILFlow f) {
    switch (f) {
    case hype::ILFlow::Branch: return "branch";
    case hype::ILFlow::Cond:   return "cond";
    case hype::ILFlow::Call:   return "call";
    case hype::ILFlow::Return: return "return";
    case hype::ILFlow::Throw:  return "throw";
    case hype::ILFlow::Meta:   return "meta";
    default:                   return "next";
    }
}

// Compact member counts for a type (used by the tree without expanding it).
json type_counts(const hype::DnType& t) {
    return {{"fields", t.field_tokens.size()},
            {"properties", t.property_tokens.size()},
            {"events", t.event_tokens.size()},
            {"methods", t.method_tokens.size()},
            {"nested", t.nested_tokens.size()}};
}

// One node in the tree: identity + kind + counts + its nested types, recursively.
json type_node(const hype::DnImage& im, const hype::DnType& t) {
    json node = token_json(t.token);
    node["name"]       = t.name;
    node["full_name"]  = t.full_name;
    node["kind"]       = t.kind;
    node["visibility"] = t.visibility;
    if (!t.base_type.empty()) node["base"] = t.base_type;
    if (!t.interfaces.empty()) node["interfaces"] = t.interfaces;
    node["counts"] = type_counts(t);
    json nested = json::array();
    for (uint32_t ntok : t.nested_tokens)
        if (const hype::DnType* nt = im.type_by_token(ntok))
            nested.push_back(type_node(im, *nt));
    if (!nested.empty()) node["nested"] = std::move(nested);
    return node;
}

// Wait (bounded, lock-free between checks) for analysis to land, then return the
// locked binary. Fails soft so an agent can poll. Mirrors tool_decomp's guard.
void dotnet_wait_ready() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    for (;;) {
        {
            std::lock_guard lk(ds::state_mutex());
            auto& bin0 = ds::get();
            if (!bin0.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
            if (bin0.format != disasm::image_format_t::pe) return;
            if (!bin0.hype)  fail("hyperion engine unavailable for this image");
            if (bin0.hype->ready()) break;
            const std::string herr = bin0.hype->error();
            if (!herr.empty())
                fail("hyperion analysis not running, " + herr + " (re-run disasm.load)");
        }
        if (std::chrono::steady_clock::now() >= deadline)
            fail("hyperion analysis still in progress, retry shortly (see disasm.loaded)");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

json method_summary(const hype::DnMethod& m) {
    json o = token_json(m.token);
    o["name"]       = m.name;
    o["signature"]  = m.signature;
    o["visibility"] = m.visibility;
    o["ret"]        = m.ret_type;
    o["static"]     = m.is_static;
    if (m.is_abstract) o["abstract"] = true;
    if (m.is_virtual)  o["virtual"]  = true;
    if (m.is_ctor)     o["ctor"]     = true;
    if (m.is_pinvoke)  o["pinvoke"]  = true;
    const bool special = (m.flags & 0x0800) != 0;
    if (special) o["special"] = true;
    o["has_body"] = (m.rva != 0 && !m.il.empty());
    o["il_count"] = m.il.size();
    if (m.entry) { o["entry"] = m.entry; o["entry_hex"] = hex64(m.entry); }
    return o;
}

} // anon

json tool_decomp(const json& args) {
    const std::string action = require_action(args);
    if (action != "function") fail("decomp: unknown action");

    const uint64_t va = parse_addr(args, "addr");

    // wait for analysis without holding the lock, fail soft so the agent can poll
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(10);
        for (;;) {
            {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                if (!bin0.ready)
                    fail("no image loaded in reverse-slop (see disasm.loaded)");
                if (!bin0.hype) fail("hyperion engine unavailable for this image");
                if (bin0.hype->ready()) break;
                // cancelled or failed means waiting is pointless
                const std::string herr = bin0.hype->error();
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                const std::string herr =
                    bin0.hype ? bin0.hype->error() : std::string{};
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
                fail("hyperion analysis in progress (" +
                     std::to_string(static_cast<int>(bin0.hype
                         ? bin0.hype->progress() * 100 : 0)) +
                     "%), retry shortly");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::lock_guard lk(ds::state_mutex());
    auto& bin = ds::get();
    if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
    if (!bin.hype) fail("hyperion engine unavailable for this image");

    // Fast reject: an unmapped VA can never decompile. Without this the
    // request falls into function lookup + full p-code/SSA lifting on
    // whatever the interval index returns, which wedged the engine.
    if (!bin.pe.va_to_offset(va))
        fail("addr 0x" + hex64(va) +
             " is not mapped in the loaded image (base 0x" + hex64(bin.base) +
             ", size_of_image 0x" + hex64(bin.pe.size_of_image) +
             "); pass a VA inside the image (see disasm.pe sections)");

    const bool annotate_bytes = args.value("annotate_bytes", false);

    const hype::Function* f = bin.hype->function_at(va);
    if (!f) fail("no hyperion function contains address " + hex64(va));
    const uint64_t entry = f->entry;

    std::vector<hype::PseudoLine> lines;
    std::string err;
    if (!bin.hype->decompile(va, lines, err)) fail(err);

    // rebuild the stack var table since the emitter inlines them into expressions
    struct var_rec { int64_t off; std::string name; uint32_t width; };
    std::map<int64_t, var_rec> vars;
    for (const auto& [bstart, bb] : f->blocks) {
        (void)bstart;
        for (const auto& in : bb.insns) {
            for (uint8_t i = 0; i < in.op_count; ++i) {
                const auto& op = in.ops[i];
                if (op.type != hype::OpType::Mem) continue;
                const bool x86_stack = bin.is_x86() &&
                    (op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_RBP);
                const bool arm64_stack = bin.arch == disasm::image_arch_t::arm64 &&
                    (op.mem.base == ARM64_REG_SP || op.mem.base == ARM64_REG_X29);
                if (!x86_stack && !arm64_stack) continue;
                const auto it = vars.find(op.mem.disp);
                if (it == vars.end()) {
                    const bool arg = x86_stack && op.mem.base == ZYDIS_REGISTER_RSP &&
                                     op.mem.disp > 0;
                    vars.emplace(op.mem.disp, var_rec{
                        op.mem.disp,
                        (arg ? "arg_" : "var_") +
                            std::to_string(std::abs(op.mem.disp)),
                        op.size});
                }
            }
        }
    }

    json jvars = json::array();
    for (const auto& [off, v] : vars)
        jvars.push_back({{"name", v.name}, {"stack_offset", off},
                         {"width", v.width}});

    // name precedence is user symbol, hyperion name, then sub_rva
    std::string fname;
    if (const auto* sym = ds::symbol_for(entry); sym && *sym)
        fname = sym;
    else {
        const auto nit = bin.hype->db().names.find(entry);
        if (nit != bin.hype->db().names.end()) fname = nit->second;
    }
    const uint64_t img_base = bin.hype->db().image_base
                                  ? bin.hype->db().image_base
                                  : bin.base;
    if (fname.empty())
        fname = "sub_" + hex64(entry - img_base);

    // rename the body to match the signature so they agree
    const std::string sub_name = "sub_" + hex64(entry - img_base);
    const std::string emitter_name = [&] {
        const auto nit = bin.hype->db().names.find(entry);
        return nit != bin.hype->db().names.end() ? nit->second : sub_name;
    }();
    auto rename_fn = [&](const std::string& text) {
        if (emitter_name.size() < 3 || sub_name.size() < 3)
            return text;
        std::string out = text;
        const auto idch = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        };
        for (const std::string& from : {emitter_name, sub_name}) {
            if (from == fname || from.size() < 3) continue;
            size_t pos = 0;
            while ((pos = out.find(from, pos)) != std::string::npos) {
                const size_t end = pos + from.size();
                const bool word = (pos == 0 || !idch(out[pos - 1])) &&
                                  (end >= out.size() || !idch(out[end]));
                if (word) {
                    out.replace(pos, from.size(), fname);
                    pos += fname.size();
                } else {
                    pos = end;
                }
            }
        }
        return out;
    };

    json jlines = json::array();
    size_t insn_count = 0;
    for (const auto& l : lines) {
        if (l.addr) ++insn_count;
        if (annotate_bytes && l.addr) {
            // prefix each line with its va
            std::ostringstream text;
            text << std::hex << std::uppercase << l.addr << std::dec << ": "
                 << rename_fn(l.text);
            jlines.push_back({{"va", l.addr}, {"text", text.str()}});
        } else {
            jlines.push_back({{"va", l.addr},
                              {"text", std::string(l.indent * 2, ' ') +
                                           rename_fn(l.text)}});
        }
    }

    std::string signature;
    {
        const auto it = bin.hype->db().signatures.find(entry);
        if (it != bin.hype->db().signatures.end()) {
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

    return {{"ok", true},
            {"engine", "hyperion"},
            {"signature", signature},
            {"function_va", entry},
            {"insn_count", insn_count},
            {"vars", jvars},
            {"lines", jlines}};
}

// tool: persist

json tool_persist(const json& args) {
    const std::string action = require_action(args);

    // one store per process, opened on first use
    static persist::session_store_t store;
    static bool store_open = false;
    if (!store_open) {
        std::string err;
        if (!store.open(persist::default_store_path(), &err))
            fail("store open failed: " + err);
        store_open = true;
    }

    if (action == "save") {
        if (!args.contains("name") || !args.contains("data"))
            fail("missing name/data");
        auto id = store.save_session(args.at("name").get<std::string>(),
                                     args.at("data").dump());
        if (!id) fail("save failed");
        return {{"saved", true}, {"id", *id}};
    }
    if (action == "list") {
        json arr = json::array();
        for (const auto& m : store.list_sessions())
            arr.push_back({{"id", m.id}, {"name", m.name},
                           {"created_at", m.created_at}});
        return {{"sessions", arr}, {"count", arr.size()}};
    }
    if (action == "load") {
        auto row = store.load_session(parse_addr(args, "id"));
        if (!row) fail("unknown session id");
        json data = json::parse(row->data, nullptr, false);
        return {{"id", row->id}, {"name", row->name},
                {"created_at", row->created_at},
                {"data", data.is_discarded() ? json(row->data) : data}};
    }
    if (action == "delete") {
        if (!store.delete_session(parse_addr(args, "id")))
            fail("unknown session id");
        return {{"deleted", true}};
    }
    if (action == "kv_set") {
        if (!args.contains("key") || !args.contains("value"))
            fail("missing key/value");
        const json& v = args.at("value");
        const std::string text =
            v.is_string() ? v.get<std::string>() : v.dump();
        if (!store.kv_set(args.at("key").get<std::string>(), text))
            fail("kv_set failed");
        return {{"set", true}};
    }
    if (action == "kv_get") {
        auto v = store.kv_get(args.value("key", ""));
        if (!v) fail("no value for key");
        json parsed = json::parse(*v, nullptr, false);
        return {{"value", parsed.is_discarded() ? json(*v) : parsed}};
    }

    // hyperion project files
    // the format keeps names comments xrefs and types, load merges the names and comments back

    if (action == "hype_save") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to write)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded (see disasm.loaded)");
        hype::Database dbio;
        const std::string dir = args.at("dir").get<std::string>();
        if (!dbio.save(dir, bin.hype->image(), bin.hype->db()))
            fail("save failed (writable dir?)");
        return {{"ok", true}, {"dir", dir},
                {"names", bin.hype->db().names.size()},
                {"comments", bin.hype->db().comments.size()},
                {"xrefs", bin.hype->db().xrefs.size()}};
    }
    if (action == "hype_load") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to read)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded to merge into (see disasm.loaded)");
        const std::string dir = args.at("dir").get<std::string>();
        hype::PEImage  img;
        hype::AnalysisDB loaded;
        hype::Database dbio;
        if (!dbio.load(dir, img, loaded)) fail("load failed (missing meta.bin?)");
        auto& db = bin.hype->db_mut();
        size_t names = 0, comments = 0;
        for (const auto& [va, n] : loaded.names) {
            db.names[va] = n;
            ++names;
        }
        for (const auto& [va, c] : loaded.comments) {
            db.comments[va] = c;
            ++comments;
        }
        return {{"ok", true}, {"dir", dir},
                {"merged_names", names}, {"merged_comments", comments}};
    }

    fail("persist: unknown action (save|list|load|delete|kv_set|kv_get|"
         "hype_save|hype_load)");
}

// tool: re

json tool_re(const json& args) {
    const std::string action = require_action(args);

    // app loaded binary unless a path is given
    std::optional<ds::binary_lock_t> shared_lock;
    disasm::pe_image_t const*   pe   = nullptr;
    std::vector<uint8_t> const* file = nullptr;
    disasm::function_index_t*   fidx = nullptr;
    disasm::xref_index_t*       xidx = nullptr;
    uint64_t                    session_base = 0;   // VA base of the source
    const hype::AnalysisDB*     hdb  = nullptr;     // hyperion DB when analyzed
    disasm::image_format_t format = disasm::image_format_t::pe;
    disasm::image_arch_t arch = disasm::image_arch_t::x64;
    const bool have_path = args.contains("path") && args.at("path").is_string();

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        format = img.format;
        arch = img.arch;
        if (action == "danger")
            require_x86_image(arch, format, "re.danger", true);
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        session_base = pe->image_base;
        // signature matching needs bounds, not decoding; import callsites
        // need the legacy x86 xref index when there is no hyperion session
        if (action == "libsig" && !img.fidx_ok) {
            if (arch == disasm::image_arch_t::x86 || arch == disasm::image_arch_t::x64) {
                auto& eng = shared_engine();
                if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
                if (!fidx->build(*pe, *file, eng, session_base))
                    fail("function index build failed");
            } else if (!fidx->build_from_bounds(*pe, *file, session_base)) {
                fail("function bounds index build failed");
            }
            img.fidx_ok = true;
        }
        if (action == "danger" && !img.xidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!xidx->build(*pe, *file, eng, session_base))
                fail("xref index build failed");
            img.xidx_ok = true;
        }
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        format = bin.format;
        arch = bin.arch;
        if (bin.indexes_dirty && (action == "danger" || action == "libsig"))
            ds::rebuild_indexes_locked(bin);
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        session_base = bin.base;
        if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
    }
    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : session_base;
    (void)base;

    if (action == "rtti_scan") {
        require_x86_image(arch, format, "re.rtti_scan", have_path);
        require_pe_image(arch, format, "re.rtti_scan", have_path);
        // Case-insensitive substring filter over mangled + demangled names,
        // plus limit/total so 600-class dumps stop truncating the session.
        const std::string filter = args.value("filter", std::string{});
        auto match_filter = [&](const std::string& a, const std::string& b) {
            if (filter.empty()) return true;
            auto contains_ci = [&](const std::string& hay) {
                if (hay.size() < filter.size()) return false;
                for (size_t i = 0; i + filter.size() <= hay.size(); ++i) {
                    bool m = true;
                    for (size_t k = 0; k < filter.size(); ++k) {
                        if (std::tolower(static_cast<unsigned char>(hay[i + k])) !=
                            std::tolower(static_cast<unsigned char>(filter[k]))) {
                            m = false;
                            break;
                        }
                    }
                    if (m) return true;
                }
                return false;
            };
            return contains_ci(a) || contains_ci(b);
        };
        const size_t rtti_limit =
            std::min<size_t>(args.value("limit", 500u), 10000u);
        // hyperion rtti beats the quick scanner when its ready
        // the lock above already pins the session
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                const auto& classes = bin.hype->rtti().classes();
                json arr = json::array();
                size_t matched = 0;
                for (const auto& c : classes) {
                    const std::string shown = c.demangled_name.empty()
                                                  ? c.mangled_name
                                                  : c.demangled_name;
                    if (!match_filter(shown, c.mangled_name)) continue;
                    ++matched;
                    if (arr.size() >= rtti_limit) continue;
                    json methods = json::array();
                    for (auto m : c.methods) methods.push_back(m);
                    arr.push_back({{"name", shown},
                                   {"mangled", c.mangled_name},
                                   {"td_va", c.type_descriptor},
                                   {"vtable_va", c.vtable},
                                   {"methods", methods},
                                   {"method_count", c.methods.size()}});
                }
                json out = {{"engine", "hyperion"}, {"classes", arr},
                            {"count", arr.size()}, {"total", matched}};
                if (!filter.empty()) out["filter"] = filter;
                if (matched > arr.size()) out["truncated"] = true;
                return out;
            }
        }
        auto r = re::rtti_scan(*pe, *file);
        json arr = json::array();
        size_t matched = 0;
        for (const auto& c : r.classes) {
            if (!match_filter(c.name, c.name)) continue;
            ++matched;
            if (arr.size() >= rtti_limit) continue;
            json vfs = json::array();
            for (auto v : c.vftables) vfs.push_back(v);
            arr.push_back({{"name", c.name}, {"td_va", c.td_va},
                           {"vftables", vfs}});
        }
        json rout = {{"classes", arr}, {"count", arr.size()},
                     {"total", matched},
                     {"scanned_bytes", r.scanned_bytes}};
        if (!filter.empty()) rout["filter"] = filter;
        if (matched > arr.size()) rout["truncated"] = true;
        return rout;
    }
    if (action == "vftable") {
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                // serve from the db when the address is indexed
                const uint64_t vva = parse_addr(args, "addr");
                for (const auto& vt : bin.hype->db().vtables) {
                    if (vt.addr != vva) continue;
                    json arr = json::array();
                    for (auto e : vt.entries) arr.push_back(e);
                    return {{"engine", "hyperion"}, {"vftable_va", vva},
                            {"targets", arr}, {"count", arr.size()}};
                }
                // raw read for everything else
            }
        }
        if (!args.contains("addr")) fail("missing addr");
        const uint64_t va = parse_addr(args, "addr");
        auto slots = re::read_vftable(
            *pe, *file, va,
            static_cast<size_t>(std::min<uint64_t>(
                args.contains("slots") ? parse_addr(args, "slots") : 32,
                256)));
        if (!slots) fail("vftable not readable in image");
        json arr = json::array();
        for (auto v : *slots) arr.push_back(v);
        return {{"vftable_va", va}, {"targets", arr},
                {"count", arr.size()}};
    }
    if (action == "danger") {
        if (arch != disasm::image_arch_t::x86 && arch != disasm::image_arch_t::x64 && !hdb)
            fail("re.danger requires completed hyperion analysis for this image; "
                 "wait for disasm.loaded hype.ready");
        // hyperion knows the iat refs, the legacy index covers explicit paths
        auto hits = analysis::danger_scan(
            *pe,
            [xidx, hdb](uint64_t target_va) {
                std::vector<uint64_t> out;
                if (hdb) {
                    // one instruction can emit two records, dedupe by from
                    std::set<uint64_t> seen;
                    const auto it = hdb->xrefs_to.find(target_va);
                    if (it != hdb->xrefs_to.end())
                        for (const auto& x : it->second)
                            if (seen.insert(x.from).second)
                                out.push_back(x.from);
                    return out;
                }
                for (const auto& r : xidx->refs_to(target_va))
                    out.push_back(r.from);
                return out;
            },
            session_base);
        json arr = json::array();
        for (const auto& h : hits) {
            json cs = json::array();
            for (auto c : h.callsites) cs.push_back(c);
            arr.push_back({{"function", h.function},
                           {"category", h.category},
                           {"iat_va", h.iat_va},
                           {"callsites", cs},
                           {"count", cs.size()}});
        }
        return {{"hits", arr}, {"count", arr.size()}};
    }
    if (action == "libsig") {
        if (!args.contains("sigset")) fail("missing sigset JSON");
        std::string sig_err;
        auto sigs = analysis::parse_sig_set(
            args.at("sigset").get<std::string>(), &sig_err);
        if (!sigs) fail(sig_err.empty() ? "bad sigset" : sig_err);
        auto hits = analysis::libsig_scan(*pe, *file, *fidx, *sigs);
        json arr = json::array();
        for (const auto& h : hits) {
            json o = {{"name", h.sig_name}, {"va", h.va}};
            if (h.function_va) o["function_va"] = *h.function_va;
            arr.push_back(std::move(o));
        }
        return {{"hits", arr}, {"count", arr.size()},
                {"requested", sigs->size()}};
    }

    fail("re: unknown action (rtti_scan|vftable|danger|libsig)");
}

// tool: xray

json tool_xray(const json& args) {
    const std::string action = require_action(args);
    const bool needs_x86 = action != "entropy" && action != "apihash";
    const bool needs_pe = action == "syscalls" || action == "anti_analysis";

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    uint64_t default_base = 0;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        if (needs_x86) require_x86_image(cache.arch, cache.format, "xray." + action, true);
        if (needs_pe) require_pe_image(cache.arch, cache.format, "xray." + action, true);
        pe = &cache.pe; file = &cache.file;
        default_base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
        // reuse the path cache; byte-only queries never build an x86 index
        if (needs_x86 && !cache.fidx_ok) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!cache.fidx.build(cache.pe, cache.file, eng, default_base))
                fail("function index build failed");
            cache.fidx_ok = true;
        }
        img.fns = &cache.fidx;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        if (needs_x86) require_x86_image(bin.arch, bin.format, "xray." + action);
        if (needs_pe) require_pe_image(bin.arch, bin.format, "xray." + action);
        pe = &bin.pe; file = &bin.file;
        default_base = bin.base;
        img_name = bin.name;
        img.fns = &bin.fns;
    }
    img.pe = pe; img.file = file; img.base = default_base;

    if (needs_x86) {
        auto& engine = shared_engine();
        if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
        img.eng = &engine;
    }

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base") : default_base;
    (void)base;

    json out;
    out["image"] = img_name;

    if (action == "cfg" || action == "complexity" || action == "cff" ||
        action == "obfuscation" || action == "strings_recon" ||
        action == "indirect_calls" || action == "anti_analysis") {
        const uint64_t fn_va = parse_addr(args, "addr");

        if (action == "cfg" || action == "complexity") {
            auto r = xray::build_cfg(img, fn_va);
            if (!r.ok) fail(r.error);
            if (action == "cfg") {
                json blocks = json::array();
                for (const auto& b : r.blocks)
                    blocks.push_back({{"start", b.start}, {"end", b.end},
                                      {"instructions", b.instructions},
                                      {"successors", b.successors}});
                out["blocks"] = blocks;
                out["block_count"] = r.blocks.size();
            } else {
                auto c = xray::function_complexity(img, fn_va);
                out["instruction_count"]  = c.instruction_count;
                out["basic_block_count"]  = c.basic_block_count;
                out["edge_count"]         = c.edge_count;
                out["cyclomatic_complexity"] = c.cyclomatic;
                out["call_count"]      = c.call_count;
                out["branch_count"]    = c.branch_count;
                out["return_count"]    = c.return_count;
                out["arithmetic_ops"]  = c.arithmetic_ops;
                out["memory_accesses"] = c.memory_accesses;
                out["string_operations"] = c.string_operations;
                out["unique_operators"] = c.unique_operators;
                out["unique_operands"]  = c.unique_operands;
                out["complexity_rating"] = c.rating;
            }
            out["edge_count"] = r.edge_count;
            out["back_edges"] = r.back_edges;
            out["cyclomatic_complexity"] = r.cyclomatic;
            return out;
        }

        if (action == "cff") {
            auto r = xray::detect_cff(img, fn_va);
            out["flattened"] = r.flattened;
            out["block_count"] = r.block_count;
            if (r.flattened) {
                out["dispatcher"] = r.dispatcher;
                out["dispatcher_backedges"] = r.dispatcher_backedges;
                out["state_variable"] = r.state_var_desc;
                json sbs = json::array();
                for (const auto& sb : r.state_blocks)
                    sbs.push_back({{"start", sb.start}, {"end", sb.end},
                                   {"next_state", sb.has_next ? json(sb.next_state) : json()},
                                   {"assign_addr", sb.assign_addr}});
                out["state_blocks"] = sbs;
                out["state_block_count"] = r.state_blocks.size();
            }
            return out;
        }

        if (action == "obfuscation") {
            // report a diagnostic when nothing decodes instead of a wall of zeros
            auto r = xray::detect_obfuscation(img, fn_va);
            json pats = json::array();
            for (const auto& p : r.patterns)
                pats.push_back({{"type", p.type}, {"address", p.address},
                                {"detail", p.detail}});
            out["patterns"] = pats;
            out["opaque_predicates"] = r.opaque_predicates;
            out["dead_heads"] = r.dead_heads;
            out["junk_sequences"] = r.junk_sequences;
            out["indirect_jumps"] = r.indirect_jumps;
            out["push_ret"] = r.push_ret;
            out["privileged"] = r.privileged;
            out["obfuscation_score_pct"] = r.score_pct;
            // check it actually decoded
            auto probe = xray::decode_range(img, fn_va, 4);
            if (probe.empty()) {
                out["warning"] = "no instructions decoded at addr, region may be "
                                 "compressed/encrypted data; obfuscation analysis "
                                 "requires decodable code";
            }
            return out;
        }

        if (action == "strings_recon") {
            auto hits = xray::string_decrypt_recon(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"type", h.type}, {"address", h.address}};
                if (!h.reconstructed.empty()) o["reconstructed"] = h.reconstructed;
                if (h.xor_key) o["xor_key"] = h.xor_key;
                o["length"] = h.length;
                arr.push_back(std::move(o));
            }
            out["candidates"] = arr;
            out["count"] = arr.size();
            return out;
        }

        if (action == "indirect_calls") {
            auto hits = xray::indirect_calls(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"address", h.address}, {"text", h.text},
                          {"classification", h.classification}};
                if (!h.base_register.empty()) {
                    o["base_register"] = h.base_register;
                    o["offset"] = h.offset;
                }
                if (h.target) o["target"] = h.target;
                arr.push_back(std::move(o));
            }
            out["indirect_calls"] = arr;
            out["total"] = arr.size();
            return out;
        }

        // anti_analysis
        auto r = xray::detect_anti_analysis(img, fn_va);
        json dets = json::array();
        for (const auto& d : r.detections)
            dets.push_back({{"type", d.type}, {"address", d.address},
                            {"detail", d.detail}});
        out["detections"] = dets;
        out["anti_debug"] = r.anti_debug;
        out["anti_vm"] = r.anti_vm;
        out["timing_checks"] = r.timing_checks;
        out["traps"] = r.traps;
        out["anti_analysis_score_pct"] = r.score_pct;
        return out;
    }

    if (action == "hooks") {
        const size_t maxf = std::min<size_t>(args.value("max_functions", 500u), 10000u);
        const size_t indexed = img.fns ? img.fns->functions().size() : 0;
        std::vector<xray::hook_hit_t> hits;
        size_t checked = 0;
        std::string source = "index";
        if (indexed > 0) {
            hits = xray::detect_hooks(img, maxf);
            checked = std::min(indexed, maxf);
        } else if (shared_lock) {
            // Legacy index empty (stripped/packed headers): fall back to
            // Hyperion's recovered functions so hooks still get checked.
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                std::vector<uint64_t> vas;
                vas.reserve(bin.hype->db().funcs.size());
                for (const auto& [va, hf] : bin.hype->db().funcs) {
                    (void)hf;
                    vas.push_back(va);
                }
                std::sort(vas.begin(), vas.end());
                hits = xray::detect_hooks_at(img, vas, maxf);
                checked = std::min(vas.size(), maxf);
                source = "hyperion";
            }
        }
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"address", h.address}, {"hook_type", h.hook_type},
                           {"target", h.target}, {"prologue_bytes", h.prologue_hex}});
        out["functions_checked"] = checked;
        out["hooks_found"] = hits.size();
        out["hooks"] = arr;
        out["source"] = source;
        if (checked == 0)
            out["note"] = "no functions available: legacy index empty and "
                          "hyperion not ready (wait for hype.ready or pass path)";
        return out;
    }

    if (action == "syscalls") {
        uint64_t va = args.contains("addr") ? parse_addr(args, "addr") : 0;
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size")) : 0;
        auto hits = xray::detect_syscalls(img, va, size);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"address", h.address}, {"syscall_number", h.ssn},
                           {"pattern", h.pattern}});
        out["syscalls_found"] = hits.size();
        out["syscalls"] = arr;
        return out;
    }

    if (action == "apihash") {
        std::string algo = args.value("algorithm", std::string{"ror13"});
        if (algo != "ror13" && algo != "djb2" && algo != "crc32" &&
            algo != "fnv1a" && algo != "sdbm")
            fail("bad algorithm (ror13|djb2|crc32|fnv1a|sdbm)");
        // Accept both integer hashes ("0x..."/decimal/number) and plain API
        // names ("LoadLibraryA", "kernel32!CreateFileW"). Names are hashed
        // with the requested algorithm so callers never need to pre-hash.
        std::vector<uint64_t> hashes;
        json name_echo = json::array();
        auto push_hash = [&](std::vector<uint64_t>& v, const json& h) {
            if (h.is_string()) {
                const std::string s = h.get<std::string>();
                try {
                    size_t pos = 0;
                    const uint64_t num = std::stoull(s, &pos, 0);
                    if (pos == s.size()) {
                        v.push_back(num);
                        return;
                    }
                } catch (...) {}
                // not numeric: treat as an API name
                const uint32_t hv = xray::hash_api(s, algo, s.find('!') != std::string::npos);
                v.push_back(hv);
                name_echo.push_back({{"name", s}, {"hash", hv}});
                return;
            }
            if (h.is_number_unsigned()) v.push_back(h.get<uint64_t>());
            else if (h.is_number_integer() && h.get<int64_t>() >= 0)
                v.push_back(static_cast<uint64_t>(h.get<int64_t>()));
            else if (h.is_number_float())
                v.push_back(static_cast<uint64_t>(h.get<double>()));
            else fail("bad hash value (string name, hex, or integer)");
        };
        if (args.contains("hashes") && args.at("hashes").is_array())
            for (const auto& h : args.at("hashes")) push_hash(hashes, h);
        else {
            if (!args.contains("hash")) fail("missing hash/hashes");
            push_hash(hashes, args.at("hash"));
        }
        auto hits = xray::resolve_api_hashes(img, hashes, algo);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"hash", h.hash}, {"api", h.api}, {"dll", h.dll}});
        out["algorithm"] = algo;
        out["total_queried"] = hashes.size();
        out["resolved_count"] = arr.size();
        out["resolved"] = arr;
        if (!name_echo.empty()) out["name_inputs"] = name_echo;
        if (hits.empty() && !hashes.empty())
            out["hint"] = "no import matched; pass algorithm=ror13|djb2|crc32|fnv1a|sdbm "
                          "matching the sample, or pass plain API names (they are hashed for you)";
        return out;
    }

    if (action == "entropy" || action == "pages" || action == "crypto_range") {
        // accept base/va/address aliases: agents naturally say base=.
        // No address at all scans from the image base (a limit-only call
        // like pages limit=10 then works instead of erroring).
        const uint64_t va = has_any(args, {"addr", "base", "va", "address"})
            ? parse_addr_alias(args, {"addr", "base", "va", "address"})
            : default_base;
        const size_t size = has_any(args, {"size", "len", "length"})
            ? static_cast<size_t>(parse_addr_alias(args, {"size", "len", "length"})) : 4096;
        out["scan_base"] = va;
        out["scan_size"] = size;

        if (action == "entropy") {
            const size_t window = has_any(args, {"window_size", "window"})
                ? static_cast<size_t>(parse_addr_alias(args, {"window_size", "window"})) : 256;
            // honor limit as well as window_limit (zero means summary only)
            size_t win_limit = args.value("window_limit", size_t{64});
            if (args.contains("limit") && !args.contains("window_limit")) {
                const json& lv = args.at("limit");
                if (lv.is_number_unsigned()) win_limit = lv.get<size_t>();
                else if (lv.is_number_integer() && lv.get<int64_t>() >= 0)
                    win_limit = static_cast<size_t>(lv.get<int64_t>());
                else if (lv.is_string()) {
                    try { win_limit = static_cast<size_t>(std::stoull(lv.get<std::string>(), nullptr, 0)); }
                    catch (...) {}
                }
            }
            win_limit = std::min(win_limit, size_t{4096});
            auto r = xray::entropy_scan(img, va, size, window);
            out["overall_entropy"] = r.overall;
            out["min_window_entropy"] = r.min_window;
            out["max_window_entropy"] = r.max_window;
            out["window_size"] = window;
            out["verdict"] = r.verdict;
            out["truncated"] = r.truncated;
            out["total_windows"] = r.windows.size();
            json wins = json::array();
            if (win_limit > 0) {
                for (size_t i = 0; i < r.windows.size() && i < win_limit; ++i) {
                    const auto& w = r.windows[i];
                    wins.push_back({{"offset", w.offset}, {"entropy", w.entropy},
                                    {"verdict", w.verdict}});
                }
            }
            out["windows"] = wins;
            return out;
        }
        if (action == "pages") {
            const size_t ps = has_any(args, {"page_size", "window_size", "window"})
                ? static_cast<size_t>(parse_addr_alias(args, {"page_size", "window_size", "window"})) : 4096;
            const size_t page_limit = std::min<size_t>(args.value("limit", 1024u), 10000u);
            auto pages = xray::classify_pages(img, va, size, ps);
            json arr = json::array();
            json summary = {{"code", 0}, {"data", 0}, {"encrypted", 0},
                            {"padding", 0}, {"mixed", 0}};
            auto bump = [&summary](const char* k) {
                summary[k] = summary[k].get<int>() + 1;
            };
            for (size_t i = 0; i < pages.size() && arr.size() < page_limit; ++i) {
                const auto& p = pages[i];
                arr.push_back({{"address", p.address}, {"size", p.size},
                               {"class", p.klass}, {"entropy", p.entropy},
                               {"insn_ratio", p.insn_ratio},
                               {"zero_ratio", p.zero_ratio},
                               {"string_ratio", p.string_ratio}});
                const std::string k = p.klass;
                if (k == "code") bump("code");
                else if (k == "padding") bump("padding");
                else if (k == "encrypted_or_compressed" ||
                         k == "single_byte_encrypted") bump("encrypted");
                else if (k == "mixed") bump("mixed");
                else bump("data");
            }
            out["total_pages"] = pages.size();
            out["summary"] = summary;
            out["pages"] = arr;
            out["count"] = arr.size();
            out["truncated"] = pages.size() > arr.size();
            return out;
        }
        // crypto_range
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);
        auto hits = xray::crypto_range(img, va, size, limit);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"va", h.va}, {"algorithm", h.algorithm},
                           {"constant", h.constant_name}, {"value", h.value},
                           {"source", h.source}});
        out["matches"] = arr;
        out["count"] = arr.size();
        return out;
    }

    if (action == "gadgets") {
        const size_t limit = std::min<size_t>(args.value("limit", 200u), 2000u);
        auto hits = xray::rop_gadgets(img, limit);
        json arr = json::array();
        for (const auto& g : hits)
            arr.push_back({{"address", g.address}, {"text", g.text}});
        out["gadgets"] = arr;
        out["count"] = arr.size();
        return out;
    }

    fail("xray: unknown action (cfg|complexity|cff|obfuscation|strings_recon|"
         "indirect_calls|anti_analysis|hooks|syscalls|apihash|entropy|pages|"
         "crypto_range|gadgets)");
}

// tool: patch

json tool_patch(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    ds::binary_lock_t lk;
    auto& bin = ds::get();
    if (action == "nop_junk" || action == "resolve_opaque" ||
        action == "patch_antidebug" || action == "decode_strings" ||
        action == "full_pass" || action == "rebuild")
        require_x86_image(bin.arch, bin.format, "patch." + action);
    if (action == "patch_antidebug" || action == "full_pass")
        require_pe_image(bin.arch, bin.format, "patch." + action);

    imgpatch::op_result_t r;

    if (action == "nop_junk") {
        const uint64_t fn_va = parse_addr(args, "addr");
        r = imgpatch::nop_junk(bin, fn_va,
                               args.value("aggressive", false),
                               static_cast<size_t>(args.value("nop_threshold", 4u)));
    } else if (action == "resolve_opaque") {
        r = imgpatch::resolve_opaque_predicates(bin, parse_addr(args, "addr"),
                                                args.value("dry_run", false));
    } else if (action == "patch_antidebug") {
        imgpatch::anti_debug_opts_t opts;
        opts.patch_api_calls = args.value("patch_api_calls", true);
        opts.patch_int_traps = args.value("patch_int_traps", true);
        opts.patch_timing    = args.value("patch_timing", true);
        // Per-function operation: no addr scans the entry-point function.
        const bool defaulted_addr = !args.contains("addr");
        const uint64_t ad_va = defaulted_addr
            ? bin.base + bin.pe.entry_rva
            : parse_addr(args, "addr");
        r = imgpatch::patch_anti_debug(bin, ad_va, opts,
                                       args.value("dry_run", false));
        if (defaulted_addr) r.note = "no addr given: scanned entry-point function";
    } else if (action == "unpack_xor") {
        const std::string method = args.value("method", std::string{"auto"});
        if (method == "auto")
            require_x86_image(bin.arch, bin.format, "patch.unpack_xor (method=auto)");
        const uint64_t va = parse_addr(args, "addr");
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size"))
            : 4096;
        r = imgpatch::unpack_xor(bin, va, size,
                                 method,
                                 args.value("key_hex", std::string{}));
    } else if (action == "decode_strings") {
        r = imgpatch::decode_strings(bin, parse_addr(args, "addr"));
    } else if (action == "write_bytes") {
        if (!args.contains("hex")) fail("missing hex payload");
        r = imgpatch::write_bytes(bin, parse_addr(args, "addr"),
                                  hex_decode(args.at("hex").get<std::string>()));
    } else if (action == "revert_all") {
        r = imgpatch::revert_all(bin);
    } else if (action == "journal") {
        json arr = json::array();
        const size_t cap = std::min<size_t>(args.value("limit", 100u), bin.patches.size());
        for (size_t i = 0; i < cap; ++i) {
            const auto& p = bin.patches[i];
            arr.push_back({{"va", p.va}, {"before", p.before}, {"after", p.after}});
        }
        return {{"patches", arr}, {"total", bin.patches.size()},
                {"indexes_dirty", bin.indexes_dirty}};
    } else if (action == "full_pass") {
        auto r = imgpatch::full_pass(bin, parse_addr(args, "addr"),
                                     args.value("dry_run", false));
        if (!r.ok) fail(r.error);
        json steps = json::array();
        for (const auto& s : r.steps)
            steps.push_back({{"step", s.name}, {"success", s.success},
                             {"note", s.note}});
        return {{"ok", true},
                {"dry_run", r.dry_run},
                {"steps", steps},
                {"pre_obfuscation_score", r.pre_score},
                {"post_obfuscation_score", r.post_score},
                {"score_reduction", r.pre_score - r.post_score},
                {"strings_found", r.strings_found},
                {"bytes_changed", r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    } else if (action == "rebuild") {
        auto r = imgpatch::rebuild(bin, parse_addr(args, "addr"));
        if (!r.ok) fail(r.error);
        json insns = json::array();
        for (const auto& [va, text] : r.insns)
            insns.push_back({{"va", va}, {"text", text}});
        return {{"ok", true},
                {"instruction_count", r.instruction_count},
                {"insns", insns},
                {"indexes_dirty", bin.indexes_dirty}};
    } else {
        fail("patch: unknown action (nop_junk|resolve_opaque|patch_antidebug|"
             "unpack_xor|decode_strings|write_bytes|revert_all|journal|"
             "full_pass|rebuild)");
    }

    if (!r.ok) fail(r.error);
    json pats = json::array();
    for (const auto& p : r.patches) {
        json o = {{"va", p.va}, {"action", p.action}};
        if (!p.detail.empty()) o["detail"] = p.detail;
        pats.push_back(std::move(o));
    }
    json out = {{"ok", true},
                {"dry_run", r.dry_run},
                {"patches", pats},
                {"bytes_changed", r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    if (r.detected_key) {
        out["detected_key"] = r.detected_key;
        out["key_confidence"] = r.key_confidence;
    }
    if (r.strings_found) out["strings_found"] = r.strings_found;
    if (!r.note.empty()) out["note"] = r.note;
    return out;
}

// tool: types

json struct_to_json(const re::type_catalog::struct_def_t& s) {
    json fields = json::array();
    for (const auto& f : s.fields)
        fields.push_back({{"name", f.name}, {"type", f.type},
                          {"offset", f.offset}, {"size", f.size},
                          {"array_count", f.array_count}});
    return {{"name", s.name}, {"size", s.size}, {"packed", s.packed},
            {"fields", fields}};
}

json enum_to_json(const re::type_catalog::enum_def_t& e) {
    json vals = json::array();
    for (const auto& [n, v] : e.values)
        vals.push_back({{"name", n}, {"value", v}});
    return {{"name", e.name}, {"underlying", e.underlying}, {"values", vals}};
}

json tool_types(const json& args) {
    namespace tc = re::type_catalog;
    const std::string action = require_action(args);

    if (action == "create_struct" || action == "declare") {
        std::string decl_text;
        if (args.contains("decl") && args.at("decl").is_string())
            decl_text = args.at("decl").get<std::string>();
        else if (args.contains("name") && args.at("name").is_string())
            decl_text = "struct " + args.at("name").get<std::string>() + " {};";

        tc::decl_parse_result_t pr = tc::parse_decls(decl_text);
        if (!pr.error.empty()) fail(pr.error);
        size_t n = 0;
        std::string errs;
        for (auto& s : pr.structs)
            if (tc::create_struct(std::move(s), &errs)) ++n;
        for (auto& e : pr.enums)
            if (tc::create_enum(std::move(e), &errs)) ++n;
        if (n == 0) fail(errs.empty() ? "nothing declared" : errs);
        return {{"declared", n}};
    }

    if (action == "get_struct") {
        auto s = tc::get_struct(args.at("name").get<std::string>());
        if (!s) fail("unknown struct");
        return struct_to_json(*s);
    }
    if (action == "list_structs") {
        auto all = tc::list_structs(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& s : all) arr.push_back(struct_to_json(s));
        return {{"structs", arr}, {"count", arr.size()}};
    }
    if (action == "add_member") {
        tc::field_t f;
        f.name  = args.at("field").get<std::string>();
        f.type  = args.at("type").get<std::string>();
        f.array_count = static_cast<uint32_t>(args.value("array_count", 0u));
        std::string err;
        if (!tc::add_member(args.at("name").get<std::string>(), f, &err)) fail(err);
        auto s = tc::get_struct(args.at("name").get<std::string>());
        return struct_to_json(*s);
    }
    if (action == "remove_struct")
        return {{"removed", tc::remove_struct(args.at("name").get<std::string>())}};

    if (action == "create_enum") {
        tc::enum_def_t e;
        e.name = args.at("name").get<std::string>();
        e.underlying = args.value("underlying", std::string{"u32"});
        for (const auto& v : args.at("values")) {
            int64_t val = 0;
            const json& jv = v.contains("value") ? v.at("value") : json();
            if (jv.is_number_integer()) val = jv.get<int64_t>();
            else if (jv.is_string())    val = static_cast<int64_t>(std::stoull(jv.get<std::string>(), nullptr, 0));
            e.values.emplace_back(v.at("name").get<std::string>(), val);
        }
        std::string err;
        if (!tc::create_enum(std::move(e), &err)) fail(err);
        return {{"created", true}};
    }
    if (action == "get_enum") {
        auto e = tc::get_enum(args.at("name").get<std::string>());
        if (!e) fail("unknown enum");
        return enum_to_json(*e);
    }
    if (action == "list_enums") {
        auto all = tc::list_enums(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& e : all) arr.push_back(enum_to_json(e));
        return {{"enums", arr}, {"count", arr.size()}};
    }
    if (action == "remove_enum")
        return {{"removed", tc::remove_enum(args.at("name").get<std::string>())}};

    if (action == "format_at") {
        // pretty print typed memory like MYSTRUCT @ 140001234
        if (!args.contains("addr")) fail("missing addr");
        if (!args.contains("type") && !args.contains("struct"))
            fail("missing type (struct or enum name)");
        const std::string type_name =
            args.value("type", args.value("struct", std::string{}));
        const uint64_t base = parse_addr(args, "addr");
        const size_t   want =
            static_cast<size_t>(args.value("size", 256u)) & 0xFFFF;

        // sync the catalog into a hyperion type system per call, theyre small
        hype::TypeSystem ts;
        std::unordered_map<std::string, uint32_t> ids;
        for (const auto& e : tc::list_enums()) {
            const uint32_t id = ts.add_enum(e.name);
            for (const auto& [n, v] : e.values) ts.add_member(id, n, v);
            ids[e.name] = id;
        }
        for (const auto& s : tc::list_structs()) {
            const uint32_t id = ts.add_struct(s.name,
                static_cast<uint32_t>(s.size ? s.size : 1));
            ids[s.name] = id;
        }
        // second pass so struct to struct references resolve
        for (const auto& s : tc::list_structs()) {
            for (const auto& f : s.fields) {
                uint32_t tid = 0;
                auto it = ids.find(f.type);
                if (it != ids.end()) {
                    tid = it->second;
                } else {
                    // map catalog names to hyperion builtins
                    static const std::unordered_map<std::string, const char*> prim = {
                        {"u8", "u8"}, {"u16", "u16"}, {"u32", "u32"}, {"u64", "u64"},
                        {"i8", "i8"}, {"i16", "i16"}, {"i32", "i32"}, {"i64", "i64"},
                        {"f32", "float"}, {"f64", "double"},
                        {"ptr", "ptr64"}, {"char", "char"},
                    };
                    auto pit = prim.find(f.type);
                    const char* pname = pit != prim.end() ? pit->second : "u8";
                    if (const auto* td = ts.find_by_name(pname)) tid = td->id;
                }
                ts.add_field(ids[s.name], f.name, tid,
                             static_cast<uint32_t>(f.offset));
            }
        }
        const auto* td = ts.find_by_name(type_name);
        if (!td) fail("unknown type: " + type_name);

        // live target when asked, else the file image
        std::vector<uint8_t> buf(want);
        std::string source = "file";
        bool got = false;
        if (args.value("live", false)) {
            if (auto sess = process::active_session(); sess && sess->valid()) {
                auto io = sess->read(static_cast<uintptr_t>(base), buf.data(),
                                     buf.size());
                if (io.ok && io.bytes) {
                    buf.resize(io.bytes);
                    got = true;
                    source = "live";
                }
            }
            if (!got) fail("live read failed (target attached?)");
        } else {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                if (auto off = bin.offset_of(base)) {
                    const size_t n = std::min(want, bin.file.size() - *off);
                    std::memcpy(buf.data(), bin.file.data() + *off, n);
                    buf.resize(n);
                    got = true;
                }
            }
            if (!got)
                fail("address not mapped in loaded image (load a binary or "
                     "pass live=true with a target attached)");
        }

        return {{"ok", true}, {"addr", base}, {"type", type_name},
                {"source", source},
                {"rendered", ts.format_at(base, td->id, buf.data(),
                                          buf.size())}};
    }

    if (action == "read_field") {
        auto s = tc::get_struct(args.at("struct").get<std::string>());
        if (!s) fail("unknown struct");
        const uint64_t base = parse_addr(args, "addr");

        // file image first, live memory when asked
        bool live = args.value("live", false);
        if (!live) {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                auto off = bin.offset_of(base);
                if (off) {
                    auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                            0 /*offset already translated*/,
                                            bin.file.data() + *off,
                                            bin.file.size() - *off,
                                            nullptr, nullptr);
                    if (v.ok) return {{"ok", true}, {"hex", v.hex},
                                      {"uint", v.uint_val}, {"int", v.int_val},
                                      {"double", v.dbl_val}, {"source", "file"}};
                }
            }
        }
        auto sess = process::active_session();
        if (!live || !sess || !sess->valid())
            fail("no image data for that address (attach a target or use a mapped VA)");

        struct cb_ctx { runtime::session_t* s; } ctx{sess.get()};
        auto cb = [](uint64_t addr, void* dst, size_t len, void* user) -> bool {
            auto* c = static_cast<cb_ctx*>(user);
            auto io = c->s->read(static_cast<uintptr_t>(addr), dst, len);
            return io.ok && io.bytes == len;
        };
        auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                base, nullptr, 0, cb, &ctx);
        if (!v.ok) fail(v.error);
        return {{"ok", true}, {"hex", v.hex}, {"uint", v.uint_val},
                {"int", v.int_val}, {"double", v.dbl_val}, {"source", "target"}};
    }

    fail("types: unknown action (declare|create_struct|get_struct|list_structs|"
         "add_member|remove_struct|create_enum|get_enum|list_enums|remove_enum|"
         "read_field|format_at)");
}

// tool: notes

json tool_notes(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    if (action == "set_comment") {
        const uint64_t va = parse_addr(args, "addr");
        const std::string text = args.value("text", std::string{});
        ds::set_comment(va, text);          // saved, empty clears
        return {{"va", va}, {"cleared", text.empty()}};
    }
    if (action == "get_comment") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"comment", ds::comment_for(va)}};
    }
    if (action == "comments") {
        auto snaps = ds::comments_snapshot();
        std::sort(snaps.begin(), snaps.end());
        json arr = json::array();
        for (const auto& [va, text] : snaps)
            arr.push_back({{"va", va}, {"comment", text}});
        return {{"comments", arr}, {"count", arr.size()}};
    }
    if (action == "bookmark_toggle") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"bookmarked", ds::toggle_bookmark(va)}};
    }
    if (action == "bookmarks") {
        auto marks = ds::bookmarks_snapshot();
        std::sort(marks.begin(), marks.end());
        return {{"bookmarks", marks}, {"count", marks.size()}};
    }
    fail("notes: unknown action (set_comment|get_comment|comments|"
         "bookmark_toggle|bookmarks)");
}

// tool: devirt

// Seeded emulation runs for recover_cfg / prove_predicates / invariants. Each
// run builds a fresh unicorn instance and maps the data sections while this
// tool holds g_tool_mu and the binary lock, so the count must stay bounded
size_t devirt_runs(const json& args) {
    constexpr int64_t kMaxRuns = 64;
    return static_cast<size_t>(
        std::clamp<int64_t>(args.value("runs", int64_t{4}), 1, kMaxRuns));
}

json tool_devirt(const json& args) {
    const std::string action = require_action(args);

    const auto pe_json = [](const magicmida::pe_info_t& pe) {
        return json{{"ok", pe.ok}, {"arch", magicmida::arch_name(pe.arch)},
                    {"entry_rva", pe.entry_rva}, {"size_of_image", pe.size_of_image},
                    {"sections", pe.sections}, {"file_size", pe.file_size},
                    {"error", pe.error}};
    };
    const auto job_json = [&pe_json](const magicmida::job_t& job) {
        json out = {{"id", job.id}, {"state", magicmida::state_name(job.state)},
                    {"input_path", job.request.input_path},
                    {"requested_output_path", job.request.output_path}};
        if (job.state == magicmida::state_t::succeeded ||
            job.state == magicmida::state_t::failed ||
            job.state == magicmida::state_t::cancelled) {
            out["result"] = {{"ok", job.result.ok},
                             {"cancelled", job.result.cancelled},
                             {"timed_out", job.result.timed_out},
                             {"exit_code", job.result.exit_code},
                             {"duration_ms", job.result.duration_ms},
                             {"arch", magicmida::arch_name(job.result.arch)},
                             {"generated_path", job.result.generated_path},
                             {"output_path", job.result.output_path},
                             {"output", pe_json(job.result.output)},
                             {"warnings", job.result.warnings},
                             {"error", job.result.error}};
        }
        return out;
    };

    if (action == "themida_status") {
        const auto install = magicmida::installation();
        json running = json::array();
        for (const auto& job : magicmida::jobs()) running.push_back(job_json(job));
        return {{"engine", "Magicmida"}, {"version", "2026-05-14"},
                {"root", install.root}, {"x86_exe", install.x86_exe},
                {"x64_exe", install.x64_exe},
                {"x86_available", install.x86_available},
                {"x64_available", install.x64_available},
                {"x64_scyllahide_available", install.x64_scyllahide_available},
                {"jobs", std::move(running)}};
    }
    if (action == "themida_start") {
        const std::string path = args.value("path", std::string{});
        if (path.empty()) fail("themida_start requires 'path'");
        magicmida::request_t request;
        request.input_path = path;
        request.output_path = args.value("output_path", std::string{});
        request.timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 300000), 1000, 1800000));
        request.overwrite = args.value("overwrite", false);
        request.load_result = args.value("load", true);
        std::string error;
        const uint64_t id = magicmida::start(std::move(request), error);
        if (id == 0) fail(error);
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job was not registered");
        return job_json(job);
    }
    if (action == "themida_job") {
        const uint64_t id = parse_addr(args, "id");
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job not found");
        return job_json(job);
    }
    if (action == "themida_cancel") {
        const uint64_t id = parse_addr(args, "id");
        return {{"id", id}, {"cancelled", magicmida::cancel(id)}};
    }

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        require_x86_image(cache.arch, cache.format, "devirt." + action, true);
        img.pe = &cache.pe; img.file = &cache.file;
        img.base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        require_x86_image(bin.arch, bin.format, "devirt." + action);
        img.pe = &bin.pe; img.file = &bin.file;
        img.base = bin.base;
        img_name = bin.name;
    }

    auto& engine = shared_engine();
    if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
    img.eng = &engine;

    json out;
    out["image"] = img_name;

    // read only deobfuscation analysis

    if (action == "recover_cfg") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto r = recover::recover_flattened(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["flattened"] = r.flattened;
        out["dispatcher"] = r.dispatcher;
        out["mode"] = r.mode;
        json edges = json::array();
        for (const auto& e : r.dispatch_map)
            edges.push_back({{"state", e.state}, {"target", e.target}});
        out["dispatch_map"] = edges;
        out["real_edges_recovered"] = r.real_edges_recovered;
        out["fake_edges"] = r.fake_edges;
        out["blocks"] = r.blocks;
        out["corroborated"] = r.corroborated;
        out["runs"] = r.runs;
        out["dispatcher_entries_observed"] = r.dispatcher_entries_observed;
        if (!r.note.empty()) out["note"] = r.note;
        return out;
    }

    if (action == "prove_predicates") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto batch = recover::prove_predicates_ex(img, fn_va, runs);
        json arr = json::array();
        for (const auto& p : batch.proofs)
            arr.push_back({{"jcc_va", p.jcc_va}, {"text", p.text},
                           {"static_idiom", p.static_idiom},
                           {"seen_runs", p.seen_runs},
                           {"taken_runs", p.taken_runs},
                           {"total_runs", p.total_runs},
                           {"proven_always_taken", p.proven_always_taken},
                           {"proven_never_taken", p.proven_never_taken}});
        out["predicates"] = arr;
        out["count"] = arr.size();
        out["completed_runs"] = batch.completed_runs;
        out["failed_runs"] = batch.failed_runs;
        out["faulted_runs"] = batch.faulted_runs;
        if (!batch.first_fault.empty()) out["first_fault"] = batch.first_fault;
        if (batch.failed_runs > 0 || batch.faulted_runs > 0)
            out["note"] = "slice emulation faulted on " +
                          std::to_string(batch.failed_runs + batch.faulted_runs) +
                          "/" + std::to_string(runs) + " runs (" +
                          batch.first_fault + "); seen_runs counts observations "
                          "from usable trace prefixes, so seen=0 with faults "
                          "means the branch was never reached (unmapped "
                          "callee/import in the slice), not that it is opaque";
        return out;
    }

    if (action == "invariants") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto r = recover::observe_invariants(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["instructions_executed"] = r.instructions_executed;
        out["stopped_reason"] = r.stopped_reason;
        json inv = json::array();
        for (const auto& i : r.invariants)
            inv.push_back({{"reg", i.reg}, {"value", i.value}});
        out["invariants"] = inv;
        return out;
    }

    if (action == "iat_audit") {
        uint64_t va = has_any(args, {"addr", "va", "table", "handler_table"})
            ? parse_addr_alias(args, {"addr", "va", "table", "handler_table"}) : 0;
        size_t size = has_any(args, {"size", "len", "length"})
            ? static_cast<size_t>(parse_addr_alias(args, {"size", "len", "length"})) : (1u << 20);
        auto r = recover::iat_audit(img, va, size);
        if (!r.ok) fail(r.error);
        out["slots_scanned"] = r.slots_scanned;
        out["named"] = r.named;
        out["unnamed_valid"] = r.unnamed_valid;
        out["invalid"] = r.invalid;
        json slots = json::array();
        for (const auto& s : r.unnamed)
            slots.push_back({{"slot_va", s.slot_va}, {"target", s.target}});
        out["unnamed_candidates"] = slots;
        out["note"] = r.note.empty()
            ? "default (no addr) audits parsed IAT slots only; pass addr+size "
              "for a targeted range (only image-VA-shaped values count)"
            : r.note;
        return out;
    }

    // devirtualization chain

    if (action == "identify") {
        auto r = devirt::identify(img, parse_addr_alias(args, {"addr", "entry", "va", "start", "address"}));
        if (!r.ok) fail(r.error);
        out["likely_vm"] = r.likely_vm;
        out["confidence_pct"] = r.confidence_pct;
        out["fn_va"] = r.fn_va;
        out["dispatcher"] = r.dispatcher;
        out["handler_table"] = r.handler_table;
        out["table_entry_size"] = r.table_entry_size;
        out["indirect_jumps"] = r.indirect_jumps;
        out["cmp_chain_len"] = r.cmp_chain_len;
        return out;
    }

    if (action == "handlers" || action == "opcode_map") {
        // accept table|handler_table|addr aliases -- agents pass addr=
        const uint64_t table = parse_addr_alias(args, {"table", "handler_table", "addr", "va", "address"});
        uint32_t es = has_any(args, {"entry_size", "stride"})
            ? static_cast<uint32_t>(parse_addr_alias(args, {"entry_size", "stride"})) : 0;
        const size_t maxh = std::min<size_t>(args.value("max_handlers", 256u), 4096u);
        auto r = devirt::classify_handlers(img, table, es, maxh);
        if (!r.ok) fail(r.error);
        out["handler_table"] = r.handler_table;
        out["entry_size"] = r.entry_size;
        out["valid_entries"] = r.valid_entries;
        json hs = json::array();
        for (const auto& h : r.handlers) {
            json o = {{"opcode", h.opcode}, {"va", h.va},
                      {"classification", h.classification},
                      {"instruction_count", h.instruction_count}};
            if (action == "handlers") {
                json texts = json::array();
                for (const auto& t : h.insns) texts.push_back(t);
                o["insns"] = texts;
            }
            hs.push_back(std::move(o));
        }
        out["handlers"] = hs;
        return out;
    }

    if (action == "trace" || action == "lift" || action == "pseudocode") {
        const uint64_t entry = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"}); // VM entry
        const uint64_t dispatcher = has_any(args, {"dispatcher"})
            ? parse_addr_alias(args, {"dispatcher"}) : 0;
        const size_t max_ops = std::min<size_t>(args.value("max_ops", 512u), 4096u);

        // handlers come from a table walk, a caller supplied list, or
        // auto-discovery via identify() when neither is given
        std::vector<uint64_t> handler_vas;
        if (has_any(args, {"handler_table", "table"})) {
            uint64_t table = parse_addr_alias(args, {"handler_table", "table"});
            uint32_t es = has_any(args, {"entry_size", "stride"})
                ? static_cast<uint32_t>(parse_addr_alias(args, {"entry_size", "stride"})) : 8;
            auto cls = devirt::classify_handlers(img, table, es, 256);
            if (!cls.ok) fail(cls.error);
            for (const auto& h : cls.handlers) handler_vas.push_back(h.va);
            out["entry_size"] = cls.entry_size;
            out["valid_entries"] = cls.valid_entries;
        } else if (args.contains("handlers") && args.at("handlers").is_array()) {
            for (const auto& v : args.at("handlers")) {
                if (v.is_string()) {
                    const std::string s = v.get<std::string>();
                    try {
                        handler_vas.push_back(std::stoull(s, nullptr, 0));
                    } catch (...) {
                        fail("bad handlers entry '" + s + "' (hex or decimal integer)");
                    }
                } else if (v.is_number_unsigned()) handler_vas.push_back(v.get<uint64_t>());
                else if (v.is_number_integer() && v.get<int64_t>() >= 0)
                    handler_vas.push_back(static_cast<uint64_t>(v.get<int64_t>()));
                else if (v.is_number_float())
                    handler_vas.push_back(static_cast<uint64_t>(v.get<double>()));
                else fail("bad handlers entry (hex string or integer)");
            }
        } else {
            // no table/list: try identify() so plain addr= works with a
            // clear diagnostic when the function is not VM-shaped
            auto id = devirt::identify(img, entry);
            if (!id.ok) fail(id.error);
            if (id.likely_vm && id.handler_table) {
                auto cls = devirt::classify_handlers(img, id.handler_table,
                                                     id.table_entry_size, 256);
                if (!cls.ok)
                    fail("auto-discovered table " + hex64(id.handler_table) +
                         " unusable: " + cls.error + " (pass handler_table/handlers explicitly)");
                for (const auto& h : cls.handlers) handler_vas.push_back(h.va);
                out["auto_table"] = id.handler_table;
                out["entry_size"] = cls.entry_size;
                out["valid_entries"] = cls.valid_entries;
            } else {
                fail("missing handler_table or handlers list; identify() says " +
                     std::string(id.likely_vm ? "likely_vm" : "not a VM function") +
                     " (confidence " + std::to_string(id.confidence_pct) +
                     "%). Run devirt.identify addr=<fn> first; trace/lift/pseudocode "
                     "require a VM dispatcher (handler_table or handlers list), "
                     "plain functions are not supported");
            }
        }
        if (handler_vas.empty()) fail("no handlers to trace");

        auto tr = devirt::trace_bytecode(img, entry, dispatcher,
                                         handler_vas, max_ops);
        if (!tr.ok && tr.bytecode.empty()) fail(tr.error);
        out["dispatcher_hits"] = tr.dispatcher_hits;
        out["stopped_reason"] = tr.stopped_reason;
        if (!tr.note.empty()) out["note"] = tr.note;

        if (action == "trace") {
            out["bytecode"] = tr.bytecode;
            out["handler_order"] = tr.handler_order;
            return out;
        }

        devirt::classify_result_t cls;
        cls.ok = true;
        for (size_t i = 0; i < handler_vas.size(); ++i) {
            devirt::handler_t h;
            h.opcode = static_cast<uint32_t>(i);
            h.va     = handler_vas[i];
            // classify by decoding each handler
            std::vector<disasm::insn_t> insns;
            uint64_t cur = h.va;
            for (size_t k = 0; k < 128; ++k) {
                uint8_t buf[16];
                if (cur < img.base) break;
                auto off = img.pe->rva_to_offset(
                    static_cast<uint32_t>(cur - img.base));
                if (!off || *off + sizeof(buf) > img.file->size()) break;
                std::memcpy(buf, img.file->data() + *off, sizeof(buf));
                auto in = img.eng->decode(cur, buf, sizeof(buf));
                if (!in || in->length == 0) break;
                insns.push_back(std::move(*in));
                cur += insns.back().length;
            }
            h.instruction_count = insns.size();
            h.classification = devirt::classify_handler_insns(insns);
            cls.handlers.push_back(std::move(h));
        }

        auto lifted = devirt::lift(tr, cls);
        if (!lifted.ok) fail(lifted.error);

        if (action == "lift") {
            json lines = json::array();
            for (const auto& l : lifted.lines)
                lines.push_back({{"opcode", l.opcode},
                                 {"handler_va", l.handler_va},
                                 {"il", l.il}});
            out["lines"] = lines;
            out["covered"] = lifted.covered;
            return out;
        }

        out["pseudocode"] = devirt::pseudocode(lifted);
        return out;
    }

    fail("devirt: unknown action (themida_status|themida_start|themida_job|"
         "themida_cancel|identify|handlers|opcode_map|trace|lift|"
         "pseudocode|recover_cfg|prove_predicates|invariants|iat_audit)");
}

// tool: frida

json tool_script(const json& args) {
    const std::string action = require_action(args);
    if (action != "run") fail("script: unknown action");

    size_t code_len = 0;
    const char* code_ptr = nullptr;
    std::string code;
    if (args.contains("code") && args.at("code").is_string())
        code = args.at("code").get<std::string>();
    if (code.empty()) fail("missing code string");
    code_ptr = code.c_str();
    code_len = code.size();

    const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
    auto r = script::lua_run(code, timeout_ms);
    json out = {{"ok", r.ok}, {"output", r.output}};
    if (!r.error.empty()) out["error"] = r.error;
    return out;
}

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

    fail("app: unknown action");
    return {};
}

} // namespace

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
          {"debugger", "watchpoint_set", R"({"addr":<hit>,"len":4})", "kernel page-guard watch (driver) or debugger ps4_find_write on PS4"},
          {"debugger", "callstack", "{}", "who wrote it (paused at the watch)"}}},
        {"find_damage_source", "Find the function that applies damage",
         "Watch the health address for writes while attacking, then break on the writer and walk up the callstack to the damage logic.",
         {{"memory", "watch_add", R"({"addr":<health>,"width":"i32","freeze":false})", "track value changes"},
          {"debugger", "ps4_find_write", R"({"addr":<health>})", "on PS4: watchpoint -> event + callstack"},
          {"debugger", "watchpoint_set", R"({"addr":<health>})", "on local: page-guard watchpoint (slopdrvr)"},
          {"debugger", "bp_set", R"({"addr":<writer>,"condition":"rcx<100"})", "break at the writer, optionally conditional"},
          {"debugger", "wait_halt", R"({"timeout_ms":60000})", "wait for the hit"},
          {"debugger", "callstack", "{}", "full stack at the hit"}}},
        {"pointer_chain", "Follow a pointer chain from a static/global to a live object",
         "pointerscan walks static roots and reads pointer chains out of live memory, returning the address path for each hit.",
         {{"memory", "pointerscan", R"({"target":<value>,"depth":5,"max_results":32})", "find chains ending at the value"},
          {"memory", "read", R"({"addr":<root>,"len":8,"format":"u64"})", "re-verify each hop"},
          {"types", "format_at", R"({"addr":<object>,"name":"<struct>"})", "render the object with a declared struct"}}},
        {"runtime_decrypt", "Catch string decryption at runtime instead of reversing the routine",
         "Games decrypt strings in place. Scan for the encrypted blob, watch the decrypted buffer region for a write, break on the writer, read the plaintext.",
         {{"memory", "aob", R"({"pattern":"48 8d 0d ?? ?? ?? ?? e8"})", "find lea+call sites referencing the blob"},
          {"memory", "watch_add", R"({"addr":<buffer>,"len":64,"width":"u8"})", "watch the destination buffer"},
          {"debugger", "bp_set", R"({"addr":<decrypt_call>,"log":"decrypt called"})", "log every call to the decrypt routine"},
          {"debugger", "wait_halt", "{}", "stop at the call"},
          {"memory", "read", R"({"addr":<buffer>,"len":64,"format":"utf8"})", "plaintext after the call"},
          {"patch", "decode_strings", R"({"addr":<func>})", "or statically decode in the loaded image"}}},
        {"api_monitor_local", "Monitor calls to a Win32/game API in a local process",
         "Attach the debugger, set a breakpoint on the import thunk with a log string or condition, continue, then read the event log and registers.",
         {{"target", "attach", R"({"pid":1234})", "attach the game"},
          {"target", "modules", "{}", "find the module base"},
          {"disasm", "disassemble", R"({"addr":<iat_thunk>,"count":4})", "resolve the API's thunk"},
          {"debugger", "attach", R"({"pid":1234})", "start the debug loop"},
          {"debugger", "bp_set", R"({"addr":<thunk>,"log":"CreateFileW","condition":""})", "bp with log = tracepoint"},
          {"debugger", "continue", "{}", "run"},
          {"debugger", "wait_halt", R"({"timeout_ms":30000})", "until next stop"},
          {"debugger", "events", "{}", "logged hits"},
          {"debugger", "regs", "{}", "rcx/rdx/r8/r9 = Win64 args"}}},
        {"snapshot_diff", "See exactly what memory a game action changed",
         "snapshot before, do the action, diff the two snapshots — every changed byte with old/new values.",
         {{"memory", "snapshot", R"({"label":"a"})", "before"},
          {"memory", "snapshot", R"({"label":"b"})", "after the action"},
          {"memory", "diff", R"({"a":<id_a>,"b":<id_b>})", "changed ranges with old/new"}}},
        {"emulate_function", "Emulate a function offline with stubbed imports",
         "emulate.run executes target_addr code in Unicorn with IAT stubs returning api_ret/api_returns, TEB/PEB, page-in from live memory, trace and taint. Ideal for crypto, checksum, decrypt routines.",
         {{"target", "attach", R"({"pid":1234})", "so target_addr reads live memory"},
          {"debugger", "ps4_regs", R"({"lwpid":101})", "on PS4: grab live regs first"},
          {"emulate", "run", R"({"target_addr":4202496,"code_len":256,"regs":{"rcx":1234},"api_returns":{"kernel32.dll!VirtualAlloc":4096},"trace":true,"trace_max":128})", "run the slice"},
          {"emulate", "run", R"({"hex":"...","count":100000,"until":<ret_addr>})", "or raw bytes"}}},
        {"devirt_cflow", "Recover a flattened/obfuscated control flow",
         "xray.cff finds the dispatcher and state blocks; devirt.recover_cfg rebuilds the CFG; decomp then shows readable code.",
         {{"disasm", "functions", R"({"limit":200})", "find suspicious functions"},
          {"xray", "cff", R"({"addr":<func>})", "dispatcher + state_blocks"},
          {"devirt", "recover_cfg", R"({"addr":<func>})", "rebuild the CFG"},
          {"decomp", "function", R"({"function_va":<func>})", "decompile after recovery"}}},
        {"unpack_runtime", "Unpack a packed binary by dumping memory, or analyze statically",
         "Packed code unpacks itself at runtime: attach early, break at the OEP (entry entropy spike), dump_module the live image, then load the dump for static analysis.",
         {{"analyze", "packer", R"({"path":"game.exe"})", "is it packed? entropy/sections"},
          {"target", "attach", R"({"pid":1234})", "attach at start"},
          {"debugger", "bp_set", R"({"addr":<oep>})", "break at the unpacked entry"},
          {"debugger", "wait_halt", R"({"timeout_ms":60000})", "wait for unpack"},
          {"target", "dump_module", R"({"base":<image_base>,"path":"dump.exe","load":true})", "dump live unpacked image and load it"},
          {"xray", "entropy", R"({"path":"dump.exe"})", "verify unpacked"}}},
        {"hw_breakpoints", "Hardware breakpoints without touching target memory",
         "With slopdrvr loaded, DR0-DR3 breakpoints catch execution/reads/writes without an INT3 byte, invisible to memory scans. debugger bp_set hw=true uses them; on PS4 use ps4_watch_set (the payload programs DR registers).",
         {{"driver", "status", "{}", "is slopdrvr active?"},
          {"debugger", "attach", R"({"pid":1234})", "attach"},
          {"debugger", "bp_set", R"({"addr":<addr>,"hw":true,"type":0,"len":8})", "type 0=exec 1=write 3=rdwr"},
          {"debugger", "continue", "{}", "go"},
          {"debugger", "ps4_watch_set", R"({"addr":<addr>,"type":3,"len":8})", "PS4 equivalent via ps4debug DR slots"}}},
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

void list_tools(json& out) {
    const char* target_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["list","attach","detach","status","modules","dump_module","threads","regions","handles","icon","ps4_connect","ps4_disconnect","ps4_auto"]},"pid":{"type":"integer"},"host":{"type":"string"},"port":{"type":"integer"},"base":{"type":"integer"},"name":{"type":"string"},"path":{"type":"string"},"paths":{"type":"array","items":{"type":"string"}},"load":{"type":"boolean"},"strict":{"type":"boolean"}},"required":["action"]})";
    const char* memory_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["read","write","scan","rescan","scan_state","scan_reset","aob","pointerscan","snapshot","snapshots","diff","snapshot_free","protect","alloc","free","siggen","live_crypto","watch_list","watch_add","watch_remove","watch_clear","watch_set"]},"addr":{"type":"integer"},"len":{"type":"integer"},"format":{"type":"string","enum":["hex","utf8","u8","u32","u64","f32","f64"]},"hex":{"type":"string"},"kind":{"type":"string","enum":["exact","between","bigger","smaller","unknown","increased","increased_by","increased_percent","decreased","decreased_by","decreased_percent","changed","unchanged"]},"width":{"type":"string","enum":["i8","u8","i16","u16","i32","u32","i64","u64","f32","f64","all"]},"rounding":{"type":"string","enum":["exact","rounded","truncated","extreme"]},"value":{},"value2":{},"begin":{"type":"integer"},"end":{"type":"integer"},"pattern":{"type":"string"},"tail":{"type":"string"},"writable":{"oneOf":[{"type":"string","enum":["any","include","exclude"]},{"type":"boolean"}]},"executable":{"type":"string","enum":["any","include","exclude"]},"copy_on_write":{"type":"string","enum":["any","include","exclude"]},"mem_private":{"type":"boolean"},"mem_image":{"type":"boolean"},"mem_mapped":{"type":"boolean"},"read_only":{"type":"boolean"},"no_exec":{"type":"boolean"},"threads":{"type":"integer","minimum":0,"maximum":64},"chunk_bytes":{"type":"integer","minimum":1},"max_results":{"type":"integer","minimum":1},"prot":{"type":"integer"},"target":{"type":"integer"},"depth":{"type":"integer"},"min_offset":{"type":"integer"},"max_offset":{"type":"integer"},"alignment":{"type":"integer"},"static_roots":{"type":"boolean"},"frontier_cap":{"type":"integer","minimum":1},"max_bytes":{"type":"integer"},"a":{"type":"integer"},"b":{"type":"integer"},"id":{"type":"integer"},"all":{"type":"boolean"},"limit":{"type":"integer"},"label":{"type":"string"},"freeze":{"type":"boolean"}},"required":["action"]})";
    const char* disasm_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["assemble","disassemble","loaded","pe","functions","xrefs","strings","symbols","symbol_set","blocks","globals","vtables","load","unload","analyze_stop"]},"addr":{"type":"integer"},"va":{"type":"integer"},"address":{"type":"integer"},"count":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer"},"name":{"type":"string"},"text":{"type":"string"},"limit":{"type":"integer"},"min_chars":{"type":"integer"},"include_exec":{"type":"boolean"}},"required":["action"]})";
    const char* debugger_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["attach","detach","status","suspend_all","resume_all","bp_set","bp_clear","continue","step_into","step_over","step_out","wait_halt","regs","events","callstack","seh","set_register","watchpoint_set","watchpoint_clear","watchpoints","trace_run","ps4_attach","ps4_detach","ps4_status","ps4_bp_set","ps4_bp_clear","ps4_watch_set","ps4_watch_clear","ps4_continue","ps4_step","ps4_suspend","ps4_resume","ps4_process_stop","ps4_regs","ps4_set_reg","ps4_dbregs","ps4_wait","ps4_events","ps4_callstack","ps4_call","ps4_bp_list","ps4_watch_list","ps4_until","ps4_find_write","ps4_trace_calls","ps4_trace_steps","until"]},"pid":{"type":"integer"},"addr":{"type":"integer"},"hw":{"type":"boolean"},"type":{"type":"integer"},"len":{"type":"integer"},"timeout_ms":{"type":"integer"},"condition":{"type":"string"},"log":{"type":"string"},"auto_continue":{"type":"boolean"},"one_shot":{"type":"boolean"},"max_frames":{"type":"integer"},"name":{"type":"string"},"value":{"type":"integer"},"count":{"type":"integer"},"lwpid":{"type":"integer"},"index":{"type":"integer"},"stop":{"type":"integer"},"state":{"type":"integer"},"max":{"type":"integer"},"clear":{"type":"boolean"},"depth":{"type":"integer"},"args":{"type":"array","items":{}}},"required":["action"]})";
    const char* xray_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["cfg","complexity","cff","obfuscation","strings_recon","indirect_calls","anti_analysis","hooks","syscalls","apihash","entropy","pages","crypto_range","gadgets"]},"addr":{"type":"integer"},"va":{"type":"integer"},"address":{"type":"integer"},"size":{"type":"integer"},"len":{"type":"integer"},"length":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer"},"window_size":{"type":"integer"},"window":{"type":"integer"},"window_limit":{"type":"integer"},"page_size":{"type":"integer"},"max_functions":{"type":"integer"},"hash":{},"hashes":{"type":"array"},"algorithm":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* patch_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["nop_junk","resolve_opaque","patch_antidebug","unpack_xor","decode_strings","write_bytes","revert_all","journal","full_pass","rebuild"]},"addr":{"type":"integer"},"size":{"type":"integer"},"hex":{"type":"string"},"aggressive":{"type":"boolean"},"nop_threshold":{"type":"integer"},"dry_run":{"type":"boolean"},"method":{"type":"string"},"key_hex":{"type":"string"},"patch_api_calls":{"type":"boolean"},"patch_int_traps":{"type":"boolean"},"patch_timing":{"type":"boolean"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* devirt_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["themida_status","themida_start","themida_job","themida_cancel","identify","handlers","opcode_map","trace","lift","pseudocode","recover_cfg","prove_predicates","invariants","iat_audit"]},"addr":{"type":"integer"},"va":{"type":"integer"},"entry":{"type":"integer"},"start":{"type":"integer"},"address":{"type":"integer"},"path":{"type":"string"},"output_path":{"type":"string"},"timeout_ms":{"type":"integer","minimum":1000,"maximum":1800000},"overwrite":{"type":"boolean"},"load":{"type":"boolean"},"id":{"type":"integer","minimum":1},"runs":{"type":"integer"},"size":{"type":"integer"},"table":{"type":"integer"},"entry_size":{"type":"integer"},"stride":{"type":"integer"},"max_handlers":{"type":"integer"},"dispatcher":{"type":"integer"},"handler_table":{"type":"integer"},"handlers":{"type":"array"},"max_ops":{"type":"integer"}},"required":["action"]})";
    const char* types_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["declare","create_struct","get_struct","list_structs","add_member","remove_struct","create_enum","get_enum","list_enums","remove_enum","read_field","format_at"]},"name":{"type":"string"},"decl":{"type":"string"},"filter":{"type":"string"},"field":{"type":"string"},"type":{"type":"string"},"underlying":{"type":"string"},"values":{"type":"array"},"array_count":{"type":"integer"},"addr":{"type":"integer"},"live":{"type":"boolean"},"struct":{"type":"string"},"size":{"type":"integer"}},"required":["action"]})";
    const char* notes_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["set_comment","get_comment","comments","bookmark_toggle","bookmarks"]},"addr":{"type":"integer"},"text":{"type":"string"}},"required":["action"]})";
    const char* emulate_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"hex":{"type":"string"},"file_addr":{"type":"integer"},"target_addr":{"type":"integer"},"code_len":{"type":"integer","minimum":1,"maximum":1048576},"base":{"type":"integer"},"entry":{"type":"integer"},"stack_base":{"type":"integer"},"stack_size":{"type":"integer","minimum":4096,"maximum":67108864},"sp":{"type":"integer"},"regs":{"type":"object"},"maps":{"type":"array"},"until":{"type":"integer"},"count":{"type":"integer"},"timeout_ms":{"type":"integer","minimum":1,"maximum":30000},"trace":{"type":"boolean"},"trace_max":{"type":"integer","minimum":0,"maximum":16384},"taint":{"type":"array"},"watch_addr":{"type":"integer"},"watch_len":{"type":"integer","minimum":0,"maximum":1048576},"page_in":{"type":"boolean"},"stub_imports":{"type":"boolean"},"api_ret":{"type":["integer","string"]},"api_returns":{"type":"object","additionalProperties":{"type":["integer","string"]}},"dump":{"type":"array","items":{"type":"object","properties":{"addr":{"type":"integer"},"len":{"type":"integer","minimum":1,"maximum":1048576}},"required":["addr","len"]}}},"required":["action"]})";
    const char* analyze_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["packer","signatures","diff","diff_start","diff_job","diff_cancel"]},"path":{"type":"string"},"path_a":{"type":"string"},"path_b":{"type":"string"},"limit":{"type":"integer"},"timeout_ms":{"type":"integer"},"max_pairs":{"type":"integer"},"id":{"type":"integer"}},"required":["action"]})";
    const char* network_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["status","capture_start","capture_stop","packets","dns","rules_add","rules_remove","rules_clear","stats","export_pcap","streams","stream_data","inject","mod_rule_add","mod_rule_remove","mod_rules_list","redirect_add","redirect_remove","redirect_rules_list","dns_spoof_add","dns_spoof_remove","dns_spoof_list","kill_conn","intercept_start","intercept_stop","intercept_list","intercept_release","bw_start","bw_stop","bw_stats","bw_processes","fingerprint_run","fingerprint_results","reassemble_stream","connections","deep_inspect","wfp_callouts","socket_handles","tcpip_dump","interfaces","block_ip","block_port","block_process"]},"pid":{"type":"integer"},"port":{"type":"integer"},"protocol":{"type":"integer"},"from":{"type":"integer"},"filter":{"type":"string"},"limit":{"type":"integer"},"rule_id":{"type":"integer"},"direction":{"type":["integer","string"]},"path":{"type":"string"},"max_packets":{"type":"integer"},"id":{"type":"integer"},"offset":{"type":"integer"},"len":{"type":"integer"},"payload_hex":{"type":"string"},"pattern_hex":{"type":"string"},"replacement_hex":{"type":"string"},"src_ip":{"type":"string"},"dst_ip":{"type":"string"},"match_ip":{"type":"string"},"redirect_ip":{"type":"string"},"ip":{"type":"string"},"domain":{"type":"string"},"ttl":{"type":"integer"},"hold_id":{"type":"integer"},"exclude_pid":{"type":"integer"},"window_ms":{"type":"integer"},"src_port":{"type":"integer"},"dst_port":{"type":"integer"},"module":{"type":"string"}},"required":["action"]})";
    const char* proxy_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status","entries","entry","replay"]},"port":{"type":"integer"},"limit":{"type":"integer"},"id":{"type":"integer"}},"required":["action"]})";
    const char* persist_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["save","list","load","delete","kv_set","kv_get","hype_save","hype_load"]},"name":{"type":"string"},"data":{},"id":{"type":"integer"},"key":{"type":"string"},"value":{},"dir":{"type":"string"}},"required":["action"]})";
    const char* re_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["rtti_scan","vftable","danger","libsig"]},"path":{"type":"string"},"base":{"type":"integer"},"addr":{"type":"integer"},"slots":{"type":"integer"},"sigset":{"type":"string"},"filter":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* script_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"code":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["action"]})";
    const char* decomp_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["function"]},"addr":{"type":"integer"},"annotate_bytes":{"type":"boolean"}},"required":["action"]})";
    const char* fs_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["read_file","write_file","list_directory","create_directory","delete_path","search_files","grep_in_files"]},"path":{"type":"string"},"hex":{"type":"string"},"text":{"type":"string"},"append":{"type":"boolean"},"root":{"type":"string"},"needle":{"type":"string"},"suffix":{"type":"string"},"limit":{"type":"integer"},"max_bytes":{"type":"integer"}},"required":["action"]})";
    const char* web_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["fetch","post"]},"url":{"type":"string"},"body":{"type":"string"},"content_type":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["action"]})";

    out.push_back({{"name", "target"},
                   {"description", "Select and inspect the live process used by memory, debugger, and other runtime tools. Start with action='status' to read the active backend plus attached-target and shared-image context; use action='list' to find a pid, then action='attach' with pid. Attach uses the kernel DTB path when slopdrvr is active and best-effort loads the process's main module from disk at its runtime base, unless the UI already has a binary loaded. dump_module selects a loaded module by base or exact name, reconstructs a conventional PE from its mapped bytes to output path, and optionally load=true opens it in the shared Hyperion analysis session. strict defaults true; false zero-fills unreadable section spans and reports complete=false. Actions modules, dump_module, threads, regions, and handles require an attached target. Detach clears the live target but does not unload a separately UI-loaded image. Remote consoles: ps4_connect {host, port=744, pid?} connects to a PS4 running ps4debug-NG and makes the console the active target (list/attach/memory/regions/threads then go over the wire); ps4_disconnect drops it. ps4_auto {host} is the one-call setup: it connects, auto-picks the game process (the one with /app0/ modules), attaches, debug-attaches via the debugger, and returns modules/threads. On a PS4 the backend badge reads PS4 and PS4 modules are ELF/SELF, so dump_module/load are PE-only - analyze live addresses instead."},
                   {"inputSchema", json::parse(target_schema)}, {"read_only", false}});
    out.push_back({{"name", "memory"},
                   {"description", "Read, search, compare, and modify memory in the process attached by target. Most actions require target.status attached=true; the active user/kernel backend is chosen automatically. Core actions: read/write bytes, protect/alloc/free pages, AOB pattern search, pointer scan, signature generation, and live crypto-constant search. CE-style scan creates per-PID scan state; follow it with rescan, inspect it with scan_state, and release it with scan_reset. snapshot returns an id; compare two ids with diff using a and b, list with snapshots, and release with snapshot_free. Scan filters cover numeric width/comparison/rounding, region type and protection, address bounds, alignment/tail, workers, chunks, and result caps. Kernel mode uses slopdrvr DTB reads and driver region enumeration."},
                   {"inputSchema", json::parse(memory_schema)}, {"read_only", false}});
    out.push_back({{"name", "disasm"},
                   {"description", "Primary static-analysis and instruction tool for the shared binary session. Call action='loaded' first: image.ready means a PE, Mach-O (thin/FAT), or .ipa executable is loaded; image.format/arch describe its code, and encrypted/warning identify FairPlay-encrypted code that must be decrypted before analysis. image.hype.ready means background Hyperion analysis is complete; image.hype.progress/error explain pending or failed analysis. Use load(path) for PE, Mach-O (thin/FAT), or .ipa and unload to manage the same session as the UI, and analyze_stop to cancel analysis. pe/strings support the shared image or an explicit path; functions/xrefs with path support x86/x64 only, so load ARM images first. symbols use the shared image; blocks/globals/vtables require hype.ready. disassemble reads attached-process memory first and otherwise decodes the loaded file's architecture. assemble converts x86/x64 text to bytes. symbol_set renames a VA persistently (empty name clears) and updates the UI. Strings paginate with limit and omit executable sections unless include_exec=true. Runtime-base loads make static and live VAs directly comparable."},
                   {"inputSchema", json::parse(disasm_schema)}, {"read_only", false}});
    out.push_back({{"name", "debugger"},
                   {"description", "Control a live debugging session. Call status first; attach(pid) starts kernel-stealth VEH debugging when slopdrvr is available, otherwise the classic Win32 debug loop. Set software or hardware breakpoints with bp_set(addr, hw); optional condition, log, auto_continue, and one_shot fields create conditional stops or tracepoints. After continue or a step action, use wait_halt(timeout_ms), then inspect regs, events, callstack, or seh; set_register mutates paused state. watchpoint_set/clear/list manage page-guard access watches, and trace_run records a bounded instruction trace. suspend_all/resume_all freeze or thaw target threads. Hardware DR0-DR3 breakpoints and handle-free thread control require the driver. On a PS4 console (target.ps4_connect), the ps4_* actions drive the console's ps4debug-NG debug session live instead: ps4_attach {pid} attaches the payload's debugger, ps4_bp_set/ps4_bp_clear arm software INT3 breakpoints (index auto-allocated 0-29), ps4_watch_set/ps4_watch_clear arm hardware DR watchpoints (type 0=exec 1=write 3=rdwr, len 1/2/4/8), ps4_continue {stop} resumes (stop 0=resume 1=SIGSTOP 2=SIGKILL), ps4_step {lwpid?} single-steps, ps4_suspend/ps4_resume freeze one thread, ps4_process_stop {state} signals the process, ps4_regs/ps4_set_reg/ps4_dbregs read or write register state, ps4_wait {timeout_ms} blocks for the next stop event on the console's port-755 stream (breakpoint hit, watchpoint hit, step, signal; signal 9 tears the session down) and ps4_events drains the queued ones, ps4_callstack {lwpid, depth} walks the rbp frame chain through live memory reads, and ps4_call {addr, args[6]} installs the payload's rpc stub (once per pid) and calls an arbitrary address in the console process returning rax. One-call power actions: until {addr} (local: temp bp + go + wait_halt + clear) and ps4_until {addr} do the same on the console; ps4_find_write {addr, len} arms a write watchpoint and returns the stop event plus the writer's callstack; ps4_trace_calls {addr, count} logs rdi/rsi/rdx/rcx/r8/r9 at every breakpoint hit; ps4_trace_steps {lwpid, count} single-steps and disassembles each rip; ps4_bp_list/ps4_watch_list show the armed slots. For whole workflows (find health, damage source, API trace, unpacking), call guide: guide list / guide get {topic}."},
                   {"inputSchema", json::parse(debugger_schema)}, {"read_only", false}});
    out.push_back({{"name", "xray"},
                   {"description", "Run focused read-only static-analysis queries on the shared image or an explicit PE, Mach-O, or .ipa path. entropy and apihash are architecture-neutral; all other actions require x86/x64, and Windows syscalls/anti_analysis require PE. For cfg, complexity, cff, obfuscation, strings_recon, indirect_calls, and anti_analysis, pass addr as a function-start VA; known functions use indexed bounds and unknown addresses fall back to linear decode. Whole-image actions detect hooks, direct syscalls and SSNs, imported-API hashes, entropy windows, page classes, crypto constants (including instruction immediates), and ROP gadgets. For raw crypto constants on ARM use analyze.signatures. apihash only searches imports of this image, including bare API and 'DLL!API' forms; it is not a global hash dictionary. Use disasm.loaded/functions first to establish image state and valid function VAs."},
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
                   {"description", "Emulate x86-64 code in an isolated Unicorn VM. action='run' accepts exactly one practical code source: hex bytes, file_addr from the shared image, or target_addr from attached-process memory; code_len sets the initial slice. With file_addr/target_addr, page_in (default true) maps any other page the code touches from that same source on first use (image sections inside SizeOfImage with base relocations applied when the image is rebased, or live process memory; up to 16 MiB), so calls, jumps and global loads outside the slice keep running; hex runs map only the code and maps. With file_addr on a PE32+ image, stub_imports (default true) points every IAT slot at a stub that returns api_ret (default 0) in rax and logs api_calls (caller ip, return address, import name, rcx/rdx/r8/r9); api_returns={\"InitializeCriticalSectionAndSpinCount\":1,\"kernel32.dll!CreateFileW\":-1} overrides it per import (case-insensitive, unmatched keys come back in api_returns_unmatched). A zeroed TEB/PEB sits at gs_base (self, PEB, stack bounds, ImageBaseAddress; BeingDebugged=0) unless regs sets gs_base. Set base/entry, registers (rax..r15, rip, rflags, fs_base, gs_base), stack, and extra maps as needed. dump=[{addr,len}] (<= 1 MiB total) returns final memory as hex in memory; writes log ip/addr/len/value. Stop with until, count (default 100000), or timeout_ms (default 5000, capped at 30000); MCP notifications/cancelled stops a run early with stopped_reason='cancelled'. Runs do not block other tools. trace enables bounded instruction history (trace_max <= 16384); taint entries mark source byte ranges (<= 1 MiB total), and watch_addr/watch_len selects the output window for byte-granular propagation results. Emulation does not modify the loaded image or live target."},
                   {"inputSchema", json::parse(emulate_schema)}, {"read_only", true}});
    out.push_back({{"name", "guide"},
                   {"description", "Task-oriented playbooks for game reverse engineering: action='list' enumerates topics, action='get' {topic} returns the exact ordered tool-call sequence (tool, action, params, why) for that workflow — PS4 setup/breakpoints/API tracing/find-writes/step traces/remote calls, Cheat-Engine style value finding, damage-source hunting, pointer chains, runtime string decryption, local API monitoring, snapshot diffs, emulation, control-flow recovery, unpacking, and hardware breakpoints. Call it whenever you are unsure which tools to combine for a task."},
                   {"inputSchema", json::parse(R"({"type":"object","properties":{"action":{"type":"string","enum":["list","get"]},"topic":{"type":"string"}},"required":["action"]})")}, {"read_only", true}});
    out.push_back({{"name", "analyze"},
                   {"description", "Run whole-binary read-only analysis. packer uses the shared image or path and reports protector names, entry signatures, entropy, import anomalies, W+X sections, TLS, overlay, crypto constants, and the shared Hyperion verdict when available. signatures requires the analyzed shared session and returns analyzer-derived names in named_functions; names may come from RTTI, vtables, thunks, or signature candidates and are not provenance-verified as FLIRT. diff(path_a,path_b) performs two full Hyperion analyses and reports added, removed, and modified functions with similarity scores, so expect a longer call; for huge binaries use async diff_start(path_a,path_b) then poll diff_job(id) for stage/progress and stop with diff_cancel(id). Check disasm.loaded before shared-session actions."},
                   {"inputSchema", json::parse(analyze_schema)}, {"read_only", true}});
    out.push_back({{"name", "network"},
                   {"description", "Capture, query, and manipulate Windows network traffic through slopdrvr/WFP. Call status first. A common read flow is capture_start -> packets/dns/streams/stats -> capture_stop; packets filter syntax includes port=80;host:1.2.3.4;text:foo;pid:1234;proto:tcp, and stream_data reads payload by id/offset/len. Mutation actions cover WFP rules, injection, pattern replacement, redirects, DNS spoofing, connection kill, hold/modify/release interception, bandwidth controls, and block_ip/block_port/block_process (direction in|out|both, default both). System inspection includes connections, DPI, callouts, socket handles, TCB dump, interfaces, fingerprints, and reassembly. Driver-dependent actions return structured errors when slopdrvr is unavailable."},
                   {"inputSchema", json::parse(network_schema)}, {"read_only", false}});
    out.push_back({{"name", "proxy"},
                   {"description", "Run the built-in localhost HTTP/1.1 inspection proxy. Use start(port) -> status -> entries(limit); fetch one captured exchange with entry(id), and replay a logged plain-HTTP request with replay(id). CONNECT tunnels record SNI and metadata but encrypted tunnel bodies are not decrypted, so replay applies only to captured plain HTTP. stop releases the listener. This proxy is independent of the kernel network capture tool."},
                   {"inputSchema", json::parse(proxy_schema)}, {"read_only", false}});
    out.push_back({{"name", "persist"},
                   {"description", "Persist agent or analysis state in the app database. save(name,data) stores an arbitrary JSON session snapshot and returns an id; list discovers snapshots, load(id) retrieves one, and delete(id) removes it. kv_set/kv_get store small named values such as layouts. hype_save(dir) writes the current Hyperion project as a .hdb directory; hype_load(dir) merges names and comments into the live shared image, but does not merge xrefs or types. Persistence does not automatically restore a process attachment or debugger session."},
                   {"inputSchema", json::parse(persist_schema)}, {"read_only", false}});
    out.push_back({{"name", "re"},
                    {"description", "Run read-only reverse-engineering reconnaissance on the shared image or an explicit path. rtti_scan prefers completed Hyperion analysis and returns demangled MSVC classes, vtables, and methods; otherwise it falls back to a quick TypeDescriptor scan. rtti_scan accepts filter (case-insensitive substring over class names) and limit (default 500) with total/truncated. vftable(addr,slots) reads virtual-function entries and uses Hyperion metadata when addr is an indexed vtable. danger finds callsites to security-sensitive imports using Hyperion xrefs for the shared session or the legacy index for explicit paths. libsig(path,sigset) identifies libraries from a JSON byte-signature set. Check disasm.loaded and wait for hype.ready for richest results."},
                   {"inputSchema", json::parse(re_schema)}, {"read_only", true}});
    out.push_back({{"name", "decomp"},
                   {"description", "Decompile one function from the shared image. Prerequisite: call disasm.loaded and wait for image.hype.ready=true, then obtain a function-start addr from disasm.functions. action='function' returns structured C, per-line VA mappings, reconstructed stack variables, and a recovered signature after p-code lifting, SSA, optimization, type inference, and control-flow structuring. Naming priority is user symbol, Hyperion name, then sub_<rva>; RTTI and recognized STL types may appear in output. Set annotate_bytes=true to prefix emitted lines with source VAs. This tool does not accept an explicit path; load the binary first."},
                   {"inputSchema", json::parse(decomp_schema)}, {"read_only", true}});
    out.push_back({{"name", "fs"},
                   {"description", "Access the Windows host filesystem, not target-process memory. read_file(path,max_bytes) returns file content; write_file(path,text|hex,append) creates or updates a file. list_directory and create_directory operate on path, while delete_path removes a file or directory. search_files(root,needle,suffix,limit) finds names and grep_in_files(root,needle,suffix,limit) searches text content. Use absolute paths when context matters and apply max_bytes/limit to bound large results."},
                   {"inputSchema", json::parse(fs_schema)}, {"read_only", false}});
    out.push_back({{"name", "web"},
                   {"description", "Make outbound HTTP(S) requests from the host through WinHTTP. fetch(url,timeout_ms) performs GET; post(url,body,content_type,timeout_ms) performs POST. Results include response status/body or a structured transport error. Use this for symbol downloads, API queries, and target-related lookups; it is unrelated to captured traffic in network or proxy and does not inherit browser cookies."},
                   {"inputSchema", json::parse(web_schema)}, {"read_only", false}});
    out.push_back({{"name", "script"},
                   {"description", "Run a Lua 5.4 automation script inside reverse-slop, the scripting layer over static analysis, like IDAPython for IDA. action='run' requires code; timeout_ms defaults to 5000 and is capped at 60000 (pass a higher timeout_ms when waiting for analysis). print() output is captured and returned values are serialized as 'return: <value>'. Scripts operate on the SAME shared binary session as the UI and every other MCP tool, so loads, renames, and comments are visible everywhere. Static-analysis API: slop.image.{load(path[,base]),load_from_target,unload,status,wait_ready([ms])}; slop.disasm.{decode(addr[,n]),functions([limit]),function_at(va),xrefs_to(va),strings([min_len[,limit]]) -- note min-length FIRST, so strings(4,3000) not strings(2000),pe(),bytes(addr[,len]),name(va),set_name(va,name),comment(va),set_comment(va,text),bookmark_toggle(va),bookmarks()}; slop.decomp.{decompile(va),blocks(va),vtables(),globals(),rtti()} (decomp.* needs slop.image.wait_ready first). Live analysis: slop.target.{list,attach,status}, slop.mem.{read_hex,write_hex,scan}, slop.disasm.disassemble(addr,count), slop.analyze.packer. Typical flow: image.load(path) -> image.wait_ready() -> disasm.functions() -> decomp.decompile(va). Use direct MCP tools when one operation is sufficient."},
                   {"inputSchema", json::parse(script_schema)}, {"read_only", false}});

}

nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel) {
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
        else if (name == "script")   out = tool_script(args);
        else if (name == "decomp")   out = tool_decomp(args);
        else if (name == "fs")       out = tool_fs(args);
        else if (name == "web")      out = tool_web(args);
        else if (name == "xray")     out = tool_xray(args);
        else if (name == "patch")    out = tool_patch(args);
        else if (name == "types")    out = tool_types(args);
        else if (name == "notes")    out = tool_notes(args);
        else if (name == "devirt")   out = tool_devirt(args);
        else if (name == "guide")    out = tool_guide(args);
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

void shutdown_tools() {
    std::lock_guard lk(g_tool_mu);
    std::lock_guard ilk(g_image_mu);
    g_proxy.stop();
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








