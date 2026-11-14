// src/core/mcp/tools_common.cpp
// shared state and helpers for the tool handlers

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

std::mutex g_tool_mu;
std::mutex g_image_mu;

std::mutex& tool_mutex() { return g_tool_mu; }

scan_state_t                g_scan;
image_cache_t               g_image;
std::vector<mcp_snapshot_t> g_snaps;
uint64_t                    g_snap_next_id = 1;
network::traffic_store_t    g_traffic;
network::http_proxy_t       g_proxy;

namespace {

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

} // namespace


// helpers

[[noreturn]] void fail(std::string msg) { throw std::runtime_error(std::move(msg)); }

void require_x86_image(disasm::image_arch_t arch, disasm::image_format_t format,
                       std::string_view action, bool path_image) {
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
                      std::string_view action, bool path_image) {
    if (format == disasm::image_format_t::pe) return;
    fail(fmt::format("{} requires a PE image; the {} image is {} ({})",
                     action, path_image ? "'path'" : "loaded",
                     disasm::image_arch_name(arch), disasm::image_format_name(format)));
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


std::shared_ptr<runtime::session_t> need_session() {
    auto s = process::active_session();
    if (!s || !s->valid()) fail("no target attached (use target.attach first)");
    return s;
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

std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string err;
    if (!infra::fmt::parse_hex(hex, out, err)) fail("bad hex payload: " + err);
    return out;
}

std::string to_hex(const uint8_t* data, size_t len) {
    return infra::fmt::format_hex_packed({data, len});
}

std::string hex64(uint64_t v) {
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string addr_hex_str(uint64_t v) {
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
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
        hype["managed"]   = bin.hype->is_dotnet();
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

std::optional<progress_sample_t> sample_progress(const std::string& tool,
                                                 const std::string& action,
                                                 int64_t elapsed_ms) {
    // memory scans expose a live byte/hit counter
    if (tool == "memory" && (action == "scan" || action == "rescan")) {
        const auto& p = g_scan.engine.progress();
        const uint64_t bytes = p.bytes.load(std::memory_order_relaxed);
        const uint64_t found = p.found.load(std::memory_order_relaxed);
        return progress_sample_t{static_cast<double>(bytes), std::nullopt,
                                 "scanned " + std::to_string(bytes) + " bytes, " +
                                     std::to_string(found) + " hits"};
    }
    // hyperion analysis has a 0..1 fraction
    if (tool == "disasm" && action == "loaded") {
        const double pct = static_cast<double>(ds::hype_progress()) * 100.0;
        return progress_sample_t{pct, 100.0,
                                 "hyperion analysis " + std::to_string(static_cast<int>(pct)) + "%"};
    }
    // no live counter: report elapsed time so a long call still proves liveness
    static const std::unordered_set<std::string> kLong = {
        "memory.pointerscan",   "memory.pointerscan_verify", "emulate.run",
        "devirt.themida_start", "devirt.themida_job",        "analyze.diff",
        "analyze.diff_start",   "disasm.load",               "script.run",
        "patch.full_pass",      "re.rtti_scan",              "fs.grep_in_files",
        "fs.search_files",      "network.reassemble_stream",
    };
    if (kLong.count(tool + "." + action) == 0) return std::nullopt;
    const double secs = static_cast<double>(elapsed_ms) / 1000.0;
    return progress_sample_t{static_cast<double>(elapsed_ms), std::nullopt,
                             tool + "." + action + " running (" +
                                 std::to_string(static_cast<int>(secs)) + "s)"};
}

} // namespace slop::core::mcp::detail
