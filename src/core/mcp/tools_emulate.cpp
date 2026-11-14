// src/core/mcp/tools_emulate.cpp
// tool: emulate (unicorn emulation over the loaded image / target)

#include "core/mcp/tools_common.hpp"

#include "core/analysis/ps4_syscalls.hpp"

#include <memory>
#include <mutex>

namespace slop::core::mcp::detail {

namespace {

struct image_view_t {
    struct reloc_t { uint32_t rva = 0; uint8_t width = 0; };   // width 4 | 8

    uint64_t hash   = 0;
    uint64_t extent = 0;            // SizeOfImage, or the section span
    uint64_t delta  = 0;            // session base - ImageBase, mod 2^64
    std::vector<reloc_t> relocs;    // sorted by rva, empty when not rebased

    // Raw mapped bytes for [rva, rva + len), no relocation. Caller holds
    // the state mutex
    static void copy_mapped(const ds::binary_t& bin, uint64_t rva, size_t len, uint8_t* out) {
        std::memset(out, 0, len);
        const uint64_t end = rva + len;
        if (bin.format == disasm::image_format_t::pe) {
            uint64_t headers = emu::kPageSize;
            for (const auto& s : bin.pe.sections)
                if (s.raw_size) headers = std::min<uint64_t>(headers, s.raw_offset);
            headers = std::min<uint64_t>(headers, bin.file.size());
            if (rva < headers)
                std::memcpy(out, bin.file.data() + rva,
                            static_cast<size_t>(std::min(end, headers) - rva));
        }
        for (const auto& s : bin.pe.sections) {
            // file bytes past VirtualSize are not mapped by the loader
            const uint64_t backed = std::min<uint64_t>(
                s.virtual_size ? s.virtual_size : s.raw_size, s.raw_size);
            const uint64_t lo = std::max<uint64_t>(rva, s.rva);
            const uint64_t hi = std::min<uint64_t>(end, s.rva + backed);
            if (lo >= hi) continue;
            const uint64_t off = uint64_t{s.raw_offset} + (lo - s.rva);
            if (off >= bin.file.size()) continue;
            const uint64_t n = std::min<uint64_t>(hi - lo, bin.file.size() - off);
            std::memcpy(out + (lo - rva), bin.file.data() + off, static_cast<size_t>(n));
        }
    }

    // Caller holds the state mutex
    static std::shared_ptr<const image_view_t> make(const ds::binary_t& bin) {
        auto v = std::make_shared<image_view_t>();
        v->hash   = bin.file_hash;
        v->extent = bin.pe.size_of_image;
        if (!v->extent)
            for (const auto& s : bin.pe.sections)
                v->extent = std::max<uint64_t>(
                    v->extent, uint64_t{s.rva} + (s.virtual_size ? s.virtual_size : s.raw_size));
        v->delta = bin.base - bin.pe.image_base;

        // IMAGE_DIRECTORY_ENTRY_BASERELOC: blocks of {page rva, size, u16
        // entries}, type in the top 4 bits (3 HIGHLOW, 10 DIR64)
        const auto& dir = bin.pe.data_dirs[5];
        if (v->delta == 0 || bin.format != disasm::image_format_t::pe ||
            !dir.rva || !dir.size || dir.size > (64u << 20))
            return v;
        std::vector<uint8_t> raw(dir.size);
        copy_mapped(bin, dir.rva, raw.size(), raw.data());
        for (size_t pos = 0; pos + 8 <= raw.size();) {
            uint32_t page = 0, block = 0;
            std::memcpy(&page, raw.data() + pos, 4);
            std::memcpy(&block, raw.data() + pos + 4, 4);
            if (block < 8 || block > raw.size() - pos) break;
            for (size_t e = pos + 8; e + 2 <= pos + block; e += 2) {
                uint16_t entry = 0;
                std::memcpy(&entry, raw.data() + e, 2);
                const uint32_t at = page + (entry & 0xFFFu);
                if ((entry >> 12) == 10)     v->relocs.push_back({at, 8});
                else if ((entry >> 12) == 3) v->relocs.push_back({at, 4});
            }
            pos += block;
        }
        std::sort(v->relocs.begin(), v->relocs.end(),
                  [](const reloc_t& a, const reloc_t& b) { return a.rva < b.rva; });
        return v;
    }

    // Relocated mapped bytes for [rva, rva + len). Caller holds the state mutex
    void read(const ds::binary_t& bin, uint64_t rva, size_t len, uint8_t* out) const {
        copy_mapped(bin, rva, len, out);
        if (relocs.empty()) return;
        // a fixup starting up to 7 bytes before the range still reaches into it
        const uint64_t from = rva >= 7 ? rva - 7 : 0;
        auto it = std::lower_bound(relocs.begin(), relocs.end(), from,
                                   [](const reloc_t& r, uint64_t a) { return r.rva < a; });
        for (; it != relocs.end() && it->rva < rva + len; ++it) {
            uint8_t v[8] = {};
            copy_mapped(bin, it->rva, it->width, v);
            if (it->width == 8) {
                uint64_t x = 0;
                std::memcpy(&x, v, 8);
                x += delta;
                std::memcpy(v, &x, 8);
            } else {
                uint32_t x = 0;
                std::memcpy(&x, v, 4);
                x += static_cast<uint32_t>(delta);
                std::memcpy(v, &x, 4);
            }
            for (uint8_t i = 0; i < it->width; ++i) {
                const uint64_t at = uint64_t{it->rva} + i;
                if (at >= rva && at < rva + len) out[at - rva] = v[i];
            }
        }
    }
};

// Demand pages over the shared image. The run is off every tool lock, so
// each page is copied under the state mutex and the source goes dry once
// another image replaces this one

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

// IAT slots of a PE32+ image, or the GOT / pointer slots the ELF and Mach-O
// loaders report for their imports; the stub mechanism is format agnostic
// and works for x86-64 and arm64 (the stub RET is arch specific)
std::vector<emu::import_slot_t> image_import_slots(const ds::binary_t& bin,
                                                   std::map<std::string, uint64_t>& returns) {
    std::vector<emu::import_slot_t> out;
    if (bin.arch != disasm::image_arch_t::x64 && bin.arch != disasm::image_arch_t::arm64)
        return out;
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

// "x64" | "x86_64" | "amd64" | "arm64" | "aarch64"; nullopt means derive
std::optional<emu::arch_t> requested_arch(const json& args) {
    const auto it = args.find("arch");
    if (it == args.end() || it->is_null()) return std::nullopt;
    if (!it->is_string()) fail("arch must be \"x64\" or \"arm64\"");
    const std::string a = lower_ascii(it->get<std::string>());
    if (a == "x64" || a == "x86_64" || a == "amd64") return emu::arch_t::x86_64;
    if (a == "arm64" || a == "aarch64") return emu::arch_t::arm64;
    fail("arch must be \"x64\" or \"arm64\"");
}

void require_image_arch(const ds::binary_t& bin, emu::arch_t arch) {
    const auto want = arch == emu::arch_t::arm64 ? disasm::image_arch_t::arm64
                                                 : disasm::image_arch_t::x64;
    if (bin.arch == want) return;
    fail(std::string("emulate executes ") +
         (arch == emu::arch_t::arm64 ? "arm64" : "x86-64") +
         " code only; the loaded image is " + disasm::image_arch_name(bin.arch) +
         " (" + disasm::image_format_name(bin.format) + ")");
}

void require_x64_target(runtime::session_t& s) {
    // a ps4 console is always x86-64 (AMD Jaguar)
    if (runtime::active_kind() == runtime::backend_kind_t::ps4) return;
    runtime::arch_t a = s.arch();
    if (a == runtime::arch_t::unknown) a = runtime::active().query_arch(s.handle());
    if (a == runtime::arch_t::x64) return;
    fail(std::string("emulate.run executes x86-64 code only; the attached target is ") +
         (a == runtime::arch_t::x86 ? "a 32-bit x86 process" : "of unknown architecture"));
}

bool is_sysv_format(disasm::image_format_t f) {
    return f == disasm::image_format_t::elf || f == disasm::image_format_t::self ||
           f == disasm::image_format_t::macho;
}

// PS4 environments name their syscalls from the Orbis table; Mach-O is SysV
// too but its syscall numbers are Darwin's
bool is_ps4_format(disasm::image_format_t f) {
    return f == disasm::image_format_t::elf || f == disasm::image_format_t::self;
}

// "auto" | "win64" | "sysv"; nullopt means auto
std::optional<emu::abi_t> requested_abi(const json& args) {
    const auto it = args.find("abi");
    if (it == args.end() || it->is_null()) return std::nullopt;
    if (!it->is_string()) fail("abi must be \"auto\", \"win64\" or \"sysv\"");
    const std::string a = lower_ascii(it->get<std::string>());
    if (a == "auto") return std::nullopt;
    if (a == "win64" || a == "windows" || a == "ms") return emu::abi_t::win64;
    if (a == "sysv" || a == "systemv" || a == "freebsd" || a == "ps4") return emu::abi_t::sysv;
    fail("abi must be \"auto\", \"win64\" or \"sysv\"");
}

// syscall_returns keys: a number (decimal or 0x hex) or a PS4 syscall name
// (with or without the sys_ prefix)
uint64_t syscall_number_key(const std::string& key) {
    if (!key.empty() && std::isdigit(static_cast<unsigned char>(key[0]))) {
        char* end = nullptr;
        const uint64_t n = std::strtoull(key.c_str(), &end, 0);
        if (end && *end == '\0') return n;
    }
    std::string name = lower_ascii(key);
    if (name.rfind("sys_", 0) == 0) name.erase(0, 4);
    for (uint64_t n = 0; n < 4096; ++n) {
        const char* s = analysis::ps4_syscall_name(n);
        if (s && name == s) return n;
    }
    fail("syscall_returns: '" + key + "' is neither a number nor a PS4 syscall name");
}

const char* abi_label(const emu::run_request_t& req) {
    return req.arch == emu::arch_t::arm64 ? "aapcs64" : emu::abi_name(req.abi);
}

// === request building ======================================================
// Shared by emulate.run and emulate.session_create: everything that reads the
// shared image or the attached target happens under g_tool_mu, the run itself
// never does

struct parsed_request_t {
    emu::run_request_t req;
    bool ps4_env = false;
    std::vector<std::string> unmatched_api_returns;
};

parsed_request_t build_request(const json& args, infra::cancel_token_t cancel) {
    // Input bounds: these all run before unicorn's timer starts (stack commit,
    // per-byte taint marking, trace growth), so an unbounded value hangs the
    // request regardless of timeout_ms
    constexpr size_t   kMaxStackSize = 64u << 20;
    constexpr size_t   kMaxTaintLen  = 1u << 20;
    constexpr size_t   kMaxTraceMax  = 16384;
    constexpr size_t   kMaxDumpLen   = 1u << 20;

    parsed_request_t out;
    emu::run_request_t& req = out.req;
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

    const auto abi_req = requested_abi(args);
    const auto arch_req = requested_arch(args);
    emu::arch_t arch = arch_req.value_or(emu::arch_t::x86_64);
    emu::abi_t auto_abi = emu::abi_t::win64;
    bool ps4_env = false;   // name syscalls from the Orbis table

    // hex wins over file_addr wins over target_addr, code runs at its real va unless base says otherwise
    bool have_code = false;
    if (args.contains("hex") && args.at("hex").is_string()) {
        // raw bytes carry no architecture of their own; x64 unless arch says otherwise
        req.code = hex_decode(args.at("hex").get<std::string>());
        have_code = !req.code.empty();
        if (have_code && arch == emu::arch_t::x86_64) {
            // a console session or a loaded PS4/ELF image means PS4 code
            if (runtime::active_kind() == runtime::backend_kind_t::ps4) {
                auto_abi = emu::abi_t::sysv;
                ps4_env = true;
            } else {
                std::lock_guard lk(ds::state_mutex());
                const auto& bin = ds::get();
                if (bin.ready && is_sysv_format(bin.format)) {
                    auto_abi = emu::abi_t::sysv;
                    ps4_env = is_ps4_format(bin.format);
                }
            }
        }
    }
    if (!have_code && args.contains("file_addr")) {
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
        if (arch_req) arch = *arch_req;
        else arch = bin.arch == disasm::image_arch_t::arm64 ? emu::arch_t::arm64
                                                           : emu::arch_t::x86_64;
        require_image_arch(bin, arch);
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
        if (arch == emu::arch_t::x86_64 && is_sysv_format(bin.format))
            auto_abi = emu::abi_t::sysv;
        ps4_env = arch == emu::arch_t::x86_64 && is_ps4_format(bin.format);
        if (page_in) req.page_in = image_page_source(std::move(view));
        if (args.value("stub_imports", true))
            req.imports = image_import_slots(bin, api_returns);
        have_code = true;
    }
    if (!have_code && args.contains("target_addr")) {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached for target_addr");
        require_x64_target(*s);
        if (arch_req && *arch_req != emu::arch_t::x86_64)
            fail("emulate can only read x86-64 code from an attached target");
        arch = emu::arch_t::x86_64;
        if (runtime::active_kind() == runtime::backend_kind_t::ps4) {
            auto_abi = emu::abi_t::sysv;
            ps4_env = true;
        }
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

    req.arch = arch;
    req.abi = abi_req.value_or(auto_abi);
    if (req.arch == emu::arch_t::x86_64 && req.abi == emu::abi_t::sysv && (ps4_env || abi_req)) {
        // an explicit sysv run on a non-Mach-O source is treated as PS4 code
        const bool macho_image = [&] {
            if (!args.contains("file_addr") || args.contains("hex")) return false;
            std::lock_guard lk(ds::state_mutex());
            return ds::get().ready && ds::get().format == disasm::image_format_t::macho;
        }();
        if (!macho_image) req.syscall_name = analysis::ps4_syscall_name;
    }
    out.ps4_env = ps4_env;

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
    // a trace is the raw material of a backward slice, so record the bytes and
    // the memory reads with it; record_slice forces the trace on
    if (args.contains("record_slice") && args.value("record_slice", false)) {
        req.record_slice = true;
        req.trace = true;
    } else if (req.trace) {
        req.record_slice = true;
    }

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
    if (args.contains("syscall_ret"))
        req.syscall_ret = parse_api_value(args.at("syscall_ret"), "syscall_ret");
    if (auto it = args.find("syscall_returns"); it != args.end()) {
        if (!it->is_object())
            fail("syscall_returns must be an object of syscall number or name -> value");
        for (auto r = it->begin(); r != it->end(); ++r)
            req.syscall_returns[syscall_number_key(r.key())] = parse_api_value(r.value(), r.key());
    }
    // Orbis syscall emulation is opt-in: it serves the numbers that have no
    // explicit syscall_returns entry, so a fixed return still wins
    if (args.value("orbis_syscalls", false)) {
        if (req.arch != emu::arch_t::x86_64)
            fail("orbis_syscalls are x86-64 only");
        req.orbis_syscalls = true;
        if (args.contains("pid")) req.orbis.pid = parse_addr(args, "pid");
    }
    for (const auto& [key, value] : api_returns) out.unmatched_api_returns.push_back(key);
    return out;
}

// === trace store (for emulate.slice) ======================================

struct trace_store_t {
    std::mutex mu;
    std::map<uint64_t, emu::run_result_t> entries;
    uint64_t next = 1;
};

trace_store_t& trace_store() {
    static trace_store_t s;
    return s;
}

uint64_t store_trace(emu::run_result_t run) {
    auto& s = trace_store();
    std::lock_guard lk(s.mu);
    constexpr size_t kMaxTraces = 8;
    while (s.entries.size() >= kMaxTraces) s.entries.erase(s.entries.begin());
    const uint64_t id = s.next++;
    s.entries.emplace(id, std::move(run));
    return id;
}

// === persistent session store =============================================

struct session_store_t {
    std::mutex mu;
    std::map<uint64_t, std::shared_ptr<emu::emulation_session_t>> entries;
    uint64_t next = 1;
};

session_store_t& session_store() {
    static session_store_t s;
    return s;
}

constexpr size_t kMaxSessions = 8;

json regs_json(const std::map<std::string, uint64_t>& regs) {
    json out = json::object();
    for (const auto& [name, value] : regs) out[name] = value;
    return out;
}

json session_state_json(const emu::emulation_session_t& session) {
    const auto& r = session.state();
    json out = {{"ok", true},
                {"arch", emu::arch_name(session.arch())},
                {"instructions", r.instructions},
                {"regs", regs_json(r.regs)},
                {"snapshots", session.snapshot_count()}};
    if (!r.stopped_reason.empty()) out["stopped_reason"] = r.stopped_reason;
    if (!r.stdout_data.empty())
        out["stdout"] = std::string(r.stdout_data.begin(), r.stdout_data.end());
    if (r.syscall_enosys) out["syscall_enosys"] = r.syscall_enosys;
    if (r.exited) {
        out["exited"] = true;
        out["exit_code"] = r.exit_code;
    }
    return out;
}

} // namespace

json tool_emulate(const json& args, infra::cancel_token_t cancel) {
    const std::string action = require_action(args);

    // === run =================================================================
    if (action == "run") {
        auto parsed = build_request(args, cancel);
        const emu::run_request_t& req = parsed.req;

        auto r = emu::emulate_run(req);
        if (!r.ok && !r.error.empty()) fail(r.error);

        json out = {{"ok", r.ok},
                    {"stopped_reason", r.stopped_reason},
                    {"instructions", r.instructions},
                    {"arch", emu::arch_name(req.arch)},
                    {"abi", abi_label(req)}};
        if (r.teb_mapped) out["teb_mapped"] = true;
        if (r.tls_mapped) out["tls_mapped"] = true;
        if (!r.error.empty()) out["error"] = r.error;

        out["regs"] = regs_json(r.regs);

        if (!r.trace.empty()) {
            json arr = json::array();
            for (const auto& t : r.trace)
                arr.push_back({{"ip", t.ip}, {"text", t.text}});
            out["trace"] = arr;
        }
        {
            json arr = json::array();
            for (const auto& w : r.writes) {
                json e = {{"ip", w.ip}, {"addr", w.addr}, {"len", w.len}, {"value", w.value}};
                if (w.truncated) e["truncated"] = true;
                arr.push_back(std::move(e));
            }
            out["writes"] = arr;
            out["total_writes"] = r.total_writes;
        }
        if (!req.imports.empty()) {
            json arr = json::array();
            for (const auto& c : r.api_calls) {
                json a = json::array();
                for (uint8_t i = 0; i < c.arg_count; ++i) a.push_back(c.args[i]);
                arr.push_back({{"ip", c.ip}, {"ret", c.ret}, {"name", c.name}, {"args", std::move(a)}});
            }
            out["api_calls"]       = arr;
            out["total_api_calls"] = r.total_api_calls;
        }
        if (r.total_syscalls) {
            json arr = json::array();
            for (const auto& sc : r.syscalls) {
                json e = {{"ip", sc.ip}, {"num", sc.num}, {"ret", sc.ret},
                          {"args", json::array({sc.args[0], sc.args[1], sc.args[2],
                                                sc.args[3], sc.args[4], sc.args[5]})}};
                if (!sc.name.empty()) e["name"] = sc.name;
                if (sc.enosys) e["enosys"] = true;
                arr.push_back(std::move(e));
            }
            out["syscalls"]       = arr;
            out["total_syscalls"] = r.total_syscalls;
        }
        if (req.orbis_syscalls) {
            if (!r.stdout_data.empty())
                out["stdout"] = std::string(r.stdout_data.begin(), r.stdout_data.end());
            out["syscall_enosys"] = r.syscall_enosys;
            if (r.exited) {
                out["exited"] = true;
                out["exit_code"] = r.exit_code;
            }
        }
        if (!parsed.unmatched_api_returns.empty()) {
            json keys = json::array();
            for (const auto& key : parsed.unmatched_api_returns) keys.push_back(key);
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
        // a recorded trace stays addressable for emulate.slice
        if (req.trace && !r.trace.empty()) out["trace_id"] = store_trace(std::move(r));
        return out;
    }

    // === slice ===============================================================
    if (action == "slice") {
        const uint64_t id = parse_addr(args, "trace_id");
        emu::run_result_t run;
        {
            auto& s = trace_store();
            std::lock_guard lk(s.mu);
            const auto it = s.entries.find(id);
            if (it == s.entries.end())
                fail("unknown trace_id (run emulate.run with trace=true first; "
                     "the store keeps the last 8 traces)");
            run = it->second;
        }
        emu::slice_request_t sr;
        if (auto it = args.find("reg"); it != args.end() && it->is_string())
            sr.reg = it->get<std::string>();
        if (args.contains("addr")) sr.addr = parse_addr(args, "addr");
        if (args.contains("len"))  sr.len  = static_cast<size_t>(parse_addr(args, "len"));
        if (args.contains("at"))   sr.at   = parse_addr(args, "at");
        const auto r = emu::emulate_slice(run, sr);
        if (!r.ok) fail(r.error);
        json insns = json::array();
        for (const auto& i : r.insns)
            insns.push_back({{"ip", i.ip}, {"text", i.text}});
        return json{{"ok", true}, {"trace_id", id}, {"count", r.insns.size()},
                    {"instructions", std::move(insns)}};
    }

    // === persistent sessions ================================================
    if (action == "session_create") {
        auto parsed = build_request(args, cancel);
        std::string err;
        auto session = emu::emulation_session_t::create(parsed.req, &err);
        if (!session) fail(err.empty() ? "session create failed" : err);
        auto& store = session_store();
        std::lock_guard lk(store.mu);
        if (store.entries.size() >= kMaxSessions)
            fail("too many live sessions (max 8): destroy one first");
        const uint64_t id = store.next++;
        json out = session_state_json(*session);
        out["session"] = id;
        out["abi"] = abi_label(parsed.req);
        store.entries.emplace(id, std::move(session));
        return out;
    }

    if (action == "session_step" || action == "session_run") {
        const uint64_t id = parse_addr(args, "session");
        std::shared_ptr<emu::emulation_session_t> session;
        {
            auto& store = session_store();
            std::lock_guard lk(store.mu);
            const auto it = store.entries.find(id);
            if (it == store.entries.end()) fail("unknown session id");
            session = it->second;
        }
        const uint64_t count = args.contains("count")
            ? parse_addr(args, "count")
            : (action == "session_run" ? 0 : 1);
        const uint32_t timeout_ms = args.contains("timeout_ms")
            ? static_cast<uint32_t>(std::min<uint64_t>(parse_addr(args, "timeout_ms"),
                                                       emu::kMaxTimeoutMs))
            : (action == "session_run" ? 5000u : 1000u);
        std::string err;
        if (!session->step(count, timeout_ms, cancel, &err))
            fail(err.empty() ? "session step failed" : err);
        json out = session_state_json(*session);
        out["session"] = id;
        return out;
    }

    if (action == "session_destroy") {
        const uint64_t id = parse_addr(args, "session");
        auto& store = session_store();
        std::lock_guard lk(store.mu);
        if (!store.entries.erase(id)) fail("unknown session id");
        return json{{"ok", true}, {"session", id}, {"destroyed", true}};
    }

    if (action == "snapshot") {
        const uint64_t id = parse_addr(args, "session");
        std::shared_ptr<emu::emulation_session_t> session;
        {
            auto& store = session_store();
            std::lock_guard lk(store.mu);
            const auto it = store.entries.find(id);
            if (it == store.entries.end()) fail("unknown session id");
            session = it->second;
        }
        std::string err;
        if (!session->snapshot(&err)) fail(err);
        json out = session_state_json(*session);
        out["session"] = id;
        out["snapshot"] = session->snapshot_count();
        out["pages"] = session->snapshot_pages();
        return out;
    }

    if (action == "restore") {
        const uint64_t id = parse_addr(args, "session");
        std::shared_ptr<emu::emulation_session_t> session;
        {
            auto& store = session_store();
            std::lock_guard lk(store.mu);
            const auto it = store.entries.find(id);
            if (it == store.entries.end()) fail("unknown session id");
            session = it->second;
        }
        std::string err;
        if (!session->restore(&err)) fail(err);
        json out = session_state_json(*session);
        out["session"] = id;
        out["restored"] = true;
        return out;
    }

    fail("emulate: unknown action");
}

} // namespace slop::core::mcp::detail
