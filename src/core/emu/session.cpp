// src/core/emu/session.cpp
// unicorn hooks and zydis operand sorting, all the unicorn includes stay in here

#include "core/emu/session.hpp"

#include "core/disasm/engine.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/emu/orbis.hpp"
#include "core/emu/unicorn.hpp"

// Vendored header defines an unused static helper (usleep shim) that trips
// C4505 at TU end, kept suppressed for the rest of this file
#pragma warning(disable : 4505)
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>

namespace slop::core::emu {

namespace {

constexpr uint64_t kPageMask   = kPageSize - 1;
constexpr uint64_t kReturnPage = 0x00110000;   // sentinel RET trampoline
constexpr uint64_t kStubBase   = 0x00120000;   // one RET per import slot
constexpr uint64_t kStubStrideX64   = 8;
constexpr uint64_t kStubStrideArm64 = 4;
constexpr uint64_t kTebBase    = kStubBase + kMaxImports * kStubStrideX64;
constexpr uint64_t kTebSize    = 0x2000;       // x64 TEB is 0x1838 bytes
constexpr uint64_t kPebBase    = kTebBase + kTebSize;
// sysv uses the same reserved range for the FreeBSD TCB (the abis exclude
// each other): static TLS below the thread pointer (variant II), the TCB at
// it, then dtv and a zeroed struct pthread
constexpr uint64_t kTlsBase    = kTebBase;
constexpr uint64_t kTlsStatic  = 0x2000;       // static TLS block below fs
constexpr uint64_t kTlsSize    = 0x4000;
constexpr uint64_t kTlsTp      = kTlsBase + kTlsStatic;   // fs base
constexpr uint64_t kTlsDtv     = kTlsTp + 0x100;
constexpr uint64_t kTlsThread  = kTlsTp + 0x1000;
constexpr size_t   kMaxApiCalls = 1024;
constexpr size_t   kMaxSyscalls = 1024;
constexpr size_t   kMaxReads    = 4096;
constexpr uint32_t kArm64Ret    = 0xD65F03C0;  // RET x30

struct reg_alias_t { const char* name; int uc_reg; };

constexpr reg_alias_t kX64Regs[] = {
    {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX},
    {"rdx", UC_X86_REG_RDX}, {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI},
    {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP},
    {"r8",  UC_X86_REG_R8},  {"r9",  UC_X86_REG_R9},  {"r10", UC_X86_REG_R10},
    {"r11", UC_X86_REG_R11}, {"r12", UC_X86_REG_R12}, {"r13", UC_X86_REG_R13},
    {"r14", UC_X86_REG_R14}, {"r15", UC_X86_REG_R15},
    {"rip", UC_X86_REG_RIP}, {"rflags", UC_X86_REG_EFLAGS},
    {"fs_base", UC_X86_REG_FS_BASE}, {"gs_base", UC_X86_REG_GS_BASE},
};

constexpr reg_alias_t kArm64Regs[] = {
    {"x0", UC_ARM64_REG_X0}, {"x1", UC_ARM64_REG_X1}, {"x2", UC_ARM64_REG_X2},
    {"x3", UC_ARM64_REG_X3}, {"x4", UC_ARM64_REG_X4}, {"x5", UC_ARM64_REG_X5},
    {"x6", UC_ARM64_REG_X6}, {"x7", UC_ARM64_REG_X7}, {"x8", UC_ARM64_REG_X8},
    {"x9", UC_ARM64_REG_X9}, {"x10", UC_ARM64_REG_X10}, {"x11", UC_ARM64_REG_X11},
    {"x12", UC_ARM64_REG_X12}, {"x13", UC_ARM64_REG_X13}, {"x14", UC_ARM64_REG_X14},
    {"x15", UC_ARM64_REG_X15}, {"x16", UC_ARM64_REG_X16}, {"x17", UC_ARM64_REG_X17},
    {"x18", UC_ARM64_REG_X18}, {"x19", UC_ARM64_REG_X19}, {"x20", UC_ARM64_REG_X20},
    {"x21", UC_ARM64_REG_X21}, {"x22", UC_ARM64_REG_X22}, {"x23", UC_ARM64_REG_X23},
    {"x24", UC_ARM64_REG_X24}, {"x25", UC_ARM64_REG_X25}, {"x26", UC_ARM64_REG_X26},
    {"x27", UC_ARM64_REG_X27}, {"x28", UC_ARM64_REG_X28},
    {"x29", UC_ARM64_REG_X29}, {"fp",  UC_ARM64_REG_X29},
    {"x30", UC_ARM64_REG_X30}, {"lr",  UC_ARM64_REG_X30},
    {"sp",  UC_ARM64_REG_SP},  {"pc",  UC_ARM64_REG_PC},
    {"nzcv", UC_ARM64_REG_NZCV},
};

const reg_alias_t* reg_table(arch_t a, size_t* n) {
    if (a == arch_t::arm64) { *n = std::size(kArm64Regs); return kArm64Regs; }
    *n = std::size(kX64Regs);
    return kX64Regs;
}

bool lookup_reg(arch_t a, const std::string& name, int* out) {
    size_t n = 0;
    const reg_alias_t* t = reg_table(a, &n);
    for (size_t i = 0; i < n; ++i) {
        if (name == t[i].name) { *out = t[i].uc_reg; return true; }
    }
    return false;
}

const char* display_name(uint64_t canonical) {
    switch (canonical) {
    case ZYDIS_REGISTER_RAX: return "rax";
    case ZYDIS_REGISTER_RCX: return "rcx";
    case ZYDIS_REGISTER_RDX: return "rdx";
    case ZYDIS_REGISTER_RBX: return "rbx";
    case ZYDIS_REGISTER_RSP: return "rsp";
    case ZYDIS_REGISTER_RBP: return "rbp";
    case ZYDIS_REGISTER_RSI: return "rsi";
    case ZYDIS_REGISTER_RDI: return "rdi";
    case ZYDIS_REGISTER_R8:  return "r8";
    case ZYDIS_REGISTER_R9:  return "r9";
    case ZYDIS_REGISTER_R10: return "r10";
    case ZYDIS_REGISTER_R11: return "r11";
    case ZYDIS_REGISTER_R12: return "r12";
    case ZYDIS_REGISTER_R13: return "r13";
    case ZYDIS_REGISTER_R14: return "r14";
    case ZYDIS_REGISTER_R15: return "r15";
    case ZYDIS_REGISTER_RFLAGS: return "rflags";
    default: return "?";
    }
}

struct run_ctx_t {
    run_request_t const* req      = nullptr;
    taint_tracker_t      taint;
    bool                 taint_on = false;

    disasm::engine_t     eng;        // trace/event text formatting
    ZydisDecoder         decoder{};  // operand classification

    uint64_t instructions = 0;
    bool     until_hit    = false;
    bool     return_hit   = false;
    bool     cancelled    = false;
    bool     exited       = false;

    std::vector<run_result_t::trace_entry_t> trace;
    std::vector<run_result_t::write_entry_t> writes;
    size_t total_writes = 0;
    std::vector<run_result_t::read_entry_t> reads;
    size_t total_reads = 0;

    std::optional<run_result_t::fault_t> fault;

    uint64_t cur_ip        = 0;
    size_t   cur_seq       = 0;   // trace index of the running instruction
    std::string cur_text;
    uint64_t last_event_ip = 0;

    std::map<uint64_t, uint64_t> slot_stubs;   // IAT slot va -> stub va
    uint64_t stub_end = kStubBase;             // kStubBase: no stubs
    std::vector<run_result_t::api_call_t> api_calls;
    size_t total_api_calls = 0;

    std::vector<run_result_t::syscall_t> syscalls;
    size_t total_syscalls = 0;

    orbis_state_t* orbis = nullptr;   // non-null when syscalls are emulated

    bool teb_mapped = false;          // win64 TEB/PEB at gs
    bool tls_mapped = false;          // sysv TCB at fs

    std::set<uint64_t> dirty_pages;   // pages written since the engine started

    size_t paged_in          = 0;
    bool   page_in_exhausted = false;
    std::vector<uint8_t> page_buf = std::vector<uint8_t>(kPageSize);
};

// The source is caller code running under a C callback, nothing may unwind
// through unicorn
bool fetch_page(const run_request_t& req, uint64_t page, uint8_t* out) noexcept {
    if (!req.page_in) return false;
    try {
        return req.page_in(page, out);
    } catch (...) {
        return false;
    }
}

// Point every IAT slot in [lo, hi) at its stub. Unmapped slots fail quietly
// and get patched when their page comes in
void patch_slots(uc_engine* uc, const run_ctx_t& c, uint64_t lo, uint64_t hi) {
    for (auto it = c.slot_stubs.lower_bound(lo);
         it != c.slot_stubs.end() && it->first < hi; ++it)
        uc_mem_write(uc, it->first, &it->second, sizeof(it->second));
}

// Map every page an unmapped access touches from the page source. False
// leaves the access faulting
bool page_in_range(uc_engine* uc, run_ctx_t* c, uint64_t address, int size) {
    if (!c->req->page_in) return false;
    const uint64_t first = address & ~kPageMask;
    uint64_t last = (address + static_cast<uint64_t>(size > 1 ? size - 1 : 0)) & ~kPageMask;
    if (last < first) last = first;   // wrapped at the top of the address space
    for (uint64_t page = first;; page += kPageSize) {
        // a straddling access can fault with one of its pages already mapped
        uint8_t probe = 0;
        if (uc_mem_read(uc, page, &probe, 1) != UC_ERR_OK) {
            if (c->paged_in >= c->req->page_in_max) {
                c->page_in_exhausted = true;
                return false;
            }
            if (!fetch_page(*c->req, page, c->page_buf.data())) return false;
            if (uc_mem_map(uc, page, kPageSize, UC_PROT_ALL) != UC_ERR_OK ||
                uc_mem_write(uc, page, c->page_buf.data(), kPageSize) != UC_ERR_OK)
                return false;
            patch_slots(uc, *c, page, page + kPageSize);
            ++c->paged_in;
        }
        if (page == last) return true;
    }
}

// A call through a stubbed IAT/GOT slot landed here: log it, set the return
// value, and let the stub's RET go back to the caller
void on_import(uc_engine* uc, run_ctx_t* c, uint64_t address) {
    const uint64_t stride = c->req->arch == arch_t::arm64 ? kStubStrideArm64
                                                         : kStubStrideX64;
    const size_t idx = static_cast<size_t>((address - kStubBase) / stride);
    const import_slot_t& slot = c->req->imports[idx];
    const std::string& name = slot.name;

    ++c->total_api_calls;
    if (c->api_calls.size() < kMaxApiCalls) {
        run_result_t::api_call_t call;
        call.ip   = c->cur_ip;   // still the instruction that got us here
        call.name = name;
        if (c->req->arch == arch_t::arm64) {
            // the stub was reached with BR x16, so the return address is in LR
            uc_reg_read(uc, UC_ARM64_REG_X30, &call.ret);
            static constexpr int kArgs[6] = {
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5};
            call.arg_count = 6;
            for (int i = 0; i < call.arg_count; ++i) uc_reg_read(uc, kArgs[i], &call.args[i]);
        } else {
            uint64_t rsp = 0;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uc_mem_read(uc, rsp, &call.ret, sizeof(call.ret));
            static constexpr int kWin64Args[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX,
                                                  UC_X86_REG_R8,  UC_X86_REG_R9};
            static constexpr int kSysvArgs[6] = {UC_X86_REG_RDI, UC_X86_REG_RSI,
                                                 UC_X86_REG_RDX, UC_X86_REG_RCX,
                                                 UC_X86_REG_R8,  UC_X86_REG_R9};
            const bool sysv = c->req->abi == abi_t::sysv;
            const int* regs = sysv ? kSysvArgs : kWin64Args;
            call.arg_count = sysv ? 6 : 4;
            for (int i = 0; i < call.arg_count; ++i) uc_reg_read(uc, regs[i], &call.args[i]);
        }
        c->api_calls.push_back(std::move(call));
    }

    const uint64_t ret = slot.has_ret ? slot.ret : c->req->api_ret;
    if (c->req->arch == arch_t::arm64) {
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret);
    } else {
        uint64_t rax = ret;
        uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    }

    ++c->instructions;
    c->cur_ip = address;
    c->cur_text = "api " + name;
    if (c->req->trace && c->trace.size() < c->req->trace_max) {
        c->cur_seq = c->trace.size();
        c->trace.push_back({address, c->cur_text});
    }
    if (c->taint_on) {
        // rax is a constant now, and an empty analyze keeps the previous
        // instruction's dests from being applied a second time
        c->taint.set_reg(ZYDIS_REGISTER_RAX, false);
        c->taint.analyze(address, c->cur_text, {});
    }
}

// Instruction text for the trace. x86-64 goes through Zydis, aarch64 through
// the hyperion/capstone bridge so both arches report real mnemonics
void decode_text(run_ctx_t* c, uint64_t address, const uint8_t* bytes, size_t n) {
    if (c->req->arch == arch_t::arm64) {
        disasm::insn_t insn;
        if (disasm::hyperion_session::session_t::decode(address, bytes, n, insn,
                                                        hype::Arch::ARM64))
            c->cur_text = insn.text;
        return;
    }
    if (auto insn = c->eng.decode(address, bytes, n))
        c->cur_text = insn->text;
}

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);

    if (c->taint_on) c->taint.boundary();

    // Caller cancellation (MCP notifications/cancelled) must stop the run now,
    // not after the full timeout budget
    if (c->req->cancel.cancelled()) {
        c->cancelled = true;
        uc_emu_stop(uc);
        return;
    }

    if (c->req->until_addr && address == c->req->until_addr) {
        c->until_hit = true;
        uc_emu_stop(uc);
        return;
    }
    if (address >= kReturnPage && address < kReturnPage + 0x1000) {
        c->return_hit = true;
        uc_emu_stop(uc);
        return;
    }
    if (address >= kStubBase && address < c->stub_end) {
        on_import(uc, c, address);
        return;
    }

    ++c->instructions;
    c->cur_ip = address;

    // Instruction text and operands only feed the trace, the slice record and
    // taint; skip the per-instruction read + decode + format when none wants it
    const bool want_trace = c->req->trace && c->trace.size() < c->req->trace_max;
    if (!want_trace && !c->taint_on) return;
    c->cur_text.clear();

    // If the bytes are unreadable (unmapped callee after a CALL outside the
    // slice), do NOT decode zeros -- 00 00 decodes as "ADD [rax],al" and
    // poisons the trace with a fake fall-through. Record the gap instead.
    uint8_t bytes[16] = {};
    const size_t n = size <= sizeof(bytes) ? size : sizeof(bytes);
    bool readable = false;
    if (n > 0 && uc_mem_read(uc, address, bytes, n) == UC_ERR_OK)
        readable = true;

    if (readable) {
        decode_text(c, address, bytes, sizeof(bytes));
    } else {
        c->cur_text = "<unmapped>";
    }
    if (want_trace) {
        c->cur_seq = c->trace.size();
        run_result_t::trace_entry_t e;
        e.ip   = address;
        e.text = c->cur_text;
        if (c->req->record_slice && readable) {
            e.size = static_cast<uint8_t>(n);
            std::memcpy(e.bytes, bytes, n);
        }
        c->trace.push_back(std::move(e));
    }

    if (!c->taint_on || n == 0 || !readable) return;

    ZydisDecodedInstruction zin{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&c->decoder, bytes, n, &zin, ops)))
        return;

    taint_tracker_t::insn_sources_t src;
    for (uint8_t i = 0; i < zin.operand_count; ++i) {
        // Full operand list: includes implicit GPRs (div/mul rax:rdx, rep
        // rcx/rsi/rdi, stack ops) so coarse register taint stays faithful
        const auto& op = ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && op.visibility != ZYDIS_OPERAND_VISIBILITY_INVALID) {
            const uint64_t canon = taint_canonical_reg(op.reg.value);
            if (!canon) continue;
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                src.src_regs_tainted |= c->taint.reg(canon);
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                src.dests.push_back({static_cast<uint32_t>(canon),
                                     /*zeroing*/ false,
                                     display_name(canon)});
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                src.reads_memory = true;
        }
    }

    // Zeroing idioms clear taint even when sources appear tainted
    if ((zin.mnemonic == ZYDIS_MNEMONIC_XOR || zin.mnemonic == ZYDIS_MNEMONIC_SUB) &&
        zin.operand_count_visible == 2 &&
        ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        const uint64_t a = taint_canonical_reg(ops[0].reg.value);
        const uint64_t b = taint_canonical_reg(ops[1].reg.value);
        if (a && a == b)
            for (auto& d : src.dests)
                if (d.canonical == a) d.zeroing = true;
    }

    c->taint.analyze(address, c->cur_text, src);
}

void hook_mem_read(uc_engine*, uc_mem_type, uint64_t address, int size,
                   int64_t, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    if (c->taint_on) c->taint.note_mem_read(address, static_cast<size_t>(size));
    if (c->req->record_slice) {
        ++c->total_reads;
        if (c->reads.size() < kMaxReads)
            c->reads.push_back({c->cur_ip, address, static_cast<size_t>(size)});
    }
}

bool hook_mem_write(uc_engine*, uc_mem_type, uint64_t address, int size,
                    int64_t value, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    const bool tainted =
        c->taint_on && c->taint.note_mem_write(address, static_cast<size_t>(size));
    ++c->total_writes;
    if (c->writes.size() < 2048) {
        // unicorn hands at most 8 bytes of the stored value; wider stores
        // keep their low 8 bytes and are flagged
        uint64_t stored = static_cast<uint64_t>(value);
        if (size > 0 && size < 8) stored &= (1ull << (size * 8)) - 1;
        c->writes.push_back({c->cur_ip, address, static_cast<size_t>(size), stored,
                             size > 8, c->cur_seq});
    }
    // snapshot/restore granularity: every page the code wrote
    const uint64_t first = address & ~kPageMask;
    const uint64_t last  = (address + static_cast<uint64_t>(size > 0 ? size - 1 : 0)) & ~kPageMask;
    for (uint64_t p = first;; p += kPageSize) {
        c->dirty_pages.insert(p);
        if (p >= last) break;
    }
    if (tainted) {
        // Propagate: the stored bytes themselves become taint carriers
        c->taint.mark_memory(address, static_cast<size_t>(size));
        if (c->cur_ip != c->last_event_ip) {
            char addr_text[32];
            std::snprintf(addr_text, sizeof(addr_text), "mem %llX",
                          static_cast<unsigned long long>(address));
            c->taint.record_event({c->cur_ip, c->cur_text, "mem", addr_text});
            c->last_event_ip = c->cur_ip;
        }
    }
    return false;
}

// syscall: log it, hand back the configured result (or the Orbis handler's)
// and fake the instruction's register effects (rcx = next rip, r11 = rflags,
// CF clear = success, CF set = the value is an errno)
void hook_syscall(uc_engine* uc, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    uint64_t num = 0, rip = 0, rflags = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &num);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &rflags);

    uint64_t args[6] = {};
    static constexpr int kArgs[6] = {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                                     UC_X86_REG_R10, UC_X86_REG_R8,  UC_X86_REG_R9};
    for (int i = 0; i < 6; ++i) uc_reg_read(uc, kArgs[i], &args[i]);

    bool ok = true;
    uint64_t ret = c->req->syscall_ret;
    bool enosys = false;
    const auto it = c->req->syscall_returns.find(num);
    if (it != c->req->syscall_returns.end()) {
        ret = it->second;
    } else if (c->orbis) {
        const orbis_result_t r = orbis_syscall(uc, *c->orbis, num, args);
        ret = r.value;
        ok  = r.ok;
        enosys = !r.ok && r.value == kOrbisENOSYS;
    }

    ++c->total_syscalls;
    const char* name = c->req->syscall_name ? c->req->syscall_name(num) : nullptr;
    if (c->syscalls.size() < kMaxSyscalls) {
        run_result_t::syscall_t sc;
        sc.ip  = c->cur_ip;
        sc.num = num;
        if (name) sc.name = name;
        for (int i = 0; i < 6; ++i) sc.args[i] = args[i];
        sc.ret = ret;
        sc.enosys = enosys;
        c->syscalls.push_back(std::move(sc));
    }
    // the trace already holds "syscall" for this ip, name it there too
    if (name && !c->trace.empty() && c->trace.back().ip == c->cur_ip)
        c->trace.back().text += std::string(" ; ") + name;

    // unicorn reports rip at the syscall itself or past it depending on the
    // path; the instruction is 2 bytes (0F 05) either way
    const uint64_t next = rip == c->cur_ip ? rip + 2 : rip;
    uint64_t r11 = rflags;
    if (ok) rflags &= ~1ull;   // CF clear: success in the FreeBSD convention
    else    rflags |= 1ull;    // CF set: rax is the errno
    uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    uc_reg_write(uc, UC_X86_REG_RCX, &next);
    uc_reg_write(uc, UC_X86_REG_R11, &r11);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &rflags);
    if (c->taint_on) {
        c->taint.set_reg(ZYDIS_REGISTER_RAX, false);
        c->taint.set_reg(ZYDIS_REGISTER_RCX, false);
        c->taint.set_reg(ZYDIS_REGISTER_R11, false);
    }
    if (c->orbis && c->orbis->exited) {
        c->exited = true;
        uc_emu_stop(uc);
    }
}

bool hook_mem_invalid(uc_engine* uc, uc_mem_type access, uint64_t address,
                      int size, int64_t value, void* user_data) {
    (void)value;
    auto* c = static_cast<run_ctx_t*>(user_data);
    // unicorn 2 retries the access when the hook maps the page and returns true
    const bool unmapped = access == UC_MEM_READ_UNMAPPED ||
                          access == UC_MEM_WRITE_UNMAPPED ||
                          access == UC_MEM_FETCH_UNMAPPED;
    if (unmapped && page_in_range(uc, c, address, size)) return true;
    if (!c->fault) {   // keep the first fault
        const char* what = access == UC_MEM_FETCH_UNMAPPED ? "fetch"
                         : access == UC_MEM_WRITE_UNMAPPED ? "write"
                         : access == UC_MEM_FETCH_PROT     ? "fetch_prot"
                         : access == UC_MEM_WRITE_PROT     ? "write_prot"
                                                           : "read";
        c->fault = {c->cur_ip, address, what};
    }
    uc_emu_stop(uc);
    return false;
}

// Zeroed TEB + PEB with the fields code reads first: gs:[0x30] self,
// gs:[0x60] PEB, stack bounds, client ids, PEB.ImageBaseAddress. Everything
// else reads 0, so PEB.BeingDebugged / NtGlobalFlag checks see a clean process
bool map_teb(unicorn_t& uc, const run_request_t& req) {
    if (!uc.map(kTebBase, kTebSize + kPageSize)) return false;
    std::vector<uint8_t> blk(kTebSize + kPageSize, 0);
    auto put = [&blk](size_t off, uint64_t v) { std::memcpy(blk.data() + off, &v, sizeof(v)); };
    put(0x08, req.stack_base + req.stack_size);   // NtTib.StackBase
    put(0x10, req.stack_base);                    // NtTib.StackLimit
    put(0x30, kTebBase);                          // NtTib.Self
    put(0x40, 0x1000);                            // ClientId.UniqueProcess
    put(0x48, 0x1004);                            // ClientId.UniqueThread
    put(0x60, kPebBase);                          // ProcessEnvironmentBlock
    put(kTebSize + 0x10, req.image_base);         // PEB.ImageBaseAddress
    if (!uc.write(kTebBase, blk.data(), blk.size())) return false;
    uint64_t gs = kTebBase;
    return uc_reg_write(uc.handle(), UC_X86_REG_GS_BASE, &gs) == UC_ERR_OK;
}

// FreeBSD/PS4 thread control block behind fs (TLS variant II): fs:[0] is the
// TCB self pointer, fs:[8] the dtv, fs:[0x10] the struct pthread. Static TLS
// sits below the thread pointer and reads as zeros; dtv[2] points the main
// module's block at it so __tls_get_addr style lookups land in mapped memory
bool map_tls(unicorn_t& uc) {
    if (!uc.map(kTlsBase, kTlsSize)) return false;
    std::vector<uint8_t> blk(kTlsSize, 0);
    auto put = [&blk](uint64_t va, uint64_t v) {
        std::memcpy(blk.data() + (va - kTlsBase), &v, sizeof(v));
    };
    put(kTlsTp + 0x00, kTlsTp);                  // tcb_self
    put(kTlsTp + 0x08, kTlsDtv);                 // tcb_dtv
    put(kTlsTp + 0x10, kTlsThread);              // tcb_thread
    put(kTlsDtv + 0x00, 1);                      // dtv generation
    put(kTlsDtv + 0x08, 1);                      // module count
    put(kTlsDtv + 0x10, kTlsBase);               // module 1 TLS block
    put(kTlsThread + 0x00, kTlsTp);              // pthread -> its tcb
    if (!uc.write(kTlsBase, blk.data(), blk.size())) return false;
    uint64_t fs = kTlsTp;
    return uc_reg_write(uc.handle(), UC_X86_REG_FS_BASE, &fs) == UC_ERR_OK;
}

// Page by page so a dump running into unmapped memory keeps its readable
// head. Pages the run never touched still read from the page source
emu_mem_region_t read_back(const unicorn_t& uc, const run_request_t& req,
                           const run_request_t::dump_range_t& d) {
    emu_mem_region_t m;
    m.addr = d.addr;
    m.bytes.reserve(d.len);
    std::vector<uint8_t> page;
    uint64_t a = d.addr;
    size_t left = d.len;
    while (left) {
        const size_t chunk = std::min<size_t>(left, kPageSize - (a & kPageMask));
        const size_t at = m.bytes.size();
        m.bytes.resize(at + chunk);
        if (!uc.read(a, m.bytes.data() + at, chunk)) {
            if (page.empty()) page.resize(kPageSize);
            if (!fetch_page(req, a & ~kPageMask, page.data())) {
                m.bytes.resize(at);
                break;
            }
            std::memcpy(m.bytes.data() + at, page.data() + (a & kPageMask), chunk);
        }
        a += chunk;
        left -= chunk;
    }
    return m;
}

// One live engine plus the request it was built from. init() materializes the
// request (code, stack, maps, stubs, TCB), start() executes a slice of it.
struct machine_t {
    std::unique_ptr<unicorn_t> uc;
    run_request_t req;
    run_ctx_t     ctx;
    uint64_t      entry_va = 0;
    bool          arm64    = false;
    bool          invalid_insn = false;
    bool          timed_out = false;
    uc_err        last_err = UC_ERR_OK;

    bool init(const run_request_t& r, std::string* err);
    bool start(uint64_t count, uint32_t timeout_ms, infra::cancel_token_t cancel,
               std::string* err);
    void collect(run_result_t& out);
};

bool machine_t::init(const run_request_t& r, std::string* err) {
    auto bad = [err](const char* msg) { if (err) *err = msg; return false; };
    req = r;
    arm64 = req.arch == arch_t::arm64;
    if (req.code.empty()) return bad("no code bytes");
    if (req.imports.size() > kMaxImports) return bad("too many imports (max 16384)");
    if (arm64 && !req.taint_sources.empty())
        return bad("taint is x86-64 only (the arm64 path has no taint tracking)");

    uc = std::make_unique<unicorn_t>(arm64 ? uc_arch_t::arm64 : uc_arch_t::x86_64);
    if (!uc->ok()) return bad("unicorn init failed");

    if (!uc->map(req.code_base, req.code.size()))
        return bad("code mapping failed (unmapped/overlap?)");
    // A slice ending mid-page has to run into the real next bytes, not zero
    // fill, so the pages it shares come from the source first
    if (req.page_in) {
        std::vector<uint8_t> page(kPageSize);
        const uint64_t lo = req.code_base & ~kPageMask;
        const uint64_t hi = (req.code_base + req.code.size() + kPageMask) & ~kPageMask;
        for (uint64_t p = lo; p < hi; p += kPageSize)
            if (fetch_page(req, p, page.data())) uc->write(p, page.data(), kPageSize);
    }
    if (!uc->write(req.code_base, req.code.data(), req.code.size()))
        return bad("code mapping failed (unmapped/overlap?)");
    if (req.stack_size < 0x1000 || !uc->map(req.stack_base, req.stack_size))
        return bad("stack mapping failed");
    for (const auto& m : req.maps) {
        if (m.bytes.empty() || !uc->map(m.addr, m.bytes.size()) ||
            !uc->write(m.addr, m.bytes.data(), m.bytes.size()))
            return bad("data mapping failed");
    }

    // x86-64: a RET byte; aarch64: RET x30
    if (!uc->map(kReturnPage, 0x1000)) return bad("trampoline mapping failed");
    if (arm64) {
        const uint32_t ret = kArm64Ret;
        if (!uc->write(kReturnPage, &ret, sizeof(ret)))
            return bad("trampoline mapping failed");
    } else {
        const uint8_t ret = 0xC3;
        if (!uc->write(kReturnPage, &ret, 1)) return bad("trampoline mapping failed");
    }

    // engine_t is not assignable, so reset the per-run state field by field
    ctx.req = &req;
    ctx.taint_on = false;
    ctx.instructions = 0;
    ctx.until_hit = ctx.return_hit = ctx.cancelled = ctx.exited = false;
    ctx.fault.reset();
    ctx.trace.clear();
    ctx.writes.clear();
    ctx.reads.clear();
    ctx.api_calls.clear();
    ctx.syscalls.clear();
    ctx.slot_stubs.clear();
    ctx.dirty_pages.clear();
    ctx.total_writes = ctx.total_reads = 0;
    ctx.total_api_calls = ctx.total_syscalls = 0;
    ctx.paged_in = 0;
    ctx.page_in_exhausted = false;
    ctx.teb_mapped = ctx.tls_mapped = false;
    ctx.orbis = nullptr;
    ctx.stub_end = kStubBase;

    // One RET per import, an invalid instruction between them so a stray jump
    // into a stub stops instead of sliding into the next one
    if (!req.imports.empty()) {
        const uint64_t stride = arm64 ? kStubStrideArm64 : kStubStrideX64;
        const size_t len = req.imports.size() * static_cast<size_t>(stride);
        std::vector<uint8_t> stubs((len + kPageMask) & ~kPageMask, arm64 ? 0x00 : 0xCC);
        for (size_t i = 0; i < req.imports.size(); ++i) {
            if (arm64) {
                const uint32_t ret = kArm64Ret;
                std::memcpy(stubs.data() + i * stride, &ret, sizeof(ret));
            } else {
                stubs[i * stride] = 0xC3;
            }
            ctx.slot_stubs[req.imports[i].slot] = kStubBase + i * stride;
        }
        if (!uc->map(kStubBase, stubs.size()) ||
            !uc->write(kStubBase, stubs.data(), stubs.size()))
            return bad("import stub mapping failed");
        ctx.stub_end = kStubBase + len;
        patch_slots(uc->handle(), ctx, 0, UINT64_MAX);
    }

    // Best effort: a caller map over the TEB/TCB pages or a caller segment
    // base wins. aarch64 has no TEB/TCB convention to fake
    if (!arm64) {
        if (req.abi == abi_t::sysv) {
            if (!req.regs.count("fs_base")) ctx.tls_mapped = map_tls(*uc);
        } else if (!req.regs.count("gs_base")) {
            ctx.teb_mapped = map_teb(*uc, req);
        }
    }

    // Initial SP with a return-address sentinel so clean leaf routines halt
    // deterministically with stopped_reason="return"
    uint64_t sp = req.sp_set ? req.sp : req.stack_base + req.stack_size - 0x1000;
    sp &= ~(arm64 ? 0xFull : 0x7ull);
    if (arm64) {
        uint64_t lr = kReturnPage;
        uc_reg_write(uc->handle(), UC_ARM64_REG_X30, &lr);
    } else {
        sp -= 8;
        const uint64_t sentinel = kReturnPage;
        if (!uc->write(sp, &sentinel, sizeof(sentinel)))
            return bad("stack sentinel write failed");
    }

    ctx.taint_on = !req.taint_sources.empty();
    if (ctx.taint_on) {
        ctx.taint.reset();
        for (const auto& s : req.taint_sources)
            ctx.taint.mark_memory(s.addr, s.len);
    }
    if (!arm64) {
        if (!ctx.eng.init()) return bad("zydis engine init failed");
        if (ZydisDecoderInit(&ctx.decoder, ZYDIS_MACHINE_MODE_LONG_64,
                             ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS)
            return bad("zydis decoder init failed");
    }
    if (req.orbis_syscalls) {
        if (arm64) return bad("orbis syscalls are x86-64 only");
        ctx.orbis = &req.orbis;
    }

    for (const auto& [name, value] : req.regs) {
        int id = 0;
        if (!lookup_reg(req.arch, name, &id)) {
            if (err) {
                *err = "unknown register '" + name + "' (" +
                       (arm64 ? "use x0..x30, sp, pc, nzcv"
                              : "use rax..r15, rip, rflags, fs_base, gs_base") + ")";
            }
            return false;
        }
        uint64_t v = value;
        uc_reg_write(uc->handle(), id, &v);
    }

    if (!req.entry_absolute && req.entry >= req.code.size())
        return bad("entry offset outside code bytes");
    entry_va = req.entry_absolute ? req.entry : req.code_base + req.entry;

    uc_hook h_code = 0, h_read = 0, h_write = 0, h_bad = 0, h_sys = 0;
    uc_hook_add(uc->handle(), &h_code, UC_HOOK_CODE,
                reinterpret_cast<void*>(hook_code), &ctx, 1, 0);
    // the read hook feeds taint and the slice record; skip the per-access
    // callback when neither wants it
    if (ctx.taint_on || req.record_slice)
        uc_hook_add(uc->handle(), &h_read, UC_HOOK_MEM_READ,
                    reinterpret_cast<void*>(hook_mem_read), &ctx, 1, 0);
    uc_hook_add(uc->handle(), &h_write, UC_HOOK_MEM_WRITE,
                reinterpret_cast<void*>(hook_mem_write), &ctx, 1, 0);
    uc_hook_add(uc->handle(), &h_bad, UC_HOOK_MEM_INVALID,
                reinterpret_cast<void*>(hook_mem_invalid), &ctx, 1, 0);
    if (!arm64)
        uc_hook_add(uc->handle(), &h_sys, UC_HOOK_INSN,
                    reinterpret_cast<void*>(hook_syscall), &ctx, 1, 0,
                    UC_X86_INS_SYSCALL);

    uint64_t pc = entry_va;
    if (arm64) {
        uint64_t spv = sp;
        uc_reg_write(uc->handle(), UC_ARM64_REG_PC, &pc);
        uc_reg_write(uc->handle(), UC_ARM64_REG_SP, &spv);
    } else {
        uint64_t rip = pc, rsp = sp;
        uc_reg_write(uc->handle(), UC_X86_REG_RIP, &rip);
        uc_reg_write(uc->handle(), UC_X86_REG_RSP, &rsp);
    }
    return true;
}

bool machine_t::start(uint64_t count, uint32_t timeout_ms,
                      infra::cancel_token_t cancel, std::string* err) {
    req.cancel = cancel;
    ctx.until_hit = false;
    ctx.return_hit = false;
    ctx.cancelled = false;
    ctx.exited = false;
    ctx.fault.reset();
    ctx.instructions = 0;
    invalid_insn = false;
    timed_out = false;

    uint64_t begin = 0;
    if (arm64) uc_reg_read(uc->handle(), UC_ARM64_REG_PC, &begin);
    else       uc_reg_read(uc->handle(), UC_X86_REG_RIP, &begin);

    const uint64_t until = req.until_addr ? req.until_addr : kReturnPage;
    const uint64_t budget = count ? count : (req.max_instructions ? req.max_instructions : 100000);
    const uint32_t ms = std::min<uint32_t>(timeout_ms ? timeout_ms : 5000, kMaxTimeoutMs);
    const uc_err e = uc_emu_start(uc->handle(), begin, until,
                                  static_cast<uint64_t>(ms) * 1000ull, budget);
    // unicorn returns OK on timeout; its timer thread records whether it fired
    size_t fired = 0;
    uc_query(uc->handle(), UC_QUERY_TIMEOUT, &fired);
    timed_out = fired != 0;

    last_err = e;
    if (e == UC_ERR_INSN_INVALID) invalid_insn = true;
    // every uc_emu_start result is a normal stop, not a setup failure: a memory
    // fault is recorded by the invalid hook, an invalid instruction or an
    // unhandled guest exception is classified by collect(), and the run still
    // reports registers/memory so the caller can see where it died
    (void)err;
    return true;
}

void machine_t::collect(run_result_t& out) {
    out.ok = true;
    out.instructions += ctx.instructions;
    ctx.instructions = 0;

    size_t n = 0;
    const reg_alias_t* t = reg_table(req.arch, &n);
    for (size_t i = 0; i < n; ++i) {
        uint64_t v = 0;
        if (uc_reg_read(uc->handle(), t[i].uc_reg, &v) == UC_ERR_OK)
            out.regs[t[i].name] = v;
    }

    if (!ctx.trace.empty()) {
        out.trace.insert(out.trace.end(), ctx.trace.begin(), ctx.trace.end());
        ctx.trace.clear();
    }
    if (!ctx.writes.empty()) {
        out.writes.insert(out.writes.end(), ctx.writes.begin(), ctx.writes.end());
        ctx.writes.clear();
    }
    out.total_writes += ctx.total_writes;
    ctx.total_writes = 0;
    if (!ctx.reads.empty()) {
        out.reads.insert(out.reads.end(), ctx.reads.begin(), ctx.reads.end());
        ctx.reads.clear();
    }
    out.total_reads += ctx.total_reads;
    ctx.total_reads = 0;
    if (!ctx.api_calls.empty()) {
        out.api_calls.insert(out.api_calls.end(), ctx.api_calls.begin(), ctx.api_calls.end());
        ctx.api_calls.clear();
    }
    out.total_api_calls += ctx.total_api_calls;
    ctx.total_api_calls = 0;
    if (!ctx.syscalls.empty()) {
        out.syscalls.insert(out.syscalls.end(), ctx.syscalls.begin(), ctx.syscalls.end());
        ctx.syscalls.clear();
    }
    out.total_syscalls += ctx.total_syscalls;
    ctx.total_syscalls = 0;

    out.paged_in += ctx.paged_in;
    ctx.paged_in = 0;
    out.page_in_exhausted = out.page_in_exhausted || ctx.page_in_exhausted;
    out.teb_mapped = out.teb_mapped || ctx.teb_mapped;
    out.tls_mapped = out.tls_mapped || ctx.tls_mapped;
    if (ctx.fault) out.fault = ctx.fault;

    if (req.orbis_syscalls) {
        out.stdout_data = req.orbis.stdout_data;
        out.syscall_enosys = req.orbis.enosys;
        out.exited = req.orbis.exited;
        out.exit_code = req.orbis.exit_code;
    }

    uint64_t pc = 0;
    if (arm64) uc_reg_read(uc->handle(), UC_ARM64_REG_PC, &pc);
    else       uc_reg_read(uc->handle(), UC_X86_REG_RIP, &pc);

    if (ctx.exited)                       out.stopped_reason = "exit";
    else if (ctx.cancelled)               out.stopped_reason = "cancelled";
    else if (ctx.return_hit)              out.stopped_reason = "return";
    else if (ctx.until_hit)               out.stopped_reason = "until";
    else if (ctx.fault)                   out.stopped_reason = std::string("invalid_mem_") + ctx.fault->access;
    else if (timed_out)                   out.stopped_reason = "timeout";
    else if (invalid_insn)                out.stopped_reason = "invalid_insn";
    else if (last_err == UC_ERR_FETCH_UNMAPPED) out.stopped_reason = "invalid_mem_fetch";
    else if (last_err != UC_ERR_OK)       out.stopped_reason = "cpu_exception";
    else if (pc >= kReturnPage && pc < kReturnPage + 0x1000) out.stopped_reason = "return";
    else if (req.until_addr && pc == req.until_addr)         out.stopped_reason = "until";
    else                                  out.stopped_reason = "count";
}

} // namespace

run_result_t emulate_run(const run_request_t& req) {
    run_result_t res;
    machine_t m;
    std::string err;
    if (!m.init(req, &err)) {
        res.error = err;
        return res;
    }
    const uint64_t count = req.max_instructions ? req.max_instructions : 100000;
    const uint32_t timeout_ms = req.timeout_ms ? req.timeout_ms : 5000;
    if (!m.start(count, timeout_ms, req.cancel, &err)) {
        res.error = err;
        return res;
    }
    m.collect(res);
    if (res.stopped_reason == "cpu_exception")
        res.error = uc_strerror(m.last_err);

    for (const auto& d : req.dumps) res.memory.push_back(read_back(*m.uc, req, d));

    if (m.ctx.taint_on) {
        m.ctx.taint.boundary();   // flush the final instruction's deferred dests
        res.taint_ranges = m.ctx.taint.tainted_ranges();
        res.taint_events = m.ctx.taint.events();
        res.output_tainted = req.watch_len > 0 &&
                             m.ctx.taint.memory_any(req.watch_addr, req.watch_len);
    }
    return res;
}

// === dynamic backward slicing =============================================

namespace {

bool slice_reg_id(const std::string& name, uint32_t* out) {
    static constexpr struct { const char* name; ZydisRegister r; } kNames[] = {
        {"rax", ZYDIS_REGISTER_RAX}, {"rbx", ZYDIS_REGISTER_RBX},
        {"rcx", ZYDIS_REGISTER_RCX}, {"rdx", ZYDIS_REGISTER_RDX},
        {"rsi", ZYDIS_REGISTER_RSI}, {"rdi", ZYDIS_REGISTER_RDI},
        {"rbp", ZYDIS_REGISTER_RBP}, {"rsp", ZYDIS_REGISTER_RSP},
        {"r8",  ZYDIS_REGISTER_R8},  {"r9",  ZYDIS_REGISTER_R9},
        {"r10", ZYDIS_REGISTER_R10}, {"r11", ZYDIS_REGISTER_R11},
        {"r12", ZYDIS_REGISTER_R12}, {"r13", ZYDIS_REGISTER_R13},
        {"r14", ZYDIS_REGISTER_R14}, {"r15", ZYDIS_REGISTER_R15},
        {"rflags", ZYDIS_REGISTER_RFLAGS},
        {"eax", ZYDIS_REGISTER_EAX}, {"ebx", ZYDIS_REGISTER_EBX},
        {"ecx", ZYDIS_REGISTER_ECX}, {"edx", ZYDIS_REGISTER_EDX},
        {"esi", ZYDIS_REGISTER_ESI}, {"edi", ZYDIS_REGISTER_EDI},
        {"ebp", ZYDIS_REGISTER_EBP}, {"esp", ZYDIS_REGISTER_ESP},
    };
    for (const auto& e : kNames) {
        if (name == e.name) { *out = e.r; return true; }
    }
    return false;
}

struct mem_range_t { uint64_t addr; size_t len; };

bool overlaps(uint64_t a, size_t alen, uint64_t b, size_t blen) {
    return a < b + blen && b < a + alen;
}

} // namespace

slice_result_t emulate_slice(const run_result_t& run, const slice_request_t& s) {
    slice_result_t out;
    if (run.trace.empty()) { out.error = "trace is empty"; return out; }
    const bool have_bytes = std::any_of(run.trace.begin(), run.trace.end(),
                                        [](const auto& t) { return t.size != 0; });
    if (!have_bytes) {
        out.error = "trace has no instruction bytes: rerun with record_slice";
        return out;
    }

    size_t start = run.trace.size();
    if (s.at) {
        for (size_t i = 0; i < run.trace.size(); ++i)
            if (run.trace[i].ip == s.at) { start = i; break; }
        if (start == run.trace.size()) {
            out.error = "at ip is not in the recorded trace";
            return out;
        }
    }

    std::set<uint32_t> need_regs;
    std::vector<mem_range_t> need_mem;
    if (!s.reg.empty()) {
        uint32_t zr = 0;
        if (!slice_reg_id(s.reg, &zr)) {
            out.error = "unknown slice register '" + s.reg + "'";
            return out;
        }
        need_regs.insert(taint_canonical_reg(zr));
    } else if (s.addr && s.len) {
        need_mem.push_back({s.addr, s.len});
    } else {
        out.error = "slice needs reg or addr+len";
        return out;
    }

    ZydisDecoder dec{};
    if (ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64) !=
        ZYAN_STATUS_SUCCESS) {
        out.error = "zydis decoder init failed";
        return out;
    }

    std::vector<size_t> hits;
    // shortcut: the write/read logs keep their first 2048/4096 entries, so a
    // slice late in a very long run can miss dependencies; raise the caps when
    // slicing runs that make more accesses than that
    for (size_t i = start; i-- > 0;) {
        const auto& tr = run.trace[i];
        if (!tr.size) continue;   // <unmapped> gap, nothing to depend on

        ZydisDecodedInstruction zin{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, tr.bytes, tr.size, &zin, ops)))
            continue;

        bool hit = false;
        // memory this instruction wrote at this execution
        for (const auto& w : run.writes) {
            if (w.seq != i) continue;
            for (auto it = need_mem.begin(); it != need_mem.end();) {
                if (overlaps(w.addr, w.len, it->addr, it->len)) {
                    hit = true;
                    it = need_mem.erase(it);
                } else {
                    ++it;
                }
            }
        }
        // registers this instruction wrote
        for (uint8_t o = 0; o < zin.operand_count; ++o) {
            const auto& op = ops[o];
            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) continue;
            const uint32_t canon = taint_canonical_reg(op.reg.value);
            if (canon && need_regs.erase(canon)) hit = true;
        }
        if (!hit) continue;
        hits.push_back(i);

        // sources of this instruction: every register it reads (explicit and
        // implicit) plus the memory it actually read at this execution
        for (uint8_t o = 0; o < zin.operand_count; ++o) {
            const auto& op = ops[o];
            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) continue;
            const uint32_t canon = taint_canonical_reg(op.reg.value);
            if (canon) need_regs.insert(canon);
        }
        for (const auto& r : run.reads) {
            if (r.seq == i) need_mem.push_back({r.addr, r.len});
        }
        if (need_regs.empty() && need_mem.empty()) break;
    }

    std::reverse(hits.begin(), hits.end());
    out.indices = std::move(hits);
    for (size_t i : out.indices) out.insns.push_back(run.trace[i]);
    out.ok = true;
    return out;
}

// === persistent sessions ===================================================

struct emulation_session_t::impl_t {
    machine_t machine;
    run_result_t result;
    struct snapshot_t {
        std::map<std::string, uint64_t> regs;
        std::map<uint64_t, std::vector<uint8_t>> pages;
    };
    std::map<uint64_t, snapshot_t> snapshots;
    uint64_t next_snapshot = 1;
};

std::unique_ptr<emulation_session_t> emulation_session_t::create(
    const run_request_t& req, std::string* err) {
    auto impl = std::make_unique<impl_t>();
    if (!impl->machine.init(req, err)) return nullptr;
    impl->result.ok = true;
    impl->machine.collect(impl->result);
    impl->result.stopped_reason.clear();
    return std::unique_ptr<emulation_session_t>(
        new emulation_session_t(std::move(impl)));
}

emulation_session_t::emulation_session_t(std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

emulation_session_t::~emulation_session_t() = default;

bool emulation_session_t::step(uint64_t count, uint32_t timeout_ms,
                               infra::cancel_token_t cancel, std::string* err) {
    if (!impl_->machine.start(count, timeout_ms, cancel, err)) return false;
    impl_->machine.collect(impl_->result);
    return true;
}

bool emulation_session_t::snapshot(std::string* err) {
    if (impl_->snapshots.size() >= kMaxSnapshots) {
        if (err) *err = "too many snapshots (max 8): restore or drop the session";
        return false;
    }
    if (impl_->machine.ctx.dirty_pages.size() > kMaxSnapshotPages) {
        if (err) *err = "too many dirty pages for a snapshot (max 4096 = 16 MiB)";
        return false;
    }
    impl_t::snapshot_t snap;
    size_t n = 0;
    const reg_alias_t* t = reg_table(impl_->machine.req.arch, &n);
    for (size_t i = 0; i < n; ++i) {
        uint64_t v = 0;
        if (uc_reg_read(impl_->machine.uc->handle(), t[i].uc_reg, &v) == UC_ERR_OK)
            snap.regs[t[i].name] = v;
    }
    std::vector<uint8_t> page(kPageSize);
    for (uint64_t p : impl_->machine.ctx.dirty_pages) {
        if (impl_->machine.uc->read(p, page.data(), kPageSize))
            snap.pages[p] = page;
    }
    impl_->snapshots[impl_->next_snapshot++] = std::move(snap);
    return true;
}

bool emulation_session_t::restore(std::string* err) {
    if (impl_->snapshots.empty()) {
        if (err) *err = "no snapshot to restore";
        return false;
    }
    auto it = std::prev(impl_->snapshots.end());
    impl_t::snapshot_t& snap = it->second;
    for (const auto& [page, bytes] : snap.pages)
        impl_->machine.uc->write(page, bytes.data(), bytes.size());
    for (const auto& [name, value] : snap.regs) {
        int id = 0;
        if (lookup_reg(impl_->machine.req.arch, name, &id)) {
            uint64_t v = value;
            uc_reg_write(impl_->machine.uc->handle(), id, &v);
        }
    }
    impl_->machine.ctx.dirty_pages.clear();
    impl_->machine.ctx.fault.reset();
    impl_->result.stopped_reason.clear();
    impl_->machine.collect(impl_->result);
    impl_->result.stopped_reason.clear();
    return true;
}

const run_result_t& emulation_session_t::state() const { return impl_->result; }

size_t emulation_session_t::snapshot_count() const { return impl_->snapshots.size(); }

size_t emulation_session_t::snapshot_pages() const {
    if (impl_->snapshots.empty()) return 0;
    return std::prev(impl_->snapshots.end())->second.pages.size();
}

arch_t emulation_session_t::arch() const { return impl_->machine.req.arch; }

const char* abi_name(abi_t a) noexcept {
    return a == abi_t::sysv ? "sysv" : "win64";
}

const char* arch_name(arch_t a) noexcept {
    return a == arch_t::arm64 ? "arm64" : "x64";
}

} // namespace slop::core::emu
