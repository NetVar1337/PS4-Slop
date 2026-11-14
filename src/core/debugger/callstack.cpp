// src/core/debugger/callstack.cpp

#include "core/debugger/callstack.hpp"

#include <cstring>
#include <set>

namespace slop::core::debugger::unwind {

namespace {

constexpr uint64_t kUserMax = 0x7FFFFFFEFFFFull;   // highest user VA

bool plausible_code(disasm::engine_t& eng, reader_t& rdr, uint64_t va) {
    if (va == 0 || va > kUserMax) return false;
    uint8_t buf[16]{};
    if (!rdr.read(va, buf, sizeof(buf))) return false;
    auto in = eng.decode(va, buf, sizeof(buf));
    return in.has_value() && in->length > 0;
}

} // namespace

std::vector<frame_t> walk_stack(disasm::engine_t& eng, reader_t& rdr,
                                uint64_t /*rip*/, uint64_t rsp, uint64_t rbp,
                                size_t max_frames) {
    std::vector<frame_t> out;
    if (max_frames == 0) return out;

    // Frame 0: the return address at [rsp] is the caller of the paused site
    uint64_t ret = 0;
    if (rdr.read(rsp, &ret, 8) && ret != 0 && ret <= kUserMax) {
        frame_t f;
        f.ret_addr = ret;
        uint8_t buf[16];
        if (rdr.read(ret, buf, sizeof(buf))) {
            if (auto in = eng.decode(ret, buf, sizeof(buf))) f.snippet = in->text;
        }
        out.push_back(std::move(f));
        if (out.size() >= max_frames) return out;
    }

    // RBP-chain walk with sanity gates
    std::set<uint64_t> seen;
    uint64_t fp = rbp;
    for (size_t guard = 0; guard < max_frames * 4 + 32; ++guard) {
        if (fp == 0 || fp > kUserMax || !seen.insert(fp).second) break;
        uint64_t saved_rbp = 0, saved_ret = 0;
        if (!rdr.read(fp, &saved_rbp, 8)) break;
        if (!rdr.read(fp + 8, &saved_ret, 8)) break;

        const bool ok_chain =
            saved_rbp == 0 ||
            (saved_rbp > fp && saved_rbp <= kUserMax);
        if (!ok_chain) break;

        frame_t f;
        f.frame_ptr = fp;
        f.ret_addr  = saved_ret;
        uint8_t buf[16];
        if (saved_ret && saved_ret <= kUserMax && rdr.read(saved_ret, buf, sizeof(buf))) {
            if (auto in = eng.decode(saved_ret, buf, sizeof(buf)))
                f.snippet = in->text;
            else
                f.ret_addr = 0;   // not code: drop frame
        }
        if (f.ret_addr) {
            // Frame 0 already reported [rsp]; skip a duplicate
            if (!(out.size() == 1 && out[0].ret_addr == f.ret_addr &&
                  out[0].frame_ptr == 0))
                out.push_back(std::move(f));
        }
        if (saved_rbp == 0) break;
        fp = saved_rbp;
        if (out.size() >= max_frames) break;
    }

    // Scan fallback when the chain died early
    if (out.size() < 3) {
        constexpr size_t kScanBytes = 0x800;
        std::set<uint64_t> known;
        for (const auto& f : out) known.insert(f.ret_addr);

        for (size_t off = 8; off < kScanBytes && out.size() < max_frames; off += 8) {
            uint64_t cand = 0;
            if (!rdr.read(rsp + off, &cand, 8)) break;
            if (cand <= rsp || cand > kUserMax || known.count(cand)) continue;

            // Memory-query gate proxy: readable via our reader, decodes as
            // an instruction start, and sits above the current stack top
            // (a real return address points back into code)
            if (!plausible_code(eng, rdr, cand)) continue;

            bool dup = false;
            for (const auto& f : out)
                if (f.ret_addr == cand) { dup = true; break; }
            if (dup) continue;

            frame_t f;
            f.ret_addr = cand;
            f.scanned  = true;
            uint8_t buf[16];
            if (rdr.read(cand, buf, sizeof(buf))) {
                if (auto in = eng.decode(cand, buf, sizeof(buf))) f.snippet = in->text;
            }
            out.push_back(std::move(f));
        }
    }
    return out;
}

seh_result_t seh_chain(reader_t& rdr, uint64_t teb_addr) {
    seh_result_t res;
    if (teb_addr == 0) {
        res.note = "no TEB address available";
        return res;
    }

    // NT_TIB at TEB+0: ExceptionList (x86), plus ExpectedDfr / etc. On x64
    // the list must be empty (-1); walk it only if it isn't
    uint64_t head = 0;
    if (!rdr.read(teb_addr, &head, 8)) {
        res.note = "TEB read failed";
        return res;
    }

    constexpr uint64_t kSentinel = 0xFFFFFFFFFFFFFFFFull;
    std::set<uint64_t> seen;
    while (head != kSentinel && head != 0) {
        if (head > kUserMax || !seen.insert(head).second) {
            res.note = "chain stop reason: implausible or cyclic entry";
            break;
        }
        // _EXCEPTION_REGISTRATION_RECORD { Next; Handler; }
        uint64_t next = 0, handler = 0;
        if (!rdr.read(head, &next, 8) || !rdr.read(head + 8, &handler, 8)) {
            res.note = "chain stop reason: unreadable record";
            break;
        }
        seh_entry_t e;
        e.handler = handler;
        e.filter  = 0;
        e.frame   = head;
        res.chain.push_back(e);
        head = next;
        if (res.chain.size() >= 32) {
            res.note = "chain truncated at 32 entries";
            break;
        }
    }
    if (head == kSentinel)
        res.chain_empty_proven = res.chain.empty();

    // x64 framed-handler candidates: scan the stack for values that look
    // like code pointers (heuristic parity with the reference viewer)
    return res;
}

// ---- PE x64 unwind info ---------------------------------------------------

namespace {

constexpr uint32_t kUnwFlagChainInfo = 0x4;
constexpr uint32_t kAllCodes = 0xFFFFFFFFu;   // apply every code (past the prologue)
constexpr uint32_t kMaxChainDepth = 8;

bool read_u16(reader_t& rdr, uint64_t addr, uint16_t& v) {
    return rdr.read(addr, &v, sizeof(v));
}

bool read_u32(reader_t& rdr, uint64_t addr, uint32_t& v) {
    return rdr.read(addr, &v, sizeof(v));
}

bool read_u64(reader_t& rdr, uint64_t addr, uint64_t& v) {
    return rdr.read(addr, &v, sizeof(v));
}

struct pe_dir_t {
    uint32_t pdata_rva = 0;
    uint32_t pdata_size = 0;
};

// exception directory (data directory 3) of the PE mapped at base
bool pe_exception_dir(reader_t& rdr, uint64_t base, pe_dir_t& out) {
    uint16_t mz = 0;
    if (!read_u16(rdr, base, mz) || mz != 0x5A4D) return false;
    uint32_t lfanew = 0;
    if (!read_u32(rdr, base + 0x3C, lfanew)) return false;
    uint32_t sig = 0;
    if (!read_u32(rdr, base + lfanew, sig) || sig != 0x00004550) return false;
    const uint64_t opt = base + lfanew + 4 + 20;
    uint16_t magic = 0;
    if (!read_u16(rdr, opt, magic) || magic != 0x20B) return false;   // PE32+
    uint32_t nrva = 0;
    if (!read_u32(rdr, opt + 108, nrva) || nrva <= 3) return false;
    const uint64_t dir = opt + 112 + 3 * 8;
    if (!read_u32(rdr, dir, out.pdata_rva) || !read_u32(rdr, dir + 4, out.pdata_size))
        return false;
    return out.pdata_rva != 0 && out.pdata_size >= 12;
}

struct runtime_function_t {
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t unwind_rva = 0;
};

bool read_runtime_function(reader_t& rdr, uint64_t at, runtime_function_t& rf) {
    uint8_t buf[12];
    if (!rdr.read(at, buf, sizeof(buf))) return false;
    std::memcpy(&rf.begin, buf, 4);
    std::memcpy(&rf.end, buf + 4, 4);
    std::memcpy(&rf.unwind_rva, buf + 8, 4);
    return true;
}

// .pdata is sorted by BeginAddress: binary search the entry covering rva
bool find_runtime_function(reader_t& rdr, uint64_t base, const pe_dir_t& dir, uint32_t rva,
                           runtime_function_t& out) {
    size_t lo = 0, hi = dir.pdata_size / 12;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        runtime_function_t rf;
        if (!read_runtime_function(rdr, base + dir.pdata_rva + mid * 12, rf)) return false;
        if (rva < rf.begin) hi = mid;
        else if (rva >= rf.end) lo = mid + 1;
        else { out = rf; return true; }
    }
    return false;
}

// unwind register numbering: 0 rax, 1 rcx, 2 rdx, 3 rbx, 4 rsp, 5 rbp,
// 6 rsi, 7 rdi, 8..15 r8..r15
struct uw_ctx_t {
    uint64_t reg[16]{};
    uint64_t rip = 0;
};

void load_ctx(const runtime::thread_context_t& c, uw_ctx_t& u) {
    u.reg[0] = c.rax; u.reg[1] = c.rcx; u.reg[2] = c.rdx; u.reg[3] = c.rbx;
    u.reg[4] = c.rsp; u.reg[5] = c.rbp; u.reg[6] = c.rsi; u.reg[7] = c.rdi;
    u.reg[8] = c.r8;  u.reg[9] = c.r9;  u.reg[10] = c.r10; u.reg[11] = c.r11;
    u.reg[12] = c.r12; u.reg[13] = c.r13; u.reg[14] = c.r14; u.reg[15] = c.r15;
    u.rip = c.rip;
}

// apply one UNWIND_INFO block; codes are ordered by decreasing code offset,
// so a forward walk is the reverse of the prologue (the RtlVirtualUnwind
// order). offset_in_func skips prologue ops that have not run yet.
bool apply_unwind_info(reader_t& rdr, uint64_t base, uint32_t unwind_rva, uw_ctx_t& u,
                       uint32_t offset_in_func, uint32_t depth) {
    if (depth > kMaxChainDepth) return false;
    const uint64_t info = base + unwind_rva;
    uint8_t hdr[4];
    if (!rdr.read(info, hdr, sizeof(hdr))) return false;
    const uint8_t flags = hdr[0] >> 3;
    const uint8_t count = hdr[2];
    const uint8_t frame_reg = hdr[3] & 0xF;
    const uint32_t frame_off = static_cast<uint32_t>(hdr[3] >> 4) * 16u;
    const uint64_t codes = info + 4;

    for (uint32_t i = 0; i < count; ++i) {
        uint16_t code = 0;
        if (!read_u16(rdr, codes + i * 2, code)) return false;
        const uint8_t off = static_cast<uint8_t>(code & 0xFF);
        const uint8_t op = static_cast<uint8_t>((code >> 8) & 0xF);
        const uint8_t op_info = static_cast<uint8_t>(code >> 12);
        if (offset_in_func != kAllCodes && off > offset_in_func) {
            // not executed yet, but its operand slots still occupy the array
            if (op == 1) i += op_info == 0 ? 1 : 2;
            else if (op == 4) i += 1;
            else if (op == 5) i += 2;
            else if (op == 8) i += 1;
            else if (op == 9) i += 2;
            continue;
        }
        switch (op) {
        case 0:   // push nonvolatile register
            if (!read_u64(rdr, u.reg[4], u.reg[op_info])) return false;
            u.reg[4] += 8;
            break;
        case 1: { // alloc large
            uint32_t size = 0;
            if (op_info == 0) {
                uint16_t slots = 0;
                if (!read_u16(rdr, codes + (i + 1) * 2, slots)) return false;
                size = static_cast<uint32_t>(slots) * 8u;
                i += 1;
            } else {
                uint16_t lo = 0, hi = 0;
                if (!read_u16(rdr, codes + (i + 1) * 2, lo) ||
                    !read_u16(rdr, codes + (i + 2) * 2, hi))
                    return false;
                size = static_cast<uint32_t>(lo) | (static_cast<uint32_t>(hi) << 16);
                i += 2;
            }
            u.reg[4] += size;
            break;
        }
        case 2:   // alloc small
            u.reg[4] += static_cast<uint32_t>(op_info) * 8u + 8u;
            break;
        case 3:   // set frame pointer
            if (frame_reg == 0 || frame_reg >= 16) return false;
            u.reg[4] = u.reg[frame_reg] - frame_off;
            break;
        case 4: { // save nonvolatile
            uint16_t slots = 0;
            if (!read_u16(rdr, codes + (i + 1) * 2, slots)) return false;
            if (!read_u64(rdr, u.reg[4] + static_cast<uint64_t>(slots) * 8u, u.reg[op_info]))
                return false;
            i += 1;
            u.reg[4] += 8;
            break;
        }
        case 5: { // save nonvolatile far
            uint16_t lo = 0, hi = 0;
            if (!read_u16(rdr, codes + (i + 1) * 2, lo) ||
                !read_u16(rdr, codes + (i + 2) * 2, hi))
                return false;
            const uint32_t disp = static_cast<uint32_t>(lo) | (static_cast<uint32_t>(hi) << 16);
            if (!read_u64(rdr, u.reg[4] + disp, u.reg[op_info])) return false;
            i += 2;
            u.reg[4] += 8;
            break;
        }
        case 8:   // save xmm128
            i += 1;
            u.reg[4] += 16;
            break;
        case 9:   // save xmm128 far
            i += 2;
            u.reg[4] += 16;
            break;
        case 10: {   // push machine frame
            if (op_info) u.reg[4] += 8;
            uint64_t new_rip = 0, new_rsp = 0;
            if (!read_u64(rdr, u.reg[4], new_rip)) return false;
            if (!read_u64(rdr, u.reg[4] + 24, new_rsp)) return false;
            u.rip = new_rip;
            u.reg[4] = new_rsp;
            break;
        }
        default:
            break;
        }
    }

    if (flags & kUnwFlagChainInfo) {
        // the chained RUNTIME_FUNCTION follows the codes, 4-byte aligned
        runtime_function_t chain;
        if (!read_runtime_function(rdr, codes + (((count + 1u) & ~1u) * 2u), chain))
            return false;
        return apply_unwind_info(rdr, base, chain.unwind_rva, u, kAllCodes, depth + 1);
    }
    return true;
}

// one frame: rip -> the caller's rip/rsp/regs
bool unwind_one(reader_t& rdr, const module_of_fn& module_of, uw_ctx_t& u) {
    module_span_t m;
    if (!module_of(u.rip, m)) return false;
    pe_dir_t dir;
    if (!pe_exception_dir(rdr, m.base, dir)) return false;
    const uint32_t rva = static_cast<uint32_t>(u.rip - m.base);
    runtime_function_t rf;
    if (!find_runtime_function(rdr, m.base, dir, rva, rf)) {
        // leaf function: the return address sits at rsp
        uint64_t ret = 0;
        if (!read_u64(rdr, u.reg[4], ret)) return false;
        u.reg[4] += 8;
        u.rip = ret;
        return true;
    }
    if (!apply_unwind_info(rdr, m.base, rf.unwind_rva, u, rva - rf.begin, 0)) return false;
    uint64_t ret = 0;
    if (!read_u64(rdr, u.reg[4], ret)) return false;
    u.reg[4] += 8;
    u.rip = ret;
    return true;
}

} // namespace

bool pe_unwind(reader_t& rdr, const runtime::thread_context_t& ctx, size_t max_frames,
               const module_of_fn& module_of, std::vector<frame_t>& out, std::string* note) {
    out.clear();
    if (max_frames == 0) return false;
    uw_ctx_t u;
    load_ctx(ctx, u);

    // frame 0 is the paused site itself, the same shape rbp_frames returns
    frame_t first;
    first.ret_addr = ctx.rip;
    first.frame_ptr = ctx.rbp;
    out.push_back(first);

    std::set<uint64_t> seen;
    seen.insert(u.rip);
    std::string why = "no .pdata for the first frame";
    while (out.size() < max_frames && u.rip != 0) {
        if (!unwind_one(rdr, module_of, u)) {
            why = "unwind stopped at " + std::to_string(u.rip);
            break;
        }
        if (u.rip == 0) break;
        if (!seen.insert(u.rip).second) {
            why = "unwind cycle at " + std::to_string(u.rip);
            break;
        }
        frame_t f;
        f.ret_addr = u.rip;
        f.frame_ptr = u.reg[5];
        out.push_back(f);
    }
    if (note) *note = why;
    return out.size() > 1;   // only the paused site: no unwind info was usable
}

} // namespace slop::core::debugger::unwind
