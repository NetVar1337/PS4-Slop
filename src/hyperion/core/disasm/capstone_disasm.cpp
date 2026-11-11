#include "capstone_disasm.h"
#include <capstone/capstone.h>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace hype {

struct CapstoneDisasm::Impl {
    csh handle = 0;
    bool open = false;
    // ARM only: a second handle in Thumb mode, chosen per decode
    csh thumb_handle = 0;
    bool thumb_open = false;
    bool thumb_default = false;
    Arch arch = Arch::ARM64;

    void close() {
        if (open) cs_close(&handle);
        if (thumb_open) cs_close(&thumb_handle);
        open = thumb_open = false;
    }
};

CapstoneDisasm::CapstoneDisasm() : impl_(std::make_unique<Impl>()) {}

CapstoneDisasm::~CapstoneDisasm() {
    impl_->close();
}

void CapstoneDisasm::set_arch(Arch arch, bool thumb) {
    impl_->close();

    impl_->arch = arch;
    impl_->thumb_default = arch == Arch::ARM && thumb;
    cs_arch cs_a = CS_ARCH_ARM64;
    cs_mode cs_m = CS_MODE_ARM;

    switch (arch) {
    case Arch::ARM64:
        cs_a = CS_ARCH_ARM64;
        cs_m = CS_MODE_ARM;
        break;
    case Arch::ARM:
        cs_a = CS_ARCH_ARM;
        cs_m = CS_MODE_ARM;
        break;
    case Arch::MIPS:
        cs_a = CS_ARCH_MIPS;
        cs_m = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
        break;
    case Arch::PPC:
        cs_a = CS_ARCH_PPC;
        cs_m = CS_MODE_64;
        break;
    case Arch::X64:
        cs_a = CS_ARCH_X86;
        cs_m = CS_MODE_64;
        break;
    case Arch::X86:
        cs_a = CS_ARCH_X86;
        cs_m = CS_MODE_32;
        break;
    }

    impl_->open = (cs_open(cs_a, cs_m, &impl_->handle) == CS_ERR_OK);
    if (impl_->open)
        cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (arch == Arch::ARM) {
        // Thumb-2 (CS_MODE_THUMB decodes both 16- and 32-bit encodings)
        impl_->thumb_open = (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &impl_->thumb_handle) == CS_ERR_OK);
        if (impl_->thumb_open)
            cs_option(impl_->thumb_handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

static u8 arm64_shift(const cs_arm64_op& cop) {
    if (cop.shift.value == 0) return 0;
    switch (cop.shift.type) {
    case ARM64_SFT_LSL: return Operand::pack_shift(ShiftKind::Lsl, cop.shift.value);
    case ARM64_SFT_LSR: return Operand::pack_shift(ShiftKind::Lsr, cop.shift.value);
    case ARM64_SFT_ASR: return Operand::pack_shift(ShiftKind::Asr, cop.shift.value);
    case ARM64_SFT_ROR: return Operand::pack_shift(ShiftKind::Ror, cop.shift.value);
    default:            return 0;   // MSL (vector immediates) is not a register shift
    }
}

static IndexExt arm64_ext(arm64_extender e) {
    switch (e) {
    case ARM64_EXT_UXTB: return IndexExt::Uxtb;
    case ARM64_EXT_UXTH: return IndexExt::Uxth;
    case ARM64_EXT_UXTW: return IndexExt::Uxtw;
    case ARM64_EXT_SXTB: return IndexExt::Sxtb;
    case ARM64_EXT_SXTH: return IndexExt::Sxth;
    case ARM64_EXT_SXTW: return IndexExt::Sxtw;
    case ARM64_EXT_SXTX: return IndexExt::Sxtx;
    default:             return IndexExt::None;   // uxtx / lsl: value used as is
    }
}

static u8 arm_shift(const cs_arm_op& cop) {
    // register-shifted-by-register forms keep the register out of the byte
    if (cop.shift.value == 0 || cop.shift.type >= ARM_SFT_ASR_REG) return 0;
    switch (cop.shift.type) {
    case ARM_SFT_LSL: return Operand::pack_shift(ShiftKind::Lsl, cop.shift.value);
    case ARM_SFT_LSR: return Operand::pack_shift(ShiftKind::Lsr, cop.shift.value);
    case ARM_SFT_ASR: return Operand::pack_shift(ShiftKind::Asr, cop.shift.value);
    case ARM_SFT_ROR: return Operand::pack_shift(ShiftKind::Ror, cop.shift.value);
    default:          return 0;
    }
}

static InsnType classify_groups(cs_insn* insn) {
    if (!insn->detail) return InsnType::Other;
    cs_detail* d = insn->detail;

    for (u8 i = 0; i < d->groups_count; ++i) {
        switch (d->groups[i]) {
        case CS_GRP_CALL:      return InsnType::Call;
        case CS_GRP_RET:
        case CS_GRP_IRET:      return InsnType::Ret;
        case CS_GRP_JUMP:      return InsnType::Jmp;
        case CS_GRP_INT:       return InsnType::Int;
        default: break;
        }
    }

    const char* mn = insn->mnemonic;
    if (mn[0] == 'n' && mn[1] == 'o' && mn[2] == 'p') return InsnType::Nop;
    if (mn[0] == 'b' && mn[1] == '.' )                 return InsnType::Jcc;
    if (mn[0] == 'c' && mn[1] == 'b')                  return InsnType::Jcc;
    if (mn[0] == 't' && mn[1] == 'b')                  return InsnType::Jcc;

    return InsnType::Other;
}

static va_t extract_branch_target(cs_insn* insn, Arch arch) {
    if (!insn->detail) return 0;
    cs_detail* d = insn->detail;

    switch (arch) {
    case Arch::ARM64: {
        auto& arm64 = d->arm64;
        for (u8 i = 0; i < arm64.op_count; ++i) {
            if (arm64.operands[i].type == ARM64_OP_IMM)
                return static_cast<va_t>(arm64.operands[i].imm);
        }
        break;
    }
    case Arch::ARM: {
        auto& arm = d->arm;
        for (u8 i = 0; i < arm.op_count; ++i) {
            if (arm.operands[i].type == ARM_OP_IMM)
                return static_cast<va_t>(arm.operands[i].imm);
        }
        break;
    }
    case Arch::MIPS: {
        auto& mips = d->mips;
        for (u8 i = 0; i < mips.op_count; ++i) {
            if (mips.operands[i].type == MIPS_OP_IMM)
                return static_cast<va_t>(mips.operands[i].imm);
        }
        break;
    }
    case Arch::PPC: {
        auto& ppc = d->ppc;
        for (u8 i = 0; i < ppc.op_count; ++i) {
            if (ppc.operands[i].type == PPC_OP_IMM)
                return static_cast<va_t>(ppc.operands[i].imm);
        }
        break;
    }
    default: break;
    }
    return 0;
}

bool CapstoneDisasm::decode(va_t addr, const u8* data, size_t len, Insn& out) {
    if (!impl_->open) return false;

    // ARM interworking convention: bit 0 of the address selects Thumb
    csh handle = impl_->handle;
    if (impl_->arch == Arch::ARM && impl_->thumb_open && (impl_->thumb_default || (addr & 1))) {
        handle = impl_->thumb_handle;
        addr &= ~va_t(1);
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, data, len, addr, 1, &insn);
    if (count == 0) return false;

    out.addr = addr;
    out.len = static_cast<u8>(insn->size);
    std::memcpy(out.bytes, insn->bytes, (insn->size < 15) ? insn->size : 15);
    out.set_mnemonic(insn->mnemonic);
    out.set_op_str(insn->op_str);
    out.mnemonic_id = static_cast<u16>(insn->id);
    std::fill(std::begin(out.ops), std::end(out.ops), Operand{});

    InsnType t = classify_groups(insn);
    if (t == InsnType::Jmp) {
        bool conditional = false;
        if (insn->detail) {
            for (u8 i = 0; i < insn->detail->groups_count; ++i) {
                if (insn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                    const char* mn = insn->mnemonic;
                    if (mn[0] == 'b' && mn[1] == '.') conditional = true;
                    if (mn[0] == 'c' && mn[1] == 'b') conditional = true;
                    if (mn[0] == 't' && mn[1] == 'b') conditional = true;
                    if (mn[0] == 'b' && mn[1] != '\0' && mn[1] != 'l' && mn[1] != 'r')
                        conditional = true;
                    break;
                }
            }
        }
        if (conditional) t = InsnType::Jcc;
    }
    out.type = t;

    constexpr u8 kMaxOps = static_cast<u8>(sizeof(out.ops) / sizeof(out.ops[0]));
    out.op_count = 0;
    out.ops_total = 0;
    if (insn->detail) {
        cs_detail* d = insn->detail;
        if (impl_->arch == Arch::ARM64) {
            auto& arm64 = d->arm64;
            out.ops_total = arm64.op_count;
            out.op_count = (std::min)(arm64.op_count, kMaxOps);
            for (u8 i = 0; i < out.op_count; ++i) {
                auto& cop = arm64.operands[i];
                auto& oop = out.ops[i];
                oop.read = (cop.access & CS_AC_READ) != 0;
                oop.write = (cop.access & CS_AC_WRITE) != 0;
                switch (cop.type) {
                case ARM64_OP_REG:
                    oop.type = OpType::Reg;
                    oop.reg = static_cast<u16>(cop.reg);
                    oop.aux = arm64_shift(cop);
                    oop.mem.ext = arm64_ext(cop.ext);
                    // `add x0, x1, w2, uxtw #2`: the extend's shift rides
                    // as an LSL on the same operand
                    if (cop.ext != ARM64_EXT_INVALID && cop.shift.value && !oop.aux)
                        oop.aux = Operand::pack_shift(ShiftKind::Lsl, cop.shift.value);
                    break;
                case ARM64_OP_IMM:
                case ARM64_OP_CIMM:
                    oop.type = OpType::Imm;
                    oop.val = static_cast<u64>(cop.imm);
                    // `movz x0, #1, lsl #16` / `add x0, x1, #1, lsl #12`:
                    // val is the effective value, aux keeps the lane shift
                    // (movk needs it to know which 16 bits it replaces)
                    if (cop.shift.type == ARM64_SFT_LSL && cop.shift.value) {
                        oop.val <<= cop.shift.value;
                        oop.aux = Operand::pack_shift(ShiftKind::Lsl, cop.shift.value);
                    }
                    break;
                case ARM64_OP_MEM:
                    oop.type = OpType::Mem;
                    oop.mem.base = static_cast<u16>(cop.mem.base);
                    oop.mem.index = static_cast<u16>(cop.mem.index);
                    oop.mem.disp = cop.mem.disp;
                    if (cop.mem.index) {
                        oop.mem.scale = static_cast<u8>(1u << (cop.shift.value & 7));
                        oop.mem.ext = arm64_ext(cop.ext);
                    }
                    if (arm64.writeback)
                        oop.aux = static_cast<u8>(Operand::kWriteback |
                                                  (arm64.post_index ? Operand::kPostIndex : 0));
                    break;
                default:
                    oop.type = OpType::None;
                    break;
                }
            }
        } else if (impl_->arch == Arch::ARM) {
            auto& arm = d->arm;
            out.ops_total = arm.op_count;
            out.op_count = (std::min)(arm.op_count, kMaxOps);
            for (u8 i = 0; i < out.op_count; ++i) {
                auto& cop = arm.operands[i];
                auto& oop = out.ops[i];
                oop.read = (cop.access & CS_AC_READ) != 0;
                oop.write = (cop.access & CS_AC_WRITE) != 0;
                switch (cop.type) {
                case ARM_OP_REG:
                    oop.type = OpType::Reg;
                    oop.reg = static_cast<u16>(cop.reg);
                    oop.aux = arm_shift(cop);
                    break;
                case ARM_OP_IMM:
                case ARM_OP_CIMM:
                case ARM_OP_PIMM:
                    oop.type = OpType::Imm;
                    oop.val = static_cast<u64>(cop.imm);
                    break;
                case ARM_OP_MEM:
                    oop.type = OpType::Mem;
                    oop.mem.base = static_cast<u16>(cop.mem.base);
                    oop.mem.index = static_cast<u16>(cop.mem.index);
                    oop.mem.disp = cop.mem.disp;
                    if (cop.mem.index) {
                        oop.mem.scale = static_cast<u8>(1u << (cop.mem.lshift & 7));
                        if (cop.mem.scale < 0) oop.mem.ext = IndexExt::Neg;
                    }
                    if (arm.writeback)
                        oop.aux = static_cast<u8>(Operand::kWriteback |
                                                  (arm.post_index ? Operand::kPostIndex : 0));
                    break;
                default:
                    oop.type = OpType::None;
                    break;
                }
            }
        }
        // Add more architectures here as needed
    }

    if (out.op_count == 0) {
        va_t target = extract_branch_target(insn, impl_->arch);
        if (target && (t == InsnType::Call || t == InsnType::Jmp || t == InsnType::Jcc)) {
            out.ops[0].type = OpType::Imm;
            out.ops[0].val = target;
            out.op_count = 1;
            out.ops_total = 1;
        }
    }

    cs_free(insn, count);
    return true;
}

std::vector<Insn> CapstoneDisasm::decode_range(va_t start, const u8* data, size_t len) {
    return decode_range(start, data, len, nullptr);
}

std::vector<Insn> CapstoneDisasm::decode_range(va_t start, const u8* data, size_t len,
                                               const std::function<bool()>& cancelled) {
    std::vector<Insn> result;
    result.reserve(len / 4);
    // an odd ARM start keeps every decode in the range in Thumb mode
    const bool thumb_bit = impl_->arch == Arch::ARM && (start & 1);
    const va_t base = thumb_bit ? (start & ~va_t(1)) : start;
    const bool thumb = thumb_bit || (impl_->arch == Arch::ARM && impl_->thumb_default);
    size_t off = 0;
    size_t last_probe = 0;
    while (off < len) {
        if (cancelled && off - last_probe >= 4096) {
            last_probe = off;
            if (cancelled()) break;
        }
        Insn insn{};
        if (decode((base + off) | (thumb_bit ? 1 : 0), data + off, len - off, insn)) {
            off += insn.len;
            result.push_back(std::move(insn));
        } else {
            // undecodable: one byte, or one halfword so Thumb stays aligned
            const size_t step = thumb ? (std::min<size_t>)(2, len - off) : 1;
            Insn bad{};
            bad.addr = base + off;
            bad.len = static_cast<u8>(step);
            bad.type = InsnType::Unknown;
            std::memcpy(bad.bytes, data + off, step);
            bad.set_mnemonic("db");
            char tmp[16];
            std::snprintf(tmp, sizeof(tmp), "0x%02X", data[off]);
            bad.set_op_str(tmp);
            result.push_back(std::move(bad));
            off += step;
        }
    }
    return result;
}

}
