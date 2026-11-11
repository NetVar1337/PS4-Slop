#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <functional>

namespace hype {

enum class InsnType : u8 {
    Unknown, Nop, Mov, Push, Pop,
    Call, Ret, Jmp, Jcc,
    Cmp, Test, Setcc,
    Add, Sub, Mul, Div, Imul, Idiv,
    Inc, Dec,
    And, Or, Xor, Not, Shl, Shr, Sar, Rol, Ror,
    Lea, Int, Syscall, Movsx, Movzx, Other
};

enum class OpType : u8 { None, Reg, Imm, Mem };

// ARM register-operand shift (`x2, lsl #3`)
enum class ShiftKind : u8 { Lsl = 0, Lsr = 1, Asr = 2, Ror = 3 };

// ARM operand extension: a memory index (`[x0, w1, sxtw #2]`, A32 `[r1, -r2]`
// is Neg) or an ARM64 extended-register operand (`add x0, x1, w2, uxtb`),
// kept in mem.ext for both since a Reg operand leaves mem unused
enum class IndexExt : u8 { None = 0, Uxtw, Sxtw, Sxtx, Neg, Uxtb, Uxth, Sxtb, Sxth };

// Field order is chosen for size, not readability: the natural ordering pads
// this out to 40 bytes, and an Insn carries five of them for every decoded
// instruction in the image. Keeping the 8-byte members first packs it to 32
struct Operand {
    u64    val  = 0;
    // scale multiplies index (x86 SIB scale; ARM `lsl #n` as 1 << n)
    struct { i64 disp; u16 base; u16 index; u8 scale; IndexExt ext; } mem{};
    u16    reg  = 0;
    u16    size = 0;
    OpType type = OpType::None;
    bool   read = false;
    bool   write = false;
    // Reg: ARM shift, amount in the low 6 bits (0 = none), ShiftKind in the
    // top 2. Imm: same packing, the LSL already folded into val (ARM64
    // `movz/movk/add #imm, lsl #n`). Mem: kWriteback / kPostIndex
    // (ARM `[x1, #8]!` / `[x1], #8`)
    u8     aux = 0;

    static constexpr u8 kWriteback = 0x01;
    static constexpr u8 kPostIndex = 0x02;

    static u8 pack_shift(ShiftKind k, unsigned amount) {
        return static_cast<u8>((static_cast<unsigned>(k) << 6) | (amount & 0x3F));
    }
    unsigned  shift_amount() const { return type == OpType::Mem ? 0u : (aux & 0x3Fu); }
    ShiftKind shift_kind()   const { return static_cast<ShiftKind>(aux >> 6); }
    bool writeback()  const { return type == OpType::Mem && (aux & kWriteback); }
    bool post_index() const { return type == OpType::Mem && (aux & kPostIndex); }
};
static_assert(sizeof(Operand) == 32, "Operand is stored per instruction, keep it packed");

// Also ordered for size — an image with tens of millions of instructions
// keeps one of these per instruction in the DB and another per basic block
struct Insn {
    va_t        addr;
    Operand     ops[5]; // Includes the mask and trailing immediate of AVX-512.
    char        op_str[63];
    // operands the decoder reported; above 5 (ARM register lists, NEON
    // table lookups) only the first 5 are in ops[], op_str has them all
    u8          ops_total;
    char        mnemonic[12];
    u8          bytes[15];
    u8          len;
    InsnType    type;
    u8          op_count;
    u16         mnemonic_id;

    bool ops_truncated() const { return ops_total > op_count; }

    void set_mnemonic(const char* s) {
        std::strncpy(mnemonic, s, sizeof(mnemonic) - 1);
        mnemonic[sizeof(mnemonic) - 1] = '\0';
    }
    void set_mnemonic(const std::string& s) { set_mnemonic(s.c_str()); }

    void set_op_str(const char* s) {
        std::strncpy(op_str, s, sizeof(op_str) - 1);
        op_str[sizeof(op_str) - 1] = '\0';
    }
    void set_op_str(const std::string& s) { set_op_str(s.c_str()); }

    bool is_branch()   const { return type == InsnType::Jmp || type == InsnType::Jcc; }
    bool is_call()     const { return type == InsnType::Call; }
    bool is_ret()      const { return type == InsnType::Ret; }
    bool is_cond_jmp() const { return type == InsnType::Jcc; }

    va_t branch_target() const {
        if (op_count > 0 && ops[0].type == OpType::Imm)
            return ops[0].val;
        return 0;
    }
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    void set_arch(Arch arch);
    // want_text=false skips the Zydis formatter (mnemonic comes from the
    // enum name table, op_str stays empty). Analysis decodes every
    // instruction in the image and never reads the text; formatting there
    // is pure overhead. Display/decompile paths keep the default.
    bool decode(va_t addr, const u8* data, size_t len, Insn& out, bool want_text = true);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len);
    // Cancellation-aware variant: probes the predicate every 4 KiB of input
    // so a section sweep can be interrupted between chunks, not after it.
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len,
                                   const std::function<bool()>& cancelled);
    // Re-render "mnemonic operands" for an instruction decoded with
    // want_text=false (analysis builds skip operand text). Decompiler
    // fallbacks use it so unlifted instructions still show their operands.
    static std::string format_text(const Insn& insn, Arch arch);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
