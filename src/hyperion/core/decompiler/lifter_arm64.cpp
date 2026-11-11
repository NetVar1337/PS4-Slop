#include "lifter_arm64.h"
#include <capstone/arm64.h>
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <charconv>

namespace hype {

[[maybe_unused]] static constexpr int REG_ARM64_SP = ARM64_REG_SP;
static constexpr int REG_ARM64_XZR = ARM64_REG_XZR;
static constexpr int REG_ARM64_WZR = ARM64_REG_WZR;
[[maybe_unused]] static constexpr int REG_ARM64_NZCV = ARM64_REG_NZCV;

Varnode LifterARM64::reg_vn(int reg_id) {
    if (reg_id == ARM64_REG_INVALID) return vn_const(0);
    if (reg_id == REG_ARM64_XZR || reg_id == REG_ARM64_WZR) return vn_const(0, (reg_id == REG_ARM64_WZR) ? 4 : 8);

    int sz = 8;
    const char* name = "unk";

    if (reg_id >= ARM64_REG_X0 && reg_id <= ARM64_REG_X28) {
        static thread_local char buf[8];
        std::snprintf(buf, sizeof(buf), "x%d", reg_id - ARM64_REG_X0);
        name = buf; sz = 8;
    } else if (reg_id >= ARM64_REG_W0 && reg_id <= ARM64_REG_W30) {
        static thread_local char buf[8];
        std::snprintf(buf, sizeof(buf), "w%d", reg_id - ARM64_REG_W0);
        name = buf; sz = 4;
    } else if (reg_id == ARM64_REG_X29) { name = "x29"; sz = 8; }
    else if (reg_id == ARM64_REG_X30) { name = "x30"; sz = 8; }
    else if (reg_id == ARM64_REG_SP)  { name = "sp";  sz = 8; }
    else if (reg_id == ARM64_REG_WSP) { name = "wsp"; sz = 4; }
    else if (reg_id == ARM64_REG_NZCV) { name = "nzcv"; sz = 4; }
    
    return vn_reg(reg_id, name, sz);
}

Varnode LifterARM64::extend(Varnode v, IndexExt ext, PcodeBlock& out) {
    PcodeOp op = PcodeOp::INT_ZEXT;
    int from = 0;
    switch (ext) {
    case IndexExt::Uxtb: from = 1; break;
    case IndexExt::Uxth: from = 2; break;
    case IndexExt::Uxtw: from = 4; break;
    case IndexExt::Sxtb: from = 1; op = PcodeOp::INT_SEXT; break;
    case IndexExt::Sxth: from = 2; op = PcodeOp::INT_SEXT; break;
    case IndexExt::Sxtw: from = 4; op = PcodeOp::INT_SEXT; break;
    default: return v;   // none / sxtx / uxtx: the full register
    }
    if (v.size > from) {
        Varnode low = alloc_temp(from);
        emit(out, PcodeOp::SUBPIECE, low, {v, vn_const(0)});
        v = low;
    }
    Varnode wide = alloc_temp(8);
    emit(out, op, wide, {v});
    return wide;
}

Varnode LifterARM64::shifted(Varnode v, const Operand& op, PcodeBlock& out) {
    const unsigned amount = op.shift_amount();
    if (!amount) return v;
    PcodeOp p = PcodeOp::SHIFT_LEFT;
    switch (op.shift_kind()) {
    case ShiftKind::Lsl: p = PcodeOp::SHIFT_LEFT; break;
    case ShiftKind::Lsr: p = PcodeOp::SHIFT_RIGHT; break;
    case ShiftKind::Asr: p = PcodeOp::SHIFT_ARIGHT; break;
    case ShiftKind::Ror: p = PcodeOp::ROTATE_RIGHT; break;
    }
    Varnode r = alloc_temp(v.size);
    emit(out, p, r, {v, vn_const(amount)});
    return r;
}

int LifterARM64::mem_operand(const Insn& insn) const {
    for (int i = 0; i < insn.op_count; ++i)
        if (insn.ops[i].type == OpType::Mem) return i;
    return -1;
}

Varnode LifterARM64::mem_address(const Insn& insn, int idx, PcodeBlock& out) {
    const Operand& op = insn.ops[idx];
    Varnode addr = vn_const(0);
    bool has = false;
    if (op.mem.base) {
        addr = reg_vn(op.mem.base);
        has = true;
    }
    // post-index accesses the bare base; the offset only moves the base after
    if (op.post_index()) return addr;
    if (op.mem.index) {
        Varnode idx_vn = extend(reg_vn(op.mem.index), op.mem.ext, out);
        if (op.mem.scale > 1) {
            Varnode t = alloc_temp();
            emit(out, PcodeOp::INT_MULT, t, {idx_vn, vn_const(op.mem.scale)});
            idx_vn = t;
        }
        if (has) {
            Varnode t = alloc_temp();
            emit(out, PcodeOp::ADD, t, {addr, idx_vn});
            addr = t;
        } else { addr = idx_vn; }
        has = true;
    }
    if (op.mem.disp != 0) {
        Varnode d = vn_const(static_cast<u64>(op.mem.disp));
        if (has) {
            Varnode t = alloc_temp();
            emit(out, PcodeOp::ADD, t, {addr, d});
            addr = t;
        } else { addr = d; }
    }
    return addr;
}

void LifterARM64::writeback(const Insn& insn, int idx, PcodeBlock& out) {
    if (idx < 0 || idx >= insn.op_count) return;
    const Operand& op = insn.ops[idx];
    if (!op.writeback() || !op.mem.base) return;
    // pre-index `[x1, #8]!` moves by disp; post-index `[x1], #8` by the
    // trailing immediate (or disp when the decoder folded it in)
    i64 delta = op.mem.disp;
    if (op.post_index()) {
        for (int i = idx + 1; i < insn.op_count; ++i)
            if (insn.ops[i].type == OpType::Imm) { delta = static_cast<i64>(insn.ops[i].val); break; }
    }
    Varnode base = reg_vn(op.mem.base);
    Varnode moved = alloc_temp(base.size);
    emit(out, PcodeOp::ADD, moved, {base, vn_const(static_cast<u64>(delta))});
    emit(out, PcodeOp::COPY, base, {moved});
}

Varnode LifterARM64::operand_read(const Insn& insn, int idx, PcodeBlock& out) {
    if (idx >= insn.op_count) return vn_const(0);
    auto& op = insn.ops[idx];
    switch (op.type) {
    case OpType::Reg:
        return shifted(extend(reg_vn(op.reg), op.mem.ext, out), op, out);
    case OpType::Imm:
        return vn_const(op.val);
    case OpType::Mem: {
        Varnode addr = mem_address(insn, idx, out);
        int sz = op.size / 8;
        if (sz < 1) sz = 8;
        Varnode res = alloc_temp(sz);
        emit(out, PcodeOp::LOAD, res, {addr});
        return res;
    }
    default: return vn_const(0);
    }
}

void LifterARM64::operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out) {
    if (idx >= insn.op_count) return;
    auto& op = insn.ops[idx];
    if (op.type == OpType::Reg) {
        emit(out, PcodeOp::COPY, reg_vn(op.reg), {val});
    } else if (op.type == OpType::Mem) {
        emit(out, PcodeOp::STORE, {}, {mem_address(insn, idx, out), val});
    }
}

Varnode LifterARM64::alloc_temp(int sz) { return vn_temp(next_temp_++, sz); }

void LifterARM64::emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a) {
    PcodeInsn p;
    p.op = op;
    p.output = out;
    p.inputs = std::move(in);
    p.addr = a ? a : cur_addr_;
    p.seq = cur_seq_++;
    b.ops.push_back(std::move(p));
}

void LifterARM64::lift_insn(const Insn& insn, PcodeBlock& blk, const AnalysisDB& db) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    std::string_view mn(insn.mnemonic);

    if (mn == "movk") {
        // Insert the immediate into a 16-bit lane; movk is not an overwrite.
        // The decoder folds `lsl #n` into the value and keeps n in aux
        if (insn.op_count >= 2) {
            Varnode old = operand_read(insn, 0, blk);
            const Operand& imm_op = insn.ops[1];
            const u64 shift = imm_op.type == OpType::Imm ? imm_op.shift_amount() : 0;
            const u64 lane = imm_op.type == OpType::Imm ? (imm_op.val & (u64(0xFFFF) << shift)) : 0;
            Varnode cleared = alloc_temp(old.size);
            emit(blk, PcodeOp::AND, cleared, {old, vn_const(~(u64(0xFFFF) << shift), old.size)});
            Varnode placed = alloc_temp(old.size);
            emit(blk, PcodeOp::OR, placed, {cleared, vn_const(lane, old.size)});
            operand_write(insn, 0, placed, blk);
        }
    } else if (mn == "mov" || mn == "movz" || mn == "movn") {
        Varnode src = operand_read(insn, 1, blk);
        operand_write(insn, 0, src, blk);
    } else if (mn == "add" || mn == "adds") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (insn.op_count == 2) {
            lhs = operand_read(insn, 0, blk);
            rhs = operand_read(insn, 1, blk);
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::ADD, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "sub" || mn == "subs") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (insn.op_count == 2) {
            lhs = operand_read(insn, 0, blk);
            rhs = operand_read(insn, 1, blk);
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::SUB, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "mul" || mn == "madd") {
        Varnode op1 = operand_read(insn, 1, blk);
        Varnode op2 = operand_read(insn, 2, blk);
        Varnode res = alloc_temp(op1.size);
        emit(blk, PcodeOp::INT_MULT, res, {op1, op2});
        if (mn == "madd" && insn.op_count == 4) {
            Varnode op3 = operand_read(insn, 3, blk);
            Varnode res2 = alloc_temp(op1.size);
            emit(blk, PcodeOp::ADD, res2, {op3, res});
            res = res2;
        }
        operand_write(insn, 0, res, blk);
    } else if (mn == "and" || mn == "ands" || mn == "bic" || mn == "bics") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "bic" || mn == "bics") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::AND, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "orr" || mn == "orn") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "orn") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::OR, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "eor" || mn == "eon") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        if (mn == "eon") {
            Varnode not_rhs = alloc_temp(rhs.size);
            emit(blk, PcodeOp::INT_NEGATE, not_rhs, {rhs});
            rhs = not_rhs;
        }
        Varnode res = alloc_temp(lhs.size);
        emit(blk, PcodeOp::XOR, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "lsl" || mn == "lsr" || mn == "asr" || mn == "ror") {
        Varnode lhs = operand_read(insn, 1, blk);
        Varnode rhs = operand_read(insn, 2, blk);
        Varnode res = alloc_temp(lhs.size);
        PcodeOp op = PcodeOp::SHIFT_LEFT;
        if (mn == "lsr") op = PcodeOp::SHIFT_RIGHT;
        else if (mn == "asr") op = PcodeOp::SHIFT_ARIGHT;
        else if (mn == "ror") op = PcodeOp::ROTATE_RIGHT;
        emit(blk, op, res, {lhs, rhs});
        operand_write(insn, 0, res, blk);
    } else if (mn == "ldr" || mn == "ldrb" || mn == "ldrh" || mn == "ldrsw" || mn == "ldrsh" ||
               mn == "ldrsb" || mn == "ldur" || mn == "ldurb" || mn == "ldurh" ||
               mn == "ldursw" || mn == "ldursh" || mn == "ldursb") {
        const int mi = mem_operand(insn);
        Varnode dst = reg_vn(insn.ops[0].reg);
        if (mi < 0) {
            // literal form: the decoder resolved the pool address
            Varnode res = alloc_temp(dst.size);
            emit(blk, PcodeOp::LOAD, res, {operand_read(insn, 1, blk)});
            operand_write(insn, 0, res, blk);
            return;
        }
        const bool sx = mn.find("ldrs") == 0 || mn.find("ldurs") == 0;
        int sz = dst.size;
        if (mn.back() == 'b') sz = 1;
        else if (mn.back() == 'h') sz = 2;
        else if (mn.back() == 'w' && sx) sz = 4;
        Varnode res = alloc_temp(sz);
        emit(blk, PcodeOp::LOAD, res, {mem_address(insn, mi, blk)});
        if (sz < dst.size) {
            Varnode wide = alloc_temp(dst.size);
            emit(blk, sx ? PcodeOp::INT_SEXT : PcodeOp::INT_ZEXT, wide, {res});
            res = wide;
        }
        operand_write(insn, 0, res, blk);
        writeback(insn, mi, blk);
    } else if (mn == "str" || mn == "strb" || mn == "strh" ||
               mn == "stur" || mn == "sturb" || mn == "sturh") {
        const int mi = mem_operand(insn);
        Varnode val = operand_read(insn, 0, blk);
        const int sz = mn.back() == 'b' ? 1 : mn.back() == 'h' ? 2 : 0;
        if (sz && val.size > sz) {
            Varnode low = alloc_temp(sz);
            emit(blk, PcodeOp::SUBPIECE, low, {val, vn_const(0)});
            val = low;
        }
        if (mi >= 0) {
            emit(blk, PcodeOp::STORE, {}, {mem_address(insn, mi, blk), val});
            writeback(insn, mi, blk);
        }
    } else if (mn == "ldp" || mn == "ldpsw" || mn == "stp") {
        const int mi = mem_operand(insn);
        if (mi >= 0) {
            Varnode addr = mem_address(insn, mi, blk);
            const bool load = mn != "stp";
            // pair element size follows the register width (ldpsw: 4)
            const int sz = mn == "ldpsw" ? 4 : reg_vn(insn.ops[0].reg).size;
            Varnode addr2 = alloc_temp();
            emit(blk, PcodeOp::ADD, addr2, {addr, vn_const(static_cast<u64>(sz))});
            for (int r = 0; r < 2; ++r) {
                Varnode at = r == 0 ? addr : addr2;
                if (load) {
                    Varnode v = alloc_temp(sz);
                    emit(blk, PcodeOp::LOAD, v, {at});
                    Varnode dst = reg_vn(insn.ops[r].reg);
                    if (sz < dst.size) {
                        Varnode wide = alloc_temp(dst.size);
                        emit(blk, PcodeOp::INT_SEXT, wide, {v});
                        v = wide;
                    }
                    operand_write(insn, r, v, blk);
                } else {
                    emit(blk, PcodeOp::STORE, {}, {at, operand_read(insn, r, blk)});
                }
            }
            writeback(insn, mi, blk);
        }
    } else if (mn == "cmp" || mn == "cmn" || mn == "tst" || mn == "subs" || mn == "adds") {
        // Emit NZCV-equivalent flags so b.cond conditions have real inputs.
        Varnode lhs = operand_read(insn, 0, blk);
        Varnode rhs = operand_read(insn, 1, blk);
        Varnode result = alloc_temp(lhs.size);
        emit(blk, mn == "cmn" || mn == "adds" ? PcodeOp::ADD : PcodeOp::SUB, result, {lhs, rhs});

        auto zf = vn_reg(100, "ZF", 1);
        auto sf = vn_reg(102, "NF", 1);
        auto vf = vn_reg(103, "VF", 1);
        auto cf = vn_reg(101, "CF", 1);
        emit(blk, PcodeOp::INT_EQUAL, zf, {result, vn_const(0, lhs.size)});
        emit(blk, PcodeOp::INT_SLESS, sf, {result, vn_const(0, lhs.size)});
        Varnode x1 = alloc_temp(lhs.size);
        emit(blk, PcodeOp::XOR, x1, {lhs, rhs});
        Varnode x2 = alloc_temp(lhs.size);
        emit(blk, PcodeOp::XOR, x2, {lhs, result});
        Varnode both = alloc_temp(lhs.size);
        emit(blk, PcodeOp::AND, both, {x1, x2});
        emit(blk, PcodeOp::INT_SLESS, vf, {both, vn_const(0, lhs.size)});
        // ARM64 carry out of SUB is "no borrow" (inverted vs x86).
        if (mn == "cmn" || mn == "adds") {
            emit(blk, PcodeOp::INT_LESS, cf, {result, lhs});
        } else {
            Varnode ncarry = alloc_temp(1);
            emit(blk, PcodeOp::INT_LESS, ncarry, {lhs, rhs});
            emit(blk, PcodeOp::BOOL_NOT, cf, {ncarry});
        }

        if (mn == "subs" || mn == "adds")
            operand_write(insn, 0, result, blk);
    } else if (mn == "cbz" || mn == "cbnz") {
        va_t target = insn.branch_target();
        Varnode cond = alloc_temp(1);
        Varnode reg = operand_read(insn, 0, blk);
        emit(blk, mn == "cbz" ? PcodeOp::INT_EQUAL : PcodeOp::INT_NEQUAL, cond, {reg, vn_const(0, reg.size)});
        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(target), cond});
    } else if (mn == "b") {
        emit(blk, PcodeOp::BRANCH, {}, {vn_const(insn.branch_target())});
    } else if (mn.starts_with("b.")) {
        std::string_view cond_str = mn.substr(2);
        auto zf = vn_reg(100, "ZF", 1);
        auto nf = vn_reg(102, "NF", 1);
        auto vf = vn_reg(103, "VF", 1);
        auto cf = vn_reg(101, "CF", 1);
        const auto not_v = [&](const Varnode& v) {
            Varnode t = alloc_temp(1);
            emit(blk, PcodeOp::BOOL_NOT, t, {v});
            return t;
        };
        const auto neq_v = [&](const Varnode& a, const Varnode& b) {
            Varnode t = alloc_temp(1);
            emit(blk, PcodeOp::INT_NEQUAL, t, {a, b});
            return t;
        };
        const auto eq_v = [&](const Varnode& a, const Varnode& b) {
            Varnode t = alloc_temp(1);
            emit(blk, PcodeOp::INT_EQUAL, t, {a, b});
            return t;
        };
        const auto or_v = [&](const Varnode& a, const Varnode& b) {
            Varnode t = alloc_temp(1);
            emit(blk, PcodeOp::BOOL_OR, t, {a, b});
            return t;
        };

        Varnode cond;
        if (cond_str == "eq") cond = zf;
        else if (cond_str == "ne") cond = not_v(zf);
        else if (cond_str == "lt") cond = neq_v(nf, vf);
        else if (cond_str == "ge") cond = eq_v(nf, vf);
        else if (cond_str == "le") cond = or_v(zf, neq_v(nf, vf));
        else if (cond_str == "gt") cond = not_v(or_v(zf, neq_v(nf, vf)));
        else if (cond_str == "mi") cond = nf;
        else if (cond_str == "pl") cond = not_v(nf);
        else if (cond_str == "vs") cond = vf;
        else if (cond_str == "vc") cond = not_v(vf);
        else if (cond_str == "hs" || cond_str == "cs") cond = cf;
        else if (cond_str == "lo" || cond_str == "cc") cond = not_v(cf);
        else if (cond_str == "hi") cond = not_v(or_v(cf, zf));
        else if (cond_str == "ls") cond = or_v(cf, zf);
        else cond = zf;  // unhandled condition: branch stays visible

        emit(blk, PcodeOp::CBRANCH, {}, {vn_const(insn.branch_target()), cond});
    } else if (mn == "bl" || mn == "blr") {
        va_t target = insn.branch_target();
        Varnode fn_addr = vn_const(target);
        if (target) {
            auto it = db.names.find(target);
            if (it != db.names.end()) fn_addr.name = it->second;
        }
        emit(blk, PcodeOp::CALL, reg_vn(ARM64_REG_X0), {fn_addr,
            reg_vn(ARM64_REG_X0), reg_vn(ARM64_REG_X1), reg_vn(ARM64_REG_X2), reg_vn(ARM64_REG_X3),
            reg_vn(ARM64_REG_X4), reg_vn(ARM64_REG_X5), reg_vn(ARM64_REG_X6), reg_vn(ARM64_REG_X7)});
    } else if (mn == "ret") {
        blk.has_return = true;
        emit(blk, PcodeOp::RETURN, {}, {reg_vn(ARM64_REG_X0)});
    } else if (mn == "adr" || mn == "adrp") {
        operand_write(insn, 0, vn_const(insn.ops[1].val), blk);
    } else if (mn == "nop") {
    } else {
        // Unsupported: keep visible instead of deleting semantics.
        Varnode intrinsic;
        intrinsic.kind = VarnodeKind::Temp;
        intrinsic.id = next_temp_++;
        intrinsic.size = 8;
        intrinsic.name = fmt::format("__asm {{ {} {} }}", insn.mnemonic, insn.op_str);
        Varnode result = alloc_temp(8);
        emit(blk, PcodeOp::INTRINSIC, result, {intrinsic});
    }
}

void LifterARM64::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    for (auto& insn : bb.insns)
        lift_insn(insn, out, db);
}

PcodeFunc LifterARM64::lift(const Function& func, const AnalysisDB& db) {
    next_temp_ = 256;

    PcodeFunc pf;
    pf.entry = func.entry;
    pf.name = func.name.empty() ? default_func_name(func.entry) : func.name;

    std::vector<va_t> order;
    for (auto& [addr, _] : func.blocks)
        order.push_back(addr);
    std::sort(order.begin(), order.end());

    for (int i = 0; i < (int)order.size(); ++i)
        addr_to_block_[order[i]] = i;

    for (int i = 0; i < (int)order.size(); ++i) {
        auto it = func.blocks.find(order[i]);
        if (it == func.blocks.end()) continue;
        PcodeBlock blk;
        blk.id = i;
        lift_block(it->second, db, blk);

        for (va_t s : it->second.succs) {
            auto sit = addr_to_block_.find(s);
            if (sit != addr_to_block_.end())
                blk.succs.push_back(sit->second);
        }
        pf.blocks.push_back(std::move(blk));
    }

    for (int i = 0; i < (int)pf.blocks.size(); ++i) {
        for (int s : pf.blocks[i].succs)
            if (s >= 0 && s < (int)pf.blocks.size())
                pf.blocks[s].preds.push_back(i);
    }

    pf.next_temp = next_temp_;
    pf.params = {
        reg_vn(ARM64_REG_X0), reg_vn(ARM64_REG_X1),
        reg_vn(ARM64_REG_X2), reg_vn(ARM64_REG_X3),
        reg_vn(ARM64_REG_X4), reg_vn(ARM64_REG_X5),
        reg_vn(ARM64_REG_X6), reg_vn(ARM64_REG_X7)
    };

    addr_to_block_.clear();
    return pf;
}

}
