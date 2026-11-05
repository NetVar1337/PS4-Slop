//! Host-side x86-64 Intel-syntax assembler built on `iced-x86`'s `BlockEncoder`.
//!
//! Pure, deterministic, `#![forbid(unsafe_code)]`, with zero console access.
//! Supports multi-statement listings separated by `;` or newlines, local labels
//! (`loop:`, `.next:`), raw byte directives (`db`), RIP-relative addressing,
//! sized memory operands (`byte/word/dword/qword/xmmword ptr [...]`), and common
//! general-purpose / control-flow / bit / string / SSE instructions used in
//! dynamic patching and code caves on PS4 (x86-64 System V / Orbis ABI).

use crate::{Result, disasm};
use anyhow::{anyhow, bail, ensure};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand,
    Register,
};
use serde_json::{Value, json};
use std::collections::HashMap;

pub const MAX_ASM_STATEMENTS: usize = 256;
pub const MAX_ASM_BYTES: usize = 4096;

#[derive(Debug, Clone)]
enum Op {
    Reg(Register, u8), // register + bit width (8, 16, 32, 64, 128)
    Imm(i128),
    Sym(String),
    Mem {
        size_bits: Option<u16>,
        segment: Register,
        base: Register,
        index: Register,
        scale: u32,
        disp: i64,
        rip_target: Option<u64>,
        rip_sym: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum Stmt {
    Label(String),
    Bytes(Vec<u8>),
    Insn {
        mnemonic: String,
        ops: Vec<Op>,
        rep: Option<&'static str>,
    },
}

fn parse_register(token: &str) -> Option<(Register, u8)> {
    Some(match token.to_ascii_lowercase().as_str() {
        "rax" => (Register::RAX, 64),
        "rbx" => (Register::RBX, 64),
        "rcx" => (Register::RCX, 64),
        "rdx" => (Register::RDX, 64),
        "rsi" => (Register::RSI, 64),
        "rdi" => (Register::RDI, 64),
        "rbp" => (Register::RBP, 64),
        "rsp" => (Register::RSP, 64),
        "r8" => (Register::R8, 64),
        "r9" => (Register::R9, 64),
        "r10" => (Register::R10, 64),
        "r11" => (Register::R11, 64),
        "r12" => (Register::R12, 64),
        "r13" => (Register::R13, 64),
        "r14" => (Register::R14, 64),
        "r15" => (Register::R15, 64),
        "eax" => (Register::EAX, 32),
        "ebx" => (Register::EBX, 32),
        "ecx" => (Register::ECX, 32),
        "edx" => (Register::EDX, 32),
        "esi" => (Register::ESI, 32),
        "edi" => (Register::EDI, 32),
        "ebp" => (Register::EBP, 32),
        "esp" => (Register::ESP, 32),
        "r8d" => (Register::R8D, 32),
        "r9d" => (Register::R9D, 32),
        "r10d" => (Register::R10D, 32),
        "r11d" => (Register::R11D, 32),
        "r12d" => (Register::R12D, 32),
        "r13d" => (Register::R13D, 32),
        "r14d" => (Register::R14D, 32),
        "r15d" => (Register::R15D, 32),
        "ax" => (Register::AX, 16),
        "bx" => (Register::BX, 16),
        "cx" => (Register::CX, 16),
        "dx" => (Register::DX, 16),
        "si" => (Register::SI, 16),
        "di" => (Register::DI, 16),
        "bp" => (Register::BP, 16),
        "sp" => (Register::SP, 16),
        "r8w" => (Register::R8W, 16),
        "r9w" => (Register::R9W, 16),
        "r10w" => (Register::R10W, 16),
        "r11w" => (Register::R11W, 16),
        "r12w" => (Register::R12W, 16),
        "r13w" => (Register::R13W, 16),
        "r14w" => (Register::R14W, 16),
        "r15w" => (Register::R15W, 16),
        "al" => (Register::AL, 8),
        "bl" => (Register::BL, 8),
        "cl" => (Register::CL, 8),
        "dl" => (Register::DL, 8),
        "sil" => (Register::SIL, 8),
        "dil" => (Register::DIL, 8),
        "bpl" => (Register::BPL, 8),
        "spl" => (Register::SPL, 8),
        "ah" => (Register::AH, 8),
        "bh" => (Register::BH, 8),
        "ch" => (Register::CH, 8),
        "dh" => (Register::DH, 8),
        "r8b" => (Register::R8L, 8),
        "r9b" => (Register::R9L, 8),
        "r10b" => (Register::R10L, 8),
        "r11b" => (Register::R11L, 8),
        "r12b" => (Register::R12L, 8),
        "r13b" => (Register::R13L, 8),
        "r14b" => (Register::R14L, 8),
        "r15b" => (Register::R15L, 8),
        "xmm0" => (Register::XMM0, 128),
        "xmm1" => (Register::XMM1, 128),
        "xmm2" => (Register::XMM2, 128),
        "xmm3" => (Register::XMM3, 128),
        "xmm4" => (Register::XMM4, 128),
        "xmm5" => (Register::XMM5, 128),
        "xmm6" => (Register::XMM6, 128),
        "xmm7" => (Register::XMM7, 128),
        "xmm8" => (Register::XMM8, 128),
        "xmm9" => (Register::XMM9, 128),
        "xmm10" => (Register::XMM10, 128),
        "xmm11" => (Register::XMM11, 128),
        "xmm12" => (Register::XMM12, 128),
        "xmm13" => (Register::XMM13, 128),
        "xmm14" => (Register::XMM14, 128),
        "xmm15" => (Register::XMM15, 128),
        _ => return None,
    })
}

fn parse_int(text: &str) -> Option<i128> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (neg, rest) = if let Some(r) = trimmed.strip_prefix('-') {
        (true, r.trim())
    } else if let Some(r) = trimmed.strip_prefix('+') {
        (false, r.trim())
    } else {
        (false, trimmed)
    };
    let clean = rest.replace('_', "");
    let val = if let Some(hex_str) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        u64::from_str_radix(hex_str, 16).ok()? as i128
    } else if let Some(hex_str) = clean.strip_suffix('h').or_else(|| clean.strip_suffix('H')) {
        if hex_str.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
            u64::from_str_radix(hex_str, 16).ok()? as i128
        } else {
            return None;
        }
    } else {
        clean.parse::<u64>().ok()? as i128
    };
    Some(if neg { -val } else { val })
}

fn is_ident(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_alphabetic() || matches!(bytes[0], b'_' | b'.' | b'$' | b'@'))
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'.' | b'$' | b'@'))
}

fn split_operands(rest: &str) -> Result<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                ensure!(depth >= 0, "Unmatched ']' in operand");
            }
            ',' if depth == 0 => {
                let part = rest[start..idx].trim();
                ensure!(!part.is_empty(), "Empty operand");
                out.push(part);
                start = idx + 1;
            }
            _ => {}
        }
    }
    ensure!(depth == 0, "Unclosed '[' in operand");
    let tail = rest[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    Ok(out)
}

fn parse_mem(raw: &str) -> Result<Op> {
    let mut text = raw.trim();
    let mut size_bits = None;
    for (prefix, bits) in [
        ("byte", 8u16),
        ("word", 16),
        ("dword", 32),
        ("qword", 64),
        ("xmmword", 128),
        ("oword", 128),
    ] {
        if text.len() > prefix.len()
            && text[..prefix.len()].eq_ignore_ascii_case(prefix)
            && !text.as_bytes()[prefix.len()].is_ascii_alphanumeric()
        {
            size_bits = Some(bits);
            text = text[prefix.len()..].trim();
            if text.len() >= 3 && text[..3].eq_ignore_ascii_case("ptr") {
                text = text[3..].trim();
            }
            break;
        }
    }
    let mut segment = Register::None;
    for (seg_name, seg_reg) in [("fs:", Register::FS), ("gs:", Register::GS)] {
        if text.len() >= 3 && text[..3].eq_ignore_ascii_case(seg_name) {
            segment = seg_reg;
            text = text[3..].trim();
            break;
        }
    }
    let inner = text
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| anyhow!("Malformed memory operand: {raw}"))?
        .trim();
    ensure!(!inner.is_empty(), "Empty memory operand");

    // Tokenize +/- terms inside [...]
    let mut normalized = String::new();
    for ch in inner.chars() {
        if ch == '+' || ch == '-' {
            normalized.push(' ');
            normalized.push(ch);
            normalized.push(' ');
        } else {
            normalized.push(ch);
        }
    }
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    let mut base = Register::None;
    let mut index = Register::None;
    let mut scale = 1u32;
    let mut disp: i128 = 0;
    let mut rip_rel = false;
    let mut rip_sym: Option<String> = None;

    let mut sign = 1i128;
    let mut i = 0usize;
    while i < parts.len() {
        let tok = parts[i];
        if tok == "+" {
            sign = 1;
            i += 1;
            continue;
        }
        if tok == "-" {
            sign = -1;
            i += 1;
            continue;
        }
        if let Some((lhs, rhs)) = tok.split_once('*') {
            ensure!(sign == 1, "Scaled index cannot be subtracted");
            let (reg, width) = if let Some(r) = parse_register(lhs.trim()) {
                let sc: u32 = rhs.trim().parse().map_err(|_| anyhow!("Invalid scale in {tok}"))?;
                ensure!([1, 2, 4, 8].contains(&sc), "Scale must be 1, 2, 4, or 8");
                scale = sc;
                r
            } else if let Some(r) = parse_register(rhs.trim()) {
                let sc: u32 = lhs.trim().parse().map_err(|_| anyhow!("Invalid scale in {tok}"))?;
                ensure!([1, 2, 4, 8].contains(&sc), "Scale must be 1, 2, 4, or 8");
                scale = sc;
                r
            } else {
                bail!("Invalid scaled index: {tok}");
            };
            ensure!(width == 64, "64-bit addressing requires 64-bit index register");
            ensure!(index == Register::None, "Multiple index registers in memory operand");
            index = reg;
        } else if tok.eq_ignore_ascii_case("rip") {
            ensure!(sign == 1 && !rip_rel, "Invalid RIP-relative expression");
            rip_rel = true;
        } else if let Some((reg, width)) = parse_register(tok) {
            ensure!(sign == 1, "Register cannot be subtracted in memory operand");
            ensure!(width == 64, "64-bit addressing requires 64-bit base/index register");
            if base == Register::None {
                base = reg;
            } else if index == Register::None {
                index = reg;
                scale = 1;
            } else {
                bail!("Too many registers in memory operand: {raw}");
            }
        } else if let Some(val) = parse_int(tok) {
            disp += sign * val;
        } else if sign == 1 && is_ident(tok) && rip_sym.is_none() {
            rip_sym = Some(tok.to_ascii_lowercase());
        } else {
            bail!("Invalid term `{tok}` in memory operand `{raw}`");
        }
        sign = 1;
        i += 1;
    }

    if rip_rel {
        ensure!(
            base == Register::None && index == Register::None,
            "RIP-relative addressing cannot combine with other registers"
        );
        return Ok(Op::Mem {
            size_bits,
            segment,
            base: Register::RIP,
            index: Register::None,
            scale: 1,
            disp: disp as i64,
            rip_target: None,
            rip_sym,
        });
    }

    if base == Register::None && index == Register::None && rip_sym.is_some() {
        return Ok(Op::Mem {
            size_bits,
            segment,
            base: Register::RIP,
            index: Register::None,
            scale: 1,
            disp: disp as i64,
            rip_target: None,
            rip_sym,
        });
    }

    // Absolute `[0x402000]` without base/index: if segment is FS/GS, keep disp32;
    // otherwise encode as RIP-relative to target address when outside disp32 or use disp.
    if base == Register::None && index == Register::None && segment == Register::None && disp >= 0x1000 {
        return Ok(Op::Mem {
            size_bits,
            segment,
            base: Register::RIP,
            index: Register::None,
            scale: 1,
            disp: 0,
            rip_target: Some(disp as u64),
            rip_sym: None,
        });
    }

    Ok(Op::Mem {
        size_bits,
        segment,
        base,
        index,
        scale,
        disp: disp as i64,
        rip_target: None,
        rip_sym: None,
    })
}

fn parse_operand(raw: &str) -> Result<Op> {
    let trimmed = raw.trim();
    if trimmed.contains('[') {
        return parse_mem(trimmed);
    }
    if let Some((reg, bits)) = parse_register(trimmed) {
        return Ok(Op::Reg(reg, bits));
    }
    if let Some(val) = parse_int(trimmed) {
        return Ok(Op::Imm(val));
    }
    if is_ident(trimmed) {
        return Ok(Op::Sym(trimmed.to_ascii_lowercase()));
    }
    bail!("Unrecognized operand: {trimmed}")
}

fn parse_statements(source: &str) -> Result<Vec<Stmt>> {
    ensure!(source.len() <= 16384, "Assembly listing exceeds 16 KiB");
    let mut stmts = Vec::new();
    for line in source.lines() {
        // Strip `;` comments only if `//` or `#` is used? Note `;` is statement separator in inline asm!
        // Support `//` comments per line, and `;` as statement separator.
        let line = line.split("//").next().unwrap_or("");
        for chunk in line.split(';') {
            let mut text = chunk.trim();
            if text.is_empty() {
                continue;
            }
            while let Some((label, rest)) = text.split_once(':') {
                // Make sure ':' isn't inside `fs:[...]` or `gs:[...]`
                let candidate = label.trim();
                if candidate.to_ascii_lowercase().ends_with("fs")
                    || candidate.to_ascii_lowercase().ends_with("gs")
                {
                    if rest.trim_start().starts_with('[') {
                        break;
                    }
                }
                if is_ident(candidate) && !candidate.contains(' ') {
                    stmts.push(Stmt::Label(candidate.to_ascii_lowercase()));
                    text = rest.trim();
                    ensure!(stmts.len() <= MAX_ASM_STATEMENTS, "Too many assembly statements");
                } else {
                    break;
                }
            }
            if text.is_empty() {
                continue;
            }
            ensure!(stmts.len() < MAX_ASM_STATEMENTS, "Too many assembly statements");
            let (first, rest) = match text.find(char::is_whitespace) {
                Some(idx) => (&text[..idx], text[idx..].trim()),
                None => (text, ""),
            };
            let lower = first.to_ascii_lowercase();
            if matches!(lower.as_str(), "db" | "dw" | "dd" | "dq") {
                let unit = match lower.as_str() {
                    "db" => 1usize,
                    "dw" => 2,
                    "dd" => 4,
                    _ => 8,
                };
                let mut raw_bytes = Vec::new();
                for item in split_operands(rest)? {
                    let v = parse_int(item)
                        .ok_or_else(|| anyhow!("Invalid numeric literal `{item}` in {lower}"))?;
                    let le = (v as u128).to_le_bytes();
                    raw_bytes.extend_from_slice(&le[..unit]);
                }
                ensure!(!raw_bytes.is_empty(), "{lower} requires at least one value");
                stmts.push(Stmt::Bytes(raw_bytes));
                continue;
            }
            let (rep, mnemonic, operand_str) =
                if matches!(lower.as_str(), "rep" | "repe" | "repz" | "repne" | "repnz") {
                    ensure!(!rest.is_empty(), "Prefix `{lower}` requires an instruction");
                    let (m, r) = match rest.find(char::is_whitespace) {
                        Some(idx) => (&rest[..idx], rest[idx..].trim()),
                        None => (rest, ""),
                    };
                    let kind = match lower.as_str() {
                        "rep" | "repe" | "repz" => "rep",
                        _ => "repne",
                    };
                    (Some(kind), m.to_ascii_lowercase(), r)
                } else {
                    (None, lower, rest)
                };
            let ops = if operand_str.is_empty() {
                Vec::new()
            } else {
                split_operands(operand_str)?
                    .into_iter()
                    .map(parse_operand)
                    .collect::<Result<Vec<_>>>()?
            };
            stmts.push(Stmt::Insn { mnemonic, ops, rep });
        }
    }
    ensure!(!stmts.is_empty(), "Assembly listing is empty");
    Ok(stmts)
}

fn to_mem_operand(op: &Op, current_ip: u64, labels: &HashMap<String, u64>) -> Result<(MemoryOperand, Option<u16>)> {
    let Op::Mem {
        size_bits,
        segment,
        base,
        index,
        scale,
        disp,
        rip_target,
        rip_sym,
    } = op
    else {
        bail!("Expected memory operand");
    };
    if *base == Register::RIP {
        let target = if let Some(sym) = rip_sym {
            let addr = labels
                .get(sym)
                .copied()
                .ok_or_else(|| anyhow!("Unknown label `{sym}`"))?;
            (addr as i128 + *disp as i128) as u64
        } else if let Some(abs) = rip_target {
            *abs
        } else {
            // Explicit `[rip + disp]`: in assembly listings users write `[rip + 0x100]`
            // either relative to next_ip or as target. Wait: standard Intel `lea rax, [rip + 0x100]`
            // means displacement `+0x100` from `next_ip`! Since `BlockEncoder` treats `displacement`
            // with `Register::RIP` as the absolute target IP, if the user wrote literal `[rip + 0x100]`
            // we need to know `next_ip` OR let's verify how `iced-x86` handles `MemoryOperand` with `Register::RIP`!
            // We'll pass a marker or compute from tentative IP. Wait: let's check in tests!
            (current_ip as i128 + *disp as i128) as u64
        };
        let mem = MemoryOperand::new(
            Register::RIP,
            Register::None,
            1,
            target as i64,
            8,
            false,
            *segment,
        );
        return Ok((mem, *size_bits));
    }
    let displ_size = if *disp == 0 && *base != Register::None && *base != Register::RBP && *base != Register::R13 {
        0
    } else if (*disp >= i8::MIN as i64 && *disp <= i8::MAX as i64) && *base != Register::None {
        1
    } else {
        4
    };
    let mem = MemoryOperand::new(
        *base,
        *index,
        *scale,
        *disp,
        if *base == Register::None && *index == Register::None { 4 } else { displ_size },
        false,
        *segment,
    );
    Ok((mem, *size_bits))
}

fn imm_fits_i8(v: i128) -> bool {
    v >= i8::MIN as i128 && v <= i8::MAX as i128
}

fn imm_fits_i32(v: i128) -> bool {
    v >= i32::MIN as i128 && v <= u32::MAX as i128
}

fn branch_codes(mnemonic: &str) -> Option<(Code, Code)> {
    Some(match mnemonic {
        "jmp" => (Code::Jmp_rel8_64, Code::Jmp_rel32_64),
        "je" | "jz" => (Code::Je_rel8_64, Code::Je_rel32_64),
        "jne" | "jnz" => (Code::Jne_rel8_64, Code::Jne_rel32_64),
        "jg" | "jnle" => (Code::Jg_rel8_64, Code::Jg_rel32_64),
        "jge" | "jnl" => (Code::Jge_rel8_64, Code::Jge_rel32_64),
        "jl" | "jnge" => (Code::Jl_rel8_64, Code::Jl_rel32_64),
        "jle" | "jng" => (Code::Jle_rel8_64, Code::Jle_rel32_64),
        "ja" | "jnbe" => (Code::Ja_rel8_64, Code::Ja_rel32_64),
        "jae" | "jnb" | "jnc" => (Code::Jae_rel8_64, Code::Jae_rel32_64),
        "jb" | "jnae" | "jc" => (Code::Jb_rel8_64, Code::Jb_rel32_64),
        "jbe" | "jna" => (Code::Jbe_rel8_64, Code::Jbe_rel32_64),
        "js" => (Code::Js_rel8_64, Code::Js_rel32_64),
        "jns" => (Code::Jns_rel8_64, Code::Jns_rel32_64),
        "jo" => (Code::Jo_rel8_64, Code::Jo_rel32_64),
        "jno" => (Code::Jno_rel8_64, Code::Jno_rel32_64),
        "jp" | "jpe" => (Code::Jp_rel8_64, Code::Jp_rel32_64),
        "jnp" | "jpo" => (Code::Jnp_rel8_64, Code::Jnp_rel32_64),
        _ => return None,
    })
}

/// Binary ALU table: `(rm8_r8, rm16_r16, rm32_r32, rm64_r64, r8_rm8, r16_rm16, r32_rm32, r64_rm64,
/// rm8_imm8, rm16_imm16, rm32_imm32, rm64_imm32, rm16_imm8, rm32_imm8, rm64_imm8)`
#[allow(clippy::type_complexity)]
fn alu_codes(
    mnemonic: &str,
) -> Option<(
    [Code; 4],
    [Code; 4],
    [Code; 4],
    [Option<Code>; 4],
)> {
    Some(match mnemonic {
        "add" => (
            [Code::Add_rm8_r8, Code::Add_rm16_r16, Code::Add_rm32_r32, Code::Add_rm64_r64],
            [Code::Add_r8_rm8, Code::Add_r16_rm16, Code::Add_r32_rm32, Code::Add_r64_rm64],
            [Code::Add_rm8_imm8, Code::Add_rm16_imm16, Code::Add_rm32_imm32, Code::Add_rm64_imm32],
            [None, Some(Code::Add_rm16_imm8), Some(Code::Add_rm32_imm8), Some(Code::Add_rm64_imm8)],
        ),
        "sub" => (
            [Code::Sub_rm8_r8, Code::Sub_rm16_r16, Code::Sub_rm32_r32, Code::Sub_rm64_r64],
            [Code::Sub_r8_rm8, Code::Sub_r16_rm16, Code::Sub_r32_rm32, Code::Sub_r64_rm64],
            [Code::Sub_rm8_imm8, Code::Sub_rm16_imm16, Code::Sub_rm32_imm32, Code::Sub_rm64_imm32],
            [None, Some(Code::Sub_rm16_imm8), Some(Code::Sub_rm32_imm8), Some(Code::Sub_rm64_imm8)],
        ),
        "xor" => (
            [Code::Xor_rm8_r8, Code::Xor_rm16_r16, Code::Xor_rm32_r32, Code::Xor_rm64_r64],
            [Code::Xor_r8_rm8, Code::Xor_r16_rm16, Code::Xor_r32_rm32, Code::Xor_r64_rm64],
            [Code::Xor_rm8_imm8, Code::Xor_rm16_imm16, Code::Xor_rm32_imm32, Code::Xor_rm64_imm32],
            [None, Some(Code::Xor_rm16_imm8), Some(Code::Xor_rm32_imm8), Some(Code::Xor_rm64_imm8)],
        ),
        "and" => (
            [Code::And_rm8_r8, Code::And_rm16_r16, Code::And_rm32_r32, Code::And_rm64_r64],
            [Code::And_r8_rm8, Code::And_r16_rm16, Code::And_r32_rm32, Code::And_r64_rm64],
            [Code::And_rm8_imm8, Code::And_rm16_imm16, Code::And_rm32_imm32, Code::And_rm64_imm32],
            [None, Some(Code::And_rm16_imm8), Some(Code::And_rm32_imm8), Some(Code::And_rm64_imm8)],
        ),
        "or" => (
            [Code::Or_rm8_r8, Code::Or_rm16_r16, Code::Or_rm32_r32, Code::Or_rm64_r64],
            [Code::Or_r8_rm8, Code::Or_r16_rm16, Code::Or_r32_rm32, Code::Or_r64_rm64],
            [Code::Or_rm8_imm8, Code::Or_rm16_imm16, Code::Or_rm32_imm32, Code::Or_rm64_imm32],
            [None, Some(Code::Or_rm16_imm8), Some(Code::Or_rm32_imm8), Some(Code::Or_rm64_imm8)],
        ),
        "cmp" => (
            [Code::Cmp_rm8_r8, Code::Cmp_rm16_r16, Code::Cmp_rm32_r32, Code::Cmp_rm64_r64],
            [Code::Cmp_r8_rm8, Code::Cmp_r16_rm16, Code::Cmp_r32_rm32, Code::Cmp_r64_rm64],
            [Code::Cmp_rm8_imm8, Code::Cmp_rm16_imm16, Code::Cmp_rm32_imm32, Code::Cmp_rm64_imm32],
            [None, Some(Code::Cmp_rm16_imm8), Some(Code::Cmp_rm32_imm8), Some(Code::Cmp_rm64_imm8)],
        ),
        "adc" => (
            [Code::Adc_rm8_r8, Code::Adc_rm16_r16, Code::Adc_rm32_r32, Code::Adc_rm64_r64],
            [Code::Adc_r8_rm8, Code::Adc_r16_rm16, Code::Adc_r32_rm32, Code::Adc_r64_rm64],
            [Code::Adc_rm8_imm8, Code::Adc_rm16_imm16, Code::Adc_rm32_imm32, Code::Adc_rm64_imm32],
            [None, Some(Code::Adc_rm16_imm8), Some(Code::Adc_rm32_imm8), Some(Code::Adc_rm64_imm8)],
        ),
        "sbb" => (
            [Code::Sbb_rm8_r8, Code::Sbb_rm16_r16, Code::Sbb_rm32_r32, Code::Sbb_rm64_r64],
            [Code::Sbb_r8_rm8, Code::Sbb_r16_rm16, Code::Sbb_r32_rm32, Code::Sbb_r64_rm64],
            [Code::Sbb_rm8_imm8, Code::Sbb_rm16_imm16, Code::Sbb_rm32_imm32, Code::Sbb_rm64_imm32],
            [None, Some(Code::Sbb_rm16_imm8), Some(Code::Sbb_rm32_imm8), Some(Code::Sbb_rm64_imm8)],
        ),
        _ => return None,
    })
}

fn size_idx(bits: u16) -> Result<usize> {
    match bits {
        8 => Ok(0),
        16 => Ok(1),
        32 => Ok(2),
        64 => Ok(3),
        _ => bail!("Unsupported operand bit size: {bits}"),
    }
}

fn setcc_code(mnemonic: &str) -> Option<Code> {
    Some(match mnemonic {
        "sete" | "setz" => Code::Sete_rm8,
        "setne" | "setnz" => Code::Setne_rm8,
        "setg" | "setnle" => Code::Setg_rm8,
        "setge" | "setnl" => Code::Setge_rm8,
        "setl" | "setnge" => Code::Setl_rm8,
        "setle" | "setng" => Code::Setle_rm8,
        "seta" | "setnbe" => Code::Seta_rm8,
        "setae" | "setnb" | "setnc" => Code::Setae_rm8,
        "setb" | "setnae" | "setc" => Code::Setb_rm8,
        "setbe" | "setna" => Code::Setbe_rm8,
        "sets" => Code::Sets_rm8,
        "setns" => Code::Setns_rm8,
        _ => return None,
    })
}

fn cmov_codes(mnemonic: &str) -> Option<[Code; 3]> {
    Some(match mnemonic {
        "cmove" | "cmovz" => [Code::Cmove_r16_rm16, Code::Cmove_r32_rm32, Code::Cmove_r64_rm64],
        "cmovne" | "cmovnz" => [Code::Cmovne_r16_rm16, Code::Cmovne_r32_rm32, Code::Cmovne_r64_rm64],
        "cmovg" | "cmovnle" => [Code::Cmovg_r16_rm16, Code::Cmovg_r32_rm32, Code::Cmovg_r64_rm64],
        "cmovge" | "cmovnl" => [Code::Cmovge_r16_rm16, Code::Cmovge_r32_rm32, Code::Cmovge_r64_rm64],
        "cmovl" | "cmovnge" => [Code::Cmovl_r16_rm16, Code::Cmovl_r32_rm32, Code::Cmovl_r64_rm64],
        "cmovle" | "cmovng" => [Code::Cmovle_r16_rm16, Code::Cmovle_r32_rm32, Code::Cmovle_r64_rm64],
        "cmova" | "cmovnbe" => [Code::Cmova_r16_rm16, Code::Cmova_r32_rm32, Code::Cmova_r64_rm64],
        "cmovae" | "cmovnb" | "cmovnc" => [Code::Cmovae_r16_rm16, Code::Cmovae_r32_rm32, Code::Cmovae_r64_rm64],
        "cmovb" | "cmovnae" | "cmovc" => [Code::Cmovb_r16_rm16, Code::Cmovb_r32_rm32, Code::Cmovb_r64_rm64],
        "cmovbe" | "cmovna" => [Code::Cmovbe_r16_rm16, Code::Cmovbe_r32_rm32, Code::Cmovbe_r64_rm64],
        "cmovs" => [Code::Cmovs_r16_rm16, Code::Cmovs_r32_rm32, Code::Cmovs_r64_rm64],
        "cmovns" => [Code::Cmovns_r16_rm16, Code::Cmovns_r32_rm32, Code::Cmovns_r64_rm64],
        _ => return None,
    })
}

fn build_one(
    mnemonic: &str,
    ops: &[Op],
    rep: Option<&'static str>,
    current_ip: u64,
    labels: &HashMap<String, u64>,
) -> Result<Instruction> {
    let resolve_target = |op: &Op| -> Result<u64> {
        match op {
            Op::Imm(v) => Ok(*v as u64),
            Op::Sym(s) => labels
                .get(s)
                .copied()
                .ok_or_else(|| anyhow!("Unknown branch label `{s}`")),
            _ => bail!("Invalid branch target operand for `{mnemonic}`"),
        }
    };

    let mut insn = match (mnemonic, ops) {
        ("nop", []) => Instruction::with(Code::Nopd),
        ("int3", []) => Instruction::with(Code::Int3),
        ("ret" | "retn", []) => Instruction::with(Code::Retnq),
        ("ret" | "retn", [Op::Imm(v)]) => Instruction::with1(Code::Retnq_imm16, *v as u32)?,
        ("syscall", []) => Instruction::with(Code::Syscall),
        ("ud2", []) => Instruction::with(Code::Ud2),
        ("leave", []) => Instruction::with(Code::Leaveq),
        ("cdq", []) => Instruction::with(Code::Cdq),
        ("cqo", []) => Instruction::with(Code::Cqo),
        ("endbr64", []) => Instruction::with(Code::Endbr64),
        ("clc", []) => Instruction::with(Code::Clc),
        ("stc", []) => Instruction::with(Code::Stc),
        ("cld", []) => Instruction::with(Code::Cld),
        ("std", []) => Instruction::with(Code::Std),
        ("movsb", []) => Instruction::with(Code::Movsb_m8_m8),
        ("movsd", []) => Instruction::with(Code::Movsd_m32_m32),
        ("movsq", []) => Instruction::with(Code::Movsq_m64_m64),
        ("stosb", []) => Instruction::with(Code::Stosb_m8_AL),
        ("stosd", []) => Instruction::with(Code::Stosd_m32_EAX),
        ("stosq", []) => Instruction::with(Code::Stosq_m64_RAX),
        ("int", [Op::Imm(3)]) => Instruction::with(Code::Int3),
        ("int", [Op::Imm(v)]) => Instruction::with1(Code::Int_imm8, *v as u32)?,

        // push / pop
        ("push", [Op::Reg(r, 64)]) => Instruction::with1(Code::Push_r64, *r)?,
        ("push", [Op::Reg(r, 16)]) => Instruction::with1(Code::Push_r16, *r)?,
        ("push", [Op::Imm(v)]) => {
            if imm_fits_i8(*v) {
                Instruction::with1(Code::Pushq_imm8, *v as i32)?
            } else {
                Instruction::with1(Code::Pushq_imm32, *v as i32)?
            }
        }
        ("push", [op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            Instruction::with1(Code::Push_rm64, mem)?
        }
        ("pop", [Op::Reg(r, 64)]) => Instruction::with1(Code::Pop_r64, *r)?,
        ("pop", [Op::Reg(r, 16)]) => Instruction::with1(Code::Pop_r16, *r)?,
        ("pop", [op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            Instruction::with1(Code::Pop_rm64, mem)?
        }

        // branches & calls
        ("call", [Op::Reg(r, 64)]) => Instruction::with1(Code::Call_rm64, *r)?,
        ("call", [op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            Instruction::with1(Code::Call_rm64, mem)?
        }
        ("call", [op]) => Instruction::with_branch(Code::Call_rel32_64, resolve_target(op)?)?,
        ("jmp", [Op::Reg(r, 64)]) => Instruction::with1(Code::Jmp_rm64, *r)?,
        ("jmp", [op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            Instruction::with1(Code::Jmp_rm64, mem)?
        }
        (br, [op]) if branch_codes(br).is_some() => {
            let (short_c, near_c) = branch_codes(br).unwrap();
            let target = resolve_target(op)?;
            let rel = target as i128 - (current_ip as i128 + 2);
            let code = if imm_fits_i8(rel) { short_c } else { near_c };
            Instruction::with_branch(code, target)?
        }

        // lea
        ("lea", [Op::Reg(r, bits), op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            let code = match *bits {
                16 => Code::Lea_r16_m,
                32 => Code::Lea_r32_m,
                64 => Code::Lea_r64_m,
                _ => bail!("Invalid destination register size for lea"),
            };
            Instruction::with2(code, *r, mem)?
        }

        // mov / movabs
        ("mov" | "movabs", [Op::Reg(dst, bits), Op::Reg(src, sbits)]) => {
            ensure!(bits == sbits, "Mismatched register sizes in mov");
            let code = match *bits {
                8 => Code::Mov_rm8_r8,
                16 => Code::Mov_rm16_r16,
                32 => Code::Mov_rm32_r32,
                64 => Code::Mov_rm64_r64,
                _ => bail!("Use movaps/movups/movdqa/movdqu for XMM moves"),
            };
            Instruction::with2(code, *dst, *src)?
        }
        ("mov" | "movabs", [Op::Reg(dst, bits), Op::Imm(val)]) => match (*bits, mnemonic) {
            (8, _) => Instruction::with2(Code::Mov_r8_imm8, *dst, *val as u32)?,
            (16, _) => Instruction::with2(Code::Mov_r16_imm16, *dst, *val as u32)?,
            (32, _) => Instruction::with2(Code::Mov_r32_imm32, *dst, *val as u32)?,
            (64, "movabs") => Instruction::with2(Code::Mov_r64_imm64, *dst, *val as u64)?,
            (64, _) => {
                if *val >= 0 && *val <= u32::MAX as i128 {
                    Instruction::with2(Code::Mov_rm64_imm32, *dst, *val as i32)?
                } else if *val >= i32::MIN as i128 && *val < 0 {
                    Instruction::with2(Code::Mov_rm64_imm32, *dst, *val as i32)?
                } else {
                    Instruction::with2(Code::Mov_r64_imm64, *dst, *val as u64)?
                }
            }
            _ => bail!("Invalid immediate mov target"),
        },
        ("mov" | "movabs", [Op::Reg(dst, 64), Op::Sym(sym)]) => {
            let addr = labels
                .get(sym)
                .copied()
                .ok_or_else(|| anyhow!("Unknown label `{sym}`"))?;
            Instruction::with2(Code::Mov_r64_imm64, *dst, addr)?
        }
        ("mov", [Op::Reg(dst, bits), op @ Op::Mem { .. }]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            if let Some(m) = mbits {
                ensure!(m == u16::from(*bits), "Memory size specifier mismatches register");
            }
            let code = match *bits {
                8 => Code::Mov_r8_rm8,
                16 => Code::Mov_r16_rm16,
                32 => Code::Mov_r32_rm32,
                64 => Code::Mov_r64_rm64,
                _ => bail!("Unsupported register width in mov"),
            };
            Instruction::with2(code, *dst, mem)?
        }
        ("mov", [op @ Op::Mem { .. }, Op::Reg(src, bits)]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            if let Some(m) = mbits {
                ensure!(m == u16::from(*bits), "Memory size specifier mismatches register");
            }
            let code = match *bits {
                8 => Code::Mov_rm8_r8,
                16 => Code::Mov_rm16_r16,
                32 => Code::Mov_rm32_r32,
                64 => Code::Mov_rm64_r64,
                _ => bail!("Unsupported register width in mov"),
            };
            Instruction::with2(code, mem, *src)?
        }
        ("mov", [op @ Op::Mem { .. }, Op::Imm(val)]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            let bits = mbits.ok_or_else(|| {
                anyhow!("Memory immediate `mov` requires explicit size (`byte/word/dword/qword ptr`)")
            })?;
            match bits {
                8 => Instruction::with2(Code::Mov_rm8_imm8, mem, *val as u32)?,
                16 => Instruction::with2(Code::Mov_rm16_imm16, mem, *val as u32)?,
                32 => Instruction::with2(Code::Mov_rm32_imm32, mem, *val as u32)?,
                64 => {
                    ensure!(imm_fits_i32(*val), "64-bit memory mov immediate must fit in signed 32-bit");
                    Instruction::with2(Code::Mov_rm64_imm32, mem, *val as i32)?
                }
                _ => bail!("Invalid memory size for immediate mov"),
            }
        }

        // movzx / movsx / movsxd
        ("movzx", [Op::Reg(dst, dbits), Op::Reg(src, sbits)]) => {
            let code = match (*dbits, *sbits) {
                (16, 8) => Code::Movzx_r16_rm8,
                (32, 8) => Code::Movzx_r32_rm8,
                (64, 8) => Code::Movzx_r64_rm8,
                (32, 16) => Code::Movzx_r32_rm16,
                (64, 16) => Code::Movzx_r64_rm16,
                _ => bail!("Invalid operand widths for movzx"),
            };
            Instruction::with2(code, *dst, *src)?
        }
        ("movzx", [Op::Reg(dst, dbits), op @ Op::Mem { .. }]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            let sbits = mbits.unwrap_or(8);
            let code = match (*dbits, sbits) {
                (16, 8) => Code::Movzx_r16_rm8,
                (32, 8) => Code::Movzx_r32_rm8,
                (64, 8) => Code::Movzx_r64_rm8,
                (32, 16) => Code::Movzx_r32_rm16,
                (64, 16) => Code::Movzx_r64_rm16,
                _ => bail!("Invalid operand widths for movzx (specify byte/word ptr)"),
            };
            Instruction::with2(code, *dst, mem)?
        }
        ("movsx" | "movsxd", [Op::Reg(dst, dbits), Op::Reg(src, sbits)]) => {
            let code = match (*dbits, *sbits) {
                (16, 8) => Code::Movsx_r16_rm8,
                (32, 8) => Code::Movsx_r32_rm8,
                (64, 8) => Code::Movsx_r64_rm8,
                (32, 16) => Code::Movsx_r32_rm16,
                (64, 16) => Code::Movsx_r64_rm16,
                (64, 32) => Code::Movsxd_r64_rm32,
                _ => bail!("Invalid operand widths for {mnemonic}"),
            };
            Instruction::with2(code, *dst, *src)?
        }
        ("movsx" | "movsxd", [Op::Reg(dst, dbits), op @ Op::Mem { .. }]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            let sbits = mbits.unwrap_or(if mnemonic == "movsxd" { 32 } else { 8 });
            let code = match (*dbits, sbits) {
                (16, 8) => Code::Movsx_r16_rm8,
                (32, 8) => Code::Movsx_r32_rm8,
                (64, 8) => Code::Movsx_r64_rm8,
                (32, 16) => Code::Movsx_r32_rm16,
                (64, 16) => Code::Movsx_r64_rm16,
                (64, 32) => Code::Movsxd_r64_rm32,
                _ => bail!("Invalid operand widths for {mnemonic}"),
            };
            Instruction::with2(code, *dst, mem)?
        }

        // xchg
        ("xchg", [Op::Reg(a, abits), Op::Reg(b, bbits)]) => {
            ensure!(abits == bbits, "Mismatched register sizes in xchg");
            let code = match *abits {
                8 => Code::Xchg_rm8_r8,
                16 => Code::Xchg_rm16_r16,
                32 => Code::Xchg_rm32_r32,
                64 => Code::Xchg_rm64_r64,
                _ => bail!("Unsupported register size in xchg"),
            };
            Instruction::with2(code, *a, *b)?
        }

        // test
        ("test", [Op::Reg(a, abits), Op::Reg(b, bbits)]) => {
            ensure!(abits == bbits, "Mismatched register sizes in test");
            let code = match *abits {
                8 => Code::Test_rm8_r8,
                16 => Code::Test_rm16_r16,
                32 => Code::Test_rm32_r32,
                64 => Code::Test_rm64_r64,
                _ => bail!("Unsupported register size in test"),
            };
            Instruction::with2(code, *a, *b)?
        }
        ("test", [Op::Reg(a, abits), Op::Imm(v)]) => match *abits {
            8 => Instruction::with2(Code::Test_rm8_imm8, *a, *v as u32)?,
            16 => Instruction::with2(Code::Test_rm16_imm16, *a, *v as u32)?,
            32 => Instruction::with2(Code::Test_rm32_imm32, *a, *v as u32)?,
            64 => Instruction::with2(Code::Test_rm64_imm32, *a, *v as i32)?,
            _ => bail!("Unsupported register size in test"),
        },
        ("test", [op @ Op::Mem { .. }, Op::Reg(b, bbits)]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            let code = match *bbits {
                8 => Code::Test_rm8_r8,
                16 => Code::Test_rm16_r16,
                32 => Code::Test_rm32_r32,
                64 => Code::Test_rm64_r64,
                _ => bail!("Unsupported register size in test"),
            };
            Instruction::with2(code, mem, *b)?
        }
        ("test", [op @ Op::Mem { .. }, Op::Imm(v)]) => {
            let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
            match mbits.ok_or_else(|| anyhow!("Specify memory size on `test [mem], imm`"))? {
                8 => Instruction::with2(Code::Test_rm8_imm8, mem, *v as u32)?,
                16 => Instruction::with2(Code::Test_rm16_imm16, mem, *v as u32)?,
                32 => Instruction::with2(Code::Test_rm32_imm32, mem, *v as u32)?,
                64 => Instruction::with2(Code::Test_rm64_imm32, mem, *v as i32)?,
                _ => bail!("Unsupported memory size in test"),
            }
        }

        // Standard binary ALU ops
        (alu, [lhs, rhs]) if alu_codes(alu).is_some() => {
            let (rm_r, r_rm, rm_imm, rm_imm8) = alu_codes(alu).unwrap();
            match (lhs, rhs) {
                (Op::Reg(a, abits), Op::Reg(b, bbits)) => {
                    ensure!(abits == bbits, "Mismatched register sizes in {alu}");
                    Instruction::with2(rm_r[size_idx(u16::from(*abits))?], *a, *b)?
                }
                (Op::Reg(a, abits), op @ Op::Mem { .. }) => {
                    let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
                    if let Some(m) = mbits {
                        ensure!(m == u16::from(*abits), "Mismatched operand size in {alu}");
                    }
                    Instruction::with2(r_rm[size_idx(u16::from(*abits))?], *a, mem)?
                }
                (op @ Op::Mem { .. }, Op::Reg(b, bbits)) => {
                    let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
                    if let Some(m) = mbits {
                        ensure!(m == u16::from(*bbits), "Mismatched operand size in {alu}");
                    }
                    Instruction::with2(rm_r[size_idx(u16::from(*bbits))?], mem, *b)?
                }
                (Op::Reg(a, abits), Op::Imm(v)) => {
                    let idx = size_idx(u16::from(*abits))?;
                    if let Some(short) = rm_imm8[idx]
                        && imm_fits_i8(*v)
                    {
                        Instruction::with2(short, *a, *v as i32)?
                    } else if *abits == 64 {
                        Instruction::with2(rm_imm[idx], *a, *v as i32)?
                    } else {
                        Instruction::with2(rm_imm[idx], *a, *v as u32)?
                    }
                }
                (op @ Op::Mem { .. }, Op::Imm(v)) => {
                    let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
                    let bits = mbits.ok_or_else(|| anyhow!("Specify memory size in `{alu} [mem], imm`"))?;
                    let idx = size_idx(bits)?;
                    if let Some(short) = rm_imm8[idx]
                        && imm_fits_i8(*v)
                    {
                        Instruction::with2(short, mem, *v as i32)?
                    } else if bits == 64 {
                        Instruction::with2(rm_imm[idx], mem, *v as i32)?
                    } else {
                        Instruction::with2(rm_imm[idx], mem, *v as u32)?
                    }
                }
                _ => bail!("Unsupported operand combination for {alu}"),
            }
        }

        // Unary inc / dec / neg / not / mul / imul(1) / div / idiv
        (un @ ("inc" | "dec" | "neg" | "not" | "mul" | "imul" | "div" | "idiv"), [target]) => {
            let table = match un {
                "inc" => [Code::Inc_rm8, Code::Inc_rm16, Code::Inc_rm32, Code::Inc_rm64],
                "dec" => [Code::Dec_rm8, Code::Dec_rm16, Code::Dec_rm32, Code::Dec_rm64],
                "neg" => [Code::Neg_rm8, Code::Neg_rm16, Code::Neg_rm32, Code::Neg_rm64],
                "not" => [Code::Not_rm8, Code::Not_rm16, Code::Not_rm32, Code::Not_rm64],
                "mul" => [Code::Mul_rm8, Code::Mul_rm16, Code::Mul_rm32, Code::Mul_rm64],
                "imul" => [Code::Imul_rm8, Code::Imul_rm16, Code::Imul_rm32, Code::Imul_rm64],
                "div" => [Code::Div_rm8, Code::Div_rm16, Code::Div_rm32, Code::Div_rm64],
                _ => [Code::Idiv_rm8, Code::Idiv_rm16, Code::Idiv_rm32, Code::Idiv_rm64],
            };
            match target {
                Op::Reg(r, bits) => Instruction::with1(table[size_idx(u16::from(*bits))?], *r)?,
                op @ Op::Mem { .. } => {
                    let (mem, mbits) = to_mem_operand(op, current_ip, labels)?;
                    let bits = mbits.ok_or_else(|| anyhow!("Specify memory size for `{un}`"))?;
                    Instruction::with1(table[size_idx(bits)?], mem)?
                }
                _ => bail!("Invalid operand for `{un}`"),
            }
        }

        // imul 2-op and 3-op
        ("imul", [Op::Reg(dst, dbits), Op::Reg(src, sbits)]) => {
            ensure!(dbits == sbits, "Mismatched sizes in imul");
            let code = match *dbits {
                16 => Code::Imul_r16_rm16,
                32 => Code::Imul_r32_rm32,
                64 => Code::Imul_r64_rm64,
                _ => bail!("Unsupported register width in 2-operand imul"),
            };
            Instruction::with2(code, *dst, *src)?
        }
        ("imul", [Op::Reg(dst, dbits), op @ Op::Mem { .. }]) => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            let code = match *dbits {
                16 => Code::Imul_r16_rm16,
                32 => Code::Imul_r32_rm32,
                64 => Code::Imul_r64_rm64,
                _ => bail!("Unsupported register width in 2-operand imul"),
            };
            Instruction::with2(code, *dst, mem)?
        }
        ("imul", [Op::Reg(dst, dbits), Op::Reg(src, sbits), Op::Imm(v)]) => {
            ensure!(dbits == sbits, "Mismatched sizes in imul");
            match (*dbits, imm_fits_i8(*v)) {
                (16, true) => Instruction::with3(Code::Imul_r16_rm16_imm8, *dst, *src, *v as i32)?,
                (16, false) => Instruction::with3(Code::Imul_r16_rm16_imm16, *dst, *src, *v as i32)?,
                (32, true) => Instruction::with3(Code::Imul_r32_rm32_imm8, *dst, *src, *v as i32)?,
                (32, false) => Instruction::with3(Code::Imul_r32_rm32_imm32, *dst, *src, *v as i32)?,
                (64, true) => Instruction::with3(Code::Imul_r64_rm64_imm8, *dst, *src, *v as i32)?,
                (64, false) => Instruction::with3(Code::Imul_r64_rm64_imm32, *dst, *src, *v as i32)?,
                _ => bail!("Unsupported register width in 3-operand imul"),
            }
        }

        // Shifts: shl / sal / shr / sar / rol / ror
        (sh @ ("shl" | "sal" | "shr" | "sar" | "rol" | "ror"), [Op::Reg(r, bits), count]) => {
            let idx = size_idx(u16::from(*bits))?;
            let (by_one, by_cl, by_imm) = match sh {
                "shl" | "sal" => (
                    [Code::Shl_rm8_1, Code::Shl_rm16_1, Code::Shl_rm32_1, Code::Shl_rm64_1],
                    [Code::Shl_rm8_CL, Code::Shl_rm16_CL, Code::Shl_rm32_CL, Code::Shl_rm64_CL],
                    [Code::Shl_rm8_imm8, Code::Shl_rm16_imm8, Code::Shl_rm32_imm8, Code::Shl_rm64_imm8],
                ),
                "shr" => (
                    [Code::Shr_rm8_1, Code::Shr_rm16_1, Code::Shr_rm32_1, Code::Shr_rm64_1],
                    [Code::Shr_rm8_CL, Code::Shr_rm16_CL, Code::Shr_rm32_CL, Code::Shr_rm64_CL],
                    [Code::Shr_rm8_imm8, Code::Shr_rm16_imm8, Code::Shr_rm32_imm8, Code::Shr_rm64_imm8],
                ),
                "sar" => (
                    [Code::Sar_rm8_1, Code::Sar_rm16_1, Code::Sar_rm32_1, Code::Sar_rm64_1],
                    [Code::Sar_rm8_CL, Code::Sar_rm16_CL, Code::Sar_rm32_CL, Code::Sar_rm64_CL],
                    [Code::Sar_rm8_imm8, Code::Sar_rm16_imm8, Code::Sar_rm32_imm8, Code::Sar_rm64_imm8],
                ),
                "rol" => (
                    [Code::Rol_rm8_1, Code::Rol_rm16_1, Code::Rol_rm32_1, Code::Rol_rm64_1],
                    [Code::Rol_rm8_CL, Code::Rol_rm16_CL, Code::Rol_rm32_CL, Code::Rol_rm64_CL],
                    [Code::Rol_rm8_imm8, Code::Rol_rm16_imm8, Code::Rol_rm32_imm8, Code::Rol_rm64_imm8],
                ),
                _ => (
                    [Code::Ror_rm8_1, Code::Ror_rm16_1, Code::Ror_rm32_1, Code::Ror_rm64_1],
                    [Code::Ror_rm8_CL, Code::Ror_rm16_CL, Code::Ror_rm32_CL, Code::Ror_rm64_CL],
                    [Code::Ror_rm8_imm8, Code::Ror_rm16_imm8, Code::Ror_rm32_imm8, Code::Ror_rm64_imm8],
                ),
            };
            match count {
                Op::Imm(1) => Instruction::with2(by_one[idx], *r, 1u32)?,
                Op::Imm(v) => Instruction::with2(by_imm[idx], *r, (*v & 0xff) as u32)?,
                Op::Reg(Register::CL, _) => Instruction::with2(by_cl[idx], *r, Register::CL)?,
                _ => bail!("Shift count must be immediate or `cl`"),
            }
        }

        // setcc / cmovcc
        (sc, [Op::Reg(r, 8)]) if setcc_code(sc).is_some() => {
            Instruction::with1(setcc_code(sc).unwrap(), *r)?
        }
        (sc, [op @ Op::Mem { .. }]) if setcc_code(sc).is_some() => {
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            Instruction::with1(setcc_code(sc).unwrap(), mem)?
        }
        (cm, [Op::Reg(dst, dbits), Op::Reg(src, sbits)]) if cmov_codes(cm).is_some() => {
            ensure!(dbits == sbits && *dbits >= 16, "Invalid cmov register sizes");
            let idx = size_idx(u16::from(*dbits))? - 1;
            Instruction::with2(cmov_codes(cm).unwrap()[idx], *dst, *src)?
        }
        (cm, [Op::Reg(dst, dbits), op @ Op::Mem { .. }]) if cmov_codes(cm).is_some() => {
            ensure!(*dbits >= 16, "Invalid cmov register size");
            let (mem, _) = to_mem_operand(op, current_ip, labels)?;
            let idx = size_idx(u16::from(*dbits))? - 1;
            Instruction::with2(cmov_codes(cm).unwrap()[idx], *dst, mem)?
        }

        // Common scalar/packed XMM float & integer ops (vital for game floats!)
        (
            sse @ ("movss" | "movsd" | "movaps" | "movups" | "movdqa" | "movdqu" | "addss"
            | "subss" | "mulss" | "divss" | "addsd" | "subsd" | "mulsd" | "divsd" | "xorps"
            | "xorpd" | "pxor" | "ucomiss" | "ucomisd"),
            [lhs, rhs],
        ) => {
            let (rr_or_rm, mr) = match sse {
                "movss" => (Code::Movss_xmm_xmmm32, Some(Code::Movss_xmmm32_xmm)),
                "movsd" => (Code::Movsd_xmm_xmmm64, Some(Code::Movsd_xmmm64_xmm)),
                "movaps" => (Code::Movaps_xmm_xmmm128, Some(Code::Movaps_xmmm128_xmm)),
                "movups" => (Code::Movups_xmm_xmmm128, Some(Code::Movups_xmmm128_xmm)),
                "movdqa" => (Code::Movdqa_xmm_xmmm128, Some(Code::Movdqa_xmmm128_xmm)),
                "movdqu" => (Code::Movdqu_xmm_xmmm128, Some(Code::Movdqu_xmmm128_xmm)),
                "addss" => (Code::Addss_xmm_xmmm32, None),
                "subss" => (Code::Subss_xmm_xmmm32, None),
                "mulss" => (Code::Mulss_xmm_xmmm32, None),
                "divss" => (Code::Divss_xmm_xmmm32, None),
                "addsd" => (Code::Addsd_xmm_xmmm64, None),
                "subsd" => (Code::Subsd_xmm_xmmm64, None),
                "mulsd" => (Code::Mulsd_xmm_xmmm64, None),
                "divsd" => (Code::Divsd_xmm_xmmm64, None),
                "xorps" => (Code::Xorps_xmm_xmmm128, None),
                "xorpd" => (Code::Xorpd_xmm_xmmm128, None),
                "pxor" => (Code::Pxor_xmm_xmmm128, None),
                "ucomiss" => (Code::Ucomiss_xmm_xmmm32, None),
                _ => (Code::Ucomisd_xmm_xmmm64, None),
            };
            match (lhs, rhs) {
                (Op::Reg(d, 128), Op::Reg(s, 128)) => Instruction::with2(rr_or_rm, *d, *s)?,
                (Op::Reg(d, 128), op @ Op::Mem { .. }) => {
                    let (mem, _) = to_mem_operand(op, current_ip, labels)?;
                    Instruction::with2(rr_or_rm, *d, mem)?
                }
                (op @ Op::Mem { .. }, Op::Reg(s, 128)) => {
                    let store = mr.ok_or_else(|| anyhow!("`{sse}` cannot write directly to memory"))?;
                    let (mem, _) = to_mem_operand(op, current_ip, labels)?;
                    Instruction::with2(store, mem, *s)?
                }
                _ => bail!("Invalid operands for `{sse}`"),
            }
        }

        _ => bail!("Unsupported instruction or operand combination: `{mnemonic}`"),
    };

    if let Some(prefix) = rep {
        if prefix == "rep" {
            insn.set_has_rep_prefix(true);
        } else {
            insn.set_has_repne_prefix(true);
        }
    }
    Ok(insn)
}

/// Assemble an Intel-syntax x86-64 listing anchored at `base_address`.
/// Uses fixed-point relaxation (up to 6 passes) so local labels, short/near
/// branches, and `[rip + offset]` operands resolve to exact instruction addresses.
pub fn assemble(source: &str, base_address: u64) -> Result<Vec<u8>> {
    let stmts = parse_statements(source)?;
    let mut labels = HashMap::<String, u64>::new();
    // Seed any unknown labels to base_address for pass 0 sizing.
    for stmt in &stmts {
        if let Stmt::Label(name) = stmt {
            ensure!(
                !labels.contains_key(name),
                "Duplicate assembly label `{name}`"
            );
            labels.insert(name.clone(), base_address);
        }
    }

    let mut last_bytes = Vec::new();
    for pass in 0..6 {
        let mut cursor = base_address;
        let mut next_labels = labels.clone();
        let mut insns = Vec::new();
        for stmt in &stmts {
            match stmt {
                Stmt::Label(name) => {
                    next_labels.insert(name.clone(), cursor);
                }
                Stmt::Bytes(raw) => {
                    for chunk in raw.chunks(16) {
                        insns.push(Instruction::with_declare_byte(chunk)?);
                    }
                    cursor = cursor.wrapping_add(raw.len() as u64);
                }
                Stmt::Insn { mnemonic, ops, rep } => {
                    // For explicit `[rip + disp]` (no symbol, no absolute target), Intel syntax
                    // defines `disp` relative to `next_ip` (`cursor + insn_len`). Measure length first!
                    let probe = build_one(mnemonic, ops, *rep, cursor, &next_labels)?;
                    let single_block = InstructionBlock::new(std::slice::from_ref(&probe), cursor);
                    let probe_len = BlockEncoder::encode(64, single_block, BlockEncoderOptions::NONE)
                        .map(|r| r.code_buffer.len() as u64)
                        .unwrap_or(7);
                    let insn = build_one(
                        mnemonic,
                        ops,
                        *rep,
                        cursor.wrapping_add(probe_len),
                        &next_labels,
                    )?;
                    let exact_block = InstructionBlock::new(std::slice::from_ref(&insn), cursor);
                    let exact_len = BlockEncoder::encode(64, exact_block, BlockEncoderOptions::NONE)
                        .map_err(|e| anyhow!("Encoding `{mnemonic}` failed: {e}"))?
                        .code_buffer
                        .len() as u64;
                    cursor = cursor.wrapping_add(exact_len);
                    insns.push(insn);
                }
            }
        }
        let block = InstructionBlock::new(&insns, base_address);
        let encoded = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
            .map_err(|e| anyhow!("Block encoding failed: {e}"))?;
        ensure!(
            encoded.code_buffer.len() <= MAX_ASM_BYTES,
            "Assembled output exceeds {} bytes",
            MAX_ASM_BYTES
        );
        if pass > 0 && next_labels == labels && encoded.code_buffer == last_bytes {
            return Ok(encoded.code_buffer);
        }
        labels = next_labels;
        last_bytes = encoded.code_buffer;
    }
    Ok(last_bytes)
}

/// JSON wrapper for the `assemble` MCP tool, including round-trip disassembly.
pub fn assemble_json(source: &str, base_address: u64) -> Result<Value> {
    let bytes = assemble(source, base_address)?;
    let decoded = disasm::decode(&bytes, base_address, disasm::MAX_INSTRUCTIONS);
    Ok(json!({
        "address": format!("{base_address:#x}"),
        "bytes": hex::encode(&bytes),
        "length": bytes.len(),
        "instruction_count": decoded.len(),
        "instructions": disasm::to_json(&decoded),
    }))
}

/// Compute NOP-padded replacement bytes when patching instructions at `address`
/// over `existing_code` so trailing bytes of a partially overwritten instruction
/// become valid single-byte `0x90` NOPs instead of corrupting instruction boundaries.
pub fn pad_patch_over_code(
    patch_bytes: &[u8],
    existing_code: &[u8],
    address: u64,
    nop_pad: bool,
) -> Result<(Vec<u8>, usize)> {
    ensure!(!patch_bytes.is_empty(), "Patch bytes must not be empty");
    if !nop_pad {
        return Ok((patch_bytes.to_vec(), 0));
    }
    let decoded = disasm::decode(existing_code, address, disasm::MAX_INSTRUCTIONS);
    let mut covered = 0usize;
    for item in &decoded {
        if covered >= patch_bytes.len() {
            break;
        }
        covered += item.length;
    }
    if covered < patch_bytes.len() {
        // Fallback if existing region wasn't long enough or ended mid-instruction
        return Ok((patch_bytes.to_vec(), 0));
    }
    let nops = covered - patch_bytes.len();
    let mut out = Vec::with_capacity(covered);
    out.extend_from_slice(patch_bytes);
    out.resize(covered, 0x90);
    Ok((out, nops))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_core_instructions_branches_labels_and_rip_relative() {
        let bytes = assemble(
            "push rbp; mov rbp, rsp; xor eax, eax; mov ecx, 0x2a; add rax, rcx; pop rbp; ret",
            0x401000,
        )
        .unwrap();
        let items = disasm::decode(&bytes, 0x401000, 16);
        let texts: Vec<_> = items.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "push rbp",
                "mov rbp, rsp",
                "xor eax, eax",
                "mov ecx, 0x2a",
                "add rax, rcx",
                "pop rbp",
                "ret"
            ]
        );

        // Forward + backward label branches
        let loop_code = assemble(
            "xor eax, eax; .loop: inc eax; cmp eax, 10; jl .loop; jmp .done; nop; .done: ret",
            0x500000,
        )
        .unwrap();
        let items = disasm::decode(&loop_code, 0x500000, 16);
        assert_eq!(items[3].flow, "conditional_jump");
        assert_eq!(items[3].branch_target, Some(0x500002));
        assert_eq!(items.last().unwrap().text, "ret");

        // Explicit RIP-relative `lea rax, [rip + 0x100]` at 0x1000 -> next_ip=0x1007 -> target=0x1107
        let rip_lea = assemble("lea rax, [rip + 0x100]", 0x1000).unwrap();
        let decoded = disasm::decode(&rip_lea, 0x1000, 1);
        assert_eq!(decoded[0].length, 7);
        assert_eq!(decoded[0].memory_target, Some(0x1107));

        // SSE scalar float instructions
        let sse = assemble("movss xmm0, [rdi + 0x10]; addss xmm0, xmm1; movss [rdi + 0x10], xmm0", 0x2000).unwrap();
        let decoded_sse = disasm::decode(&sse, 0x2000, 8);
        assert_eq!(decoded_sse.len(), 3);
    }

    #[test]
    fn nop_padding_aligns_to_overwritten_instruction_boundary() {
        // Existing: `call +0x10` (5 bytes: e8 10 00 00 00), `xor eax, eax` (2 bytes)
        let existing = [0xe8, 0x10, 0x00, 0x00, 0x00, 0x31, 0xc0];
        // Patch 2-byte `xor eax, eax` over 5-byte `call` -> padded to 5 bytes with 3 NOPs!
        let patch = assemble("xor eax, eax", 0x1000).unwrap();
        assert_eq!(patch.len(), 2);
        let (padded, nops) = pad_patch_over_code(&patch, &existing, 0x1000, true).unwrap();
        assert_eq!(nops, 3);
        assert_eq!(padded, vec![0x31, 0xc0, 0x90, 0x90, 0x90]);
    }
}
