//! DWARF `.eh_frame` Call Frame Information (CFI) parser and unwinder for x86-64.
//!
//! PS4 Orbis OS games and system modules are compiled with Clang (`-fomit-frame-pointer`
//! by default in release builds) and carry standard System V AMD64 `.eh_frame`
//! unwind tables (`PT_GNU_EH_FRAME` = `0x6474e550`). Unwinding via `.eh_frame`
//! recovers accurate return addresses and saved registers (`rbp`, `rbx`, `r12`–`r15`)
//! even when `rbp` is used as a general-purpose scratch register.

use crate::Result;
use anyhow::{anyhow, bail, ensure};
use std::collections::HashMap;

const MAX_CFI_OPS: usize = 4096;
const MAX_FDES: usize = 65536;

/// AMD64 DWARF register numbers:
/// 0=rax, 1=rdx, 2=rcx, 3=rbx, 4=rsi, 5=rdi, 6=rbp, 7=rsp,
/// 8..=15 = r8..=r15, 16 = rip (return address).
pub const DWARF_RBP: u8 = 6;
pub const DWARF_RSP: u8 = 7;
pub const DWARF_RIP: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegRule {
    Undefined,
    SameValue,
    Offset(i64),    // value stored at *(CFA + offset)
    ValOffset(i64), // value is (CFA + offset)
}

#[derive(Debug, Clone)]
pub struct UnwindRow {
    pub cfa_reg: u8,
    pub cfa_offset: i64,
    pub regs: HashMap<u8, RegRule>,
}

impl Default for UnwindRow {
    fn default() -> Self {
        Self {
            cfa_reg: DWARF_RSP,
            cfa_offset: 8,
            regs: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Cie {
    code_align: u64,
    data_align: i64,
    return_reg: u8,
    fde_encoding: u8,
    initial_instructions: Vec<u8>,
}

fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| anyhow!("Truncated ULEB128 in .eh_frame"))?;
        *pos += 1;
        ensure!(shift < 64, "ULEB128 overflow");
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> Result<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| anyhow!("Truncated SLEB128 in .eh_frame"))?;
        *pos += 1;
        ensure!(shift < 64, "SLEB128 overflow");
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Ok(result);
        }
    }
}

fn read_encoded_ptr(
    data: &[u8],
    pos: &mut usize,
    encoding: u8,
    field_vaddr: u64,
    section_vaddr: u64,
) -> Result<u64> {
    if encoding == 0xff {
        return Ok(0);
    }
    let raw: i128 = match encoding & 0x0f {
        0x00 | 0x04 => {
            let b = data.get(*pos..*pos + 8).ok_or_else(|| anyhow!("Truncated u64 ptr"))?;
            *pos += 8;
            u64::from_le_bytes(b.try_into()?) as i128
        }
        0x01 => read_uleb128(data, pos)? as i128,
        0x02 => {
            let b = data.get(*pos..*pos + 2).ok_or_else(|| anyhow!("Truncated u16 ptr"))?;
            *pos += 2;
            u16::from_le_bytes(b.try_into()?) as i128
        }
        0x03 => {
            let b = data.get(*pos..*pos + 4).ok_or_else(|| anyhow!("Truncated u32 ptr"))?;
            *pos += 4;
            u32::from_le_bytes(b.try_into()?) as i128
        }
        0x09 => read_sleb128(data, pos)? as i128,
        0x0a => {
            let b = data.get(*pos..*pos + 2).ok_or_else(|| anyhow!("Truncated i16 ptr"))?;
            *pos += 2;
            i16::from_le_bytes(b.try_into()?) as i128
        }
        0x0b => {
            let b = data.get(*pos..*pos + 4).ok_or_else(|| anyhow!("Truncated i32 ptr"))?;
            *pos += 4;
            i32::from_le_bytes(b.try_into()?) as i128
        }
        0x0c => {
            let b = data.get(*pos..*pos + 8).ok_or_else(|| anyhow!("Truncated i64 ptr"))?;
            *pos += 8;
            i64::from_le_bytes(b.try_into()?) as i128
        }
        other => bail!("Unsupported DWARF pointer format {other:#x}"),
    };
    let base: i128 = match encoding & 0x70 {
        0x00 => 0,
        0x10 => field_vaddr as i128,
        0x30 => section_vaddr as i128,
        other => bail!("Unsupported DWARF pointer application {other:#x}"),
    };
    Ok((base + raw) as u64)
}

fn execute_cfi(
    program: &[u8],
    cie: &Cie,
    mut pc: u64,
    target_pc: u64,
    row: &mut UnwindRow,
) -> Result<()> {
    let mut pos = 0usize;
    let mut ops = 0usize;
    let mut stack: Vec<UnwindRow> = Vec::new();
    while pos < program.len() && pc <= target_pc {
        ops += 1;
        ensure!(ops <= MAX_CFI_OPS, "CFI program exceeds instruction cap");
        let opcode = program[pos];
        pos += 1;
        match opcode >> 6 {
            1 => {
                // DW_CFA_advance_loc (delta in low 6 bits)
                let delta = u64::from(opcode & 0x3f) * cie.code_align;
                if pc.saturating_add(delta) > target_pc {
                    break;
                }
                pc = pc.saturating_add(delta);
            }
            2 => {
                // DW_CFA_offset (reg in low 6 bits, factored ULEB128 offset)
                let reg = opcode & 0x3f;
                let off = read_uleb128(program, &mut pos)? as i64 * cie.data_align;
                row.regs.insert(reg, RegRule::Offset(off));
            }
            3 => {
                // DW_CFA_restore (reg in low 6 bits) — reset to SameValue
                let reg = opcode & 0x3f;
                row.regs.insert(reg, RegRule::SameValue);
            }
            0 => match opcode {
                0x00 => {} // DW_CFA_nop
                0x01 => {
                    // DW_CFA_set_loc
                    let next = read_encoded_ptr(program, &mut pos, cie.fde_encoding & 0x0f, 0, 0)?;
                    if next > target_pc {
                        break;
                    }
                    pc = next;
                }
                0x02 => {
                    // DW_CFA_advance_loc1
                    let d = u64::from(*program.get(pos).ok_or_else(|| anyhow!("Truncated loc1"))?)
                        * cie.code_align;
                    pos += 1;
                    if pc.saturating_add(d) > target_pc {
                        break;
                    }
                    pc = pc.saturating_add(d);
                }
                0x03 => {
                    // DW_CFA_advance_loc2
                    let b = program.get(pos..pos + 2).ok_or_else(|| anyhow!("Truncated loc2"))?;
                    pos += 2;
                    let d = u64::from(u16::from_le_bytes(b.try_into()?)) * cie.code_align;
                    if pc.saturating_add(d) > target_pc {
                        break;
                    }
                    pc = pc.saturating_add(d);
                }
                0x04 => {
                    // DW_CFA_advance_loc4
                    let b = program.get(pos..pos + 4).ok_or_else(|| anyhow!("Truncated loc4"))?;
                    pos += 4;
                    let d = u64::from(u32::from_le_bytes(b.try_into()?)) * cie.code_align;
                    if pc.saturating_add(d) > target_pc {
                        break;
                    }
                    pc = pc.saturating_add(d);
                }
                0x05 => {
                    // DW_CFA_offset_extended
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    let off = read_uleb128(program, &mut pos)? as i64 * cie.data_align;
                    row.regs.insert(reg, RegRule::Offset(off));
                }
                0x06 => {
                    // DW_CFA_restore_extended
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    row.regs.insert(reg, RegRule::SameValue);
                }
                0x07 => {
                    // DW_CFA_undefined
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    row.regs.insert(reg, RegRule::Undefined);
                }
                0x08 => {
                    // DW_CFA_same_value
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    row.regs.insert(reg, RegRule::SameValue);
                }
                0x0a => {
                    if stack.len() < 16 {
                        stack.push(row.clone());
                    }
                }
                0x0b => {
                    if let Some(prev) = stack.pop() {
                        *row = prev;
                    }
                }
                0x0c => {
                    // DW_CFA_def_cfa
                    row.cfa_reg = read_uleb128(program, &mut pos)? as u8;
                    row.cfa_offset = read_uleb128(program, &mut pos)? as i64;
                }
                0x0d => {
                    // DW_CFA_def_cfa_register
                    row.cfa_reg = read_uleb128(program, &mut pos)? as u8;
                }
                0x0e => {
                    // DW_CFA_def_cfa_offset
                    row.cfa_offset = read_uleb128(program, &mut pos)? as i64;
                }
                0x11 => {
                    // DW_CFA_offset_extended_sf
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    let off = read_sleb128(program, &mut pos)? * cie.data_align;
                    row.regs.insert(reg, RegRule::Offset(off));
                }
                0x12 => {
                    // DW_CFA_def_cfa_sf
                    row.cfa_reg = read_uleb128(program, &mut pos)? as u8;
                    row.cfa_offset = read_sleb128(program, &mut pos)? * cie.data_align;
                }
                0x13 => {
                    // DW_CFA_def_cfa_offset_sf
                    row.cfa_offset = read_sleb128(program, &mut pos)? * cie.data_align;
                }
                0x14 => {
                    // DW_CFA_val_offset
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    let off = read_uleb128(program, &mut pos)? as i64 * cie.data_align;
                    row.regs.insert(reg, RegRule::ValOffset(off));
                }
                0x15 => {
                    // DW_CFA_val_offset_sf
                    let reg = read_uleb128(program, &mut pos)? as u8;
                    let off = read_sleb128(program, &mut pos)? * cie.data_align;
                    row.regs.insert(reg, RegRule::ValOffset(off));
                }
                0x2e => {
                    // DW_CFA_GNU_args_size
                    let _ = read_uleb128(program, &mut pos)?;
                }
                // Unsupported DWARF expressions (0x0f/0x10/0x16): bail cleanly so caller falls back
                other => bail!("Unsupported CFI opcode {other:#x}"),
            },
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn parse_cie(record: &[u8], record_vaddr: u64, section_vaddr: u64) -> Result<Cie> {
    ensure!(record.len() >= 9, "CIE record too small");
    let mut pos = 4usize; // skip CIE_id (0)
    let version = record[pos];
    ensure!(matches!(version, 1 | 3 | 4), "Unsupported CIE version {version}");
    pos += 1;
    let aug_end = record[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("Unterminated CIE augmentation"))?
        + pos;
    let aug = std::str::from_utf8(&record[pos..aug_end]).unwrap_or("");
    pos = aug_end + 1;
    if version == 4 {
        pos += 2; // address_size + segment_size
    }
    let code_align = read_uleb128(record, &mut pos)?;
    let data_align = read_sleb128(record, &mut pos)?;
    let return_reg = if version == 1 {
        let r = *record.get(pos).ok_or_else(|| anyhow!("Truncated CIE"))?;
        pos += 1;
        r
    } else {
        read_uleb128(record, &mut pos)? as u8
    };
    let mut fde_encoding = 0x00u8; // absptr default
    if let Some(rest) = aug.strip_prefix('z') {
        let aug_len = read_uleb128(record, &mut pos)? as usize;
        let aug_data_end = (pos + aug_len).min(record.len());
        let mut apos = pos;
        for ch in rest.chars() {
            if apos >= aug_data_end {
                break;
            }
            match ch {
                'R' => {
                    fde_encoding = record[apos];
                    apos += 1;
                }
                'L' => {
                    apos += 1; // LSDA encoding byte
                }
                'P' => {
                    let enc = record[apos];
                    apos += 1;
                    let field_va = record_vaddr + apos as u64;
                    let _ = read_encoded_ptr(record, &mut apos, enc, field_va, section_vaddr)?;
                }
                'S' | 'B' => {}
                _ => break,
            }
        }
        pos = aug_data_end;
    }
    Ok(Cie {
        code_align: code_align.max(1),
        data_align,
        return_reg,
        fde_encoding,
        initial_instructions: record[pos..].to_vec(),
    })
}

/// Find the unwind row for `pc` within a raw `.eh_frame` section mapped at `section_vaddr`.
pub fn unwind_at_pc(
    eh_frame: &[u8],
    section_vaddr: u64,
    pc: u64,
) -> Result<Option<(UnwindRow, u8)>> {
    let mut cies: HashMap<usize, (Cie, bool)> = HashMap::new();
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos + 4 <= eh_frame.len() && count < MAX_FDES {
        count += 1;
        let record_start = pos;
        let len32 = u32::from_le_bytes(eh_frame[pos..pos + 4].try_into()?);
        pos += 4;
        if len32 == 0 {
            break;
        }
        let length = if len32 == 0xffff_ffff {
            if pos + 8 > eh_frame.len() {
                break;
            }
            let len64 = u64::from_le_bytes(eh_frame[pos..pos + 8].try_into()?) as usize;
            pos += 8;
            len64
        } else {
            len32 as usize
        };
        if length < 4 || pos + length > eh_frame.len() {
            break;
        }
        let body = &eh_frame[pos..pos + length];
        let body_vaddr = section_vaddr + pos as u64;
        let cie_ptr = u32::from_le_bytes(body[0..4].try_into()?);
        if cie_ptr == 0 {
            let has_z = body.get(5).copied() == Some(b'z');
            if let Ok(cie) = parse_cie(body, body_vaddr, section_vaddr) {
                cies.insert(record_start, (cie, has_z));
            }
        } else if let Some(cie_offset) = pos.checked_sub(cie_ptr as usize)
            && let Some((cie, has_z)) = cies.get(&cie_offset)
        {
            let mut fpos = 4usize;
            let pc_field_va = section_vaddr + (pos + fpos) as u64;
            if let Ok(initial_loc) =
                read_encoded_ptr(body, &mut fpos, cie.fde_encoding, pc_field_va, section_vaddr)
                && let Ok(range) =
                    read_encoded_ptr(body, &mut fpos, cie.fde_encoding & 0x0f, 0, 0)
                && pc >= initial_loc
                && pc < initial_loc.saturating_add(range)
            {
                if *has_z {
                    let aug_len = read_uleb128(body, &mut fpos)? as usize;
                    fpos = (fpos + aug_len).min(body.len());
                }
                let mut row = UnwindRow::default();
                execute_cfi(&cie.initial_instructions, cie, initial_loc, initial_loc, &mut row)?;
                execute_cfi(&body[fpos..], cie, initial_loc, pc, &mut row)?;
                return Ok(Some((row, cie.return_reg)));
            }
        }
        pos += length;
    }
    Ok(None)
}

/// Locate the `.eh_frame` range `(vaddr, byte_size)` from an in-memory ELF64 header
/// and program headers (`PT_GNU_EH_FRAME` = `0x6474e550` -> `.eh_frame_hdr` -> `.eh_frame`).
///
/// Returns `(eh_frame_vaddr, max_size_to_read)` when present.
pub fn find_eh_frame_from_elf_header(
    header_page: &[u8],
    module_base: u64,
    module_end: u64,
    read_hdr: impl FnOnce(u64, usize) -> Result<Vec<u8>>,
) -> Option<(u64, usize)> {
    if header_page.len() < 64 || &header_page[..4] != b"\x7fELF" || header_page[4] != 2 {
        return None;
    }
    let phoff = u64::from_le_bytes(header_page[32..40].try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(header_page[54..56].try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(header_page[56..58].try_into().ok()?) as usize;
    if phentsize < 56 || phnum > 128 || phoff + phnum * phentsize > header_page.len() {
        return None;
    }
    let mut min_vaddr = u64::MAX;
    let mut eh_hdr = None;
    for i in 0..phnum {
        let b = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(header_page[b..b + 4].try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(header_page[b + 16..b + 24].try_into().ok()?);
        let p_memsz = u64::from_le_bytes(header_page[b + 40..b + 48].try_into().ok()?);
        if p_type == 1 && p_vaddr < min_vaddr {
            min_vaddr = p_vaddr;
        }
        if p_type == 0x6474_e550 {
            eh_hdr = Some((p_vaddr, p_memsz));
        }
    }
    let (hdr_rel, hdr_sz) = eh_hdr?;
    let load_bias = if min_vaddr == u64::MAX {
        module_base
    } else {
        module_base.wrapping_sub(min_vaddr)
    };
    let hdr_va = load_bias.wrapping_add(hdr_rel);
    if hdr_va < module_base || hdr_va >= module_end {
        return None;
    }
    let hdr_bytes = read_hdr(hdr_va, (hdr_sz as usize).clamp(16, 64)).ok()?;
    if hdr_bytes.len() < 8 || hdr_bytes[0] != 1 {
        return None;
    }
    let eh_frame_ptr_enc = hdr_bytes[1];
    let mut pos = 4usize;
    let eh_frame_va =
        read_encoded_ptr(&hdr_bytes, &mut pos, eh_frame_ptr_enc, hdr_va + 4, hdr_va).ok()?;
    if eh_frame_va < module_base || eh_frame_va >= module_end {
        return None;
    }
    let max_len = (module_end - eh_frame_va).min(262_144) as usize;
    Some((eh_frame_va, max_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwinds_frame_pointer_omitted_function_via_dwarf_cfi() {
        // Construct a canonical Clang x86-64 CIE ("zR", code_align=1, data_align=-8, ret=16, enc=0x1b pcrel|sdata4)
        // Initial: DW_CFA_def_cfa(rsp=7, 8), DW_CFA_offset(rip=16, 1 * -8)
        // FDE for [0x401000..0x401040):
        //   +4 bytes (`sub rsp, 0x28`): DW_CFA_advance_loc(4), DW_CFA_def_cfa_offset(0x30)
        //   +4 bytes (`push rbx` equivalent save at rsp+0x20): DW_CFA_advance_loc(4), DW_CFA_offset(rbx=3, 2 * -8)
        let mut sec = Vec::new();
        let cie_body = vec![
            0, 0, 0, 0, // CIE_id = 0
            1,          // version = 1
            b'z', b'R', 0, // augmentation "zR\0"
            1,          // code_align = 1
            0x78,       // data_align = -8 (SLEB128)
            16,         // return_address_register = 16 (rip)
            1,          // augmentation length = 1
            0x1b,       // DW_EH_PE_pcrel | DW_EH_PE_sdata4
            0x0c, 7, 8, // DW_CFA_def_cfa(rsp, 8)
            0x80 | 16, 1, // DW_CFA_offset(rip, 1 * -8)
            0,          // pad to 4-byte multiple
        ];
        sec.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
        sec.extend_from_slice(&cie_body);

        let sec_vaddr = 0x402000u64;
        let fde_body_pos = sec.len() + 4;
        let cie_ptr = fde_body_pos as u32; // offset back to CIE at 0
        let pc_field_va = sec_vaddr + (fde_body_pos + 4) as u64;
        let rel_pc = (0x401000i64 - pc_field_va as i64) as i32;
        let mut fde_body = Vec::new();
        fde_body.extend_from_slice(&cie_ptr.to_le_bytes());
        fde_body.extend_from_slice(&rel_pc.to_le_bytes());
        fde_body.extend_from_slice(&0x40i32.to_le_bytes()); // range = 0x40
        fde_body.push(0); // aug_len = 0
        fde_body.extend_from_slice(&[
            0x40 | 4,   // advance_loc(4) -> 0x401004
            0x0e, 0x30, // def_cfa_offset(0x30)
            0x40 | 4,   // advance_loc(4) -> 0x401008
            0x80 | 3, 2, // offset(rbx=3, 2 * -8 = -16)
        ]);
        sec.extend_from_slice(&(fde_body.len() as u32).to_le_bytes());
        sec.extend_from_slice(&fde_body);
        sec.extend_from_slice(&0u32.to_le_bytes()); // terminator

        // At entry 0x401000: CFA = rsp + 8, rip at [CFA - 8] = [rsp]
        let (row0, ret_reg) = unwind_at_pc(&sec, sec_vaddr, 0x401000).unwrap().unwrap();
        assert_eq!(ret_reg, DWARF_RIP);
        assert_eq!(row0.cfa_reg, DWARF_RSP);
        assert_eq!(row0.cfa_offset, 8);
        assert_eq!(row0.regs.get(&DWARF_RIP), Some(&RegRule::Offset(-8)));

        // After `sub rsp, 0x28` at 0x401010: CFA = rsp + 0x30, rip at [CFA - 8] = [rsp + 0x28], rbx at [CFA - 16]
        let (row1, _) = unwind_at_pc(&sec, sec_vaddr, 0x401010).unwrap().unwrap();
        assert_eq!(row1.cfa_offset, 0x30);
        assert_eq!(row1.regs.get(&DWARF_RIP), Some(&RegRule::Offset(-8)));
        assert_eq!(row1.regs.get(&3), Some(&RegRule::Offset(-16)));

        // Outside FDE range returns None
        assert!(unwind_at_pc(&sec, sec_vaddr, 0x401050).unwrap().is_none());
    }
}
