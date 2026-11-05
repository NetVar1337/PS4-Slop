//! Shortest unique wildcarded AOB signatures (`48 8B ?? ??` syntax shared with
//! `pattern_scan` / `memory_search`), verified by scanning the module's
//! executable segments with the existing pattern engine.

use anyhow::{bail, ensure};
use iced_x86::{ConstantOffsets, FlowControl, Instruction};
use serde_json::{Value, json};

use crate::Result;
use crate::binimage::Image;
use crate::cfg::{decode_at, hex, near_target};

pub const MAX_PATTERN: usize = 256;
const REFERENCE_SWEEP_BUDGET: usize = 4_000_000;

#[derive(Clone, Debug)]
pub struct SigOptions {
    pub min_length: usize,
    pub max_length: usize,
    /// Also wildcard every 32/64-bit displacement and immediate (struct offsets,
    /// constants) for signatures that survive more rebuilds.
    pub wildcard_operands: bool,
}

impl Default for SigOptions {
    fn default() -> Self {
        SigOptions { min_length: 5, max_length: 64, wildcard_operands: false }
    }
}

fn address_like(image: &Image, value: u64) -> bool {
    image.base >= 0x10000 && image.contains(value)
}

/// Bytes of the instruction at `va` with a per-byte wildcard mask: relative
/// branch targets, RIP-relative displacements and absolute image addresses are
/// wildcarded (they move with relocation / relinking).
pub fn masked_instruction(image: &Image, va: u64, wildcard_operands: bool) -> Option<(Instruction, Vec<u8>, Vec<bool>)> {
    let (instruction, offsets) = decode_at(image, va)?;
    let bytes = image.read(va, instruction.len())?.to_vec();
    let mask = mask_for(image, &instruction, &offsets, wildcard_operands);
    Some((instruction, bytes, mask))
}

pub fn mask_for(image: &Image, instruction: &Instruction, offsets: &ConstantOffsets, wildcard_operands: bool) -> Vec<bool> {
    let mut mask = vec![false; instruction.len()];
    let mut set = |offset: usize, size: usize| {
        for flag in mask.iter_mut().skip(offset).take(size) {
            *flag = true;
        }
    };
    if offsets.has_displacement() {
        let size = offsets.displacement_size();
        let value = instruction.memory_displacement64();
        if instruction.is_ip_rel_memory_operand() || (size >= 4 && (address_like(image, value) || wildcard_operands)) {
            set(offsets.displacement_offset(), size);
        }
    }
    if offsets.has_immediate() {
        let size = offsets.immediate_size();
        let branch = near_target(instruction).is_some();
        let wild = if branch {
            size >= 4
        } else {
            let value = (0..instruction.op_count())
                .find_map(|op| instruction.try_immediate(op).ok())
                .unwrap_or(0);
            size >= 4 && (address_like(image, value) || wildcard_operands)
        };
        if wild {
            set(offsets.immediate_offset(), size);
        }
    }
    mask
}

pub fn pattern_text(pattern: &[Option<u8>]) -> String {
    pattern
        .iter()
        .map(|byte| byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Matches of `pattern` in the executable segments, stopping after `limit`.
pub fn find(image: &Image, pattern: &[Option<u8>], limit: usize) -> Vec<u64> {
    let mut found = Vec::new();
    let Some(anchor) = pattern.iter().position(Option::is_some) else { return found };
    let anchor_byte = pattern[anchor].unwrap_or_default();
    for segment in image.exec_segments() {
        let data = &segment.data;
        if data.len() < pattern.len() {
            continue;
        }
        for offset in 0..=data.len() - pattern.len() {
            if data[offset + anchor] != anchor_byte {
                continue;
            }
            if pattern
                .iter()
                .zip(&data[offset..])
                .all(|(want, have)| want.is_none_or(|byte| byte == *have))
            {
                found.push(segment.vaddr + offset as u64);
                if found.len() >= limit {
                    return found;
                }
            }
        }
    }
    found
}

/// Verify with the shared `pattern_scan` engine.
fn verify(image: &Image, text: &str) -> Result<Vec<u64>> {
    let mut matches = Vec::new();
    for segment in image.exec_segments() {
        let result = crate::analysis::scan_pattern_at(&segment.data, text, segment.vaddr, 8)?;
        for item in result["matches"].as_array().into_iter().flatten() {
            if let Some(value) = item.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()) {
                matches.push(value);
            }
        }
    }
    Ok(matches)
}

#[derive(Debug)]
pub struct Signature {
    pub pattern: Vec<Option<u8>>,
    pub instructions: usize,
}

/// Grow instruction by instruction from `va` until unique, then trim to the
/// shortest unique prefix (not below `min_length`).
pub fn grow(image: &Image, va: u64, options: &SigOptions) -> std::result::Result<Signature, String> {
    let max = options.max_length.min(MAX_PATTERN);
    let mut pattern: Vec<Option<u8>> = Vec::new();
    let mut pc = va;
    let mut instructions = 0usize;
    let mut boundaries = Vec::new();
    loop {
        if pattern.len() >= max {
            return Err(format!("not unique within max_length={max} bytes"));
        }
        let Some((instruction, bytes, mask)) = masked_instruction(image, pc, options.wildcard_operands) else {
            return Err(format!("undecodable or non-executable bytes at {pc:#x} before the signature became unique"));
        };
        for (byte, wild) in bytes.iter().zip(&mask) {
            if pattern.len() < max {
                pattern.push((!wild).then_some(*byte));
            }
        }
        instructions += 1;
        boundaries.push(pattern.len());
        pc = instruction.next_ip();
        if pattern.len() >= options.min_length && pattern.iter().any(Option::is_some) {
            let matches = find(image, &pattern, 2);
            if matches == [va] {
                break;
            }
        }
        // Never extend past the end of the code path (into padding / the next function).
        if matches!(
            instruction.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Exception
        ) || matches!(instruction.mnemonic(), iced_x86::Mnemonic::Int3 | iced_x86::Mnemonic::Hlt)
        {
            return Err(format!("not unique before the code path ends at {:#x}", instruction.ip()));
        }
    }
    // Binary search for the shortest unique prefix.
    let (mut lo, mut hi) = (options.min_length.max(1), pattern.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        let prefix = &pattern[..mid];
        if prefix.iter().any(Option::is_some) && find(image, prefix, 2) == [va] {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    pattern.truncate(hi);
    while pattern.last() == Some(&None) && pattern.len() > options.min_length {
        pattern.pop();
    }
    // Instructions whose first byte is still covered by the trimmed pattern.
    let covered = 1 + boundaries.iter().filter(|end| **end < pattern.len()).count();
    Ok(Signature { pattern, instructions: covered.min(instructions) })
}

/// Code references to `target`: rel32 branches/calls and RIP-relative operands.
pub fn references(image: &Image, target: u64, limit: usize) -> (Vec<(u64, usize, usize, &'static str)>, bool) {
    let mut found = Vec::new();
    let mut budget = REFERENCE_SWEEP_BUDGET;
    for segment in image.exec_segments() {
        let mut decoder = iced_x86::Decoder::with_ip(64, &segment.data, segment.vaddr, iced_x86::DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            if budget == 0 {
                return (found, true);
            }
            budget -= 1;
            let position = decoder.position();
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                if decoder.set_position(position + 1).is_err() {
                    break;
                }
                decoder.set_ip(segment.vaddr + position as u64 + 1);
                continue;
            }
            let offsets = decoder.get_constant_offsets(&instruction);
            let hit = if near_target(&instruction) == Some(target) && offsets.immediate_size() == 4 {
                Some((offsets.immediate_offset(), "branch_rel32"))
            } else if instruction.is_ip_rel_memory_operand() && instruction.ip_rel_memory_address() == target {
                Some((offsets.displacement_offset(), "rip_relative"))
            } else {
                None
            };
            if let Some((operand, kind)) = hit {
                found.push((instruction.ip(), instruction.len(), operand, kind));
                if found.len() >= limit {
                    return (found, true);
                }
            }
        }
    }
    (found, false)
}

pub fn make(image: &Image, target: u64, options: &SigOptions, via_reference: &str) -> Result<Value> {
    ensure!(image.is_exec(target), "Address {target:#x} is not inside an executable segment");
    ensure!(options.min_length >= 1 && options.min_length <= options.max_length, "min_length must be 1..=max_length");
    let rva = |va: u64| hex(va.wrapping_sub(image.base));
    let mut result = json!({
        "address": hex(target), "rva": rva(target), "image_base": hex(image.base),
        "syntax": "space-separated hex bytes with ?? wildcards; accepted by pattern_scan and memory_search",
        "wildcards": if options.wildcard_operands { "relative branches, RIP-relative/absolute addresses, all 32/64-bit operands" } else { "relative branches, RIP-relative displacements, absolute image addresses" },
    });
    let mut direct_ok = false;
    if via_reference != "only" {
        match grow(image, target, options) {
            Ok(signature) => {
                let text = pattern_text(&signature.pattern);
                let verified = verify(image, &text)?;
                ensure!(verified == [target], "Internal error: verification scan disagrees ({verified:x?})");
                result["direct"] = json!({
                    "pattern": text, "length": signature.pattern.len(),
                    "wildcards": signature.pattern.iter().filter(|b| b.is_none()).count(),
                    "instructions": signature.instructions, "match_offset": 0,
                    "unique": true, "verified_matches": verified.iter().map(|va| hex(*va)).collect::<Vec<_>>(),
                });
                direct_ok = true;
            }
            Err(reason) => {
                result["direct"] = Value::Null;
                result["direct_failure"] = json!(reason);
            }
        }
    }
    if via_reference == "only" || (via_reference == "auto" && !direct_ok) {
        let (refs, refs_truncated) = references(image, target, 64);
        result["references_found"] = json!(refs.len());
        result["references_truncated"] = json!(refs_truncated);
        let mut chosen = Value::Null;
        let mut attempts = Vec::new();
        for (site, length, operand, kind) in refs.iter().take(16) {
            match grow(image, *site, options) {
                Ok(signature) => {
                    let text = pattern_text(&signature.pattern);
                    let verified = verify(image, &text)?;
                    if verified != [*site] {
                        continue;
                    }
                    // Check the resolve formula against the actual bytes.
                    let displacement = image
                        .read(site + *operand as u64, 4)
                        .map(|b| i32::from_le_bytes(b.try_into().unwrap_or_default()))
                        .unwrap_or_default();
                    let resolved = (*site as i64 + *length as i64 + displacement as i64) as u64;
                    if resolved != target {
                        continue;
                    }
                    chosen = json!({
                        "pattern": text, "length": signature.pattern.len(),
                        "reference_site": hex(*site), "reference_rva": rva(*site), "kind": kind,
                        "verified_matches": verified.iter().map(|va| hex(*va)).collect::<Vec<_>>(),
                        "resolve": {
                            "operand_offset": operand, "instruction_length": length,
                            "formula": format!("target = match + {length} + int32_le(match + {operand})"),
                            "verified_target": hex(resolved),
                        },
                    });
                    break;
                }
                Err(reason) => attempts.push(json!({"site": hex(*site), "failure": reason})),
            }
        }
        if chosen.is_null() && !attempts.is_empty() {
            result["via_reference_failures"] = json!(attempts);
        }
        result["via_reference"] = chosen;
    }
    if result["direct"].is_null() && result["via_reference"].is_null() {
        bail!(
            "No unique signature found: {}",
            result["direct_failure"].as_str().unwrap_or("no unique reference-site signature")
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::tests::sample;

    #[test]
    fn unique_signature_with_wildcards_and_reference_fallback() {
        let (builder, f0, f1, _) = sample(0x400000);
        let image = Image::from_elf(&builder.build(), None).unwrap();
        let result = make(&image, f0, &SigOptions::default(), "auto").unwrap();
        let pattern = result["direct"]["pattern"].as_str().unwrap();
        assert!(pattern.starts_with("55 48 89 E5"), "{pattern}");
        assert_eq!(result["direct"]["verified_matches"], json!([hex(f0)]));

        // f1 (xor eax,eax; ret) is not unique by itself only if repeated; duplicate it.
        let mut builder2 = builder;
        let mut text = builder2.text.clone();
        text.extend_from_slice(&[0xcc; 13]);
        text.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        builder2.text = text;
        let image = Image::from_elf(&builder2.build(), None).unwrap();
        let result = make(&image, f1, &SigOptions::default(), "auto").unwrap();
        assert!(result["direct"].is_null());
        let via = &result["via_reference"];
        assert_eq!(via["kind"], "branch_rel32");
        assert_eq!(via["resolve"]["verified_target"], hex(f1));
        assert!(via["pattern"].as_str().unwrap().starts_with("E8 ?? ?? ?? ??"));
    }
}
