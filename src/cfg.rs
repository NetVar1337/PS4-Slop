//! Function discovery, control-flow graphs and call graphs over an [`Image`].
//!
//! Recursive descent with iced-x86. Everything is bounded (instructions per
//! function, total instructions, functions) and reports truncation.

use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::binimage::Image;

pub const DEFAULT_MAX_FUNCTION_INSNS: usize = 20_000;
pub const DEFAULT_MAX_TOTAL_INSNS: usize = 4_000_000;
pub const DEFAULT_MAX_FUNCTIONS: usize = 50_000;
const MAX_FDES: usize = 500_000;
const MAX_TABLE_ENTRIES: usize = 1024;

/// Decode one instruction at `va` from an executable segment.
pub fn decode_at(image: &Image, va: u64) -> Option<(Instruction, ConstantOffsets)> {
    if !image.is_exec(va) {
        return None;
    }
    let bytes = image.bytes_from(va)?;
    let window = &bytes[..bytes.len().min(15)];
    let mut decoder = Decoder::with_ip(64, window, va, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }
    let offsets = decoder.get_constant_offsets(&instruction);
    Some((instruction, offsets))
}

pub fn near_target(instruction: &Instruction) -> Option<u64> {
    matches!(instruction.op0_kind(), OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16)
        .then(|| instruction.near_branch_target())
}

fn is_trap(instruction: &Instruction) -> bool {
    matches!(instruction.flow_control(), FlowControl::Exception)
        || matches!(instruction.mnemonic(), Mnemonic::Int3 | Mnemonic::Int1 | Mnemonic::Hlt | Mnemonic::Int)
}

/// Import slot referenced by `call/jmp qword ptr [rip+slot]`.
pub fn import_slot(image: &Image, instruction: &Instruction) -> Option<(u64, String)> {
    if instruction.op0_kind() == OpKind::Memory && instruction.is_ip_rel_memory_operand() {
        let slot = instruction.ip_rel_memory_address();
        return image.imports.get(&slot).map(|name| (slot, name.clone()));
    }
    None
}

// ---- .eh_frame --------------------------------------------------------------

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        if shift > 70 {
            return None;
        }
    }
}

fn sleb(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some(result);
        }
        if shift > 70 {
            return None;
        }
    }
}

fn encoded(data: &[u8], pos: &mut usize, encoding: u8, field_va: u64) -> Option<u64> {
    if encoding == 0xff {
        return Some(0);
    }
    let take = |pos: &mut usize, n: usize| -> Option<u64> {
        let bytes = data.get(*pos..*pos + n)?;
        *pos += n;
        let mut buffer = [0u8; 8];
        buffer[..n].copy_from_slice(bytes);
        Some(u64::from_le_bytes(buffer))
    };
    let value = match encoding & 0x0f {
        0x00 | 0x04 | 0x0c => take(pos, 8)?,
        0x01 => uleb(data, pos)?,
        0x02 => take(pos, 2)?,
        0x03 => take(pos, 4)?,
        0x09 => sleb(data, pos)? as u64,
        0x0a => take(pos, 2)? as i16 as i64 as u64,
        0x0b => take(pos, 4)? as u32 as i32 as i64 as u64,
        _ => return None,
    };
    Some(match encoding & 0x70 {
        0x10 => field_va.wrapping_add(value),
        _ => value,
    })
}

/// `.eh_frame` location: section header, else `PT_GNU_EH_FRAME` -> `eh_frame_ptr`.
fn eh_frame_location(image: &Image) -> Option<(u64, u64)> {
    if let Some(found) = image.eh_frame {
        return Some(found);
    }
    let (hdr_va, _) = image.eh_frame_hdr?;
    let hdr = image.read(hdr_va, 4)?;
    if hdr[0] != 1 {
        return None;
    }
    let bytes = image.bytes_from(hdr_va)?;
    let mut pos = 4;
    let va = encoded(bytes, &mut pos, hdr[1], hdr_va + 4)?;
    let segment = image.segment_at(va)?;
    Some((va, segment.data_end() - va))
}

/// Every FDE `(start, end)` in the image's `.eh_frame`.
pub fn eh_frame_ranges(image: &Image) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let Some((section_va, size)) = eh_frame_location(image) else { return ranges };
    let Some(all) = image.bytes_from(section_va) else { return ranges };
    let data = &all[..all.len().min(size as usize)];
    let mut cies: HashMap<usize, (u8, bool)> = HashMap::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() && ranges.len() < MAX_FDES {
        let record = pos;
        let len32 = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default());
        pos += 4;
        if len32 == 0 {
            break;
        }
        let length = if len32 == 0xffff_ffff {
            let Some(bytes) = data.get(pos..pos + 8) else { break };
            pos += 8;
            u64::from_le_bytes(bytes.try_into().unwrap_or_default()) as usize
        } else {
            len32 as usize
        };
        let Some(body) = data.get(pos..pos.saturating_add(length)) else { break };
        if body.len() < 4 {
            break;
        }
        let id = u32::from_le_bytes(body[..4].try_into().unwrap_or_default());
        if id == 0 {
            if let Some(cie) = parse_cie(body) {
                cies.insert(record, cie);
            }
        } else if let Some(cie_record) = pos.checked_sub(id as usize)
            && let Some((encoding, _)) = cies.get(&cie_record)
        {
            let mut fpos = 4usize;
            let field_va = section_va + (pos + fpos) as u64;
            if let Some(start) = encoded(body, &mut fpos, *encoding, field_va)
                && let Some(range) = encoded(body, &mut fpos, encoding & 0x0f, 0)
                && range > 0
                && range < 0x100_0000
            {
                ranges.push((start, start.wrapping_add(range)));
            }
        }
        pos += length;
    }
    ranges
}

fn parse_cie(body: &[u8]) -> Option<(u8, bool)> {
    let version = *body.get(4)?;
    let mut pos = 5;
    let aug_end = pos + body.get(pos..)?.iter().position(|b| *b == 0)?;
    let augmentation = body[pos..aug_end].to_vec();
    pos = aug_end + 1;
    if augmentation.windows(2).any(|w| w == b"eh") {
        pos += 8;
    }
    uleb(body, &mut pos)?;
    sleb(body, &mut pos)?;
    if version == 1 {
        pos += 1;
    } else {
        uleb(body, &mut pos)?;
    }
    let mut encoding = 0u8;
    if augmentation.first() == Some(&b'z') {
        uleb(body, &mut pos)?;
        for byte in &augmentation[1..] {
            match byte {
                b'R' => {
                    encoding = *body.get(pos)?;
                    pos += 1;
                }
                b'P' => {
                    let personality = *body.get(pos)?;
                    pos += 1;
                    encoded(body, &mut pos, personality & 0x7f, 0)?;
                }
                b'L' => pos += 1,
                _ => {}
            }
        }
    }
    Some((encoding, augmentation.first() == Some(&b'z')))
}

// ---- function CFG -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub instructions: u32,
    pub successors: Vec<(u64, &'static str)>,
    pub terminator: &'static str,
}

#[derive(Clone, Debug)]
pub struct CallSite {
    pub at: u64,
    pub target: Option<u64>,
    pub import: Option<String>,
    /// `direct`, `indirect`, `import`, `tail`, `tail_import`.
    pub kind: &'static str,
}

#[derive(Clone, Debug)]
pub struct JumpTable {
    pub at: u64,
    pub table: u64,
    pub entries: Vec<u64>,
    pub bounded_by: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct FunctionCfg {
    pub start: u64,
    pub end: u64,
    pub blocks: Vec<Block>,
    pub calls: Vec<CallSite>,
    pub jump_tables: Vec<JumpTable>,
    pub instructions: usize,
    pub truncated: bool,
    pub unresolved_indirect_jumps: usize,
    /// Instruction start addresses in address order (for hashing/alignment).
    pub insn_addrs: Vec<u64>,
}

impl FunctionCfg {
    pub fn edge_count(&self) -> usize {
        self.blocks.iter().map(|block| block.successors.len()).sum()
    }
}

fn reg_eq(a: Register, b: Register) -> bool {
    a != Register::None && a.full_register() == b.full_register()
}

/// Best-effort switch-table recovery for an indirect `jmp` at `at`.
fn jump_table(image: &Image, insns: &BTreeMap<u64, Instruction>, at: u64, jmp: &Instruction) -> Option<JumpTable> {
    let previous: Vec<&Instruction> = insns.range(..at).rev().take(24).map(|(_, i)| i).collect();
    let bound = previous.iter().find_map(|instruction| {
        (instruction.mnemonic() == Mnemonic::Cmp
            && instruction.op_count() == 2
            && matches!(instruction.op1_kind(), OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64))
        .then(|| instruction.immediate(1))
        .filter(|value| *value < MAX_TABLE_ENTRIES as u64)
    });
    let lea_base = |base: Register| -> Option<u64> {
        previous.iter().find_map(|instruction| {
            (instruction.mnemonic() == Mnemonic::Lea && reg_eq(instruction.op0_register(), base) && instruction.is_ip_rel_memory_operand())
                .then(|| instruction.ip_rel_memory_address())
        })
    };
    let (table, relative, width) = if jmp.op0_kind() == OpKind::Register {
        // lea B,[rip+T]; movsxd R,dword ptr [B+I*4]; add R,B; jmp R
        let movsxd = previous.iter().find(|instruction| {
            instruction.mnemonic() == Mnemonic::Movsxd && instruction.op1_kind() == OpKind::Memory && instruction.memory_index_scale() == 4
        })?;
        (lea_base(movsxd.memory_base())?, true, 4usize)
    } else if jmp.op0_kind() == OpKind::Memory && jmp.memory_index_scale() == 8 && !jmp.is_ip_rel_memory_operand() {
        let table = if jmp.memory_base() == Register::None {
            jmp.memory_displacement64()
        } else {
            lea_base(jmp.memory_base())?.wrapping_add(jmp.memory_displacement64())
        };
        (table, false, 8usize)
    } else {
        return None;
    };
    let limit = bound.map_or(256, |value| value as usize + 1);
    let mut entries = Vec::new();
    for index in 0..limit {
        let Some(bytes) = image.read(table + (index * width) as u64, width) else { break };
        let target = if relative {
            table.wrapping_add(i32::from_le_bytes(bytes.try_into().ok()?) as i64 as u64)
        } else {
            u64::from_le_bytes(bytes.try_into().ok()?)
        };
        if !image.is_exec(target) {
            break;
        }
        entries.push(target);
    }
    (!entries.is_empty()).then_some(JumpTable {
        at,
        table,
        entries,
        bounded_by: if bound.is_some() { "cmp" } else { "heuristic" },
    })
}

/// Recursive-descent CFG of the function at `start`. Direct jumps to another
/// known function start, or outside `bound` (FDE/symbol range), are tail calls.
pub fn function_cfg(
    image: &Image,
    start: u64,
    known_starts: &BTreeSet<u64>,
    bound: Option<(u64, u64)>,
    max_insns: usize,
) -> FunctionCfg {
    let mut cfg = FunctionCfg { start, ..Default::default() };
    let mut insns: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::from([start]);
    let mut tails: BTreeMap<u64, CallSite> = BTreeMap::new();
    let mut tables: BTreeMap<u64, JumpTable> = BTreeMap::new();
    let mut work = vec![start];
    let in_bound = |target: u64| bound.is_none_or(|(lo, hi)| lo <= target && target < hi);
    let is_tail = |target: u64| target != start && (known_starts.contains(&target) || !in_bound(target));
    'outer: while let Some(mut pc) = work.pop() {
        loop {
            if insns.contains_key(&pc) {
                leaders.insert(pc);
                break;
            }
            if insns.len() >= max_insns {
                cfg.truncated = true;
                break 'outer;
            }
            let Some((instruction, _)) = decode_at(image, pc) else { break };
            insns.insert(pc, instruction);
            let next = instruction.next_ip();
            if is_trap(&instruction) {
                break;
            }
            match instruction.flow_control() {
                FlowControl::ConditionalBranch => {
                    if let Some(target) = near_target(&instruction)
                        && image.is_exec(target)
                    {
                        if is_tail(target) {
                            tails.insert(pc, CallSite { at: pc, target: Some(target), import: None, kind: "tail" });
                        } else {
                            leaders.insert(target);
                            work.push(target);
                        }
                    }
                    leaders.insert(next);
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = near_target(&instruction)
                        && image.is_exec(target)
                    {
                        if is_tail(target) {
                            tails.insert(pc, CallSite { at: pc, target: Some(target), import: None, kind: "tail" });
                        } else {
                            leaders.insert(target);
                            work.push(target);
                        }
                    }
                    break;
                }
                FlowControl::IndirectBranch => {
                    if let Some((_, name)) = import_slot(image, &instruction) {
                        tails.insert(pc, CallSite { at: pc, target: None, import: Some(name), kind: "tail_import" });
                    } else if let Some(table) = jump_table(image, &insns, pc, &instruction) {
                        for entry in &table.entries {
                            if in_bound(*entry) {
                                leaders.insert(*entry);
                                work.push(*entry);
                            }
                        }
                        tables.insert(pc, table);
                    } else {
                        cfg.unresolved_indirect_jumps += 1;
                    }
                    break;
                }
                FlowControl::Return => break,
                FlowControl::Call => {
                    let target = near_target(&instruction);
                    cfg.calls.push(CallSite { at: pc, target, import: None, kind: "direct" });
                }
                FlowControl::IndirectCall => {
                    let import = import_slot(image, &instruction).map(|(_, name)| name);
                    let kind = if import.is_some() { "import" } else { "indirect" };
                    cfg.calls.push(CallSite { at: pc, target: None, import, kind });
                }
                _ => {}
            }
            pc = next;
        }
    }
    // Build blocks over the decoded instructions.
    let mut current: Option<Block> = None;
    let mut blocks = Vec::new();
    let finish = |block: Block, blocks: &mut Vec<Block>| blocks.push(block);
    for (&address, instruction) in &insns {
        if let Some(block) = current.as_ref()
            && (block.end != address || leaders.contains(&address))
        {
            let mut block = current.take().unwrap_or_else(|| unreachable!());
            if block.end == address {
                block.successors.push((address, "fallthrough"));
                block.terminator = "fallthrough";
            } else {
                block.terminator = if cfg.truncated { "truncated" } else { "invalid_or_unmapped" };
            }
            finish(block, &mut blocks);
        }
        let block = current.get_or_insert_with(|| Block {
            start: address,
            end: address,
            instructions: 0,
            successors: Vec::new(),
            terminator: "",
        });
        block.end = instruction.next_ip();
        block.instructions += 1;
        let next = instruction.next_ip();
        let terminator = if is_trap(instruction) {
            Some("trap")
        } else {
            match instruction.flow_control() {
                FlowControl::ConditionalBranch => {
                    if let Some(target) = near_target(instruction) {
                        let kind = if tails.contains_key(&address) { "tail_call" } else { "taken" };
                        block.successors.push((target, kind));
                    }
                    block.successors.push((next, "fallthrough"));
                    Some("conditional")
                }
                FlowControl::UnconditionalBranch => {
                    if tails.contains_key(&address) {
                        Some("tail_call")
                    } else {
                        if let Some(target) = near_target(instruction) {
                            block.successors.push((target, "jump"));
                        }
                        Some("jump")
                    }
                }
                FlowControl::IndirectBranch => {
                    if tails.contains_key(&address) {
                        Some("tail_call")
                    } else if let Some(table) = tables.get(&address) {
                        let mut seen = BTreeSet::new();
                        for entry in &table.entries {
                            if seen.insert(*entry) && insns.contains_key(entry) {
                                block.successors.push((*entry, "switch"));
                            }
                        }
                        Some("switch")
                    } else {
                        Some("indirect_jump")
                    }
                }
                FlowControl::Return => Some("return"),
                _ => None,
            }
        };
        if let Some(terminator) = terminator {
            let mut block = current.take().unwrap_or_else(|| unreachable!());
            block.terminator = terminator;
            finish(block, &mut blocks);
        }
    }
    if let Some(mut block) = current.take() {
        block.terminator = if cfg.truncated { "truncated" } else { "invalid_or_unmapped" };
        blocks.push(block);
    }
    cfg.end = blocks.iter().map(|block| block.end).max().unwrap_or(start);
    cfg.instructions = insns.len();
    cfg.insn_addrs = insns.keys().copied().collect();
    cfg.calls.extend(tails.into_values());
    cfg.calls.sort_by_key(|call| call.at);
    cfg.jump_tables = tables.into_values().collect();
    cfg.blocks = blocks;
    cfg
}

// ---- function discovery -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct DiscoverOptions {
    pub eh_frame: bool,
    pub symbols: bool,
    pub call_targets: bool,
    pub linear_sweep: bool,
    pub prologues: bool,
    pub max_functions: usize,
    pub max_function_insns: usize,
    pub max_total_insns: usize,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        DiscoverOptions {
            eh_frame: true,
            symbols: true,
            call_targets: true,
            linear_sweep: true,
            prologues: false,
            max_functions: DEFAULT_MAX_FUNCTIONS,
            max_function_insns: DEFAULT_MAX_FUNCTION_INSNS,
            max_total_insns: DEFAULT_MAX_TOTAL_INSNS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub sources: BTreeSet<&'static str>,
    pub cfg: FunctionCfg,
}

#[derive(Clone, Debug, Default)]
pub struct Discovery {
    pub functions: Vec<Function>,
    pub truncated: bool,
    pub notes: Vec<String>,
    pub total_instructions: usize,
}

#[derive(Default)]
struct Seed {
    name: Option<String>,
    sources: BTreeSet<&'static str>,
    end: Option<u64>,
}

/// `call rel32` targets from a linear sweep of the executable segments.
fn linear_call_targets(image: &Image, budget: usize) -> (BTreeSet<u64>, bool) {
    let mut targets = BTreeSet::new();
    let mut decoded = 0usize;
    for segment in image.exec_segments() {
        let mut decoder = Decoder::with_ip(64, &segment.data, segment.vaddr, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            if decoded >= budget {
                return (targets, true);
            }
            decoded += 1;
            let position = decoder.position();
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                let next = position + 1;
                if decoder.set_position(next).is_err() {
                    break;
                }
                decoder.set_ip(segment.vaddr + next as u64);
                continue;
            }
            if instruction.flow_control() == FlowControl::Call
                && let Some(target) = near_target(&instruction)
                && image.is_exec(target)
                && decode_at(image, target).is_some()
            {
                targets.insert(target);
            }
        }
    }
    (targets, false)
}

fn prologue_starts(image: &Image) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    for segment in image.exec_segments() {
        let mut offset = 0usize;
        while offset + 4 <= segment.data.len() {
            let after_padding = offset == 0 || matches!(segment.data[offset - 1], 0xcc | 0x90 | 0xc3 | 0x00);
            if after_padding && crate::disasm::has_frame_prologue(&segment.data[offset..], segment.vaddr + offset as u64) {
                found.insert(segment.vaddr + offset as u64);
            }
            offset += 16;
        }
    }
    found
}

/// Name for a function whose first instruction is `jmp [rip+import_slot]`.
fn thunk_name(image: &Image, start: u64) -> Option<String> {
    let (instruction, _) = decode_at(image, start)?;
    (instruction.flow_control() == FlowControl::IndirectBranch)
        .then(|| import_slot(image, &instruction).map(|(_, name)| name))
        .flatten()
}

pub fn discover(image: &Image, options: &DiscoverOptions) -> Discovery {
    let mut discovery = Discovery::default();
    let mut seeds: BTreeMap<u64, Seed> = BTreeMap::new();
    if let Some(entry) = image.entry {
        seeds.entry(entry).or_default().sources.insert("entry");
    }
    if options.eh_frame {
        let ranges = eh_frame_ranges(image);
        if ranges.is_empty() {
            discovery.notes.push("No .eh_frame FDEs found".into());
        }
        for (start, end) in ranges {
            if image.is_exec(start) {
                let seed = seeds.entry(start).or_default();
                seed.sources.insert("eh_frame");
                seed.end = Some(end);
            }
        }
    }
    if options.symbols {
        for symbol in image.function_symbols() {
            let seed = seeds.entry(symbol.value).or_default();
            seed.sources.insert("symbol");
            if seed.name.is_none() {
                seed.name = Some(symbol.name.clone());
            }
            if symbol.size > 0 && seed.end.is_none() {
                seed.end = Some(symbol.value + symbol.size);
            }
        }
    }
    let mut budget = options.max_total_insns;
    if options.linear_sweep {
        let (targets, truncated) = linear_call_targets(image, budget / 2);
        if truncated {
            discovery.notes.push("Linear call sweep stopped at the instruction budget".into());
            discovery.truncated = true;
        }
        for target in targets {
            seeds.entry(target).or_default().sources.insert("call_target");
        }
    }
    if options.prologues {
        for start in prologue_starts(image) {
            seeds.entry(start).or_default().sources.insert("prologue");
        }
    }
    // Drop weak (sweep/prologue-only) seeds that fall inside a bounded function.
    let bounded: Vec<(u64, u64)> = seeds.iter().filter_map(|(start, seed)| seed.end.map(|end| (*start, end))).collect();
    seeds.retain(|start, seed| {
        let weak = seed.sources.iter().all(|source| matches!(*source, "call_target" | "prologue"));
        !weak || !bounded.iter().any(|(lo, hi)| lo < start && start < hi)
    });

    let mut known: BTreeSet<u64> = seeds.keys().copied().collect();
    let mut queue: VecDeque<u64> = known.iter().copied().collect();
    let mut done: BTreeMap<u64, FunctionCfg> = BTreeMap::new();
    while let Some(start) = queue.pop_front() {
        if done.contains_key(&start) {
            continue;
        }
        if done.len() >= options.max_functions {
            discovery.truncated = true;
            discovery.notes.push(format!("Stopped at max_functions={}", options.max_functions));
            break;
        }
        if budget == 0 {
            discovery.truncated = true;
            discovery.notes.push("Stopped at the total instruction budget".into());
            break;
        }
        let bound = seeds.get(&start).and_then(|seed| seed.end.map(|end| (start, end)));
        let cfg = function_cfg(image, start, &known, bound, options.max_function_insns.min(budget));
        budget = budget.saturating_sub(cfg.instructions);
        discovery.total_instructions += cfg.instructions;
        if options.call_targets {
            for call in &cfg.calls {
                if let Some(target) = call.target
                    && image.is_exec(target)
                    && known.insert(target)
                {
                    seeds.entry(target).or_default().sources.insert("call_target");
                    queue.push_back(target);
                }
            }
        }
        done.insert(start, cfg);
    }
    for (start, cfg) in done {
        let seed = seeds.remove(&start).unwrap_or_default();
        let name = seed.name.or_else(|| thunk_name(image, start));
        let mut sources = seed.sources;
        if name.is_some() && !sources.contains("symbol") {
            sources.insert("import_thunk");
        }
        discovery.functions.push(Function {
            start,
            end: seed.end.unwrap_or(cfg.end).max(start + 1),
            name,
            sources,
            cfg,
        });
    }
    discovery
}

impl Discovery {
    /// Index of the function containing `va` (start <= va < end), preferring an exact start.
    pub fn containing(&self, va: u64) -> Option<usize> {
        let index = self.functions.partition_point(|function| function.start <= va);
        if index == 0 {
            return None;
        }
        (0..index).rev().take(64).find(|&i| {
            let function = &self.functions[i];
            function.start <= va && va < function.end
        })
    }

    pub fn by_start(&self, va: u64) -> Option<usize> {
        self.functions.binary_search_by_key(&va, |function| function.start).ok()
    }

    /// The agreed `ps4wb-blocks-v1` document.
    pub fn blocks_document(&self, image: &Image) -> Value {
        let base = image.base;
        let mut blocks: BTreeMap<u64, u64> = BTreeMap::new();
        for function in &self.functions {
            for block in &function.cfg.blocks {
                let size = block.end - block.start;
                let entry = blocks.entry(block.start).or_insert(size);
                *entry = (*entry).max(size);
            }
        }
        json!({
            "format": "ps4wb-blocks-v1",
            "module": image.name,
            "module_sha256": image.sha256,
            "image_base": format!("{base:#x}"),
            "blocks": blocks.iter().map(|(start, size)| json!({"start": format!("{:#x}", start - base), "size": size})).collect::<Vec<_>>(),
            "functions": self.functions.iter().map(|function| json!({
                "start": format!("{:#x}", function.start - base),
                "end": format!("{:#x}", function.end - base),
                "name": function.name,
            })).collect::<Vec<_>>(),
        })
    }
}

// ---- JSON / DOT renderers ---------------------------------------------------

pub fn hex(value: u64) -> String {
    format!("{value:#x}")
}

pub fn cfg_json(image: &Image, cfg: &FunctionCfg) -> Value {
    let base = image.base;
    json!({
        "start": hex(cfg.start), "rva": hex(cfg.start - base), "end": hex(cfg.end),
        "instructions": cfg.instructions, "truncated": cfg.truncated,
        "block_count": cfg.blocks.len(), "edge_count": cfg.edge_count(),
        "unresolved_indirect_jumps": cfg.unresolved_indirect_jumps,
        "blocks": cfg.blocks.iter().map(|block| json!({
            "start": hex(block.start), "end": hex(block.end), "size": block.end - block.start,
            "instructions": block.instructions, "terminator": block.terminator,
            "successors": block.successors.iter().map(|(to, kind)| json!({"to": hex(*to), "kind": kind})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "calls": cfg.calls.iter().map(|call| json!({
            "at": hex(call.at), "target": call.target.map(hex), "import": call.import, "kind": call.kind,
        })).collect::<Vec<_>>(),
        "jump_tables": cfg.jump_tables.iter().map(|table| json!({
            "at": hex(table.at), "table": hex(table.table), "entries": table.entries.len(),
            "targets": table.entries.iter().copied().collect::<BTreeSet<_>>().into_iter().map(hex).collect::<Vec<_>>(),
            "bounded_by": table.bounded_by,
            "note": "best-effort switch recovery; verify the bound",
        })).collect::<Vec<_>>(),
    })
}

pub fn cfg_dot(cfg: &FunctionCfg, name: Option<&str>) -> String {
    let mut out = format!("digraph \"{}\" {{\n  node [shape=box, fontname=monospace];\n", name.unwrap_or(&hex(cfg.start)).replace('"', "'"));
    for block in &cfg.blocks {
        out.push_str(&format!(
            "  \"{}\" [label=\"{}\\n{} insns\\n{}\"];\n",
            hex(block.start),
            hex(block.start),
            block.instructions,
            block.terminator
        ));
        for (to, kind) in &block.successors {
            let style = match *kind {
                "taken" => " color=green",
                "fallthrough" => " color=red style=dashed",
                "switch" => " color=blue",
                "tail_call" => " style=dotted",
                _ => "",
            };
            out.push_str(&format!("  \"{}\" -> \"{}\" [label=\"{kind}\"{style}];\n", hex(block.start), hex(*to)));
        }
    }
    out.push_str("}\n");
    out
}

// ---- call graph ---------------------------------------------------------------

/// Callee node: a function start or an import name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Function(u64),
    Import(String),
}

pub fn node_json(discovery: &Discovery, image: &Image, node: &Node) -> Value {
    match node {
        Node::Function(start) => {
            let name = discovery.by_start(*start).and_then(|i| discovery.functions[i].name.clone());
            json!({"address": hex(*start), "rva": hex(start.wrapping_sub(image.base)), "name": name})
        }
        Node::Import(name) => json!({"import": name}),
    }
}

/// Direct callees (including tail calls and resolved imports) of each function.
pub fn callee_map(discovery: &Discovery) -> BTreeMap<u64, Vec<(u64, Node)>> {
    let mut map = BTreeMap::new();
    for function in &discovery.functions {
        let mut callees = Vec::new();
        for call in &function.cfg.calls {
            let node = if let Some(target) = call.target {
                match discovery.by_start(target) {
                    Some(index) => match (&discovery.functions[index].name, discovery.functions[index].sources.contains("import_thunk")) {
                        (Some(name), true) => Node::Import(name.clone()),
                        _ => Node::Function(target),
                    },
                    None => Node::Function(target),
                }
            } else if let Some(import) = &call.import {
                Node::Import(import.clone())
            } else {
                continue;
            };
            callees.push((call.at, node));
        }
        map.insert(function.start, callees);
    }
    map
}

/// Up to `max_paths` shortest call paths from `from` to `to` (BFS, depth-bounded).
pub fn shortest_paths(
    callees: &BTreeMap<u64, Vec<(u64, Node)>>,
    from: u64,
    to: &Node,
    max_depth: usize,
    max_paths: usize,
) -> (Vec<Vec<Node>>, bool) {
    let mut depth: HashMap<Node, usize> = HashMap::new();
    let mut parents: HashMap<Node, Vec<Node>> = HashMap::new();
    let start = Node::Function(from);
    depth.insert(start.clone(), 0);
    let mut queue = VecDeque::from([start.clone()]);
    let mut found_depth = None;
    let mut visited = 0usize;
    let mut truncated = false;
    while let Some(node) = queue.pop_front() {
        visited += 1;
        if visited > 200_000 {
            truncated = true;
            break;
        }
        let current = depth[&node];
        if found_depth.is_some_and(|found| current >= found) || current >= max_depth {
            continue;
        }
        let Node::Function(address) = node else { continue };
        for (_, callee) in callees.get(&address).into_iter().flatten() {
            match depth.get(callee) {
                None => {
                    depth.insert(callee.clone(), current + 1);
                    parents.insert(callee.clone(), vec![node.clone()]);
                    if callee == to {
                        found_depth = Some(current + 1);
                    } else {
                        queue.push_back(callee.clone());
                    }
                }
                Some(&existing) if existing == current + 1 => {
                    let list = parents.entry(callee.clone()).or_default();
                    if !list.contains(&node) && list.len() < 64 {
                        list.push(node.clone());
                    }
                }
                _ => {}
            }
        }
    }
    let mut paths = Vec::new();
    if found_depth.is_none() {
        return (paths, truncated);
    }
    // Enumerate paths backwards from `to`.
    let mut stack: Vec<Vec<Node>> = vec![vec![to.clone()]];
    while let Some(partial) = stack.pop() {
        if paths.len() >= max_paths {
            truncated = true;
            break;
        }
        let head = partial.last().cloned().unwrap_or_else(|| unreachable!());
        if head == start {
            let mut path = partial.clone();
            path.reverse();
            paths.push(path);
            continue;
        }
        for parent in parents.get(&head).into_iter().flatten() {
            let mut next = partial.clone();
            next.push(parent.clone());
            stack.push(next);
        }
    }
    (paths, truncated)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::binimage::testelf::{Builder, eh_frame};

    /// Two-function synthetic module:
    /// f0: push rbp; mov rbp,rsp; cmp edi,2; ja L; lea rcx,[rip+table]; movsxd rax,dword [rcx+rax*4];
    ///     add rax,rcx; jmp rax; cases...; L: call f1; call [rip+slot]; pop rbp; ret
    pub fn sample(base: u64) -> (Builder, u64, u64, u64) {
        sample_with(base, 0)
    }

    /// `sample` with `pad` bytes of int3 before the first function.
    pub fn sample_with(base: u64, pad: usize) -> (Builder, u64, u64, u64) {
        let mut builder = Builder::new(base);
        let text = builder.text_va();
        let data = builder.data_va();
        let slot = data + 0x10;
        let table = data + 0x20;
        let mut code: Vec<u8> = vec![0xcc; pad];
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5]); // push rbp; mov rbp,rsp
        code.extend_from_slice(&[0x83, 0xff, 0x02]); // cmp edi,2
        let ja_at = code.len();
        code.extend_from_slice(&[0x77, 0x00]); // ja L (patched)
        code.extend_from_slice(&[0x89, 0xf8]); // mov eax,edi
        let lea_at = code.len();
        code.extend_from_slice(&[0x48, 0x8d, 0x0d, 0, 0, 0, 0]); // lea rcx,[rip+table]
        let lea_end = code.len() as u64;
        code.extend_from_slice(&[0x48, 0x63, 0x04, 0x81]); // movsxd rax,dword [rcx+rax*4]
        code.extend_from_slice(&[0x48, 0x01, 0xc8]); // add rax,rcx
        code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        let mut cases = Vec::new();
        for value in 0..3u8 {
            cases.push(code.len() as u64);
            code.extend_from_slice(&[0xb8, value + 1, 0, 0, 0]); // mov eax,n
            code.extend_from_slice(&[0xeb, 0x00]); // jmp L (patched)
        }
        let label = code.len() as u64;
        for case in &cases {
            let jmp = *case as usize + 5;
            code[jmp + 1] = (label as i64 - (jmp as i64 + 2)) as u8;
        }
        code[ja_at + 1] = (label as usize - (ja_at + 2)) as u8;
        let call_at = code.len();
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]); // call f1 (patched)
        let icall_at = code.len();
        code.extend_from_slice(&[0xff, 0x15, 0, 0, 0, 0]); // call [rip+slot]
        code.extend_from_slice(&[0x5d, 0xc3]); // pop rbp; ret
        let f0_len = (code.len() - pad) as u64;
        while !code.len().is_multiple_of(16) {
            code.push(0xcc);
        }
        let f1 = code.len() as u64;
        code.extend_from_slice(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
        let rel = |at: usize, len: usize, target: u64| ((target as i64) - (text as i64 + at as i64 + len as i64)) as i32;
        code[lea_at + 3..lea_at + 7].copy_from_slice(&rel(lea_at, 7, table).to_le_bytes());
        code[call_at + 1..call_at + 5].copy_from_slice(&rel(call_at, 5, text + f1).to_le_bytes());
        code[icall_at + 2..icall_at + 6].copy_from_slice(&rel(icall_at, 6, slot).to_le_bytes());
        let _ = lea_end;
        builder.text = code;
        let mut data_bytes = vec![0u8; 0x20];
        for case in &cases {
            data_bytes.extend_from_slice(&(((text + case) as i64 - table as i64) as i32).to_le_bytes());
        }
        data_bytes.extend_from_slice(b"hello world\0");
        builder.data = data_bytes;
        builder.imports.push((slot, "1jfXLRVzisc#libkernel#libkernel".into()));
        let f0 = text + pad as u64;
        builder.symbols.push(("dispatch".into(), f0, f0_len));
        let eh_va = {
            let image = builder.build();
            let parsed = crate::binimage::Image::from_elf(&image, None).unwrap();
            parsed.eh_frame.unwrap().0
        };
        builder.eh_frame = eh_frame(eh_va, &[(f0, f0_len), (text + f1, 3)]);
        (builder, f0, text + f1, slot)
    }

    #[test]
    fn cfg_recovers_switch_calls_and_imports() {
        let (builder, f0, f1, _) = sample(0x400000);
        let image = Image::from_elf(&builder.build(), Some("sample".into())).unwrap();
        assert_eq!(eh_frame_ranges(&image).len(), 2);
        let discovery = discover(&image, &DiscoverOptions::default());
        assert_eq!(discovery.functions.len(), 2, "{:?}", discovery.functions.iter().map(|f| f.start).collect::<Vec<_>>());
        let main = &discovery.functions[0];
        assert_eq!(main.start, f0);
        assert_eq!(main.name.as_deref(), Some("dispatch"));
        assert!(main.sources.contains("eh_frame") && main.sources.contains("symbol"));
        assert_eq!(main.cfg.jump_tables.len(), 1);
        assert_eq!(main.cfg.jump_tables[0].entries.len(), 3);
        assert_eq!(main.cfg.jump_tables[0].bounded_by, "cmp");
        assert!(main.cfg.calls.iter().any(|c| c.target == Some(f1)));
        assert!(main.cfg.calls.iter().any(|c| c.import.as_deref() == Some("sceKernelUsleep")));
        assert!(main.cfg.blocks.len() >= 6);
        let document = discovery.blocks_document(&image);
        assert_eq!(document["format"], "ps4wb-blocks-v1");
        assert_eq!(document["functions"][0]["start"], "0x1000");
        assert!(cfg_dot(&main.cfg, None).contains("switch"));

        let callees = callee_map(&discovery);
        let (paths, _) = shortest_paths(&callees, f0, &Node::Function(f1), 4, 4);
        assert_eq!(paths, vec![vec![Node::Function(f0), Node::Function(f1)]]);
        let (paths, _) = shortest_paths(&callees, f0, &Node::Import("sceKernelUsleep".into()), 4, 4);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn discovery_without_metadata_uses_call_targets_and_prologues() {
        let (builder, f0, f1, _) = sample(0);
        let elf = builder.build();
        let image = Image::from_raw(0x1000, elf[0x1000..0x1000 + builder.text.len()].to_vec(), None);
        let options = DiscoverOptions { prologues: true, ..Default::default() };
        let discovery = discover(&image, &options);
        let starts: Vec<u64> = discovery.functions.iter().map(|f| f.start).collect();
        assert!(starts.contains(&f0) && starts.contains(&f1), "{starts:x?}");
        assert!(discovery.functions[0].sources.contains("prologue"));
    }
}
