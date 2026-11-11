//! Watchpoint access finding, crash triage, pointer-scan snapshots and
//! host-scripted breakpoints.
//!
//! Hardware semantics: data watchpoints trap after the accessing instruction
//! retires, so the live rip points past it. The accessing instruction is
//! recovered by decoding every candidate that starts at rip-15..rip-1 and ends
//! exactly at rip, keeping those whose memory operand (evaluated with the live,
//! post-instruction registers) covers the watched range. Ambiguity is reported,
//! never hidden. Faults trap before the instruction retires, so crash triage
//! decodes the instruction at rip with pre-fault registers.
//!
//! Every operation here disarms the watchpoints / internal breakpoints it set on
//! every exit path and leaves the target halted; uncertain cleanup is reported.
use super::*;
use crate::{disasm, expr::RegisterFile, hostscript, pointerscan, structinfer::MapEntry};
use iced_x86::{Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

/// Hard upper bound for every run loop in this module.
pub const MAX_SECONDS: u64 = 300;
const SIGTRAP: u32 = 5;
const SETTLE: Duration = Duration::from_secs(2);

// ---- pure helpers ----------------------------------------------------------

/// FreeBSD signal names (`sys/signal.h`).
pub fn signal_name(signal: u32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGEMT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGBUS",
        11 => "SIGSEGV",
        12 => "SIGSYS",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGURG",
        17 => "SIGSTOP",
        18 => "SIGTSTP",
        19 => "SIGCONT",
        20 => "SIGCHLD",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGIO",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGINFO",
        30 => "SIGUSR1",
        31 => "SIGUSR2",
        _ => "SIG?",
    }
}

/// Decoded FreeBSD `wait(2)` status.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WaitStatus {
    Stopped(u32),
    Exited(u32),
    Signaled(u32, bool),
}

pub fn decode_wait_status(status: u32) -> WaitStatus {
    if status & 0xff == 0x7f {
        WaitStatus::Stopped((status >> 8) & 0xff)
    } else if status & 0x7f == 0 {
        WaitStatus::Exited((status >> 8) & 0xff)
    } else {
        WaitStatus::Signaled(status & 0x7f, status & 0x80 != 0)
    }
}

pub fn wait_status_json(status: u32) -> Value {
    match decode_wait_status(status) {
        WaitStatus::Stopped(signal) => json!({"raw":status,"kind":"stopped","signal":signal,"signal_name":signal_name(signal)}),
        WaitStatus::Exited(code) => json!({"raw":status,"kind":"exited","exit_code":code}),
        WaitStatus::Signaled(signal, core) => json!({"raw":status,"kind":"signaled","signal":signal,
            "signal_name":signal_name(signal),"core_dumped":core}),
    }
}

/// Exact split of `[start, start+length)` into naturally aligned 1/2/4/8 slots.
pub fn plan_exact(start: u64, length: u64) -> Vec<(u64, u32)> {
    let mut slots = Vec::new();
    let (mut position, end) = (start, start.saturating_add(length));
    while position < end {
        let size = [8u64, 4, 2, 1]
            .into_iter()
            .find(|size| position.is_multiple_of(*size) && position + size <= end)
            .unwrap_or(1);
        slots.push((position, size as u32));
        position += size;
    }
    slots
}

/// Cover `[start, start+length)` with 8-byte aligned slots (may over-cover).
pub fn plan_cover8(start: u64, length: u64) -> Vec<(u64, u32)> {
    let first = start & !7;
    let end = start.saturating_add(length).div_ceil(8) * 8;
    (first..end).step_by(8).map(|address| (address, 8)).collect()
}

/// A memory operand evaluated against a register file.
#[derive(Debug, Clone)]
pub struct MemoryOperand {
    pub address: Option<u64>,
    pub size: u64,
    pub access: &'static str,
    /// The instruction also writes the base/index register (post-instruction
    /// registers then no longer describe the address it accessed).
    pub base_clobbered: bool,
}

fn register_value(raw: &[u8], tls: Option<(u64, u64)>, register: Register) -> Option<u64> {
    match register {
        Register::FS => tls.map(|pair| pair.0),
        Register::GS => tls.map(|pair| pair.1),
        Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
        _ if register.is_gpr() => {
            let name = format!("{:?}", register.full_register()).to_ascii_lowercase();
            let value = RegisterFile(raw).get(&name)?;
            Some(match register.size() {
                8 => value,
                4 => value & 0xffff_ffff,
                2 => value & 0xffff,
                _ if matches!(register, Register::AH | Register::BH | Register::CH | Register::DH) => (value >> 8) & 0xff,
                _ => value & 0xff,
            })
        }
        _ => None,
    }
}

/// Memory operands of `instruction` evaluated with `raw` registers (`lea` and
/// other no-access operands are skipped).
pub fn memory_operands(instruction: &Instruction, raw: &[u8], tls: Option<(u64, u64)>) -> Vec<MemoryOperand> {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(instruction);
    let written: Vec<Register> = info
        .used_registers()
        .iter()
        .filter(|used| matches!(used.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite))
        .map(|used| used.register().full_register())
        .collect();
    info.used_memory()
        .iter()
        .filter_map(|memory| {
            let access = match memory.access() {
                OpAccess::Read | OpAccess::CondRead => "read",
                OpAccess::Write | OpAccess::CondWrite => "write",
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => "read_write",
                _ => return None,
            };
            let clobbered = [memory.base(), memory.index()]
                .into_iter()
                .any(|register| register != Register::None && written.contains(&register.full_register()));
            Some(MemoryOperand {
                address: memory.virtual_address(0, |register, _, _| register_value(raw, tls, register)),
                size: memory.memory_size().size() as u64,
                access,
                base_clobbered: clobbered,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct AccessCandidate {
    pub address: u64,
    pub length: usize,
    pub text: String,
    pub operand: Option<MemoryOperand>,
    /// The evaluated operand overlaps a watched range.
    pub exact: bool,
}

fn overlaps(address: u64, size: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(start, length)| address < start.saturating_add(*length) && *start < address.saturating_add(size.max(1)))
}

/// Candidate accessing instructions for a data-watchpoint trap at `rip`.
/// `code` holds the bytes at `code_start..rip`. Exact candidates come first.
pub fn recover_access(
    code: &[u8],
    code_start: u64,
    rip: u64,
    raw: &[u8],
    tls: Option<(u64, u64)>,
    watched: &[(u64, u64)],
) -> Vec<AccessCandidate> {
    let mut exact = Vec::new();
    let mut plausible = Vec::new();
    for length in 1..=15u64 {
        let Some(start) = rip.checked_sub(length) else { break };
        if start < code_start {
            break;
        }
        let offset = (start - code_start) as usize;
        let Some(bytes) = code.get(offset..offset + length as usize) else { continue };
        let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() as u64 != length {
            continue;
        }
        let operands = memory_operands(&instruction, raw, tls);
        if operands.is_empty() {
            continue;
        }
        let text = disasm::decode(bytes, start, 1).first().map(|item| item.text.clone()).unwrap_or_default();
        let hit = operands
            .iter()
            .find(|operand| operand.address.is_some_and(|address| overlaps(address, operand.size, watched)));
        match hit {
            Some(operand) => exact.push(AccessCandidate {
                address: start,
                length: length as usize,
                text,
                operand: Some(operand.clone()),
                exact: true,
            }),
            None => {
                if let Some(operand) = operands.iter().find(|operand| operand.base_clobbered || operand.address.is_none()) {
                    plausible.push(AccessCandidate {
                        address: start,
                        length: length as usize,
                        text,
                        operand: Some(operand.clone()),
                        exact: false,
                    });
                }
            }
        }
    }
    // Shorter decodes ending at rip are usually tails of the real instruction: prefer the longest.
    exact.sort_by_key(|candidate| std::cmp::Reverse(candidate.length));
    plausible.sort_by_key(|candidate| std::cmp::Reverse(candidate.length));
    exact.extend(plausible);
    exact
}

/// Facts for [`classify_crash`] (all from the stop, no console access).
#[derive(Debug, Clone, Default)]
pub struct CrashFacts {
    pub signal: Option<u32>,
    pub trapno: u64,
    pub err: u64,
    pub rip: u64,
    pub rip_map: Option<MapEntry>,
    pub rip_in_module: bool,
    pub mnemonic: Option<String>,
    pub operands: Vec<(MemoryOperand, Option<MapEntry>)>,
    pub rsp: u64,
    pub rsp_map: Option<MapEntry>,
}

fn canonical(address: u64) -> bool {
    let top = address >> 47;
    top == 0 || top == 0x1ffff
}

/// Ranked crash classifications `{class, confidence, reason}`.
pub fn classify_crash(facts: &CrashFacts) -> Vec<Value> {
    let mut out = Vec::new();
    let added = std::cell::Cell::new(0usize);
    let mut add = |class: &str, confidence: &str, reason: String| {
        added.set(added.get() + 1);
        out.push(json!({"class":class,"confidence":confidence,"reason":reason}));
    };
    let mnemonic = facts.mnemonic.as_deref().unwrap_or("");
    let signal = facts.signal.unwrap_or(0);
    if matches!(mnemonic, "div" | "idiv") && (signal == 8 || facts.trapno == 0) {
        add("divide_error", "high", format!("{mnemonic} raised #DE (division by zero or quotient overflow)"));
    } else if signal == 8 {
        add("divide_error", "medium", "SIGFPE without a decoded div/idiv".into());
    }
    if mnemonic == "int3" || (signal == SIGTRAP && facts.trapno == 3) {
        add("int3_breakpoint", "high", "int3 trap (compiled-in breakpoint or a debugger breakpoint)".into());
    }
    if mnemonic == "ud2" {
        add("ud2_trap", "high", "ud2: __builtin_trap / compiler-inserted unreachable or assertion".into());
    } else if signal == 4 {
        add("illegal_instruction", "medium", "SIGILL at a non-ud2 instruction (corrupt code or wrong mode)".into());
    }
    if signal == 6 {
        add("abort", "high", "SIGABRT: abort()/assertion failure; inspect the stack for the caller".into());
    }
    match &facts.rip_map {
        None if facts.rip < 0x10000 => add(
            "execute_null_pointer",
            "high",
            format!("rip {:#x} is near NULL: call through a null function pointer / vtable slot", facts.rip),
        ),
        None => add("execute_unmapped", "high", format!("rip {:#x} is not mapped (wild jump/return, corrupted return address)", facts.rip)),
        Some(entry) if entry.2 & 4 == 0 => add(
            "execute_non_executable",
            "high",
            format!("rip {:#x} is in non-executable mapping {:?} ({:#x}-{:#x})", facts.rip, entry.3, entry.0, entry.1),
        ),
        Some(_) if !facts.rip_in_module => add(
            "rip_outside_modules",
            "medium",
            format!("rip {:#x} is executable but outside every named module (JIT/trampoline or hijacked flow)", facts.rip),
        ),
        _ => {}
    }
    for (operand, map) in &facts.operands {
        let Some(address) = operand.address else { continue };
        let writes = operand.access != "read";
        let verb = if writes { "write" } else { "read" };
        if address < 0x10000 {
            add(
                "null_pointer_dereference",
                "high",
                format!("{verb} of {} bytes at {address:#x} (NULL + {address:#x})", operand.size),
            );
        } else if !canonical(address) {
            add("non_canonical_address", "high", format!("{verb} at non-canonical {address:#x} (#GP; garbage pointer)"));
        } else if map.is_none() {
            let near_stack = facts
                .rsp_map
                .as_ref()
                .is_some_and(|stack| address < stack.0 && stack.0 - address <= 0x10000);
            if near_stack {
                add("stack_overflow", "high", format!("{verb} at {address:#x} just below the stack mapping (guard page hit)"));
            } else {
                add(
                    if writes { "wild_write" } else { "wild_read" },
                    if signal == 11 || signal == 10 { "high" } else { "medium" },
                    format!("{verb} of {} bytes at unmapped {address:#x}", operand.size),
                );
            }
        } else if let Some(entry) = map {
            if writes && entry.2 & 2 == 0 {
                add(
                    "write_to_read_only",
                    "high",
                    format!("write at {address:#x} into read-only mapping {:?} ({:#x}-{:#x})", entry.3, entry.0, entry.1),
                );
            } else if entry.2 & 1 == 0 {
                let guard = facts.rsp_map.as_ref().is_some_and(|stack| entry.1 == stack.0);
                add(
                    if guard { "stack_overflow" } else { "read_protected" },
                    "high",
                    format!("access at {address:#x} into no-access mapping ({:#x}-{:#x})", entry.0, entry.1),
                );
            }
        }
    }
    if facts.rsp_map.is_none() && signal == 11 {
        add("stack_pointer_corrupt", "medium", format!("rsp {:#x} is not in a mapping (stack overflow or pivot)", facts.rsp));
    }
    if added.get() == 0 {
        match signal {
            10 => add("bus_error", "medium", "SIGBUS without a decoded faulting operand (alignment/backing store)".into()),
            11 => add(
                "segv_unexplained",
                "low",
                "SIGSEGV but every decoded operand is mapped with suitable protection (implicit access or maps changed)".into(),
            ),
            0 | SIGTRAP => add("no_fault", "low", "this stop is not a fault signal".into()),
            other => add("signal", "low", format!("{} without a specific classifier", signal_name(other))),
        }
    }
    let rank = |value: &Value| match value["confidence"].as_str() {
        Some("high") => 0,
        Some("medium") => 1,
        _ => 2,
    };
    out.sort_by_key(rank);
    out
}

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn parse_hex(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn map_containing(maps: &[MapEntry], address: u64) -> Option<MapEntry> {
    maps.iter().find(|(start, end, _, _)| *start <= address && address < *end).cloned()
}

fn map_json(entry: &Option<MapEntry>) -> Value {
    match entry {
        Some((start, end, protection, name)) => json!({"start":hex(*start),"end":hex(*end),"name":name,
            "protection":format!("{}{}{}", if protection & 1 != 0 {'r'} else {'-'}, if protection & 2 != 0 {'w'} else {'-'}, if protection & 4 != 0 {'x'} else {'-'}),
            "readable":protection & 1 != 0,"writable":protection & 2 != 0,"executable":protection & 4 != 0}),
        None => Value::Null,
    }
}

// ---- request types -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub address: u64,
    pub length: u64,
    /// `write` or `read_write`.
    pub access: String,
    /// Struct mode: watch `[address, address+span)` by rotating slots.
    pub span: Option<u64>,
    pub timeout: Duration,
    pub max_hits: u64,
    pub samples: usize,
}

#[derive(Debug, Clone)]
pub struct CrashRequest {
    pub wait: bool,
    pub timeout: Duration,
    pub thread_id: Option<u32>,
    pub max_events: usize,
    pub capture_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ScriptRequest {
    pub source: String,
    /// `(name, address)`.
    pub breakpoints: Vec<(String, u64)>,
    pub timeout: Duration,
    pub max_stops: usize,
    pub limits: hostscript::Limits,
}

#[derive(Default)]
struct AccessEntry {
    instruction: u64,
    location: Option<String>,
    disasm: String,
    address: u64,
    offset: i64,
    size: u64,
    kind: String,
    confidence: &'static str,
    count: u64,
    samples: Vec<Value>,
    alternatives: Vec<Value>,
}

struct AccessRun {
    pid: u32,
    base: u64,
    total: u64,
    access: String,
    max_hits: u64,
    samples: usize,
    armed: Vec<(u32, u64, u32)>,
    entries: BTreeMap<(u64, i64, String), AccessEntry>,
    shadow: Option<Vec<u8>>,
    modules: Vec<(String, u64, u64)>,
    code_cache: HashMap<u64, (u64, Vec<u8>)>,
    hits: u64,
    outside_hits: u64,
    unrecovered: u64,
    resumes: u64,
    round_timeouts: u64,
    stop_reason: Option<Value>,
}

struct DebuggerMemory {
    debugger: Debugger,
    pid: u32,
}

impl hostscript::ScriptMemory for DebuggerMemory {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.debugger.read_memory(self.pid, address, length, false)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

impl Debugger {
    fn access_pid(&self) -> Result<u32> {
        self.attached_pid.context("No active debugger session")
    }

    fn access_maps(&mut self, pid: u32) -> Result<Vec<MapEntry>> {
        Ok(self
            .maps(pid)?
            .as_array()
            .context("Expected maps")?
            .iter()
            .map(|entry| {
                (
                    entry["start"].as_u64().unwrap_or(0),
                    entry["end"].as_u64().unwrap_or(0),
                    entry["protection"].as_u64().unwrap_or(0),
                    entry["name"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect())
    }

    fn access_modules(&mut self, pid: u32) -> Vec<(String, u64, u64)> {
        let Ok(list) = self.module_list(pid) else { return Vec::new() };
        list.as_array()
            .into_iter()
            .flatten()
            .filter_map(|module| {
                let base = parse_hex(&module["base"])?;
                Some((module["name"].as_str()?.to_owned(), base, base + module["size"].as_u64()?))
            })
            .collect()
    }

    fn access_tls(&mut self, thread: u32) -> Option<(u64, u64)> {
        let value = self.tls_bases(thread).ok()?;
        Some((parse_hex(&value["fsbase"])?, parse_hex(&value["gsbase"])?))
    }

    /// Halt everything and consume the resulting stop event (best effort).
    fn halt_and_settle(&mut self) -> Result<bool> {
        self.control("halt", 0)?;
        Ok(self.wait_stop(SETTLE)?.is_some())
    }

    /// Up to 15 code bytes ending at `rip` (`(start, bytes)`), int3 bytes masked.
    fn code_before(&mut self, pid: u32, rip: u64) -> Result<(u64, Vec<u8>)> {
        let start = rip.saturating_sub(15);
        match self.read_code(pid, start, (rip - start) as usize) {
            Ok(bytes) if bytes.len() == (rip - start) as usize => Ok((start, bytes)),
            _ => {
                let page = rip & !0xfff;
                ensure!(page < rip && page > start, "No readable code before rip {rip:#x}");
                let bytes = self.read_code(pid, page, (rip - page) as usize)?;
                Ok((page, bytes))
            }
        }
    }

    // ---- find accesses ---------------------------------------------------------

    /// Cheat-Engine style "find out what accesses/writes this address": arm
    /// hardware watchpoints, resume until timeout/max_hits, and collect unique
    /// accessing instructions. Returns `{"document": ps4wb-access-v1, ...}`.
    pub fn find_accesses(&mut self, request: &AccessRequest) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.access_pid()?;
        ensure!(matches!(request.access.as_str(), "write" | "read_write"), "access must be write or read_write");
        ensure!(request.timeout.as_secs() <= MAX_SECONDS && !request.timeout.is_zero(), "timeout must be 1-300 s");
        ensure!((1..=10_000).contains(&request.max_hits), "max_hits must be 1-10000");
        let (base, total) = match request.span {
            Some(span) => {
                ensure!((8..=0x400).contains(&span), "struct span must be 8..=0x400 bytes");
                (request.address, span)
            }
            None => {
                ensure!((1..=32).contains(&request.length), "length must be 1-32");
                (request.address, request.length)
            }
        };
        ensure!(base.checked_add(total).is_some(), "Watched range overflows");
        let free: Vec<u32> = (0..4).filter(|slot| !self.watchpoints.contains_key(slot)).collect();
        ensure!(!free.is_empty(), "All 4 hardware watchpoint slots are in use; clear one with debug_watchpoint");
        let exact = plan_exact(base, total);
        let regions = if exact.len() <= free.len() { exact } else { plan_cover8(base, total) };
        let rounds: Vec<Vec<(u64, u32)>> = regions.chunks(free.len()).map(<[_]>::to_vec).collect();
        let shadow = self.read_memory(pid, base, total as usize, false).ok();
        let modules = self.access_modules(pid);
        let maps = self.access_maps(pid).unwrap_or_default();
        let mut run = AccessRun {
            pid,
            base,
            total,
            access: request.access.clone(),
            max_hits: request.max_hits,
            samples: request.samples.min(16),
            armed: Vec::new(),
            entries: BTreeMap::new(),
            shadow,
            modules,
            code_cache: HashMap::new(),
            hits: 0,
            outside_hits: 0,
            unrecovered: 0,
            resumes: 0,
            round_timeouts: 0,
            stop_reason: None,
        };
        let started = Instant::now();
        let outcome = self.access_rounds(&mut run, &free, &rounds, started + request.timeout);
        // Cleanup on every path: disarm whatever is still armed.
        let mut cleanup_errors = Vec::new();
        for (slot, address, length) in std::mem::take(&mut run.armed) {
            if let Err(error) = self.watchpoint(slot, address, length, &run.access, false) {
                cleanup_errors.push(format!("watchpoint slot {slot}: {error:#}"));
                self.watchpoints.remove(&slot);
            }
        }
        if let Err(error) = &outcome {
            if self.attached_pid.is_some() {
                // Best effort: never leave the target running after a failure.
                if let Err(halt) = self.halt_and_settle() {
                    cleanup_errors.push(format!("halt after error: {halt:#}"));
                }
            }
            if !cleanup_errors.is_empty() {
                return Err(anyhow::anyhow!(
                    "{error:#}; cleanup uncertain: {}; inspect debug_watchpoint_list / debug_registers_dr",
                    cleanup_errors.join("; ")
                ));
            }
        }
        outcome?;
        let accesses: Vec<Value> = run
            .entries
            .values()
            .map(|entry| {
                json!({"instruction":hex(entry.instruction),"location":entry.location,"disasm":entry.disasm,
                    "address":hex(entry.address),"offset":entry.offset,"size":entry.size,"kind":entry.kind,
                    "count":entry.count,"confidence":entry.confidence,"samples":entry.samples,
                    "alternatives":entry.alternatives})
            })
            .collect();
        let compact_maps: Vec<Value> = maps
            .iter()
            .take(4096)
            .map(|(start, end, protection, name)| json!([hex(*start), hex(*end), protection, name]))
            .collect();
        let document = json!({"format":crate::structinfer::ACCESS_FORMAT,"base":hex(base),"length":total,
            "span":request.span,"pid":pid,"access":request.access,"accesses":accesses,"maps":compact_maps});
        Ok(json!({
            "document": document,
            "hits": run.hits,
            "unique_accesses": run.entries.len(),
            "outside_range_hits": run.outside_hits,
            "unrecovered_hits": run.unrecovered,
            "rounds": rounds.len(),
            "slots_per_round": free.len(),
            "regions": regions.iter().map(|(address, length)| json!({"address":hex(*address),"length":length})).collect::<Vec<_>>(),
            "resumes": run.resumes,
            "round_timeouts": run.round_timeouts,
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "stop_reason": run.stop_reason.unwrap_or_else(|| json!({"reason":"timeout"})),
            "cleanup": {"watchpoints_disarmed": cleanup_errors.is_empty(), "errors": cleanup_errors, "target_state": "halted"},
            "note": "Data watchpoints trap after the access retires; the instruction is recovered by back-decoding to rip with post-instruction registers (confidence exact|ambiguous|plausible|unknown).",
        }))
    }

    fn access_rounds(
        &mut self,
        run: &mut AccessRun,
        free: &[u32],
        rounds: &[Vec<(u64, u32)>],
        deadline: Instant,
    ) -> Result<()> {
        for (index, round) in rounds.iter().enumerate() {
            let now = Instant::now();
            let Some(left) = deadline.checked_duration_since(now) else { break };
            let round_deadline = now + left / (rounds.len() - index) as u32;
            for (slot, (address, length)) in free.iter().zip(round) {
                self.watchpoint(*slot, *address, *length, &run.access.clone(), true)?;
                run.armed.push((*slot, *address, *length));
            }
            loop {
                let Some(remaining) = round_deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
                    run.round_timeouts += 1;
                    break;
                };
                self.control("resume", 0)?;
                run.resumes += 1;
                let Some(event) = self.wait_stop(remaining)? else {
                    self.halt_and_settle()?;
                    run.round_timeouts += 1;
                    break;
                };
                let status = event["status"].as_u64().unwrap_or(0) as u32;
                if decode_wait_status(status) != WaitStatus::Stopped(SIGTRAP) {
                    run.stop_reason = Some(json!({"reason":"unexpected_stop","status":wait_status_json(status),
                        "thread_id":event["thread_id"],"rip":event["registers"]["rip"],
                        "note":"Target stopped on a non-watchpoint signal and was left halted; try debug_crash_triage"}));
                    return Ok(());
                }
                if !self.record_access_hit(run, &event)? {
                    return Ok(());
                }
                if run.hits >= run.max_hits {
                    run.stop_reason = Some(json!({"reason":"max_hits"}));
                    return Ok(());
                }
            }
            for (slot, address, length) in std::mem::take(&mut run.armed) {
                if let Err(error) = self.watchpoint(slot, address, length, &run.access.clone(), false) {
                    run.armed.push((slot, address, length));
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Record one watchpoint stop. Returns `false` when the stop was not ours
    /// (a software breakpoint), which ends the run with the target halted.
    fn record_access_hit(&mut self, run: &mut AccessRun, event: &Value) -> Result<bool> {
        let thread = event["thread_id"].as_u64().unwrap_or(0) as u32;
        let event_rip = parse_hex(&event["registers"]["rip"]).unwrap_or(0);
        if let Some((slot, _)) = self
            .breakpoints
            .iter()
            .find(|(_, record)| record.enabled && (record.address == event_rip || record.address + 1 == event_rip))
        {
            run.stop_reason = Some(json!({"reason":"foreign_breakpoint","slot":slot,"thread_id":thread,"rip":hex(event_rip),
                "note":"A software breakpoint stopped the target; it was left halted"}));
            return Ok(false);
        }
        let raw = self.get_registers_raw(thread)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(event_rip);
        let dr6 = self.hardware_debug_registers(thread).ok().and_then(|value| parse_hex(&value["dr6"])).unwrap_or(0);
        let fired: Vec<(u64, u64)> = run
            .armed
            .iter()
            .filter(|(slot, _, _)| dr6 & (1 << slot) != 0)
            .map(|(_, address, length)| (*address, *length as u64))
            .collect();
        let watched: Vec<(u64, u64)> = run.armed.iter().map(|(_, address, length)| (*address, *length as u64)).collect();
        let tls = self.access_tls(thread);
        let code = match run.code_cache.get(&rip) {
            Some(code) => Some(code.clone()),
            None => match self.code_before(run.pid, rip) {
                Ok(code) => {
                    run.code_cache.insert(rip, code.clone());
                    Some(code)
                }
                Err(_) => None,
            },
        };
        let candidates = code
            .as_ref()
            .map(|(start, bytes)| recover_access(bytes, *start, rip, &raw, tls, &watched))
            .unwrap_or_default();
        let exact_count = candidates.iter().filter(|candidate| candidate.exact).count();
        let chosen = candidates.first();
        let confidence = match (exact_count, chosen) {
            (1, _) => "exact",
            (n, _) if n > 1 => "ambiguous",
            (_, Some(_)) => "plausible",
            _ => "unknown",
        };
        // Accessed range: the operand when known, else the fired slot region.
        let (address, size, kind) = match chosen.and_then(|candidate| candidate.operand.clone()) {
            Some(MemoryOperand { address: Some(address), size, access, .. }) if chosen.is_some_and(|c| c.exact) => {
                (address, size.max(1), if access == "read" { "read" } else { "write" })
            }
            other => {
                let (address, size) = fired.first().or(watched.first()).copied().unwrap_or((run.base, 1));
                let kind = match other {
                    Some(operand) if operand.access == "read" => "read",
                    Some(_) => "write",
                    None if run.access == "write" => "write",
                    None => "read",
                };
                (address, size, kind)
            }
        };
        if !overlaps(address, size, &[(run.base, run.total)]) {
            run.outside_hits += 1;
            return Ok(true);
        }
        run.hits += 1;
        if confidence == "unknown" {
            run.unrecovered += 1;
        }
        let instruction = chosen.map_or(rip, |candidate| candidate.address);
        let offset = address as i64 - run.base as i64;
        // Old value from the shadow copy, new value read live; then update the shadow.
        let read_size = size.min(16) as usize;
        let new_bytes = self.read_memory(run.pid, address, read_size, false).ok();
        let shadow_offset = address.checked_sub(run.base).map(|offset| offset as usize);
        let old_bytes = match (&run.shadow, shadow_offset) {
            (Some(shadow), Some(start)) => shadow.get(start..start + read_size).map(<[u8]>::to_vec),
            _ => None,
        };
        if let (Some(shadow), Some(start), Some(new)) = (run.shadow.as_mut(), shadow_offset, new_bytes.as_ref()) {
            for (index, byte) in new.iter().enumerate() {
                if let Some(slot) = shadow.get_mut(start + index) {
                    *slot = *byte;
                }
            }
        }
        let as_value = |bytes: &Option<Vec<u8>>| -> Value {
            match bytes {
                Some(bytes) if bytes.len() <= 8 => {
                    let mut padded = [0u8; 8];
                    padded[..bytes.len()].copy_from_slice(bytes);
                    json!(hex(u64::from_le_bytes(padded)))
                }
                Some(bytes) => json!(hex::encode(bytes)),
                None => Value::Null,
            }
        };
        let key = (instruction, offset, kind.to_owned());
        let location = Self::annotate(instruction, &run.modules);
        let entry = run.entries.entry(key).or_insert_with(|| AccessEntry {
            instruction,
            location: location.clone(),
            disasm: chosen.map_or_else(|| format!("<unrecovered; trap rip {rip:#x}>"), |candidate| candidate.text.clone()),
            address,
            offset,
            size,
            kind: kind.to_owned(),
            confidence,
            alternatives: candidates
                .iter()
                .skip(1)
                .take(4)
                .map(|candidate| json!({"instruction":hex(candidate.address),"disasm":candidate.text,"exact":candidate.exact}))
                .collect(),
            ..Default::default()
        });
        entry.count += 1;
        if entry.samples.len() < run.samples {
            entry.samples.push(json!({"thread_id":thread,"rip_after":hex(rip),"dr6":hex(dr6),
                "old":as_value(&old_bytes),"new":as_value(&new_bytes),"registers":registers(&raw)?}));
        }
        Ok(true)
    }

    // ---- crash triage ------------------------------------------------------------

    /// Analyze the current stop, or resume and wait for a fault stop. Never
    /// resumes after the fault; returns `{"report": ..., "capture": bytes?}`.
    pub fn crash_triage(&mut self, request: &CrashRequest) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.access_pid()?;
        ensure!(request.timeout.as_secs() <= MAX_SECONDS, "timeout must be 1-300 s");
        let mut skipped = Vec::new();
        let event = if request.wait {
            let deadline = Instant::now() + request.timeout;
            loop {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    let settled = self.halt_and_settle()?;
                    return Ok(json!({"fault":false,"reason":"timeout","skipped_stops":skipped,"halted":settled}));
                };
                self.control("resume", 0)?;
                let Some(event) = self.wait_stop(remaining)? else {
                    let settled = self.halt_and_settle()?;
                    return Ok(json!({"fault":false,"reason":"timeout","skipped_stops":skipped,"halted":settled,
                        "note":"No fault within the timeout; the target was halted"}));
                };
                let status = event["status"].as_u64().unwrap_or(0) as u32;
                if decode_wait_status(status) == WaitStatus::Stopped(SIGTRAP) {
                    skipped.push(json!({"thread_id":event["thread_id"],"rip":event["registers"]["rip"]}));
                    if skipped.len() >= request.max_events {
                        return Ok(json!({"fault":false,"reason":"max_events","skipped_stops":skipped,
                            "note":"Only SIGTRAP stops were seen; the target is halted at the last one"}));
                    }
                    continue;
                }
                break Some(event);
            }
        } else {
            let wanted = request.thread_id;
            self.stash
                .iter()
                .rev()
                .find(|event| wanted.is_none_or(|thread| event["thread_id"].as_u64() == Some(thread as u64)))
                .cloned()
        };
        let thread = match (request.thread_id, &event) {
            (Some(thread), _) => thread,
            (None, Some(event)) => event["thread_id"].as_u64().unwrap_or(0) as u32,
            (None, None) => self
                .threads()?
                .as_array()
                .and_then(|threads| threads.first())
                .and_then(Value::as_u64)
                .context("No thread to analyze")? as u32,
        };
        let mut report = self.analyze_crash(pid, thread, event.as_ref(), request.capture_bytes)?;
        report["skipped_stops"] = json!(skipped);
        report["waited"] = json!(request.wait);
        Ok(report)
    }

    fn analyze_crash(&mut self, pid: u32, thread: u32, event: Option<&Value>, capture_bytes: usize) -> Result<Value> {
        let raw = self.get_registers_raw(thread)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(0);
        let rsp = file.get("rsp").unwrap_or(0);
        let trapno = word(&raw, 120) as u64;
        let err = word(&raw, 128) as u64;
        let status = event.and_then(|event| event["status"].as_u64()).map(|status| status as u32);
        let signal = status.and_then(|status| match decode_wait_status(status) {
            WaitStatus::Stopped(signal) | WaitStatus::Signaled(signal, _) => Some(signal),
            WaitStatus::Exited(_) => None,
        });
        let maps = self.access_maps(pid)?;
        let modules = self.access_modules(pid);
        let tls = self.access_tls(thread);
        let rip_map = map_containing(&maps, rip);
        let code = self.read_code(pid, rip, 15);
        let mut facts = CrashFacts {
            signal,
            trapno,
            err,
            rip,
            rip_in_module: Self::annotate(rip, &modules).is_some(),
            rip_map: rip_map.clone(),
            rsp,
            rsp_map: map_containing(&maps, rsp),
            ..Default::default()
        };
        let mut instruction_json = Value::Null;
        let mut operands_json = Vec::new();
        if let Ok(bytes) = &code {
            let mut decoder = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if !instruction.is_invalid() {
                let text = disasm::decode(&bytes[..instruction.len().min(bytes.len())], rip, 1)
                    .first()
                    .map(|item| item.text.clone())
                    .unwrap_or_default();
                facts.mnemonic = Some(match instruction.mnemonic() {
                    Mnemonic::Int3 => "int3".to_owned(),
                    Mnemonic::Ud2 => "ud2".to_owned(),
                    _ => crate::structinfer::mnemonic(&text),
                });
                instruction_json = json!({"address":hex(rip),"text":text,"bytes":hex::encode(&bytes[..instruction.len()]),
                    "length":instruction.len()});
                for operand in memory_operands(&instruction, &raw, tls) {
                    let map = operand.address.and_then(|address| map_containing(&maps, address));
                    operands_json.push(json!({"address":operand.address.map(hex),"size":operand.size,"access":operand.access,
                        "mapping":map_json(&map),"mapped":map.is_some(),
                        "location":operand.address.and_then(|address| Self::annotate(address, &modules))}));
                    facts.operands.push((operand, map));
                }
            } else {
                instruction_json = json!({"address":hex(rip),"error":"undecodable bytes","bytes":hex::encode(&bytes[..bytes.len().min(15)])});
            }
        } else if let Err(error) = &code {
            instruction_json = json!({"address":hex(rip),"error":format!("{error:#}")});
        }
        let classification = classify_crash(&facts);
        // Which registers hold pointers, and into what: the usual first question for a bad deref.
        let register_pointers: Vec<Value> = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        ]
        .iter()
        .filter_map(|name| {
            let value = file.get(name)?;
            let map = map_containing(&maps, value)?;
            Some(json!({"register":name,"value":hex(value),"location":Self::annotate(value, &modules),"mapping":map_json(&Some(map))}))
        })
        .collect();
        // The instructions after the faulting one show what the code intended to do next.
        let code_window: Vec<Value> = self
            .read_code(pid, rip, 64)
            .map(|bytes| {
                disasm::decode(&bytes, rip, 8)
                    .into_iter()
                    .map(|item| json!({"address":hex(item.address),"text":item.text}))
                    .collect()
            })
            .unwrap_or_default();
        let stack = self.stack_trace(thread, 16).unwrap_or_else(|error| json!({"error":format!("{error:#}")}));
        // Bounded memory captures around rsp and each mapped operand.
        let mut captures = Vec::new();
        let mut capture_blob: Vec<u8> = Vec::new();
        let mut budget = capture_bytes.min(4096);
        let mut regions = vec![("rsp", rsp, budget.min(512))];
        for (operand, map) in &facts.operands {
            if let (Some(address), Some(_)) = (operand.address, map) {
                regions.push(("operand", address.saturating_sub(32) & !0xf, 96));
            }
        }
        for (label, address, want) in regions {
            if budget == 0 || want == 0 {
                break;
            }
            let Some(entry) = map_containing(&maps, address).filter(|entry| entry.2 & 1 != 0) else { continue };
            let length = want.min(budget).min((entry.1 - address) as usize);
            if length == 0 {
                continue;
            }
            if let Ok(bytes) = self.read_memory(pid, address, length, false) {
                budget -= bytes.len();
                captures.push(json!({"label":label,"address":hex(address),"length":bytes.len(),"hex":hex::encode(&bytes)}));
                capture_blob.extend(&bytes);
            }
        }
        Ok(json!({
            "fault": signal.is_some_and(|signal| signal != SIGTRAP),
            "thread_id": thread,
            "status": status.map(wait_status_json),
            "signal": signal.map(signal_name),
            "trapno": trapno,
            "error_code": hex(err),
            "page_fault_error": (trapno == 12 || trapno == 14).then(|| json!({"present":err & 1 != 0,"write":err & 2 != 0,
                "user":err & 4 != 0,"instruction_fetch":err & 16 != 0})),
            "rip": hex(rip),
            "rip_location": Self::annotate(rip, &modules),
            "rip_mapping": map_json(&rip_map),
            "rsp": hex(rsp),
            "rsp_mapping": map_json(&facts.rsp_map),
            "instruction": instruction_json,
            "memory_operands": operands_json,
            "code_window": code_window,
            "register_pointers": register_pointers,
            "classification": classification.first().cloned(),
            "classifications": classification,
            "registers": registers(&raw)?,
            "stack": stack,
            "memory": captures,
            "capture_hex_bytes": capture_blob.len(),
            "note": "Faults trap before the instruction retires: rip is the faulting instruction and registers are pre-fault. The target was not resumed.",
        }))
    }

    // ---- host-scripted breakpoints -----------------------------------------------

    /// Run with host-side Rhai breakpoint scripts. Internal breakpoints are
    /// cleared on every exit path; the target is left halted.
    pub fn run_script(&mut self, request: &ScriptRequest) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.access_pid()?;
        ensure!(request.timeout.as_secs() <= MAX_SECONDS && !request.timeout.is_zero(), "timeout must be 1-300 s");
        ensure!((1..=16).contains(&request.breakpoints.len()), "1-16 breakpoints required");
        ensure!((1..=1000).contains(&request.max_stops), "max_stops must be 1-1000");
        let slot: hostscript::MemorySlot = std::rc::Rc::new(std::cell::RefCell::new(None));
        // Compile before touching the target.
        let mut host = hostscript::ScriptHost::new(&request.source, request.limits, slot.clone())?;
        let modules = self.access_modules(pid);
        let mut ours: Vec<u32> = Vec::new();
        let mut targets: Vec<(String, u64, u64)> = Vec::new(); // (name, address, hits)
        let mut armed = Ok(());
        for (name, address) in &request.breakpoints {
            hostscript::validate_name(name)?;
            targets.push((name.clone(), *address, 0));
            let existing = self.breakpoints.iter().any(|(_, record)| record.enabled && record.address == *address);
            if !existing {
                match self.set_internal_breakpoint(*address) {
                    Ok(index) => ours.push(index),
                    Err(error) => {
                        armed = Err(error);
                        break;
                    }
                }
            }
        }
        let outcome = match armed {
            Ok(()) => self.script_loop(pid, request, &mut host, &slot, &mut targets, &modules),
            Err(error) => Err(error),
        };
        let mut cleanup_errors = Vec::new();
        for index in ours {
            if let Err(error) = self.clear_internal_breakpoint(index) {
                cleanup_errors.push(format!("breakpoint slot {index}: {error:#}"));
            }
        }
        let (hits, logs, reason) = match outcome {
            Ok(result) => result,
            Err(error) => {
                if self.attached_pid.is_some()
                    && let Err(halt) = self.halt_and_settle()
                {
                    cleanup_errors.push(format!("halt after error: {halt:#}"));
                }
                let cleanup = if cleanup_errors.is_empty() {
                    "internal breakpoints cleared".to_owned()
                } else {
                    format!("cleanup uncertain: {}", cleanup_errors.join("; "))
                };
                return Err(error.context(cleanup));
            }
        };
        Ok(json!({
            "stop_reason": reason,
            "stops": hits.len(),
            "hits": hits,
            "logs": logs,
            "state": host.state_json(),
            "breakpoints": targets.iter().map(|(name, address, count)| json!({"name":name,"address":hex(*address),
                "location":Self::annotate(*address, &modules),"hits":count})).collect::<Vec<_>>(),
            "cleanup": {"breakpoints_cleared": cleanup_errors.is_empty(), "errors": cleanup_errors, "target_state": "halted"},
            "note": "Scripts are read-only: on_stop may read registers/memory, log and decide continue/stop; script errors or budget exhaustion stop the run.",
        }))
    }

    #[allow(clippy::type_complexity)]
    fn script_loop(
        &mut self,
        pid: u32,
        request: &ScriptRequest,
        host: &mut hostscript::ScriptHost,
        slot: &hostscript::MemorySlot,
        targets: &mut [(String, u64, u64)],
        modules: &[(String, u64, u64)],
    ) -> Result<(Vec<Value>, Vec<String>, Value)> {
        let deadline = Instant::now() + request.timeout;
        let mut hits = Vec::new();
        let mut logs: Vec<String> = Vec::new();
        let mut total = 0u64;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
                self.halt_and_settle()?;
                return Ok((hits, logs, json!({"reason":"timeout"})));
            };
            self.control("resume", 0)?;
            let Some(event) = self.wait_stop(remaining)? else {
                self.halt_and_settle()?;
                return Ok((hits, logs, json!({"reason":"timeout"})));
            };
            let status = event["status"].as_u64().unwrap_or(0) as u32;
            let thread = event["thread_id"].as_u64().unwrap_or(0) as u32;
            let event_rip = parse_hex(&event["registers"]["rip"]).unwrap_or(0);
            if decode_wait_status(status) != WaitStatus::Stopped(SIGTRAP) {
                return Ok((hits, logs, json!({"reason":"signal","status":wait_status_json(status),"thread_id":thread,
                    "rip":hex(event_rip),"note":"Non-breakpoint signal; target left halted (try debug_crash_triage)"})));
            }
            let Some(target) = targets
                .iter_mut()
                .find(|(_, address, _)| *address == event_rip || address + 1 == event_rip)
            else {
                return Ok((hits, logs, json!({"reason":"foreign_stop","thread_id":thread,"rip":hex(event_rip)})));
            };
            target.2 += 1;
            total += 1;
            let raw = self.get_registers_raw(thread)?;
            let named = registers(&raw)?;
            let registers_map = named
                .as_object()
                .map(|object| {
                    object
                        .iter()
                        .filter_map(|(name, value)| Some((name.clone(), parse_hex(value)?)))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default();
            let hit = hostscript::Hit {
                registers: registers_map,
                bp_name: target.0.clone(),
                bp_address: target.1,
                hits: target.2,
                total_hits: total,
                thread_id: thread,
                location: Self::annotate(target.1, modules),
            };
            let (name, address, count) = (target.0.clone(), target.1, target.2);
            // Lend the debugger to the script for read-only memory access, then take it back.
            let placeholder = Debugger::new(self.profile.clone());
            let real = std::mem::replace(self, placeholder);
            *slot.borrow_mut() = Some(Box::new(DebuggerMemory { debugger: real, pid }));
            let outcome = host.on_stop(hit);
            let lent = slot.borrow_mut().take().expect("script memory slot is only emptied here");
            *self = hostscript::recover::<DebuggerMemory>(lent).expect("slot holds DebuggerMemory").debugger;
            for line in &outcome.logs {
                if logs.len() < request.limits.max_logs {
                    logs.push(format!("[{name}#{count}] {line}"));
                }
            }
            let mut record = outcome.to_json();
            record["name"] = json!(name);
            record["address"] = json!(hex(address));
            record["thread_id"] = json!(thread);
            record["hit"] = json!(count);
            record["rip"] = named["rip"].clone();
            hits.push(record);
            if outcome.decision == hostscript::Decision::Stop {
                return Ok((hits, logs, json!({"reason":"script_stop","error":outcome.error,"breakpoint":name})));
            }
            if hits.len() >= request.max_stops {
                return Ok((hits, logs, json!({"reason":"max_stops"})));
            }
        }
    }

    // ---- pointer scanning ----------------------------------------------------------

    /// Read-only snapshot of writable non-executable data maps (module data
    /// segments first) within `budget` bytes.
    pub fn pointer_snapshot(&mut self, pid: u32, budget: usize, include_heap: bool) -> Result<(pointerscan::Snapshot, Value)> {
        let maps = self.access_maps(pid)?;
        let modules: Vec<pointerscan::Module> = self
            .access_modules(pid)
            .into_iter()
            .map(|(name, base, end)| pointerscan::Module { name, base, end })
            .collect();
        let readable: Vec<(u64, u64)> = maps.iter().filter(|entry| entry.2 & 1 != 0).map(|entry| (entry.0, entry.1)).collect();
        let in_module = |entry: &MapEntry| modules.iter().any(|module| module.base <= entry.0 && entry.0 < module.end);
        let mut candidates: Vec<&MapEntry> = maps.iter().filter(|entry| entry.2 & 3 == 3 && entry.2 & 4 == 0).collect();
        candidates.retain(|entry| include_heap || in_module(entry));
        candidates.sort_by_key(|entry| (!in_module(entry), entry.0));
        let chunk = self.profile.limit("memory_bytes").clamp(0x1000, 1 << 20) & !0xfff;
        let started = Instant::now();
        let mut regions = Vec::new();
        let (mut used, mut failures, mut truncated) = (0usize, 0usize, false);
        'outer: for entry in &candidates {
            let mut cursor = entry.0;
            while cursor < entry.1 {
                if used >= budget || started.elapsed() > Duration::from_secs(MAX_SECONDS / 2) {
                    truncated = true;
                    break 'outer;
                }
                let length = (entry.1 - cursor).min(chunk as u64).min((budget - used) as u64) as usize;
                match self.read_memory(pid, cursor, length, false) {
                    Ok(data) => {
                        used += data.len();
                        regions.push(pointerscan::Region { start: cursor, data });
                    }
                    Err(_) => failures += 1,
                }
                cursor += length as u64;
            }
        }
        let stats = json!({"bytes_read":used,"budget":budget,"regions_considered":candidates.len(),"chunks":regions.len(),
            "chunk_failures":failures,"truncated":truncated,"elapsed_ms":started.elapsed().as_millis() as u64});
        Ok((pointerscan::Snapshot { regions, readable, modules }, stats))
    }

    /// Resolve saved pointer paths live (page-cached, read-only, bounded by `budget`).
    pub fn pointer_resolve(&mut self, pid: u32, paths: &[pointerscan::PointerPath], budget: usize) -> Result<(Vec<Option<u64>>, Value)> {
        let modules = self.access_modules(pid);
        let bases: HashMap<String, u64> = modules.iter().map(|(name, base, _)| (name.clone(), *base)).collect();
        let mut pages: HashMap<u64, Option<Vec<u8>>> = HashMap::new();
        let mut used = 0usize;
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            let value = pointerscan::resolve(path, |name| bases.get(name).copied(), |address| {
                let mut bytes = [0u8; 8];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    let at = address.checked_add(index as u64)?;
                    let page = at & !0xfff;
                    let content = match pages.entry(page) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            if used + 0x1000 > budget {
                                return None;
                            }
                            used += 0x1000;
                            entry.insert(self.read_memory(pid, page, 0x1000, false).ok())
                        }
                    };
                    *byte = *content.as_ref()?.get((at - page) as usize)?;
                }
                Some(u64::from_le_bytes(bytes))
            });
            results.push(value);
        }
        Ok((results, json!({"pages_read":pages.len(),"bytes_read":used,"budget":budget,
            "modules":modules.iter().map(|(name, base, _)| json!({"name":name,"base":hex(*base)})).collect::<Vec<_>>()})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake;

    fn raw_registers(values: &[(&str, u64)]) -> Vec<u8> {
        let mut raw = vec![0u8; 176];
        for (name, value) in values {
            let offset = crate::expr::offset_of(name).unwrap();
            raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        raw
    }

    #[test]
    fn wait_status_and_slot_plans() {
        assert_eq!(decode_wait_status(0x57f), WaitStatus::Stopped(5));
        assert_eq!(decode_wait_status((11 << 8) | 0x7f), WaitStatus::Stopped(11));
        assert_eq!(decode_wait_status(0x100), WaitStatus::Exited(1));
        assert_eq!(decode_wait_status(0x8b), WaitStatus::Signaled(11, true));
        assert_eq!(plan_exact(0x1001, 7), vec![(0x1001, 1), (0x1002, 2), (0x1004, 4)]);
        assert_eq!(plan_exact(0x1000, 32).len(), 4);
        assert_eq!(plan_exact(0x1001, 32).len(), 7);
        assert_eq!(plan_cover8(0x1001, 32), vec![(0x1000, 8), (0x1008, 8), (0x1010, 8), (0x1018, 8), (0x1020, 8)]);
    }

    #[test]
    fn back_decoding_recovers_the_accessing_instruction() {
        // nop; mov dword ptr [rax+0x10], ecx (89 48 10); trap rip is after it.
        let code = [0x90, 0x90, 0x89, 0x48, 0x10];
        let raw = raw_registers(&[("rax", 0x5000)]);
        let candidates = recover_access(&code, 0x400000, 0x400005, &raw, None, &[(0x5010, 4)]);
        assert!(candidates[0].exact);
        assert_eq!(candidates[0].address, 0x400002);
        assert_eq!(candidates[0].text, "mov [rax+0x10], ecx");
        assert_eq!(candidates[0].operand.as_ref().unwrap().access, "write");
        // Operand elsewhere: no exact candidate.
        assert!(recover_access(&code, 0x400000, 0x400005, &raw, None, &[(0x9000, 4)]).iter().all(|c| !c.exact));
        // mov rax, [rax]: base clobbered -> plausible only (the tail `mov eax, [rax]` too); longest first.
        let code = [0x48, 0x8b, 0x00];
        let candidates = recover_access(&code, 0x400000, 0x400003, &raw, None, &[(0x7777, 8)]);
        assert_eq!(candidates[0].address, 0x400000);
        assert!(candidates.iter().all(|c| !c.exact && c.operand.as_ref().unwrap().base_clobbered));
    }

    #[test]
    fn crash_classifier_covers_common_faults() {
        let decode = |bytes: &[u8], raw: &[u8]| {
            let instruction = Decoder::with_ip(64, bytes, 0x400000, DecoderOptions::NONE).decode();
            memory_operands(&instruction, raw, None)
        };
        let raw = raw_registers(&[("rax", 0), ("rsp", 0x7fff_0000)]);
        let stack = Some((0x7fff_0000, 0x8000_0000, 3, String::new()));
        let code = Some((0x400000, 0x401000, 5, "eboot.bin".to_owned()));
        let base = CrashFacts { signal: Some(11), rip: 0x400000, rip_map: code.clone(), rip_in_module: true, rsp: 0x7fff_0000, rsp_map: stack.clone(), ..Default::default() };
        // mov ecx, [rax+0x18] with rax = 0
        let facts = CrashFacts {
            mnemonic: Some("mov".into()),
            operands: decode(&[0x8b, 0x48, 0x18], &raw).into_iter().map(|op| (op, None)).collect(),
            ..base.clone()
        };
        assert_eq!(classify_crash(&facts)[0]["class"], "null_pointer_dereference");
        // push rbp at the very bottom of the stack mapping.
        let facts = CrashFacts {
            mnemonic: Some("push".into()),
            operands: decode(&[0x55], &raw).into_iter().map(|op| (op, None)).collect(),
            ..base.clone()
        };
        assert_eq!(classify_crash(&facts)[0]["class"], "stack_overflow");
        // Write into read-only code.
        let raw_code = raw_registers(&[("rax", 0x400100), ("rsp", 0x7fff_0000)]);
        let facts = CrashFacts {
            mnemonic: Some("mov".into()),
            operands: decode(&[0x89, 0x08], &raw_code).into_iter().map(|op| (op, code.clone())).collect(),
            ..base.clone()
        };
        assert_eq!(classify_crash(&facts)[0]["class"], "write_to_read_only");
        let facts = CrashFacts { signal: Some(8), mnemonic: Some("idiv".into()), ..base.clone() };
        assert_eq!(classify_crash(&facts)[0]["class"], "divide_error");
        let facts = CrashFacts { signal: Some(4), mnemonic: Some("ud2".into()), ..base.clone() };
        assert_eq!(classify_crash(&facts)[0]["class"], "ud2_trap");
        let facts = CrashFacts { rip: 0x18, rip_map: None, ..base.clone() };
        assert_eq!(classify_crash(&facts)[0]["class"], "execute_null_pointer");
        let facts = CrashFacts { rip_map: stack.clone(), ..base.clone() };
        assert_eq!(classify_crash(&facts)[0]["class"], "execute_non_executable");
        let facts = CrashFacts { signal: Some(5), ..base };
        assert_eq!(classify_crash(&facts)[0]["class"], "no_fault");
    }

    const BASE: u64 = 0x40_0000;
    const OBJECT: u64 = 0x9000_0000;

    /// Fixture image: write at +0x10 (mov [rax+0x10], ecx), read at +0x20 (movss xmm0, [rax+0x14]),
    /// a breakpoint target at +0x30 and a null dereference at +0x40 (mov ecx, [rax+0x18]).
    fn image() -> Vec<u8> {
        let mut image = vec![0x90u8; 0x100];
        image[0x10..0x13].copy_from_slice(&[0x89, 0x48, 0x10]);
        image[0x20..0x25].copy_from_slice(&[0xf3, 0x0f, 0x10, 0x40, 0x14]);
        image[0x40..0x43].copy_from_slice(&[0x8b, 0x48, 0x18]);
        image
    }

    fn fixture(program: Vec<fake::FixtureStep>) -> (fake::FakeDebugger, tempfile::TempDir, Debugger) {
        let mut object = vec![0u8; 0x40];
        object[0x14..0x18].copy_from_slice(&1.5f32.to_le_bytes());
        object[0x20..0x28].copy_from_slice(&(BASE + 0x40).to_le_bytes());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = fake::spawn_fixture(
            listener,
            fake::Fixture {
                pid: 71,
                thread_id: 72,
                base: BASE,
                image: image(),
                rip: BASE,
                program,
                extra_maps: vec![
                    (OBJECT, OBJECT + 0x1000, 3, String::new()),
                    (0x50_0000, 0x50_1000, 3, "fixture.elf".to_owned()),
                ],
                extra_memory: vec![(OBJECT, object), (0x50_0100, OBJECT.to_le_bytes().to_vec())],
                ..Default::default()
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let mut debugger = Debugger::new(fake::qualified_profile(directory.path(), fake.port));
        debugger.attach(71, "127.0.0.1").unwrap();
        debugger.wait_stop(Duration::from_secs(2)).unwrap().expect("attach stop");
        (fake, directory, debugger)
    }

    fn step(rip: u64, access: Option<(u64, u64, bool)>) -> fake::FixtureStep {
        fake::FixtureStep { rip, registers: vec![("rax".into(), OBJECT), ("rcx".into(), 7)], access, ..Default::default() }
    }

    #[test]
    fn find_accesses_struct_mode_and_struct_inference_against_fixture() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let program = vec![
            step(BASE + 0x10, Some((OBJECT + 0x10, 4, true))),
            step(BASE + 0x20, Some((OBJECT + 0x14, 4, false))),
            step(BASE + 0x10, Some((OBJECT + 0x10, 4, true))),
        ];
        let (_fake, _directory, mut debugger) = fixture(program);
        let result = debugger
            .find_accesses(&AccessRequest {
                address: OBJECT + 0x10,
                length: 8,
                access: "read_write".into(),
                span: None,
                timeout: Duration::from_secs(3),
                max_hits: 16,
                samples: 2,
            })
            .unwrap();
        assert_eq!(result["hits"], 3, "{result:#}");
        let accesses = result["document"]["accesses"].as_array().unwrap();
        let write = accesses.iter().find(|a| a["kind"] == "write").unwrap();
        assert_eq!(write["instruction"], format!("{:#x}", BASE + 0x10));
        assert_eq!(write["location"], "fixture.elf+0x10");
        assert_eq!(write["count"], 2);
        assert_eq!(write["offset"], 0);
        assert_eq!(write["confidence"], "exact");
        assert_eq!(write["disasm"], "mov [rax+0x10], ecx");
        let read = accesses.iter().find(|a| a["kind"] == "read").unwrap();
        assert_eq!(read["offset"], 4);
        assert_eq!(read["disasm"], "movss xmm0, [rax+0x14]");
        // Its tails (movups / adc) also decode to rip and touch the range: reported, not hidden.
        assert_eq!(read["confidence"], "ambiguous");
        assert!(!read["alternatives"].as_array().unwrap().is_empty());
        assert!(debugger.watchpoints.is_empty(), "watchpoints disarmed");
        assert_eq!(result["stop_reason"]["reason"], "timeout");

        // Struct inference consumes the access log directly.
        let mut document = result["document"].clone();
        document["base"] = json!(format!("{OBJECT:#x}"));
        for access in document["accesses"].as_array_mut().unwrap() {
            access["offset"] = json!(access["offset"].as_i64().unwrap() + 0x10);
        }
        let inferred = crate::structinfer::infer(
            "Obj",
            Some(0x20),
            &crate::structinfer::Evidence { access_logs: vec![document], images: vec![], maps: vec![] },
        )
        .unwrap();
        let field = |offset: u64| inferred["fields"].as_array().unwrap().iter().find(|f| f["offset"] == offset).cloned().unwrap();
        assert_eq!(field(0x14)["type"], "float");
        assert_eq!(field(0x10)["size"], 4);
        debugger.detach().unwrap();
    }

    #[test]
    fn struct_mode_rotates_slots_over_the_span() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        // Accesses at +0x10 and +0x30: different 32-byte rounds.
        let program = vec![
            step(BASE + 0x10, Some((OBJECT + 0x10, 4, true))),
            step(BASE + 0x40, Some((OBJECT + 0x18, 4, false))),
        ];
        let (_fake, _directory, mut debugger) = fixture(program);
        let result = debugger
            .find_accesses(&AccessRequest {
                address: OBJECT,
                length: 0,
                access: "read_write".into(),
                span: Some(0x40),
                timeout: Duration::from_secs(4),
                max_hits: 16,
                samples: 1,
            })
            .unwrap();
        assert_eq!(result["rounds"], 2);
        // Both accesses fall into round one (0x0..0x20); the program is consumed there.
        assert_eq!(result["hits"], 2, "{result:#}");
        let offsets: Vec<i64> = result["document"]["accesses"].as_array().unwrap().iter().map(|a| a["offset"].as_i64().unwrap()).collect();
        assert!(offsets.contains(&0x10) && offsets.contains(&0x18), "{offsets:?}");
        assert!(debugger.watchpoints.is_empty());
        debugger.detach().unwrap();
    }

    #[test]
    fn crash_triage_waits_for_fault_and_classifies_null_dereference() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let mut fault = step(BASE + 0x40, None);
        fault.registers = vec![("rax".into(), 0)];
        fault.signal = Some(11);
        let (_fake, _directory, mut debugger) = fixture(vec![fault]);
        let report = debugger
            .crash_triage(&CrashRequest { wait: true, timeout: Duration::from_secs(3), thread_id: None, max_events: 8, capture_bytes: 128 })
            .unwrap();
        assert_eq!(report["fault"], true, "{report:#}");
        assert_eq!(report["signal"], "SIGSEGV");
        assert_eq!(report["classification"]["class"], "null_pointer_dereference");
        assert_eq!(report["instruction"]["text"], "mov ecx, [rax+0x18]");
        assert_eq!(report["memory_operands"][0]["address"], "0x18");
        assert_eq!(report["rip_location"], "fixture.elf+0x40");
        assert!(report["stack"]["frames"].is_array());
        assert!(!report["memory"].as_array().unwrap().is_empty());
        assert_eq!(report["code_window"][0]["text"], "mov ecx, [rax+0x18]");
        // rax is null, so it must not be listed as a pointer.
        assert!(report["register_pointers"].as_array().unwrap().iter().all(|entry| entry["register"] != "rax"));
        // Analyzing the current stop again (no resume) gives the same answer.
        let again = debugger
            .crash_triage(&CrashRequest { wait: false, timeout: Duration::from_secs(1), thread_id: None, max_events: 1, capture_bytes: 0 })
            .unwrap();
        assert_eq!(again["classification"]["class"], "null_pointer_dereference");
        debugger.detach().unwrap();
    }

    #[test]
    fn run_script_decides_per_hit_and_clears_breakpoints() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let program = vec![step(BASE + 0x30, None), step(BASE + 0x31, None), step(BASE + 0x30, None)];
        let (_fake, _directory, mut debugger) = fixture(program);
        let source = r#"
            fn on_stop(ctx) {
                ctx.state.n = (ctx.state.n ?? 0) + 1;
                log(`${ctx.bp_name} hit ${ctx.hits} rax=${hex(ctx.reg("rax"))} f=${ctx.read_f32(ctx.reg("rax") + 0x14)}`);
                if ctx.state.n >= 2 { "stop" } else { "continue" }
            }
        "#;
        let result = debugger
            .run_script(&ScriptRequest {
                source: source.into(),
                breakpoints: vec![("tick".into(), BASE + 0x30)],
                timeout: Duration::from_secs(4),
                max_stops: 10,
                limits: hostscript::Limits::default(),
            })
            .unwrap();
        assert_eq!(result["stop_reason"]["reason"], "script_stop", "{result:#}");
        assert_eq!(result["stops"], 2);
        assert_eq!(result["logs"][0], "[tick#1] tick hit 1 rax=0x90000000 f=1.5");
        assert_eq!(result["state"]["n"], 2);
        assert_eq!(result["breakpoints"][0]["location"], "fixture.elf+0x30");
        assert!(debugger.breakpoints.is_empty(), "internal breakpoints cleared");
        assert!(debugger.attached_pid.is_some(), "debugger returned after lending it to the script");
        debugger.detach().unwrap();
    }

    #[test]
    fn pointer_scan_and_rescan_against_fixture_memory() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let (_fake, _directory, mut debugger) = fixture(vec![]);
        let (snapshot, stats) = debugger.pointer_snapshot(71, 1 << 20, true).unwrap();
        assert!(stats["bytes_read"].as_u64().unwrap() > 0);
        let outcome = pointerscan::scan(
            &snapshot,
            OBJECT + 0x14,
            pointerscan::ScanOptions { max_depth: 3, max_offset: 0x100, max_results: 50 },
        );
        let texts: Vec<String> = outcome.paths.iter().map(pointerscan::PointerPath::text).collect();
        assert!(texts.contains(&"[fixture.elf+0x100100] -> +0x14".to_owned()), "{texts:?}");
        let (resolved, _) = debugger.pointer_resolve(71, &outcome.paths, 1 << 20).unwrap();
        assert!(resolved.iter().all(|value| *value == Some(OBJECT + 0x14)), "{resolved:?}");
        debugger.detach().unwrap();
    }
}
