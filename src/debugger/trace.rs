//! Run-loop tracing on top of the pinned ps4debug-NG breakpoint model: import
//! (ltrace-like), syscall-wrapper and function tracing plus one-shot breakpoint
//! coverage with rotating slot batches.
//!
//! Hardware semantics this code is written against (see `ops.rs` and
//! `docs/PROTOCOL.md`): the server steps the thread over the instruction under a
//! software breakpoint *before* it reports the hit, so the live registers reflect
//! the state after that first instruction while the event's register block may be
//! a stale (pre-step) snapshot. Every hit therefore decodes the original first
//! instruction: registers it does not write are read live; registers it writes are
//! taken from the event snapshot and labelled as such. The model is all-stop:
//! one resume continues every thread.
//!
//! Safety rules: internal breakpoints only use free slots (user breakpoints are
//! never touched), at most [`MAX_INTERNAL_SLOTS`] at once; every exit path halts a
//! still-running target and clears every internal slot, reporting any failure as
//! an uncertain console state. Memory is only read inside known readable maps
//! (a rejected read drops the debugger session) and never written except by the
//! breakpoint command itself.

use super::*;
use crate::{expr::RegisterFile, tracekit};
use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;

/// Software breakpoint slots exposed by the pinned server (`breakpoint` checks `index < 30`).
pub const SLOT_COUNT: u32 = 30;
/// Upper bound on internal slots one tracing tool may hold at once.
pub const MAX_INTERNAL_SLOTS: u32 = 28;
pub const MAX_TRACE_SECONDS: u64 = 300;
pub const MAX_TRACE_EVENTS: usize = 10_000;
/// Bytes of executable memory a single planning scan may read.
pub const DEFAULT_SCAN_LIMIT: usize = 64 * 1024 * 1024;

const CALL_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const SYSCALL_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];
/// FreeBSD wait status `WIFSTOPPED` with `SIGTRAP` (5).
const SIGTRAP: u64 = 5;

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn hex_opt(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |value| json!(hex(value)))
}

// ---- probes, options, reports ----------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// Function entry or PLT stub: SysV arguments, `[rsp]` is the return address.
    Call,
    /// `mov rax/eax, N` that starts a recognised syscall wrapper.
    SyscallWrapper { number: u64, rcx_is_arg4: bool, entry_like: bool },
    /// The `syscall` instruction itself: it has executed when the hit is
    /// reported, so everything comes from the (pre-step) event snapshot.
    SyscallInstruction,
}

#[derive(Debug, Clone)]
pub struct TraceProbe {
    pub address: u64,
    pub label: String,
    pub kind: ProbeKind,
    /// Static facts echoed into every event (symbol, library, syscall, ...).
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub timeout: Duration,
    pub max_events: usize,
    pub max_breakpoints: u32,
    pub capture_returns: bool,
    pub arg_count: usize,
    /// Dereference pointer arguments as C strings up to this many bytes (0 = off).
    pub string_bytes: usize,
    pub thread_id: Option<u32>,
    /// Per-hit `debug_stack`-style backtrace depth (0 = off; expensive).
    pub backtrace_frames: usize,
    pub syscall_names: Option<HashMap<u64, String>>,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_events: 1000,
            max_breakpoints: MAX_INTERNAL_SLOTS,
            capture_returns: false,
            arg_count: 6,
            string_bytes: 0,
            thread_id: None,
            backtrace_frames: 0,
            syscall_names: None,
        }
    }
}

pub struct TraceReport {
    pub events: Vec<Value>,
    pub summary: Value,
    pub cleanup: Value,
    pub cleanup_complete: bool,
}

pub struct CoveragePlan {
    pub module: String,
    pub base: u64,
    pub end: u64,
    pub image_base: u64,
    pub module_sha256: Option<String>,
    /// `(rva, size)` relative to `base` / `image_base`.
    pub blocks: Vec<(u64, u64)>,
    pub granularity: &'static str,
    pub source: String,
    pub dropped: usize,
    pub notes: Vec<String>,
}

pub struct CoverageRun {
    /// Per block: 1 when its one-shot breakpoint fired, else 0.
    pub hits: Vec<u64>,
    pub first_hit_ms: Vec<Option<u64>>,
    pub never_armed: Vec<usize>,
    pub stop_reason: String,
    pub stops: usize,
    pub foreign_stop: Option<Value>,
    pub cleanup: Value,
    pub cleanup_complete: bool,
}

// ---- session state -----------------------------------------------------------

#[derive(Debug, Clone)]
struct MapEntry {
    start: u64,
    end: u64,
    protection: u64,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Probe(usize),
    Return,
    Block(usize),
}

/// `(name, base, end)` of loaded modules.
type Modules = Vec<(String, u64, u64)>;

struct Session {
    pid: u32,
    slots: BTreeMap<u32, (u64, Role)>,
    running: bool,
    queue: VecDeque<Value>,
    started: Instant,
    maps: Vec<MapEntry>,
    modules: Modules,
}

fn covered(maps: &[MapEntry], address: u64, length: u64, mask: u64) -> bool {
    let end = address as u128 + length as u128;
    let mut position = address as u128;
    let mut entries: Vec<&MapEntry> = maps.iter().filter(|entry| entry.protection & mask == mask).collect();
    entries.sort_by_key(|entry| entry.start);
    for entry in entries {
        if (entry.start as u128) <= position && position < entry.end as u128 {
            position = entry.end as u128;
            if position >= end {
                return true;
            }
        }
    }
    length == 0
}

impl Session {
    fn executable(&self, address: u64) -> bool {
        covered(&self.maps, address, 1, 4)
    }
    /// End of the non-executable readable map holding `address` (the stack).
    fn stack_end(&self, address: u64) -> Option<u64> {
        self.maps
            .iter()
            .find(|entry| entry.protection & 5 == 1 && entry.start <= address && address < entry.end)
            .map(|entry| entry.end)
    }
    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
    /// Our slot whose breakpoint explains a stop at `rip` (int3 trap reports
    /// `address + 1`; some paths report `address`).
    fn slot_at(&self, rip: u64) -> Option<(u32, u64, Role)> {
        let find = |predicate: &dyn Fn(u64) -> bool| {
            self.slots
                .iter()
                .find(|(_, (address, _))| predicate(*address))
                .map(|(slot, (address, role))| (*slot, *address, *role))
        };
        find(&|address| address.wrapping_add(1) == rip).or_else(|| find(&|address| address == rip))
    }
}

fn parse_maps(maps: &Value) -> Vec<MapEntry> {
    maps.as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| MapEntry {
                    start: entry["start"].as_u64().unwrap_or(0),
                    end: entry["end"].as_u64().unwrap_or(0),
                    protection: entry["protection"].as_u64().unwrap_or(0),
                    name: entry["name"].as_str().unwrap_or("").to_owned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_modules(modules: &Value) -> Modules {
    modules
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|module| {
                    let base = tracekit::parse_number(module["base"].as_str()?)?;
                    Some((module["name"].as_str()?.to_owned(), base, base + module["size"].as_u64()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Exact (case-insensitive) module name match, else unique-first substring match.
fn pick_module(modules: &[(String, u64, u64)], wanted: &str) -> Result<(String, u64, u64)> {
    let needle = wanted.to_ascii_lowercase();
    modules
        .iter()
        .find(|(name, _, _)| name.eq_ignore_ascii_case(wanted))
        .or_else(|| modules.iter().find(|(name, _, _)| name.to_ascii_lowercase().contains(&needle)))
        .cloned()
        .with_context(|| {
            format!(
                "Module '{wanted}' not found; loaded: {}",
                modules.iter().map(|(name, _, _)| name.as_str()).take(40).collect::<Vec<_>>().join(", ")
            )
        })
}

// ---- first-instruction analysis ------------------------------------------------

fn register_of(name: &str) -> Option<Register> {
    Some(match name {
        "rax" => Register::RAX,
        "rbx" => Register::RBX,
        "rcx" => Register::RCX,
        "rdx" => Register::RDX,
        "rsi" => Register::RSI,
        "rdi" => Register::RDI,
        "rbp" => Register::RBP,
        "rsp" => Register::RSP,
        "r8" => Register::R8,
        "r9" => Register::R9,
        "r10" => Register::R10,
        "r11" => Register::R11,
        "r12" => Register::R12,
        "r13" => Register::R13,
        "r14" => Register::R14,
        "r15" => Register::R15,
        _ => return None,
    })
}

/// What the instruction at a probe does to the registers before the hit is
/// reported: written full registers and the `rsp` delta that recovers the value
/// at the probe (`rsp_at_probe = live_rsp + delta`), `None` when not derivable.
struct FirstInstruction {
    decoded: bool,
    written: Vec<Register>,
    rsp_delta: Option<i64>,
    text: String,
}

fn first_instruction(code: &[u8], address: u64) -> FirstInstruction {
    let mut decoder = Decoder::with_ip(64, code, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return FirstInstruction { decoded: false, written: Vec::new(), rsp_delta: None, text: String::new() };
    }
    let mut factory = InstructionInfoFactory::new();
    let written: Vec<Register> = factory
        .info(&instruction)
        .used_registers()
        .iter()
        .filter(|used| {
            matches!(used.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
        })
        .map(|used| used.register().full_register())
        .collect();
    let rsp_delta = if !written.contains(&Register::RSP) {
        Some(0)
    } else if instruction.stack_pointer_increment() != 0 {
        Some(-(instruction.stack_pointer_increment() as i64))
    } else if matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Add)
        && instruction.op0_kind() == OpKind::Register
        && instruction.op0_register() == Register::RSP
        && matches!(
            instruction.op1_kind(),
            OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate8to64 | OpKind::Immediate32to64
        )
    {
        let immediate = instruction.immediate(1) as i64;
        Some(if instruction.mnemonic() == Mnemonic::Sub { immediate } else { -immediate })
    } else {
        None
    };
    FirstInstruction { decoded: true, written, rsp_delta, text: format!("{instruction}") }
}

/// Register view of one hit (see the module docs for the source rules).
struct HitView {
    live: Vec<u8>,
    event: Option<Vec<u8>>,
    first: FirstInstruction,
    /// Everything from the event snapshot (the probed instruction was a syscall).
    event_only: bool,
}

impl HitView {
    fn new(code: &[u8], address: u64, live: Vec<u8>, event: &Value, event_only: bool) -> Self {
        let event = event["raw_hex"]
            .as_str()
            .and_then(|text| hex::decode(text).ok())
            .filter(|data| data.len() >= 224)
            .map(|data| data[48..224].to_vec());
        Self { live, event, first: first_instruction(code, address), event_only }
    }

    fn event_value(&self, name: &str) -> Option<u64> {
        self.event.as_ref().and_then(|event| RegisterFile(event).get(name))
    }

    fn get(&self, name: &str) -> (Option<u64>, &'static str) {
        let clobbered = self.event_only
            || !self.first.decoded
            || register_of(name).is_some_and(|register| self.first.written.contains(&register));
        if clobbered && self.event.is_some() {
            return (self.event_value(name), "event_snapshot");
        }
        (RegisterFile(&self.live).get(name), if clobbered { "live_possibly_clobbered" } else { "live" })
    }

    /// `rsp` as it was when the probed instruction started.
    fn rsp(&self) -> (Option<u64>, &'static str) {
        if !self.event_only
            && let Some(delta) = self.first.rsp_delta
            && let Some(live) = RegisterFile(&self.live).get("rsp")
        {
            return (Some(live.wrapping_add(delta as u64)), if delta == 0 { "live" } else { "live_adjusted" });
        }
        match self.event_value("rsp") {
            Some(value) => (Some(value), "event_snapshot"),
            None => (RegisterFile(&self.live).get("rsp"), "live_possibly_clobbered"),
        }
    }
}

struct Pending {
    slot: u32,
    thread: u32,
    expected_rsp: Option<u64>,
    event: usize,
    at: Instant,
}

// ---- engine -----------------------------------------------------------------------

impl Debugger {
    fn trace_pid(&self) -> Result<u32> {
        self.attached_pid.context("No active debugger session; call debug_attach first")
    }

    fn trace_layout(&mut self, pid: u32) -> Result<(Vec<MapEntry>, Modules)> {
        let maps = parse_maps(&self.maps(pid)?);
        let modules = parse_modules(&self.module_list(pid)?);
        Ok((maps, modules))
    }

    fn trace_open(&mut self) -> Result<Session> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        let pid = self.trace_pid()?;
        // Older stops (e.g. the attach stop) must not be attributed to this trace.
        let stale = self.read_events()?;
        self.stash.extend(stale);
        let (maps, modules) = self.trace_layout(pid)?;
        Ok(Session {
            pid,
            slots: BTreeMap::new(),
            running: false,
            queue: VecDeque::new(),
            started: Instant::now(),
            maps,
            modules,
        })
    }

    /// Slots this tool may use: free slots, capped by the request and the global cap.
    fn trace_budget(&self, requested: u32) -> u32 {
        let free = (0..SLOT_COUNT).filter(|slot| !self.breakpoints.contains_key(slot)).count() as u32;
        requested.clamp(1, MAX_INTERNAL_SLOTS).min(free)
    }

    /// Arm an internal breakpoint in a free slot; `None` when no slot is free or
    /// another (user or internal) breakpoint already covers `address`.
    fn trace_arm(&mut self, session: &mut Session, address: u64, role: Role) -> Result<Option<u32>> {
        if self.breakpoints.values().any(|record| record.enabled && record.address == address) {
            return Ok(None);
        }
        let Some(slot) = (0..SLOT_COUNT).rev().find(|slot| !self.breakpoints.contains_key(slot)) else {
            return Ok(None);
        };
        self.breakpoint_ex(slot, address, true, None, None, 0)?;
        if let Some(record) = self.breakpoints.get_mut(&slot) {
            record.internal = true;
        }
        session.slots.insert(slot, (address, role));
        Ok(Some(slot))
    }

    fn trace_disarm(&mut self, session: &mut Session, slot: u32) -> Result<()> {
        session.slots.remove(&slot);
        let result = self.breakpoint(slot, 0, false).map(|_| ());
        self.breakpoints.remove(&slot);
        result
    }

    fn trace_resume(&mut self, session: &mut Session) -> Result<()> {
        self.control("resume", 0)?;
        session.running = true;
        Ok(())
    }

    /// Next stop event (queued first), or `None` at the deadline. Trace stops are
    /// recorded in the trace artifact instead of the unbounded event stash.
    fn trace_next(&mut self, session: &mut Session, deadline: Instant) -> Result<Option<Value>> {
        if let Some(event) = session.queue.pop_front() {
            return Ok(Some(event));
        }
        loop {
            let mut events = self.read_events()?;
            if !events.is_empty() {
                session.running = false;
                let first = events.remove(0);
                session.queue.extend(events);
                return Ok(Some(first));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Halt a still-running target, then clear every internal slot. Never fails;
    /// returns the report and whether cleanup was complete.
    fn trace_close(&mut self, session: &mut Session) -> (Value, bool) {
        let mut errors = Vec::new();
        let mut notes = Vec::new();
        let mut halted = false;
        if session.running {
            match self.control("halt", 0) {
                Ok(_) => {
                    halted = true;
                    session.running = false;
                    match self.wait_stop(Duration::from_secs(3)) {
                        Ok(Some(_)) => {}
                        Ok(None) => notes.push("No stop event arrived within 3 s of the halt request".to_owned()),
                        Err(error) => errors.push(format!("waiting for the halt stop failed: {error:#}")),
                    }
                }
                Err(error) => errors.push(format!("halt failed: {error:#}")),
            }
        }
        let leftover: Vec<Value> = session.queue.drain(..).collect();
        if !leftover.is_empty() {
            notes.push(format!("{} queued stop event(s) left unprocessed in debug_events", leftover.len()));
            self.stash.extend(leftover);
        }
        let slots: Vec<u32> = session.slots.keys().copied().collect();
        let mut cleared = 0usize;
        for slot in slots {
            match self.trace_disarm(session, slot) {
                Ok(()) => cleared += 1,
                Err(error) => errors.push(format!("clearing internal breakpoint slot {slot} failed: {error:#}")),
            }
        }
        let complete = errors.is_empty();
        (
            json!({"complete": complete, "halted_after_timeout": halted, "cleared_slots": cleared,
                "errors": errors, "notes": notes,
                "target_state": if complete { "halted" } else { "uncertain" }}),
            complete,
        )
    }

    /// Bounded read that refuses ranges outside known readable maps.
    fn trace_read(&mut self, pid: u32, maps: &[MapEntry], address: u64, length: usize) -> Result<Option<Vec<u8>>> {
        if length == 0 || !covered(maps, address, length as u64, 1) {
            return Ok(None);
        }
        let chunk = self.profile.limit("memory_bytes").clamp(4096, 1024 * 1024);
        let mut content = Vec::with_capacity(length);
        let mut position = address;
        while content.len() < length {
            let ask = (length - content.len()).min(chunk);
            content.extend(self.read_memory(pid, position, ask, false)?);
            position = position.wrapping_add(ask as u64);
        }
        for record in self.breakpoints.values().filter(|record| record.enabled) {
            if let Some(original) = record.original
                && record.address >= address
                && ((record.address - address) as usize) < content.len()
            {
                content[(record.address - address) as usize] = original;
            }
        }
        Ok(Some(content))
    }

    /// Visit executable `r-x` segments of `module` in overlapping windows.
    fn trace_scan_module(
        &mut self,
        pid: u32,
        maps: &[MapEntry],
        module: &str,
        limit: usize,
        mut visit: impl FnMut(&[u8], u64),
    ) -> Result<(usize, bool)> {
        const OVERLAP: usize = 16;
        let segments: Vec<(u64, u64)> = maps
            .iter()
            .filter(|entry| entry.name == module && entry.protection & 5 == 5)
            .map(|entry| (entry.start, entry.end))
            .collect();
        let window = self.profile.limit("memory_bytes").clamp(4096, 1024 * 1024);
        let mut scanned = 0usize;
        for (start, end) in segments {
            let mut position = start;
            let mut carry: Vec<u8> = Vec::new();
            while position < end {
                if scanned >= limit {
                    return Ok((scanned, true));
                }
                let length = ((end - position) as usize).min(window).min(limit - scanned);
                let Some(bytes) = self.trace_read(pid, maps, position, length)? else { break };
                scanned += bytes.len();
                let mut buffer = std::mem::take(&mut carry);
                let buffer_start = position - buffer.len() as u64;
                buffer.extend_from_slice(&bytes);
                visit(&buffer, buffer_start);
                carry = buffer[buffer.len().saturating_sub(OVERLAP)..].to_vec();
                position += length as u64;
            }
        }
        Ok((scanned, false))
    }

    /// C string at `address` if it is readable and printable (bounded).
    fn trace_string(&mut self, session: &Session, address: u64, limit: usize) -> Result<Option<String>> {
        let available = session
            .maps
            .iter()
            .find(|entry| entry.protection & 1 != 0 && entry.start <= address && address < entry.end)
            .map(|entry| entry.end - address);
        let Some(available) = available else { return Ok(None) };
        let length = (limit as u64).min(available).min(4096 - (address & 0xfff)) as usize;
        let Some(bytes) = self.trace_read(session.pid, &session.maps, address, length)? else {
            return Ok(None);
        };
        let text: Vec<u8> = bytes.iter().copied().take_while(|byte| *byte != 0).collect();
        let printable = text.len() >= 2 && text.iter().all(|byte| (0x20..0x7f).contains(byte) || matches!(byte, b'\t' | b'\n' | b'\r'));
        Ok(printable.then(|| {
            let mut value = String::from_utf8_lossy(&text).into_owned();
            if text.len() == bytes.len() {
                value.push('…');
            }
            value
        }))
    }

    // ---- planning ----------------------------------------------------------

    /// Resolve the PLT imports of `module` (default `eboot.bin`) and choose one
    /// probe per selected import. Returns the probes and a plan description.
    pub fn plan_imports(
        &mut self,
        module: Option<&str>,
        elf_file: Option<&[u8]>,
        filter: Option<&regex::Regex>,
        probe_at: &str,
        scan_limit: usize,
    ) -> Result<(Vec<TraceProbe>, Value)> {
        ensure!(matches!(probe_at, "plt" | "target"), "probe_at must be plt or target");
        let pid = self.trace_pid()?;
        let (maps, modules) = self.trace_layout(pid)?;
        let (name, base, end) = pick_module(&modules, module.unwrap_or("eboot.bin"))?;
        let mut notes = Vec::new();
        let (source, mut imports) = match elf_file {
            Some(file) => {
                let (_, imports, parsed_notes) = tracekit::imports_from_elf_file(file)?;
                notes.extend(parsed_notes);
                ("elf_artifact", imports)
            }
            None => ("live_memory", self.live_imports(pid, &maps, base, end, &mut notes)?),
        };
        let named = !imports.is_empty();
        if named && let Some(filter) = filter {
            imports.retain(|import| {
                filter.is_match(&import.display())
                    || filter.is_match(&import.symbol)
                    || import.library.as_deref().is_some_and(|library| filter.is_match(library))
            });
        }
        let wanted: BTreeSet<u64> = imports.iter().map(|import| base.wrapping_add(import.got_rva)).collect();
        let mut stubs: BTreeMap<u64, tracekit::PltStub> = BTreeMap::new();
        let mut unnamed: BTreeMap<u64, tracekit::PltStub> = BTreeMap::new();
        let need_scan = probe_at == "plt" || !named;
        let (scanned, truncated) = if need_scan {
            self.trace_scan_module(pid, &maps, &name, scan_limit, |code, address| {
                for stub in tracekit::find_plt_stubs(code, address) {
                    if wanted.contains(&stub.got) {
                        stubs.entry(stub.got).or_insert(stub);
                    } else if !named && stub.lazy_index.is_some() && base <= stub.got && stub.got < end {
                        unnamed.entry(stub.got).or_insert(stub);
                    }
                }
            })?
        } else {
            (0, false)
        };
        if truncated {
            notes.push(format!("PLT scan stopped at the {scan_limit}-byte scan limit"));
        }
        if !named {
            notes.push(
                "No import table was readable; falling back to unnamed lazy PLT stubs (FF 25 .. 68 .. E9). \
                 Pass elf_artifact (a decrypted ELF of this module) to get symbol names"
                    .to_owned(),
            );
            for (got, stub) in &unnamed {
                imports.push(tracekit::ImportEntry {
                    index: stub.lazy_index.unwrap_or(0) as usize,
                    got_rva: got.wrapping_sub(base),
                    symbol: format!("plt_{}", stub.lazy_index.unwrap_or(0)),
                    nid: None,
                    library: None,
                    name: None,
                });
                stubs.insert(*got, *stub);
            }
        }
        // GOT values (bound targets) for reporting and `probe_at: target`.
        let mut probes: Vec<TraceProbe> = Vec::new();
        let mut listing = Vec::new();
        let mut skipped = Vec::new();
        for import in &imports {
            let got = base.wrapping_add(import.got_rva);
            let target = self.trace_read(pid, &maps, got, 8)?.map(|bytes| qword(&bytes, 0));
            let bound = target.is_some_and(|value| value < base || value >= end);
            let stub = stubs.get(&got).map(|stub| stub.address);
            let target_location = target.and_then(|value| Self::annotate(value, &modules));
            let mut label = import.display();
            if !named && let Some(location) = &target_location {
                label = format!("{label}->{location}");
            }
            if !named && let Some(filter) = filter
                && !filter.is_match(&label)
            {
                continue;
            }
            let executable = |address: u64| covered(&maps, address, 1, 4);
            let choice = match probe_at {
                "target" => target.filter(|value| executable(*value)).map(|value| (value, "target")).or(stub.map(|s| (s, "plt"))),
                _ => stub.map(|s| (s, "plt")).or(target.filter(|value| bound && executable(*value)).map(|value| (value, "target"))),
            };
            let entry = json!({"name": label, "symbol": import.symbol, "nid": import.nid, "library": import.library,
                "got": hex(got), "got_value": hex_opt(target), "bound": bound, "target_location": target_location,
                "plt_stub": hex_opt(stub), "probe": choice.map(|(address, kind)| json!({"address": hex(address), "kind": kind}))});
            if listing.len() < 256 {
                listing.push(entry.clone());
            }
            let Some((address, kind)) = choice else {
                skipped.push(json!({"name": label, "reason": "no PLT stub found and GOT value not an executable bound target"}));
                continue;
            };
            let detail = json!({"symbol": label, "raw_symbol": import.symbol, "library": import.library,
                "nid": import.nid, "got": hex(got), "probe_kind": kind});
            match probes.iter_mut().find(|probe| probe.address == address) {
                Some(existing) => existing.label = format!("{}|{label}", existing.label),
                None => probes.push(TraceProbe { address, label, kind: ProbeKind::Call, detail }),
            }
        }
        let plan = json!({"module": name, "base": hex(base), "end": hex(end), "source": source,
            "named": named, "selected_imports": listing.len().max(probes.len()), "probe_count": probes.len(),
            "probe_at": probe_at, "scanned_bytes": scanned, "imports": listing, "skipped": skipped, "notes": notes,
            "filter": filter.map(regex::Regex::as_str)});
        Ok((probes, plan))
    }

    /// Imports from the module's in-memory ELF header, `PT_DYNAMIC` and (when it is
    /// mapped) `PT_SCE_DYNLIBDATA`. Missing pieces become notes, not errors.
    fn live_imports(
        &mut self,
        pid: u32,
        maps: &[MapEntry],
        base: u64,
        end: u64,
        notes: &mut Vec<String>,
    ) -> Result<Vec<tracekit::ImportEntry>> {
        let header_length = (end - base).min(4096) as usize;
        let Some(header) = self.trace_read(pid, maps, base, header_length)? else {
            notes.push("Module base is not readable".into());
            return Ok(Vec::new());
        };
        let Some(segments) = tracekit::program_headers(&header) else {
            notes.push("No ELF64 header with program headers at the module base".into());
            return Ok(Vec::new());
        };
        let static_base = tracekit::image_base(&segments);
        let runtime = |vaddr: u64| base.wrapping_add(vaddr.wrapping_sub(static_base));
        let inside = |address: u64, length: u64| address >= base && address.saturating_add(length) <= end;
        let Some(dynamic) = segments.iter().find(|segment| segment.p_type == tracekit::PT_DYNAMIC) else {
            notes.push("No PT_DYNAMIC program header".into());
            return Ok(Vec::new());
        };
        let dynamic_length = dynamic.filesz.max(dynamic.memsz).min(16 * 1024);
        let dynamic_bytes = if inside(runtime(dynamic.vaddr), dynamic_length) {
            self.trace_read(pid, maps, runtime(dynamic.vaddr), dynamic_length as usize)?
        } else {
            None
        };
        let Some(dynamic_bytes) = dynamic_bytes else {
            notes.push("PT_DYNAMIC is not mapped in process memory".into());
            return Ok(Vec::new());
        };
        let dynlib = match segments.iter().find(|segment| segment.p_type == tracekit::PT_SCE_DYNLIBDATA) {
            Some(segment) if inside(runtime(segment.vaddr), segment.filesz) && segment.filesz > 0 => {
                self.trace_read(pid, maps, runtime(segment.vaddr), segment.filesz.min(8 * 1024 * 1024) as usize)?
            }
            Some(_) => {
                notes.push(
                    "PT_SCE_DYNLIBDATA is not mapped in process memory (the Orbis loader keeps it kernel-side); \
                     pass elf_artifact for names"
                        .into(),
                );
                None
            }
            None => None,
        };
        let entries = tracekit::dynamic_entries(&dynamic_bytes);
        let mut failure = None;
        let (imports, parsed_notes) = tracekit::imports_from_dynamic(&entries, static_base, |space, value, length| {
            if failure.is_some() {
                return None;
            }
            match space {
                tracekit::TableSpace::DynlibData => {
                    let data = dynlib.as_ref()?;
                    let start = value as usize;
                    data.get(start..start.checked_add(length)?.min(data.len())).map(<[u8]>::to_vec)
                }
                tracekit::TableSpace::Vaddr => {
                    let address = runtime(value);
                    if !inside(address, length as u64) {
                        return None;
                    }
                    match self.trace_read(pid, maps, address, length) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            failure = Some(error);
                            None
                        }
                    }
                }
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        notes.extend(parsed_notes);
        Ok(imports)
    }

    /// Recognised syscall wrappers in `libkernel*` modules (or `module` substring).
    pub fn plan_syscalls(
        &mut self,
        module: Option<&str>,
        numbers: &[u64],
        names: &[String],
        user: Option<&HashMap<u64, String>>,
        include_unrecognized: bool,
        scan_limit: usize,
    ) -> Result<(Vec<TraceProbe>, Value)> {
        let pid = self.trace_pid()?;
        let (maps, modules) = self.trace_layout(pid)?;
        let needle = module.unwrap_or("libkernel").to_ascii_lowercase();
        let targets: Modules = modules
            .iter()
            .filter(|(name, _, _)| name.to_ascii_lowercase().contains(&needle))
            .cloned()
            .collect();
        ensure!(!targets.is_empty(), "No loaded module matches '{needle}'");
        let mut sites: BTreeMap<u64, (tracekit::SyscallSite, String)> = BTreeMap::new();
        let mut scanned_total = 0usize;
        let mut notes = Vec::new();
        for (name, _, _) in &targets {
            let budget = scan_limit.saturating_sub(scanned_total);
            if budget == 0 {
                notes.push(format!("Scan limit reached before {name}"));
                continue;
            }
            let (scanned, truncated) = self.trace_scan_module(pid, &maps, name, budget, |code, address| {
                for site in tracekit::find_syscall_sites(code, address, include_unrecognized) {
                    sites.entry(site.probe).or_insert((site, name.clone()));
                }
            })?;
            scanned_total += scanned;
            if truncated {
                notes.push(format!("Scan of {name} stopped at the scan limit"));
            }
        }
        let lowered: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();
        let filtered = !numbers.is_empty() || !lowered.is_empty();
        let mut probes = Vec::new();
        let mut numbers_seen: BTreeMap<String, usize> = BTreeMap::new();
        for (site, module_name) in sites.values() {
            let name = site.number.map(|number| tracekit::syscall_name(number, user));
            if filtered {
                let Some(number) = site.number else { continue };
                let by_number = numbers.contains(&number);
                let by_name = name.as_ref().is_some_and(|name| {
                    let name = name.to_ascii_lowercase();
                    lowered.iter().any(|wanted| name.contains(wanted.as_str()))
                });
                if !by_number && !by_name {
                    continue;
                }
            }
            let location = Self::annotate(site.probe, &modules);
            let label = name.clone().unwrap_or_else(|| format!("syscall@{}", location.clone().unwrap_or_else(|| hex(site.probe))));
            *numbers_seen.entry(label.clone()).or_default() += 1;
            let kind = match site.number {
                Some(number) => ProbeKind::SyscallWrapper { number, rcx_is_arg4: site.moves_rcx_to_r10, entry_like: site.entry_like },
                None => ProbeKind::SyscallInstruction,
            };
            probes.push(TraceProbe {
                address: site.probe,
                label,
                kind,
                detail: json!({"module": module_name, "location": location, "syscall_instruction": hex(site.syscall_instruction),
                    "number": site.number, "name": name,
                    "name_source": site.number.map(|number| tracekit::syscall_name_source(number, user)),
                    "entry_like": site.entry_like}),
            });
        }
        let listing: Vec<Value> = probes
            .iter()
            .take(256)
            .map(|probe| json!({"label": probe.label, "address": hex(probe.address), "detail": probe.detail}))
            .collect();
        let plan = json!({"modules": targets.iter().map(|(name, base, _)| json!({"name": name, "base": hex(*base)})).collect::<Vec<_>>(),
            "sites_found": sites.len(), "probe_count": probes.len(), "scanned_bytes": scanned_total,
            "per_name": numbers_seen, "probes": listing, "notes": notes,
            "name_sources": "FreeBSD 9 syscalls.master natives; Orbis dynlib_* 589-595 (public payload SDKs / psdevwiki); user dictionary overrides"});
        Ok((probes, plan))
    }

    /// Resolve function targets: `0x..` addresses, `module+0xoff`, or label names.
    pub fn plan_functions(&mut self, targets: &[String]) -> Result<(Vec<TraceProbe>, Value)> {
        ensure!(!targets.is_empty(), "Provide at least one target");
        let pid = self.trace_pid()?;
        let (maps, modules) = self.trace_layout(pid)?;
        let mut probes: Vec<TraceProbe> = Vec::new();
        for target in targets {
            let address = if let Some(address) = tracekit::parse_number(target) {
                address
            } else if let Some((module, offset)) = target.rsplit_once('+')
                && let Some(offset) = tracekit::parse_number(offset)
            {
                let (_, base, end) = pick_module(&modules, module.trim())?;
                ensure!(offset < end - base, "{target}: offset outside module");
                base + offset
            } else if let Some(address) = self.labels.get(target.as_str()) {
                *address
            } else {
                bail!("Cannot resolve target '{target}' (use 0x address, module+0xoffset or a debug_label name)");
            };
            ensure!(covered(&maps, address, 1, 4), "{target} ({address:#x}) is not in an executable mapping");
            if probes.iter().any(|probe| probe.address == address) {
                continue;
            }
            probes.push(TraceProbe {
                address,
                label: target.clone(),
                kind: ProbeKind::Call,
                detail: json!({"target": target, "location": Self::annotate(address, &modules)}),
            });
        }
        let plan = json!({"probe_count": probes.len(), "probes": probes.iter().map(|probe|
            json!({"label": probe.label, "address": hex(probe.address), "detail": probe.detail})).collect::<Vec<_>>()});
        Ok((probes, plan))
    }

    // ---- tracing loop ---------------------------------------------------------

    /// Arm every probe, resume, record hits until `max_events`, the timeout or a
    /// foreign stop; then halt if needed and clear all internal breakpoints.
    pub fn trace_probes(&mut self, probes: &[TraceProbe], options: &TraceOptions) -> Result<TraceReport> {
        ensure!(!probes.is_empty(), "Nothing to trace: no probes selected");
        ensure!((1..=MAX_TRACE_EVENTS).contains(&options.max_events), "max_events must be 1-{MAX_TRACE_EVENTS}");
        ensure!(options.timeout.as_secs() <= MAX_TRACE_SECONDS, "timeout exceeds {MAX_TRACE_SECONDS} s");
        let mut session = self.trace_open()?;
        let budget = self.trace_budget(options.max_breakpoints);
        ensure!(
            probes.len() <= budget as usize,
            "{} probes selected but only {budget} breakpoint slots are available (user breakpoints are kept; \
             at most {MAX_INTERNAL_SLOTS} internal); narrow the filter/targets. First: {}",
            probes.len(),
            probes.iter().take(40).map(|probe| probe.label.as_str()).collect::<Vec<_>>().join(", ")
        );
        let outcome = self.trace_probes_inner(&mut session, probes, options, budget);
        let (cleanup, complete) = self.trace_close(&mut session);
        match outcome {
            Ok((events, mut summary)) => {
                summary["cleanup"] = cleanup.clone();
                Ok(TraceReport { events, summary, cleanup, cleanup_complete: complete })
            }
            Err(error) => Err(error.context(format!("Trace aborted; cleanup report: {cleanup}"))),
        }
    }

    fn trace_probes_inner(
        &mut self,
        session: &mut Session,
        probes: &[TraceProbe],
        options: &TraceOptions,
        budget: u32,
    ) -> Result<(Vec<Value>, Value)> {
        let pid = session.pid;
        let mut codes = Vec::with_capacity(probes.len());
        for probe in probes {
            codes.push(self.read_code(pid, probe.address, 16)?);
        }
        let mut armed = Vec::new();
        let mut skipped = Vec::new();
        for (index, probe) in probes.iter().enumerate() {
            match self.trace_arm(session, probe.address, Role::Probe(index))? {
                Some(slot) => armed.push(json!({"label": probe.label, "address": hex(probe.address), "slot": slot})),
                None => skipped.push(json!({"label": probe.label, "address": hex(probe.address),
                    "reason": "address already has a breakpoint or no free slot"})),
            }
        }
        ensure!(!armed.is_empty(), "No probe could be armed: {skipped:?}");
        let deadline = session.started + options.timeout;
        let max_stops = options.max_events.saturating_mul(4).max(1000);
        let mut events: Vec<Value> = Vec::new();
        let mut hits = vec![0u64; probes.len()];
        let mut pending: Vec<Pending> = Vec::new();
        let mut return_code: HashMap<u64, Vec<u8>> = HashMap::new();
        let (mut stops, mut filtered, mut unmatched_returns, mut returns_skipped) = (0usize, 0usize, 0usize, 0usize);
        let mut foreign = Value::Null;
        self.trace_resume(session)?;
        let stop_reason = loop {
            let Some(event) = self.trace_next(session, deadline)? else { break "timeout" };
            stops += 1;
            let thread = event["thread_id"].as_u64().unwrap_or(0) as u32;
            let status = event["status"].as_u64().unwrap_or(0);
            let rip = event["registers"]["rip"].as_str().and_then(tracekit::parse_number).unwrap_or(0);
            let trap = status & 0xff != 0x7f || (status >> 8) & 0xff == SIGTRAP;
            let hit = if trap { session.slot_at(rip) } else { None };
            match hit {
                None => {
                    foreign = json!({"thread_id": thread, "status": status, "rip": hex(rip), "name": event["name"]});
                    session.queue.push_front(event);
                    break "foreign_stop";
                }
                Some((slot, address, Role::Return)) => {
                    let live = self.get_registers_raw(thread)?;
                    let code = return_code.get(&address).cloned().unwrap_or_default();
                    let view = HitView::new(&code, address, live, &event, false);
                    let (rsp_now, _) = view.rsp();
                    let (rax, rax_source) = view.get("rax");
                    let position = pending
                        .iter()
                        .position(|p| p.slot == slot && p.thread == thread && p.expected_rsp.is_some() && p.expected_rsp == rsp_now)
                        .map(|index| (index, "thread_and_rsp"))
                        .or_else(|| {
                            pending.iter().rposition(|p| p.slot == slot && p.thread == thread).map(|index| (index, "thread_only"))
                        });
                    match position {
                        Some((index, matched_by)) => {
                            let entry = pending.remove(index);
                            events[entry.event]["return"] = json!({"rax": hex_opt(rax), "rax_source": rax_source,
                                "host_elapsed_ms": entry.at.elapsed().as_secs_f64() * 1000.0,
                                "t_ms": session.elapsed_ms(), "matched_by": matched_by});
                        }
                        None => unmatched_returns += 1,
                    }
                    if !pending.iter().any(|p| p.slot == slot) {
                        self.trace_disarm(session, slot)?;
                    }
                }
                Some((_, _, Role::Block(_))) => unreachable!("trace sessions arm no coverage blocks"),
                Some((_, _, Role::Probe(index))) => {
                    if options.thread_id.is_some_and(|wanted| wanted != thread) {
                        filtered += 1;
                    } else {
                        hits[index] += 1;
                        let probe = &probes[index];
                        let record = self.trace_hit(session, probe, &codes[index], &event, thread, options, events.len())?;
                        events.push(record);
                        let returns_here = matches!(
                            probe.kind,
                            ProbeKind::Call | ProbeKind::SyscallWrapper { entry_like: true, .. }
                        );
                        let caller = events.last().and_then(|event| event["caller"]["address"].as_str()).and_then(tracekit::parse_number);
                        if options.capture_returns && returns_here && let Some(caller) = caller {
                            let rsp = events.last().and_then(|event| event["rsp_at_entry"].as_str()).and_then(tracekit::parse_number);
                            let existing = session
                                .slots
                                .iter()
                                .find(|(_, (address, role))| *address == caller && *role == Role::Return)
                                .map(|(slot, _)| *slot);
                            let slot = match existing {
                                Some(slot) => Some(slot),
                                None if (session.slots.len() as u32) < budget => {
                                    if let std::collections::hash_map::Entry::Vacant(entry) = return_code.entry(caller) {
                                        entry.insert(self.read_code(pid, caller, 16)?);
                                    }
                                    self.trace_arm(session, caller, Role::Return)?
                                }
                                None => None,
                            };
                            match slot {
                                Some(slot) => pending.push(Pending {
                                    slot,
                                    thread,
                                    expected_rsp: rsp.map(|rsp| rsp.wrapping_add(8)),
                                    event: events.len() - 1,
                                    at: Instant::now(),
                                }),
                                None => {
                                    returns_skipped += 1;
                                    if let Some(last) = events.last_mut() {
                                        last["return"] = json!({"captured": false,
                                            "reason": "no free breakpoint slot, or the return address already has a breakpoint"});
                                    }
                                }
                            }
                        }
                        if events.len() >= options.max_events {
                            break "max_events";
                        }
                    }
                }
            }
            if stops >= max_stops {
                break "max_stops";
            }
            if session.queue.is_empty() {
                self.trace_resume(session)?;
            }
        };
        for entry in &pending {
            if let Some(event) = events.get_mut(entry.event) {
                event["return"] = json!({"captured": false, "reason": "trace ended before the call returned"});
            }
        }
        let per_probe: Vec<Value> = probes
            .iter()
            .zip(&hits)
            .map(|(probe, hits)| json!({"label": probe.label, "address": hex(probe.address), "hits": hits}))
            .collect();
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for (probe, hits) in probes.iter().zip(&hits) {
            *counts.entry(probe.label.clone()).or_default() += hits;
        }
        let summary = json!({
            "stop_reason": stop_reason, "events": events.len(), "stops": stops, "elapsed_ms": session.elapsed_ms(),
            "counts": counts, "per_probe": per_probe, "armed": armed, "skipped": skipped, "budget": budget,
            "filtered_other_threads": filtered, "unmatched_return_hits": unmatched_returns,
            "returns_not_captured_for_lack_of_slots": returns_skipped, "foreign_stop": foreign,
            "note": "All-stop model: each hit halts every thread; durations are host-observed and include debugger round trips. \
                     Registers written by the probed instruction come from the event snapshot (register source per argument).",
        });
        Ok((events, summary))
    }

    #[allow(clippy::too_many_arguments)]
    fn trace_hit(
        &mut self,
        session: &Session,
        probe: &TraceProbe,
        code: &[u8],
        event: &Value,
        thread: u32,
        options: &TraceOptions,
        sequence: usize,
    ) -> Result<Value> {
        let pid = session.pid;
        let live = self.get_registers_raw(thread)?;
        let event_only = probe.kind == ProbeKind::SyscallInstruction;
        let view = HitView::new(code, probe.address, live, event, event_only);
        let names = match probe.kind {
            ProbeKind::Call => CALL_ARGS,
            _ => SYSCALL_ARGS,
        };
        let mut args = Vec::new();
        for name in names.iter().take(options.arg_count) {
            let (value, source) = match probe.kind {
                ProbeKind::SyscallWrapper { rcx_is_arg4: true, .. } if *name == "r10" => {
                    let (value, source) = view.get("rcx");
                    (value, if source == "live" { "live_rcx_before_mov_r10" } else { source })
                }
                _ => view.get(name),
            };
            let mut arg = json!({"register": name, "value": hex_opt(value), "source": source});
            if options.string_bytes > 0
                && let Some(value) = value
                && let Some(text) = self.trace_string(session, value, options.string_bytes)?
            {
                arg["string"] = json!(text);
            }
            args.push(arg);
        }
        let (rsp, rsp_source) = view.rsp();
        let entry_like = matches!(probe.kind, ProbeKind::Call | ProbeKind::SyscallWrapper { entry_like: true, .. });
        let mut caller = Value::Null;
        if let Some(rsp) = rsp
            && let Some(bytes) = self.trace_read(pid, &session.maps, rsp, 8)?
        {
            let address = qword(&bytes, 0);
            if session.executable(address) {
                caller = json!({"address": hex(address), "location": Self::annotate(address, &session.modules),
                    "confidence": if entry_like { "entry_return_address" } else { "stack_top_heuristic" }});
            }
        }
        let mut record = json!({
            "seq": sequence, "t_ms": session.elapsed_ms(), "time": crate::artifacts::utc_now(),
            "thread_id": thread, "probe": probe.label, "address": hex(probe.address),
            "detail": probe.detail, "args": args, "caller": caller,
            "rsp_at_entry": hex_opt(rsp), "rsp_source": rsp_source,
            "first_instruction": view.first.text, "return": Value::Null,
        });
        match probe.kind {
            ProbeKind::SyscallWrapper { number, .. } => {
                record["syscall"] = json!({"number": number,
                    "name": tracekit::syscall_name(number, options.syscall_names.as_ref()),
                    "live_rax": hex_opt(RegisterFile(&view.live).get("rax"))});
            }
            ProbeKind::SyscallInstruction => {
                let number = view.event_value("rax");
                record["syscall"] = json!({"number": number, "number_source": "event_snapshot_rax",
                    "name": number.map(|number| tracekit::syscall_name(number, options.syscall_names.as_ref())),
                    "note": "The syscall had already executed when the hit was reported; live rax holds its result"});
            }
            ProbeKind::Call => {}
        }
        if let Some(rsp) = rsp
            && let Some(end) = session.stack_end(rsp)
        {
            record["stack_bytes_in_use"] = json!(end - rsp);
        }
        if options.backtrace_frames > 0 {
            let trace = self.stack_trace(thread, options.backtrace_frames.min(64))?;
            let frames = trace["frames"].as_array().cloned().unwrap_or_default();
            record["stack_depth"] = json!(frames.len());
            record["backtrace"] = json!(frames
                .iter()
                .map(|frame| json!({"address": frame["address"], "symbol": frame["symbol"], "via": frame["via"]}))
                .collect::<Vec<_>>());
        }
        Ok(record)
    }

    // ---- coverage ---------------------------------------------------------------

    /// Choose the coverage blocks for `module`: a blocks document (RVAs rebased to
    /// the live module base) or function entries from `.eh_frame` FDEs / prologues.
    pub fn plan_coverage(
        &mut self,
        module: Option<&str>,
        blocks: Option<tracekit::BlockSet>,
        source: &str,
        max_blocks: usize,
        scan_limit: usize,
    ) -> Result<CoveragePlan> {
        ensure!(matches!(source, "auto" | "eh_frame" | "prologue"), "source must be auto, eh_frame or prologue");
        let pid = self.trace_pid()?;
        let (maps, modules) = self.trace_layout(pid)?;
        let wanted = module
            .map(str::to_owned)
            .or_else(|| blocks.as_ref().and_then(|set| set.module.clone()))
            .unwrap_or_else(|| "eboot.bin".to_owned());
        let (name, base, end) = pick_module(&modules, &wanted)?;
        let mut notes = Vec::new();
        let executable = |address: u64| address >= base && address < end && covered(&maps, address, 1, 4);
        let max_blocks = max_blocks.clamp(1, tracekit::MAX_BLOCKS);
        if let Some(set) = blocks {
            let total = set.blocks.len();
            let mut kept: Vec<(u64, u64)> =
                set.blocks.iter().copied().filter(|(rva, _)| executable(base.wrapping_add(*rva))).collect();
            let outside = total - kept.len();
            if outside > 0 {
                notes.push(format!("{outside} block(s) fall outside the module's executable mappings and were dropped"));
            }
            let truncated = kept.len().saturating_sub(max_blocks);
            kept.truncate(max_blocks);
            if truncated > 0 {
                notes.push(format!("{truncated} block(s) beyond max_blocks were dropped"));
            }
            return Ok(CoveragePlan {
                module: name,
                base,
                end,
                image_base: set.image_base,
                module_sha256: set.module_sha256,
                blocks: kept,
                granularity: set.granularity,
                source: "blocks_artifact".into(),
                dropped: outside + truncated,
                notes,
            });
        }
        let header = self.trace_read(pid, &maps, base, (end - base).min(4096) as usize)?;
        let image_base = header
            .as_deref()
            .and_then(tracekit::program_headers)
            .map(|segments| tracekit::image_base(&segments))
            .unwrap_or(0);
        let mut starts: BTreeMap<u64, u64> = BTreeMap::new();
        let mut used = "none";
        if matches!(source, "auto" | "eh_frame")
            && let Some(header) = &header
        {
            let mut lookup_failure = None;
            let maps_copy = maps.clone();
            let located = crate::ehframe::find_eh_frame_from_elf_header(header, base, end, |address, length| {
                if !covered(&maps_copy, address, length as u64, 1) {
                    bail!("eh_frame_hdr not readable");
                }
                self.read_memory(pid, address, length, false).inspect_err(|error| {
                    lookup_failure = Some(anyhow::anyhow!("{error:#}"));
                })
            });
            if let Some(error) = lookup_failure {
                return Err(error);
            }
            match located {
                Some((address, length)) => {
                    let readable = maps
                        .iter()
                        .find(|entry| entry.protection & 1 != 0 && entry.start <= address && address < entry.end)
                        .map_or(0, |entry| (entry.end - address) as usize);
                    if let Some(bytes) = self.trace_read(pid, &maps, address, length.min(readable))? {
                        for (start, size) in tracekit::fde_ranges(&bytes, address, max_blocks.saturating_mul(4)) {
                            if executable(start) {
                                starts.entry(start).or_insert(size);
                            }
                        }
                        used = "eh_frame";
                    }
                }
                None => notes.push("No PT_GNU_EH_FRAME / .eh_frame found via the in-memory ELF header".into()),
            }
        } else if header.is_none() {
            notes.push("Module header not readable; eh_frame unavailable".into());
        }
        if starts.is_empty() && matches!(source, "auto" | "prologue") {
            let mut found = Vec::new();
            let (_, truncated) = self.trace_scan_module(pid, &maps, &name, scan_limit, |code, address| {
                found.extend(tracekit::prologue_entries(code, address, tracekit::MAX_BLOCKS));
            })?;
            if truncated {
                notes.push("Prologue scan stopped at the scan limit".into());
            }
            for start in found {
                starts.entry(start).or_insert(1);
            }
            used = "prologue_heuristic";
        }
        ensure!(!starts.is_empty(), "No coverage blocks could be derived for {name}: {notes:?}");
        let total = starts.len();
        let blocks: Vec<(u64, u64)> = starts.into_iter().take(max_blocks).map(|(start, size)| (start - base, size)).collect();
        if total > blocks.len() {
            notes.push(format!("{} function(s) beyond max_blocks were dropped", total - blocks.len()));
        }
        Ok(CoveragePlan {
            module: name,
            base,
            end,
            image_base,
            module_sha256: None,
            dropped: total - blocks.len(),
            blocks,
            granularity: "function_entry",
            source: used.into(),
            notes,
        })
    }

    /// One-shot coverage over `addresses` with rotating batches of at most
    /// `max_breakpoints` armed slots: every hit disarms its slot and arms the next
    /// unarmed block. Stops at timeout, `max_hits`, a foreign stop, or when every
    /// block has been hit or attempted.
    pub fn coverage_blocks(
        &mut self,
        addresses: &[u64],
        timeout: Duration,
        max_breakpoints: u32,
        max_hits: usize,
    ) -> Result<CoverageRun> {
        ensure!(!addresses.is_empty(), "No blocks to cover");
        ensure!(timeout.as_secs() <= MAX_TRACE_SECONDS, "timeout exceeds {MAX_TRACE_SECONDS} s");
        let mut session = self.trace_open()?;
        let budget = self.trace_budget(max_breakpoints);
        ensure!(budget > 0, "No free breakpoint slots");
        let mut run = CoverageRun {
            hits: vec![0; addresses.len()],
            first_hit_ms: vec![None; addresses.len()],
            never_armed: Vec::new(),
            stop_reason: String::new(),
            stops: 0,
            foreign_stop: None,
            cleanup: Value::Null,
            cleanup_complete: false,
        };
        let outcome = self.coverage_inner(&mut session, addresses, timeout, budget, max_hits.max(1), &mut run);
        let (cleanup, complete) = self.trace_close(&mut session);
        run.cleanup = cleanup.clone();
        run.cleanup_complete = complete;
        match outcome {
            Ok(()) => Ok(run),
            Err(error) => Err(error.context(format!(
                "Coverage aborted after {} hit(s); cleanup report: {cleanup}",
                run.hits.iter().sum::<u64>()
            ))),
        }
    }

    fn coverage_inner(
        &mut self,
        session: &mut Session,
        addresses: &[u64],
        timeout: Duration,
        budget: u32,
        max_hits: usize,
        run: &mut CoverageRun,
    ) -> Result<()> {
        let mut next = 0usize;
        let deadline = session.started + timeout;
        let fill = |debugger: &mut Self, session: &mut Session, next: &mut usize, run: &mut CoverageRun| -> Result<()> {
            while (session.slots.len() as u32) < budget && *next < addresses.len() {
                if debugger.trace_arm(session, addresses[*next], Role::Block(*next))?.is_none() {
                    run.never_armed.push(*next);
                }
                *next += 1;
            }
            Ok(())
        };
        fill(self, session, &mut next, run)?;
        if session.slots.is_empty() {
            run.stop_reason = "nothing_armed".into();
            return Ok(());
        }
        let mut total_hits = 0usize;
        self.trace_resume(session)?;
        loop {
            let Some(event) = self.trace_next(session, deadline)? else {
                run.stop_reason = "timeout".into();
                return Ok(());
            };
            run.stops += 1;
            let status = event["status"].as_u64().unwrap_or(0);
            let rip = event["registers"]["rip"].as_str().and_then(tracekit::parse_number).unwrap_or(0);
            let trap = status & 0xff != 0x7f || (status >> 8) & 0xff == SIGTRAP;
            match session.slot_at(rip).filter(|_| trap) {
                Some((slot, _, Role::Block(index))) => {
                    run.hits[index] = 1;
                    run.first_hit_ms[index] = Some(session.elapsed_ms());
                    total_hits += 1;
                    self.trace_disarm(session, slot)?;
                    fill(self, session, &mut next, run)?;
                }
                _ => {
                    run.foreign_stop = Some(json!({"thread_id": event["thread_id"], "status": status, "rip": hex(rip)}));
                    session.queue.push_front(event);
                    run.stop_reason = "foreign_stop".into();
                    return Ok(());
                }
            }
            if session.slots.is_empty() && next >= addresses.len() {
                run.stop_reason = "all_blocks_attempted".into();
                return Ok(());
            }
            if total_hits >= max_hits {
                run.stop_reason = "max_hits".into();
                return Ok(());
            }
            if session.queue.is_empty() {
                self.trace_resume(session)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake::{self, Fixture, FixtureStep};

    const BASE: u64 = 0x40_0000;
    const KERNEL: u64 = 0x80_0000;

    fn step(rip: u64, registers: &[(&str, u64)]) -> FixtureStep {
        FixtureStep {
            rip,
            registers: registers.iter().map(|(name, value)| ((*name).to_owned(), *value)).collect(),
            ..Default::default()
        }
    }

    fn attach(fixture: Fixture) -> (tempfile::TempDir, Debugger) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pid = fixture.pid;
        let fake = fake::spawn_fixture(listener, fixture);
        let directory = tempfile::tempdir().unwrap();
        let mut debugger = Debugger::new(fake::qualified_profile(directory.path(), fake.port));
        debugger.attach(pid, "127.0.0.1").unwrap();
        debugger.wait_stop(Duration::from_secs(2)).unwrap().expect("attach stop");
        (directory, debugger)
    }

    fn options(seconds: u64) -> TraceOptions {
        TraceOptions { timeout: Duration::from_secs(seconds), ..Default::default() }
    }

    /// Function at BASE+0x20 (`mov eax, 1`, does not touch args or rsp) called
    /// from BASE+0x5; the return site BASE+0x5 is a `nop`.
    #[test]
    fn function_trace_records_args_caller_and_return_then_cleans_up() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let mut image = vec![0x90u8; 0x100];
        image[0x20..0x25].copy_from_slice(&[0xb8, 1, 0, 0, 0]);
        let rsp = fake::FAKE_STACK + 0x100;
        let program = vec![
            step(BASE, &[("rsp", rsp + 8)]),
            step(BASE + 0x20, &[("rdi", 0x11), ("rsi", BASE + 0x80), ("rsp", rsp)]),
            step(BASE + 0x5, &[("rax", 0x99), ("rsp", rsp + 8)]),
        ];
        let mut text = b"hello".to_vec();
        text.push(0);
        let fixture = Fixture {
            pid: 71, thread_id: 72, base: BASE, image, rip: BASE, program,
            extra_memory: vec![(rsp, (BASE + 0x5).to_le_bytes().to_vec()), (BASE + 0x80, text)],
            ..Default::default()
        };
        let (_directory, mut debugger) = attach(fixture);
        let (probes, plan) = debugger.plan_functions(&["fixture.elf+0x20".to_owned()]).unwrap();
        assert_eq!(plan["probe_count"], 1);
        let report = debugger
            .trace_probes(&probes, &TraceOptions { capture_returns: true, string_bytes: 32, ..options(2) })
            .unwrap();
        assert_eq!(report.events.len(), 1, "{:?}", report.summary);
        let event = &report.events[0];
        assert_eq!(event["args"][0]["value"], "0x11");
        assert_eq!(event["args"][0]["source"], "live");
        assert_eq!(event["args"][1]["string"], "hello");
        assert_eq!(event["caller"]["location"], "fixture.elf+0x5");
        assert_eq!(event["rsp_at_entry"], hex(rsp));
        assert_eq!(event["return"]["rax"], "0x99");
        assert_eq!(event["return"]["matched_by"], "thread_and_rsp");
        assert_eq!(report.summary["stop_reason"], "timeout");
        assert!(report.cleanup_complete, "{}", report.cleanup);
        assert_eq!(report.cleanup["halted_after_timeout"], true);
        assert!(debugger.breakpoints.is_empty(), "internal breakpoints must be cleared");
        debugger.detach().unwrap();
    }

    /// Orbis-shaped in-memory ELF: PT_DYNAMIC + mapped PT_SCE_DYNLIBDATA, one
    /// JUMP_SLOT import (sceKernelUsleep) through a lazy PLT stub at BASE+0x100.
    fn import_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x800];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&3u16.to_le_bytes());
        let phdr = |image: &mut Vec<u8>, index: usize, p_type: u32, vaddr: u64, size: u64| {
            let at = 64 + index * 56;
            image[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
            image[at + 40..at + 48].copy_from_slice(&size.to_le_bytes());
        };
        phdr(&mut image, 0, tracekit::PT_LOAD, 0, 0x800);
        phdr(&mut image, 1, tracekit::PT_DYNAMIC, 0x200, 0x70);
        phdr(&mut image, 2, tracekit::PT_SCE_DYNLIBDATA, 0x400, 0x100);
        let tags: [(u64, u64); 6] = [
            (0x6100_0029, 0), (0x6100_002d, 24), (0x6100_0035, 0x40), (0x6100_0037, 0x20),
            (0x6100_0039, 0x80), (0x6100_003f, 48),
        ];
        for (index, (tag, value)) in tags.iter().enumerate() {
            let at = 0x200 + index * 16;
            image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        image[0x400..0x408].copy_from_slice(&0x600u64.to_le_bytes());
        image[0x408..0x410].copy_from_slice(&((1u64 << 32) | 7).to_le_bytes());
        let name = b"\x001jfXLRVzisc#A#B\0";
        image[0x440..0x440 + name.len()].copy_from_slice(name);
        image[0x480 + 24..0x480 + 28].copy_from_slice(&1u32.to_le_bytes());
        // PLT stub at 0x100: jmp [rip+0x4fa] (-> GOT 0x600); push 0; jmp ...
        image[0x100..0x110].copy_from_slice(&[0xff, 0x25, 0xfa, 0x04, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
        image[0x600..0x608].copy_from_slice(&(KERNEL + 0x40).to_le_bytes());
        image[0x700..0x706].copy_from_slice(b"hello\0");
        image
    }

    #[test]
    fn import_trace_names_plt_hits_and_derefs_strings() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let rsp = fake::FAKE_STACK + 0x200;
        let program = vec![step(BASE + 0x100, &[("rdi", BASE + 0x700), ("rsp", rsp)])];
        let fixture = Fixture {
            pid: 71, thread_id: 72, base: BASE, image: import_image(), rip: BASE, program,
            extra_maps: vec![(KERNEL, KERNEL + 0x1000, 5, "libkernel.sprx".into())],
            extra_memory: vec![(rsp, (BASE + 0x50).to_le_bytes().to_vec()), (KERNEL, vec![0x90; 0x100])],
        };
        let (_directory, mut debugger) = attach(fixture);
        let filter = regex::Regex::new("(?i)usleep").unwrap();
        let (probes, plan) =
            debugger.plan_imports(Some("fixture.elf"), None, Some(&filter), "plt", DEFAULT_SCAN_LIMIT).unwrap();
        assert_eq!(plan["named"], true, "{plan}");
        assert_eq!(probes.len(), 1, "{plan}");
        assert_eq!(probes[0].address, BASE + 0x100);
        assert_eq!(plan["imports"][0]["target_location"], "libkernel.sprx+0x40");
        assert_eq!(plan["imports"][0]["bound"], true);
        let report = debugger.trace_probes(&probes, &TraceOptions { string_bytes: 32, ..options(2) }).unwrap();
        assert_eq!(report.events.len(), 1);
        let event = &report.events[0];
        assert_eq!(event["probe"], "sceKernelUsleep");
        assert_eq!(event["args"][0]["string"], "hello");
        assert_eq!(event["caller"]["location"], "fixture.elf+0x50");
        assert_eq!(report.summary["counts"]["sceKernelUsleep"], 1);
        assert!(report.cleanup_complete);
        assert!(debugger.breakpoints.is_empty());
        debugger.detach().unwrap();
    }

    #[test]
    fn syscall_trace_derives_number_and_rcx_arg4_and_stops_at_max_events() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let mut kernel = vec![0xccu8; 0x100];
        // 0x10: mov rax, 4; mov r10, rcx; syscall; ret
        kernel[0x10..0x1d].copy_from_slice(&[0x48, 0xc7, 0xc0, 4, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05, 0xc3]);
        // 0x20: mov rax, 3; mov r10, rcx; syscall; ret
        kernel[0x20..0x2d].copy_from_slice(&[0x48, 0xc7, 0xc0, 3, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05, 0xc3]);
        let rsp = fake::FAKE_STACK + 0x300;
        let program = vec![
            step(KERNEL + 0x10, &[("rdi", 1), ("rcx", 0x77), ("rsp", rsp)]),
            step(KERNEL + 0x10, &[("rdi", 2)]),
        ];
        let fixture = Fixture {
            pid: 71, thread_id: 72, base: BASE, image: vec![0x90; 0x100], rip: BASE, program,
            extra_maps: vec![(KERNEL, KERNEL + 0x1000, 5, "libkernel.sprx".into())],
            extra_memory: vec![(KERNEL, kernel), (rsp, (BASE + 0x10).to_le_bytes().to_vec())],
        };
        let (_directory, mut debugger) = attach(fixture);
        let (probes, plan) = debugger.plan_syscalls(None, &[], &["write".to_owned()], None, false, DEFAULT_SCAN_LIMIT).unwrap();
        assert_eq!(plan["sites_found"], 2, "{plan}");
        assert_eq!(probes.len(), 1);
        let report = debugger.trace_probes(&probes, &TraceOptions { max_events: 1, ..options(3) }).unwrap();
        assert_eq!(report.summary["stop_reason"], "max_events");
        let event = &report.events[0];
        assert_eq!(event["syscall"]["number"], 4);
        assert_eq!(event["syscall"]["name"], "write");
        assert_eq!(event["args"][0]["value"], "0x1");
        assert_eq!(event["args"][3]["register"], "r10");
        assert_eq!(event["args"][3]["value"], "0x77");
        assert_eq!(event["caller"]["location"], "fixture.elf+0x10");
        assert_eq!(report.cleanup["halted_after_timeout"], false);
        assert!(debugger.breakpoints.is_empty());
        debugger.detach().unwrap();
    }

    #[test]
    fn coverage_rotates_batches_through_a_small_budget() {
        let Some(_guard) = fake::callback_port_guard() else { return };
        let blocks = [BASE + 0x10, BASE + 0x20, BASE + 0x30];
        let program = vec![step(BASE + 0x10, &[]), step(BASE + 0x30, &[])];
        let fixture = Fixture { pid: 71, thread_id: 72, base: BASE, image: vec![0x90; 0x100], rip: BASE, program, ..Default::default() };
        let (_directory, mut debugger) = attach(fixture);
        // A user breakpoint must survive untouched.
        debugger.breakpoint_ex(0, BASE + 0x80, true, None, None, 0).unwrap();
        let run = debugger.coverage_blocks(&blocks, Duration::from_secs(2), 2, 100).unwrap();
        assert_eq!(run.hits, vec![1, 0, 1]);
        assert_eq!(run.stop_reason, "timeout");
        assert!(run.cleanup_complete, "{}", run.cleanup);
        assert_eq!(debugger.breakpoints.len(), 1);
        assert!(debugger.breakpoints.contains_key(&0));
        debugger.detach().unwrap();
    }

    #[test]
    fn first_instruction_effects_drive_register_sources() {
        let push = first_instruction(&[0x55], 0x1000);
        assert_eq!(push.rsp_delta, Some(8));
        let sub = first_instruction(&[0x48, 0x83, 0xec, 0x28], 0x1000);
        assert_eq!(sub.rsp_delta, Some(0x28));
        let jmp = first_instruction(&[0xff, 0x25, 0, 0, 0, 0], 0x1000);
        assert_eq!(jmp.rsp_delta, Some(0));
        let mov = first_instruction(&[0x48, 0xc7, 0xc0, 4, 0, 0, 0], 0x1000);
        assert!(mov.written.contains(&Register::RAX));
        assert!(!mov.written.contains(&Register::RDI));
    }
}
