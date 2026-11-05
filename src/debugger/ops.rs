//! Higher-level debugger operations built on the pinned ps4debug-NG command set:
//! register writes, FPU/debug-register reads, tracked breakpoints with conditions,
//! stepping, conditional run, call stacks, modules and expression evaluation.
//!
//! Hardware caveat: the pinned server steps a thread past a software breakpoint
//! before it reports the hit, so event registers can be stale. Every operation here
//! re-reads the live registers after a stop instead of trusting the event.

use super::*;
use crate::{
    disasm,
    expr::{self, Context, RegisterFile},
};
use anyhow::Context as _;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct BreakpointRecord {
    pub address: u64,
    pub enabled: bool,
    pub original: Option<u8>,
    pub condition: Option<String>,
    pub log: Option<String>,
    /// Stop only once this many hits have occurred (0/1 = every hit).
    pub stop_after: u64,
    pub hits: u64,
    pub internal: bool,
}

/// Writable architectural flag bits: CF PF AF ZF SF TF DF OF.
const FLAG_MASK: u64 = 0xcd5 | 0x100;
const WRITABLE: [&str; 18] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "rip", "rflags",
];

fn parse_hex(text: &Value) -> Option<u64> {
    u64::from_str_radix(text.as_str()?.strip_prefix("0x")?, 16).ok()
}

impl Debugger {
    fn attached(&self) -> Result<u32> {
        self.attached_pid.context("No active debugger session")
    }

    fn page_chunks(address: u64, length: usize) -> Vec<(u64, usize)> {
        let mut chunks = Vec::new();
        let (mut position, end) = (address, address as u128 + length as u128);
        while (position as u128) < end {
            let boundary = (position | 0xfff).wrapping_add(1);
            let stop = if boundary == 0 { end } else { end.min(boundary as u128) };
            chunks.push((position, (stop - position as u128) as usize));
            position = stop as u64;
        }
        chunks
    }

    pub fn get_registers_raw(&mut self, thread_id: u32) -> Result<Vec<u8>> {
        self.session()?;
        Self::pid(thread_id)?;
        self.exchange_read(|debugger| {
            debugger.packet(0xbdbb0008, &thread_id.to_le_bytes())?;
            debugger.status()?;
            debugger.read(176)
        })
    }

    /// Read-modify-write of the general-purpose block with readback verification.
    /// The pinned server applies SETREGS to its current ptrace target, not to the
    /// thread id in the request, so verification is essential, not optional.
    pub fn set_registers(&mut self, thread_id: u32, changes: &[(String, u64)]) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        ensure!(!changes.is_empty() && changes.len() <= 18, "Provide 1-18 register changes");
        let mut raw = self.get_registers_raw(thread_id)?;
        let mut expected = Vec::new();
        for (name, value) in changes {
            let name = name.to_ascii_lowercase();
            ensure!(WRITABLE.contains(&name.as_str()), "Register not writable: {name}");
            let offset = expr::offset_of(&name).context("Unknown register")?;
            let old = u64::from_le_bytes(raw[offset..offset + 8].try_into()?);
            let new = if name == "rflags" {
                (old & !FLAG_MASK) | (value & FLAG_MASK)
            } else {
                *value
            };
            raw[offset..offset + 8].copy_from_slice(&new.to_le_bytes());
            expected.push((name, offset, old, new));
        }
        self.exchange(|debugger| {
            let mut body = thread_id.to_le_bytes().to_vec();
            body.extend(176u32.to_le_bytes());
            debugger.packet(0xbdbb0009, &body)?;
            debugger.status()?;
            debugger.write(&raw)?;
            debugger.status()
        })?;
        let after = self.get_registers_raw(thread_id)?;
        let mut report = Vec::new();
        let mut verified = true;
        for (name, offset, old, new) in expected {
            let actual = u64::from_le_bytes(after[offset..offset + 8].try_into()?);
            verified &= actual == new;
            report.push(json!({"register":name,"old":format!("{old:#x}"),
                "requested":format!("{new:#x}"),"actual":format!("{actual:#x}"),"match":actual == new}));
        }
        ensure!(
            verified,
            "Register readback differs from the request ({report:?}); the server may have written another thread. State uncertain"
        );
        Ok(json!({"thread_id":thread_id,"changes":report,"verified":true}))
    }

    pub fn fpu_registers(&mut self, thread_id: u32) -> Result<Value> {
        self.session()?;
        Self::pid(thread_id)?;
        let data = self.exchange_read(|debugger| {
            debugger.packet(0xbdbb000a, &thread_id.to_le_bytes())?;
            debugger.status()?;
            debugger.read(832)
        })?;
        let word16 = |at: usize| u16::from_le_bytes(data[at..at + 2].try_into().unwrap());
        Ok(json!({
            "fcw":format!("{:#06x}",word16(0)),"fsw":format!("{:#06x}",word16(2)),
            "ftw":format!("{:#04x}",data[4]),"fop":format!("{:#06x}",word16(6)),
            "fip":format!("{:#x}",qword(&data,8)),"fdp":format!("{:#x}",qword(&data,16)),
            "mxcsr":format!("{:#010x}",word(&data,24)),
            "st":(0..8).map(|i| hex::encode(&data[32+16*i..42+16*i])).collect::<Vec<_>>(),
            "xmm":(0..16).map(|i| hex::encode(&data[160+16*i..176+16*i])).collect::<Vec<_>>(),
            "ymm_high":(0..16).map(|i| hex::encode(&data[576+16*i..592+16*i])).collect::<Vec<_>>(),
        }))
    }

    pub fn hardware_debug_registers(&mut self, thread_id: u32) -> Result<Value> {
        self.session()?;
        Self::pid(thread_id)?;
        let data = self.exchange_read(|debugger| {
            debugger.packet(0xbdbb000c, &thread_id.to_le_bytes())?;
            debugger.status()?;
            debugger.read(128)
        })?;
        let dr = |index: usize| format!("{:#x}", qword(&data, index * 8));
        Ok(json!({"dr0":dr(0),"dr1":dr(1),"dr2":dr(2),"dr3":dr(3),"dr6":dr(6),"dr7":dr(7)}))
    }

    // ---- breakpoints -------------------------------------------------------

    fn free_slot(&self) -> Result<u32> {
        (0..30)
            .rev()
            .find(|index| !self.breakpoints.contains_key(index))
            .context("All 30 breakpoint slots are in use")
    }

    /// Set or clear a tracked software breakpoint. Conditions are evaluated on the
    /// host after each stop by `run`; they never reach the console.
    pub fn breakpoint_ex(
        &mut self,
        index: u32,
        address: u64,
        enabled: bool,
        condition: Option<String>,
        log: Option<String>,
        stop_after: u64,
    ) -> Result<Value> {
        let pid = self.attached()?;
        if let Some(text) = &condition {
            expr::validate(text)?;
        }
        if let Some(text) = &log {
            ensure!(text.len() <= 256, "Log template too long");
        }
        let original = if enabled {
            ensure!(
                !self.breakpoints.iter().any(|(slot, record)| *slot != index && record.enabled && record.address == address),
                "Another breakpoint already uses this address"
            );
            Some(self.read_memory(pid, address, 1, false)?[0])
        } else {
            None
        };
        let result = self.breakpoint(index, address, enabled)?;
        if enabled {
            self.breakpoints.insert(
                index,
                BreakpointRecord {
                    address,
                    enabled,
                    original,
                    condition,
                    log,
                    stop_after,
                    hits: 0,
                    internal: false,
                },
            );
        } else {
            self.breakpoints.remove(&index);
        }
        Ok(result)
    }

    pub fn breakpoint_list(&self) -> Value {
        json!(
            self.breakpoints
                .iter()
                .filter(|(_, record)| !record.internal)
                .map(|(index, record)| json!({"index":index,"address":format!("{:#x}",record.address),
                    "enabled":record.enabled,"condition":record.condition,"log":record.log,
                    "stop_after":record.stop_after,"hits":record.hits}))
                .collect::<Vec<_>>()
        )
    }

    // ---- code, modules, evaluation ----------------------------------------

    pub fn module_list(&mut self, pid: u32) -> Result<Value> {
        let maps = self.maps(pid)?;
        let mut modules: Vec<(String, u64, u64, Vec<Value>)> = Vec::new();
        for entry in maps.as_array().context("Expected maps")? {
            let name = entry["name"].as_str().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let (start, end) = (entry["start"].as_u64().unwrap_or(0), entry["end"].as_u64().unwrap_or(0));
            let segment = json!({"start":format!("{start:#x}"),"end":format!("{end:#x}"),
                "offset":format!("{:#x}",entry["offset"].as_u64().unwrap_or(0)),
                "protection":Self::protection(entry["protection"].as_u64().unwrap_or(0))});
            match modules.iter_mut().find(|module| module.0 == name) {
                Some(module) => {
                    module.1 = module.1.min(start);
                    module.2 = module.2.max(end);
                    module.3.push(segment);
                }
                None => modules.push((name.to_owned(), start, end, vec![segment])),
            }
        }
        Ok(json!(
            modules
                .into_iter()
                .map(|(name, base, end, segments)| json!({"name":name,"base":format!("{base:#x}"),
                    "size":end - base,"segments":segments}))
                .collect::<Vec<_>>()
        ))
    }

    fn protection(bits: u64) -> String {
        format!(
            "{}{}{}",
            if bits & 1 != 0 { 'r' } else { '-' },
            if bits & 2 != 0 { 'w' } else { '-' },
            if bits & 4 != 0 { 'x' } else { '-' }
        )
    }

    fn module_bases(&mut self, pid: u32) -> Result<Vec<(String, u64, u64)>> {
        Ok(self
            .module_list(pid)?
            .as_array()
            .context("modules")?
            .iter()
            .filter_map(|module| {
                let base = parse_hex(&module["base"])?;
                Some((module["name"].as_str()?.to_owned(), base, base + module["size"].as_u64()?))
            })
            .collect())
    }

    /// `module+0xoffset` for an address, if it lies inside a named module.
    pub fn annotate(address: u64, modules: &[(String, u64, u64)]) -> Option<String> {
        modules
            .iter()
            .find(|(_, base, end)| *base <= address && address < *end)
            .map(|(name, base, _)| format!("{name}+{:#x}", address - base))
    }

    /// Readable bytes at `address`, bounded by the process maps and with the
    /// original bytes of our own int3 breakpoints restored.
    pub fn read_code(&mut self, pid: u32, address: u64, want: usize) -> Result<Vec<u8>> {
        ensure!(want > 0 && want <= 8192, "Invalid code read length");
        let maps = self.maps(pid)?;
        let mut extent = 0u128;
        let end = address as u128 + want as u128;
        let mut position = address as u128;
        let mut entries: Vec<(u128, u128)> = maps
            .as_array()
            .context("maps")?
            .iter()
            .filter(|entry| entry["protection"].as_u64().unwrap_or(0) & 1 != 0)
            .map(|entry| (entry["start"].as_u64().unwrap_or(0) as u128, entry["end"].as_u64().unwrap_or(0) as u128))
            .collect();
        entries.sort();
        for (start, stop) in entries {
            if start <= position && position < stop {
                position = end.min(stop);
                extent = position - address as u128;
            }
        }
        ensure!(extent > 0, "Address {address:#x} is not in a readable mapping");
        let mut content = Vec::new();
        for (chunk_address, length) in Self::page_chunks(address, extent as usize) {
            content.extend(self.read_memory(pid, chunk_address, length, false)?);
        }
        for record in self.breakpoints.values().filter(|record| record.enabled) {
            if let Some(original) = record.original
                && record.address >= address
                && ((record.address - address) as usize) < content.len()
            {
                content[(record.address - address) as usize] = original;
            }
        }
        Ok(content)
    }

    pub fn disassemble_live(&mut self, pid: u32, address: u64, count: usize) -> Result<Value> {
        ensure!((1..=disasm::MAX_INSTRUCTIONS).contains(&count), "Invalid instruction count");
        let bytes = self.read_code(pid, address, (count * 15).min(8192))?;
        let items = disasm::decode(&bytes, address, count);
        let modules = self.module_bases(pid).unwrap_or_default();
        let mut listing = disasm::to_json(&items);
        for (entry, item) in listing.as_array_mut().unwrap().iter_mut().zip(&items) {
            if let Some(target) = item.branch_target
                && let Some(label) = Self::annotate(target, &modules)
            {
                entry["branch_target_symbol"] = json!(label);
            }
            if self.breakpoints.values().any(|record| record.enabled && record.address == item.address) {
                entry["breakpoint"] = json!(true);
            }
        }
        Ok(json!({"pid":pid,"address":format!("{address:#x}"),"instructions":listing,
            "breakpoint_bytes_masked":true,"bytes_read":bytes.len()}))
    }

    pub fn evaluate(&mut self, expression: &str, pid: Option<u32>, thread_id: Option<u32>) -> Result<Value> {
        let pid = pid.or(self.attached_pid);
        let registers = match thread_id {
            Some(thread) => self.get_registers_raw(thread)?,
            None => Vec::new(),
        };
        let modules = match pid {
            Some(pid) => self.module_bases(pid).unwrap_or_default(),
            None => Vec::new(),
        };
        let mut context = Live { debugger: self, pid, registers, modules };
        let value = expr::eval(expression, &mut context)?;
        Ok(json!({"expression":expression,"value":format!("{value:#x}"),"decimal":value.to_string(),
            "signed":(value as i64).to_string()}))
    }

    // ---- execution control -------------------------------------------------

    /// Wait for the next stop callback. Consumed events are stashed so that
    /// `poll_events` (and the broker's event journal) still sees them.
    pub fn wait_stop(&mut self, timeout: Duration) -> Result<Option<Value>> {
        self.session()?;
        let deadline = Instant::now() + timeout;
        loop {
            let events = self.read_events()?;
            if !events.is_empty() {
                let first = events[0].clone();
                self.stash.extend(events);
                return Ok(Some(first));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn live_state(&mut self, thread_id: u32) -> Result<Value> {
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(0);
        let pid = self.attached()?;
        let modules = self.module_bases(pid).unwrap_or_default();
        Ok(json!({"thread_id":thread_id,"rip":format!("{rip:#x}"),
            "rsp":format!("{:#x}",file.get("rsp").unwrap_or(0)),
            "location":Self::annotate(rip, &modules),"registers":registers(&raw)?}))
    }

    // ---- execution control -------------------------------------------------

    /// Slot of an already-tracked enabled breakpoint at `address`, if any.
    fn target_slot_for(&self, address: u64) -> Option<u32> {
        self.breakpoints
            .iter()
            .find(|(_, record)| record.enabled && record.address == address)
            .map(|(slot, _)| *slot)
    }

    /// Temporary breakpoint in a free slot, tracked as internal so it never
    /// shows up in `breakpoint_list` and is always cleared by the caller.
    fn set_internal_breakpoint(&mut self, address: u64) -> Result<u32> {
        let slot = self.free_slot()?;
        self.breakpoint_ex(slot, address, true, None, None, 0)?;
        if let Some(record) = self.breakpoints.get_mut(&slot) {
            record.internal = true;
        }
        Ok(slot)
    }

    fn clear_internal_breakpoint(&mut self, slot: u32) -> Result<()> {
        let result = self.breakpoint(slot, 0, false).map(|_| ());
        self.breakpoints.remove(&slot);
        result
    }

    /// Step one instruction (`into`), over calls and repeated string ops
    /// (`over`), or out of the current function (`out`). Over/out fall back to a
    /// temporary breakpoint at the next instruction / stack return address when
    /// a single step cannot produce that stop. After every stop the live
    /// registers are re-read: the pinned server steps past a breakpoint
    /// instruction before reporting, so event registers can be stale.
    pub fn step(&mut self, mode: &str, thread_id: u32, timeout: Duration) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.attached()?;
        Self::pid(thread_id)?;
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").context("Thread has no rip")?;
        let plan = match mode {
            "into" => disasm::StepPlan::Single,
            "over" => {
                let bytes = self.read_code(pid, rip, 16)?;
                disasm::step_over_plan(&bytes, rip)?
            }
            "out" => {
                let bytes = self.read_code(pid, rip, 16)?;
                if disasm::is_return(&bytes, rip) {
                    disasm::StepPlan::Single
                } else {
                    let rsp = file.get("rsp").context("Thread has no rsp")?;
                    let bytes = self.read_memory(pid, rsp, 8, false)?;
                    let target = u64::from_le_bytes(
                        <[u8; 8]>::try_from(bytes.as_slice())
                            .map_err(|_| anyhow::anyhow!("Short read at rsp"))?,
                    );
                    let executable = self
                        .maps(pid)?
                        .as_array()
                        .context("Expected maps")?
                        .iter()
                        .any(|entry| {
                            let protection = entry["protection"].as_u64().unwrap_or(0);
                            protection & 4 != 0
                                && entry["start"].as_u64().unwrap_or(0) <= target
                                && target < entry["end"].as_u64().unwrap_or(0)
                        });
                    ensure!(
                        executable,
                        "Stack top {target:#x} is not executable; step out refused"
                    );
                    disasm::StepPlan::RunTo(target)
                }
            }
            other => bail!("Unsupported step mode: {other} (use into, over or out)"),
        };
        let (stop, note) = match plan {
            disasm::StepPlan::Single => {
                self.control("step_thread", thread_id)?;
                (self.wait_stop(timeout)?, "single_step")
            }
            disasm::StepPlan::RunTo(target) => {
                let internal = match self.target_slot_for(target) {
                    Some(_) => None,
                    None => Some(self.set_internal_breakpoint(target)?),
                };
                let resumed = self.control("resume", 0);
                let stopped = self.wait_stop(timeout);
                let cleared = internal.map_or(Ok(()), |slot| self.clear_internal_breakpoint(slot));
                resumed?;
                let stop = stopped?;
                cleared?;
                (
                    stop,
                    "run_to_temp_breakpoint: the server executes the instruction at the breakpoint before reporting the stop, so live rip can be one instruction past the target",
                )
            }
        };
        let state = self.live_state(thread_id).ok();
        Ok(json!({"mode":mode,"thread_id":thread_id,"plan":note,"stop":stop,"state":state}))
    }

    /// Resume all threads and report stop events. Stops at the first event
    /// unless a `condition` is given and evaluates false on the stopped thread
    /// (then it resumes again). Also stops when the run-to `target` is hit or a
    /// tracked breakpoint reaches its `stop_after` hit count. Bounded by
    /// `max_stops` events and `timeout`; never resumes after the final stop.
    pub fn run(
        &mut self,
        target: Option<u64>,
        condition: Option<&str>,
        max_stops: u32,
        timeout: Duration,
    ) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.attached()?;
        if let Some(text) = condition {
            expr::validate(text)?;
        }
        ensure!((1..=64).contains(&max_stops), "max_stops must be 1-64");
        let (target_slot, internal) = match target {
            Some(address) => match self.target_slot_for(address) {
                Some(slot) => (Some(slot), false),
                None => (Some(self.set_internal_breakpoint(address)?), true),
            },
            None => (None, false),
        };
        let outcome = self.run_loop(pid, target, target_slot, condition, max_stops, timeout);
        if internal
            && let Some(slot) = target_slot
            && let Err(error) = self.clear_internal_breakpoint(slot)
            && outcome.is_ok()
        {
            return Err(error.context("Run finished but the temporary breakpoint could not be cleared; console state uncertain"));
        }
        outcome
    }

    fn run_loop(
        &mut self,
        pid: u32,
        target: Option<u64>,
        target_slot: Option<u32>,
        condition: Option<&str>,
        max_stops: u32,
        timeout: Duration,
    ) -> Result<Value> {
        self.control("resume", 0)?;
        let deadline = Instant::now() + timeout;
        let mut stops = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("Run timeout; threads may still be running; call debug_control halt")?;
            let Some(event) = self.wait_stop(remaining)? else {
                break;
            };
            let event_thread = event["thread_id"].as_u64().unwrap_or(0) as u32;
            let event_rip = parse_hex(&event["registers"]["rip"]).unwrap_or(0);
            let mut hit_slot = None;
            for (slot, record) in self.breakpoints.iter_mut() {
                if record.enabled
                    && (record.address == event_rip || record.address + 1 == event_rip)
                {
                    record.hits += 1;
                    hit_slot = Some(*slot);
                }
            }
            let state = self.live_state(event_thread).ok();
            let mut condition_value = Value::Null;
            let mut condition_met = true;
            if let Some(text) = condition {
                match self.evaluate(text, Some(pid), Some(event_thread)) {
                    Ok(value) => {
                        condition_value = value["value"].clone();
                        condition_met = parse_hex(&value["value"]).unwrap_or(0) != 0;
                    }
                    Err(error) => {
                        return Err(error.context(
                            "Condition evaluation failed; stopped without resuming",
                        ));
                    }
                }
            }
            let stop_after_hit = hit_slot
                .and_then(|slot| self.breakpoints.get(&slot))
                .is_some_and(|record| record.stop_after > 0 && record.hits >= record.stop_after);
            let target_hit = hit_slot.is_some_and(|slot| Some(slot) == target_slot);
            stops.push(json!({
                "event":event,"hit_breakpoint":hit_slot,"target_hit":target_hit,
                "condition":condition_value,"condition_met":condition_met,
                "stop_after_hit":stop_after_hit,"state":state,
            }));
            let keep_running = condition.is_some()
                && !condition_met
                && !stop_after_hit
                && !target_hit
                && stops.len() < max_stops as usize;
            if !keep_running {
                break;
            }
            self.control("resume", 0)?;
        }
        Ok(json!({
            "stop_count":stops.len(),"stops":stops,
            "target":target.map(|address| format!("{address:#x}")),
            "condition":condition,
            "breakpoints":self.breakpoint_list(),
            "note":"All-stop model: resume continues every thread. Event registers can be stale; each stop carries re-read live registers in state.",
        }))
    }

    /// Best-effort call-stack unwind for one thread: frame-pointer chain first,
    /// then a bounded scan of the stack for values inside executable mappings.
    pub fn stack_trace(&mut self, thread_id: u32, max_frames: usize) -> Result<Value> {
        ensure!((1..=64).contains(&max_frames), "max_frames must be 1-64");
        let pid = self.attached()?;
        Self::pid(thread_id)?;
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(0);
        let rbp = file.get("rbp").unwrap_or(0);
        let rsp = file.get("rsp").unwrap_or(0);
        let maps = self.maps(pid)?;
        let modules = self.module_bases(pid)?;
        let entries = maps.as_array().context("Expected maps")?;
        let executable: Vec<(u64, u64)> = entries
            .iter()
            .filter(|entry| entry["protection"].as_u64().unwrap_or(0) & 4 != 0)
            .map(|entry| {
                (
                    entry["start"].as_u64().unwrap_or(0),
                    entry["end"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        let in_executable =
            |address: u64| executable.iter().any(|(start, end)| *start <= address && address < *end);
        let stack_entry = entries
            .iter()
            .find(|entry| {
                let protection = entry["protection"].as_u64().unwrap_or(0);
                let (start, end) = (
                    entry["start"].as_u64().unwrap_or(0),
                    entry["end"].as_u64().unwrap_or(0),
                );
                protection & 1 != 0 && protection & 4 == 0 && start <= rsp && rsp < end
            })
            .cloned();
        let stack_end = stack_entry
            .as_ref()
            .and_then(|entry| entry["end"].as_u64())
            .unwrap_or(rsp);
        let mut frames = vec![json!({"depth":0,"address":format!("{rip:#x}"),
            "symbol":Self::annotate(rip, &modules),"via":"current_rip"})];
        let mut chain_complete = true;
        let mut current = rbp;
        let mut visited = std::collections::HashSet::new();
        while frames.len() < max_frames
            && current >= rsp
            && current < stack_end
            && current % 8 == 0
            && visited.insert(current)
        {
            let Ok(pair) = self.read_memory(pid, current, 16, false) else {
                chain_complete = false;
                break;
            };
            let next = qword(&pair, 0);
            let return_address = qword(&pair, 8);
            if !in_executable(return_address) {
                chain_complete = false;
                break;
            }
            frames.push(json!({"depth":frames.len(),"address":format!("{return_address:#x}"),
                "symbol":Self::annotate(return_address, &modules),"via":"frame_pointer",
                "frame_pointer":format!("{current:#x}")}));
            if next <= current || next >= stack_end {
                chain_complete = false;
                break;
            }
            current = next;
        }
        let scan_end = stack_end.min(rsp.saturating_add(16384));
        let mut scanned = 0u64;
        if scan_end > rsp {
            for (chunk_address, length) in Self::page_chunks(rsp, (scan_end - rsp) as usize) {
                if frames.len() >= max_frames {
                    break;
                }
                let Ok(content) = self.read_memory(pid, chunk_address, length, false) else {
                    break;
                };
                scanned += length as u64;
                for offset in (0..content.len().saturating_sub(7)).step_by(8) {
                    if frames.len() >= max_frames {
                        break;
                    }
                    let candidate = qword(&content, offset);
                    if in_executable(candidate)
                        && !frames
                            .iter()
                            .any(|frame| parse_hex(&frame["address"]) == Some(candidate))
                    {
                        frames.push(json!({"depth":frames.len(),"address":format!("{candidate:#x}"),
                            "symbol":Self::annotate(candidate, &modules),"via":"stack_scan",
                            "stack_address":format!("{:#x}", chunk_address + offset as u64)}));
                    }
                }
            }
        }
        Ok(json!({"thread_id":thread_id,"rip":format!("{rip:#x}"),"rsp":format!("{rsp:#x}"),
            "rbp":format!("{rbp:#x}"),"frames":frames,"frame_pointer_complete":chain_complete,
            "stack_scanned_bytes":scanned,
            "note":"Heuristic unwind (frame-pointer chain plus stack scan); verify frames against disassembly"}))
    }
}

struct Live<'a> {
    debugger: &'a mut Debugger,
    pid: Option<u32>,
    registers: Vec<u8>,
    modules: Vec<(String, u64, u64)>,
}

impl Context for Live<'_> {
    fn register(&mut self, name: &str) -> Result<Option<u64>> {
        Ok(RegisterFile(&self.registers).get(name))
    }
    fn symbol(&mut self, name: &str) -> Result<Option<u64>> {
        let lower = name.to_ascii_lowercase();
        if let Some(value) = self.debugger.labels.get(&lower) {
            return Ok(Some(*value));
        }
        Ok(self
            .modules
            .iter()
            .find(|(module, _, _)| module.to_ascii_lowercase() == lower)
            .map(|(_, base, _)| *base))
    }
    fn read(&mut self, address: u64, size: usize) -> Result<u64> {
        let pid = self.pid.context("Memory expressions need a pid or an active session")?;
        let bytes = self.debugger.read_memory(pid, address, size, false)?;
        let mut padded = [0u8; 8];
        padded[..size].copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(padded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ATTESTATION, Profile};
    use crate::debugger::fake;
    use std::path::Path;

    fn qualified_profile(directory: &Path, port: u16) -> Profile {
        let mut data: Value =
            serde_json::from_str(include_str!("../../profiles/ps4-1400.json")).unwrap();
        data["host"] = json!("127.0.0.1");
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        data["ports"]["debug"] = json!(port);
        data["permissions"]["debug_control"] = json!(true);
        data["jailbreak"]["installed_commit"] = json!("a".repeat(40));
        data["jailbreak"]["hen_build"] = json!("test-hen");
        data["debugger"]["expected_brand"] = json!("ps4debug-NG by Pharaoh2k v1.3.4");
        data["debugger"]["payload_sha256"] = json!("b".repeat(64));
        let path = directory.join("profile.json");
        std::fs::write(&path, data.to_string()).unwrap();
        let profile = Profile::load(path).unwrap();
        let record = json!({
            "profile_sha256": profile.fingerprint(), "attestation": ATTESTATION,
            "approved_permissions": ["debug_control"], "debugger_payload_sha256": "b".repeat(64),
            "payload_sha256_allowlist": [], "build_recipe_sha256_allowlist": [],
        });
        std::fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
    }

    #[test]
    fn attach_step_run_stack_eval_and_registers_against_fake() {
        // The pinned protocol fixes the debug callback port at 755. Hosts with
        // an unprivileged-port floor above 755 (some CI runners) cannot bind it;
        // skip there instead of failing — other runners cover the full path.
        if std::net::TcpListener::bind(("127.0.0.1", 755)).is_err() {
            eprintln!("skipping: cannot bind the fixed callback port 755 on this host");
            return;
        }
        let fake = fake::spawn_debuggable();
        let directory = tempfile::tempdir().unwrap();
        let profile = qualified_profile(directory.path(), fake.port);
        let mut debugger = Debugger::new(profile);

        let attached = debugger.attach(77, "127.0.0.1").unwrap();
        assert_eq!(attached["attached_pid"], 77);

        let regs = debugger.get_registers(1).unwrap();
        assert_eq!(regs["rip"], format!("{:#x}", fake::FAKE_RIP));

        // Register write with readback verification.
        let report = debugger
            .set_registers(1, &[("rip".to_owned(), 0x1005)])
            .unwrap();
        assert_eq!(report["verified"], true);
        assert_eq!(debugger.get_registers(1).unwrap()["rip"], "0x1005");
        assert!(debugger.set_registers(1, &[("nope".to_owned(), 1)]).is_err());

        // FPU and debug registers.
        assert_eq!(
            debugger.fpu_registers(1).unwrap()["xmm"].as_array().unwrap().len(),
            16
        );
        assert!(debugger.hardware_debug_registers(1).unwrap()["dr7"].is_string());

        // Tracked breakpoint with a condition; disassembly masks its int3 byte.
        debugger
            .breakpoint_ex(0, 0x1009, true, Some("rax == 0".to_owned()), None, 0)
            .unwrap();
        assert_eq!(debugger.breakpoint_list()[0]["condition"], "rax == 0");
        let modules = debugger.module_list(77).unwrap();
        assert_eq!(modules[0]["name"], "eboot.bin");
        assert_eq!(modules[0]["base"], "0x1000");
        let listing = debugger.disassemble_live(77, 0x1000, 8).unwrap();
        let instructions = listing["instructions"].as_array().unwrap();
        assert_eq!(instructions[0]["text"], "push rbp");
        let call = &instructions[2];
        assert_eq!(call["flow"], "call");
        assert_eq!(call["branch_target"], "0x1019");
        assert_eq!(call["branch_target_symbol"], "eboot.bin+0x19");
        let at_bp = instructions
            .iter()
            .find(|item| item["address"] == "0x1009")
            .unwrap();
        assert_eq!(at_bp["breakpoint"], true);
        assert_eq!(at_bp["bytes"], "31c0", "original byte restored, not int3");
        // Clear it so the step-over temporary breakpoint can use the address.
        debugger.breakpoint_ex(0, 0x1009, false, None, None, 0).unwrap();
        assert!(debugger.breakpoint_list().as_array().unwrap().is_empty());

        // Expression evaluation against live registers, memory and modules.
        let value = debugger.evaluate("rip + 1", Some(77), Some(1)).unwrap();
        assert_eq!(value["value"], "0x1006");
        let deref = debugger.evaluate("[rsp+8]", Some(77), Some(1)).unwrap();
        assert_eq!(deref["value"], format!("{:#x}", fake::FAKE_RET));
        let module = debugger.evaluate("eboot.bin + 0x10", Some(77), None).unwrap();
        assert_eq!(module["value"], "0x1010");

        // Step into: single-step command plus one stop event.
        let step = debugger.step("into", 1, Duration::from_secs(5)).unwrap();
        assert_eq!(step["plan"], "single_step");
        assert!(step["stop"].is_object());
        assert_eq!(step["stop"]["thread_id"], 1);

        // Step over the call at 0x1004: temporary breakpoint at the next instruction.
        debugger
            .set_registers(1, &[("rip".to_owned(), 0x1004)])
            .unwrap();
        let step = debugger.step("over", 1, Duration::from_secs(5)).unwrap();
        assert!(step["plan"].as_str().unwrap().starts_with("run_to_temp_breakpoint"));
        assert!(step["stop"].is_object());
        assert!(
            debugger.breakpoint_list().as_array().unwrap().is_empty(),
            "internal breakpoint hidden and cleared"
        );

        // Run to the tracked breakpoint address: one stop, hit counted.
        debugger
            .breakpoint_ex(0, 0x1009, true, Some("rax == 0".to_owned()), None, 0)
            .unwrap();
        let run = debugger
            .run(Some(0x1009), None, 4, Duration::from_secs(5))
            .unwrap();
        assert_eq!(run["stop_count"], 1);
        assert_eq!(run["stops"][0]["target_hit"], true);
        assert_eq!(run["breakpoints"][0]["hits"], 1);

        // Conditional run: false condition keeps resuming up to max_stops.
        let run = debugger
            .run(None, Some("rax == 1"), 3, Duration::from_secs(5))
            .unwrap();
        assert_eq!(run["stop_count"], 3);
        assert_eq!(run["stops"][0]["condition_met"], false);
        // True condition stops at the first event.
        let run = debugger
            .run(None, Some("rax == 0"), 3, Duration::from_secs(5))
            .unwrap();
        assert_eq!(run["stop_count"], 1);
        assert_eq!(run["stops"][0]["condition_met"], true);

        // Call-stack unwind: current rip plus the frame-pointer return address.
        let stack = debugger.stack_trace(1, 16).unwrap();
        let frames = stack["frames"].as_array().unwrap();
        assert_eq!(frames[0]["via"], "current_rip");
        assert_eq!(frames[1]["address"], format!("{:#x}", fake::FAKE_RET));
        assert_eq!(frames[1]["symbol"], "eboot.bin+0x500");
        assert_eq!(frames[1]["via"], "frame_pointer");

        debugger.detach().unwrap();
        assert!(debugger.attached_pid.is_none());
    }
}
