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
