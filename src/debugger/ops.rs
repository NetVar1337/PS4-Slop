//! Higher-level debugger operations built on the pinned ps4debug-NG command set:
//! register writes, FPU/debug-register reads, tracked breakpoints with conditions,
//! stepping, conditional run, call stacks, modules and expression evaluation.
//!
//! Hardware caveat: the pinned server steps a thread past a software breakpoint
//! before it reports the hit, so event registers can be stale. Every operation here
//! re-reads the live registers after a stop instead of trusting the event.

use super::*;
use crate::{
    asm, disasm, ehframe,
    expr::{self, Context, RegisterFile},
    scanner::{ScanComparison, ScanRegion, ScanRequest, ScanValueType},
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

#[derive(Debug, Clone)]
pub struct PatchRecord {
    pub id: u32,
    pub pid: u32,
    pub address: u64,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub assembly: Option<String>,
    pub nop_padded: usize,
    pub active: bool,
    pub comment: Option<String>,
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

pub fn parse_protection_spec(raw: &Value) -> Result<u32> {
    if let Some(bits) = raw.as_u64() {
        ensure!((1..=7).contains(&bits), "Protection bitmask must be 1..=7");
        return Ok(bits as u32);
    }
    if let Some(s) = raw.as_str() {
        let trimmed = s.trim().to_ascii_lowercase();
        if let Ok(bits) = trimmed.parse::<u32>() {
            ensure!((1..=7).contains(&bits), "Protection bitmask must be 1..=7");
            return Ok(bits);
        }
        let mut bits = 0u32;
        for ch in trimmed.chars() {
            match ch {
                'r' => bits |= 1,
                'w' => bits |= 2,
                'x' => bits |= 4,
                '-' => {}
                other => bail!("Invalid protection flag '{other}' (use r/w/x or 1..=7)"),
            }
        }
        ensure!((1..=7).contains(&bits), "Protection must enable at least one of r/w/x");
        return Ok(bits);
    }
    bail!("Protection must be a string ('rwx', 'rx', 'rw') or integer bitmask (1..=7)")
}

fn encode_xmm_value(val: &Value) -> Result<[u8; 16]> {
    if let Some(hex_str) = val.as_str() {
        let s = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let decoded = hex::decode(s)?;
        ensure!(decoded.len() == 16, "XMM hex value must be 16 bytes (32 hex chars)");
        let mut out = [0u8; 16];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }
    if let Some(num) = val.as_f64() {
        ensure!(num.is_finite(), "Float value must be finite");
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&(num as f32).to_le_bytes());
        return Ok(out);
    }
    if let Some(obj) = val.as_object() {
        let mut out = [0u8; 16];
        if let Some(f32_val) = obj.get("f32") {
            if let Some(arr) = f32_val.as_array() {
                ensure!(!arr.is_empty() && arr.len() <= 4, "xmm f32 array must have 1..=4 items");
                for (i, item) in arr.iter().enumerate() {
                    let f = item.as_f64().context("f32 element must be numeric")? as f32;
                    ensure!(f.is_finite(), "f32 element must be finite");
                    out[i * 4..i * 4 + 4].copy_from_slice(&f.to_le_bytes());
                }
                return Ok(out);
            }
            let f = f32_val.as_f64().context("f32 must be numeric")? as f32;
            ensure!(f.is_finite(), "f32 must be finite");
            out[..4].copy_from_slice(&f.to_le_bytes());
            return Ok(out);
        }
        if let Some(f64_val) = obj.get("f64") {
            if let Some(arr) = f64_val.as_array() {
                ensure!(!arr.is_empty() && arr.len() <= 2, "xmm f64 array must have 1..=2 items");
                for (i, item) in arr.iter().enumerate() {
                    let f = item.as_f64().context("f64 element must be numeric")?;
                    ensure!(f.is_finite(), "f64 element must be finite");
                    out[i * 8..i * 8 + 8].copy_from_slice(&f.to_le_bytes());
                }
                return Ok(out);
            }
            let f = f64_val.as_f64().context("f64 must be numeric")?;
            ensure!(f.is_finite(), "f64 must be finite");
            out[..8].copy_from_slice(&f.to_le_bytes());
            return Ok(out);
        }
    }
    bail!("XMM value must be 32-char hex, float scalar, or {{\"f32\": ...}} / {{\"f64\": ...}}")
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

    pub fn fpu_registers_raw(&mut self, thread_id: u32) -> Result<Vec<u8>> {
        self.session()?;
        Self::pid(thread_id)?;
        self.exchange_read(|debugger| {
            debugger.packet(0xbdbb000a, &thread_id.to_le_bytes())?;
            debugger.status()?;
            debugger.read(832)
        })
    }

    pub fn fpu_registers(&mut self, thread_id: u32) -> Result<Value> {
        let data = self.fpu_registers_raw(thread_id)?;
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

    /// Read-modify-write of the 832-byte `savefpu_ymm` block (`0xBDBB000B`) with
    /// full readback verification. Supports `xmm0`..`xmm15`, `ymm_high0`..`ymm_high15`,
    /// `st0`..`st7`, `mxcsr`, `fcw`, `fsw`, `ftw`, and `fop`.
    pub fn set_fpu_registers(&mut self, thread_id: u32, changes: &Value) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        Self::pid(thread_id)?;
        let obj = changes.as_object().context("changes must be an object")?;
        ensure!(!obj.is_empty() && obj.len() <= 40, "Provide 1-40 FPU/SIMD register changes");

        let mut raw = self.fpu_registers_raw(thread_id)?;
        let mut checks: Vec<(String, usize, Vec<u8>)> = Vec::new();
        let mut touched_ymm = false;

        let parse_u32_field = |v: &Value| -> Result<u32> {
            if let Some(n) = v.as_u64() {
                return Ok(u32::try_from(n)?);
            }
            if let Some(s) = v.as_str() {
                let s = s.trim();
                if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    return Ok(u32::from_str_radix(h, 16)?);
                }
                return Ok(s.parse::<u32>()?);
            }
            bail!("Numeric or hex string expected")
        };

        for (key, val) in obj {
            let k = key.to_ascii_lowercase();
            if k == "mxcsr" {
                let v = parse_u32_field(val)? & 0xffbf;
                let bytes = v.to_le_bytes().to_vec();
                raw[24..28].copy_from_slice(&bytes);
                checks.push((k, 24, bytes));
            } else if k == "fcw" || k == "fsw" || k == "fop" {
                let off = match k.as_str() {
                    "fcw" => 0,
                    "fsw" => 2,
                    _ => 6,
                };
                let v = (parse_u32_field(val)? as u16).to_le_bytes().to_vec();
                raw[off..off + 2].copy_from_slice(&v);
                checks.push((k, off, v));
            } else if k == "ftw" {
                let v = vec![parse_u32_field(val)? as u8];
                raw[4] = v[0];
                checks.push((k, 4, v));
            } else if let Some(idx_str) = k.strip_prefix("xmm") {
                let idx: usize = idx_str.parse()?;
                ensure!(idx < 16, "XMM index must be 0..=15");
                let bytes = encode_xmm_value(val)?;
                let off = 160 + 16 * idx;
                raw[off..off + 16].copy_from_slice(&bytes);
                checks.push((k, off, bytes.to_vec()));
            } else if let Some(idx_str) = k.strip_prefix("ymm_high") {
                let idx: usize = idx_str.parse()?;
                ensure!(idx < 16, "YMM high index must be 0..=15");
                let bytes = encode_xmm_value(val)?;
                let off = 576 + 16 * idx;
                raw[off..off + 16].copy_from_slice(&bytes);
                touched_ymm = true;
                checks.push((k, off, bytes.to_vec()));
            } else if let Some(idx_str) = k.strip_prefix("st") {
                let idx: usize = idx_str.parse()?;
                ensure!(idx < 8, "ST index must be 0..=7");
                let s = val.as_str().context("ST register value must be a 20-char hex string")?;
                let bytes = hex::decode(s.trim().strip_prefix("0x").unwrap_or(s.trim()))?;
                ensure!(bytes.len() == 10, "ST register value must be 10 bytes (20 hex chars)");
                let off = 32 + 16 * idx;
                raw[off..off + 10].copy_from_slice(&bytes);
                checks.push((k, off, bytes));
            } else {
                bail!("Unsupported FPU/SIMD register key: {key}");
            }
        }
        if touched_ymm {
            let mut xstate_bv = qword(&raw, 512);
            xstate_bv |= 0x7; // X87 | SSE | AVX
            raw[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        }

        self.exchange(|debugger| {
            let mut body = thread_id.to_le_bytes().to_vec();
            body.extend(832u32.to_le_bytes());
            debugger.packet(0xbdbb000b, &body)?;
            debugger.status()?;
            debugger.write(&raw)?;
            debugger.status()
        })?;

        let after = self.fpu_registers_raw(thread_id)?;
        let mut report = Vec::new();
        for (name, off, expected) in checks {
            let actual = &after[off..off + expected.len()];
            ensure!(
                actual == expected.as_slice(),
                "FPU register '{name}' readback mismatch (requested {}, got {}); state uncertain",
                hex::encode(&expected),
                hex::encode(actual)
            );
            report.push(json!({
                "register": name,
                "requested": hex::encode(&expected),
                "actual": hex::encode(actual),
                "match": true,
            }));
        }
        Ok(json!({
            "thread_id": thread_id,
            "changes": report,
            "verified": true,
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

    /// Read Orbis OS per-thread `fsbase` and `gsbase` (`CMD_DEBUG_GETFSGSBASE = 0xBDBB000E`).
    pub fn tls_bases(&mut self, thread_id: u32) -> Result<Value> {
        self.session()?;
        Self::pid(thread_id)?;
        let data = self.exchange_read(|debugger| {
            debugger.packet(0xbdbb000e, &thread_id.to_le_bytes())?;
            debugger.status()?;
            debugger.read(16)
        })?;
        Ok(json!({
            "thread_id": thread_id,
            "fsbase": format!("{:#x}", qword(&data, 0)),
            "gsbase": format!("{:#x}", qword(&data, 8)),
        }))
    }

    /// Update per-thread `fsbase` / `gsbase` (`CMD_DEBUG_SETFSGSBASE = 0xBDBB000F`) with readback verification.
    pub fn set_tls_bases(
        &mut self,
        thread_id: u32,
        fsbase: Option<u64>,
        gsbase: Option<u64>,
    ) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        Self::pid(thread_id)?;
        ensure!(
            fsbase.is_some() || gsbase.is_some(),
            "Specify at least one of fsbase or gsbase"
        );
        let before = self.tls_bases(thread_id)?;
        let old_fs = parse_hex(&before["fsbase"]).unwrap_or(0);
        let old_gs = parse_hex(&before["gsbase"]).unwrap_or(0);
        let new_fs = fsbase.unwrap_or(old_fs);
        let new_gs = gsbase.unwrap_or(old_gs);

        self.exchange(|debugger| {
            let mut body = thread_id.to_le_bytes().to_vec();
            body.extend(16u32.to_le_bytes());
            debugger.packet(0xbdbb000f, &body)?;
            debugger.status()?;
            let mut payload = Vec::with_capacity(16);
            payload.extend(new_fs.to_le_bytes());
            payload.extend(new_gs.to_le_bytes());
            debugger.write(&payload)?;
            debugger.status()
        })?;

        let after = self.tls_bases(thread_id)?;
        let actual_fs = parse_hex(&after["fsbase"]).unwrap_or(0);
        let actual_gs = parse_hex(&after["gsbase"]).unwrap_or(0);
        ensure!(
            actual_fs == new_fs && actual_gs == new_gs,
            "TLS base readback mismatch (fsbase {actual_fs:#x} vs {new_fs:#x}, gsbase {actual_gs:#x} vs {new_gs:#x})"
        );
        Ok(json!({
            "thread_id": thread_id,
            "fsbase": format!("{actual_fs:#x}"),
            "gsbase": format!("{actual_gs:#x}"),
            "previous_fsbase": format!("{old_fs:#x}"),
            "previous_gsbase": format!("{old_gs:#x}"),
            "verified": true,
        }))
    }

    /// Allocate RWX process memory via `CMD_PROC_ALLOC` (`0xBDAA000B`) or
    /// `CMD_PROC_ALLOC_HINTED` (`0xBDAA000E`, useful for +-2 GiB `rel32` code caves).
    pub fn memory_alloc(&mut self, pid: u32, length: usize, hint: Option<u64>) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        Self::pid(pid)?;
        ensure!(
            (1..=64 * 1024 * 1024).contains(&length),
            "Allocation length must be 1..=67108864 bytes"
        );
        let address = self.exchange(|debugger| {
            if let Some(hint_addr) = hint.filter(|&h| h != 0) {
                let mut body = Vec::with_capacity(16);
                body.extend(pid.to_le_bytes());
                body.extend(hint_addr.to_le_bytes());
                body.extend((length as u32).to_le_bytes());
                debugger.packet(0xbdaa000e, &body)?;
            } else {
                let mut body = Vec::with_capacity(8);
                body.extend(pid.to_le_bytes());
                body.extend((length as u32).to_le_bytes());
                debugger.packet(0xbdaa000b, &body)?;
            }
            debugger.status()?;
            Ok(qword(&debugger.read(8)?, 0))
        })?;
        ensure!(address != 0, "Target allocator returned NULL (0x0)");
        let verified_in_maps = self
            .maps(pid)
            .ok()
            .and_then(|m| {
                m.as_array().map(|arr| {
                    arr.iter().any(|e| {
                        let s = e["start"].as_u64().unwrap_or(0);
                        let end = e["end"].as_u64().unwrap_or(0);
                        s <= address && address < end
                    })
                })
            })
            .unwrap_or(false);
        Ok(json!({
            "pid": pid,
            "address": format!("{address:#x}"),
            "requested_length": length,
            "hint": hint.map(|h| format!("{h:#x}")),
            "verified_in_maps": verified_in_maps,
        }))
    }

    /// Free process memory allocated by `memory_alloc` (`CMD_PROC_FREE = 0xBDAA000C`).
    pub fn memory_free(&mut self, pid: u32, address: u64, length: usize) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        Self::pid(pid)?;
        ensure!(address != 0, "Cannot free NULL address");
        ensure!(
            (1..=64 * 1024 * 1024).contains(&length),
            "Free length must be 1..=67108864 bytes"
        );
        self.exchange(|debugger| {
            let mut body = Vec::with_capacity(16);
            body.extend(pid.to_le_bytes());
            body.extend(address.to_le_bytes());
            body.extend((length as u32).to_le_bytes());
            debugger.packet(0xbdaa000c, &body)?;
            debugger.status()
        })?;
        Ok(json!({
            "pid": pid,
            "address": format!("{address:#x}"),
            "length": length,
            "freed": true,
        }))
    }

    /// Change virtual memory protection (`CMD_PROC_PROTECT = 0xBDAA0008`), draining
    /// the trailing `CMD_DATA_NULL (0xF0000003)` emitted by `ps4debug-NG@8be828fe`
    /// `proc_protect_handle` and verifying the resulting protection via `maps`.
    pub fn memory_protect(
        &mut self,
        pid: u32,
        address: u64,
        length: usize,
        prot: u32,
    ) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        Self::pid(pid)?;
        ensure!((1..=7).contains(&prot), "Protection bitmask must be 1..=7");
        ensure!(
            (1..=64 * 1024 * 1024).contains(&length),
            "Protection length must be 1..=67108864 bytes"
        );
        let trailing = self.exchange(|debugger| {
            let mut body = Vec::with_capacity(20);
            body.extend(pid.to_le_bytes());
            body.extend(address.to_le_bytes());
            body.extend((length as u32).to_le_bytes());
            body.extend(prot.to_le_bytes());
            debugger.packet(0xbdaa0008, &body)?;
            debugger.status()?;
            debugger.drain_optional_trailing_status()
        })?;
        if let Some(code) = trailing {
            ensure!(
                code == CMD_DATA_NULL || code == SUCCESS,
                "Unexpected trailing status after CMD_PROC_PROTECT: {code:#010x}"
            );
        }
        let maps = self.maps(pid)?;
        let observed = maps.as_array().and_then(|arr| {
            arr.iter()
                .find(|e| {
                    let s = e["start"].as_u64().unwrap_or(0);
                    let end = e["end"].as_u64().unwrap_or(0);
                    s <= address && address < end
                })
                .and_then(|e| e["protection"].as_u64())
        });
        let verified = observed.is_some_and(|p| (p as u32 & 7) == (prot & 7));
        self.eh_cache.clear();
        Ok(json!({
            "pid": pid,
            "address": format!("{address:#x}"),
            "length": length,
            "requested_protection": Self::protection(prot as u64),
            "requested_bits": prot,
            "observed_protection": observed.map(Self::protection),
            "verified": verified,
            "drained_trailing_status": trailing.map(|c| format!("{c:#010x}")),
        }))
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
            if let Some(label) = self
                .labels
                .iter()
                .find(|(_, value)| **value == item.address)
                .map(|(name, _)| name.clone())
            {
                entry["label"] = json!(label);
            }
            if let Some(target) = item.branch_target
                && let Some(label) = self
                    .labels
                    .iter()
                    .find(|(_, value)| **value == target)
                    .map(|(name, _)| name.clone())
            {
                entry["branch_target_label"] = json!(label);
            }
            if self.breakpoints.values().any(|record| record.enabled && record.address == item.address) {
                entry["breakpoint"] = json!(true);
            }
        }
        Ok(json!({"pid":pid,"address":format!("{address:#x}"),"instructions":listing,
            "breakpoint_bytes_masked":true,"bytes_read":bytes.len()}))
    }

    pub fn evaluate(
        &mut self,
        expression: &str,
        pid: Option<u32>,
        thread_id: Option<u32>,
    ) -> Result<Value> {
        let pid = pid.or(self.attached_pid);
        let registers = match thread_id {
            Some(thread) => self.get_registers_raw(thread)?,
            None => Vec::new(),
        };
        let tls = match thread_id {
            Some(thread) if self.attached_pid.is_some() => self
                .tls_bases(thread)
                .ok()
                .map(|v| (parse_hex(&v["fsbase"]).unwrap_or(0), parse_hex(&v["gsbase"]).unwrap_or(0))),
            _ => None,
        };
        let modules = match pid {
            Some(pid) => self.module_bases(pid).unwrap_or_default(),
            None => Vec::new(),
        };
        let mut context = Live {
            debugger: self,
            pid,
            registers,
            tls,
            modules,
        };
        let value = expr::eval(expression, &mut context)?;
        Ok(json!({"expression":expression,"value":format!("{value:#x}"),"decimal":value.to_string(),
            "signed":(value as i64).to_string()}))
    }

    fn interpolate_log(
        &mut self,
        template: &str,
        pid: u32,
        thread_id: u32,
    ) -> String {
        let mut out = String::with_capacity(template.len() + 32);
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            if let Some(close) = after.find('}') {
                let inner = after[..close].trim();
                if inner.is_empty() {
                    out.push_str("{}");
                } else {
                    match self.evaluate(inner, Some(pid), Some(thread_id)) {
                        Ok(val) => out.push_str(val["value"].as_str().unwrap_or("?")),
                        Err(_) => {
                            out.push('{');
                            out.push_str(inner);
                            out.push('}');
                        }
                    }
                }
                rest = &after[close + 1..];
            } else {
                out.push_str(&rest[open..]);
                return out;
            }
        }
        out.push_str(rest);
        out
    }

    // ---- DWARF .eh_frame CFI support ---------------------------------------

    fn load_module_eh_frame(
        &mut self,
        pid: u32,
        module_base: u64,
        module_end: u64,
    ) -> Option<(u64, Vec<u8>)> {
        if let Some(cached) = self.eh_cache.get(&(pid, module_base)) {
            return cached.clone();
        }
        let found = (|| -> Option<(u64, Vec<u8>)> {
            let hdr_len = (module_end.saturating_sub(module_base)).min(4096) as usize;
            if hdr_len < 64 {
                return None;
            }
            let header = self.read_memory(pid, module_base, hdr_len, false).ok()?;
            let (eh_va, max_len) = ehframe::find_eh_frame_from_elf_header(
                &header,
                module_base,
                module_end,
                |va, len| self.read_memory(pid, va, len, false),
            )?;
            let cap = max_len.min(self.profile.limit("memory_bytes")).min(262_144);
            let mut bytes = Vec::new();
            for (chunk_va, chunk_len) in Self::page_chunks(eh_va, cap) {
                match self.read_memory(pid, chunk_va, chunk_len, false) {
                    Ok(part) => bytes.extend(part),
                    Err(_) => break,
                }
            }
            if bytes.len() < 16 {
                return None;
            }
            Some((eh_va, bytes))
        })();
        self.eh_cache.insert((pid, module_base), found.clone());
        found
    }

    fn dwarf_regs_from_raw(raw: &[u8]) -> [Option<u64>; 17] {
        let f = RegisterFile(raw);
        [
            f.get("rax"),
            f.get("rdx"),
            f.get("rcx"),
            f.get("rbx"),
            f.get("rsi"),
            f.get("rdi"),
            f.get("rbp"),
            f.get("rsp"),
            f.get("r8"),
            f.get("r9"),
            f.get("r10"),
            f.get("r11"),
            f.get("r12"),
            f.get("r13"),
            f.get("r14"),
            f.get("r15"),
            f.get("rip"),
        ]
    }

    /// Attempt to unwind one frame at `lookup_pc` using DWARF `.eh_frame` CFI.
    /// Returns `Some((caller_rip, cfa, updated_dwarf_regs))`.
    fn unwind_cfi_once(
        &mut self,
        pid: u32,
        lookup_pc: u64,
        regs: &[Option<u64>; 17],
        modules: &[(String, u64, u64)],
    ) -> Option<(u64, u64, [Option<u64>; 17])> {
        let (_, base, end) = modules
            .iter()
            .find(|(_, b, e)| *b <= lookup_pc && lookup_pc < *e)?;
        let (eh_va, eh_bytes) = self.load_module_eh_frame(pid, *base, *end)?;
        let (row, ret_reg) = ehframe::unwind_at_pc(&eh_bytes, eh_va, lookup_pc).ok()??;
        let cfa_base = (*regs.get(row.cfa_reg as usize)?)?;
        let cfa = (cfa_base as i128 + row.cfa_offset as i128) as u64;
        if cfa == 0 {
            return None;
        }
        let eval_rule = |debugger: &mut Self, reg_idx: u8, rule: ehframe::RegRule| -> Option<u64> {
            match rule {
                ehframe::RegRule::Undefined => None,
                ehframe::RegRule::SameValue => *regs.get(reg_idx as usize)?,
                ehframe::RegRule::Offset(off) => {
                    let addr = (cfa as i128 + off as i128) as u64;
                    let bytes = debugger.read_memory(pid, addr, 8, false).ok()?;
                    Some(qword(&bytes, 0))
                }
                ehframe::RegRule::ValOffset(off) => Some((cfa as i128 + off as i128) as u64),
            }
        };
        let ret_rule = row.regs.get(&ret_reg).copied()?;
        let caller_rip = eval_rule(self, ret_reg, ret_rule)?;
        let mut next = [None; 17];
        // Callee-saved System V / Orbis registers default to SameValue unless overridden by FDE
        for preserved in [3usize, 6, 12, 13, 14, 15] {
            next[preserved] = regs[preserved];
        }
        for (&reg_idx, &rule) in &row.regs {
            if (reg_idx as usize) < 17 {
                next[reg_idx as usize] = eval_rule(self, reg_idx, rule);
            }
        }
        next[ehframe::DWARF_RSP as usize] = Some(cfa);
        next[ehframe::DWARF_RIP as usize] = Some(caller_rip);
        Some((caller_rip, cfa, next))
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
    /// temporary breakpoint at the next instruction / caller return address
    /// (resolved via DWARF `.eh_frame` CFI -> `[rbp+8]` -> `[rsp]`).
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
                    let maps = self.maps(pid)?;
                    let is_exec = |addr: u64| -> bool {
                        maps.as_array().is_some_and(|arr| {
                            arr.iter().any(|entry| {
                                entry["protection"].as_u64().unwrap_or(0) & 4 != 0
                                    && entry["start"].as_u64().unwrap_or(0) <= addr
                                    && addr < entry["end"].as_u64().unwrap_or(0)
                            })
                        })
                    };
                    let modules = self.module_bases(pid).unwrap_or_default();
                    let dwarf_regs = Self::dwarf_regs_from_raw(&raw);
                    let mut target_opt = self
                        .unwind_cfi_once(pid, rip, &dwarf_regs, &modules)
                        .map(|(ret, _, _)| ret)
                        .filter(|&ret| is_exec(ret));

                    let rsp = file.get("rsp").context("Thread has no rsp")?;
                    let rbp = file.get("rbp").unwrap_or(0);
                    if target_opt.is_none()
                        && rbp >= rsp
                        && rbp.is_multiple_of(8)
                        && let Ok(pair) = self.read_memory(pid, rbp, 16, false)
                    {
                        let ret = qword(&pair, 8);
                        if is_exec(ret) {
                            target_opt = Some(ret);
                        }
                    }
                    if target_opt.is_none()
                        && let Ok(top) = self.read_memory(pid, rsp, 8, false)
                    {
                        let ret = qword(&top, 0);
                        if is_exec(ret) {
                            target_opt = Some(ret);
                        }
                    }
                    let target = target_opt.ok_or_else(|| {
                        anyhow::anyhow!(
                            "Could not resolve an executable return address via .eh_frame, [rbp+8], or [rsp]; step out refused"
                        )
                    })?;
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

    /// Resume all threads and report stop events. Evaluates both per-breakpoint
    /// conditions/logs/`stop_after` thresholds and optional run-level `condition`.
    /// Bounded by `max_stops` events and `timeout`; never resumes after the final stop.
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
            let mut bp_cond_expr: Option<String> = None;
            let mut bp_log_tpl: Option<String> = None;
            let mut bp_stop_after = 0u64;
            let mut bp_hits = 0u64;
            for (slot, record) in self.breakpoints.iter_mut() {
                if record.enabled
                    && (record.address == event_rip || record.address + 1 == event_rip)
                {
                    record.hits += 1;
                    hit_slot = Some(*slot);
                    bp_cond_expr = record.condition.clone();
                    bp_log_tpl = record.log.clone();
                    bp_stop_after = record.stop_after;
                    bp_hits = record.hits;
                }
            }
            let state = self.live_state(event_thread).ok();
            let log_message = bp_log_tpl
                .as_deref()
                .map(|tpl| self.interpolate_log(tpl, pid, event_thread));

            let mut bp_condition_value = Value::Null;
            let mut bp_condition_met = true;
            if let Some(bp_expr) = bp_cond_expr.as_deref() {
                match self.evaluate(bp_expr, Some(pid), Some(event_thread)) {
                    Ok(value) => {
                        bp_condition_value = value["value"].clone();
                        bp_condition_met = parse_hex(&value["value"]).unwrap_or(0) != 0;
                    }
                    Err(error) => {
                        return Err(error.context(
                            "Breakpoint condition evaluation failed; stopped without resuming",
                        ));
                    }
                }
            }

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

            let stop_after_hit = bp_stop_after > 0 && bp_hits >= bp_stop_after && bp_condition_met;
            let target_hit = hit_slot.is_some_and(|slot| Some(slot) == target_slot);
            let mut stop_obj = json!({
                "event": event,
                "hit_breakpoint": hit_slot,
                "target_hit": target_hit,
                "condition": condition_value,
                "condition_met": condition_met,
                "breakpoint_condition": bp_condition_value,
                "breakpoint_condition_met": bp_condition_met,
                "stop_after_hit": stop_after_hit,
                "state": state,
            });
            if let Some(msg) = log_message {
                stop_obj["log_message"] = json!(msg);
            }
            stops.push(stop_obj);

            let bp_cond_unsatisfied = bp_cond_expr.is_some() && !bp_condition_met && !target_hit;
            let bp_hits_pending = bp_stop_after > 1 && bp_hits < bp_stop_after && !target_hit;
            let run_cond_unsatisfied =
                condition.is_some() && !condition_met && !stop_after_hit && !target_hit;
            let keep_running = (bp_cond_unsatisfied || bp_hits_pending || run_cond_unsatisfied)
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

    /// Call-stack unwind for one thread:
    /// 1. DWARF `.eh_frame` CFI unwind (handles `-fomit-frame-pointer` PS4 Clang code)
    /// 2. Frame-pointer (`rbp`) chain
    /// 3. Bounded stack scan for return addresses inside executable mappings.
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

        // Phase 1: DWARF .eh_frame CFI unwind
        let mut dwarf_regs = Self::dwarf_regs_from_raw(&raw);
        let mut cfi_pc = rip;
        let mut cfi_cfas = std::collections::HashSet::new();
        let mut fp_seed_rbp = rbp;
        let mut fp_seed_rsp = rsp;
        while frames.len() < max_frames {
            let Some((ret_addr, cfa, next_regs)) =
                self.unwind_cfi_once(pid, cfi_pc, &dwarf_regs, &modules)
            else {
                break;
            };
            if !in_executable(ret_addr) || !cfi_cfas.insert(cfa) {
                break;
            }
            frames.push(json!({
                "depth": frames.len(),
                "address": format!("{ret_addr:#x}"),
                "symbol": Self::annotate(ret_addr, &modules),
                "via": "eh_frame_cfi",
                "cfa": format!("{cfa:#x}"),
            }));
            dwarf_regs = next_regs;
            fp_seed_rsp = cfa;
            if let Some(restored_rbp) = dwarf_regs[ehframe::DWARF_RBP as usize] {
                fp_seed_rbp = restored_rbp;
            }
            cfi_pc = ret_addr.saturating_sub(1);
        }

        // Phase 2: Frame-pointer chain fallback
        let mut chain_complete = true;
        let mut current = fp_seed_rbp;
        let mut visited = std::collections::HashSet::new();
        while frames.len() < max_frames
            && current >= fp_seed_rsp
            && current < stack_end
            && current.is_multiple_of(8)
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
            if !frames
                .iter()
                .any(|f| parse_hex(&f["address"]) == Some(return_address))
            {
                frames.push(json!({"depth":frames.len(),"address":format!("{return_address:#x}"),
                    "symbol":Self::annotate(return_address, &modules),"via":"frame_pointer",
                    "frame_pointer":format!("{current:#x}")}));
            }
            if next <= current || next >= stack_end {
                chain_complete = false;
                break;
            }
            current = next;
        }

        // Phase 3: Bounded stack scan fallback
        let scan_start = fp_seed_rsp.max(rsp);
        let scan_end = stack_end.min(scan_start.saturating_add(16384));
        let mut scanned = 0u64;
        if scan_end > scan_start {
            for (chunk_address, length) in
                Self::page_chunks(scan_start, (scan_end - scan_start) as usize)
            {
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
            "note":"Unwound via DWARF .eh_frame CFI when available, falling back to frame-pointer chain plus bounded stack scan"}))
    }

    // ---- xrefs, search, patches, scanner, labels, persistence --------------

    /// Read a code range without re-validating maps per chunk; own breakpoint
    /// bytes are restored, same as `read_code`.
    fn read_code_fast(&mut self, pid: u32, address: u64, length: usize) -> Result<Vec<u8>> {
        let step_cap = self.profile.limit("memory_bytes").clamp(4096, 262_144);
        let mut content = Vec::with_capacity(length);
        let mut cursor = address;
        let mut remaining = length;
        while remaining > 0 {
            let ask = remaining.min(step_cap);
            let chunk = self.read_memory(pid, cursor, ask, false)?;
            let got = chunk.len();
            content.extend(chunk);
            if got == 0 {
                break;
            }
            cursor = cursor.saturating_add(got as u64);
            remaining -= got;
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

    pub fn code_xrefs(&mut self, pid: u32, target: u64, max_results: usize) -> Result<Value> {
        self.code_xrefs_filtered(pid, target, max_results, None, None)
    }

    /// Find instructions whose branch target or rip-relative memory operand is
    /// `target`, decoded locally over readable+executable mappings with optional
    /// module or `[address, address + length)` filtering.
    pub fn code_xrefs_filtered(
        &mut self,
        pid: u32,
        target: u64,
        max_results: usize,
        module_filter: Option<&str>,
        range_filter: Option<(u64, usize)>,
    ) -> Result<Value> {
        ensure!((1..=1024).contains(&max_results), "max_results must be 1-1024");
        Self::pid(pid)?;
        let maps = self.maps(pid)?;
        let entries = maps.as_array().context("Expected maps")?;
        let mod_needle = module_filter.map(|s| s.to_ascii_lowercase());
        let mut exec = Vec::new();
        for entry in entries {
            let protection = entry["protection"].as_u64().unwrap_or(0);
            if protection & 5 != 5 {
                continue;
            }
            let mut start = entry["start"].as_u64().unwrap_or(0);
            let mut end = entry["end"].as_u64().unwrap_or(0);
            let name = entry["name"].as_str().unwrap_or("").to_owned();
            if let Some(ref needle) = mod_needle
                && !name.to_ascii_lowercase().contains(needle)
            {
                continue;
            }
            if let Some((r_start, r_len)) = range_filter {
                let r_end = r_start.saturating_add(r_len as u64);
                start = start.max(r_start);
                end = end.min(r_end);
            }
            if start < end {
                exec.push((start, end, name));
            }
        }
        let cap = if module_filter.is_some() || range_filter.is_some() {
            self.profile
                .limit("transfer_bytes")
                .max(self.profile.limit("memory_bytes"))
                .min(16 * 1024 * 1024) as u64
        } else {
            self.profile.limit("memory_bytes").max(4096) as u64
        };
        let mut refs = Vec::new();
        let mut scanned = 0u64;
        'outer: for (start, end, name) in exec {
            let length = (end - start).min(cap.saturating_sub(scanned));
            if length == 0 {
                break;
            }
            let bytes = self.read_code_fast(pid, start, length as usize)?;
            scanned += bytes.len() as u64;
            let mut position = 0usize;
            while position < bytes.len() {
                let items = disasm::decode(
                    &bytes[position..],
                    start + position as u64,
                    disasm::MAX_INSTRUCTIONS,
                );
                if items.is_empty() {
                    position += 1;
                    continue;
                }
                let last = items.last().unwrap();
                let consumed =
                    ((last.address + last.length as u64) - (start + position as u64)) as usize;
                for item in &items {
                    if item.branch_target == Some(target) || item.memory_target == Some(target) {
                        if refs.len() >= max_results {
                            break 'outer;
                        }
                        let kind = if item.branch_target == Some(target) {
                            match item.flow {
                                "call" | "indirect_call" => "call",
                                _ => "jump",
                            }
                        } else {
                            "rip_relative"
                        };
                        refs.push(json!({"address":format!("{:#x}",item.address),"module":name,
                            "instruction":item.text,"kind":kind,"target":format!("{target:#x}")}));
                    }
                }
                position += consumed.max(1);
            }
            if scanned >= cap {
                break;
            }
        }
        let modules = self.module_bases(pid).unwrap_or_default();
        let target_symbol = Self::annotate(target, &modules).or_else(|| {
            self.labels
                .iter()
                .find(|(_, value)| **value == target)
                .map(|(name, _)| name.clone())
        });
        Ok(json!({
            "target": format!("{target:#x}"),
            "target_symbol": target_symbol,
            "module_filter": module_filter,
            "references": refs,
            "count": refs.len(),
            "scanned_bytes": scanned,
            "truncated": refs.len() >= max_results || scanned >= cap,
            "note": "Decoded locally over readable+executable mappings with own int3 bytes masked",
        }))
    }

    /// Live pattern search (hex bytes with `??` wildcards) over a bounded range,
    /// chunked by page with `(pattern_len - 1)` overlap carry so matches straddling
    /// 4 KiB page boundaries are never missed.
    pub fn memory_search(
        &mut self,
        pid: u32,
        address: u64,
        length: usize,
        pattern: &str,
        max_matches: usize,
    ) -> Result<Value> {
        ensure!((1..=4096).contains(&max_matches), "max_matches must be 1-4096");
        address_range(address, length, self.profile.limit("memory_bytes"))?;
        // Validate pattern once up-front and determine byte width for page-boundary carry.
        let pat_len = crate::analysis::pattern_len(pattern)?;
        let overlap = pat_len.saturating_sub(1);

        let mut matches = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        let mut carry: Vec<u8> = Vec::new();
        let mut carry_addr = address;

        for (chunk_address, chunk_length) in Self::page_chunks(address, length) {
            let content = self.read_memory(pid, chunk_address, chunk_length, false)?;
            scanned += content.len();
            let base = if carry.is_empty() {
                chunk_address
            } else {
                carry_addr
            };
            let mut window = Vec::with_capacity(carry.len() + content.len());
            window.extend_from_slice(&carry);
            window.extend_from_slice(&content);

            let found = crate::analysis::scan_pattern_at(
                &window,
                pattern,
                base,
                max_matches - matches.len(),
            )?;
            if let Some(items) = found["matches"].as_array() {
                for item in items {
                    if !matches.contains(item) {
                        matches.push(item.clone());
                        if matches.len() >= max_matches {
                            break;
                        }
                    }
                }
            }
            if matches.len() >= max_matches {
                truncated = true;
                break;
            }
            let keep = overlap.min(window.len());
            carry.clear();
            if keep > 0 {
                carry.extend_from_slice(&window[window.len() - keep..]);
                carry_addr = base + (window.len() - keep) as u64;
            }
        }
        Ok(json!({
            "address": format!("{address:#x}"),
            "length": length,
            "pattern": pattern,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned,
            "truncated": truncated,
            "note": "Local scan of chunked reads with full 4 KiB page-boundary overlap",
        }))
    }

    /// Assemble or hex-decode a patch at `address`, optionally NOP-pad to the
    /// overwritten instruction boundary, record original bytes, write, and readback-verify.
    pub fn apply_patch(
        &mut self,
        pid: u32,
        address: u64,
        assembly: Option<&str>,
        bytes_hex: Option<&str>,
        nop_pad: bool,
        comment: Option<String>,
    ) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        Self::pid(pid)?;
        ensure!(
            assembly.is_some() ^ bytes_hex.is_some(),
            "Provide exactly one of 'assembly' or 'data_hex'"
        );
        let raw_patch = if let Some(src) = assembly {
            asm::assemble(src, address)?
        } else {
            let s = bytes_hex.unwrap().trim();
            let decoded = hex::decode(s.strip_prefix("0x").unwrap_or(s))?;
            ensure!(
                !decoded.is_empty() && decoded.len() <= asm::MAX_ASM_BYTES,
                "Patch must be 1..={} bytes",
                asm::MAX_ASM_BYTES
            );
            decoded
        };

        let inspect_len = (raw_patch.len() + 15).min(self.profile.limit("memory_bytes"));
        let existing = self.read_memory(pid, address, inspect_len, false)?;
        let (final_patch, nop_padded) =
            asm::pad_patch_over_code(&raw_patch, &existing, address, nop_pad)?;
        ensure!(
            existing.len() >= final_patch.len(),
            "Insufficient readable bytes at {address:#x} to capture original patch window"
        );
        let original = existing[..final_patch.len()].to_vec();

        self.write_memory(pid, address, &final_patch, false)?;
        let readback = self.read_memory(pid, address, final_patch.len(), false)?;
        ensure!(
            readback == final_patch,
            "Patch readback mismatch at {address:#x}; target memory may not be writable (call memory_protect first)"
        );

        let id = self.next_patch_id;
        self.next_patch_id += 1;
        let record = PatchRecord {
            id,
            pid,
            address,
            original: original.clone(),
            patched: final_patch.clone(),
            assembly: assembly.map(str::to_owned),
            nop_padded,
            active: true,
            comment: comment.clone(),
        };
        self.patches.insert(id, record);
        let decoded = disasm::decode(&final_patch, address, disasm::MAX_INSTRUCTIONS);
        Ok(json!({
            "id": id,
            "patch_id": id,
            "pid": pid,
            "address": format!("{address:#x}"),
            "byte_length": final_patch.len(),
            "nop_padded": nop_padded,
            "original_hex": hex::encode(&original),
            "patched_hex": hex::encode(&final_patch),
            "assembly": assembly,
            "comment": comment,
            "instructions": disasm::to_json(&decoded),
            "verified": true,
        }))
    }

    pub fn patch_list(&self, pid: Option<u32>) -> Value {
        let items: Vec<Value> = self
            .patches
            .values()
            .filter(|r| pid.is_none_or(|p| r.pid == p))
            .map(|r| {
                json!({
                    "id": r.id,
                    "patch_id": r.id,
                    "pid": r.pid,
                    "address": format!("{:#x}", r.address),
                    "byte_length": r.patched.len(),
                    "nop_padded": r.nop_padded,
                    "original_hex": hex::encode(&r.original),
                    "patched_hex": hex::encode(&r.patched),
                    "assembly": r.assembly,
                    "comment": r.comment,
                    "active": r.active,
                })
            })
            .collect();
        json!({ "count": items.len(), "patches": items })
    }

    pub fn patch_restore(&mut self, patch_id: u32) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        let record = self
            .patches
            .get(&patch_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Patch {patch_id} not found"))?;
        ensure!(record.active, "Patch {patch_id} is already restored");
        self.write_memory(record.pid, record.address, &record.original, false)?;
        let readback =
            self.read_memory(record.pid, record.address, record.original.len(), false)?;
        ensure!(
            readback == record.original,
            "Patch restore readback mismatch at {:#x}",
            record.address
        );
        if let Some(entry) = self.patches.get_mut(&patch_id) {
            entry.active = false;
        }
        Ok(json!({
            "patch_id": patch_id,
            "pid": record.pid,
            "address": format!("{:#x}", record.address),
            "restored_hex": hex::encode(&record.original),
            "verified": true,
        }))
    }

    /// Stateful multi-pass memory value scanner (`first`, `next`, `get`, `list`, `reset`).
    pub fn memory_scan(&mut self, arguments: &Value) -> Result<Value> {
        let action = arguments["action"]
            .as_str()
            .unwrap_or("first")
            .to_ascii_lowercase();
        let session_id = arguments["session_id"]
            .as_str()
            .unwrap_or("default")
            .to_owned();
        ensure!(
            !session_id.is_empty() && session_id.len() <= 64,
            "session_id must be 1..=64 chars"
        );
        let limit = arguments["limit"]
            .as_u64()
            .map(|n| n as usize)
            .unwrap_or(crate::scanner::DEFAULT_PAGE_LIMIT);
        let offset = arguments["offset"].as_u64().unwrap_or(0) as usize;

        match action.as_str() {
            "list" => return Ok(self.scans.list()),
            "reset" => return Ok(self.scans.reset(&session_id)),
            "get" => {
                let refresh = arguments["refresh"].as_bool().unwrap_or(false);
                if refresh {
                    let pid = arguments["pid"]
                        .as_u64()
                        .map(|n| n as u32)
                        .or(self.attached_pid)
                        .context("pid required when refresh=true without active attachment")?;
                    Self::pid(pid)?;
                    let scans = std::mem::take(&mut self.scans);
                    let mut reader = |addr: u64, len: usize| self.read_memory(pid, addr, len, false);
                    let res = scans.get(&session_id, offset, limit, Some(&mut reader));
                    self.scans = scans;
                    return res;
                }
                return self.scans.get(&session_id, offset, limit, None);
            }
            "first" | "next" => {}
            other => bail!("Unsupported memory_scan action '{other}' (use first, next, get, list, reset)"),
        }

        let pid = arguments["pid"]
            .as_u64()
            .map(|n| n as u32)
            .or(self.attached_pid)
            .context("pid is required when not attached")?;
        Self::pid(pid)?;

        let value_type = match arguments.get("value_type").and_then(Value::as_str) {
            Some(s) => Some(ScanValueType::parse(s)?),
            None => None,
        };
        let default_cmp = if action == "first" {
            "exact"
        } else if arguments.get("value").is_some_and(|v| !v.is_null()) {
            "exact"
        } else {
            "changed"
        };
        let comparison = ScanComparison::parse(
            arguments["comparison"].as_str().unwrap_or(default_cmp),
        )?;
        let stringify = |v: &Value| -> Option<String> {
            match v {
                Value::Null => None,
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(u8::from(*b).to_string()),
                _ => None,
            }
        };
        let req = ScanRequest {
            session_id,
            value_type,
            comparison,
            value: arguments.get("value").and_then(stringify),
            value_max: arguments.get("value_max").and_then(stringify),
            float_epsilon: arguments["float_epsilon"].as_f64().unwrap_or(0.0001),
            case_insensitive: arguments["case_insensitive"].as_bool().unwrap_or(false),
            alignment: arguments["alignment"].as_u64().map(|n| n as usize),
            max_candidates: arguments["max_candidates"]
                .as_u64()
                .map(|n| n as usize)
                .unwrap_or(100_000),
            limit,
            offset,
        };

        let chunk_cap = self.profile.limit("memory_bytes").clamp(4096, 262_144);
        let max_scan_bytes = self
            .profile
            .limit("transfer_bytes")
            .max(chunk_cap)
            .min(64 * 1024 * 1024);

        if action == "first" {
            let writable_only = arguments["writable_only"].as_bool().unwrap_or(false);
            let module_filter = arguments["module"].as_str().map(str::to_ascii_lowercase);
            let explicit_start = match arguments.get("address") {
                Some(Value::Null) | None => None,
                Some(v) => Some(
                    v.as_u64()
                        .or_else(|| parse_hex(v))
                        .context("Invalid scan start address")?,
                ),
            };
            let explicit_len = arguments["length"].as_u64();

            let maps = self.maps(pid)?;
            let mut regions = Vec::new();
            for entry in maps.as_array().context("Expected maps")? {
                let prot = entry["protection"].as_u64().unwrap_or(0) as u32;
                if prot & 1 == 0 || (writable_only && prot & 2 == 0) {
                    continue;
                }
                let name = entry["name"].as_str().unwrap_or("").to_owned();
                if let Some(ref mf) = module_filter
                    && !name.to_ascii_lowercase().contains(mf)
                {
                    continue;
                }
                let mut start = entry["start"].as_u64().unwrap_or(0);
                let mut end = entry["end"].as_u64().unwrap_or(0);
                if let Some(es) = explicit_start {
                    start = start.max(es);
                    if let Some(el) = explicit_len {
                        end = end.min(es.saturating_add(el));
                    }
                }
                if start < end {
                    regions.push(ScanRegion {
                        start,
                        end,
                        name,
                        prot,
                    });
                }
            }
            let mut scans = std::mem::take(&mut self.scans);
            let res = scans.first_scan(
                pid,
                &req,
                &regions,
                chunk_cap,
                max_scan_bytes,
                |addr, len| self.read_memory(pid, addr, len, false),
            );
            self.scans = scans;
            res
        } else {
            let mut scans = std::mem::take(&mut self.scans);
            let res = scans.next_scan(pid, &req, chunk_cap, |addr, len| {
                self.read_memory(pid, addr, len, false)
            });
            self.scans = scans;
            res
        }
    }

    // ---- labels ------------------------------------------------------------

    pub fn label_set(&mut self, name: &str, address: u64) -> Result<Value> {
        let bytes = name.as_bytes();
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && (bytes[0].is_ascii_alphabetic() || matches!(bytes[0], b'_' | b'$' | b'@'))
                && bytes.iter().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$' | b'@')
                }),
            "Invalid label name (use [A-Za-z_$@][A-Za-z0-9_.$@]*, max 128 chars)"
        );
        self.labels.insert(name.to_ascii_lowercase(), address);
        Ok(json!({"name":name.to_ascii_lowercase(),"address":format!("{address:#x}"),"labels":self.label_list()}))
    }

    pub fn label_remove(&mut self, name: &str) -> Result<Value> {
        let removed = self.labels.remove(&name.to_ascii_lowercase());
        Ok(json!({"name":name.to_ascii_lowercase(),"removed":removed.is_some(),"labels":self.label_list()}))
    }

    pub fn label_list(&self) -> Value {
        json!(self
            .labels
            .iter()
            .map(|(name, value)| json!({"name":name,"address":format!("{value:#x}")}))
            .collect::<Vec<_>>())
    }

    pub fn labels_export(&self) -> Value {
        json!({
            "version": 1,
            "labels": self.label_list(),
        })
    }

    pub fn labels_import(&mut self, document: &Value, replace: bool) -> Result<Value> {
        ensure!(document["version"] == 1, "Unsupported label document version");
        let entries = document["labels"].as_array().context("labels array required")?;
        ensure!(entries.len() <= 10_000, "Label document exceeds 10000 entries");
        if replace {
            self.labels.clear();
        }
        let mut loaded = 0usize;
        for entry in entries {
            let name = entry["name"].as_str().context("label name")?;
            let addr = entry["address"]
                .as_u64()
                .or_else(|| parse_hex(&entry["address"]))
                .context("label address")?;
            self.label_set(name, addr)?;
            loaded += 1;
        }
        Ok(json!({
            "loaded": loaded,
            "replaced": replace,
            "labels": self.label_list(),
        }))
    }

    // ---- breakpoint / watchpoint persistence -------------------------------

    /// Export tracked breakpoints and watchpoints as a versioned JSON document
    /// that `breakpoints_import` can re-apply.
    pub fn breakpoints_export(&self) -> Value {
        json!({"version":1,"breakpoints":self.breakpoint_list(),
            "watchpoints":self.watchpoint_list()})
    }

    /// Re-apply a document produced by `breakpoints_export`. Console-mutating:
    /// requires the debug_control permission and qualification.
    pub fn breakpoints_import(&mut self, document: &Value) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        ensure!(document["version"] == 1, "Unsupported breakpoint document version");
        let breakpoints = document["breakpoints"].as_array().context("breakpoints array required")?;
        let watchpoints = document["watchpoints"].as_array().context("watchpoints array required")?;
        ensure!(
            breakpoints.len() <= 30 && watchpoints.len() <= 4,
            "Document exceeds slot counts"
        );
        let mut applied = Vec::new();
        for entry in breakpoints {
            if entry["enabled"].as_bool() == Some(false) {
                continue;
            }
            let index = entry["index"].as_u64().context("breakpoint index")? as u32;
            let address = parse_hex(&entry["address"]).context("breakpoint address")?;
            if self.breakpoints.contains_key(&index) {
                self.breakpoint(index, 0, false)?;
                self.breakpoints.remove(&index);
            }
            self.breakpoint_ex(
                index,
                address,
                true,
                entry["condition"].as_str().map(str::to_owned),
                entry["log"].as_str().map(str::to_owned),
                entry["stop_after"].as_u64().unwrap_or(0),
            )?;
            applied.push(json!({"kind":"breakpoint","index":index,"address":format!("{address:#x}")}));
        }
        for entry in watchpoints {
            if entry["enabled"].as_bool() == Some(false) {
                continue;
            }
            let index = entry["index"].as_u64().context("watchpoint index")? as u32;
            let address = parse_hex(&entry["address"]).context("watchpoint address")?;
            let length = entry["length"].as_u64().context("watchpoint length")? as u32;
            let access = entry["access"].as_str().context("watchpoint access")?;
            if self.watchpoints.contains_key(&index) {
                self.watchpoint(index, 0, 1, "write", false)?;
                self.watchpoints.remove(&index);
            }
            self.watchpoint(index, address, length, access, true)?;
            applied.push(json!({"kind":"watchpoint","index":index,"address":format!("{address:#x}")}));
        }
        Ok(json!({"applied":applied,"count":applied.len(),
            "breakpoints":self.breakpoint_list(),"watchpoints":self.watchpoint_list()}))
    }

    pub fn watchpoint_list(&self) -> Value {
        json!(self
            .watchpoints
            .values()
            .map(|record| json!({"index":record.index,"address":format!("{:#x}",record.address),
                "length":record.length,"access":record.access,"enabled":record.enabled}))
            .collect::<Vec<_>>())
    }
}

struct Live<'a> {
    debugger: &'a mut Debugger,
    pid: Option<u32>,
    registers: Vec<u8>,
    tls: Option<(u64, u64)>,
    modules: Vec<(String, u64, u64)>,
}

impl Context for Live<'_> {
    fn register(&mut self, name: &str) -> Result<Option<u64>> {
        if let Some((fs, gs)) = self.tls {
            match name.to_ascii_lowercase().as_str() {
                "fsbase" | "fs_base" => return Ok(Some(fs)),
                "gsbase" | "gs_base" => return Ok(Some(gs)),
                _ => {}
            }
        }
        Ok(RegisterFile(&self.registers).get(name))
    }
    fn symbol(&mut self, name: &str) -> Result<Option<u64>> {
        let lower = name.to_ascii_lowercase();
        if let Some((fs, gs)) = self.tls {
            match lower.as_str() {
                "fsbase" | "fs_base" => return Ok(Some(fs)),
                "gsbase" | "gs_base" => return Ok(Some(gs)),
                _ => {}
            }
        }
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
        data["permissions"]["process_write"] = json!(true);
        data["jailbreak"]["installed_commit"] = json!("a".repeat(40));
        data["jailbreak"]["hen_build"] = json!("test-hen");
        data["debugger"]["expected_brand"] = json!("ps4debug-NG by Pharaoh2k v1.3.4");
        data["debugger"]["payload_sha256"] = json!("b".repeat(64));
        let path = directory.join("profile.json");
        std::fs::write(&path, data.to_string()).unwrap();
        let profile = Profile::load(path).unwrap();
        let record = json!({
            "profile_sha256": profile.fingerprint(), "attestation": ATTESTATION,
            "approved_permissions": ["debug_control", "process_write"], "debugger_payload_sha256": "b".repeat(64),
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

        // FPU/XMM read + write with readback verification.
        assert_eq!(
            debugger.fpu_registers(1).unwrap()["xmm"].as_array().unwrap().len(),
            16
        );
        let fpu_set = debugger
            .set_fpu_registers(1, &json!({ "xmm0": { "f32": [100.0, 2.5] }, "mxcsr": "0x1f80" }))
            .unwrap();
        assert_eq!(fpu_set["verified"], true);
        assert_eq!(debugger.fpu_registers(1).unwrap()["mxcsr"], "0x00001f80");
        assert!(debugger.hardware_debug_registers(1).unwrap()["dr7"].is_string());

        // TLS FS/GS base read + write + expression evaluation.
        let tls = debugger.tls_bases(1).unwrap();
        assert_eq!(tls["fsbase"], "0x80010000");
        let tls_set = debugger.set_tls_bases(1, Some(0x8002_0000), None).unwrap();
        assert_eq!(tls_set["verified"], true);
        assert_eq!(
            debugger.evaluate("fsbase + 0x28", Some(77), Some(1)).unwrap()["value"],
            "0x80020028"
        );

        // VM alloc, protect (with trailing CMD_DATA_NULL drain!), patch, scan, restore, free.
        let alloc = debugger.memory_alloc(77, 0x4000, Some(0x5000_0000)).unwrap();
        assert_eq!(alloc["address"], "0x50000000");
        assert_eq!(alloc["verified_in_maps"], true);
        let prot = debugger.memory_protect(77, 0x5000_0000, 0x4000, 7).unwrap();
        assert_eq!(prot["verified"], true);
        assert_eq!(prot["drained_trailing_status"], "0xf0000003");
        // Verify persistent socket remained 100% synchronized after CMD_PROC_PROTECT!
        let patch = debugger
            .apply_patch(
                77,
                0x1004,
                Some("xor eax, eax"),
                None,
                true,
                Some("skip call +0x10".to_owned()),
            )
            .unwrap();
        assert_eq!(patch["verified"], true);
        assert_eq!(patch["nop_padded"], 3); // 5-byte call -> 2-byte xor + 3 NOPs!
        assert_eq!(patch["patched_hex"], "31c0909090");
        let restored = debugger.patch_restore(patch["patch_id"].as_u64().unwrap() as u32).unwrap();
        assert_eq!(restored["verified"], true);
        assert_eq!(restored["restored_hex"], "e810000000");
        debugger.memory_free(77, 0x5000_0000, 0x4000).unwrap();

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

        // Step out resolves [rbp+8] = FAKE_RET = 0x1500 even when [rsp] is saved rbp!
        let step_out = debugger.step("out", 1, Duration::from_secs(5)).unwrap();
        assert!(step_out["plan"].as_str().unwrap().starts_with("run_to_temp_breakpoint"));

        // Run to the tracked breakpoint address with log interpolation & stop_after.
        debugger
            .breakpoint_ex(
                0,
                0x1009,
                true,
                Some("rax == 0".to_owned()),
                Some("hit rip={rip}".to_owned()),
                0,
            )
            .unwrap();
        let run = debugger
            .run(Some(0x1009), None, 4, Duration::from_secs(5))
            .unwrap();
        assert_eq!(run["stop_count"], 1);
        assert_eq!(run["stops"][0]["target_hit"], true);
        assert_eq!(run["breakpoints"][0]["hits"], 1);
        assert!(run["stops"][0]["log_message"].as_str().unwrap().starts_with("hit rip=0x"));

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

        // Per-breakpoint stop_after=3 keeps running until the 3rd hit!
        debugger
            .breakpoint_ex(0, 0x1009, true, None, None, 3)
            .unwrap();
        let run_thresh = debugger.run(None, None, 5, Duration::from_secs(5)).unwrap();
        assert_eq!(run_thresh["stop_count"], 3);
        assert_eq!(run_thresh["stops"][2]["stop_after_hit"], true);

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

    #[test]
    fn memory_search_crosses_page_boundary_and_finds_multiple_matches() {
        let fake = fake::spawn_debuggable();
        let directory = tempfile::tempdir().unwrap();
        let profile = qualified_profile(directory.path(), fake.port);
        let mut debugger = Debugger::new(profile);

        // Allocate 2 pages (0x2000 bytes) at 0x20_0000 and plant a 4-byte signature
        // straddling 0x20_0ffe..0x20_1002 plus a second occurrence at 0x20_1040.
        debugger.memory_alloc(77, 0x2000, Some(0x20_0000)).unwrap();
        debugger
            .write_memory(77, 0x20_0ffe, &[0xde, 0xad, 0xbe, 0xef], false)
            .unwrap();
        debugger
            .write_memory(77, 0x20_1040, &[0xde, 0xad, 0xca, 0xfe], false)
            .unwrap();

        let found = debugger
            .memory_search(77, 0x20_0000, 0x1100, "de ad ?? ??", 16)
            .unwrap();
        assert_eq!(found["count"], 2);
        assert_eq!(found["matches"], json!(["0x200ffe", "0x201040"]));
    }
}
