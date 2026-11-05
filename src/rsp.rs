use crate::Result;
use crate::client::BrokerClient;
use crate::config::require_integer;
use anyhow::{anyhow, bail};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::LazyLock;
use std::time::Duration;

pub const MAX_PACKET: usize = 16384;
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const CORE_NAMES: [&str; 24] = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"];
const FPU_NAMES: [&str; 8] = ["fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop"];
const MUTATING_PREFIXES: [&str; 9] = ["M", "X", "G", "P", "k", "vKill", "R", "vRun", "qRcmd"];

pub static REGISTER_LAYOUT: LazyLock<Vec<(String, usize)>> = LazyLock::new(|| {
    let mut layout: Vec<(String, usize)> = CORE_NAMES.iter().enumerate()
        .map(|(index, name)| (name.to_string(), if index < 17 { 64 } else { 32 })).collect();
    layout.extend((0..8).map(|index| (format!("st{index}"), 80)));
    layout.extend(FPU_NAMES.iter().map(|name| (name.to_string(), 32)));
    layout.extend((0..16).map(|index| (format!("xmm{index}"), 128)));
    layout.push(("mxcsr".to_string(), 32));
    layout
});

pub static TARGET_XML: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let core_regs: String = REGISTER_LAYOUT[..40].iter().enumerate().map(|(index, (name, bits))| {
        let kind = if *bits == 80 { "i387_ext" } else { "int" };
        format!("<reg name=\"{name}\" bitsize=\"{bits}\" regnum=\"{index}\" type=\"{kind}\"/>")
    }).collect();
    let sse_regs: String = REGISTER_LAYOUT[40..].iter().enumerate().map(|(offset, (name, bits))| {
        let index = 40 + offset;
        let kind = if *bits == 128 { "uint128" } else { "int" };
        format!("<reg name=\"{name}\" bitsize=\"{bits}\" regnum=\"{index}\" type=\"{kind}\"/>")
    }).collect();
    format!(
        "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target><architecture>i386:x86-64</architecture><osabi>FreeBSD</osabi><feature name=\"org.gnu.gdb.i386.core\">{core_regs}</feature><feature name=\"org.gnu.gdb.i386.sse\">{sse_regs}</feature></target>"
    ).into_bytes()
});

fn bounded(value: i128, name: &str, minimum: i128, maximum: i128) -> Result<i128> {
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        bail!("{name} must be an integer in [{minimum}, {maximum}]")
    }
}

pub fn parse_hex(text: &str) -> Result<i128> {
    let trimmed = text.trim();
    let (negative, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")).unwrap_or(unsigned);
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_hexdigit()) {
        bail!("invalid literal for int() with base 16: {text:?}");
    }
    let magnitude = i128::from_str_radix(digits, 16).map_err(|_| anyhow!("Hexadecimal value out of range"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

pub fn numeric(value: &Value) -> Result<u64> {
    match value {
        Value::String(text) => {
            let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(digits) => u64::from_str_radix(digits, 16).ok(),
                None => text.parse::<u64>().ok(),
            };
            parsed.ok_or_else(|| anyhow!("Invalid numeric value: {text:?}"))
        }
        other => other.as_u64().ok_or_else(|| anyhow!("Expected an unsigned integer")),
    }
}

fn identifier(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(|| anyhow!("Expected a numeric thread identifier"))
}

fn to_u64(value: i128, name: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow!("{name} exceeds uint64"))
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn memory_map_xml(mappings: &[Value]) -> Result<Vec<u8>> {
    let mut regions = String::new();
    for entry in mappings {
        let protection = entry.get("protection").and_then(Value::as_u64).ok_or_else(|| anyhow!("Mapping lacks protection"))?;
        if protection & 1 != 0 {
            let start = numeric(entry.get("start").unwrap_or(&Value::Null))?;
            let end = numeric(entry.get("end").unwrap_or(&Value::Null))?;
            let length = end.checked_sub(start).ok_or_else(|| anyhow!("Mapping ends before it starts"))?;
            regions.push_str(&format!("<memory type=\"ram\" start=\"{start:#x}\" length=\"{length:#x}\"/>"));
        }
    }
    Ok(format!("<?xml version=\"1.0\"?><memory-map>{regions}</memory-map>").into_bytes())
}

pub fn libraries_svr4_xml(modules: &[Value]) -> Result<Vec<u8>> {
    let mut libs = String::new();
    let mut seen = HashSet::new();
    for entry in modules {
        let Some(raw_name) = entry.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) else {
            continue;
        };
        let addr_val = entry.get("base").or_else(|| entry.get("start")).unwrap_or(&Value::Null);
        let Ok(base) = numeric(addr_val) else {
            continue;
        };
        if !seen.insert(raw_name.to_string()) {
            continue;
        }
        let escaped = xml_escape(raw_name);
        libs.push_str(&format!(
            "<library name=\"{escaped}\" lm=\"0x0\" l_addr=\"{base:#x}\" l_ld=\"0x0\"/>"
        ));
    }
    Ok(format!("<?xml version=\"1.0\"?><library-list-svr4 version=\"1.0\">{libs}</library-list-svr4>").into_bytes())
}

pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(payload.len() + 4);
    for &value in payload {
        if matches!(value, 35 | 36 | 42 | 125) {
            encoded.extend([125, value ^ 32]);
        } else {
            encoded.push(value);
        }
    }
    let checksum = encoded.iter().fold(0u8, |total, value| total.wrapping_add(*value));
    let mut framed = Vec::with_capacity(encoded.len() + 4);
    framed.push(b'$');
    framed.extend(encoded);
    framed.extend(format!("#{checksum:02x}").into_bytes());
    framed
}

pub fn merge_fpu_registers(target: &mut serde_json::Map<String, Value>, fpu: &Value) {
    let Some(obj) = fpu.as_object() else {
        return;
    };
    for (src, dst) in [
        ("fcw", "fctrl"),
        ("fsw", "fstat"),
        ("ftw", "ftag"),
        ("fop", "fop"),
        ("mxcsr", "mxcsr"),
    ] {
        if let Some(v) = obj.get(src).and_then(Value::as_str) {
            target.insert(dst.to_string(), Value::String(v.to_string()));
        }
    }
    for (src, dst) in [("fip", "fioff"), ("fdp", "fooff")] {
        if let Some(v) = obj.get(src)
            && let Ok(n) = numeric(v)
        {
            target.insert(dst.to_string(), Value::String(format!("{:#x}", n as u32)));
        }
    }
    if let Some(st) = obj.get("st").and_then(Value::as_array) {
        for (i, item) in st.iter().take(8).enumerate() {
            if let Some(s) = item.as_str()
                && s.len() == 20
                && s.chars().all(|c| c.is_ascii_hexdigit())
            {
                target.insert(format!("st{i}"), Value::String(format!("le:{s}")));
            }
        }
    }
    if let Some(xmm) = obj.get("xmm").and_then(Value::as_array) {
        for (i, item) in xmm.iter().take(16).enumerate() {
            if let Some(s) = item.as_str()
                && s.len() == 32
                && s.chars().all(|c| c.is_ascii_hexdigit())
            {
                target.insert(format!("xmm{i}"), Value::String(format!("le:{s}")));
            }
        }
    }
}

pub fn register_bytes(values: &Value) -> Result<Vec<u8>> {
    let mut output = String::new();
    for (name, bits) in REGISTER_LAYOUT.iter() {
        let source = if name == "eflags" { "rflags" } else { name.as_str() };
        match values.get(source) {
            None | Some(Value::Null) => output.push_str(&"xx".repeat(bits / 8)),
            Some(Value::String(text)) => {
                if let Some(raw_le) = text.strip_prefix("le:") {
                    if raw_le.len() != bits / 4 || !raw_le.chars().all(|c| c.is_ascii_hexdigit()) {
                        bail!("Invalid little-endian register bytes for {source}");
                    }
                    output.push_str(&raw_le.to_ascii_lowercase());
                } else {
                    let digits = text.trim();
                    let unsigned = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")).unwrap_or(digits);
                    if unsigned.is_empty() || !unsigned.chars().all(|c| c.is_ascii_hexdigit()) {
                        bail!("invalid literal for int() with base 16: {text:?}");
                    }
                    let number = u128::from_str_radix(unsigned, 16)
                        .map_err(|_| anyhow!("Hexadecimal value out of range"))?;
                    let mask = if *bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
                    let masked = number & mask;
                    output.push_str(&hex::encode(&masked.to_le_bytes()[..bits / 8]));
                }
            }
            Some(_) => bail!("Register {source} must be a hexadecimal string"),
        }
    }
    Ok(output.into_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Interrupt,
    Ack,
    Nak,
    BadChecksum,
    Packet(Vec<u8>),
}

#[derive(Default)]
pub struct PacketDecoder {
    buffer: Vec<u8>,
}

impl PacketDecoder {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Message>> {
        self.buffer.extend_from_slice(data);
        let mut messages = Vec::new();
        while let Some(&first) = self.buffer.first() {
            let control = match first {
                3 => Some(Message::Interrupt),
                43 => Some(Message::Ack),
                45 => Some(Message::Nak),
                36 => None,
                _ => bail!("Invalid RSP framing"),
            };
            if let Some(message) = control {
                messages.push(message);
                self.buffer.remove(0);
                continue;
            }
            let Some(delimiter) = self.buffer[1..].iter().position(|value| *value == b'#').map(|offset| offset + 1) else {
                if self.buffer.len() > MAX_PACKET {
                    bail!("RSP packet exceeds limit");
                }
                break;
            };
            if delimiter > MAX_PACKET {
                bail!("RSP packet exceeds limit");
            }
            if self.buffer.len() < delimiter + 3 {
                break;
            }
            let encoded = self.buffer[1..delimiter].to_vec();
            let checksum = std::str::from_utf8(&self.buffer[delimiter + 1..delimiter + 3]).ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok());
            self.buffer.drain(..delimiter + 3);
            if checksum != Some(encoded.iter().fold(0u8, |total, value| total.wrapping_add(*value))) {
                messages.push(Message::BadChecksum);
                continue;
            }
            let mut decoded = Vec::with_capacity(encoded.len());
            let mut escaped = false;
            for value in encoded {
                if escaped {
                    decoded.push(value ^ 32);
                    escaped = false;
                } else if value == 125 {
                    escaped = true;
                } else if value == 42 {
                    bail!("Client-side RSP run-length encoding unsupported");
                } else {
                    decoded.push(value);
                }
            }
            if escaped {
                bail!("Truncated RSP escape");
            }
            messages.push(Message::Packet(decoded));
        }
        Ok(messages)
    }
}

pub struct RspSession {
    client: BrokerClient,
    pid: u32,
    listen_address: String,
    observer: bool,
    pub allow_writes: bool,
    thread_id: Option<u64>,
    continue_thread: Option<u64>,
    cursor: u64,
    last_stop: Option<Vec<u8>>,
    pub awaiting_stop: bool,
    attached_here: bool,
    breakpoints: HashMap<(i128, u64, i128), i128>,
    pub finished: bool,
    pub no_ack: bool,
    session_id: Value,
    map_xml: Option<Vec<u8>>,
    libs_xml: Option<Vec<u8>>,
}

fn chunk(content: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let marker = if offset + length >= content.len() { b'l' } else { b'm' };
    let start = offset.min(content.len());
    let end = (offset + length).min(content.len());
    let mut reply = vec![marker];
    reply.extend_from_slice(&content[start..end]);
    reply
}

fn transfer_range(command: &str, label: &str) -> Result<(usize, usize)> {
    let range = command.rsplit(':').next().unwrap_or_default();
    let parts: Vec<&str> = range.split(',').collect();
    if parts.len() != 2 {
        bail!("Malformed qXfer range");
    }
    let offset = bounded(parse_hex(parts[0])?, &format!("{label} offset"), 0, 0xFFFF_FFFF)?;
    let length = bounded(parse_hex(parts[1])?, &format!("{label} chunk"), 1, MAX_PACKET as i128 - 1)?;
    Ok((offset as usize, length as usize))
}

impl RspSession {
    pub fn new(client: BrokerClient, pid: u32, listen_address: &str, observer: bool) -> Result<Self> {
        require_integer(&json!(pid), "pid", 1, 0x7FFF_FFFF)?;
        let cursor = client.state()?.get("event_cursor").and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("Broker state lacks an event cursor"))?;
        Ok(Self {
            client,
            pid,
            listen_address: listen_address.to_string(),
            observer,
            allow_writes: false,
            thread_id: None,
            continue_thread: None,
            cursor,
            last_stop: None,
            awaiting_stop: false,
            attached_here: false,
            breakpoints: HashMap::new(),
            finished: false,
            no_ack: false,
            session_id: Value::Null,
            map_xml: None,
            libs_xml: None,
        })
    }

    pub fn with_writes(mut self, allow_writes: bool) -> Self {
        self.allow_writes = allow_writes && !self.observer;
        self
    }

    fn ensure_attached(&mut self) -> Result<()> {
        let state = self.client.state()?;
        match state.get("attached_pid").and_then(Value::as_u64) {
            None => {
                if self.observer {
                    bail!("Observer requires an existing attached session");
                }
                self.client.call("debug_attach", json!({"pid": self.pid, "listen_address": self.listen_address}))?;
                self.attached_here = true;
            }
            Some(attached) if attached != u64::from(self.pid) => bail!("Another process is already attached"),
            Some(_) => {
                if !self.observer && state.get("controller").and_then(Value::as_str) != Some(self.client.client_id()) {
                    bail!("Another client owns the session; use a separate observer bridge");
                }
            }
        }
        self.session_id = self.client.state()?.get("session_id").cloned().unwrap_or(Value::Null);
        Ok(())
    }

    fn require_control(&mut self) -> Result<()> {
        if self.observer {
            bail!("Observer debugger cannot mutate or resume the target");
        }
        self.ensure_attached()
    }

    fn threads(&self) -> Result<Vec<u64>> {
        let listing = self.client.call("debug_threads", json!({}))?;
        listing.as_array().ok_or_else(|| anyhow!("Thread list must be an array"))?.iter().map(identifier).collect()
    }

    fn current_thread(&mut self) -> Result<u64> {
        self.ensure_attached()?;
        if let Some(thread_id) = self.thread_id {
            return Ok(thread_id);
        }
        let first = *self.threads()?.first().ok_or_else(|| anyhow!("No thread available"))?;
        self.thread_id = Some(first);
        Ok(first)
    }

    pub fn stop_reply(&mut self, event: &Value) -> Result<Vec<u8>> {
        let thread_id = identifier(event.get("thread_id").unwrap_or(&Value::Null))?;
        self.thread_id = Some(thread_id);
        let status = event.get("status").and_then(Value::as_u64).ok_or_else(|| anyhow!("Stop event lacks status"))?;
        if status & 255 != 127 {
            bail!("Unsupported non-stop wait status; inspect broker event journal");
        }
        let signal = match (status >> 8) & 255 {
            signal @ (2 | 4 | 5 | 8 | 10 | 11 | 17) => signal,
            19 => 17,
            _ => bail!("Unmapped FreeBSD stop signal; inspect broker event journal"),
        };
        Ok(format!("T{signal:02x}thread:{thread_id:x};").into_bytes())
    }

    pub fn poll_stop(&mut self) -> Result<Option<Vec<u8>>> {
        let events = self.client.events(self.cursor, 64)?;
        self.cursor = events.get("cursor").and_then(Value::as_u64).ok_or_else(|| anyhow!("Event page lacks a cursor"))?;
        if events.get("lost_events").and_then(Value::as_u64).unwrap_or(0) != 0 {
            bail!("Debug events were lost; target state is uncertain");
        }
        let mut reply = None;
        for event in events.get("events").and_then(Value::as_array).cloned().unwrap_or_default() {
            match event.get("type").and_then(Value::as_str) {
                Some("session_error" | "detached") => bail!("Shared debugger state changed or failed; inspect broker"),
                Some("stop") => {
                    if event.get("session_id").cloned().unwrap_or(Value::Null) != self.session_id {
                        continue;
                    }
                    let stop = self.stop_reply(&event)?;
                    self.last_stop = Some(stop.clone());
                    reply = Some(stop);
                }
                _ => {}
            }
        }
        if self.awaiting_stop && reply.is_some() {
            self.awaiting_stop = false;
            return Ok(reply);
        }
        Ok(None)
    }

    fn read_memory(&mut self, address: u64, length: i128) -> Result<Vec<u8>> {
        self.ensure_attached()?;
        let length = bounded(length, "RSP memory length", 0, (MAX_PACKET / 2) as i128)? as usize;
        if length == 0 {
            return Ok(Vec::new());
        }
        let result = self.client.call("memory_peek", json!({"pid": self.pid, "address": format!("{address:#x}"), "length": length}))?;
        let content = hex::decode(result.get("hex").and_then(Value::as_str).unwrap_or_default())?;
        if content.len() != length {
            bail!("Short broker memory capture");
        }
        Ok(hex::encode(content).into_bytes())
    }

    fn write_memory(&mut self, rest: &str) -> Result<Vec<u8>> {
        self.require_control()?;
        let Some((header, hex_body)) = rest.split_once(':') else {
            bail!("Malformed memory write packet");
        };
        let parts: Vec<&str> = header.split(',').collect();
        if parts.len() != 2 {
            bail!("Malformed memory write header");
        }
        let address = to_u64(parse_hex(parts[0])?, "Memory address")?;
        let length = bounded(parse_hex(parts[1])?, "RSP memory write length", 0, (MAX_PACKET / 2) as i128)? as usize;
        let decoded = hex::decode(hex_body)?;
        if decoded.len() != length {
            bail!("Memory write payload length mismatch");
        }
        if length == 0 {
            return Ok(b"OK".to_vec());
        }
        let peeked = self.client.call("memory_peek", json!({
            "pid": self.pid,
            "address": format!("{address:#x}"),
            "length": length,
        }))?;
        let expected_hex = peeked.get("hex").and_then(Value::as_str)
            .ok_or_else(|| anyhow!("memory_peek lacked hex"))?;
        self.client.call("memory_write", json!({
            "pid": self.pid,
            "address": format!("{address:#x}"),
            "hex_data": hex::encode(&decoded),
            "expected_hex": expected_hex,
        }))?;
        Ok(b"OK".to_vec())
    }

    fn decode_register_slot(index: usize, le_hex: &str) -> Result<(&'static str, String, Value)> {
        if index >= REGISTER_LAYOUT.len() {
            bail!("Register index out of range");
        }
        let (name, bits) = &REGISTER_LAYOUT[index];
        if le_hex.len() != bits / 4 {
            bail!("Register {name} expects {} hex chars", bits / 4);
        }
        let raw = hex::decode(le_hex)?;
        if index < 18 {
            let reg_name = if name == "eflags" { "rflags" } else { name.as_str() };
            let val = if *bits == 64 {
                u64::from_le_bytes(raw.try_into().map_err(|_| anyhow!("Invalid 64-bit reg"))?)
            } else {
                u64::from(u32::from_le_bytes(raw.try_into().map_err(|_| anyhow!("Invalid 32-bit reg"))?))
            };
            return Ok(("gp", reg_name.to_string(), Value::String(format!("{val:#x}"))));
        }
        if (24..32).contains(&index) || (40..56).contains(&index) {
            return Ok(("fpu", name.clone(), Value::String(hex::encode(raw))));
        }
        let fpu_scalar = match name.as_str() {
            "fctrl" => Some("fcw"),
            "fstat" => Some("fsw"),
            "ftag" => Some("ftw"),
            "fop" => Some("fop"),
            "mxcsr" => Some("mxcsr"),
            _ => None,
        };
        if let Some(key) = fpu_scalar {
            let val = u32::from_le_bytes(raw.try_into().map_err(|_| anyhow!("Invalid 32-bit FPU reg"))?);
            return Ok(("fpu", key.to_string(), Value::String(format!("{val:#x}"))));
        }
        bail!("Register {name} is read-only via RSP")
    }

    fn write_single_register(&mut self, rest: &str) -> Result<Vec<u8>> {
        self.require_control()?;
        let Some((idx_str, le_hex)) = rest.split_once('=') else {
            bail!("Malformed register write packet");
        };
        let index = bounded(parse_hex(idx_str)?, "register index", 0, REGISTER_LAYOUT.len() as i128 - 1)? as usize;
        let thread_id = self.current_thread()?;
        let (group, key, val) = Self::decode_register_slot(index, le_hex)?;
        let mut regs = serde_json::Map::new();
        regs.insert(key, val);
        let tool = if group == "gp" { "debug_registers_set" } else { "debug_registers_fpu_set" };
        self.client.call(tool, json!({
            "thread_id": thread_id,
            "registers": Value::Object(regs),
        }))?;
        Ok(b"OK".to_vec())
    }

    fn write_all_registers(&mut self, all_hex: &str) -> Result<Vec<u8>> {
        self.require_control()?;
        let total_chars: usize = REGISTER_LAYOUT.iter().map(|(_, bits)| bits / 4).sum();
        let gp_chars: usize = REGISTER_LAYOUT[..18].iter().map(|(_, bits)| bits / 4).sum();
        if all_hex.len() != total_chars && all_hex.len() != gp_chars {
            bail!("Malformed G register block length");
        }
        let thread_id = self.current_thread()?;
        let mut gp_regs = serde_json::Map::new();
        let mut fpu_regs = serde_json::Map::new();
        let mut offset = 0usize;
        for (index, (_, bits)) in REGISTER_LAYOUT.iter().enumerate() {
            let width = bits / 4;
            if offset + width > all_hex.len() {
                break;
            }
            let slice = &all_hex[offset..offset + width];
            offset += width;
            if slice.chars().any(|c| matches!(c, 'x' | 'X')) {
                continue;
            }
            if let Ok((group, key, val)) = Self::decode_register_slot(index, slice) {
                if group == "gp" {
                    gp_regs.insert(key, val);
                } else {
                    fpu_regs.insert(key, val);
                }
            }
        }
        if !gp_regs.is_empty() {
            self.client.call("debug_registers_set", json!({
                "thread_id": thread_id,
                "registers": Value::Object(gp_regs),
            }))?;
        }
        if !fpu_regs.is_empty() {
            self.client.call("debug_registers_fpu_set", json!({
                "thread_id": thread_id,
                "registers": Value::Object(fpu_regs),
            }))?;
        }
        Ok(b"OK".to_vec())
    }

    fn set_breakpoint(&mut self, command: &str) -> Result<Vec<u8>> {
        self.require_control()?;
        let parts: Vec<&str> = command[1..].split(',').collect();
        if parts.len() != 3 {
            bail!("Malformed breakpoint packet");
        }
        let kind = parse_hex(parts[0])?;
        let address = to_u64(parse_hex(parts[1])?, "Breakpoint address")?;
        let length = parse_hex(parts[2])?;
        if ![0, 1, 2, 4].contains(&kind) {
            return Ok(Vec::new());
        }
        if kind == 0 && length != 1 {
            bail!("x86 software breakpoints require one-byte kind");
        }
        let key = (kind, address, length);
        let (index, enabled) = if command.starts_with('z') {
            match self.breakpoints.get(&key) {
                None => return Ok(b"OK".to_vec()),
                Some(index) => (*index, false),
            }
        } else {
            if self.breakpoints.contains_key(&key) {
                return Ok(b"OK".to_vec());
            }
            let used: HashSet<i128> = self.breakpoints.iter()
                .filter(|((other, _, _), _)| (*other == 0) == (kind == 0)).map(|(_, index)| *index).collect();
            let slots = if kind == 0 { 30 } else { 4 };
            let index = (0..slots).find(|slot| !used.contains(slot)).ok_or_else(|| anyhow!("No breakpoint slots available"))?;
            (index, true)
        };
        if kind == 0 {
            self.client.call("debug_breakpoint", json!({"index": index as i64, "address": format!("{address:#x}"), "enabled": enabled}))?;
        } else {
            let access = match kind { 1 => "execute", 2 => "write", _ => "read_write" };
            let length = i64::try_from(length).map_err(|_| anyhow!("Watchpoint length out of range"))?;
            self.client.call("debug_watchpoint", json!({"index": index as i64, "address": format!("{address:#x}"),
                "length": length, "access": access, "enabled": enabled}))?;
        }
        if enabled {
            self.breakpoints.insert(key, index);
        } else {
            self.breakpoints.remove(&key);
        }
        Ok(b"OK".to_vec())
    }

    fn resume(&mut self, step: bool, thread_id: Option<u64>) -> Result<Option<Vec<u8>>> {
        self.require_control()?;
        if self.last_stop.is_none() {
            bail!("Wait for a real stop event before resuming or stepping");
        }
        self.cursor = self.client.state()?.get("event_cursor").and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("Broker state lacks an event cursor"))?;
        if step {
            let selected = match thread_id.filter(|value| *value != 0).or(self.continue_thread) {
                Some(selected) => selected,
                None => self.current_thread()?,
            };
            self.client.call("debug_control", json!({"action": "step_thread", "thread_id": selected}))?;
        } else {
            if thread_id.is_some() {
                bail!("Thread-specific continue is not implemented; use all-stop continue");
            }
            self.client.call("debug_control", json!({"action": "resume"}))?;
        }
        self.last_stop = None;
        self.awaiting_stop = true;
        Ok(None)
    }

    fn query_stop(&mut self) -> Result<Option<Vec<u8>>> {
        self.ensure_attached()?;
        let state = self.client.state()?;
        let stopped = state.get("execution_state").and_then(Value::as_str) == Some("stopped");
        if self.last_stop.is_some() && stopped {
            return Ok(self.last_stop.clone());
        }
        if self.observer {
            if !stopped {
                bail!("Observer requires the controller to stop the target first");
            }
            let event = state.get("last_stop").cloned().unwrap_or(Value::Null);
            if !event.is_null() && event.get("session_id").cloned().unwrap_or(Value::Null) == self.session_id {
                self.last_stop = Some(self.stop_reply(&event)?);
            }
            if self.last_stop.is_some() {
                return Ok(self.last_stop.clone());
            }
        }
        self.awaiting_stop = true;
        self.poll_stop()
    }

    pub fn interrupt(&mut self) -> Result<()> {
        self.require_control()?;
        self.client.call("debug_control", json!({"action": "halt"}))?;
        self.awaiting_stop = true;
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.attached_here {
            self.client.call("debug_detach", json!({}))?;
            self.attached_here = false;
        }
        Ok(())
    }

    pub fn handle(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if !payload.is_ascii() {
            bail!("RSP packet must be ASCII");
        }
        let command = std::str::from_utf8(payload)?;
        let reply = |text: &str| -> Result<Option<Vec<u8>>> { Ok(Some(text.as_bytes().to_vec())) };
        if command.starts_with("qSupported") {
            return reply("PacketSize=4000;qXfer:features:read+;qXfer:memory-map:read+;qXfer:libraries-svr4:read+;QStartNoAckMode+");
        }
        if command == "QStartNoAckMode" {
            self.no_ack = true;
            return reply("OK");
        }
        if command.starts_with("qXfer:features:read:target.xml:") {
            let (offset, length) = transfer_range(command, "XML")?;
            return Ok(Some(chunk(&TARGET_XML, offset, length)));
        }
        if command.starts_with("qXfer:memory-map:read::") {
            self.ensure_attached()?;
            let (offset, length) = transfer_range(command, "map XML")?;
            if offset == 0 {
                let mappings = self.client.call("process_maps", json!({"pid": self.pid}))?;
                let Some(entries) = mappings.as_array() else {
                    bail!("Large map list requires artifact inspection");
                };
                self.map_xml = Some(memory_map_xml(entries)?);
            }
            let Some(content) = &self.map_xml else {
                bail!("Begin a memory map transfer at offset zero");
            };
            return Ok(Some(chunk(content, offset, length)));
        }
        if command.starts_with("qXfer:libraries-svr4:read::") {
            self.ensure_attached()?;
            let (offset, length) = transfer_range(command, "libraries XML")?;
            if offset == 0 {
                let modules = match self.client.call("module_list", json!({"pid": self.pid})) {
                    Ok(Value::Array(items)) => items,
                    _ => {
                        let mappings = self.client.call("process_maps", json!({"pid": self.pid}))?;
                        mappings.as_array().cloned().ok_or_else(|| anyhow!("Large map list requires artifact inspection"))?
                    }
                };
                self.libs_xml = Some(libraries_svr4_xml(&modules)?);
            }
            let Some(content) = &self.libs_xml else {
                bail!("Begin a libraries transfer at offset zero");
            };
            return Ok(Some(chunk(content, offset, length)));
        }
        if command == "?" {
            return self.query_stop();
        }
        if let Some(rest) = command.strip_prefix("vAttach;") {
            if parse_hex(rest)? != i128::from(self.pid) {
                bail!("Attach PID differs from explicitly configured PID");
            }
            return self.query_stop();
        }
        if command == "qAttached" {
            return reply("1");
        }
        if command == "qC" {
            let thread_id = self.current_thread()?;
            return reply(&format!("QC{thread_id:x}"));
        }
        if command == "qfThreadInfo" {
            self.ensure_attached()?;
            let threads = self.threads()?;
            if threads.is_empty() {
                return reply("l");
            }
            let listed: Vec<String> = threads.iter().map(|thread_id| format!("{thread_id:x}")).collect();
            return reply(&format!("m{}", listed.join(",")));
        }
        if command == "qsThreadInfo" {
            return reply("l");
        }
        if command.starts_with("Hg") || command.starts_with("Hc") {
            let selected = parse_hex(&command[2..])?;
            let thread_id = if matches!(selected, -1 | 0) { None } else { Some(to_u64(selected, "Thread")?) };
            if let Some(thread_id) = thread_id
                && !self.threads()?.contains(&thread_id) {
                    bail!("Unknown thread");
                }
            if command.as_bytes()[1] == b'g' {
                self.thread_id = thread_id;
            } else {
                self.continue_thread = thread_id;
            }
            return reply("OK");
        }
        if let Some(rest) = command.strip_prefix('T') {
            let selected = parse_hex(rest)?;
            let known = self.threads()?.iter().any(|thread_id| i128::from(*thread_id) == selected);
            return reply(if known { "OK" } else { "E01" });
        }
        if command == "g" || command.starts_with('p') {
            let thread_id = self.current_thread()?;
            let mut values = self.client.call("debug_registers", json!({"thread_id": thread_id}))?;
            if let Some(map) = values.as_object_mut()
                && let Ok(fpu) = self.client.call("debug_registers_fpu", json!({"thread_id": thread_id}))
            {
                merge_fpu_registers(map, &fpu);
            }
            let content = register_bytes(&values)?;
            if command == "g" {
                return Ok(Some(content));
            }
            let index = bounded(parse_hex(&command[1..])?, "register index", 0, REGISTER_LAYOUT.len() as i128 - 1)? as usize;
            let offset: usize = REGISTER_LAYOUT[..index].iter().map(|(_, bits)| bits / 4).sum();
            return Ok(Some(content[offset..offset + REGISTER_LAYOUT[index].1 / 4].to_vec()));
        }
        if let Some(rest) = command.strip_prefix('m') {
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() != 2 {
                bail!("Malformed memory read packet");
            }
            let address = to_u64(parse_hex(parts[0])?, "Memory address")?;
            return Ok(Some(self.read_memory(address, parse_hex(parts[1])?)?));
        }
        if self.allow_writes {
            if let Some(rest) = command.strip_prefix('M') {
                return Ok(Some(self.write_memory(rest)?));
            }
            if let Some(rest) = command.strip_prefix('P') {
                return Ok(Some(self.write_single_register(rest)?));
            }
            if let Some(rest) = command.strip_prefix('G') {
                return Ok(Some(self.write_all_registers(rest)?));
            }
            if command.starts_with('X') {
                // Returning empty packet tells GDB binary `X` is unsupported so it falls back to hex `M`.
                return reply("");
            }
        }
        if command.starts_with('Z') || command.starts_with('z') {
            return Ok(Some(self.set_breakpoint(command)?));
        }
        if command == "vCont?" {
            return reply("vCont;c;s");
        }
        if let Some(rest) = command.strip_prefix("vCont;") {
            let actions: Vec<&str> = rest.split(';').collect();
            if actions.len() != 1 {
                bail!("Mixed per-thread vCont actions are unsupported");
            }
            let (action, selected) = actions[0].split_once(':').unwrap_or((actions[0], ""));
            if action != "c" && action != "s" {
                return reply("");
            }
            let thread_id = if selected.is_empty() { None } else { Some(to_u64(parse_hex(selected)?, "Thread")?) };
            return self.resume(action == "s", thread_id);
        }
        if command == "c" || command == "s" {
            return self.resume(command == "s", None);
        }
        if command == "D" || command == format!("D;{:x}", self.pid) {
            self.cleanup()?;
            self.finished = true;
            return reply("OK");
        }
        if MUTATING_PREFIXES.iter().any(|prefix| command.starts_with(prefix)) {
            return reply("E01");
        }
        reply("")
    }
}

fn send(stream: &mut TcpStream, response: &[u8], last_frame: &mut Option<Vec<u8>>) -> Result<()> {
    let framed = frame(response);
    stream.write_all(&framed)?;
    *last_frame = Some(framed);
    Ok(())
}

pub fn serve_connection(mut stream: TcpStream, session: &mut RspSession) -> Result<()> {
    stream.set_read_timeout(Some(POLL_INTERVAL))?;
    let _ = stream.set_nodelay(true);
    let mut decoder = PacketDecoder::default();
    let mut last_frame: Option<Vec<u8>> = None;
    let mut last_request: Option<Vec<u8>> = None;
    let mut unacknowledged = false;
    let mut buffer = vec![0u8; MAX_PACKET];
    while !session.finished {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                for message in decoder.feed(&buffer[..count])? {
                    let payload = match message {
                        Message::Ack => {
                            unacknowledged = false;
                            continue;
                        }
                        Message::Nak => {
                            if let Some(previous) = &last_frame {
                                stream.write_all(previous)?;
                            }
                            continue;
                        }
                        Message::BadChecksum => {
                            if !session.no_ack {
                                stream.write_all(b"-")?;
                            }
                            continue;
                        }
                        Message::Interrupt => None,
                        Message::Packet(payload) => {
                            if !session.no_ack {
                                stream.write_all(b"+")?;
                            }
                            if unacknowledged && last_request.as_ref() == Some(&payload) {
                                if let Some(previous) = &last_frame {
                                    stream.write_all(previous)?;
                                }
                                continue;
                            }
                            Some(payload)
                        }
                    };
                    let outcome = match payload {
                        None => session.interrupt().map(|_| None),
                        Some(payload) => {
                            if session.awaiting_stop && last_request.as_ref() == Some(&payload) {
                                continue;
                            }
                            let outcome = session.handle(&payload);
                            if outcome.is_ok() {
                                last_request = Some(payload);
                            }
                            outcome
                        }
                    };
                    if let Some(response) = outcome.unwrap_or_else(|_| Some(b"E01".to_vec())) {
                        send(&mut stream, &response, &mut last_frame)?;
                        unacknowledged = !session.no_ack;
                    }
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
        if session.awaiting_stop {
            let response = session.poll_stop().unwrap_or_else(|_| {
                session.awaiting_stop = false;
                Some(b"E01".to_vec())
            });
            if let Some(response) = response {
                send(&mut stream, &response, &mut last_frame)?;
                unacknowledged = !session.no_ack;
            }
        }
    }
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    client: &BrokerClient,
    pid: u32,
    callback_ip: &str,
    observer: bool,
    allow_writes: bool,
) -> Result<()> {
    let identity = client.with_identity(&format!("gdb-{}", uuid::Uuid::new_v4().simple()))?;
    let mut session = RspSession::new(identity, pid, callback_ip, observer)?.with_writes(allow_writes);
    let outcome = serve_connection(stream, &mut session);
    let cleanup = session.cleanup();
    outcome.and(cleanup)
}

pub fn serve_listener_with_options(
    listener: TcpListener,
    client: &BrokerClient,
    pid: u32,
    callback_ip: &str,
    observer: bool,
    allow_writes: bool,
) -> Result<()> {
    require_integer(&json!(pid), "pid", 1, 0x7FFF_FFFF)?;
    for stream in listener.incoming().flatten() {
        let _ = handle_connection(stream, client, pid, callback_ip, observer, allow_writes);
    }
    Ok(())
}

pub fn serve_listener(listener: TcpListener, client: &BrokerClient, pid: u32, callback_ip: &str, observer: bool) -> Result<()> {
    serve_listener_with_options(listener, client, pid, callback_ip, observer, false)
}

pub fn serve_with_options(
    client: BrokerClient,
    pid: u32,
    callback_ip: &str,
    port: u16,
    observer: bool,
    allow_writes: bool,
) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    serve_listener_with_options(listener, &client, pid, callback_ip, observer, allow_writes)
}

pub fn serve(client: BrokerClient, pid: u32, callback_ip: &str, port: u16, observer: bool) -> Result<()> {
    serve_with_options(client, pid, callback_ip, port, observer, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testing::{fixture, run};
    use std::sync::{Arc, Mutex};

    #[test]
    fn packet_fragmentation_and_escaping() {
        let mut decoder = PacketDecoder::default();
        let encoded = frame(b"test#$}*");
        assert!(decoder.feed(&encoded[..4]).unwrap().is_empty());
        assert_eq!(decoder.feed(&encoded[4..]).unwrap(), vec![Message::Packet(b"test#$}*".to_vec())]);
    }

    #[test]
    fn bad_checksum_does_not_produce_command() {
        assert_eq!(PacketDecoder::default().feed(b"$c#00").unwrap(), vec![Message::BadChecksum]);
    }

    #[test]
    fn decoder_handles_ack_interrupt_and_multiple_packets() {
        let mut input = b"+\x03-".to_vec();
        input.extend(frame(b"g"));
        input.extend(frame(b"?"));
        assert_eq!(PacketDecoder::default().feed(&input).unwrap(), vec![Message::Ack, Message::Interrupt, Message::Nak,
            Message::Packet(b"g".to_vec()), Message::Packet(b"?".to_vec())]);
    }

    #[test]
    fn oversized_and_invalid_framing_rejected() {
        let mut oversized = b"$".to_vec();
        oversized.extend(vec![b'A'; 16385]);
        assert!(PacketDecoder::default().feed(&oversized).is_err());
        assert!(PacketDecoder::default().feed(b"x").is_err());
        assert!(PacketDecoder::default().feed(b"$a*b#ed").is_err());
        assert!(PacketDecoder::default().feed(b"$a}#de").is_err());
    }

    #[test]
    fn target_description_matches_encoded_register_bytes() {
        assert!(TARGET_XML.len() < 4096, "TARGET_XML must fit in a single 0x1000 qXfer packet");
        let description = String::from_utf8(TARGET_XML.clone()).unwrap();
        assert_eq!(description.matches("<reg ").count(), REGISTER_LAYOUT.len());
        assert!(description.contains("<reg name=\"st0\" bitsize=\"80\" regnum=\"24\" type=\"i387_ext\"/>"));
        assert!(description.contains("<feature name=\"org.gnu.gdb.i386.sse\">"));
        assert!(description.contains("<reg name=\"xmm0\" bitsize=\"128\" regnum=\"40\" type=\"uint128\"/>"));
        assert!(description.contains("<reg name=\"mxcsr\" bitsize=\"32\" regnum=\"56\" type=\"int\"/>"));
        let mut map = serde_json::Map::new();
        map.insert("rax".into(), json!("0x1234"));
        map.insert("rflags".into(), json!("0x202"));
        merge_fpu_registers(&mut map, &json!({
            "mxcsr": "0x1f80",
            "xmm": ["0102030405060708090a0b0c0d0e0f10"],
            "st": ["112233445566778899aa"],
        }));
        let values = register_bytes(&Value::Object(map)).unwrap();
        assert!(values.starts_with(b"3412000000000000"));
        assert_eq!(values.len(), REGISTER_LAYOUT.iter().map(|(_, bits)| bits / 4).sum::<usize>());
        let text = String::from_utf8(values).unwrap();
        assert!(text.contains("xxxxxxxx"));
        assert!(text.contains("0102030405060708090a0b0c0d0e0f10"));
        assert!(text.contains("112233445566778899aa"));
        assert!(text.ends_with("801f0000"));
    }

    #[test]
    fn memory_map_and_svr4_libraries_xml() {
        let mappings = [json!({"start": 16384, "end": 32768, "protection": 5}),
            json!({"start": "0x9000", "end": "0xa000", "protection": 2})];
        let content = String::from_utf8(memory_map_xml(&mappings).unwrap()).unwrap();
        assert!(content.contains("start=\"0x4000\" length=\"0x4000\""));
        assert!(!content.contains("0x9000"));

        let modules = [
            json!({"name": "eboot.bin", "base": "0x400000"}),
            json!({"name": "libSce&Test.sprx", "base": "0x80000000"}),
        ];
        let libs = String::from_utf8(libraries_svr4_xml(&modules).unwrap()).unwrap();
        assert!(libs.contains("<library-list-svr4 version=\"1.0\">"));
        assert!(libs.contains("<library name=\"eboot.bin\" lm=\"0x0\" l_addr=\"0x400000\" l_ld=\"0x0\"/>"));
        assert!(libs.contains("name=\"libSce&amp;Test.sprx\""));
    }

    #[test]
    fn hexadecimal_parsing_matches_python_int() {
        assert_eq!(parse_hex("-1").unwrap(), -1);
        assert_eq!(parse_hex("0x1f").unwrap(), 31);
        assert_eq!(parse_hex("ff").unwrap(), 255);
        assert!(parse_hex("").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn session_rejects_mutation_and_enforces_observer() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let client = BrokerClient::new(&running.url, &fixture.token_path, "gdb", None).unwrap();
        let mut session = RspSession::new(client.clone(), 71, "127.0.0.1", false).unwrap();
        for packet in [&b"M4000,1:ff"[..], b"P0=00", b"G00", b"k", b"vKill;47", b"qRcmd,00", b"X4000,0:"] {
            assert_eq!(session.handle(packet).unwrap(), Some(b"E01".to_vec()));
        }
        let supported = String::from_utf8(session.handle(b"qSupported:xmlRegisters=i386").unwrap().unwrap()).unwrap();
        assert!(supported.starts_with("PacketSize=4000"));
        assert!(supported.contains("qXfer:libraries-svr4:read+"));
        assert!(session.handle(b"qXfer:features:read:target.xml:0,100").unwrap().unwrap().starts_with(b"m<?xml"));
        assert!(session.handle(b"qXfer:features:read:target.xml:0,3fff").unwrap().unwrap().starts_with(b"l<?xml"));
        assert!(session.handle(b"vAttach;48").unwrap_err().to_string().contains("PID differs"));
        assert_eq!(session.handle(b"vCont?").unwrap(), Some(b"vCont;c;s".to_vec()));
        assert_eq!(session.handle(b"qUnknown").unwrap(), Some(Vec::new()));
        assert_eq!(session.stop_reply(&json!({"thread_id": 72, "status": 0x57F})).unwrap(), b"T05thread:48;".to_vec());
        assert!(session.stop_reply(&json!({"thread_id": 72, "status": 0})).is_err());
        assert!(session.handle(b"c").is_err());
        let mut observer = RspSession::new(client.with_identity("ghidra").unwrap(), 71, "127.0.0.1", true).unwrap();
        for packet in [&b"?"[..], b"c", b"s", b"Z0,4000,1", b"m4000,4", b"g"] {
            assert!(observer.handle(packet).is_err());
        }
        assert!(observer.interrupt().unwrap_err().to_string().contains("Observer"));
        assert!(fixture.hub.state()["attached_pid"].is_null());
        assert!(fixture.hub.state()["controller"].is_null());
    }

    #[test]
    fn opt_in_writes_fpu_reads_and_svr4_libraries_over_mock_broker() {
        let dir = tempfile::tempdir().unwrap();
        let token = "ab".repeat(32);
        let token_path = dir.path().join("token.local");
        std::fs::write(&token_path, &token).unwrap();

        let calls: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_srv = calls.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut data = Vec::new();
                let mut chunk = [0u8; 4096];
                let body_offset = loop {
                    let Ok(n) = stream.read(&mut chunk) else { break None };
                    if n == 0 {
                        break None;
                    }
                    data.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let hdr = String::from_utf8_lossy(&data[..pos]);
                        let content_len = hdr
                            .lines()
                            .find_map(|line| {
                                let (k, v) = line.split_once(':')?;
                                k.trim().eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + content_len {
                            break Some((pos + 4, pos + 4 + content_len));
                        }
                    }
                };
                let Some((start, end)) = body_offset else { continue };
                let Ok(val) = serde_json::from_slice::<Value>(&data[start..end]) else { continue };
                let op = val["operation"].as_str().unwrap_or("");
                let result = match op {
                    "state" => json!({
                        "profile_sha256": "c".repeat(64),
                        "attached_pid": 71,
                        "controller": "gdb-rw",
                        "execution_state": "stopped",
                        "session_id": "s1",
                        "event_cursor": 1,
                    }),
                    "call" => {
                        let tool = val["arguments"]["name"].as_str().unwrap_or("").to_string();
                        let args = val["arguments"]["arguments"].clone();
                        calls_srv.lock().unwrap().push((tool.clone(), args));
                        match tool.as_str() {
                            "debug_threads" => json!([72]),
                            "debug_registers" => json!({"rax": "0x1234", "rflags": "0x202"}),
                            "debug_registers_fpu" => json!({
                                "fcw": "0x037f",
                                "mxcsr": "0x1f80",
                                "xmm": ["aabbccddeeff00112233445566778899"],
                            }),
                            "module_list" => json!([{"name": "eboot.bin", "base": "0x400000"}]),
                            "memory_peek" => json!({"hex": "9090"}),
                            "memory_write" | "debug_registers_set" | "debug_registers_fpu_set" => json!({"verified": true}),
                            _ => json!({}),
                        }
                    }
                    _ => json!({}),
                };
                let resp_body = json!({"ok": true, "result": result}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let client = BrokerClient::new(&format!("http://127.0.0.1:{port}"), &token_path, "gdb-rw", None).unwrap();
        let mut session = RspSession::new(client, 71, "127.0.0.1", false).unwrap().with_writes(true);

        // Read xmm0 (reg 40 = 0x28) & SVR4 libraries.
        assert_eq!(
            session.handle(b"p28").unwrap().unwrap(),
            b"aabbccddeeff00112233445566778899".to_vec()
        );
        let libs = String::from_utf8(session.handle(b"qXfer:libraries-svr4:read::0,1000").unwrap().unwrap()).unwrap();
        assert!(libs.starts_with("l<?xml"));
        assert!(libs.contains("eboot.bin"));

        // Binary X returns empty so GDB falls back to hex M; M, P (GP & XMM), and G succeed!
        assert_eq!(session.handle(b"X4000,0:").unwrap().unwrap(), b"".to_vec());
        assert_eq!(session.handle(b"M4000,2:c390").unwrap().unwrap(), b"OK".to_vec());
        assert_eq!(session.handle(b"P0=efbeadde00000000").unwrap().unwrap(), b"OK".to_vec());
        assert_eq!(
            session.handle(b"P28=00112233445566778899aabbccddeeff").unwrap().unwrap(),
            b"OK".to_vec()
        );
        // Kill / monitor commands are STILL rejected even with allow_writes=true!
        assert_eq!(session.handle(b"k").unwrap().unwrap(), b"E01".to_vec());
        assert_eq!(session.handle(b"qRcmd,00").unwrap().unwrap(), b"E01".to_vec());

        let log = calls.lock().unwrap();
        assert!(log.iter().any(|(t, a)| t == "memory_write" && a["expected_hex"] == "9090" && a["hex_data"] == "c390"));
        assert!(log.iter().any(|(t, a)| t == "debug_registers_set" && a["registers"]["rax"] == "0xdeadbeef"));
        assert!(log.iter().any(|(t, a)| t == "debug_registers_fpu_set" && a["registers"]["xmm0"] == "00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn real_socket_negotiation_and_detach() {
        let fixture = fixture();
        let running = run(fixture.hub.clone(), fixture.token.clone());
        let client = BrokerClient::new(&running.url, &fixture.token_path, "gdb-bridge", None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || serve_listener(listener, &client, 71, "127.0.0.1", false));
        let mut connection = TcpStream::connect(address).unwrap();
        connection.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut decoder = PacketDecoder::default();
        let mut exchange = |command: &[u8]| -> Vec<u8> {
            connection.write_all(&frame(command)).unwrap();
            let mut buffer = [0u8; 16384];
            loop {
                let count = connection.read(&mut buffer).unwrap();
                assert!(count > 0);
                for message in decoder.feed(&buffer[..count]).unwrap() {
                    if let Message::Packet(payload) = message {
                        connection.write_all(b"+").unwrap();
                        return payload;
                    }
                }
            }
        };
        assert!(exchange(b"qSupported").starts_with(b"PacketSize=4000"));
        assert!(exchange(b"qXfer:features:read:target.xml:0,1000").starts_with(b"l<?xml"));
        assert_eq!(exchange(b"M4000,1:ff"), b"E01".to_vec());
        assert_eq!(exchange(b"QStartNoAckMode"), b"OK".to_vec());
        assert_eq!(exchange(b"D"), b"OK".to_vec());
        assert!(fixture.hub.state()["attached_pid"].is_null());
    }
}
