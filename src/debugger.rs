use crate::{Result, config::Profile, link};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::Instant,
};

mod ops;
pub use ops::BreakpointRecord;

#[derive(Debug, Clone)]
pub struct WatchpointRecord {
    pub index: u32,
    pub address: u64,
    pub length: u32,
    pub access: String,
    pub enabled: bool,
}

pub const MAGIC: u32 = 0xffaabbcc;
pub const SUCCESS: u32 = 0x80000000;
pub const EVENT_SIZE: usize = 1184;

pub fn address_range(address: u64, length: usize, maximum: usize) -> Result<()> {
    ensure!(length > 0 && length <= maximum, "Invalid transfer length");
    ensure!(
        address as u128 + length as u128 <= 1u128 << 64,
        "Address range overflows uint64"
    );
    Ok(())
}

fn cstring(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned()
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn registers(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() == 176,
        "GP register block must be exactly 176 bytes"
    );
    let mut result = json!({});
    for (index, name) in [
        "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rdi", "rsi", "rbp", "rbx", "rdx",
        "rcx", "rax",
    ]
    .iter()
    .enumerate()
    {
        result[name] = json!(format!("{:#x}", qword(bytes, index * 8)));
    }
    for (name, offset, size) in [
        ("trapno", 120, 4),
        ("fs", 124, 2),
        ("gs", 126, 2),
        ("err", 128, 4),
        ("es", 132, 2),
        ("ds", 134, 2),
        ("rip", 136, 8),
        ("cs", 144, 8),
        ("rflags", 152, 8),
        ("rsp", 160, 8),
        ("ss", 168, 8),
    ] {
        let value = match size {
            2 => u16::from_le_bytes(bytes[offset..offset + 2].try_into()?) as u64,
            4 => word(bytes, offset) as u64,
            _ => qword(bytes, offset),
        };
        result[name] = json!(format!("{value:#x}"));
    }
    Ok(result)
}

pub struct Debugger {
    profile: Profile,
    connection: Option<TcpStream>,
    events: Option<TcpStream>,
    event_buffer: Vec<u8>,
    deadline: Instant,
    pub identity: Option<Value>,
    pub attached_pid: Option<u32>,
    pub breakpoints: std::collections::BTreeMap<u32, BreakpointRecord>,
    pub watchpoints: std::collections::BTreeMap<u32, WatchpointRecord>,
    stash: Vec<Value>,
    pub labels: std::collections::BTreeMap<String, u64>,
}

impl Debugger {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            connection: None,
            events: None,
            event_buffer: Vec::new(),
            deadline: Instant::now(),
            identity: None,
            attached_pid: None,
            breakpoints: Default::default(),
            watchpoints: Default::default(),
            stash: Vec::new(),
            labels: Default::default(),
        }
    }

    fn reset(&mut self) {
        self.connection = None;
        self.events = None;
        self.identity = None;
        self.attached_pid = None;
        self.breakpoints.clear();
        self.watchpoints.clear();
        self.event_buffer.clear();
    }

    fn socket(&self) -> Result<&TcpStream> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .context("Debugger deadline exceeded; state may be uncertain")?;
        let connection = self.connection.as_ref().context("No debugger connection")?;
        connection.set_read_timeout(Some(remaining))?;
        connection.set_write_timeout(Some(remaining))?;
        Ok(connection)
    }

    fn read(&self, length: usize) -> Result<Vec<u8>> {
        let mut content = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let mut connection = self.socket()?;
            let count = connection.read(&mut content[offset..])?;
            ensure!(count > 0, "Debugger disconnected mid-response");
            offset += count;
        }
        Ok(content)
    }

    fn write(&self, content: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < content.len() {
            let mut connection = self.socket()?;
            let count = connection.write(&content[offset..])?;
            ensure!(count > 0, "Debugger disconnected during write");
            offset += count;
        }
        Ok(())
    }

    fn packet(&self, command: u32, body: &[u8]) -> Result<()> {
        let mut content = Vec::with_capacity(12 + body.len());
        content.extend(MAGIC.to_le_bytes());
        content.extend(command.to_le_bytes());
        content.extend((body.len() as u32).to_le_bytes());
        content.extend(body);
        self.write(&content)
    }

    fn status(&self) -> Result<()> {
        let status = word(&self.read(4)?, 0);
        ensure!(
            status == SUCCESS,
            "Debugger rejected command: {status:#010x}"
        );
        Ok(())
    }

    fn text(&self) -> Result<String> {
        let length = word(&self.read(4)?, 0) as usize;
        ensure!((1..=1024).contains(&length), "Invalid identity length");
        Ok(String::from_utf8(self.read(length)?)?)
    }

    fn connect(&mut self) -> Result<()> {
        if self.connection.is_some() {
            return Ok(());
        }
        let address: SocketAddr =
            format!("{}:{}", self.profile.host(), self.profile.port("debug")).parse()?;
        self.connection = Some(TcpStream::connect_timeout(
            &address,
            self.profile.timeout(),
        )?);
        self.packet(0xbd000001, &[])?;
        let version = self.text()?.trim_end_matches('\0').to_owned();
        ensure!(
            version == self.profile.data["debugger"]["protocol"],
            "Unsupported debugger protocol"
        );
        self.packet(0xbd000501, &[])?;
        let branding = self.text()?;
        let (brand, capability) = branding.split_once('\0').unwrap_or((&branding, ""));
        ensure!(
            brand.starts_with("ps4debug-NG by Pharaoh2k v"),
            "Unknown debugger branding; no legacy fallback"
        );
        if let Some(expected) = self.profile.data["debugger"]["expected_brand"].as_str() {
            ensure!(
                brand == expected,
                "Debugger brand differs from pinned profile"
            );
        }
        self.packet(0xbd000500, &[])?;
        let encoded = u16::from_le_bytes(self.read(2)?.try_into().unwrap());
        let firmware = format!("{}.{:02}", encoded / 100, encoded % 100);
        ensure!(
            firmware == self.profile.data["firmware"],
            "Debugger firmware mismatch: {firmware}"
        );
        self.packet(0xbd000502, &[])?;
        let platform = u16::from_le_bytes(self.read(2)?.try_into().unwrap());
        ensure!(platform == 4, "Debugger does not identify as PS4");
        self.identity = Some(
            json!({"brand":brand,"capability":capability.trim_end_matches('\0'),"protocol":version,"firmware":firmware,
            "platform":platform,"firmware_encoding":"decimal_major_times_100","binary_hash_remotely_verified":false,"hardware_compatibility_guaranteed":false}),
        );
        Ok(())
    }

    fn exchange<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let attached = self.attached_pid;
        self.deadline = Instant::now() + self.profile.timeout();
        let result = self.connect().and_then(|()| action(self));
        match result {
            Ok(value) => {
                link::record_ok("debug");
                Ok(value)
            }
            Err(error) => {
                link::record_err("debug", &error);
                self.reset();
                Err(Self::lost(error, attached))
            }
        }
    }

    /// For read-only commands only: when the connection fails transiently and no
    /// attachment exists to lose, reconnect (re-running the identity handshake)
    /// and repeat the read once. Mutations must use `exchange`.
    fn exchange_read<T>(
        &mut self,
        mut action: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let attached = self.attached_pid;
        for attempt in 0..2 {
            self.deadline = Instant::now() + self.profile.timeout();
            match self.connect().and_then(|()| action(self)) {
                Ok(value) => {
                    link::record_ok("debug");
                    return Ok(value);
                }
                Err(error) => {
                    link::record_err("debug", &error);
                    self.reset();
                    if attempt == 0 && attached.is_none() && link::is_transient(&error) {
                        link::record_retry("debug");
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        continue;
                    }
                    return Err(Self::lost(error, attached));
                }
            }
        }
        unreachable!("loop returns on both attempts")
    }

    fn lost(error: anyhow::Error, attached: Option<u32>) -> anyhow::Error {
        match attached {
            Some(pid) => error.context(format!(
                "Debugger connection lost while attached to pid {pid}; the attachment was cleared locally and the console-side state is uncertain. Call debug_attach again"
            )),
            None => error,
        }
    }

    pub fn close(&mut self) -> Result<()> {
        if self.attached_pid.is_some() {
            self.detach()?;
        } else {
            self.reset();
        }
        Ok(())
    }

    pub fn probe(&mut self) -> Result<Value> {
        self.exchange_read(|debugger| Ok(debugger.identity.clone().unwrap()))
    }

    fn list(
        &mut self,
        command: u32,
        body: &[u8],
        size: usize,
        decode: impl Fn(&[u8]) -> Result<Value>,
    ) -> Result<Value> {
        self.exchange_read(|debugger| {
            debugger.packet(command, body)?;
            debugger.status()?;
            let count = word(&debugger.read(4)?, 0) as usize;
            ensure!(
                count <= debugger.profile.limit("list_entries"),
                "Server entry count exceeds configured limit"
            );
            let mut result = Vec::with_capacity(count);
            for _ in 0..count {
                result.push(decode(&debugger.read(size)?)?);
            }
            Ok(json!(result))
        })
    }

    pub fn processes(&mut self) -> Result<Value> {
        self.list(0xbdaa0001, &[], 36, |data| {
            Ok(json!({"pid":word(data,32),"name":cstring(&data[..32])}))
        })
    }

    pub fn maps(&mut self, pid: u32) -> Result<Value> {
        Self::pid(pid)?;
        self.list(0xbdaa0004,&pid.to_le_bytes(),64,|data| {
            ensure!(qword(data,8)>=qword(data,0),"Invalid map range");
            Ok(json!({"start":qword(data,0),"end":qword(data,8),"offset":qword(data,16),"protection":qword(data,24),"name":cstring(&data[32..])}))
        })
    }

    pub fn process_info(&mut self, pid: u32) -> Result<Value> {
        Self::pid(pid)?;
        self.exchange(|debugger| {
            debugger.packet(0xbdaa000a,&pid.to_le_bytes())?; debugger.status()?;
            let data=debugger.read(188)?;
            Ok(json!({"pid":word(&data,0),"name":cstring(&data[4..44]),"path":cstring(&data[44..108]),"title_id":cstring(&data[108..124]),"content_id":cstring(&data[124..188])}))
        })
    }

    pub fn require_qualified_debugger(&self, permission: &str) -> Result<()> {
        let qualification = self.profile.require(permission)?;
        let settings = &self.profile.data["debugger"];
        ensure!(
            settings["expected_brand"].is_string() && settings["payload_sha256"].is_string(),
            "Pin actual debugger brand and binary hash before privileged access"
        );
        ensure!(
            qualification["debugger_payload_sha256"] == settings["payload_sha256"],
            "Debugger hash differs from qualification"
        );
        Ok(())
    }

    fn memory_body(pid: u32, address: u64, length: usize, kernel: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if !kernel {
            body.extend(pid.to_le_bytes());
        }
        body.extend(address.to_le_bytes());
        body.extend((length as u32).to_le_bytes());
        body
    }

    pub fn read_memory(
        &mut self,
        pid: u32,
        address: u64,
        length: usize,
        kernel: bool,
    ) -> Result<Vec<u8>> {
        address_range(address, length, self.profile.limit("memory_bytes"))?;
        if kernel {
            self.require_qualified_debugger("kernel_read")?;
        } else {
            Self::pid(pid)?;
        }
        self.exchange_read(|debugger| {
            debugger.packet(
                if kernel { 0xbdcc0002 } else { 0xbdaa0002 },
                &Self::memory_body(pid, address, length, kernel),
            )?;
            debugger.status()?;
            debugger.read(length)
        })
    }

    pub fn write_memory(
        &mut self,
        pid: u32,
        address: u64,
        content: &[u8],
        kernel: bool,
    ) -> Result<()> {
        self.require_qualified_debugger(if kernel {
            "kernel_write"
        } else {
            "process_write"
        })?;
        address_range(address, content.len(), self.profile.limit("memory_bytes"))?;
        if !kernel {
            Self::pid(pid)?;
        }
        self.exchange(|debugger| {
            ensure!(
                kernel || debugger.identity.as_ref().unwrap()["capability"] == "1.1",
                "Writes require capability 1.1 verified-write semantics"
            );
            debugger.packet(
                if kernel { 0xbdcc0003 } else { 0xbdaa0003 },
                &Self::memory_body(pid, address, content.len(), kernel),
            )?;
            debugger.status()?;
            debugger.write(content)?;
            debugger.status()
        })
    }

    pub fn kernel_base(&mut self) -> Result<Value> {
        self.require_qualified_debugger("kernel_read")?;
        self.exchange_read(|debugger| {
            debugger.packet(0xbdcc0001, &[])?;
            debugger.status()?;
            Ok(json!({"kernel_base":format!("{:#x}",qword(&debugger.read(8)?,0))}))
        })
    }

    fn pid(pid: u32) -> Result<()> {
        ensure!(pid > 0 && pid <= i32::MAX as u32, "Invalid PID/thread ID");
        Ok(())
    }
    fn session(&self) -> Result<()> {
        ensure!(self.attached_pid.is_some(), "No active debugger session");
        Ok(())
    }

    pub fn attach(&mut self, pid: u32, listen_address: &str) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        Self::pid(pid)?;
        ensure!(self.attached_pid.is_none(), "Already attached");
        let interface: Ipv4Addr = listen_address.parse()?;
        ensure!(
            !interface.is_unspecified() && !interface.is_multicast() && !interface.is_broadcast(),
            "Explicit local callback IPv4 required"
        );
        self.exchange(|debugger| {
            let listener = TcpListener::bind((interface, 755))?;
            listener.set_nonblocking(true)?;
            let mut body = pid.to_le_bytes().to_vec();
            body.extend(interface.octets());
            debugger.packet(0xbdbb0001, &body)?;
            debugger.status()?;
            debugger.attached_pid = Some(pid);
            loop {
                ensure!(
                    Instant::now() < debugger.deadline,
                    "Callback accept timed out; attachment state uncertain"
                );
                match listener.accept() {
                    Ok((events, peer)) => {
                        ensure!(
                            peer.ip().to_string() == debugger.profile.host(),
                            "Unexpected debug callback peer"
                        );
                        events.set_nonblocking(true)?;
                        debugger.events = Some(events);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(json!({"attached_pid":pid,"callback_address":listen_address,"callback_port":755}))
        })
    }

    pub fn detach(&mut self) -> Result<Value> {
        if self.attached_pid.is_none() {
            return Ok(json!({"detached":false}));
        }
        let result = self.exchange(|debugger| {
            debugger.packet(0xbdbb0002, &[])?;
            debugger.status()?;
            Ok(json!({"detached":true}))
        });
        self.reset();
        result
    }

    pub fn threads(&mut self) -> Result<Value> {
        self.session()?;
        self.list(0xbdbb0005, &[], 4, |data| Ok(json!(word(data, 0))))
    }
    pub fn thread_info(&mut self, thread_id: u32) -> Result<Value> {
        self.session()?;
        Self::pid(thread_id)?;
        self.exchange_read(|debugger| {
            debugger.packet(0xbdbb0011, &thread_id.to_le_bytes())?;
            debugger.status()?;
            let data = debugger.read(40)?;
            Ok(json!({"thread_id":word(&data,0),"priority":word(&data,4),"name":cstring(&data[8..40])}))
        })
    }
    pub fn get_registers(&mut self, thread_id: u32) -> Result<Value> {
        self.session()?;
        Self::pid(thread_id)?;
        self.exchange(|debugger| {
            debugger.packet(0xbdbb0008, &thread_id.to_le_bytes())?;
            debugger.status()?;
            registers(&debugger.read(176)?)
        })
    }

    pub fn control(&mut self, action: &str, thread_id: u32) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        let (command, body) = match action {
            "resume" | "halt" => (
                0xbdbb0010,
                u32::from(action == "halt").to_le_bytes().to_vec(),
            ),
            "step" => (0xbdbb0012, vec![]),
            "step_thread" | "suspend_thread" | "resume_thread" => {
                Self::pid(thread_id)?;
                (
                    match action {
                        "step_thread" => 0xbdbb0013,
                        "suspend_thread" => 0xbdbb0006,
                        _ => 0xbdbb0007,
                    },
                    thread_id.to_le_bytes().to_vec(),
                )
            }
            _ => bail!("Unsupported debugger action"),
        };
        self.exchange(|debugger| {
            debugger.packet(command, &body)?;
            debugger.status()?;
            Ok(json!({"action":action,"acknowledged":true}))
        })
    }

    pub fn breakpoint(&mut self, index: u32, address: u64, enabled: bool) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        ensure!(index < 30, "Invalid breakpoint index");
        let mut body = index.to_le_bytes().to_vec();
        body.extend(u32::from(enabled).to_le_bytes());
        body.extend(address.to_le_bytes());
        self.exchange(|debugger| {
            debugger.packet(0xbdbb0003, &body)?;
            debugger.status()?;
            Ok(json!({"index":index,"address":format!("{address:#x}"),"enabled":enabled}))
        })
    }

    pub fn watchpoint(
        &mut self,
        index: u32,
        address: u64,
        length: u32,
        access: &str,
        enabled: bool,
    ) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        self.session()?;
        ensure!(
            index < 4 && [1, 2, 4, 8].contains(&length),
            "Invalid watchpoint slot/length"
        );
        address_range(address, length as usize, 8)?;
        ensure!(
            address.is_multiple_of(length as u64) && (access != "execute" || length == 1),
            "Watchpoint must be aligned; execute length is 1"
        );
        let access_name = access;
        let access: u32 = match access {
            "execute" => 0,
            "write" => 1,
            "read_write" => 3,
            _ => bail!("Invalid watchpoint access"),
        };
        let encoding: u32 = match length {
            1 => 0,
            2 => 1,
            4 => 3,
            _ => 2,
        };
        let mut body = index.to_le_bytes().to_vec();
        body.extend(u32::from(enabled).to_le_bytes());
        body.extend(encoding.to_le_bytes());
        body.extend(access.to_le_bytes());
        body.extend(address.to_le_bytes());
        let result = self.exchange(|debugger| {
            debugger.packet(0xbdbb0004, &body)?;
            debugger.status()?;
            Ok(json!({"index":index,"enabled":enabled}))
        });
        if result.is_ok() {
            if enabled {
                self.watchpoints.insert(
                    index,
                    WatchpointRecord { index, address, length, access: access_name.to_owned(), enabled },
                );
            } else {
                self.watchpoints.remove(&index);
            }
        }
        result
    }

    pub fn poll_events(&mut self) -> Result<Value> {
        self.session()?;
        let mut result = std::mem::take(&mut self.stash);
        result.extend(self.read_events()?);
        Ok(json!(result))
    }

    fn read_events(&mut self) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        while result.len() < 16 {
            while self.event_buffer.len() < EVENT_SIZE {
                let mut buffer = vec![0; EVENT_SIZE - self.event_buffer.len()];
                match self
                    .events
                    .as_ref()
                    .context("No event callback")?
                    .read(&mut buffer)
                {
                    Ok(0) => bail!("Debug callback disconnected; inspect console state"),
                    Ok(count) => self.event_buffer.extend(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(result);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let data = std::mem::take(&mut self.event_buffer);
            result.push(json!({"thread_id":word(&data,0),"status":word(&data,4),"name":cstring(&data[8..48]),"registers":registers(&data[48..224])?,"raw_hex":hex::encode(data)}));
        }
        Ok(result)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Minimal in-process ps4debug-NG protocol 1.3 server for offline tests.
    //! `spawn` only implements the identity/process-list commands; `spawn_debuggable`
    //! additionally implements attach, the event callback, registers, memory, maps,
    //! breakpoints and execution control so the higher-level ops can be tested.
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    pub struct FakeDebugger {
        pub port: u16,
        pub connections: Arc<AtomicUsize>,
    }

    pub const FAKE_BRAND: &[u8] = b"ps4debug-NG by Pharaoh2k v1.3.4\x001.1\0";
    pub const FAKE_RIP: u64 = 0x1000;
    pub const FAKE_STACK: u64 = 0x7fff_0000;
    pub const FAKE_EXEC_END: u64 = 0x2000;
    pub const FAKE_RET: u64 = 0x1500;
    /// push rbp; mov rbp,rsp; call +0x10; xor eax,eax; ret ... at FAKE_RIP.
    pub const CODE_AT_RIP: [u8; 12] = [
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0x10, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xc3,
    ];

    fn text(stream: &mut TcpStream, value: &[u8]) {
        let mut out = (value.len() as u32).to_le_bytes().to_vec();
        out.extend(value);
        let _ = stream.write_all(&out);
    }

    fn success(stream: &mut TcpStream) {
        let _ = stream.write_all(&SUCCESS.to_le_bytes());
    }

    fn event_bytes() -> Vec<u8> {
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&1u32.to_le_bytes());
        event[4..8].copy_from_slice(&6u32.to_le_bytes());
        event[8..11].copy_from_slice(b"th\0");
        let mut regs = vec![0u8; 176];
        regs[crate::expr::RIP_OFFSET..crate::expr::RIP_OFFSET + 8].copy_from_slice(&0x1009u64.to_le_bytes());
        regs[80..88].copy_from_slice(&FAKE_STACK.to_le_bytes());
        regs[160..168].copy_from_slice(&FAKE_STACK.to_le_bytes());
        event[48..224].copy_from_slice(&regs);
        event
    }

    fn map_entry(start: u64, end: u64, protection: u64, name: &str) -> [u8; 64] {
        let mut entry = [0u8; 64];
        entry[..8].copy_from_slice(&start.to_le_bytes());
        entry[8..16].copy_from_slice(&end.to_le_bytes());
        entry[24..32].copy_from_slice(&protection.to_le_bytes());
        entry[32..32 + name.len()].copy_from_slice(name.as_bytes());
        entry
    }

    fn fake_memory(address: u64, length: usize) -> Vec<u8> {
        let mut content = vec![0u8; length];
        let end = address.saturating_add(length as u64);
        if address < FAKE_EXEC_END && end > FAKE_RIP {
            for (index, byte) in content.iter_mut().enumerate() {
                let at = address.saturating_add(index as u64);
                *byte = if (FAKE_RIP..FAKE_RIP + CODE_AT_RIP.len() as u64).contains(&at) {
                    CODE_AT_RIP[(at - FAKE_RIP) as usize]
                } else {
                    0x90
                };
            }
        } else if address >= FAKE_STACK && end <= FAKE_STACK + 0x10000 {
            for (index, byte) in content.iter_mut().enumerate() {
                let offset = address.saturating_add(index as u64) - FAKE_STACK;
                let value = match offset / 8 {
                    0 => FAKE_STACK + 8,
                    1 => FAKE_RET,
                    _ => 0,
                };
                *byte = (value >> (8 * (offset % 8))) as u8;
            }
        }
        content
    }

    struct Shared {
        events: Option<TcpStream>,
        registers: [u8; 176],
    }

    /// Full fake: attach binds nothing itself; on BDBB0001 it connects back to the
    /// requested callback address:755 and stores the stream so resume/step commands
    /// can push one stop event each.
    pub fn spawn_debuggable() -> FakeDebugger {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Mutex::new(Shared {
            events: None,
            registers: {
                let mut regs = [0u8; 176];
                regs[crate::expr::RIP_OFFSET..crate::expr::RIP_OFFSET + 8]
                    .copy_from_slice(&FAKE_RIP.to_le_bytes());
                regs[80..88].copy_from_slice(&FAKE_STACK.to_le_bytes());
                regs[160..168].copy_from_slice(&FAKE_STACK.to_le_bytes());
                regs
            },
        }));
        let counter = connections.clone();
        let state = shared.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let state = state.clone();
                std::thread::spawn(move || {
                    loop {
                        let mut header = [0; 12];
                        if stream.read_exact(&mut header).is_err() {
                            return;
                        }
                        let command = u32::from_le_bytes(header[4..8].try_into().unwrap());
                        let length = u32::from_le_bytes(header[8..12].try_into().unwrap());
                        let mut body = vec![0; length as usize];
                        if stream.read_exact(&mut body).is_err() {
                            return;
                        }
                        match command {
                            0xbd000001 => text(&mut stream, b"1.3\0"),
                            0xbd000501 => text(&mut stream, FAKE_BRAND),
                            0xbd000500 => {
                                let _ = stream.write_all(&1400u16.to_le_bytes());
                            }
                            0xbd000502 => {
                                let _ = stream.write_all(&4u16.to_le_bytes());
                            }
                            0xbdaa0001 => {
                                success(&mut stream);
                                let mut out = 1u32.to_le_bytes().to_vec();
                                let mut entry = [0u8; 36];
                                entry[..4].copy_from_slice(b"eboo");
                                entry[32..36].copy_from_slice(&77u32.to_le_bytes());
                                out.extend(entry);
                                let _ = stream.write_all(&out);
                            }
                            0xbdaa0004 => {
                                success(&mut stream);
                                let mut out = 2u32.to_le_bytes().to_vec();
                                out.extend(map_entry(FAKE_RIP, FAKE_EXEC_END, 5, "eboot.bin"));
                                out.extend(map_entry(FAKE_STACK, FAKE_STACK + 0x10000, 3, ""));
                                let _ = stream.write_all(&out);
                            }
                            0xbdaa000a => {
                                success(&mut stream);
                                let mut data = vec![0u8; 188];
                                data[..4].copy_from_slice(&77u32.to_le_bytes());
                                data[4..9].copy_from_slice(b"eboot");
                                let _ = stream.write_all(&data);
                            }
                            0xbdaa0002 => {
                                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                                let length = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                                success(&mut stream);
                                let _ = stream.write_all(&fake_memory(address, length));
                            }
                            0xbdbb0001 => {
                                let interface = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                                success(&mut stream);
                                if let Ok(events) = TcpStream::connect((interface, 755)) {
                                    state.lock().unwrap().events = Some(events);
                                }
                            }
                            0xbdbb0002 => success(&mut stream),
                            0xbdbb0003 | 0xbdbb0004 => success(&mut stream),
                            0xbdbb0005 => {
                                success(&mut stream);
                                let mut out = 1u32.to_le_bytes().to_vec();
                                out.extend(1u32.to_le_bytes());
                                let _ = stream.write_all(&out);
                            }
                            0xbdbb0008 => {
                                success(&mut stream);
                                let regs = state.lock().unwrap().registers;
                                let _ = stream.write_all(&regs);
                            }
                            0xbdbb0009 => {
                                success(&mut stream);
                                let mut regs = [0u8; 176];
                                if stream.read_exact(&mut regs).is_err() {
                                    return;
                                }
                                success(&mut stream);
                                state.lock().unwrap().registers = regs;
                            }
                            0xbdbb000a => {
                                success(&mut stream);
                                let _ = stream.write_all(&[0u8; 832]);
                            }
                            0xbdbb000c => {
                                success(&mut stream);
                                let _ = stream.write_all(&[0u8; 128]);
                            }
                            0xbdbb0010 => {
                                let resume = body.first().copied() == Some(0);
                                success(&mut stream);
                                if resume {
                                    let event = event_bytes();
                                    let mut guard = state.lock().unwrap();
                                    if let Some(events) = guard.events.as_mut() {
                                        let _ = events.write_all(&event);
                                    }
                                }
                            }
                            0xbdbb0011 => {
                                success(&mut stream);
                                let mut data = vec![0u8; 40];
                                data[..4].copy_from_slice(&1u32.to_le_bytes());
                                data[8..10].copy_from_slice(b"th");
                                let _ = stream.write_all(&data);
                            }
                            0xbdbb0012 | 0xbdbb0013 => {
                                success(&mut stream);
                                let event = event_bytes();
                                let mut guard = state.lock().unwrap();
                                if let Some(events) = guard.events.as_mut() {
                                    let _ = events.write_all(&event);
                                }
                            }
                            _ => return,
                        }
                    }
                });
            }
        });
        FakeDebugger { port, connections }
    }

    /// `drop_first_list`: the first connection to receive a process-list command is
    /// closed without answering (simulates a console-side drop).
    pub fn spawn(drop_first_list: bool) -> FakeDebugger {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let index = counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    loop {
                        let mut header = [0; 12];
                        if stream.read_exact(&mut header).is_err() {
                            return;
                        }
                        let command = u32::from_le_bytes(header[4..8].try_into().unwrap());
                        let length = u32::from_le_bytes(header[8..12].try_into().unwrap());
                        let mut body = vec![0; length as usize];
                        if stream.read_exact(&mut body).is_err() {
                            return;
                        }
                        match command {
                            0xbd000001 => text(&mut stream, b"1.3\0"),
                            0xbd000501 => text(&mut stream, FAKE_BRAND),
                            0xbd000500 => {
                                let _ = stream.write_all(&1400u16.to_le_bytes());
                            }
                            0xbd000502 => {
                                let _ = stream.write_all(&4u16.to_le_bytes());
                            }
                            0xbdaa0001 => {
                                if drop_first_list && index == 0 {
                                    return;
                                }
                                let mut out = SUCCESS.to_le_bytes().to_vec();
                                out.extend(1u32.to_le_bytes());
                                let mut entry = [0u8; 36];
                                entry[..4].copy_from_slice(b"eboo");
                                entry[32..36].copy_from_slice(&77u32.to_le_bytes());
                                out.extend(entry);
                                let _ = stream.write_all(&out);
                            }
                            _ => return,
                        }
                    }
                });
            }
        });
        FakeDebugger { port, connections }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_layout_is_exact() {
        assert!(registers(&[0; 184]).is_err());
        let mut content = [0; 176];
        content[136..144].copy_from_slice(&0x12345678u64.to_le_bytes());
        assert_eq!(registers(&content).unwrap()["rip"], "0x12345678");
        assert_eq!(registers(&content).unwrap().as_object().unwrap().len(), 26);
    }
    #[test]
    fn ranges_allow_last_byte_not_overflow() {
        assert!(address_range(u64::MAX, 1, 1).is_ok());
        assert!(address_range(u64::MAX, 2, 2).is_err());
        assert!(address_range(0, 0, 1).is_err());
    }

    fn profile(port: u16) -> (tempfile::TempDir, Profile) {
        let directory = tempfile::tempdir().unwrap();
        let mut profile = crate::artifacts::tests::test_profile(directory.path());
        profile.data["ports"]["debug"] = json!(port);
        (directory, profile)
    }

    #[test]
    fn read_only_command_reconnects_once_after_a_dropped_connection() {
        let fake = fake::spawn(true);
        let (_directory, profile) = profile(fake.port);
        let mut debugger = Debugger::new(profile);
        let list = debugger.processes().unwrap();
        assert_eq!(list[0]["pid"], 77);
        assert_eq!(list[0]["name"], "eboo");
        assert_eq!(
            fake.connections.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "second connection after the first was dropped"
        );
    }

    #[test]
    fn lost_attachment_is_reported_not_silently_cleared() {
        let fake = fake::spawn(true);
        let (_directory, profile) = profile(fake.port);
        let mut debugger = Debugger::new(profile);
        debugger.attached_pid = Some(5);
        let error = debugger.processes().unwrap_err();
        assert!(format!("{error:#}").contains("attached to pid 5"), "{error:#}");
        assert!(debugger.attached_pid.is_none());
    }
}
