use crate::{Result, config::Profile, link};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::Instant,
};

mod ops;
/// Run-loop tracing: import/syscall/function tracing and breakpoint coverage.
pub mod trace;
/// Access finding (watchpoints), crash triage and host-scripted breakpoints.
pub mod access;
pub use ops::{BreakpointRecord, PatchRecord, parse_protection_spec};

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
pub const CMD_DATA_NULL: u32 = 0xf0000003;
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
    pub patches: std::collections::BTreeMap<u32, PatchRecord>,
    next_patch_id: u32,
    pub scans: crate::scanner::ScanBook,
    eh_cache: EhFrameCache,
}

type EhFrameCache = std::collections::HashMap<(u32, u64), Option<(u64, Vec<u8>)>>;

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
            patches: Default::default(),
            next_patch_id: 1,
            scans: Default::default(),
            eh_cache: Default::default(),
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
        self.eh_cache.clear();
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

    /// Upstream `ps4debug-NG@8be828fe` `proc_protect_handle` (`proc.c:830-848`) omits
    /// `return 0;` after sending `CMD_SUCCESS`, falling through to emit a trailing
    /// 4-byte `CMD_DATA_NULL (0xF0000003)` on the persistent command socket. Drain it
    /// with a short timeout so both unpatched `8be828fe` and patched builds stay in sync.
    fn drain_optional_trailing_status(&self) -> Result<Option<u32>> {
        let connection = self.connection.as_ref().context("No debugger connection")?;
        connection.set_read_timeout(Some(std::time::Duration::from_millis(60)))?;
        let mut buf = [0u8; 4];
        let mut offset = 0usize;
        while offset < 4 {
            match (&*connection).read(&mut buf[offset..]) {
                Ok(0) => bail!("Debugger disconnected after status"),
                Ok(n) => offset += n,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if offset == 0 {
                        return Ok(None);
                    }
                    bail!("Partial trailing status ({offset}/4 bytes) left socket uncertain");
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(Some(u32::from_le_bytes(buf)))
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
        // Upstream `struct proc_vm_map_entry` (packed): char name[32]; u64 start, end, offset; u16 prot.
        self.list(0xbdaa0004,&pid.to_le_bytes(),58,|data| {
            ensure!(qword(data,40)>=qword(data,32),"Invalid map range");
            Ok(json!({"start":qword(data,32),"end":qword(data,40),"offset":qword(data,48),"protection":u16::from_le_bytes([data[56],data[57]]) as u64,"name":cstring(&data[..32])}))
        })
    }

    pub fn process_info(&mut self, pid: u32) -> Result<Value> {
        Self::pid(pid)?;
        self.exchange_read(|debugger| {
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
        self.exchange_read(|debugger| {
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

#[cfg(any(test, feature = "fixture"))]
pub mod fake {
    //! Minimal in-process ps4debug-NG protocol 1.3 server for offline tests.
    //! `spawn` only implements the identity/process-list commands; `spawn_debuggable`
    //! additionally implements attach, the event callback, registers, memory, maps,
    //! breakpoints and execution control so the higher-level ops can be tested.
    //! `spawn_fixture` adds a loaded image and real stop semantics for the
    //! installed-app bridge tests (`ps4debug-fixture` binary, `fixture` feature).
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    pub struct FakeDebugger {
        pub port: u16,
        pub connections: Arc<AtomicUsize>,
    }

    /// The pinned protocol fixes the debug callback port at 755: every test that
    /// attaches must hold this guard for its whole lifetime.
    static CALLBACK_PORT: Mutex<()> = Mutex::new(());

    /// Serialize use of callback port 755; `None` when this host cannot bind it
    /// (unprivileged-port floor), in which case the caller should skip.
    pub fn callback_port_guard() -> Option<std::sync::MutexGuard<'static, ()>> {
        let guard = CALLBACK_PORT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if TcpListener::bind(("127.0.0.1", 755)).is_err() {
            eprintln!("skipping: cannot bind the fixed callback port 755 on this host");
            return None;
        }
        Some(guard)
    }

    /// A profile pointing at a fake on `port`, with `debug_control` and
    /// `process_write` enabled and a matching local qualification record.
    pub fn qualified_profile(directory: &std::path::Path, port: u16) -> Profile {
        let mut data: Value =
            serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
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
            "profile_sha256": profile.fingerprint(), "attestation": crate::config::ATTESTATION,
            "approved_permissions": ["debug_control", "process_write"], "debugger_payload_sha256": "b".repeat(64),
            "payload_sha256_allowlist": [], "build_recipe_sha256_allowlist": [],
        });
        std::fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
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

    /// Opt-in behaviour for installed-app bridge tests: `image` mapped at `base`,
    /// a SIGTRAP stop event on attach and on halt, and single-steps that advance
    /// RIP by the decoded instruction length.
    ///
    /// `program` scripts what a resume "executes" (this is not an emulator): steps
    /// are consumed in order until one hits an enabled software breakpoint, an armed
    /// hardware watchpoint, or raises a fault signal; that step produces one stop
    /// event. A resume that exhausts the program produces no event (still running).
    #[derive(Clone, Default)]
    pub struct Fixture {
        pub pid: u32,
        pub thread_id: u32,
        pub base: u64,
        pub image: Vec<u8>,
        pub rip: u64,
        pub program: Vec<FixtureStep>,
        /// Additional named maps `(start, end, protection bits, name)`.
        pub extra_maps: Vec<(u64, u64, u64, String)>,
        /// Additional memory contents `(address, bytes)` (other modules, heap, stack).
        pub extra_memory: Vec<(u64, Vec<u8>)>,
    }

    /// One scripted instruction for [`Fixture::program`].
    #[derive(Clone, Default, Debug)]
    pub struct FixtureStep {
        pub rip: u64,
        /// Register values (by name, e.g. `rdi`, `rsp`) in effect while this step executes.
        pub registers: Vec<(String, u64)>,
        /// Data access `(address, length, is_write)` performed by the instruction.
        pub access: Option<(u64, u64, bool)>,
        /// Fault signal raised by this step (e.g. 11 = SIGSEGV); execution stops here.
        pub signal: Option<u32>,
    }

    /// FreeBSD wait status for a SIGTRAP stop.
    const STOP_STATUS: u32 = 0x57f;

    fn fixture_event(fixture: &Fixture, registers: &[u8; 176]) -> Vec<u8> {
        fixture_event_status(fixture, registers, STOP_STATUS)
    }

    fn fixture_event_status(fixture: &Fixture, registers: &[u8; 176], status: u32) -> Vec<u8> {
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&fixture.thread_id.to_le_bytes());
        event[4..8].copy_from_slice(&status.to_le_bytes());
        event[8..15].copy_from_slice(b"fixture");
        event[48..224].copy_from_slice(registers);
        event
    }

    fn set_register(registers: &mut [u8; 176], name: &str, value: u64) {
        if let Some(offset) = crate::expr::offset_of(name) {
            registers[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn instruction_length(address: u64, fixture: &Fixture) -> u64 {
        let code = fake_memory(address, 15, &BTreeMap::new(), Some(fixture));
        iced_x86::Decoder::with_ip(64, &code, address, iced_x86::DecoderOptions::NONE)
            .decode()
            .len()
            .max(1) as u64
    }

    /// Consume `fixture.program` until a breakpoint, watchpoint or fault produces a stop.
    fn run_program(guard: &mut Shared, fixture: &Fixture) {
        while guard.cursor < fixture.program.len() {
            let step = fixture.program[guard.cursor].clone();
            guard.cursor += 1;
            set_register(&mut guard.registers, "rip", step.rip);
            for (name, value) in &step.registers {
                set_register(&mut guard.registers, name, *value);
            }
            let next = step.rip + instruction_length(step.rip, fixture);
            let execute_watch = guard
                .watchpoints
                .iter()
                .find(|(_, (address, _, access))| *access == 0 && *address == step.rip)
                .map(|(index, _)| *index);
            if guard.breakpoints.values().any(|address| *address == step.rip) {
                // The pinned server reports the trap (rip just past int3) after stepping
                // the thread over the original instruction.
                let mut reported = guard.registers;
                set_register(&mut reported, "rip", step.rip + 1);
                set_register(&mut guard.registers, "rip", next);
                let event = fixture_event(fixture, &reported);
                push_event(guard, &event);
                return;
            }
            if let Some(index) = execute_watch {
                guard.dr6 = 1 << index;
                let event = fixture_event(fixture, &guard.registers);
                push_event(guard, &event);
                return;
            }
            if let Some(signal) = step.signal {
                let event = fixture_event_status(fixture, &guard.registers, (signal << 8) | 0x7f);
                push_event(guard, &event);
                return;
            }
            if let Some((address, length, write)) = step.access {
                let hit = guard.watchpoints.iter().find(|(_, (start, size, access))| {
                    address < start + size
                        && *start < address + length
                        && (*access == 3 || (*access == 1 && write))
                });
                if let Some((index, _)) = hit {
                    // Data watchpoints trap after the accessing instruction retires.
                    guard.dr6 = 1 << index;
                    set_register(&mut guard.registers, "rip", next);
                    let event = fixture_event(fixture, &guard.registers);
                    push_event(guard, &event);
                    return;
                }
            }
            set_register(&mut guard.registers, "rip", next);
        }
    }

    fn register_rip(registers: &[u8; 176]) -> u64 {
        u64::from_le_bytes(registers[crate::expr::RIP_OFFSET..crate::expr::RIP_OFFSET + 8].try_into().unwrap())
    }

    fn push_event(guard: &mut Shared, event: &[u8]) {
        if let Some(events) = guard.events.as_mut() {
            let _ = events.write_all(event);
        }
    }

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

    fn map_entry(start: u64, end: u64, protection: u64, name: &str) -> [u8; 58] {
        let mut entry = [0u8; 58];
        let cap = name.len().min(31);
        entry[..cap].copy_from_slice(&name.as_bytes()[..cap]);
        entry[32..40].copy_from_slice(&start.to_le_bytes());
        entry[40..48].copy_from_slice(&end.to_le_bytes());
        entry[56..58].copy_from_slice(&(protection as u16).to_le_bytes());
        entry
    }

    fn fake_memory(address: u64, length: usize, overlay: &BTreeMap<u64, u8>, fixture: Option<&Fixture>) -> Vec<u8> {
        let mut content = vec![0u8; length];
        let end = address.saturating_add(length as u64);
        if let Some(fixture) = fixture {
            for (index, byte) in content.iter_mut().enumerate() {
                let at = address.saturating_add(index as u64);
                if let Some(value) = at.checked_sub(fixture.base).and_then(|offset| fixture.image.get(offset as usize)) {
                    *byte = *value;
                }
                for (start, bytes) in &fixture.extra_memory {
                    if let Some(value) = at.checked_sub(*start).and_then(|offset| bytes.get(offset as usize)) {
                        *byte = *value;
                    }
                }
            }
        } else if address < FAKE_EXEC_END && end > FAKE_RIP {
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
        for (&at, &val) in overlay.range(address..end) {
            content[(at - address) as usize] = val;
        }
        content
    }

    struct Shared {
        events: Option<TcpStream>,
        registers: [u8; 176],
        fpregs: [u8; 832],
        fsbase: u64,
        gsbase: u64,
        overlay: BTreeMap<u64, u8>,
        maps: Vec<(u64, u64, u64, String)>,
        next_alloc: u64,
        fixture: Option<Fixture>,
        /// Enabled software breakpoints by slot.
        breakpoints: BTreeMap<u32, u64>,
        /// Armed hardware watchpoints by slot: (address, length, access 0/1/3).
        watchpoints: BTreeMap<u32, (u64, u64, u32)>,
        /// Next `Fixture::program` step to execute.
        cursor: usize,
        dr6: u64,
    }

    /// Full fake: attach binds nothing itself; on BDBB0001 it connects back to the
    /// requested callback address:755 and stores the stream so resume/step commands
    /// can push one stop event each.
    pub fn spawn_debuggable() -> FakeDebugger {
        serve_debuggable(TcpListener::bind("127.0.0.1:0").unwrap(), None)
    }

    /// Fixture-mode fake on an explicit listener (see [`Fixture`]).
    pub fn spawn_fixture(listener: TcpListener, fixture: Fixture) -> FakeDebugger {
        serve_debuggable(listener, Some(fixture))
    }

    fn serve_debuggable(listener: TcpListener, fixture: Option<Fixture>) -> FakeDebugger {
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let rip = fixture.as_ref().map_or(FAKE_RIP, |fixture| fixture.rip);
        let maps = match &fixture {
            Some(fixture) => {
                let mut maps = vec![
                    (fixture.base, fixture.base + ((fixture.image.len() as u64 + 0xfff) & !0xfff), 5, "fixture.elf".to_owned()),
                    (FAKE_STACK, FAKE_STACK + 0x10000, 3, String::new()),
                ];
                maps.extend(fixture.extra_maps.iter().cloned());
                maps
            }
            None => vec![
                (FAKE_RIP, FAKE_EXEC_END, 5, "eboot.bin".to_owned()),
                (FAKE_STACK, FAKE_STACK + 0x10000, 3, String::new()),
            ],
        };
        let shared = Arc::new(Mutex::new(Shared {
            events: None,
            registers: {
                let mut regs = [0u8; 176];
                regs[crate::expr::RIP_OFFSET..crate::expr::RIP_OFFSET + 8]
                    .copy_from_slice(&rip.to_le_bytes());
                regs[80..88].copy_from_slice(&FAKE_STACK.to_le_bytes());
                regs[160..168].copy_from_slice(&FAKE_STACK.to_le_bytes());
                regs
            },
            fpregs: [0u8; 832],
            fsbase: 0x8001_0000,
            gsbase: 0,
            overlay: BTreeMap::new(),
            maps,
            next_alloc: 0x9000_0000,
            fixture,
            breakpoints: BTreeMap::new(),
            watchpoints: BTreeMap::new(),
            cursor: 0,
            dr6: 0,
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
                                let pid = state.lock().unwrap().fixture.as_ref().map_or(77, |fixture| fixture.pid);
                                let mut out = 1u32.to_le_bytes().to_vec();
                                let mut entry = [0u8; 36];
                                entry[..4].copy_from_slice(b"eboo");
                                entry[32..36].copy_from_slice(&pid.to_le_bytes());
                                out.extend(entry);
                                let _ = stream.write_all(&out);
                            }
                            0xbdaa0004 => {
                                success(&mut stream);
                                let guard = state.lock().unwrap();
                                let mut out = (guard.maps.len() as u32).to_le_bytes().to_vec();
                                for (s, e, p, n) in &guard.maps {
                                    out.extend(map_entry(*s, *e, *p, n));
                                }
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
                                let guard = state.lock().unwrap();
                                let _ = stream.write_all(&fake_memory(address, length, &guard.overlay, guard.fixture.as_ref()));
                            }
                            0xbdaa0003 => {
                                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                                let length = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                                success(&mut stream);
                                let mut data = vec![0u8; length];
                                if stream.read_exact(&mut data).is_err() {
                                    return;
                                }
                                let mut guard = state.lock().unwrap();
                                for (i, b) in data.into_iter().enumerate() {
                                    guard.overlay.insert(address + i as u64, b);
                                }
                                success(&mut stream);
                            }
                            0xbdaa0008 => {
                                // Reproduce ps4debug-NG@8be828fe proc_protect_handle missing `return 0;`:
                                // sends CMD_SUCCESS followed immediately by CMD_DATA_NULL (0xF0000003)!
                                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                                let length = u32::from_le_bytes(body[12..16].try_into().unwrap()) as u64;
                                let prot = u32::from_le_bytes(body[16..20].try_into().unwrap()) as u64;
                                {
                                    let mut guard = state.lock().unwrap();
                                    for (s, e, p, _) in &mut guard.maps {
                                        if *s <= address && address < *e && address + length <= *e {
                                            *p = prot;
                                        }
                                    }
                                }
                                success(&mut stream);
                                let _ = stream.write_all(&CMD_DATA_NULL.to_le_bytes());
                            }
                            0xbdaa000b => {
                                let length = u32::from_le_bytes(body[4..8].try_into().unwrap()) as u64;
                                let aligned = ((length.max(1) + 0x3fff) & !0x3fff).max(0x4000);
                                let mut guard = state.lock().unwrap();
                                let addr = guard.next_alloc;
                                guard.next_alloc += aligned;
                                guard.maps.push((addr, addr + aligned, 7, "alloc".to_owned()));
                                success(&mut stream);
                                let _ = stream.write_all(&addr.to_le_bytes());
                            }
                            0xbdaa000e => {
                                let hint = u64::from_le_bytes(body[4..12].try_into().unwrap());
                                let length = u32::from_le_bytes(body[12..16].try_into().unwrap()) as u64;
                                let aligned = ((length.max(1) + 0x3fff) & !0x3fff).max(0x4000);
                                let mut guard = state.lock().unwrap();
                                let addr = if hint != 0 { hint & !0x3fff } else { guard.next_alloc };
                                if hint == 0 {
                                    guard.next_alloc += aligned;
                                }
                                guard.maps.push((addr, addr + aligned, 7, "alloc_hint".to_owned()));
                                success(&mut stream);
                                let _ = stream.write_all(&addr.to_le_bytes());
                            }
                            0xbdaa000c => {
                                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                                state.lock().unwrap().maps.retain(|(s, _, _, _)| *s != address);
                                success(&mut stream);
                            }
                            0xbdbb0001 => {
                                let interface = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                                success(&mut stream);
                                if let Ok(events) = TcpStream::connect((interface, 755)) {
                                    let mut guard = state.lock().unwrap();
                                    guard.events = Some(events);
                                    // A real attach stops the process (PT_ATTACH -> SIGSTOP/SIGTRAP).
                                    if let Some(fixture) = guard.fixture.clone() {
                                        let event = fixture_event(&fixture, &guard.registers);
                                        push_event(&mut guard, &event);
                                    }
                                }
                            }
                            0xbdbb0002 => success(&mut stream),
                            0xbdbb0003 => {
                                if body.len() >= 16 {
                                    let index = u32::from_le_bytes(body[0..4].try_into().unwrap());
                                    let enabled = u32::from_le_bytes(body[4..8].try_into().unwrap()) != 0;
                                    let address = u64::from_le_bytes(body[8..16].try_into().unwrap());
                                    let mut guard = state.lock().unwrap();
                                    if enabled {
                                        guard.breakpoints.insert(index, address);
                                    } else {
                                        guard.breakpoints.remove(&index);
                                    }
                                }
                                success(&mut stream);
                            }
                            0xbdbb0004 => {
                                if body.len() >= 24 {
                                    let word = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap());
                                    let (index, enabled, encoding, access) = (word(0), word(4) != 0, word(8), word(12));
                                    let address = u64::from_le_bytes(body[16..24].try_into().unwrap());
                                    let length = match encoding {
                                        0 => 1,
                                        1 => 2,
                                        3 => 4,
                                        _ => 8,
                                    };
                                    let mut guard = state.lock().unwrap();
                                    if enabled {
                                        guard.watchpoints.insert(index, (address, length, access));
                                    } else {
                                        guard.watchpoints.remove(&index);
                                    }
                                }
                                success(&mut stream);
                            }
                            0xbdbb0005 => {
                                success(&mut stream);
                                let thread = state.lock().unwrap().fixture.as_ref().map_or(1, |fixture| fixture.thread_id);
                                let mut out = 1u32.to_le_bytes().to_vec();
                                out.extend(thread.to_le_bytes());
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
                                let fpregs = state.lock().unwrap().fpregs;
                                let _ = stream.write_all(&fpregs);
                            }
                            0xbdbb000b => {
                                success(&mut stream);
                                let mut fpregs = [0u8; 832];
                                if stream.read_exact(&mut fpregs).is_err() {
                                    return;
                                }
                                state.lock().unwrap().fpregs = fpregs;
                                success(&mut stream);
                            }
                            0xbdbb000c => {
                                success(&mut stream);
                                let guard = state.lock().unwrap();
                                let mut out = [0u8; 128];
                                for (index, (address, _, _)) in &guard.watchpoints {
                                    let at = *index as usize * 8;
                                    out[at..at + 8].copy_from_slice(&address.to_le_bytes());
                                }
                                out[48..56].copy_from_slice(&guard.dr6.to_le_bytes());
                                let _ = stream.write_all(&out);
                            }
                            0xbdbb000e => {
                                success(&mut stream);
                                let guard = state.lock().unwrap();
                                let mut out = Vec::with_capacity(16);
                                out.extend(guard.fsbase.to_le_bytes());
                                out.extend(guard.gsbase.to_le_bytes());
                                let _ = stream.write_all(&out);
                            }
                            0xbdbb000f => {
                                success(&mut stream);
                                let mut buf = [0u8; 16];
                                if stream.read_exact(&mut buf).is_err() {
                                    return;
                                }
                                let mut guard = state.lock().unwrap();
                                guard.fsbase = u64::from_le_bytes(buf[..8].try_into().unwrap());
                                guard.gsbase = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                                success(&mut stream);
                            }
                            0xbdbb0010 => {
                                let resume = body.first().copied() == Some(0);
                                success(&mut stream);
                                let mut guard = state.lock().unwrap();
                                match guard.fixture.clone() {
                                    // Fixture: halt reports a stop; resume runs until a stop it never reaches.
                                    Some(fixture) if !resume => {
                                        let event = fixture_event(&fixture, &guard.registers);
                                        push_event(&mut guard, &event);
                                    }
                                    Some(fixture) => run_program(&mut guard, &fixture),
                                    None if resume => push_event(&mut guard, &event_bytes()),
                                    None => {}
                                }
                            }
                            0xbdbb0011 => {
                                success(&mut stream);
                                let thread = state.lock().unwrap().fixture.as_ref().map_or(1, |fixture| fixture.thread_id);
                                let mut data = vec![0u8; 40];
                                data[..4].copy_from_slice(&thread.to_le_bytes());
                                data[8..10].copy_from_slice(b"th");
                                let _ = stream.write_all(&data);
                            }
                            0xbdbb0012 | 0xbdbb0013 => {
                                success(&mut stream);
                                let mut guard = state.lock().unwrap();
                                match guard.fixture.clone() {
                                    Some(fixture) => {
                                        let rip = register_rip(&guard.registers);
                                        let code = fake_memory(rip, 15, &guard.overlay, Some(&fixture));
                                        let length = iced_x86::Decoder::with_ip(64, &code, rip, iced_x86::DecoderOptions::NONE)
                                            .decode()
                                            .len()
                                            .max(1) as u64;
                                        guard.registers[crate::expr::RIP_OFFSET..crate::expr::RIP_OFFSET + 8]
                                            .copy_from_slice(&(rip + length).to_le_bytes());
                                        let event = fixture_event(&fixture, &guard.registers);
                                        push_event(&mut guard, &event);
                                    }
                                    None => push_event(&mut guard, &event_bytes()),
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

    /// Python `test_async_packets_handle_fragmentation_and_source_offsets`.
    #[test]
    fn async_event_packets_reassemble_fragments_at_source_offsets() {
        let (_directory, profile) = profile(1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let receiver = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut sender, _) = listener.accept().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut debugger = Debugger::new(profile);
        debugger.events = Some(receiver);
        debugger.attached_pid = Some(71);
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&72u32.to_le_bytes());
        event[4..8].copy_from_slice(&5u32.to_le_bytes());
        event[48 + 136..48 + 144].copy_from_slice(&0x1234u64.to_le_bytes());
        sender.write_all(&event[..100]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(debugger.poll_events().unwrap(), json!([]));
        sender.write_all(&event[100..]).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        let events = loop {
            let events = debugger.poll_events().unwrap();
            if !events.as_array().unwrap().is_empty() || Instant::now() > deadline {
                break events;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(events.as_array().unwrap().len(), 1);
        assert_eq!(events[0]["thread_id"], 72);
        assert_eq!(events[0]["status"], 5);
        assert_eq!(events[0]["registers"]["rip"], "0x1234");
        debugger.attached_pid = None;
    }
}
