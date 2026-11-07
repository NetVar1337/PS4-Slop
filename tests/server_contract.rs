//! Server contract tests: safety gates, transports, broker, MCP framing, RSP and
//! extraction behaviour, carried over from the retired Python server suite (the
//! `test_*` names in doc comments are the original test names). Every console
//! service is an in-process loopback fake; nothing here contacts real hardware.

use ps4_workbench_rs::{
    agents::{AnalysisAgents, AnalysisWorker},
    broker::{BrokerServer, SessionHub, load_token},
    client::{BrokerClient, RemoteRegistry},
    config::{ATTESTATION, Profile},
    debugger::Debugger,
    mcp::McpServer,
    rsp::{RspSession, memory_map_xml},
    tools::ToolRegistry,
    transports,
    workbench::{Workbench, digest},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Python `WorkbenchCase`: the reference profile on loopback with a private
/// artifact directory and qualification file.
struct Env {
    dir: tempfile::TempDir,
    settings: Value,
}

impl Env {
    fn new() -> Self {
        let mut settings: Value =
            serde_json::from_str(include_str!("../profiles/ps4-1400.json")).unwrap();
        settings["host"] = json!("127.0.0.1");
        settings["artifact_directory"] = json!("artifacts");
        settings["qualification_file"] = json!("qualification.json");
        Self { dir: tempfile::tempdir().unwrap(), settings }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("profile.json")
    }

    fn port(&mut self, service: &str, port: u16) -> &mut Self {
        self.settings["ports"][service] = json!(port);
        self
    }

    fn profile(&self) -> Profile {
        std::fs::write(self.path(), self.settings.to_string()).unwrap();
        Profile::load(self.path()).unwrap()
    }

    fn workbench(&self) -> Workbench {
        Workbench::new(self.profile()).unwrap()
    }

    fn registry(&self) -> ToolRegistry {
        ToolRegistry::with_toolset(self.workbench(), ps4_workbench_rs::tools::Toolset::Full).unwrap()
    }

    /// Python `WorkbenchCase.qualify`.
    fn qualify(&mut self, permissions: &[&str], payloads: &[String]) -> Profile {
        for permission in permissions {
            self.settings["permissions"][*permission] = json!(true);
        }
        self.settings["jailbreak"]["installed_commit"] = json!("a".repeat(40));
        self.settings["jailbreak"]["hen_build"] = json!("test-hen");
        self.settings["debugger"]["expected_brand"] = json!("ps4debug-NG by Pharaoh2k v1.3.4");
        self.settings["debugger"]["payload_sha256"] = json!("b".repeat(64));
        let profile = self.profile();
        let record = json!({"profile_sha256": profile.fingerprint(), "attestation": ATTESTATION,
            "approved_permissions": permissions, "debugger_payload_sha256": "b".repeat(64),
            "payload_sha256_allowlist": payloads, "build_recipe_sha256_allowlist": []});
        std::fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
    }

    fn audit(&self, workbench: &Workbench) -> String {
        String::from_utf8(workbench.store.read("audit.jsonl").unwrap_or_default()).unwrap()
    }
}

/// A listener that only counts connections. `ftp` speaks just enough FTP for
/// a banner probe (220 greeting, 221 reply to anything).
struct Counter {
    port: u16,
    count: Arc<AtomicUsize>,
}

impl Counter {
    fn spawn(ftp: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                seen.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    if ftp {
                        let _ = stream.write_all(b"220 fake\r\n");
                    }
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|count| count > 0) {
                        if ftp {
                            let _ = stream.write_all(b"221 bye\r\n");
                        }
                        line.clear();
                    }
                });
            }
        });
        Self { port, count }
    }

    fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

/// Point every console service at a counting listener.
fn counted_services(env: &mut Env) -> BTreeMap<&'static str, Counter> {
    let mut counters = BTreeMap::new();
    for service in ["payload", "ftp", "klog", "debug"] {
        let counter = Counter::spawn(service == "ftp");
        env.port(service, counter.port);
        counters.insert(service, counter);
    }
    counters
}

fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Fake ps4debug-NG 1.3 console (full command subset used by the server)
// ---------------------------------------------------------------------------

const MAGIC: u32 = 0xffaa_bbcc;
const OK: [u8; 4] = 0x8000_0000u32.to_le_bytes();
const REJECTED: [u8; 4] = 0xf000_0001u32.to_le_bytes();
const BRAND: &[u8] = b"ps4debug-NG by Pharaoh2k v1.3.4\x001.1";
const EVENT_SIZE: usize = 1184;

fn text(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u32).to_le_bytes().to_vec();
    out.extend(value);
    out
}

fn identity(protocol: &[u8], brand: &[u8], firmware: u16, platform: u16) -> Vec<u8> {
    let mut out = text(protocol);
    out.extend(text(brand));
    out.extend(firmware.to_le_bytes());
    out.extend(platform.to_le_bytes());
    out
}

fn good_identity() -> Vec<u8> {
    identity(b"1.3", BRAND, 1400, 4)
}

fn header(command: u32, length: u32) -> Vec<u8> {
    let mut out = MAGIC.to_le_bytes().to_vec();
    out.extend(command.to_le_bytes());
    out.extend(length.to_le_bytes());
    out
}

fn process_entry(name: &[u8], pid: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 36];
    entry[..name.len()].copy_from_slice(name);
    entry[32..].copy_from_slice(&pid.to_le_bytes());
    entry
}

fn stop_event() -> Vec<u8> {
    let mut event = vec![0u8; EVENT_SIZE];
    event[..4].copy_from_slice(&72u32.to_le_bytes());
    event[4..8].copy_from_slice(&0x57fu32.to_le_bytes());
    event[8..14].copy_from_slice(b"sample");
    event[48 + 136..48 + 144].copy_from_slice(&0x4000u64.to_le_bytes());
    event
}

fn register_block() -> Vec<u8> {
    let mut registers = vec![0u8; 176];
    registers[112..120].copy_from_slice(&0x1234u64.to_le_bytes());
    registers[136..144].copy_from_slice(&0x4000u64.to_le_bytes());
    registers[152..160].copy_from_slice(&0x202u64.to_le_bytes());
    registers[160..168].copy_from_slice(&0x8000u64.to_le_bytes());
    registers
}

/// Every (command, body) packet the fake console received, in order.
type CommandLog = Mutex<Vec<(u32, Vec<u8>)>>;

struct ConsoleState {
    overlay: BTreeMap<u64, u8>,
    maps: Vec<(u64, u64, u64, &'static str)>,
    process_name: &'static str,
    process_path: &'static str,
    title_id: &'static str,
    content_id: &'static str,
    rpc_installs: usize,
    elf_uploads: usize,
    apply_writes: bool,
    /// Memory reads served before every further read drops the connection.
    read_budget: Option<usize>,
    reads: usize,
    events: Option<TcpStream>,
}

/// Unwritten memory reads as `A` (0x41), like the Python mocks.
struct FakeConsole {
    port: u16,
    log: Arc<CommandLog>,
    state: Arc<Mutex<ConsoleState>>,
}

impl FakeConsole {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(ConsoleState {
            overlay: BTreeMap::new(),
            maps: vec![(0x4000, 0x8000, 5, "eboot.bin")],
            process_name: "eboot.bin",
            process_path: "/app0/eboot.bin",
            title_id: "CUSA12552",
            content_id: "UP0000-CUSA12552_00-TEST000000000000",
            rpc_installs: 0,
            elf_uploads: 0,
            apply_writes: true,
            read_budget: None,
            reads: 0,
            events: None,
        }));
        let (log_handle, state_handle) = (log.clone(), state.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (log, state) = (log_handle.clone(), state_handle.clone());
                std::thread::spawn(move || serve_console(stream, &log, &state));
            }
        });
        Self { port, log, state }
    }

    fn configure(&self, change: impl FnOnce(&mut ConsoleState)) {
        change(&mut lock(&self.state));
    }

    fn bodies(&self, command: u32) -> Vec<Vec<u8>> {
        lock(&self.log).iter().filter(|(seen, _)| *seen == command).map(|(_, body)| body.clone()).collect()
    }

    fn rpc_installs(&self) -> usize {
        lock(&self.state).rpc_installs
    }

    fn elf_uploads(&self) -> usize {
        lock(&self.state).elf_uploads
    }

    /// Deliver one real stop event on the debug callback channel.
    fn push_stop(&self) {
        let mut state = lock(&self.state);
        state.events.as_mut().expect("debug callback connected").write_all(&stop_event()).unwrap();
    }

    fn drop_events(&self) {
        if let Some(events) = lock(&self.state).events.take() {
            let _ = events.shutdown(Shutdown::Both);
        }
    }
}

fn serve_console(mut stream: TcpStream, log: &CommandLog, state: &Mutex<ConsoleState>) {
    loop {
        let mut head = [0u8; 12];
        if stream.read_exact(&mut head).is_err() {
            return;
        }
        let command = u32::from_le_bytes(head[4..8].try_into().unwrap());
        let mut body = vec![0u8; u32::from_le_bytes(head[8..12].try_into().unwrap()) as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        lock(log).push((command, body.clone()));
        let mut reply = Vec::new();
        match command {
            0xbd00_0001 => reply = text(b"1.3"),
            0xbd00_0501 => reply = text(BRAND),
            0xbd00_0500 => reply.extend(1400u16.to_le_bytes()),
            0xbd00_0502 => reply.extend(4u16.to_le_bytes()),
            0xbdaa_0001 => {
                reply.extend(OK);
                reply.extend(1u32.to_le_bytes());
                reply.extend(process_entry(b"sample", 71));
            }
            0xbdaa_0004 => {
                let state = lock(state);
                reply.extend(OK);
                reply.extend((state.maps.len() as u32).to_le_bytes());
                for (start, end, protection, name) in &state.maps {
                    let mut entry = [0u8; 58];
                    entry[..name.len()].copy_from_slice(name.as_bytes());
                    entry[32..40].copy_from_slice(&start.to_le_bytes());
                    entry[40..48].copy_from_slice(&end.to_le_bytes());
                    entry[56..58].copy_from_slice(&(*protection as u16).to_le_bytes());
                    reply.extend(entry);
                }
            }
            0xbdaa_000a => {
                reply.extend(OK);
                let state = lock(state);
                let mut info = vec![0u8; 188];
                info[..4].copy_from_slice(&71u32.to_le_bytes());
                for (offset, capacity, text) in [
                    (4, 40, state.process_name),
                    (44, 64, state.process_path),
                    (108, 16, state.title_id),
                    (124, 64, state.content_id),
                ] {
                    let bytes = text.as_bytes();
                    let length = bytes.len().min(capacity - 1);
                    info[offset..offset + length].copy_from_slice(&bytes[..length]);
                }
                reply.extend(info);
            }
            0xbdaa_0005 => {
                lock(state).rpc_installs += 1;
                reply.extend(OK);
                reply.extend(0x9000u64.to_le_bytes());
            }
            0xbdaa_0006 => {
                let command = u64::from_le_bytes(body[20..28].try_into().unwrap());
                let lifecycle = if command == 2 { 4u64 } else { 2u64 };
                let status = (0x4158_4553u64 << 32) | lifecycle;
                reply.extend(OK);
                reply.extend(71u32.to_le_bytes());
                reply.extend(status.to_le_bytes());
            }
            0xbdaa_0010 => {
                let length = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let mut elf = vec![0u8; length];
                if stream.read_exact(&mut elf).is_err() {
                    return;
                }
                lock(state).elf_uploads += 1;
                reply.extend(OK);
                reply.extend(0x9000u64.to_le_bytes());
            }
            0xbdcc_0001 => {
                reply.extend(OK);
                reply.extend(0x8000_0000u64.to_le_bytes());
            }
            0xbdcc_0002 => {
                let address = u64::from_le_bytes(body[0..8].try_into().unwrap());
                let length = u32::from_le_bytes(body[8..12].try_into().unwrap()) as u64;
                reply.extend(OK);
                reply.extend((address..address + length).map(|at| *lock(state).overlay.get(&at).unwrap_or(&0x4b)));
            }
            0xbdcc_0003 => {
                let address = u64::from_le_bytes(body[0..8].try_into().unwrap());
                let mut data = vec![0u8; u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize];
                if stream.write_all(&OK).is_err() || stream.read_exact(&mut data).is_err() {
                    return;
                }
                let mut state = lock(state);
                if state.apply_writes {
                    for (offset, byte) in data.into_iter().enumerate() {
                        state.overlay.insert(address + offset as u64, byte);
                    }
                }
                reply.extend(OK);
            }
            0xbdaa_0007 => {
                let length = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let mut elf = vec![0u8; length];
                if stream.read_exact(&mut elf).is_err() {
                    return;
                }
                lock(state).elf_uploads += 1;
                reply.extend(OK);
            }
            0xbdaa_0009 => {
                let value_type = body[4];
                let compare_type = body[5];
                let length = u32::from_le_bytes(body[6..10].try_into().unwrap()) as usize;
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let mut data = vec![0u8; length];
                if stream.read_exact(&mut data).is_err() {
                    return;
                }
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let element = match value_type {
                    2 | 3 => 2,
                    4 | 5 | 8 => 4,
                    6 | 7 | 9 => 8,
                    10 | 11 => length.max(1),
                    _ => 1,
                };
                let state = lock(state);
                if compare_type == 0 && element > 0 && length >= element {
                    for (start, end, _, _) in &state.maps {
                        let mut at = *start;
                        while at + element as u64 <= *end {
                            let matches = (0..element).all(|i| *state.overlay.get(&(at + i as u64)).unwrap_or(&0x41) == data[i]);
                            if matches && stream.write_all(&at.to_le_bytes()).is_err() {
                                return;
                            }
                            at += element as u64;
                        }
                    }
                }
                if stream.write_all(&u64::MAX.to_le_bytes()).is_err() {
                    return;
                }
                continue;
            }
            0xbdaa_0002 => {
                let mut state = lock(state);
                if state.read_budget.is_some_and(|budget| state.reads >= budget) {
                    return;
                }
                state.reads += 1;
                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                let length = u32::from_le_bytes(body[12..16].try_into().unwrap()) as u64;
                reply.extend(OK);
                reply.extend((address..address + length).map(|at| *state.overlay.get(&at).unwrap_or(&0x41)));
            }
            0xbdaa_0003 => {
                let address = u64::from_le_bytes(body[4..12].try_into().unwrap());
                let mut data = vec![0u8; u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize];
                if stream.write_all(&OK).is_err() || stream.read_exact(&mut data).is_err() {
                    return;
                }
                let mut state = lock(state);
                if state.apply_writes {
                    for (offset, byte) in data.into_iter().enumerate() {
                        state.overlay.insert(address + offset as u64, byte);
                    }
                }
                reply.extend(OK);
            }
            0xbdbb_0001 => {
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let interface = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                lock(state).events = TcpStream::connect((interface, 755)).ok();
                continue;
            }
            0xbdbb_0002 => {
                lock(state).events = None;
                reply.extend(OK);
            }
            0xbdbb_0003 | 0xbdbb_0004 | 0xbdbb_0006 | 0xbdbb_0007 => reply.extend(OK),
            0xbdbb_0005 => {
                reply.extend(OK);
                reply.extend(1u32.to_le_bytes());
                reply.extend(72u32.to_le_bytes());
            }
            0xbdbb_0008 => {
                reply.extend(OK);
                reply.extend(register_block());
            }
            0xbdbb_000a => {
                reply.extend(OK);
                reply.extend([0u8; 832]);
            }
            0xbdbb_0010 | 0xbdbb_0012 | 0xbdbb_0013 => {
                if stream.write_all(&OK).is_err() {
                    return;
                }
                let resume = command != 0xbdbb_0010 || body.first() == Some(&0);
                if resume && let Some(events) = lock(state).events.as_mut() {
                    let _ = events.write_all(&stop_event());
                }
                continue;
            }
            _ => return,
        }
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

/// The ps4debug protocol fixes the debug callback port at 755; serialize every
/// attach in this binary and skip where the host forbids binding it.
static CALLBACK_PORT: Mutex<()> = Mutex::new(());

fn callback_port() -> Option<MutexGuard<'static, ()>> {
    let guard = lock(&CALLBACK_PORT);
    if TcpListener::bind(("127.0.0.1", 755)).is_err() {
        eprintln!("skipping: cannot bind the fixed callback port 755 on this host");
        return None;
    }
    Some(guard)
}

/// Python `FakeSocket`: serve a canned response (in `fragment`-byte writes) on
/// every connection and record what the client sent and whether it closed.
struct Scripted {
    port: u16,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    closed: Arc<AtomicUsize>,
}

impl Scripted {
    fn spawn(response: Vec<u8>, fragment: usize, eof_after: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let (sent_handle, closed_handle) = (sent.clone(), closed.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let index = {
                    let mut sent = lock(&sent_handle);
                    sent.push(Vec::new());
                    sent.len() - 1
                };
                let (sent, closed, response) = (sent_handle.clone(), closed_handle.clone(), response.clone());
                let mut writer = stream.try_clone().unwrap();
                std::thread::spawn(move || {
                    for piece in response.chunks(fragment) {
                        if writer.write_all(piece).is_err() {
                            return;
                        }
                        if fragment < response.len() {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    if eof_after {
                        let _ = writer.shutdown(Shutdown::Write);
                    }
                });
                std::thread::spawn(move || {
                    let mut reader = stream;
                    let mut buffer = [0u8; 4096];
                    loop {
                        match reader.read(&mut buffer) {
                            Ok(count) if count > 0 => lock(&sent)[index].extend(&buffer[..count]),
                            _ => break,
                        }
                    }
                    closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Self { port, sent, closed }
    }

    fn sent(&self, connection: usize) -> Vec<u8> {
        lock(&self.sent).get(connection).cloned().unwrap_or_default()
    }

    fn wait_sent(&self, length: usize) -> Vec<u8> {
        wait_until(Duration::from_secs(3), || self.sent(0).len() >= length);
        self.sent(0)
    }

    fn wait_closed(&self) -> bool {
        wait_until(Duration::from_secs(3), || self.closed.load(Ordering::SeqCst) > 0)
    }
}

fn scripted_debugger(env: &mut Env, response: Vec<u8>, fragment: usize) -> (Scripted, Debugger) {
    let scripted = Scripted::spawn(response, fragment, false);
    env.port("debug", scripted.port);
    let debugger = Debugger::new(env.profile());
    (scripted, debugger)
}

fn qualified_scripted(env: &mut Env, permission: &str, response: Vec<u8>) -> (Scripted, Debugger) {
    let scripted = Scripted::spawn(response, 65536, false);
    env.port("debug", scripted.port);
    let debugger = Debugger::new(env.qualify(&[permission], &[]));
    (scripted, debugger)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Fake FTP server
// ---------------------------------------------------------------------------

struct FakeFtp {
    port: u16,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    seen: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
}

impl FakeFtp {
    fn spawn(files: &[(&str, &[u8])]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let files = Arc::new(Mutex::new(files.iter().map(|(path, data)| (path.to_string(), data.to_vec())).collect()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (files_handle, seen_handle, count) = (files.clone(), seen.clone(), connections.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                count.fetch_add(1, Ordering::SeqCst);
                let (files, seen) = (files_handle.clone(), seen_handle.clone());
                std::thread::spawn(move || serve_ftp(stream, &files, &seen));
            }
        });
        Self { port, files, seen, connections }
    }
}

fn serve_ftp(stream: TcpStream, files: &Mutex<BTreeMap<String, Vec<u8>>>, seen: &Mutex<Vec<String>>) {
    let mut writer = stream.try_clone().unwrap();
    let _ = writer.write_all(b"220 Test FTP\r\n");
    let mut passive: Option<TcpListener> = None;
    for line in BufReader::new(stream).lines().map_while(|line| line.ok()) {
        lock(seen).push(line.clone());
        let (verb, argument) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        let reply = match verb {
            "USER" => "331 Password required".to_owned(),
            "PASS" => "230 Logged in".to_owned(),
            "TYPE" | "NOOP" => "200 OK".to_owned(),
            "PASV" => {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                passive = Some(listener);
                format!("227 Entering Passive Mode (127,0,0,1,{},{})", port / 256, port % 256)
            }
            "LIST" | "RETR" | "STOR" => {
                let Some(listener) = passive.take() else { return };
                if verb == "RETR" && !lock(files).contains_key(argument) {
                    "550 No such file".to_owned()
                } else {
                    let (mut data, _) = listener.accept().unwrap();
                    let _ = writer.write_all(b"150 Data connection\r\n");
                    match verb {
                        "LIST" => {
                            let _ = data.write_all(b"-rw-r--r-- 1 root wheel 6 Jan 1 00:00 source\r\n");
                        }
                        "RETR" => {
                            let content = lock(files)[argument].clone();
                            let _ = data.write_all(&content);
                        }
                        _ => {
                            let mut content = Vec::new();
                            let _ = data.read_to_end(&mut content);
                            lock(files).insert(argument.to_owned(), content);
                        }
                    }
                    drop(data);
                    "226 Transfer complete".to_owned()
                }
            }
            "QUIT" => {
                let _ = writer.write_all(b"221 Bye\r\n");
                return;
            }
            _ => "500 Unsupported".to_owned(),
        };
        if writer.write_all(format!("{reply}\r\n").as_bytes()).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Broker fixtures
// ---------------------------------------------------------------------------

struct Running {
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_broker(hub: Arc<SessionHub>, token: String) -> Running {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (ready, bound) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(async move {
            let server = BrokerServer::bind(hub, "127.0.0.1:0".parse().unwrap(), token).await.unwrap();
            ready.send(server.local_addr().unwrap().port()).unwrap();
            server.run(async {
                let _ = stopped.await;
            }).await.unwrap();
        });
    });
    let port = bound.recv().unwrap();
    Running { url: format!("http://127.0.0.1:{port}"), stop: Some(stop), thread: Some(thread) }
}

/// Python `BrokerCase`: a hub over a debug_control/process_write qualified
/// profile whose debug port is a fake console.
struct Broker {
    env: Env,
    console: FakeConsole,
    hub: Arc<SessionHub>,
    token_path: PathBuf,
    token: String,
}

impl Broker {
    fn new() -> Self {
        let console = FakeConsole::spawn();
        let mut env = Env::new();
        env.port("debug", console.port);
        let profile = env.qualify(&["debug_control", "process_write"], &[]);
    let hub = Arc::new(SessionHub::from_registry(ToolRegistry::with_toolset(
        Workbench::new(profile).unwrap(),
        ps4_workbench_rs::tools::Toolset::Full,
    ).unwrap()));
        let token_path = env.dir.path().join("broker-token.local");
        let token = load_token(&token_path, true).unwrap();
        Self { env, console, hub, token_path, token }
    }

    fn run(&self) -> Running {
        run_broker(self.hub.clone(), self.token.clone())
    }

    fn client(&self, running: &Running, name: &str) -> BrokerClient {
        BrokerClient::new(&running.url, &self.token_path, name, None).unwrap()
    }

    fn attach(&self, client: &str) -> anyhow::Result<Value> {
        self.hub.call(client, "debug_attach", json!({"pid": 71, "listen_address": "127.0.0.1"}))
    }

    /// Python `stop_event`: a real stop event, pumped into the shared journal.
    fn stop(&self) {
        self.console.push_stop();
        assert!(wait_until(Duration::from_secs(3), || {
            self.hub.pump();
            self.hub.state()["execution_state"] == "stopped"
        }));
    }
}

/// Minimal HTTP stand-in for the broker answering `{"result": handler(envelope)}`.
fn mock_broker(handler: impl Fn(&Value) -> Value + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || {
                let mut data = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let Ok(count) = stream.read(&mut chunk) else { return };
                    if count == 0 {
                        return;
                    }
                    data.extend_from_slice(&chunk[..count]);
                    let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    let length = head.lines().find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok()).unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        break data[end + 4..end + 4 + length].to_vec();
                    }
                };
                let envelope: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let content = json!({"result": handler(&envelope)}).to_string();
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}", content.len()).as_bytes());
            });
        }
    });
    port
}

// ---------------------------------------------------------------------------
// Subprocess helpers (MCP stdio and CLI)
// ---------------------------------------------------------------------------

const BINARY: &str = env!("CARGO_BIN_EXE_ps4-workbench");
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tests","version":"1"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Mcp {
    fn spawn(arguments: &[&str]) -> Self {
        let mut child = Command::new(BINARY).args(arguments)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
                let _ = sender.send(line);
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        Self { stdin: child.stdin.take(), child, lines, stderr: Some(stderr) }
    }

    fn local(env: &Env) -> Self {
        Self::spawn(&["--profile", env.path().to_str().unwrap(), "serve"])
    }

    fn local_with_toolset(env: &Env, toolset: &str) -> Self {
        Self::spawn(&[
            "--profile",
            env.path().to_str().unwrap(),
            "--toolset",
            toolset,
            "serve",
        ])
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        let _ = stdin.write_all(line.as_bytes()).and_then(|()| stdin.write_all(b"\n")).and_then(|()| stdin.flush());
    }

    fn receive(&self) -> Value {
        let line = self.lines.recv_timeout(Duration::from_secs(30)).expect("MCP response");
        serde_json::from_str(&line).unwrap()
    }

    fn silent(&self, period: Duration) -> bool {
        self.lines.recv_timeout(period).is_err()
    }

    fn initialize(&mut self) -> Value {
        self.send(INITIALIZE);
        let response = self.receive();
        self.send(INITIALIZED);
        response
    }

    fn call(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}).to_string());
        let response = self.receive();
        assert_eq!(response["id"], id, "{response}");
        response
    }

    /// Close stdin (EOF) and wait for the server to exit.
    fn finish(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("MCP server did not exit after EOF");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        (status, self.stderr.take().unwrap().join().unwrap())
    }

    /// Close stdin, wait for exit and return every reply the server wrote.
    fn finish_collect(mut self) -> (ExitStatus, Vec<Value>) {
        let lines = std::mem::replace(&mut self.lines, mpsc::channel().1);
        let (status, _) = self.finish();
        let replies = std::iter::from_fn(|| lines.recv_timeout(Duration::from_secs(5)).ok())
            .map(|line| serde_json::from_str(&line).unwrap())
            .collect();
        (status, replies)
    }
}

fn request(id: Value, method: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method}).to_string()
}

fn cli(env: &Env, arguments: &[&str]) -> (bool, Value, String) {
    let output = Command::new(BINARY).arg("--profile").arg(env.path()).args(arguments).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (output.status.success(), value, String::from_utf8(output.stderr).unwrap())
}

// ===========================================================================
// test_broker.py
// ===========================================================================

/// `test_broker_startup_and_status_do_not_connect_to_console`
#[test]
fn broker_startup_and_status_do_not_connect_to_console() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let hub = Arc::new(SessionHub::from_registry(env.registry()));
    let token_path = env.dir.path().join("broker-token.local");
    let running = run_broker(hub, load_token(&token_path, true).unwrap());
    let client = BrokerClient::new(&running.url, &token_path, "ida", None).unwrap();
    assert!(client.state().unwrap()["attached_pid"].is_null());
    assert_eq!(client.call("console_status", json!({})).unwrap()["host"], "127.0.0.1");
    assert!(counters.values().all(|counter| counter.connections() == 0));
}

/// `test_only_one_controller_but_reads_allowed` (+ protocol
/// `test_attach_uses_network_order_callback_address`).
#[test]
fn only_one_controller_but_reads_allowed() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    let mut body = 71u32.to_le_bytes().to_vec();
    body.extend([127, 0, 0, 1]);
    assert_eq!(broker.console.bodies(0xbdbb_0001), vec![body]);
    let denied = broker.hub.call("ghidra", "debug_control", json!({"action": "resume"})).unwrap_err();
    assert!(denied.to_string().contains("Another client"), "{denied}");
    let read = broker.hub.call("ghidra", "memory_peek", json!({"pid": 71, "address": "0x4000", "length": 4})).unwrap();
    assert_eq!(read["hex"], "41414141");
    broker.hub.call("ida", "debug_detach", json!({})).unwrap();
}

/// `test_observer_cannot_detach_controller`
#[test]
fn observer_cannot_detach_controller() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    let denied = broker.hub.call("ghidra", "debug_detach", json!({})).unwrap_err();
    assert!(denied.to_string().contains("Another client"), "{denied}");
    assert_eq!(broker.hub.state()["attached_pid"], 71);
    assert!(broker.console.bodies(0xbdbb_0002).is_empty());
    broker.hub.call("ida", "debug_detach", json!({})).unwrap();
}

/// `test_event_cursors_are_independent`
#[test]
fn event_cursors_are_independent() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    broker.stop();
    let first = broker.hub.events_since(&json!(0), &json!(64)).unwrap();
    let second = broker.hub.events_since(&json!(0), &json!(64)).unwrap();
    assert_eq!(first["events"], second["events"]);
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    assert_eq!(first["events"][0]["type"], "stop");
    assert_eq!(first["events"][0]["pid"], 71);
    assert_eq!(broker.hub.events_since(&first["cursor"], &json!(64)).unwrap()["events"], json!([]));
    broker.hub.call("ida", "debug_detach", json!({})).unwrap();
}

/// `test_event_channel_failure_is_reported_once_without_fake_stop`
#[test]
fn event_channel_failure_is_reported_once_without_fake_stop() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    broker.console.drop_events();
    assert!(wait_until(Duration::from_secs(3), || {
        broker.hub.pump();
        broker.hub.state()["event_cursor"] != 0
    }));
    broker.hub.pump();
    broker.hub.pump();
    let events = broker.hub.events_since(&json!(0), &json!(64)).unwrap();
    let kinds: Vec<&Value> = events["events"].as_array().unwrap().iter().map(|event| &event["type"]).collect();
    assert_eq!(kinds, vec!["session_error"]);
    assert_eq!(broker.hub.state()["execution_state"], "uncertain");
}

/// `test_attach_failure_retains_lease_until_explicit_release`
#[test]
fn attach_failure_retains_lease_until_explicit_release() {
    let mut env = Env::new();
    env.port("debug", closed_port());
    let profile = env.qualify(&["debug_control"], &[]);
    let hub = SessionHub::from_registry(ToolRegistry::with_toolset(
        Workbench::new(profile).unwrap(),
        ps4_workbench_rs::tools::Toolset::Full,
    ).unwrap());
    assert!(hub.call("ida", "debug_attach", json!({"pid": 71, "listen_address": "127.0.0.1"})).is_err());
    assert_eq!(hub.state()["controller"], "ida");
    assert!(hub.dispatch("ghidra", &json!("release"), &Map::new()).is_err());
    hub.dispatch("ida", &json!("release"), &Map::new()).unwrap();
    assert!(hub.state()["controller"].is_null());
}

/// `test_payload_sending_blocked_while_attached`
#[test]
fn payload_sending_blocked_while_attached() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    let blocked = broker.hub.call("ida", "payload_execute", json!({})).unwrap_err();
    assert!(blocked.to_string().contains("Detach"), "{blocked}");
    broker.hub.call("ida", "debug_detach", json!({})).unwrap();
}

/// `test_mcp_proxy_reads_shared_session_and_does_not_close_owner`
#[test]
fn mcp_proxy_reads_shared_session_and_does_not_close_owner() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    broker.attach("ida").unwrap();
    broker.stop();
    {
        let running = broker.run();
        let mut registry = RemoteRegistry::new(broker.client(&running, "mcp")).unwrap();
        assert!(registry.available().iter().any(|tool| tool["name"] == "analysis_decompile"));
        assert_eq!(registry.call("session_state", json!({})).unwrap()["controller"], "ida");
        assert_eq!(registry.call("session_events", json!({})).unwrap()["events"].as_array().unwrap().len(), 1);
        assert_eq!(registry.call("session_events", json!({})).unwrap()["events"], json!([]));
        McpServer::remote(broker.client(&running, "mcp-proxy")).unwrap().close().unwrap();
    }
    assert_eq!(broker.hub.state()["attached_pid"], 71);
    assert!(broker.console.bodies(0xbdbb_0002).is_empty());
    broker.hub.call("ida", "debug_detach", json!({})).unwrap();
}

/// `test_existing_client_is_bound_to_original_profile`
#[test]
fn existing_client_is_bound_to_original_profile() {
    let env = Env::new();
    let hub = Arc::new(SessionHub::from_registry(env.registry()));
    let token_path = env.dir.path().join("broker-token.local");
    let running = run_broker(hub.clone(), load_token(&token_path, true).unwrap());
    let client = BrokerClient::new(&running.url, &token_path, "ida", None).unwrap();
    hub.registry().lock().unwrap().workbench.profile.data["name"] = json!("changed-profile");
    let mismatch = client.call("console_status", json!({})).unwrap_err();
    assert!(mismatch.to_string().contains("profile mismatch"), "{mismatch}");
}

/// `test_shared_mcp_subprocess_end_to_end`
#[test]
fn shared_mcp_subprocess_end_to_end() {
    let broker = Broker::new();
    let running = broker.run();
    let mut mcp = Mcp::spawn(&["--profile", broker.env.path().to_str().unwrap(), "serve", "--broker", &running.url,
        "--token-file", broker.token_path.to_str().unwrap()]);
    assert!(mcp.initialize()["result"].is_object());
    assert!(mcp.call(2, "session_state", json!({}))["result"]["structuredContent"]["data"]["controller"].is_null());
    assert_eq!(mcp.call(3, "analysis_status", json!({}))["result"]["isError"], false);
    let peek = mcp.call(4, "memory_peek", json!({"pid": 71, "address": "0x4000", "length": 4}));
    assert_eq!(peek["result"]["structuredContent"]["data"]["hex"], "41414141");
    let (status, stderr) = mcp.finish();
    assert!(status.success(), "{stderr}");
}

// ===========================================================================
// test_rsp.py
// ===========================================================================

fn attach_and_stop(broker: &Broker, session: &mut RspSession) {
    assert_eq!(session.handle(b"?").unwrap(), None);
    broker.stop();
    assert_eq!(session.poll_stop().unwrap(), Some(b"T05thread:48;".to_vec()));
}

/// `test_attach_waits_for_actual_stop_instead_of_fabricating`
#[test]
fn rsp_attach_waits_for_actual_stop_instead_of_fabricating() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    let running = broker.run();
    let mut session = RspSession::new(broker.client(&running, "gdb"), 71, "127.0.0.1", false).unwrap();
    assert_eq!(session.handle(b"?").unwrap(), None);
    assert_eq!(session.poll_stop().unwrap(), None);
    broker.stop();
    assert_eq!(session.poll_stop().unwrap(), Some(b"T05thread:48;".to_vec()));
    session.cleanup().unwrap();
    assert!(broker.hub.state()["attached_pid"].is_null());
}

/// `test_memory_registers_and_xml`
#[test]
fn rsp_memory_registers_and_xml() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    let running = broker.run();
    let mut session = RspSession::new(broker.client(&running, "gdb"), 71, "127.0.0.1", false).unwrap();
    attach_and_stop(&broker, &mut session);
    assert_eq!(session.handle(b"m4000,4").unwrap(), Some(b"41414141".to_vec()));
    assert_eq!(session.handle(b"p0").unwrap(), Some(b"3412000000000000".to_vec()));
    let map = session.handle(b"qXfer:memory-map:read::0,1000").unwrap().unwrap();
    assert!(contains(&map, b"memory-map") && contains(&map, b"start=\"0x4000\" length=\"0x4000\""));
    assert!(contains(&session.handle(b"qXfer:libraries-svr4:read::0,1000").unwrap().unwrap(), b"library-list-svr4"));
    let target = session.handle(b"qXfer:features:read:target.xml:0,1000").unwrap().unwrap();
    assert!(target.starts_with(b"l<?xml") && contains(&target, b"org.gnu.gdb.i386.sse"));
    session.cleanup().unwrap();
}

/// `test_observer_reads_same_session_but_cannot_control`
#[test]
fn rsp_observer_reads_same_session_but_cannot_control() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    let running = broker.run();
    let owner_client = broker.client(&running, "gdb");
    let mut owner = RspSession::new(owner_client.clone(), 71, "127.0.0.1", false).unwrap();
    attach_and_stop(&broker, &mut owner);
    let mut observer = RspSession::new(owner_client.with_identity("ghidra").unwrap(), 71, "127.0.0.1", true).unwrap();
    assert_eq!(observer.handle(b"?").unwrap(), Some(b"T05thread:48;".to_vec()));
    assert_eq!(observer.handle(b"m4000,1").unwrap(), Some(b"41".to_vec()));
    assert!(observer.handle(b"c").unwrap_err().to_string().contains("Observer"));
    observer.cleanup().unwrap();
    assert_eq!(broker.hub.state()["attached_pid"], 71);
    owner.cleanup().unwrap();
}

/// `test_continue_and_step_wait_for_real_events`
#[test]
fn rsp_continue_and_step_wait_for_real_events() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    let running = broker.run();
    let mut session = RspSession::new(broker.client(&running, "gdb"), 71, "127.0.0.1", false).unwrap();
    attach_and_stop(&broker, &mut session);
    assert_eq!(session.handle(b"c").unwrap(), None);
    assert_eq!(broker.hub.state()["execution_state"], "running");
    assert_eq!(session.poll_stop().unwrap(), None);
    assert!(wait_until(Duration::from_secs(3), || {
        broker.hub.pump();
        broker.hub.state()["execution_state"] == "stopped"
    }));
    assert_eq!(session.poll_stop().unwrap(), Some(b"T05thread:48;".to_vec()));
    assert_eq!(session.handle(b"s").unwrap(), None);
    assert_eq!(broker.console.bodies(0xbdbb_0013), vec![72u32.to_le_bytes().to_vec()]);
    session.cleanup().unwrap();
}

/// `test_breakpoint_slots_and_idempotent_removal`
#[test]
fn rsp_breakpoint_slots_and_idempotent_removal() {
    let Some(_port) = callback_port() else { return };
    let broker = Broker::new();
    let running = broker.run();
    let mut session = RspSession::new(broker.client(&running, "gdb"), 71, "127.0.0.1", false).unwrap();
    attach_and_stop(&broker, &mut session);
    assert_eq!(session.handle(b"Z0,4000,1").unwrap(), Some(b"OK".to_vec()));
    assert_eq!(session.handle(b"Z0,4000,1").unwrap(), Some(b"OK".to_vec()));
    assert_eq!(broker.console.bodies(0xbdbb_0003).len(), 1);
    assert_eq!(session.handle(b"z0,4000,1").unwrap(), Some(b"OK".to_vec()));
    assert_eq!(session.handle(b"z0,4000,1").unwrap(), Some(b"OK".to_vec()));
    assert_eq!(broker.console.bodies(0xbdbb_0003).len(), 2);
    session.cleanup().unwrap();
}

/// Consumer audit for wire `json_safe`: map addresses above 2^53 arrive as hex strings.
#[test]
fn rsp_memory_map_accepts_hex_string_addresses_above_2_pow_53() {
    let xml = memory_map_xml(&[json!({"start": "0xffffffff80000000", "end": "0xffffffff80001000", "protection": 5})]).unwrap();
    assert!(contains(&xml, b"start=\"0xffffffff80000000\" length=\"0x1000\""));
}

// ===========================================================================
// test_agents_and_extraction.py — AgentTests
// ===========================================================================

/// `test_real_worker_and_broker_static_decompile`
#[test]
fn real_worker_and_broker_static_decompile() {
    let broker = Broker::new();
    let running = broker.run();
    let mut worker = AnalysisWorker::start(broker.client(&running, "ida-agent"), "ida", &"a".repeat(64),
        Box::new(|operation, _| Ok(json!({"text": "return 42;", "operation": operation})))).unwrap();
    let mut registry = RemoteRegistry::new(broker.client(&running, "mcp")).unwrap();
    let result = registry.call("analysis_decompile", json!({"target": "ida", "address": "0x4000"})).unwrap();
    assert_eq!(result["text"], "return 42;");
    assert_eq!(registry.call("analysis_status", json!({})).unwrap()["ida"]["connected"], true);
    worker.stop().unwrap();
}

/// `test_no_agent_is_an_explicit_failure`
#[test]
fn no_agent_is_an_explicit_failure() {
    let hub = SessionHub::from_registry(Env::new().registry());
    for (target, tool, arguments) in [("ghidra", "analysis_functions", json!({"target": "ghidra"})),
        ("binja", "analysis_functions", json!({"target": "binja"})),
        ("iaito", "analysis_xrefs", json!({"target": "iaito", "address": "0x1000"}))] {
        let error = hub.call("mcp", tool, arguments).unwrap_err();
        assert!(error.to_string().contains(&format!("No live {target}")), "{error}");
    }
}

/// `test_foreign_agent_cannot_complete_job`
#[test]
fn foreign_agent_cannot_complete_job() {
    let agents = Arc::new(AnalysisAgents::new());
    agents.register("first", &json!("ida"), &json!("program")).unwrap();
    let submitter = agents.clone();
    let pending = std::thread::spawn(move || submitter.submit("ida", "functions", json!({}), Duration::from_secs(5)));
    let mut job = Value::Null;
    assert!(wait_until(Duration::from_secs(3), || {
        job = agents.poll("first", &json!("ida")).unwrap();
        !job.is_null()
    }));
    let foreign = agents.complete("second", &job["id"], json!("fake"), Value::Null).unwrap_err();
    assert!(foreign.to_string().contains("Foreign"), "{foreign}");
    agents.complete("first", &job["id"], json!([]), Value::Null).unwrap();
    assert_eq!(pending.join().unwrap().unwrap(), json!([]));
}

/// `test_agent_exception_is_reported_not_fabricated`
#[test]
fn agent_exception_is_reported_not_fabricated() {
    let broker = Broker::new();
    let running = broker.run();
    let mut worker = AnalysisWorker::start(broker.client(&running, "agent"), "ghidra", "hash",
        Box::new(|_, _| Err(anyhow::anyhow!("Decompiler unavailable")))).unwrap();
    let failure = broker.client(&running, "mcp")
        .call("analysis_decompile", json!({"target": "ghidra", "address": "0x4000"})).unwrap_err();
    assert!(failure.to_string().contains("Decompiler unavailable"), "{failure}");
    worker.stop().unwrap();
}

/// `test_late_job_result_does_not_kill_analysis_worker`
#[test]
fn late_job_result_does_not_kill_analysis_worker() {
    let finished = Arc::new(AtomicBool::new(false));
    let jobs = Arc::new(Mutex::new(VecDeque::from([
        json!({"id": "late", "operation": "functions", "arguments": {}}),
        json!({"id": "current", "operation": "functions", "arguments": {}}),
    ])));
    let signal = finished.clone();
    let port = mock_broker(move |envelope| match envelope["operation"].as_str().unwrap_or_default() {
        "state" => json!({"profile_sha256": "c".repeat(64)}),
        "agent_poll" => lock(&jobs).pop_front().unwrap_or(Value::Null),
        "agent_result" if envelope["arguments"]["identifier"] == "late" => json!({"accepted": false}),
        "agent_result" => {
            signal.store(true, Ordering::SeqCst);
            json!({"accepted": true})
        }
        _ => json!({}),
    });
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("token.local");
    std::fs::write(&token_path, "ab".repeat(32)).unwrap();
    let client = BrokerClient::new(&format!("http://127.0.0.1:{port}"), &token_path, "ida-agent", None).unwrap();
    let mut worker = AnalysisWorker::start(client, "ida", "hash", Box::new(|_, _| Ok(json!([])))).unwrap();
    assert!(wait_until(Duration::from_secs(5), || finished.load(Ordering::SeqCst)));
    assert!(worker.running());
    assert!(worker.last_error().unwrap_or_default().contains("expiration"));
    worker.stop().unwrap();
}

// ===========================================================================
// test_agents_and_extraction.py — ExtractionTests
// ===========================================================================

/// `test_multi_file_extraction_retains_paths_and_hashes`
#[test]
fn multi_file_extraction_retains_paths_and_hashes() {
    let ftp = FakeFtp::spawn(&[("/data/a", b"one"), ("/data/b", b"two")]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    let workbench = env.workbench();
    let result = workbench.ftp_extract(&["/data/a".into(), "/data/b".into()]).unwrap();
    assert_eq!(result["complete"], true);
    assert_eq!(result["total_bytes"], 6);
    let manifest: Value = serde_json::from_slice(&workbench.store.read(result["manifest"]["path"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(manifest["files"][0]["remote_path"], "/data/a");
    assert_eq!(manifest["files"][0]["artifact"]["metadata"]["remote_path"], "/data/a");
    assert_eq!(manifest["files"][1]["artifact"]["sha256"], digest(b"two"));
}

/// `test_extraction_budget_failure_is_partial_not_success`
#[test]
fn extraction_budget_failure_is_partial_not_success() {
    let ftp = FakeFtp::spawn(&[("/data/a", b"one"), ("/data/b", b"two")]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    env.settings["limits"]["transfer_bytes"] = json!(5);
    let result = env.workbench().ftp_extract(&["/data/a".into(), "/data/b".into()]).unwrap();
    assert_eq!(result["complete"], false);
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.iter().filter(|file| file["complete"] == true).count(), 1);
    assert!(files.last().unwrap()["error"].as_str().unwrap().contains("limit"));
}

/// `test_duplicate_and_traversal_paths_rejected_before_network`
#[test]
fn extraction_rejects_bad_path_sets_before_network() {
    let ftp = FakeFtp::spawn(&[]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    let workbench = env.workbench();
    assert!(workbench.ftp_extract(&[]).is_err());
    let traversal = workbench.ftp_extract(&["/data/ok".into(), "/data/../x".into()]).unwrap_err();
    assert!(traversal.to_string().contains("traversal"), "{traversal}");
    let duplicate = workbench.ftp_extract(&["/data/a".into(), "/data/a".into()]).unwrap_err();
    assert!(duplicate.to_string().contains("Duplicate"), "{duplicate}");
    assert_eq!(ftp.connections.load(Ordering::SeqCst), 0);
}

fn region_workbench(console: &FakeConsole, memory_bytes: u64) -> (Env, Workbench) {
    let mut env = Env::new();
    env.port("debug", console.port);
    env.settings["limits"]["memory_bytes"] = json!(memory_bytes);
    let workbench = env.workbench();
    (env, workbench)
}

/// `test_region_dump_chunks_and_keeps_provenance`
#[test]
fn region_dump_chunks_and_keeps_provenance() {
    let console = FakeConsole::spawn();
    console.configure(|state| state.maps = vec![(0x1000, 0x2000, 1, "")]);
    let (_env, mut workbench) = region_workbench(&console, 4);
    let result = workbench.region_dump(71, 0x1000, 10).unwrap();
    assert_eq!(result["complete"], true);
    let lengths: Vec<u32> = console.bodies(0xbdaa_0002).iter()
        .map(|body| u32::from_le_bytes(body[12..16].try_into().unwrap())).collect();
    assert_eq!(lengths, vec![4, 4, 2]);
    let path = result["artifact"]["path"].as_str().unwrap();
    assert_eq!(workbench.store.read(path).unwrap(), b"A".repeat(10));
    assert_eq!(result["artifact"]["metadata"]["process"]["pid"], 71);
    assert_eq!(result["artifact"]["metadata"]["requested_length"], 10);
}

/// `test_region_dump_preserves_partial_capture`
#[test]
fn region_dump_preserves_partial_capture() {
    let console = FakeConsole::spawn();
    console.configure(|state| {
        state.maps = vec![(0x1000, 0x2000, 1, "")];
        state.read_budget = Some(1);
    });
    let (_env, mut workbench) = region_workbench(&console, 4);
    let result = workbench.region_dump(71, 0x1000, 10).unwrap();
    assert_eq!(result["complete"], false);
    assert!(result["error"].is_string());
    assert_eq!(workbench.store.read(result["artifact"]["path"].as_str().unwrap()).unwrap(), b"AAAA");
}

/// `test_region_dump_rejects_mapping_gap_before_read`
#[test]
fn region_dump_rejects_mapping_gap_before_read() {
    let console = FakeConsole::spawn();
    console.configure(|state| state.maps = vec![(0x1000, 0x1004, 1, ""), (0x1008, 0x1010, 1, "")]);
    let (_env, mut workbench) = region_workbench(&console, 1_048_576);
    let error = workbench.region_dump(71, 0x1000, 12).unwrap_err();
    assert!(error.to_string().contains("unmapped"), "{error}");
    assert!(console.bodies(0xbdaa_0002).is_empty());
}

// ===========================================================================
// test_safety.py — SafetyTests
// ===========================================================================

/// `test_default_status_makes_no_network_connections`
#[test]
fn default_status_makes_no_network_connections() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let status = env.workbench().status(false).unwrap();
    assert_eq!(status["compatibility"]["state"], "hardware_unverified");
    assert!(counters.values().all(|counter| counter.connections() == 0));
}

/// `test_probe_never_touches_payload_port`
#[test]
fn probe_never_touches_payload_port() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    env.workbench().status(true).unwrap();
    // The debug handshake's TCP accept on the counter side is asynchronous;
    // allow it to land before asserting (CI scheduling varies).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    for service in ["ftp", "klog", "debug"] {
        while counters[service].connections() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(counters[service].connections() >= 1, "{service}");
    }
    assert_eq!(counters["payload"].connections(), 0);
}

/// `test_malformed_qualification_is_unverified_not_crash`
#[test]
fn malformed_qualification_is_unverified_not_crash() {
    let env = Env::new();
    let workbench = env.workbench();
    std::fs::write(workbench.profile.qualification_path(), "not JSON").unwrap();
    assert_eq!(workbench.status(false).unwrap()["compatibility"]["state"], "hardware_unverified");
}

/// `test_ftp_download_enforces_cap_without_size_support`
#[test]
fn ftp_download_enforces_cap_without_size_support() {
    let ftp = FakeFtp::spawn(&[("/data/file", b"12345")]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    env.settings["limits"]["transfer_bytes"] = json!(4);
    let error = transports::ftp_download(&env.profile(), "/data/file").unwrap_err();
    assert!(error.to_string().contains("limit"), "{error}");
}

/// `test_ftp_upload_path_allowlist_before_connection`
#[test]
fn ftp_upload_path_allowlist_before_connection() {
    let ftp = FakeFtp::spawn(&[]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    let workbench = Workbench::new(env.qualify(&["ftp_upload"], &[])).unwrap();
    let artifact = workbench.store.save("upload", b"content", json!({}), "bin").unwrap();
    let error = workbench.ftp_upload(artifact["path"].as_str().unwrap(), "/system/file",
        artifact["sha256"].as_str().unwrap()).unwrap_err();
    assert!(error.to_string().contains("allowed roots"), "{error}");
    assert_eq!(ftp.connections.load(Ordering::SeqCst), 0);
}

/// Process-wide payload gate: serialize payload sends and let the 1 s cooldown lapse.
static PAYLOAD_GATE: Mutex<()> = Mutex::new(());

fn payload_binary() -> Vec<u8> {
    (0..4096u32).map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// Save a payload and its manifest; returns (manifest path, sha256).
fn payload_manifest(workbench: &Workbench, content: &[u8]) -> (String, String) {
    let binary = workbench.store.save("payload", content, json!({}), "bin").unwrap();
    let jailbreak = &workbench.profile.data["jailbreak"];
    let record = json!({"artifact": binary["path"], "sha256": binary["sha256"], "firmware": "14.00",
        "afterglow_commit": jailbreak["installed_commit"], "hen_build": jailbreak["hen_build"],
        "format": "bin", "loader": "goldhen-binloader", "source_commit": "c".repeat(40)});
    let manifest = workbench.store.save("manifest", record.to_string().as_bytes(), json!({}), "json").unwrap();
    (manifest["path"].as_str().unwrap().to_owned(), binary["sha256"].as_str().unwrap().to_owned())
}

/// `test_payload_requires_permission_before_network`
#[test]
fn payload_requires_permission_before_network() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let error = env.workbench().send_payload("not-present", &"a".repeat(64)).unwrap_err();
    assert!(error.to_string().contains("Disabled"), "{error}");
    assert_eq!(counters["payload"].connections(), 0);
}

/// `test_elf_payload_is_never_sent_to_binloader`
#[test]
fn elf_payload_is_never_sent_to_binloader() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let workbench = Workbench::new(env.qualify(&["payload_execute"], &[])).unwrap();
    let mut elf = b"\x7fELF".to_vec();
    elf.extend(payload_binary());
    let (manifest, sha256) = payload_manifest(&workbench, &elf);
    let error = workbench.send_payload(&manifest, &sha256).unwrap_err();
    assert!(error.to_string().contains("ELF"), "{error}");
    assert_eq!(counters["payload"].connections(), 0);
}

/// `test_payload_requires_artifact_allowlist`
#[test]
fn payload_requires_artifact_allowlist() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let workbench = Workbench::new(env.qualify(&["payload_execute"], &[])).unwrap();
    let (manifest, sha256) = payload_manifest(&workbench, &payload_binary());
    let error = workbench.send_payload(&manifest, &sha256).unwrap_err();
    assert!(error.to_string().contains("allowlist"), "{error}");
    assert_eq!(counters["payload"].connections(), 0);
}

fn payload_env(payload_port: u16, content: &[u8]) -> Env {
    let mut env = Env::new();
    env.port("payload", payload_port).port("ftp", closed_port()).port("klog", closed_port()).port("debug", closed_port());
    env.settings["limits"]["payload_cooldown_seconds"] = json!(1);
    env.qualify(&["payload_execute"], &[digest(content)]);
    env
}

/// `test_payload_transport_failure_is_uncertain_and_never_retried`
#[test]
fn payload_transport_failure_is_uncertain_and_never_retried() {
    let _gate = lock(&PAYLOAD_GATE);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            let mut first = [0u8; 1024];
            let _ = stream.read(&mut first);
            // Dropping with unread data resets the connection mid-transfer.
            drop(stream);
        }
    });
    let content: Vec<u8> = (0..8 * 1024 * 1024u32).map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let env = payload_env(port, &content);
    let workbench = env.workbench();
    let (manifest, sha256) = payload_manifest(&workbench, &content);
    std::thread::sleep(Duration::from_millis(1100));
    // Whether the reset surfaces during the write (error) or only after the OS
    // buffered everything (reported reset) depends on the host's socket
    // buffering; either way the outcome is uncertain and never retried.
    match workbench.send_payload(&manifest, &sha256) {
        Err(error) => {
            assert!(format!("{error:#}").to_lowercase().contains("never retry"), "{error:#}");
            assert!(env.audit(&workbench).contains("payload_send_uncertain"));
        }
        Ok(result) => {
            assert_eq!(result["execution_verified"], false);
            assert_eq!(result["loader_closed_cleanly"], false);
            assert!(result["warning"].as_str().unwrap().contains("never retry"));
        }
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// `test_payload_bytes_sent_is_not_execution_success`
#[test]
fn payload_bytes_sent_is_not_execution_success() {
    let _gate = lock(&PAYLOAD_GATE);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut content = Vec::new();
            let _ = stream.read_to_end(&mut content);
            lock(&sink).extend(content);
        }
    });
    let content = payload_binary();
    let env = payload_env(port, &content);
    let workbench = env.workbench();
    let (manifest, sha256) = payload_manifest(&workbench, &content);
    std::thread::sleep(Duration::from_millis(1100));
    let result = workbench.send_payload(&manifest, &sha256).unwrap();
    assert_eq!(result["execution_verified"], false);
    assert!(wait_until(Duration::from_secs(3), || lock(&received).len() == content.len()));
    assert_eq!(*lock(&received), content);
}

fn write_workbench(console: &FakeConsole) -> (Env, Workbench) {
    let mut env = Env::new();
    env.port("debug", console.port);
    let workbench = Workbench::new(env.qualify(&["process_write"], &[])).unwrap();
    (env, workbench)
}

/// `test_compare_before_write_mismatch_prevents_write`
#[test]
fn compare_before_write_mismatch_prevents_write() {
    let console = FakeConsole::spawn();
    let (_env, mut workbench) = write_workbench(&console);
    let error = workbench.memory_write(71, 0x4000, &hex::encode(b"new"), &hex::encode(b"bad"), false).unwrap_err();
    assert!(error.to_string().contains("Original bytes differ"), "{error}");
    assert!(console.bodies(0xbdaa_0003).is_empty());
}

/// `test_write_keeps_backup_replacement_and_readback`
#[test]
fn write_keeps_backup_replacement_and_readback() {
    let console = FakeConsole::spawn();
    let (_env, mut workbench) = write_workbench(&console);
    let result = workbench.memory_write(71, 0x4000, &hex::encode(b"new"), &hex::encode(b"AAA"), false).unwrap();
    assert_eq!(result["verified"], true);
    let read = |key: &str| workbench.store.read(result[key]["path"].as_str().unwrap()).unwrap();
    assert_eq!(read("backup"), b"AAA");
    assert_eq!(read("replacement"), b"new");
    assert_eq!(read("readback"), b"new");
}

/// `test_readback_mismatch_logs_uncertainty_without_retry`
#[test]
fn readback_mismatch_logs_uncertainty_without_retry() {
    let console = FakeConsole::spawn();
    console.configure(|state| state.apply_writes = false);
    let (env, mut workbench) = write_workbench(&console);
    let error = workbench.memory_write(71, 0x4000, &hex::encode(b"new"), &hex::encode(b"AAA"), false).unwrap_err();
    assert!(error.to_string().contains("readback mismatch"), "{error}");
    assert_eq!(console.bodies(0xbdaa_0003).len(), 1);
    assert!(env.audit(&workbench).contains("memory_write_uncertain"));
}

// ===========================================================================
// test_safety.py — ToolTests
// ===========================================================================

/// `test_mutations_hidden_by_default`
#[test]
fn mutations_hidden_by_default() {
    let mut registry = Env::new().registry();
    let names: Vec<Value> = registry.available().iter().map(|tool| tool["name"].clone()).collect();
    for name in ["payload_execute", "memory_write", "kernel_read", "kernel_write", "debug_attach", "sdk_build", "ftp_upload"] {
        assert!(!names.contains(&json!(name)), "{name}");
        let error = registry.call(name, json!({})).unwrap_err();
        assert!(error.to_string().contains("disabled"), "{name}: {error}");
    }
}

/// `test_schema_rejects_unknown_arguments_before_network`
#[test]
fn schema_rejects_unknown_arguments_before_network() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let error = env.registry().call("console_status", json!({"execute_payload": true})).unwrap_err();
    assert!(error.to_string().contains("execute_payload"), "{error}");
    assert!(counters.values().all(|counter| counter.connections() == 0));
}

/// `test_schema_rejects_bool_instead_of_pid`
#[test]
fn schema_rejects_bool_instead_of_pid() {
    let error = Env::new().registry().call("process_info", json!({"pid": true})).unwrap_err();
    assert!(error.to_string().contains("integer"), "{error}");
}

/// `test_large_results_saved_not_inline`
#[test]
fn large_results_saved_not_inline() {
    let mut registry = Env::new().registry();
    for index in 0..150u32 {
        registry.workbench.store.save("memory", &index.to_le_bytes(), json!({"index": index}), "bin").unwrap();
    }
    let result = registry.call("artifact_list", json!({})).unwrap();
    let saved = result["result_saved"]["path"].as_str().expect("result saved as artifact");
    let stored: Value = serde_json::from_slice(&registry.workbench.store.read(saved).unwrap()).unwrap();
    assert_eq!(stored.as_array().unwrap().len(), 150);
}

/// `test_no_policy_or_qualification_tool`
#[test]
fn no_policy_or_qualification_tool() {
    let mut env = Env::new();
    for permission in ["ftp_upload", "payload_execute", "process_inject", "process_write", "debug_control", "kernel_read", "kernel_write", "build"] {
        env.settings["permissions"][permission] = json!(true);
    }
    let registry = env.registry();
    let names: Vec<String> = registry.available().iter().map(|tool| tool["name"].as_str().unwrap().to_owned()).collect();
    assert!(names.contains(&"payload_execute".to_owned()));
    assert!(!names.iter().any(|name| name.contains("qualif") || name.contains("permission")), "{names:?}");
}

// ===========================================================================
// test_protocol.py
// ===========================================================================

/// `test_identity_decimal_firmware_and_exact_headers`
#[test]
fn identity_decimal_firmware_and_exact_headers() {
    let mut env = Env::new();
    let (scripted, mut debugger) = scripted_debugger(&mut env, good_identity(), 1);
    let identity = debugger.probe().unwrap();
    assert_eq!(identity["firmware"], "14.00");
    assert_eq!(identity["binary_hash_remotely_verified"], false);
    let expected: Vec<u8> = [0xbd00_0001u32, 0xbd00_0501, 0xbd00_0500, 0xbd00_0502].iter()
        .flat_map(|command| header(*command, 0)).collect();
    assert_eq!(scripted.wait_sent(expected.len()), expected);
}

/// `test_reject_documented_bcd_encoding_instead_of_guessing`
#[test]
fn reject_documented_bcd_encoding_instead_of_guessing() {
    let mut env = Env::new();
    let (scripted, mut debugger) = scripted_debugger(&mut env, identity(b"1.3", BRAND, 0x1400, 4), 65536);
    assert!(debugger.probe().unwrap_err().to_string().contains("firmware mismatch"));
    assert!(scripted.wait_closed());
}

/// `test_reject_wrong_firmware`
#[test]
fn reject_wrong_firmware() {
    let mut env = Env::new();
    let (_scripted, mut debugger) = scripted_debugger(&mut env, identity(b"1.3", BRAND, 1202, 4), 65536);
    assert!(debugger.processes().unwrap_err().to_string().contains("firmware mismatch"));
}

/// `test_reject_unknown_protocol_before_extra_commands`
#[test]
fn reject_unknown_protocol_before_extra_commands() {
    let mut env = Env::new();
    // Only the protocol reply: fully consumed, so the close is a clean FIN.
    let (scripted, mut debugger) = scripted_debugger(&mut env, text(b"2.0"), 65536);
    assert!(debugger.probe().unwrap_err().to_string().contains("protocol"));
    assert!(scripted.wait_closed());
    assert_eq!(scripted.sent(0).len(), 12);
}

/// `test_reject_legacy_brand`
#[test]
fn reject_legacy_brand() {
    let mut env = Env::new();
    let (_scripted, mut debugger) = scripted_debugger(&mut env, identity(b"1.3", b"ps4debug 1.3", 1400, 4), 65536);
    assert!(debugger.probe().unwrap_err().to_string().contains("branding"));
}

/// `test_reject_wrong_platform`
#[test]
fn reject_wrong_platform() {
    let mut env = Env::new();
    let (_scripted, mut debugger) = scripted_debugger(&mut env, identity(b"1.3", BRAND, 1400, 5), 65536);
    assert!(debugger.probe().unwrap_err().to_string().contains("PS4"));
}

/// `test_reject_oversized_identity`
#[test]
fn reject_oversized_identity() {
    let mut env = Env::new();
    let (scripted, mut debugger) = scripted_debugger(&mut env, 1_048_577u32.to_le_bytes().to_vec(), 65536);
    assert!(debugger.probe().unwrap_err().to_string().contains("identity length"));
    assert!(scripted.wait_closed());
}

/// `test_partial_eof_drops_connection`
#[test]
fn partial_eof_drops_connection() {
    let mut env = Env::new();
    let scripted = Scripted::spawn(b"\x03\x00".to_vec(), 65536, true);
    env.port("debug", scripted.port);
    let error = Debugger::new(env.profile()).probe().unwrap_err();
    assert!(format!("{error:#}").contains("disconnected"), "{error:#}");
    assert!(scripted.wait_closed());
}

/// `test_rejected_command_drops_connection`
#[test]
fn rejected_command_drops_connection() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(REJECTED);
    let (scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    assert!(debugger.processes().unwrap_err().to_string().contains("rejected"));
    assert!(scripted.wait_closed());
}

/// `test_process_list`
#[test]
fn process_list_with_fragmented_reply() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(1u32.to_le_bytes());
    response.extend(process_entry(b"eboot.bin", 71));
    let (_scripted, mut debugger) = scripted_debugger(&mut env, response, 7);
    assert_eq!(debugger.processes().unwrap(), json!([{"name": "eboot.bin", "pid": 71}]));
}

/// `test_list_count_cap`
#[test]
fn list_count_cap() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(u32::MAX.to_le_bytes());
    let (scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    assert!(debugger.processes().unwrap_err().to_string().contains("entry count"));
    assert!(scripted.wait_closed());
}

/// `test_maps_wire_layout`
#[test]
fn maps_wire_layout() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(1u32.to_le_bytes());
    // Upstream packed `proc_vm_map_entry`: name[32], start, end, offset (u64), prot (u16).
    let mut name = [0u8; 32];
    name[..6].copy_from_slice(b"module");
    response.extend(name);
    for value in [0x4000u64, 0x5000, 0x1000] {
        response.extend(value.to_le_bytes());
    }
    response.extend(5u16.to_le_bytes());
    let (_scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    assert_eq!(debugger.maps(71).unwrap()[0],
        json!({"start": 0x4000, "end": 0x5000, "offset": 0x1000, "protection": 5, "name": "module"}));
}

fn packed_map(name: &str, start: u64, end: u64, offset: u64, prot: u16) -> Vec<u8> {
    let mut entry = vec![0u8; 32];
    entry[..name.len()].copy_from_slice(name.as_bytes());
    for value in [start, end, offset] {
        entry.extend(value.to_le_bytes());
    }
    entry.extend(prot.to_le_bytes());
    assert_eq!(entry.len(), 58);
    entry
}

/// Consecutive 58-byte entries must not drift (a 64-byte stride misreads entry 2+),
/// and named non-executable maps (heaps, shm) are not modules.
#[test]
fn maps_stride_and_module_grouping_follow_live_layout() {
    let mut env = Env::new();
    let entries = [
        packed_map("executable", 0x6aba_0000, 0x6b69_8000, 0, 5),
        packed_map("executable", 0x6b69_8000, 0x6b6e_4000, 0, 3),
        packed_map("__vm_gc_heap", 0x8_0000_0000, 0x8_0010_0000, 0, 3),
        packed_map("libkernel.sprx", 0x8_1000_0000, 0x8_1004_0000, 0x4000, 5),
    ];
    let mut maps_reply = OK.to_vec();
    maps_reply.extend((entries.len() as u32).to_le_bytes());
    for entry in &entries {
        maps_reply.extend(entry);
    }
    let mut response = good_identity();
    response.extend(&maps_reply);
    response.extend(&maps_reply);
    let (_scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    let maps = debugger.maps(42).unwrap();
    assert_eq!(maps.as_array().unwrap().len(), 4);
    assert_eq!(maps[3], json!({"start": 0x8_1000_0000u64, "end": 0x8_1004_0000u64, "offset": 0x4000,
        "protection": 5, "name": "libkernel.sprx"}));
    let modules = debugger.module_list(42).unwrap();
    let names: Vec<&str> = modules.as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["executable", "libkernel.sprx"]);
    assert_eq!(modules[0]["base"], "0x6aba0000");
    assert_eq!(modules[0]["size"], 0x6b6e_4000u64 - 0x6aba_0000);
}

/// `test_memory_read_body_has_no_native_padding`
#[test]
fn memory_read_body_has_no_native_padding() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(b"test");
    let (scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    assert_eq!(debugger.read_memory(71, 0x1122_3344_5566_7788, 4, false).unwrap(), b"test");
    let mut expected = header(0xbdaa_0002, 16);
    expected.extend(71u32.to_le_bytes());
    expected.extend(0x1122_3344_5566_7788u64.to_le_bytes());
    expected.extend(4u32.to_le_bytes());
    assert!(scripted.wait_sent(76).ends_with(&expected));
}

#[test]
fn rpc_install_uses_exact_packed_request_and_rejects_null_stub() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(0x9000_1234u64.to_le_bytes());
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_inject", response);
    assert_eq!(debugger.install_rpc(71).unwrap(), 0x9000_1234);
    let mut expected = header(0xbdaa_0005, 4);
    expected.extend(71u32.to_le_bytes());
    assert!(scripted.wait_sent(64).ends_with(&expected));

    let mut response = good_identity();
    response.extend(OK);
    response.extend(0u64.to_le_bytes());
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_inject", response);
    assert!(debugger.install_rpc(71).unwrap_err().to_string().contains("null RPC stub"));
    assert!(scripted.wait_closed());
}

#[test]
fn rpc_call_uses_68_byte_body_and_checks_response_pid() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(71u32.to_le_bytes());
    response.extend(0x1122_3344_5566_7788u64.to_le_bytes());
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_inject", response);
    let arguments = [1, 2, 3, 4, 5, 6];
    assert_eq!(
        debugger.call_rpc(71, 0x9000, 0x5000, arguments).unwrap(),
        0x1122_3344_5566_7788
    );
    let mut expected = header(0xbdaa_0006, 68);
    expected.extend(71u32.to_le_bytes());
    expected.extend(0x9000u64.to_le_bytes());
    expected.extend(0x5000u64.to_le_bytes());
    for argument in arguments {
        expected.extend(argument.to_le_bytes());
    }
    assert_eq!(expected.len(), 80);
    assert!(scripted.wait_sent(48 + 80).ends_with(&expected));
}

#[test]
fn elf_rpc_consumes_ready_upload_final_status_and_entry() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(OK);
    response.extend(0x8000_5000u64.to_le_bytes());
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_inject", response);
    let elf = b"\x7fELF-test-payload";
    assert_eq!(debugger.load_elf_rpc(71, elf).unwrap(), 0x8000_5000);
    let mut expected = header(0xbdaa_0010, 8);
    expected.extend(71u32.to_le_bytes());
    expected.extend((elf.len() as u32).to_le_bytes());
    expected.extend(elf);
    assert!(scripted.wait_sent(48 + 20 + elf.len()).ends_with(&expected));
}

fn internals_artifacts(workbench: &Workbench) -> (String, String, String, Vec<u8>) {
    let mut builder = ps4_workbench_rs::binimage::testelf::Builder::new(0);
    builder.text = (0u8..64).collect();
    builder.symbols.push(("payload_rpc_entry".into(), builder.text_va(), 64));
    let elf = builder.build();
    let payload_sha256 = digest(&elf);
    let signature = builder.text[..16].to_vec();
    let target = json!({
        "format":"ps4wb-internals-target-v1","name":"Apex fixture","title_id":"CUSA12552",
        "process_name":"eboot.bin","process_path":"/app0/eboot.bin","application_version":"01.00",
        "executable_text_sha256":digest(&vec![0x41; 0x4000]),"status_magic":"0x41584553",
        "fingerprints":[{"address":"0x4000","hex":"41414141414141414141414141414141"}],
        "pointers":[{"address":"0x4008","expected":"0x4141414141414141"}]
    });
    let target_path = workbench.store.save("internals-target", &serde_json::to_vec(&target).unwrap(), json!({}), "json").unwrap()["path"].as_str().unwrap().to_owned();
    let payload_path = workbench.store.save("internals-payload", &elf, json!({}), "elf").unwrap()["path"].as_str().unwrap().to_owned();
    (target_path, payload_path, payload_sha256, signature)
}

#[test]
fn resident_payload_stages_controls_and_reuses_one_rpc_stub() {
    let console = FakeConsole::spawn();
    let mut env = Env::new();
    env.port("debug", console.port);
    let workbench = Workbench::new(env.profile()).unwrap();
    let (target, payload, sha256, signature) = internals_artifacts(&workbench);
    console.configure(|state| {
        for (index, byte) in signature.iter().enumerate() {
            // Seed outside the eboot text map (0x4000-0x8000): seeding inside it
            // would change the executable-text SHA-256 that payload_stage verifies.
            state.overlay.insert(0x9000 + index as u64, *byte);
        }
    });
    let profile = env.qualify(&["process_inject"], std::slice::from_ref(&sha256));
    let workbench = Workbench::new(profile).unwrap();
    let mut registry = ToolRegistry::with_toolset(workbench, ps4_workbench_rs::tools::Toolset::Full).unwrap();
    let staged = registry.call("payload_stage", json!({"pid":71,"target":target,"payload":payload,"sha256":sha256})).unwrap();
    assert_eq!(staged["status"]["lifecycle_name"], "ready");
    assert_eq!(staged["raw_entry_called"], false);
    let status = registry.call("payload_status", json!({"pid":71})).unwrap();
    assert_eq!(status["lifecycle"], 2);
    let rpc = registry.call("payload_rpc", json!({"pid":71,"command":4,"argument":"0x2","argument2":"0x3"})).unwrap();
    assert_eq!(rpc["command"], 4);
    let shutdown = registry.call("payload_shutdown", json!({"pid":71})).unwrap();
    assert_eq!(shutdown["status"]["lifecycle_name"], "disabled");
    assert_eq!(console.rpc_installs(), 1);
    assert_eq!(console.elf_uploads(), 1);
}

#[test]
fn resident_signature_recovers_and_duplicate_stage_never_uploads() {
    let console = FakeConsole::spawn();
    let mut env = Env::new();
    env.port("debug", console.port);
    let workbench = Workbench::new(env.profile()).unwrap();
    let (target, payload, sha256, signature) = internals_artifacts(&workbench);
    let profile = env.qualify(&["process_inject"], std::slice::from_ref(&sha256));
    let workbench = Workbench::new(profile).unwrap();
    console.configure(|state| {
        state.maps.push((0x9000, 0xa000, 5, ""));
        for (index, byte) in signature.iter().enumerate() {
            state.overlay.insert(0x9000 + index as u64, *byte);
        }
    });
    let mut registry = ToolRegistry::with_toolset(workbench, ps4_workbench_rs::tools::Toolset::Full).unwrap();
    let error = registry.call("payload_stage", json!({"pid":71,"target":target,"payload":payload,"sha256":sha256})).unwrap_err();
    assert!(error.to_string().contains("already resident"), "{error:#}");
    assert_eq!(console.rpc_installs(), 0);
    assert_eq!(console.elf_uploads(), 0);
    let recovered = registry.call("payload_recover", json!({"pid":71,"target":target,"payload":payload,"sha256":sha256})).unwrap();
    assert_eq!(recovered["rpc_entry"], "0x9000");
    assert_eq!(recovered["status"]["lifecycle_name"], "ready");
    assert_eq!(console.rpc_installs(), 1);
    assert_eq!(console.elf_uploads(), 0);
}

/// `test_memory_bounds_before_connect`
#[test]
fn memory_bounds_before_connect() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let profile = env.profile();
    let limit = profile.limit("memory_bytes");
    let mut debugger = Debugger::new(profile);
    for length in [0, limit + 1] {
        assert!(debugger.read_memory(1, 0, length, false).is_err(), "{length}");
    }
    assert_eq!(counters["debug"].connections(), 0);
}

/// `test_get_registers_consumes_176_only`
#[test]
fn get_registers_consumes_176_only() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend([0u8; 176]);
    response.extend(OK);
    response.extend(1u32.to_le_bytes());
    response.extend(process_entry(b"next", 9));
    let (_scripted, mut debugger) = scripted_debugger(&mut env, response, 65536);
    debugger.attached_pid = Some(71);
    assert_eq!(debugger.get_registers(72).unwrap()["rip"], "0x0");
    assert_eq!(debugger.processes().unwrap(), json!([{"name": "next", "pid": 9}]));
    debugger.attached_pid = None;
}

/// `test_writes_denied_without_any_connection`
#[test]
fn writes_denied_without_any_connection() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    let error = Debugger::new(env.profile()).write_memory(1, 0, b"a", false).unwrap_err();
    assert!(error.to_string().contains("Disabled"), "{error}");
    assert_eq!(counters["debug"].connections(), 0);
}

/// `test_process_write_consumes_both_statuses`
#[test]
fn process_write_consumes_both_statuses() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(OK);
    response.extend(OK);
    response.extend(1u32.to_le_bytes());
    response.extend(process_entry(b"next", 9));
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_write", response);
    debugger.write_memory(71, 0x4000, b"new", false).unwrap();
    assert_eq!(debugger.processes().unwrap(), json!([{"name": "next", "pid": 9}]));
    let mut expected = header(0xbdaa_0003, 16);
    expected.extend(71u32.to_le_bytes());
    expected.extend(0x4000u64.to_le_bytes());
    expected.extend(3u32.to_le_bytes());
    expected.extend(b"new");
    assert!(contains(&scripted.wait_sent(48 + 31 + 12), &expected));
}

/// `test_process_write_requires_verified_write_capability`
#[test]
fn process_write_requires_verified_write_capability() {
    let mut env = Env::new();
    let response = identity(b"1.3", b"ps4debug-NG by Pharaoh2k v1.3.4\x001.0", 1400, 4);
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_write", response);
    let error = debugger.write_memory(71, 0x4000, b"new", false).unwrap_err();
    assert!(error.to_string().contains("capability"), "{error}");
    assert!(scripted.wait_closed());
    assert_eq!(scripted.sent(0).len(), 48);
}

/// `test_write_terminal_error_is_not_success`
#[test]
fn write_terminal_error_is_not_success() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(REJECTED);
    let (scripted, mut debugger) = qualified_scripted(&mut env, "process_write", response);
    assert!(debugger.write_memory(71, 0x4000, b"new", false).unwrap_err().to_string().contains("rejected"));
    assert!(scripted.wait_closed());
}

/// `test_kernel_write_two_statuses`
#[test]
fn kernel_write_two_statuses() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(OK);
    let (scripted, mut debugger) = qualified_scripted(&mut env, "kernel_write", response);
    debugger.write_memory(0, 0xffff_ffff_8000_1000, b"x", true).unwrap();
    let mut expected = header(0xbdcc_0003, 12);
    expected.extend(0xffff_ffff_8000_1000u64.to_le_bytes());
    expected.extend(1u32.to_le_bytes());
    expected.extend(b"x");
    assert!(scripted.wait_sent(48 + 25).ends_with(&expected));
}

/// `kernel_write` then `kernel_search` through the full registry path against
/// the FakeConsole kernel handlers (0xbdcc0001/2/3).
#[test]
fn kernel_write_and_search_through_registry() {
    let console = FakeConsole::spawn();
    let mut env = Env::new();
    env.port("debug", console.port);
    env.qualify(&["kernel_read", "kernel_write"], &[]);
    let mut registry = env.registry();

    let base = registry.call("kernel_base", json!({})).unwrap();
    assert_eq!(base["kernel_base"], "0x80000000");

    // FakeConsole kernel reads default to 0x4b; seed a pattern via kernel_write.
    let written = registry.call("kernel_write", json!({
        "address": "0x80000100", "hex_data": "488b05414141", "expected_hex": "4b4b4b4b4b4b",
    })).unwrap();
    assert_eq!(written["verified"], true);
    assert_eq!(console.bodies(0xbdcc_0003).len(), 1);

    let found = registry.call("kernel_search", json!({
        "address": "0x80000000", "length": 0x200, "pattern": "48 8b ??", "max_results": 16,
    })).unwrap();
    assert_eq!(found["count"], 1, "{found}");
    assert_eq!(found["matches"][0], "0x80000100");
    assert_eq!(found["kernel"], true);
    assert!(console.bodies(0xbdcc_0002).len() >= 2, "write expected-byte read + search reads");

    // Without kernel_read approval the tool stays closed.
    let mut plain = Env::new().registry();
    assert!(plain.call("kernel_search", json!({"address": "0x0", "length": 16, "pattern": "48"}))
        .unwrap_err().to_string().contains("disabled"));
}

/// `payload_run`, `process_call`, `memory_scan_server` and `process_find`
/// through the full registry path against FakeConsole.
#[test]
fn payload_run_process_call_server_scan_and_process_find() {
    let console = FakeConsole::spawn();
    let mut env = Env::new();
    env.port("debug", console.port);
    let workbench = Workbench::new(env.profile()).unwrap();
    let (target, payload, sha256, _signature) = internals_artifacts(&workbench);
    let profile = env.qualify(&["process_inject"], std::slice::from_ref(&sha256));
    let workbench = Workbench::new(profile).unwrap();
    let mut registry = ToolRegistry::with_toolset(workbench, ps4_workbench_rs::tools::Toolset::Full).unwrap();

    let run = registry.call("payload_run", json!({"pid":71,"payload":payload,"sha256":sha256})).unwrap();
    assert_eq!(run["server_spawned_entry"], true);
    assert_eq!(console.elf_uploads(), 1);

    let called = registry.call("process_call", json!({"pid":71,"target":target,"address":"0x4000","arguments":["0x1","0x2"]})).unwrap();
    assert_eq!(called["fingerprint_verified"], true);
    let expected = (0x4158_4553u64 << 32) | 2;
    assert_eq!(called["rax"], format!("{expected:#x}"));

    let error = registry.call("process_call", json!({"pid":71,"target":target,"address":"0x5000"})).unwrap_err();
    assert!(error.to_string().contains("fingerprint"), "{error}");

    let scan = registry.call("memory_scan_server", json!({"pid":71,"value_type":"bytes","data_hex":"414141","max_results":4})).unwrap();
    assert_eq!(scan["count"], 4);
    assert_eq!(scan["matches"][0], "0x4000");
    assert_eq!(scan["truncated"], true);
    assert_eq!(scan["server_side"], true);

    let found = registry.call("process_find", json!({"name":"SAMP"})).unwrap();
    assert_eq!(found["count"], 1);
    assert_eq!(found["matches"][0]["pid"], 71);
    assert_eq!(registry.call("process_find", json!({"name":"zzz"})).unwrap()["count"], 0);

    // A payload outside the allowlist is rejected before any byte is sent.
    let mut env2 = Env::new();
    env2.port("debug", console.port);
    let wb2 = Workbench::new(env2.profile()).unwrap();
    let (_t2, payload2, sha2, _s2) = internals_artifacts(&wb2);
    let wb2 = Workbench::new(env2.qualify(&["process_inject"], &[])).unwrap();
    let mut reg2 = ToolRegistry::with_toolset(wb2, ps4_workbench_rs::tools::Toolset::Full).unwrap();
    let err = reg2.call("payload_run", json!({"pid":71,"payload":payload2,"sha256":sha2})).unwrap_err();
    assert!(err.to_string().contains("allowlist"), "{err}");
    assert_eq!(console.elf_uploads(), 1);
}

/// `test_watchpoint_encoding`
#[test]
fn watchpoint_encoding() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    let (scripted, mut debugger) = qualified_scripted(&mut env, "debug_control", response);
    debugger.attached_pid = Some(71);
    debugger.watchpoint(2, 0x4000, 4, "write", true).unwrap();
    debugger.attached_pid = None;
    let mut expected = Vec::new();
    for word in [2u32, 1, 3, 1] {
        expected.extend(word.to_le_bytes());
    }
    expected.extend(0x4000u64.to_le_bytes());
    assert!(scripted.wait_sent(48 + 36).ends_with(&expected));
}

// ===========================================================================
// test_loopback.py
// ===========================================================================

/// `test_real_tcp_debugger_handshake_and_reads`
#[test]
fn real_tcp_debugger_handshake_and_reads() {
    let mut env = Env::new();
    let mut response = good_identity();
    response.extend(OK);
    response.extend(1u32.to_le_bytes());
    response.extend(process_entry(b"sample", 71));
    response.extend(OK);
    response.extend(b"test");
    let (scripted, mut debugger) = scripted_debugger(&mut env, response, 3);
    assert_eq!(debugger.processes().unwrap(), json!([{"pid": 71, "name": "sample"}]));
    assert_eq!(debugger.read_memory(71, 0x4000, 4, false).unwrap(), b"test");
    let sent = scripted.wait_sent(6 * 12 + 16);
    let mut commands = Vec::new();
    let mut offset = 0;
    while offset + 12 <= sent.len() {
        assert_eq!(u32::from_le_bytes(sent[offset..offset + 4].try_into().unwrap()), MAGIC);
        commands.push(u32::from_le_bytes(sent[offset + 4..offset + 8].try_into().unwrap()));
        offset += 12 + u32::from_le_bytes(sent[offset + 8..offset + 12].try_into().unwrap()) as usize;
    }
    assert_eq!(commands, vec![0xbd00_0001, 0xbd00_0501, 0xbd00_0500, 0xbd00_0502, 0xbdaa_0001, 0xbdaa_0002]);
    let mut body = 71u32.to_le_bytes().to_vec();
    body.extend(0x4000u64.to_le_bytes());
    body.extend(4u32.to_le_bytes());
    assert!(sent.ends_with(&body));
}

/// `test_real_tcp_klog_capture_saves_raw_bytes`
#[test]
fn real_tcp_klog_capture_saves_raw_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for (index, mut stream) in listener.incoming().flatten().enumerate() {
            if index == 0 {
                let _ = stream.write_all(b"kernel log\n\xffbinary\n");
            } else {
                held.push(stream);
            }
        }
    });
    let mut env = Env::new();
    env.port("klog", port);
    let capture = transports::klog_capture(&env.profile(), 1).unwrap();
    assert_eq!(capture.content, b"kernel log\n\xffbinary\n");
    assert!(!capture.ended_early);
}

/// `test_real_ftp_login_list_retr_and_verified_stor`
#[test]
fn real_ftp_login_list_retr_and_verified_stor() {
    let ftp = FakeFtp::spawn(&[("/data/source", b"sample")]);
    let mut env = Env::new();
    env.port("ftp", ftp.port);
    let workbench = Workbench::new(env.qualify(&["ftp_upload"], &[])).unwrap();
    let listing = transports::ftp_list(&workbench.profile, "/data").unwrap();
    assert_eq!(listing["listing"].as_array().unwrap().len(), 1);
    let artifact = workbench.ftp_download("/data/source").unwrap();
    let path = artifact["path"].as_str().unwrap();
    assert_eq!(workbench.store.read(path).unwrap(), b"sample");
    let result = workbench.ftp_upload(path, "/data/ps4-debugmcps/sample", artifact["sha256"].as_str().unwrap()).unwrap();
    assert_eq!(result["readback_verified"], true);
    assert_eq!(lock(&ftp.files)["/data/ps4-debugmcps/sample"], b"sample");
    assert!(lock(&ftp.seen).contains(&"STOR /data/ps4-debugmcps/sample".to_owned()));
}

/// `test_subprocess_mcp_stdio_end_to_end` and MCP `test_status_tool_no_network`.
#[test]
fn subprocess_mcp_stdio_end_to_end_without_network() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    env.profile();
    let mut mcp = Mcp::local(&env);
    assert_eq!(mcp.initialize()["id"], 1);
    mcp.send(&request(json!(2), "tools/list"));
    let tools = mcp.receive();
    assert_eq!(tools["id"], 2);
    assert!(tools["result"]["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "console_status"));
    let status = mcp.call(3, "console_status", json!({}));
    assert_eq!(status["result"]["isError"], false);
    let text: Value = serde_json::from_str(status["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["data"]["compatibility"]["state"], "hardware_unverified");
    let (exit, stderr) = mcp.finish();
    assert!(exit.success(), "{stderr}");
    assert_eq!(stderr, "");
    assert!(counters.values().all(|counter| counter.connections() == 0));
}

// ===========================================================================
// test_mcp_and_development.py — MCPTests (stdio transport)
// ===========================================================================

fn plain_mcp() -> (Env, Mcp) {
    let env = Env::new();
    env.profile();
    let mcp = Mcp::local(&env);
    (env, mcp)
}

/// `test_initialization_lifecycle`
#[test]
fn mcp_initialization_lifecycle() {
    let (_env, mut mcp) = plain_mcp();
    mcp.send(&request(json!(1), "tools/list"));
    assert!(mcp.receive()["error"].is_object());
    assert_eq!(mcp.initialize()["result"]["protocolVersion"], "2025-11-25");
    mcp.send(&request(json!(2), "tools/list"));
    assert!(mcp.receive()["result"]["tools"].is_array());
    mcp.finish();
}

/// `test_unsupported_version_negotiates_supported_version`
#[test]
fn mcp_unsupported_version_negotiates_supported_version() {
    let (_env, mut mcp) = plain_mcp();
    mcp.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"unknown","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#);
    assert_eq!(mcp.receive()["result"]["protocolVersion"], "2025-11-25");
    mcp.finish();
}

/// `test_invalid_initialize_does_not_initialize`
#[test]
fn mcp_invalid_initialize_does_not_initialize() {
    let (_env, mut mcp) = plain_mcp();
    mcp.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    mcp.send(&request(json!(2), "tools/list"));
    let (_, replies) = mcp.finish_collect();
    assert!(replies.iter().any(|reply| reply["id"] == 1 && reply["error"].is_object()), "{replies:?}");
    assert!(replies.iter().all(|reply| reply["result"].is_null()), "{replies:?}");
}

/// `test_tool_failure_is_mcp_error_content`
#[test]
fn mcp_tool_failure_is_error_content() {
    let (_env, mut mcp) = plain_mcp();
    mcp.initialize();
    let response = mcp.call(2, "artifact_read", json!({"artifact": "missing.bin"}));
    assert_eq!(response["result"]["isError"], true);
    assert!(response["error"].is_null());
    mcp.finish();
}

/// `test_notifications_have_no_response`
#[test]
fn mcp_notifications_have_no_response() {
    let (_env, mut mcp) = plain_mcp();
    mcp.initialize();
    mcp.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}"#);
    mcp.send(&request(json!(2), "ping"));
    assert_eq!(mcp.receive(), json!({"jsonrpc": "2.0", "id": 2, "result": {}}));
    mcp.finish();
}

/// `test_invalid_request_ids_and_batches`
#[test]
fn mcp_invalid_request_ids_and_batches() {
    let (_env, mut mcp) = plain_mcp();
    mcp.initialize();
    for invalid in ["[]".to_owned(), request(json!(true), "ping"), request(Value::Null, "ping")] {
        mcp.send(&invalid);
        assert_eq!(mcp.receive()["error"]["code"], -32600, "{invalid}");
    }
    mcp.finish();
}

/// `test_unknown_method`
#[test]
fn mcp_unknown_method() {
    let (_env, mut mcp) = plain_mcp();
    mcp.initialize();
    mcp.send(&request(json!(2), "unknown"));
    assert_eq!(mcp.receive()["error"]["code"], -32601);
    mcp.finish();
}

/// `test_stream_parse_errors_and_ping_no_stdout_noise`
#[test]
fn mcp_stream_parse_errors_and_ping_no_stdout_noise() {
    let (_env, mut mcp) = plain_mcp();
    mcp.send("{invalid}");
    assert_eq!(mcp.receive()["error"]["code"], -32700);
    mcp.send(&request(json!(7), "ping"));
    assert_eq!(mcp.receive(), json!({"jsonrpc": "2.0", "id": 7, "result": {}}));
    mcp.initialize();
    let (status, stderr) = mcp.finish();
    assert!(status.success() && stderr.is_empty(), "{stderr}");
}

/// `test_nonfinite_json_rejected`
#[test]
fn mcp_nonfinite_json_rejected() {
    let (_env, mut mcp) = plain_mcp();
    mcp.send(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}"#);
    let response = mcp.receive();
    assert_eq!(response["error"]["code"], -32700);
    assert!(response["id"].is_null());
    mcp.finish();
}

/// `test_oversize_input_closes_transport`
#[test]
fn mcp_oversize_input_closes_transport() {
    let (_env, mut mcp) = plain_mcp();
    mcp.initialize();
    mcp.send(&"x".repeat(ps4_workbench_rs::mcp::MAX_MESSAGE + 1));
    let response = mcp.receive();
    assert!(response["error"]["message"].as_str().unwrap().contains("exceeds"), "{response}");
    mcp.send(&request(json!(2), "ping"));
    assert!(mcp.silent(Duration::from_millis(500)));
    let deadline = Instant::now() + Duration::from_secs(10);
    while mcp.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "transport stayed open after an oversized message");
        std::thread::sleep(Duration::from_millis(20));
    }
    mcp.finish();
}

/// `test_eof_always_cleans_up_session`
#[test]
fn mcp_eof_always_cleans_up_session() {
    let Some(_port) = callback_port() else { return };
    let console = FakeConsole::spawn();
    let mut env = Env::new();
    env.port("debug", console.port);
    env.qualify(&["debug_control"], &[]);
    let mut mcp = Mcp::local_with_toolset(&env, "debug");
    mcp.initialize();
    let attached = mcp.call(2, "debug_attach", json!({"pid": 71, "listen_address": "127.0.0.1"}));
    assert_eq!(attached["result"]["isError"], false, "{attached}");
    assert!(console.bodies(0xbdbb_0002).is_empty());
    let (status, stderr) = mcp.finish();
    assert!(status.success(), "{stderr}");
    assert_eq!(console.bodies(0xbdbb_0002).len(), 1);
}

// ===========================================================================
// test_mcp_and_development.py — CLITests
// ===========================================================================

/// `test_validate_command_no_network`
#[test]
fn cli_validate_command_no_network() {
    let mut env = Env::new();
    let counters = counted_services(&mut env);
    env.profile();
    let (success, output, stderr) = cli(&env, &["validate"]);
    assert!(success, "{stderr}");
    assert_eq!(output["compatibility"]["state"], "hardware_unverified");
    assert!(counters.values().all(|counter| counter.connections() == 0));
}

/// `test_local_ingest`
#[test]
fn cli_local_ingest() {
    let env = Env::new();
    env.profile();
    let source = env.dir.path().join("source.bin");
    std::fs::write(&source, b"local").unwrap();
    let (success, output, stderr) = cli(&env, &["ingest", source.to_str().unwrap()]);
    assert!(success, "{stderr}");
    assert_eq!(env.workbench().store.read(output["path"].as_str().unwrap()).unwrap(), b"local");
}

/// `test_qualification_does_not_invent_installed_versions`
#[test]
fn cli_qualification_does_not_invent_installed_versions() {
    let mut env = Env::new();
    env.settings["permissions"]["ftp_upload"] = json!(true);
    env.profile();
    let evidence = env.dir.path().join("evidence.txt");
    std::fs::write(&evidence, "I tested this configuration on my hardware").unwrap();
    let (success, _, stderr) = cli(&env, &["qualify", "--evidence", evidence.to_str().unwrap(),
        "--attest", ATTESTATION, "--approve", "ftp_upload"]);
    assert!(!success);
    assert!(stderr.contains("actual"), "{stderr}");
    assert!(!env.profile().qualification_path().exists());
}

/// `test_qualification_records_evidence_not_guarantee`
#[test]
fn cli_qualification_records_evidence_not_guarantee() {
    let mut env = Env::new();
    env.settings["jailbreak"]["installed_commit"] = json!("a".repeat(40));
    env.settings["jailbreak"]["hen_build"] = json!("test-hen");
    env.settings["permissions"]["ftp_upload"] = json!(true);
    env.profile();
    let evidence = env.dir.path().join("evidence.txt");
    std::fs::write(&evidence, "I tested this configuration on my hardware").unwrap();
    let (success, record, stderr) = cli(&env, &["qualify", "--evidence", evidence.to_str().unwrap(),
        "--attest", ATTESTATION, "--approve", "ftp_upload"]);
    assert!(success, "{stderr}");
    assert_eq!(record["hardware_compatibility_guaranteed"], false);
    let approved = env.profile().require("ftp_upload").unwrap();
    assert!(approved["approved_permissions"].as_array().unwrap().contains(&json!("ftp_upload")));
}
