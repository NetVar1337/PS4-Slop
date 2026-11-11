use crate::{Result, config::Profile, link};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn connect(profile: &Profile, port: u16) -> Result<TcpStream> {
    let address: SocketAddr = format!("{}:{port}", profile.host()).parse()?;
    let stream = TcpStream::connect_timeout(&address, profile.timeout())?;
    stream.set_read_timeout(Some(profile.timeout()))?;
    stream.set_write_timeout(Some(profile.timeout()))?;
    Ok(stream)
}

pub fn remote_path(path: &str) -> Result<String> {
    ensure!(
        path.starts_with('/')
            && !path.starts_with("//")
            && !path.contains('\\')
            && path.len() <= 1024,
        "Remote path must be absolute POSIX syntax"
    );
    ensure!(
        !path.chars().any(|character| character.is_control()),
        "Control characters forbidden in remote paths"
    );
    ensure!(
        !path.split('/').any(|component| component == ".."),
        "Parent traversal forbidden"
    );
    let components: Vec<_> = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    Ok(format!("/{}", components.join("/")))
}

pub fn probe_services(profile: &Profile) -> Result<Value> {
    let mut services = json!({});
    for service in ["payload", "ftp", "klog", "debug"] {
        let mut entry = json!({"port":profile.port(service),"state":"configured_not_probed"});
        if service == "ftp" {
            match probe_ftp(profile) {
                Ok(banner) => {
                    link::record_ok("ftp");
                    entry["state"] = json!("ftp_banner_220");
                    entry["banner"] = json!(banner);
                }
                Err(error) => {
                    link::record_err("ftp", &error);
                    entry["state"] = json!("unreachable");
                    entry["error"] = json!(error.to_string());
                }
            }
        } else if service != "payload" {
            let name: &'static str = if service == "klog" { "klog" } else { "debug" };
            match connect(profile, profile.port(service)) {
                Ok(_) => {
                    link::record_ok(name);
                    entry["state"] = json!("tcp_reachable_not_protocol_verified");
                }
                Err(error) => {
                    link::record_err(name, &error);
                    entry["state"] = json!("unreachable");
                    entry["error"] = json!(error.to_string());
                }
            }
        }
        services[service] = entry;
    }
    Ok(services)
}

/// Connect, read the 220 greeting, and leave politely with QUIT so the console's
/// small FTP slot table is released immediately.
fn probe_ftp(profile: &Profile) -> Result<String> {
    let mut ftp = Ftp::open_unauthenticated(profile)?;
    let banner = ftp.expect(&[220])?;
    let _ = ftp.command("QUIT");
    Ok(banner.chars().take(120).collect())
}

struct Ftp<'a> {
    profile: &'a Profile,
    control: TcpStream,
    deadline: Instant,
}

impl Drop for Ftp<'_> {
    /// Always release the console-side FTP slot, even after a failed transfer.
    fn drop(&mut self) {
        let _ = self
            .control
            .set_write_timeout(Some(Duration::from_millis(500)));
        let _ = self
            .control
            .set_read_timeout(Some(Duration::from_millis(500)));
        if self.control.write_all(b"QUIT\r\n").is_ok() {
            let mut sink = [0; 256];
            let _ = self.control.read(&mut sink);
        }
        let _ = self.control.shutdown(Shutdown::Both);
    }
}

impl<'a> Ftp<'a> {
    fn open_unauthenticated(profile: &'a Profile) -> Result<Self> {
        Ok(Self {
            profile,
            control: connect(profile, profile.port("ftp"))?,
            deadline: Instant::now() + Duration::from_secs(10),
        })
    }

    fn begin(&mut self) {
        self.deadline = Instant::now() + Duration::from_secs(60);
    }

    fn open(profile: &'a Profile) -> Result<Self> {
        let mut ftp = Self {
            profile,
            control: connect(profile, profile.port("ftp"))?,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        ftp.expect(&[220])?;
        let (code, _) = ftp.command("USER anonymous")?;
        if code == 331 {
            ftp.command_expect("PASS anonymous@", &[230])?;
        } else {
            ensure!(code == 230, "FTP anonymous login rejected: {code}");
        }
        ftp.command_expect("TYPE I", &[200])?;
        Ok(ftp)
    }

    fn remaining(&self) -> Result<Duration> {
        Ok(self.profile.timeout().min(
            self.deadline
                .checked_duration_since(Instant::now())
                .context("FTP exceeded 60-second deadline")?,
        ))
    }

    fn line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        loop {
            self.control.set_read_timeout(Some(self.remaining()?))?;
            let mut byte = [0];
            self.control.read_exact(&mut byte)?;
            line.push(byte[0]);
            ensure!(line.len() <= 8192, "FTP response line too long");
            if byte[0] == b'\n' {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_owned())
    }

    fn response(&mut self) -> Result<(u16, String)> {
        let first = self.line()?;
        ensure!(
            first.len() >= 4 && first.as_bytes()[..3].iter().all(u8::is_ascii_digit),
            "Invalid FTP response"
        );
        let code: u16 = first[..3].parse()?;
        let mut text = first.clone();
        if first.as_bytes()[3] == b'-' {
            let terminal = format!("{code} ");
            loop {
                let line = self.line()?;
                ensure!(
                    text.len() + line.len() < 65536,
                    "FTP multiline response too long"
                );
                text.push('\n');
                text.push_str(&line);
                if line.starts_with(&terminal) {
                    break;
                }
            }
        } else {
            ensure!(
                first.as_bytes()[3] == b' ',
                "Invalid FTP response separator"
            );
        }
        Ok((code, text))
    }

    fn expect(&mut self, codes: &[u16]) -> Result<String> {
        let (code, text) = self.response()?;
        ensure!(codes.contains(&code), "FTP command rejected: {text}");
        Ok(text)
    }

    fn command(&mut self, command: &str) -> Result<(u16, String)> {
        ensure!(
            !command.contains(['\r', '\n']),
            "FTP command injection rejected"
        );
        self.control.set_write_timeout(Some(self.remaining()?))?;
        self.control
            .write_all(format!("{command}\r\n").as_bytes())?;
        self.response()
    }

    fn command_expect(&mut self, command: &str, codes: &[u16]) -> Result<String> {
        let (code, text) = self.command(command)?;
        ensure!(codes.contains(&code), "FTP command rejected: {text}");
        Ok(text)
    }

    fn data(&mut self, command: &str) -> Result<TcpStream> {
        let response = self.command_expect("PASV", &[227])?;
        let start = response.rfind('(').context("Invalid passive response")?;
        let end = response[start..]
            .find(')')
            .context("Invalid passive response")?
            + start;
        let fields = response[start + 1..end]
            .split(',')
            .map(|part| part.trim().parse::<u8>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(fields.len() == 6, "Invalid passive address");
        let port = fields[4] as u16 * 256 + fields[5] as u16;
        ensure!(
            port > 0
                && ![
                    self.profile.port("payload"),
                    self.profile.port("debug"),
                    self.profile.port("klog"),
                    self.profile.port("ftp")
                ]
                .contains(&port),
            "Unsafe FTP passive port"
        );
        let stream = connect(self.profile, port)?;
        self.command_expect(command, &[125, 150])?;
        Ok(stream)
    }

    fn download_to<W: Write>(
        &mut self,
        command: &str,
        writer: &mut W,
        maximum: usize,
    ) -> Result<usize> {
        let mut stream = self.data(command)?;
        let mut total = 0usize;
        let mut buffer = [0; 65536];
        loop {
            stream.set_read_timeout(Some(self.remaining()?))?;
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            ensure!(
                total + count <= maximum,
                "FTP transfer exceeds byte limit"
            );
            writer.write_all(&buffer[..count])?;
            total += count;
        }
        drop(stream);
        self.expect(&[226, 250])?;
        Ok(total)
    }

    fn download(&mut self, command: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut content = Vec::new();
        self.download_to(command, &mut content, maximum)?;
        Ok(content)
    }
}

/// One reusable FTP control connection for multi-file reads. A session idle for
/// more than ten seconds is revalidated with NOOP; a failed or dead session is
/// replaced and the (read-only) transfer retried once on a fresh connection.
pub struct FtpBatch<'a> {
    profile: &'a Profile,
    session: Option<(Ftp<'a>, Instant)>,
}

impl<'a> FtpBatch<'a> {
    pub fn new(profile: &'a Profile) -> Self {
        Self {
            profile,
            session: None,
        }
    }

    fn ready(&mut self) -> Result<&mut Ftp<'a>> {
        if let Some((ftp, used)) = self.session.as_mut()
            && used.elapsed() > Duration::from_secs(10)
        {
            ftp.begin();
            if ftp.command_expect("NOOP", &[200]).is_err() {
                self.session = None;
            }
        }
        if self.session.is_none() {
            self.session = Some((Ftp::open(self.profile)?, Instant::now()));
        }
        let (ftp, used) = self.session.as_mut().context("FTP session unavailable")?;
        *used = Instant::now();
        ftp.begin();
        Ok(ftp)
    }

    pub fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        let path = remote_path(path)?;
        let limit = self.profile.limit("transfer_bytes");
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = self
                .ready()
                .and_then(|ftp| ftp.download(&format!("RETR {path}"), limit));
            match result {
                Ok(content) => {
                    link::record_ok("ftp");
                    return Ok(content);
                }
                Err(error) => {
                    self.session = None;
                    link::record_err("ftp", &error);
                    if attempt >= 2 || !link::is_transient(&error) {
                        return Err(error);
                    }
                    link::record_retry("ftp");
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }

    /// Stream a remote file directly into `store` bounded by `remaining_budget`,
    /// avoiding holding multi-hundred-MiB binaries in RAM.
    pub fn download_to_store(
        &mut self,
        store: &crate::artifacts::ArtifactStore,
        raw_path: &str,
        remaining_budget: usize,
    ) -> Result<(Value, usize)> {
        let canonical = remote_path(raw_path)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut transferred = 0usize;
            let result = self.ready().and_then(|ftp| {
                store.save_stream(
                    "ftp",
                    remaining_budget,
                    json!({"remote_path": raw_path}),
                    "bin",
                    |out| {
                        transferred = ftp.download_to(
                            &format!("RETR {canonical}"),
                            out,
                            remaining_budget,
                        )?;
                        Ok(())
                    },
                )
            });
            match result {
                Ok(artifact) => {
                    link::record_ok("ftp");
                    return Ok((artifact, transferred));
                }
                Err(error) => {
                    self.session = None;
                    link::record_err("ftp", &error);
                    if attempt >= 2 || !link::is_transient(&error) {
                        return Err(error);
                    }
                    link::record_retry("ftp");
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
}

pub fn ftp_list(profile: &Profile, path: &str) -> Result<Value> {
    let path = remote_path(path)?;
    let content = link::retry("ftp", 3, || {
        Ftp::open(profile)?.download(&format!("LIST {path}"), profile.limit("transfer_bytes"))
    })?;
    let listing: Vec<_> = String::from_utf8_lossy(&content)
        .lines()
        .map(str::to_owned)
        .collect();
    ensure!(
        listing.len() <= profile.limit("list_entries"),
        "FTP listing exceeds entry limit"
    );
    Ok(json!({"path":path,"listing":listing,"format":"server_supplied_LIST"}))
}

pub fn ftp_download(profile: &Profile, path: &str) -> Result<Vec<u8>> {
    let path = remote_path(path)?;
    link::retry("ftp", 3, || {
        Ftp::open(profile)?.download(&format!("RETR {path}"), profile.limit("transfer_bytes"))
    })
}

/// Stream an FTP download directly to `store` without holding the entire file in memory.
pub fn ftp_download_to_store(
    profile: &Profile,
    store: &crate::artifacts::ArtifactStore,
    raw_path: &str,
) -> Result<Value> {
    let canonical = remote_path(raw_path)?;
    let limit = profile.limit("transfer_bytes");
    link::retry("ftp", 3, || {
        store.save_stream("ftp", limit, json!({"remote_path": raw_path}), "bin", |out| {
            Ftp::open(profile)?.download_to(&format!("RETR {canonical}"), out, limit)?;
            Ok(())
        })
    })
}

pub fn ftp_upload(profile: &Profile, path: &str, content: &[u8]) -> Result<Value> {
    profile.require("ftp_upload")?;
    let path = remote_path(path)?;
    ensure!(
        content.len() <= profile.limit("transfer_bytes"),
        "Upload exceeds byte limit"
    );
    let roots = profile.data["ftp_upload_roots"]
        .as_array()
        .context("Missing upload roots")?;
    let allowed = roots
        .iter()
        .filter_map(Value::as_str)
        .map(remote_path)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        allowed
            .iter()
            .any(|root| root != "/" && path.starts_with(&format!("{root}/"))),
        "FTP upload outside allowed roots"
    );
    // Mutation: a single attempt only, never retried.
    let result = (|| -> Result<Value> {
        let mut ftp = Ftp::open(profile)?;
        let mut stream = ftp.data(&format!("STOR {path}"))?;
        let mut position = 0;
        while position < content.len() {
            stream.set_write_timeout(Some(ftp.remaining()?))?;
            let count = stream.write(&content[position..content.len().min(position + 65536)])?;
            ensure!(count > 0, "FTP write disconnected; remote state uncertain");
            position += count;
        }
        stream.shutdown(Shutdown::Write)?;
        drop(stream);
        ftp.expect(&[226, 250])?;
        Ok(json!({"path":path,"bytes_sent":content.len(),"readback_verified":false}))
    })();
    match &result {
        Ok(_) => link::record_ok("ftp"),
        Err(error) => link::record_err("ftp", error),
    }
    result
}

pub struct KlogCapture {
    pub content: Vec<u8>,
    pub reconnects: u32,
    /// True when the stream closed and could not be re-established before the
    /// requested duration elapsed.
    pub ended_early: bool,
}

/// Klog lines that look like a crash, kernel trap, panic or assertion, so a
/// crash outside the debugger is visible without reading the raw artifact.
/// Returns at most 64 `{line, text}` entries (1-based line numbers).
pub fn klog_crash_lines(content: &[u8]) -> Vec<Value> {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?i)exited on signal|fatal trap|\bpanic\b|fault virtual address|instruction pointer\s*=|\bSIG(SEGV|BUS|ILL|FPE|ABRT|SYS|KILL)\b|page fault|core ?dump|crash|unhandled exception|assert(ion)? fail|\babort\(",
        )
        .expect("static klog crash pattern")
    });
    String::from_utf8_lossy(content)
        .lines()
        .enumerate()
        .filter(|(_, text)| pattern.is_match(text))
        .take(64)
        .map(|(index, text)| json!({"line": index + 1, "text": text.trim_end().chars().take(400).collect::<String>()}))
        .collect()
}

/// Capture raw Klog for a bounded time. The log is a read-only stream, so a
/// dropped connection is re-established (up to three times) rather than
/// silently truncating the capture.
pub fn klog_capture(profile: &Profile, seconds: u64) -> Result<KlogCapture> {
    ensure!(
        seconds > 0 && seconds <= profile.limit("log_seconds") as u64,
        "Invalid Klog duration"
    );
    let open = || link::retry("klog", 3, || connect(profile, profile.port("klog")));
    let mut stream = open()?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut content = Vec::new();
    let mut buffer = [0; 65536];
    let mut reconnects = 0;
    let mut ended_early = false;
    while content.len() < profile.limit("log_bytes") {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        stream.set_read_timeout(Some(remaining.min(profile.timeout())))?;
        let limit = buffer.len().min(profile.limit("log_bytes") - content.len());
        match stream.read(&mut buffer[..limit]) {
            Ok(0) => {
                if reconnects >= 3 {
                    ended_early = true;
                    break;
                }
                reconnects += 1;
                std::thread::sleep(Duration::from_millis(200));
                match open() {
                    Ok(next) => stream = next,
                    Err(_) => {
                        ended_early = true;
                        break;
                    }
                }
            }
            Ok(count) => content.extend(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(KlogCapture {
        content,
        reconnects,
        ended_early,
    })
}

/// Magic numbers of file types that are never raw BinLoader payloads.
const REJECTED_MAGIC: &[(&[u8], &str)] = &[
    (b"\x7fELF", "ELF (BinLoader accepts raw BIN, not ELF)"),
    (b"\x4f\x15\x3d\x1d", "PS4 SELF"),
    (b"\x7fCNT", "PS4 PKG"),
    (b"MZ", "Windows PE"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG", "PNG image"),
    (b"SQLite format 3\0", "SQLite database"),
    (b"<!DOCTYPE", "HTML document"),
    (b"<html", "HTML document"),
    (b"<?xml", "XML document"),
];

/// Reject files that cannot be a raw payload *before* any byte is sent. A loader
/// fed garbage may crash or wedge, and the PC cannot restart it, so this is the
/// main defence. A pass means "plausibly a raw binary", never "safe to run".
pub fn validate_payload(content: &[u8], maximum: usize) -> Result<Value> {
    ensure!(
        content.len() >= 16,
        "Payload too small to be code ({} bytes)",
        content.len()
    );
    ensure!(
        content.len() <= maximum,
        "Payload exceeds configured byte limit"
    );
    for (magic, name) in REJECTED_MAGIC {
        ensure!(
            !content.starts_with(magic),
            "Payload is a {name}, not a raw BIN payload"
        );
    }
    ensure!(
        content.iter().any(|byte| *byte != content[0]),
        "Payload is a uniform fill (all {:#04x}); likely erased or corrupt",
        content[0]
    );
    let head = &content[..content.len().min(1024)];
    let printable = head
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    ensure!(
        printable * 100 < head.len() * 97,
        "Payload looks like text, not machine code"
    );
    Ok(json!({"kind":"raw_binary","size":content.len(),"checks":
        ["min_size","size_limit","known_container_magic","uniform_fill","not_text"],
        "guarantees_safe_execution":false}))
}

static PAYLOAD_GATE: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);

fn payload_cooldown(profile: &Profile) -> Duration {
    Duration::from_secs(
        profile.data["limits"]["payload_cooldown_seconds"]
            .as_u64()
            .unwrap_or(5)
            .clamp(1, 300),
    )
}

/// Informational only: a payload may legitimately replace or stop services.
fn console_after_send(profile: &Profile) -> Value {
    std::thread::sleep(Duration::from_millis(1500));
    let ftp = match probe_ftp(profile) {
        Ok(_) => {
            link::record_ok("ftp");
            json!("reachable")
        }
        Err(error) => {
            link::record_err("ftp", &error);
            json!("unreachable")
        }
    };
    let klog = if connect(profile, profile.port("klog")).is_ok() {
        "reachable"
    } else {
        "unreachable_or_disabled"
    };
    json!({"ftp":ftp,"klog":klog,"debug":"not_probed_single_client",
        "note":"Informational only; unreachable services after a payload may be expected or may mean the console crashed"})
}

/// Send one BIN payload exactly once. Pre-validated, serialized process-wide,
/// rate-limited, delivered completely, and closed gracefully so the loader sees
/// a clean EOF rather than a reset. Never retried.
pub fn payload_send(profile: &Profile, content: &[u8]) -> Result<Value> {
    profile.require("payload_execute")?;
    let validation = validate_payload(content, profile.limit("transfer_bytes"))?;
    let mut gate = PAYLOAD_GATE
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Another payload send is in progress; nothing was sent"))?;
    let cooldown = payload_cooldown(profile);
    if let Some(last) = *gate
        && let Some(wait) = cooldown.checked_sub(last.elapsed())
    {
        anyhow::bail!(
            "Payload loader cooldown: wait {:.1}s before sending again; nothing was sent",
            wait.as_secs_f32()
        );
    }
    let mut stream = match connect(profile, profile.port("payload")) {
        Ok(stream) => stream,
        Err(error) => {
            link::record_err("payload", &error);
            return Err(error.context("Payload loader unreachable; nothing was sent"));
        }
    };
    *gate = Some(Instant::now());
    let deadline = Instant::now() + profile.timeout().max(Duration::from_secs(10));
    let sent = (|| -> Result<()> {
        let mut position = 0;
        while position < content.len() {
            stream.set_write_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .context("Payload deadline; state uncertain, never retry")?,
            ))?;
            let count = stream.write(&content[position..])?;
            ensure!(
                count > 0,
                "Payload disconnected; execution uncertain, never retry"
            );
            position += count;
        }
        stream.flush()?;
        stream.shutdown(Shutdown::Write)?;
        Ok(())
    })();
    if let Err(error) = sent {
        link::record_err("payload", &error);
        return Err(error.context(
            "Payload transfer interrupted after connecting; execution uncertain, never retry",
        ));
    }
    // Let the loader finish reading and close first; ignore anything it says.
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut sink = [0; 256];
    let mut loader_closed = false;
    let mut loader_reset = false;
    loop {
        match stream.read(&mut sink) {
            Ok(0) => {
                loader_closed = true;
                break;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                loader_reset = true;
                break;
            }
            Err(_) => break,
        }
    }
    drop(stream);
    link::record_ok("payload");
    let console = console_after_send(profile);
    Ok(json!({"bytes_sent":content.len(),"execution_verified":false,
        "validation":validation,"loader_closed_cleanly":loader_closed,
        "loader_reset":loader_reset,"cooldown_seconds":cooldown.as_secs(),
        "console_after_send":console}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_path_injection_and_parent_traversal() {
        for path in [
            "relative",
            "/data/../secret",
            "//host/path",
            "/data\\secret",
            "/data\r\nSTOR bad",
        ] {
            assert!(remote_path(path).is_err(), "{path}");
        }
        assert_eq!(
            remote_path("/data/./files//test").unwrap(),
            "/data/files/test"
        );
    }

    #[test]
    fn payload_validation_rejects_wrong_containers_and_garbage() {
        let mut elf = b"\x7fELF".to_vec();
        elf.extend([1u8; 64]);
        assert!(validate_payload(&elf, 1 << 20).is_err());
        assert!(validate_payload(&[0u8; 4096], 1 << 20).is_err());
        assert!(validate_payload(&[0x90u8; 4096], 1 << 20).is_err());
        assert!(validate_payload(b"too small", 1 << 20).is_err());
        assert!(validate_payload(&b"hello world this is plain text. ".repeat(64), 1 << 20).is_err());
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend((0..200u8).collect::<Vec<_>>());
        assert!(validate_payload(&zip, 1 << 20).is_err());
        assert!(validate_payload(&[0x55u8; 32], 16).is_err());
        let code: Vec<u8> = (0..2048u32).map(|n| (n * 31 % 251) as u8).collect();
        assert!(validate_payload(&code, 1 << 20).is_ok());
    }

    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    /// Loopback FTP server: returns (port, control connections seen, QUITs seen).
    fn fake_ftp_server() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let controls = Arc::new(AtomicUsize::new(0));
        let quits = Arc::new(AtomicUsize::new(0));
        let (controls_seen, quits_seen) = (controls.clone(), quits.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                controls_seen.fetch_add(1, Ordering::SeqCst);
                let quits = quits_seen.clone();
                std::thread::spawn(move || {
                    let mut writer = stream.try_clone().unwrap();
                    writer.write_all(b"220 fake\r\n").unwrap();
                    let mut data: Option<TcpListener> = None;
                    for line in BufReader::new(stream).lines().map_while(|l| l.ok()) {
                        let reply = match line.split(' ').next().unwrap() {
                            "USER" => "230 ok\r\n".to_owned(),
                            "TYPE" => "200 ok\r\n".to_owned(),
                            "NOOP" => "200 ok\r\n".to_owned(),
                            "PASV" => {
                                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                                let port = listener.local_addr().unwrap().port();
                                data = Some(listener);
                                format!("227 Entering Passive Mode (127,0,0,1,{},{})\r\n", port / 256, port % 256)
                            }
                            "RETR" => {
                                let (mut transfer, _) = data.take().unwrap().accept().unwrap();
                                writer.write_all(b"150 go\r\n").unwrap();
                                transfer.write_all(b"payload-bytes").unwrap();
                                drop(transfer);
                                "226 done\r\n".to_owned()
                            }
                            "QUIT" => {
                                quits.fetch_add(1, Ordering::SeqCst);
                                let _ = writer.write_all(b"221 bye\r\n");
                                return;
                            }
                            _ => "502 no\r\n".to_owned(),
                        };
                        writer.write_all(reply.as_bytes()).unwrap();
                    }
                });
            }
        });
        (port, controls, quits)
    }

    #[test]
    fn ftp_download_through_loopback_proxy() {
        use crate::proxy::{Mode, Route, start};
        let (remote, _, _) = fake_ftp_server();
        let ports = start("127.0.0.1", &[Route { local: 0, remote, mode: Mode::Ftp }]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut profile = crate::artifacts::tests::test_profile(directory.path());
        profile.data["ports"]["ftp"] = json!(ports[0]);
        profile.data["limits"]["transfer_bytes"] = json!(1 << 20);
        let mut batch = FtpBatch::new(&profile);
        assert_eq!(batch.download("/a").unwrap(), b"payload-bytes");
        assert_eq!(batch.download("/b").unwrap(), b"payload-bytes");
    }

    #[test]
    fn ftp_session_quits_cleanly_and_batch_reuses_one_connection() {
        let (port, controls, quits) = fake_ftp_server();
        let directory = tempfile::tempdir().unwrap();
        let mut profile = crate::artifacts::tests::test_profile(directory.path());
        profile.data["ports"]["ftp"] = json!(port);
        profile.data["limits"]["transfer_bytes"] = json!(1 << 20);
        {
            let mut batch = FtpBatch::new(&profile);
            assert_eq!(batch.download("/a").unwrap(), b"payload-bytes");
            assert_eq!(batch.download("/b").unwrap(), b"payload-bytes");
            assert_eq!(batch.download("/c").unwrap(), b"payload-bytes");
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(controls.load(Ordering::SeqCst), 1, "one control connection");
        assert_eq!(quits.load(Ordering::SeqCst), 1, "QUIT sent on drop");
        assert_eq!(ftp_download(&profile, "/d").unwrap(), b"payload-bytes");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(controls.load(Ordering::SeqCst), 2);
        assert_eq!(quits.load(Ordering::SeqCst), 2);
    }
}
