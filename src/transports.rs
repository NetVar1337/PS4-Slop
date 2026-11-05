use crate::{Result, config::Profile};
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
        if service != "payload" {
            match connect(profile, profile.port(service)) {
                Ok(_) => entry["state"] = json!("tcp_reachable_not_protocol_verified"),
                Err(error) => {
                    entry["state"] = json!("unreachable");
                    entry["error"] = json!(error.to_string());
                }
            }
        }
        services[service] = entry;
    }
    Ok(services)
}

struct Ftp<'a> {
    profile: &'a Profile,
    control: TcpStream,
    deadline: Instant,
}

impl<'a> Ftp<'a> {
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

    fn download(&mut self, command: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut stream = self.data(command)?;
        let mut content = Vec::new();
        let mut buffer = [0; 65536];
        loop {
            stream.set_read_timeout(Some(self.remaining()?))?;
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            ensure!(
                content.len() + count <= maximum,
                "FTP transfer exceeds byte limit"
            );
            content.extend(&buffer[..count]);
        }
        drop(stream);
        self.expect(&[226, 250])?;
        Ok(content)
    }
}

pub fn ftp_list(profile: &Profile, path: &str) -> Result<Value> {
    let path = remote_path(path)?;
    let content =
        Ftp::open(profile)?.download(&format!("LIST {path}"), profile.limit("transfer_bytes"))?;
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
    Ftp::open(profile)?.download(&format!("RETR {path}"), profile.limit("transfer_bytes"))
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
}

pub fn klog_capture(profile: &Profile, seconds: u64) -> Result<Vec<u8>> {
    ensure!(
        seconds > 0 && seconds <= profile.limit("log_seconds") as u64,
        "Invalid Klog duration"
    );
    let mut stream = connect(profile, profile.port("klog"))?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut content = Vec::new();
    let mut buffer = [0; 65536];
    while content.len() < profile.limit("log_bytes") {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        stream.set_read_timeout(Some(remaining.min(profile.timeout())))?;
        let limit = buffer.len().min(profile.limit("log_bytes") - content.len());
        match stream.read(&mut buffer[..limit]) {
            Ok(0) => break,
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
    Ok(content)
}

pub fn payload_send(profile: &Profile, content: &[u8]) -> Result<Value> {
    profile.require("payload_execute")?;
    ensure!(
        !content.is_empty()
            && content.len() <= profile.limit("transfer_bytes")
            && !content.starts_with(b"\x7fELF"),
        "Invalid BIN payload"
    );
    let mut stream = connect(profile, profile.port("payload"))?;
    let deadline = Instant::now() + profile.timeout();
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
    stream.shutdown(Shutdown::Write)?;
    Ok(json!({"bytes_sent":content.len(),"execution_verified":false}))
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
}
