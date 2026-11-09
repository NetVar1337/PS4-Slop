//! Loopback TCP relay from 127.0.0.1 to the console, for setups where the PC
//! reaches the PS4 over a route GoldHEN FTP rejects (it requires data
//! connections from the control channel's source IP). Every connection to the
//! console is outbound from this process, so no firewall hole is needed.
//! Debug and klog are byte pipes; FTP is a byte pipe whose `227` replies are
//! rewritten to a local listener that bridges the data connection.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DATA_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Pipe,
    Ftp,
}

#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub local: u16,
    pub remote: u16,
    pub mode: Mode,
}

/// Binds every route on 127.0.0.1 and serves each on a background thread.
/// Returns the bound local ports (useful when a route asks for port 0).
pub fn start(target: &str, routes: &[Route]) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for route in routes {
        let listener = TcpListener::bind(("127.0.0.1", route.local))
            .with_context(|| format!("Cannot bind 127.0.0.1:{}", route.local))?;
        ports.push(listener.local_addr()?.port());
        let (target, route) = (target.to_owned(), *route);
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let target = target.clone();
                thread::spawn(move || {
                    if let Err(error) = session(client, &target, route) {
                        eprintln!("[proxy :{}] {error:#}", route.local);
                    }
                });
            }
        });
    }
    Ok(ports)
}

fn dial(host: &str, port: u16) -> Result<TcpStream> {
    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("Cannot resolve {host}"))?;
    TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .with_context(|| format!("Cannot reach {host}:{port}"))
}

fn session(client: TcpStream, target: &str, route: Route) -> Result<()> {
    let console = dial(target, route.remote)?;
    match route.mode {
        Mode::Pipe => pipe_both(client, console),
        Mode::Ftp => {
            let upstream = client.try_clone()?;
            let console_writer = console.try_clone()?;
            let forward = thread::spawn(move || copy_then_close(upstream, console_writer));
            let result = relay_ftp_replies(console, client, target);
            let _ = forward.join();
            result
        }
    }
}

fn copy_then_close(mut from: TcpStream, mut to: TcpStream) {
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

fn pipe_both(a: TcpStream, b: TcpStream) -> Result<()> {
    let (a2, b2) = (a.try_clone()?, b.try_clone()?);
    let forward = thread::spawn(move || copy_then_close(a, b2));
    copy_then_close(b, a2);
    let _ = forward.join();
    Ok(())
}

/// Copies console→client control lines, replacing each `227` reply with one
/// pointing at a fresh loopback listener bridged to the console's data port.
fn relay_ftp_replies(console: TcpStream, mut client: TcpStream, target: &str) -> Result<()> {
    let mut reader = BufReader::new(console);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.by_ref().take(8192).read_until(b'\n', &mut line)? == 0 {
            let _ = client.shutdown(Shutdown::Write);
            return Ok(());
        }
        if line.starts_with(b"227") {
            match bridge_passive(&line, target) {
                Ok(port) => {
                    line = format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{}).\r\n",
                        port >> 8,
                        port & 0xff
                    )
                    .into_bytes();
                }
                Err(error) => line = format!("425 Proxy data setup failed: {error}\r\n").into_bytes(),
            }
        }
        client.write_all(&line)?;
    }
}

fn passive_port(reply: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(reply).ok()?;
    let inner = &text[text.rfind('(')? + 1..];
    let fields: Vec<u16> = inner[..inner.find(')')?]
        .split(',')
        .map(|part| part.trim().parse().ok())
        .collect::<Option<_>>()?;
    (fields.len() == 6 && fields.iter().all(|&f| f <= 255)).then(|| fields[4] * 256 + fields[5])
}

/// Connects to the console's passive port now (before the client sends the
/// transfer command) and serves exactly one client data connection.
fn bridge_passive(reply: &[u8], target: &str) -> Result<u16> {
    let port = passive_port(reply).context("Invalid passive reply")?;
    // Same rule as the client: the address in the reply is ignored, only the port is used.
    let console_data = dial(target, port)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local = listener.local_addr()?.port();
    thread::spawn(move || {
        if let Ok(client_data) = accept_before(&listener, Instant::now() + DATA_ACCEPT_TIMEOUT) {
            let _ = pipe_both(client_data, console_data);
        }
    });
    Ok(local)
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> Result<TcpStream> {
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::ensure!(Instant::now() < deadline, "No data connection");
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_port_parsing() {
        assert_eq!(passive_port(b"227 Entering Passive Mode (192,168,1,2,19,137).\r\n"), Some(5001));
        assert_eq!(passive_port(b"227 (1,2,3,4,5)\r\n"), None);
        assert_eq!(passive_port(b"227 (1,2,3,4,256,1)\r\n"), None);
        assert_eq!(passive_port(b"227 no parens\r\n"), None);
    }

    #[test]
    fn pipe_route_relays_bytes_both_ways() {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().unwrap();
            let mut buffer = [0; 4];
            stream.read_exact(&mut buffer).unwrap();
            stream.write_all(&buffer).unwrap();
        });
        let ports = start("127.0.0.1", &[Route { local: 0, remote, mode: Mode::Pipe }]).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", ports[0])).unwrap();
        client.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ping");
    }
}
