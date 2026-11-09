//! Loopback ps4debug-NG protocol 1.3 fixture for installed-app bridge tests.
//!
//! Serves a local image as process memory so IDA/Ghidra can attach through the
//! real `ps4-mcp broker` + `gdb-server` stack without a console. This is a
//! protocol fixture, not an emulator: no instruction is executed; single-steps
//! only advance RIP by the decoded instruction length.
use anyhow::{Context, Result};
use clap::Parser;
use ps4_mcp::debugger::fake::{Fixture, spawn_fixture};
use std::{net::TcpListener, path::PathBuf};

#[derive(Parser)]
struct Arguments {
    /// Image file mapped at --base (e.g. an ELF fixture).
    #[arg(long)]
    image: PathBuf,
    #[arg(long, value_parser = parse_u64, default_value = "0x400000")]
    base: u64,
    #[arg(long, value_parser = parse_u64)]
    rip: u64,
    #[arg(long, default_value_t = 71)]
    pid: u32,
    #[arg(long, default_value_t = 72)]
    thread: u32,
    /// Loopback port; 0 picks a free port (printed on stdout).
    #[arg(long, default_value_t = 0)]
    port: u16,
}

fn parse_u64(text: &str) -> Result<u64, String> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|error| error.to_string())
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let image = std::fs::read(&arguments.image).with_context(|| format!("read {}", arguments.image.display()))?;
    let listener = TcpListener::bind(("127.0.0.1", arguments.port))?;
    let fake = spawn_fixture(
        listener,
        Fixture {
            pid: arguments.pid,
            thread_id: arguments.thread,
            base: arguments.base,
            image,
            rip: arguments.rip,
            ..Default::default()
        },
    );
    println!("{}", fake.port);
    loop {
        std::thread::park();
    }
}
