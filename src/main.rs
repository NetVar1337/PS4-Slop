#![forbid(unsafe_code)]

use anyhow::{Context, ensure};
use clap::{Args, Parser, Subcommand};
use ps4_workbench_rs::{
    Result,
    artifacts::utc_now,
    broker,
    client::BrokerClient,
    config::{ATTESTATION, Profile, require_hash},
    jailbreak,
    mcp::McpServer,
    tools::{ToolRegistry, Toolset},
    workbench::{Workbench, digest, read_bounded},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Native Rust PS4 workbench: MCP, shared IDA/Ghidra broker, GDB bridge and guarded artifacts"
)]
struct Cli {
    #[arg(long, global = true, default_value = "profiles/ps4-1400.json")]
    profile: PathBuf,
    #[arg(long, global = true, value_enum, default_value = "read-only")]
    toolset: Toolset,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Input {
    #[arg(long, conflicts_with = "arguments_file")]
    arguments: Option<String>,
    #[arg(long)]
    arguments_file: Option<PathBuf>,
}

impl Input {
    fn value(&self) -> Result<Value> {
        let content = if let Some(path) = &self.arguments_file {
            String::from_utf8(read_bounded(path, 1_048_576)?)?
        } else {
            self.arguments.clone().unwrap_or_else(|| "{}".into())
        };
        ensure!(content.len() <= 1_048_576, "Arguments exceed 1 MiB");
        let value: Value = serde_json::from_str(content.trim_start_matches('\u{feff}'))?;
        ensure!(value.is_object(), "Arguments must be a JSON object");
        Ok(value)
    }
}

#[derive(Args)]
struct Remote {
    #[arg(long, default_value = "http://127.0.0.1:8765")]
    broker: String,
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long, default_value = "cli")]
    client_id: String,
}

#[derive(Subcommand)]
enum Command {
    Validate,
    Tools,
    AfterglowVerify {
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    DebuggerPayloadVerify {
        #[arg(long)]
        path: Option<PathBuf>,
    },
    Preflight {
        #[arg(long)]
        afterglow_directory: Option<PathBuf>,
        #[arg(long)]
        debugger_payload: Option<PathBuf>,
        #[arg(
            long,
            help = "Explicitly probe FTP/Klog and perform debugger identity handshake; never probe payload port"
        )]
        probe: bool,
    },
    Call {
        tool: String,
        #[command(flatten)]
        input: Input,
    },
    Serve {
        #[arg(long)]
        broker: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        client_id: Option<String>,
    },
    Broker {
        #[arg(long, default_value_t = 8765)]
        port: u16,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    RemoteCall {
        tool: String,
        #[command(flatten)]
        remote: Remote,
        #[command(flatten)]
        input: Input,
    },
    GdbServer {
        #[command(flatten)]
        remote: Remote,
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        listen_address: String,
        #[arg(long, default_value_t = 1234)]
        port: u16,
        #[arg(long)]
        observer: bool,
        #[arg(long)]
        allow_writes: bool,
    },
    Ingest {
        file: PathBuf,
    },
    Hash {
        file: PathBuf,
    },
    Qualify {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        attest: String,
        #[arg(long)]
        approve: Vec<String>,
        #[arg(long)]
        payload_sha256: Vec<String>,
        #[arg(long)]
        build_recipe_sha256: Vec<String>,
        #[arg(long, help = "Afterglow checkout to hash and bind into qualification evidence")]
        afterglow_directory: Option<PathBuf>,
        #[arg(long, help = "Exact ps4debug-NG BIN to hash for debugger approvals")]
        debugger_payload: Option<PathBuf>,
        #[arg(long)]
        replace: bool,
    },
}

fn token_path(profile: &Profile, argument: Option<&Path>) -> Result<PathBuf> {
    let path = std::path::absolute(
        argument
            .map(Path::to_path_buf)
            .unwrap_or_else(|| broker::token_file(profile)),
    )?;
    let resolved = ps4_workbench_rs::config::resolve_lenient(&path)?;
    let root = ps4_workbench_rs::config::resolve_lenient(&profile.artifact_root())?;
    ensure!(
        !resolved.starts_with(root),
        "Token must stay outside MCP-readable artifacts"
    );
    Ok(path)
}

fn remote_client(profile: &Profile, remote: &Remote) -> Result<BrokerClient> {
    BrokerClient::new(
        &remote.broker,
        &token_path(profile, remote.token_file.as_deref())?,
        &remote.client_id,
        Some(profile.fingerprint()),
    )
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn run(cli: Cli) -> Result<Option<Value>> {
    let profile = Profile::load(cli.profile)?;
    let toolset = cli.toolset;
    match cli.command {
        Command::Hash { file } => {
            let mut file = std::fs::File::open(file)?;
            let mut hash = sha2::Sha256::new();
            let mut buffer = [0; 65536];
            use sha2::Digest;
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            Ok(Some(json!({"sha256":hex::encode(hash.finalize())})))
        }
        Command::AfterglowVerify { directory } => Ok(Some(jailbreak::afterglow_verify(
            &profile,
            directory.as_deref(),
        )?)),
        Command::DebuggerPayloadVerify { path } => Ok(Some(jailbreak::debugger_payload_verify(
            &profile,
            path.as_deref(),
        )?)),
        Command::Preflight {
            afterglow_directory,
            debugger_payload,
            probe,
        } => Ok(Some(jailbreak::preflight(
            &profile,
            afterglow_directory.as_deref(),
            debugger_payload.as_deref(),
            probe,
        )?)),
        Command::Serve {
            broker,
            token_file,
            client_id,
        } => {
            let client_id =
                client_id.unwrap_or_else(|| format!("mcp-{}", uuid::Uuid::new_v4().simple()));
            let server = if let Some(url) = broker {
                McpServer::remote(BrokerClient::new(
                    &url,
                    &token_path(&profile, token_file.as_deref())?,
                    &client_id,
                    Some(profile.fingerprint()),
                )?)?
            } else {
                McpServer::local(
                    ToolRegistry::with_toolset(Workbench::new(profile)?, toolset)?,
                    &client_id,
                )?
            };
            runtime()?.block_on(server.serve())?;
            Ok(None)
        }
        Command::Broker { port, token_file } => {
            ensure!(port > 0, "Broker port must be nonzero");
            let token = token_path(&profile, token_file.as_deref())?;
            let registry = ToolRegistry::with_toolset(Workbench::new(profile)?, toolset)?;
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            eprintln!("Broker: http://{address}; token file: {}", token.display());
            runtime()?.block_on(broker::serve(registry, address, token))?;
            Ok(None)
        }
        Command::RemoteCall {
            tool,
            remote,
            input,
        } => {
            let mut registry =
                ps4_workbench_rs::client::RemoteRegistry::new(remote_client(&profile, &remote)?)?;
            Ok(Some(registry.call(&tool, input.value()?)?))
        }
        Command::GdbServer {
            remote,
            pid,
            listen_address,
            port,
            observer,
            allow_writes,
        } => {
            ensure!(
                pid > 0 && pid <= i32::MAX as u32 && port > 0,
                "Invalid PID or GDB port"
            );
            let client = remote_client(&profile, &remote)?;
            eprintln!(
                "GDB Remote: 127.0.0.1:{port}; PID {pid}; observer={observer}; allow_writes={allow_writes}"
            );
            ps4_workbench_rs::rsp::serve_with_options(
                client,
                pid,
                &listen_address,
                port,
                observer,
                allow_writes,
            )?;
            Ok(None)
        }
        Command::Qualify {
            evidence,
            attest,
            mut approve,
            mut payload_sha256,
            mut build_recipe_sha256,
            afterglow_directory,
            debugger_payload,
            replace,
        } => {
            ensure!(
                attest == ATTESTATION,
                "Explicit hardware-test attestation required; this is not a compatibility guarantee"
            );
            ensure!(
                profile.data["jailbreak"]["installed_commit"].is_string()
                    && profile.data["jailbreak"]["hen_build"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty()),
                "Record actual installed Afterglow commit and HEN build before qualification"
            );
            ensure!(
                !approve.is_empty()
                    && approve
                        .iter()
                        .all(|permission| profile.permission_enabled(permission)),
                "Approve only permissions explicitly enabled in the local profile"
            );
            let needs_afterglow = approve.iter().any(|permission| {
                [
                    "payload_execute",
                    "process_inject",
                    "process_write",
                    "debug_control",
                    "kernel_read",
                    "kernel_write",
                    "build",
                ]
                .contains(&permission.as_str())
            });
            let afterglow = if needs_afterglow {
                let verification = jailbreak::afterglow_verify(
                    &profile,
                    afterglow_directory.as_deref(),
                )?;
                ensure!(
                    verification["ok"] == true,
                    "Afterglow verification failed; refusing advanced qualification"
                );
                Some(verification)
            } else {
                None
            };
            let debugger_verification = if approve.iter().any(|permission| {
                ["process_inject", "process_write", "debug_control", "kernel_read", "kernel_write"]
                    .contains(&permission.as_str())
            }) {
                let verification = jailbreak::debugger_payload_verify(
                    &profile,
                    debugger_payload.as_deref(),
                )?;
                ensure!(
                    verification["ok"] == true,
                    "ps4debug-NG payload verification failed; refusing debugger qualification"
                );
                Some(verification)
            } else {
                None
            };
            if approve.iter().any(|permission| {
                [
                    "process_inject",
                    "process_write",
                    "debug_control",
                    "kernel_read",
                    "kernel_write",
                ]
                .contains(&permission.as_str())
            }) {
                ensure!(
                    profile.data["debugger"]["expected_brand"].is_string()
                        && profile.data["debugger"]["payload_sha256"].is_string(),
                    "Pin actual debugger brand and payload hash before qualification"
                );
            }
            for hash in payload_sha256.iter().chain(build_recipe_sha256.iter()) {
                require_hash(hash, "sha256")?;
            }
            ensure!(
                !approve
                    .iter()
                    .any(|permission| matches!(permission.as_str(), "payload_execute" | "process_inject"))
                    || !payload_sha256.is_empty(),
                "Payload and injection permissions need a tested hash allowlist"
            );
            ensure!(
                !approve.iter().any(|permission| permission == "build")
                    || !build_recipe_sha256.is_empty(),
                "Build permission needs reviewed recipe hash allowlist"
            );
            let target = profile.qualification_path();
            ensure!(
                replace || !target.exists(),
                "Qualification already exists; use --replace after requalification"
            );
            let content = read_bounded(&evidence, profile.limit("transfer_bytes"))?;
            ensure!(!content.is_empty(), "Evidence must not be empty");
            let workbench = Workbench::new(profile.clone())?;
            let artifact = workbench.store.save(
                "qualification-evidence",
                &content,
                json!({"original_name":evidence.file_name()}),
                "bin",
            )?;
            approve.sort();
            approve.dedup();
            payload_sha256.sort();
            payload_sha256.dedup();
            build_recipe_sha256.sort();
            build_recipe_sha256.dedup();
            let record = json!({"recorded_at":utc_now(),"profile_sha256":profile.fingerprint(),"attestation":attest,"approved_permissions":approve,
                "evidence":artifact,"debugger_payload_sha256":profile.data["debugger"]["payload_sha256"],"payload_sha256_allowlist":payload_sha256,
                "build_recipe_sha256_allowlist":build_recipe_sha256,
                "afterglow_verification":afterglow,"debugger_payload_verification":debugger_verification,
                "hardware_compatibility_guaranteed":false});
            std::fs::create_dir_all(target.parent().context("Qualification path needs parent")?)?;
            let temporary =
                target.with_file_name(format!("qualification-{}.tmp", uuid::Uuid::new_v4()));
            let result = (|| -> Result<()> {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(&serde_json::to_vec_pretty(&record)?)?;
                file.sync_all()?;
                drop(file);
                if replace {
                    std::fs::rename(&temporary, &target)?;
                } else {
                    std::fs::hard_link(&temporary, &target)?;
                    std::fs::remove_file(&temporary)?;
                }
                Ok(())
            })();
            if temporary.exists() {
                let _ = std::fs::remove_file(&temporary);
            }
            result?;
            Ok(Some(record))
        }
        command => {
            let mut registry =
                ToolRegistry::with_toolset(Workbench::new(profile.clone())?, toolset)?;
            let result = match command {
                Command::Validate => registry.workbench.status(false)?,
                Command::Tools => json!(registry.available()),
                Command::AfterglowVerify { .. }
                | Command::DebuggerPayloadVerify { .. }
                | Command::Preflight { .. } => unreachable!(),
                Command::Call { tool, input } => registry.call(&tool, input.value()?)?,
                Command::Ingest { file } => {
                    let content = read_bounded(&file, profile.limit("transfer_bytes"))?;
                    registry.workbench.store.save(
                        "import",
                        &content,
                        json!({"original_name":file.file_name(),"sha256":digest(&content)}),
                        "bin",
                    )?
                }
                _ => unreachable!(),
            };
            registry.workbench.close()?;
            Ok(Some(result))
        }
    }
}

fn main() {
    match run(Cli::parse()) {
        Ok(Some(value)) => println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON value serialization")
        ),
        Ok(None) => {}
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    }
}
