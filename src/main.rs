#![forbid(unsafe_code)]

use anyhow::{Context, ensure};
use clap::{Args, Parser, Subcommand};
use ps4_mcp::{
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
    about = "PS4-MCP: MCP server and toolset for PS4 reverse engineering — IDA/Ghidra broker, GDB bridge, guarded artifacts"
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
    /// One-call hash-qualified payload staging: ingest local target/payload
    /// files when needed, upload the ELF once via payload_stage (immediate
    /// CMD_PROC_ELF staging with RPC-entry recovery), then read payload_status.
    /// Uses the console address from the profile; requires the process_inject
    /// permission and a hardware-qualified payload hash. Never auto-retried.
    Inject {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        payload: PathBuf,
        #[arg(long, help = "Expected (qualified) payload SHA-256; computed when omitted")]
        sha256: Option<String>,
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
    /// Relay the profile's debug/ftp/klog ports on 127.0.0.1 to the console (runs until stopped).
    /// Use when the profile host is 127.0.0.1; FTP passive data is bridged so GoldHEN
    /// sees one source IP. Run it in its own terminal or with Start-Process.
    Proxy {
        #[arg(long, env = "PS4_HOST", help = "Console address (or set PS4_HOST)")]
        target: String,
        #[arg(long, default_value_t = 744, help = "ps4debug-NG port on the console")]
        remote_debug_port: u16,
    },
    /// Full system diagnostic: qualification hash, proxy reachability, PS4 status.
    Doctor {
        #[arg(long)]
        afterglow_directory: Option<PathBuf>,
        #[arg(long)]
        debugger_payload: Option<PathBuf>,
    },
    /// Download and install the latest ps4-mcp release from GitHub.
    Update {
        #[arg(long, short = 'y', help = "Skip the y/N confirmation prompt")]
        yes: bool,
    },
}

fn token_path(profile: &Profile, argument: Option<&Path>) -> Result<PathBuf> {
    let path = std::path::absolute(
        argument
            .map(Path::to_path_buf)
            .unwrap_or_else(|| broker::token_file(profile)),
    )?;
    let resolved = ps4_mcp::config::resolve_lenient(&path)?;
    let root = ps4_mcp::config::resolve_lenient(&profile.artifact_root())?;
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
                ps4_mcp::client::RemoteRegistry::new(remote_client(&profile, &remote)?)?;
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
            ps4_mcp::rsp::serve_with_options(
                client,
                pid,
                &listen_address,
                port,
                observer,
                allow_writes,
            )?;
            Ok(None)
        }
        Command::Proxy { target, remote_debug_port } => {
            use ps4_mcp::proxy::{Mode, Route, start};
            let routes = [
                Route { local: profile.port("debug"), remote: remote_debug_port, mode: Mode::Pipe },
                Route { local: profile.port("ftp"), remote: profile.port("ftp"), mode: Mode::Ftp },
                Route { local: profile.port("klog"), remote: profile.port("klog"), mode: Mode::Pipe },
            ];
            // An unconfigured port reads as 0, which would bind a random port.
            let routes: Vec<Route> = routes.into_iter().filter(|r| r.local != 0).collect();
            ensure!(!routes.is_empty(), "Profile configures none of the debug/ftp/klog ports");
            start(&target, &routes)?;
            for route in routes {
                eprintln!("127.0.0.1:{} -> {target}:{} [{:?}]", route.local, route.remote, route.mode);
            }
            eprintln!("Proxy running; Ctrl-C to stop.");
            loop {
                std::thread::park();
            }
        }
        Command::Doctor { afterglow_directory, debugger_payload } => {
            let mut report = serde_json::Map::new();

            // 1. Qualification validity
            let qual_path = profile.qualification_path();
            let qual_ok = if qual_path.exists() {
                let qual: Value = serde_json::from_slice(&std::fs::read(&qual_path)?)?;
                let qual_hash = qual["profile_sha256"].as_str().unwrap_or("");
                let profile_hash = profile.fingerprint();
                let ok = qual_hash == profile_hash;
                if ok {
                    eprintln!("[OK]  Qualification valid");
                } else {
                    eprintln!("[ERR] Qualification STALE — expected {profile_hash}, file has {qual_hash}");
                    eprintln!("      Run: scripts/qualify-local.ps1 to re-qualify");
                }
                ok
            } else {
                eprintln!("[ERR] Qualification missing: {}", qual_path.display());
                false
            };
            report.insert("qualification_valid".into(), qual_ok.into());

            // 2. Proxy TCP reachability
            let debug_port = profile.data["ports"]["debug"].as_u64().unwrap_or(7441) as u16;
            let host = profile.data["host"].as_str().unwrap_or("127.0.0.1");
            let proxy_ok = std::net::TcpStream::connect(format!("{host}:{debug_port}")).is_ok();
            if proxy_ok {
                eprintln!("[OK]  Proxy reachable at {host}:{debug_port}");
            } else {
                eprintln!("[ERR] Proxy not reachable at {host}:{debug_port} — run: ps4-mcp proxy --target <console IP>");
            }
            report.insert("proxy_reachable".into(), proxy_ok.into());

            // 3. Preflight (console connectivity + jailbreak checks)
            match jailbreak::preflight(&profile, afterglow_directory.as_deref(), debugger_payload.as_deref(), false) {
                Ok(pf) => {
                    let console_ok = pf["ok"] == true;
                    eprintln!("[{}]  Console preflight", if console_ok { "OK " } else { "ERR" });
                    report.insert("preflight".into(), pf);
                }
                Err(e) => {
                    eprintln!("[ERR] Console preflight: {e}");
                    report.insert("preflight".into(), json!({"ok": false, "error": e.to_string()}));
                }
            }

            report.insert("version".into(), env!("CARGO_PKG_VERSION").into());
            Ok(Some(Value::Object(report)))
        }
        Command::Update { yes } => {
            let current_ver = env!("CARGO_PKG_VERSION");
            eprintln!("ps4-mcp v{current_ver}");
            eprintln!("Checking https://github.com/May-Ethereal/PS4-MCP for updates...");

            let client = reqwest::blocking::Client::builder()
                .user_agent(concat!("ps4-mcp/", env!("CARGO_PKG_VERSION")))
                .build()?;
            let release: Value = client
                .get("https://api.github.com/repos/May-Ethereal/PS4-MCP/releases/latest")
                .send()
                .context("GitHub API request failed")?
                .error_for_status()
                .context("GitHub API returned an error")?
                .json()?;

            let tag = release["tag_name"].as_str().context("Missing tag_name in release")?;
            let latest_ver = tag.trim_start_matches('v');

            if latest_ver == current_ver {
                eprintln!("Already up to date ({current_ver}).");
                return Ok(Some(json!({"status":"up_to_date","version":current_ver})));
            }
            eprintln!("New version available: {latest_ver}");

            let assets = release["assets"].as_array().context("No assets in this release")?;
            let asset = assets
                .iter()
                .find(|a| {
                    let name = a["name"].as_str().unwrap_or("");
                    name.ends_with(".exe") || (name.contains("windows") && name.contains("x86_64"))
                })
                .context("No Windows binary found in this release — check https://github.com/May-Ethereal/PS4-MCP/releases")?;
            let download_url = asset["browser_download_url"].as_str().context("Missing download URL")?;
            let asset_name = asset["name"].as_str().unwrap_or("ps4-mcp.exe");

            if !yes {
                eprint!("Update {current_ver} → {latest_ver}? [y/N] ");
                std::io::stdout().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                ensure!(answer.trim().eq_ignore_ascii_case("y"), "Update cancelled");
            }

            eprintln!("Downloading {asset_name}...");
            let mut response = client
                .get(download_url)
                .send()
                .context("Download failed")?
                .error_for_status()
                .context("Download error")?;

            let current_exe = std::env::current_exe().context("Cannot locate current executable")?;
            let new_path = current_exe.with_extension("update.exe");
            {
                let mut f = std::fs::File::create(&new_path)?;
                std::io::copy(&mut response, &mut f)?;
            }

            // Windows: rename running exe out of the way first (can't overwrite a running exe),
            // then rename the new download into its place.
            // Unix: direct rename over the running file works fine (inode stays open).
            let backup = current_exe.with_extension(format!("v{current_ver}.bak"));
            #[cfg(windows)]
            {
                std::fs::rename(&current_exe, &backup)
                    .context("Could not rename current binary — is the exe locked by another process?")?;
                if let Err(e) = std::fs::rename(&new_path, &current_exe) {
                    let _ = std::fs::rename(&backup, &current_exe); // best-effort restore
                    return Err(e).context("Could not move new binary into place; original restored");
                }
            }
            #[cfg(not(windows))]
            {
                std::fs::rename(&new_path, &current_exe)
                    .context("Could not replace binary")?;
                // No backup needed on Unix; keep path consistent with the Windows message below
                let _ = std::fs::copy(&current_exe, &backup);
            }

            eprintln!("Updated to {latest_ver}. Previous binary saved as {}", backup.display());
            Ok(Some(json!({"status":"updated","from":current_ver,"to":latest_ver,"backup":backup.display().to_string()})))
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
                | Command::Preflight { .. }
                | Command::Proxy { .. }
                | Command::Doctor { .. }
                | Command::Update { .. } => unreachable!(),
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
                Command::Inject {
                    pid,
                    target,
                    payload,
                    sha256,
                } => {
                    let intern = |registry: &ToolRegistry,
                                  path: &Path,
                                  kind: &str,
                                  extension: &str|
                     -> Result<String> {
                        let text = path.to_string_lossy().to_string();
                        if registry.workbench.read_artifact(&text, 1 << 20).is_ok() {
                            return Ok(text);
                        }
                        let local = ps4_mcp::config::resolve_lenient(path)?;
                        ensure!(local.is_file(), "Not an artifact or local file: {}", local.display());
                        let content =
                            read_bounded(&local, registry.workbench.profile.limit("transfer_bytes"))?;
                        let saved = registry.workbench.store.save(
                            kind,
                            &content,
                            json!({"original_name":local.file_name(),"source":"local-file"}),
                            extension,
                        )?;
                        Ok(saved["path"].as_str().context("Missing saved path")?.to_owned())
                    };
                    let target_artifact = intern(&registry, &target, "internals-target", "json")?;
                    let payload_artifact = intern(&registry, &payload, "payload", "elf")?;
                    let payload_bytes = registry.workbench.read_artifact(
                        &payload_artifact,
                        profile.limit("transfer_bytes"),
                    )?;
                    let sha = match sha256 {
                        Some(value) => require_hash(&value, "sha256")?.to_owned(),
                        None => digest(&payload_bytes),
                    };
                    let staged = registry.call(
                        "payload_stage",
                        json!({"pid":pid,"target":target_artifact,"payload":payload_artifact,"sha256":sha}),
                    )?;
                    let status = registry.call("payload_status", json!({"pid":pid}))?;
                    json!({"stage":staged,"status":status,"payload_sha256":sha,"automatic_retry":false,"hardware_verified":false})
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
