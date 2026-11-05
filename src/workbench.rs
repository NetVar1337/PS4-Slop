use crate::{
    Result,
    artifacts::ArtifactStore,
    config::Profile,
    debugger::{Debugger, address_range},
    transports,
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Workbench {
    pub profile: Profile,
    pub debugger: Debugger,
    pub store: Arc<ArtifactStore>,
}

pub fn digest(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

pub fn read_bounded(path: impl AsRef<std::path::Path>, maximum: usize) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut content)?;
    ensure!(
        content.len() <= maximum,
        "File exceeds configured byte limit"
    );
    Ok(content)
}

impl Workbench {
    pub fn new(profile: Profile) -> Result<Self> {
        let store = Arc::new(ArtifactStore::new(&profile)?);
        Ok(Self {
            debugger: Debugger::new(profile.clone()),
            profile,
            store,
        })
    }

    pub fn close(&mut self) -> Result<()> {
        if let Err(error) = self.debugger.close() {
            self.store.audit(
                "debug_cleanup_failure",
                json!({"error":error.to_string(),"console_state":"uncertain"}),
            )?;
            return Err(error);
        }
        Ok(())
    }

    pub fn read_artifact(&self, artifact: &str, maximum: usize) -> Result<Vec<u8>> {
        read_bounded(self.store.path(artifact)?, maximum)
    }

    pub fn status(&self, probe: bool) -> Result<Value> {
        let mut services = json!({});
        for service in ["payload", "ftp", "klog", "debug"] {
            services[service] =
                json!({"port":self.profile.port(service),"state":"configured_not_probed"});
        }
        if probe {
            services = transports::probe_services(&self.profile)?;
        }
        services["payload"]["note"] =
            json!("Never probed: a loader connection can have side effects");
        let qualification = match self.profile.qualification() {
            Ok(record) => {
                json!({"state":"user_attested_not_guaranteed","recorded_at":record["recorded_at"]})
            }
            Err(error) => json!({"state":"hardware_unverified","reason":error.to_string()}),
        };
        Ok(
            json!({"host":self.profile.host(),"firmware_claim":"14.00","services":services,
            "compatibility":qualification,"profile_sha256":self.profile.fingerprint(),
            "permissions":self.profile.data["permissions"],"hardware_compatibility_guaranteed":false,
            "implementation":"native-rust","version":env!("CARGO_PKG_VERSION")}),
        )
    }

    pub fn ftp_download(&self, path: &str) -> Result<Value> {
        let content = transports::ftp_download(&self.profile, path)?;
        self.store
            .save("ftp", &content, json!({"remote_path":path}), "bin")
    }

    pub fn ftp_extract(&self, paths: &[String]) -> Result<Value> {
        ensure!(
            !paths.is_empty() && paths.len() <= 64,
            "Extract needs 1-64 explicit paths"
        );
        let mut files = Vec::new();
        let mut total = 0;
        let mut complete = true;
        for path in paths {
            let result = (|| -> Result<Value> {
                let content = transports::ftp_download(&self.profile, path)?;
                ensure!(
                    content.len() <= self.profile.limit("transfer_bytes") - total,
                    "Cumulative transfer limit exceeded"
                );
                total += content.len();
                let artifact =
                    self.store
                        .save("ftp", &content, json!({"remote_path":path}), "bin")?;
                Ok(json!({"remote_path":path,"artifact":artifact,"complete":true}))
            })();
            match result {
                Ok(entry) => files.push(entry),
                Err(error) => {
                    complete = false;
                    files.push(
                        json!({"remote_path":path,"complete":false,"error":error.to_string()}),
                    );
                    break;
                }
            }
        }
        let record = json!({"files":files,"complete":complete,"total_bytes":total,
            "requested_files":paths.len(),"attempted_files":files.len(),"automatic_retry":false});
        let manifest = self.store.save(
            "extraction",
            &serde_json::to_vec_pretty(&record)?,
            json!({}),
            "json",
        )?;
        Ok(json!({"manifest":manifest,"complete":complete,"files":files,"total_bytes":total}))
    }

    pub fn ftp_upload(&self, artifact: &str, path: &str, sha256: &str) -> Result<Value> {
        self.profile.require("ftp_upload")?;
        let content = self.read_artifact(artifact, self.profile.limit("transfer_bytes"))?;
        ensure!(digest(&content) == sha256, "Upload artifact hash mismatch");
        self.store
            .audit("ftp_upload_intent", json!({"path":path,"sha256":sha256}))?;
        let result = (|| -> Result<Value> {
            transports::ftp_upload(&self.profile, path, &content)?;
            let readback = transports::ftp_download(&self.profile, path)?;
            ensure!(
                digest(&readback) == sha256,
                "FTP readback mismatch; no retry"
            );
            Ok(json!({"path":path,"sha256":sha256,"readback_verified":true}))
        })();
        self.audit_result("ftp_upload", &result)?;
        result
    }

    pub fn inspect_payload(&self, manifest: &str) -> Result<Value> {
        let record: Value = serde_json::from_slice(&self.read_artifact(manifest, 65536)?)?;
        let artifact = record["artifact"]
            .as_str()
            .context("Manifest needs artifact")?;
        let content = self.read_artifact(artifact, self.profile.limit("transfer_bytes"))?;
        let hash = digest(&content);
        ensure!(
            record["sha256"].as_str() == Some(&hash),
            "Payload manifest hash mismatch"
        );
        ensure!(record["firmware"] == "14.00", "Payload firmware mismatch");
        let jailbreak = &self.profile.data["jailbreak"];
        ensure!(
            jailbreak["installed_commit"].is_string()
                && record["afterglow_commit"] == jailbreak["installed_commit"],
            "Payload does not match actual installed Afterglow commit"
        );
        ensure!(
            jailbreak["hen_build"]
                .as_str()
                .is_some_and(|name| !name.is_empty())
                && record["hen_build"] == jailbreak["hen_build"],
            "Payload does not match actual HEN build"
        );
        ensure!(
            record["format"] == "bin" && record["loader"] == "goldhen-binloader",
            "Only qualified GoldHEN BinLoader BIN artifacts may execute"
        );
        ensure!(
            !content.is_empty() && !content.starts_with(b"\x7fELF"),
            "Empty/ELF files cannot be sent as BIN payloads"
        );
        ensure!(
            regex::Regex::new("^[0-9a-f]{40}$")?
                .is_match(record["source_commit"].as_str().unwrap_or("")),
            "Payload needs source commit"
        );
        Ok(
            json!({"manifest":record,"actual_sha256":hash,"size":content.len(),"execution_verified":false}),
        )
    }

    pub fn send_payload(&self, manifest: &str, sha256: &str) -> Result<Value> {
        ensure!(
            self.debugger.attached_pid.is_none(),
            "Payload sending is blocked during attachment"
        );
        let qualification = self.profile.require("payload_execute")?;
        let inspected = self.inspect_payload(manifest)?;
        ensure!(
            inspected["actual_sha256"] == sha256
                && qualification["payload_sha256_allowlist"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == sha256)),
            "Payload not in hardware-qualified hash allowlist"
        );
        let artifact = inspected["manifest"]["artifact"]
            .as_str()
            .context("Missing artifact")?;
        let content = self.read_artifact(artifact, self.profile.limit("transfer_bytes"))?;
        ensure!(
            digest(&content) == sha256,
            "Payload changed after inspection"
        );
        self.store.audit(
            "payload_send_intent",
            json!({"sha256":sha256,"size":content.len()}),
        )?;
        let result = transports::payload_send(&self.profile, &content);
        self.audit_result("payload_send", &result)?;
        let mut result = result?;
        result["sha256"] = json!(sha256);
        result["execution_verified"] = json!(false);
        result["warning"] =
            json!("TCP transfer is not execution acknowledgement; never retry automatically");
        Ok(result)
    }

    pub fn memory_read(&mut self, pid: u32, address: u64, length: usize) -> Result<Value> {
        let content = self.debugger.read_memory(pid, address, length, false)?;
        let mut result = self.store.save(
            "memory",
            &content,
            json!({"pid":pid,"address":address,
            "runtime_identity":self.debugger.identity,"atomic_snapshot":false}),
            "bin",
        )?;
        if length <= 256 {
            result["hex"] = json!(hex::encode(content));
        }
        Ok(result)
    }

    pub fn memory_peek(&mut self, pid: u32, address: u64, length: usize) -> Result<Value> {
        ensure!(length <= 8192, "Peek exceeds 8192 bytes");
        let content = self.debugger.read_memory(pid, address, length, false)?;
        Ok(
            json!({"pid":pid,"address":format!("{address:#x}"),"length":content.len(),
            "hex":hex::encode(content),"atomic_snapshot":false,"runtime_identity":self.debugger.identity}),
        )
    }

    pub fn region_dump(&mut self, pid: u32, address: u64, length: usize) -> Result<Value> {
        address_range(address, length, self.profile.limit("transfer_bytes"))?;
        let maps = self.debugger.maps(pid)?;
        let mut entries = maps.as_array().context("Expected map array")?.clone();
        entries.sort_by_key(|entry| entry["start"].as_u64().unwrap_or(0));
        let end = address as u128 + length as u128;
        let mut position = address as u128;
        for entry in entries {
            let start = entry["start"].as_u64().context("Invalid map start")? as u128;
            let stop = entry["end"].as_u64().context("Invalid map end")? as u128;
            if start <= position
                && position < stop
                && entry["protection"].as_u64().unwrap_or(0) & 1 != 0
            {
                position = end.min(stop);
            }
        }
        ensure!(
            position == end,
            "Dump crosses an unmapped/unreadable region"
        );
        let process = self.debugger.process_info(pid)?;
        let mut content = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut failure = None;
        while content.len() < length {
            if Instant::now() >= deadline {
                failure = Some("Region dump exceeded 60 seconds".to_owned());
                break;
            }
            let count = self
                .profile
                .limit("memory_bytes")
                .min(length - content.len());
            match self
                .debugger
                .read_memory(pid, address + content.len() as u64, count, false)
            {
                Ok(chunk) if chunk.len() == count => content.extend(chunk),
                Ok(_) => {
                    failure = Some("Short region read".to_owned());
                    break;
                }
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        let complete = content.len() == length;
        let artifact = self.store.save("region", &content, json!({"pid":pid,"address":address,
            "requested_length":length,"complete":complete,"error":failure,"process":process,"maps":maps,
            "runtime_identity":self.debugger.identity,"atomic_snapshot":false,"format":"raw_memory_not_reconstructed_elf"}), "bin")?;
        Ok(json!({"artifact":artifact,"complete":complete,"error":failure}))
    }

    pub fn memory_write(
        &mut self,
        pid: u32,
        address: u64,
        hex_data: &str,
        expected_hex: &str,
        kernel: bool,
    ) -> Result<Value> {
        self.debugger.require_qualified_debugger(if kernel {
            "kernel_write"
        } else {
            "process_write"
        })?;
        if kernel {
            self.profile.require("kernel_read")?;
        }
        let content = hex::decode(hex_data)?;
        let expected = hex::decode(expected_hex)?;
        ensure!(
            !content.is_empty() && content.len() == expected.len(),
            "Supply equal nonempty replacement and expected byte counts"
        );
        let original = self
            .debugger
            .read_memory(pid, address, content.len(), kernel)?;
        ensure!(
            original == expected,
            "Original bytes differ; no write attempted"
        );
        let metadata = json!({"pid":pid,"address":address,"kernel":kernel});
        let backup = self
            .store
            .save("prewrite", &original, metadata.clone(), "bin")?;
        let replacement = self
            .store
            .save("replacement", &content, metadata.clone(), "bin")?;
        self.store.audit("memory_write_intent", json!({"pid":pid,"address":address,"kernel":kernel,"backup":backup,"replacement":replacement}))?;
        let result = (|| -> Result<Value> {
            self.debugger.write_memory(pid, address, &content, kernel)?;
            let actual = self
                .debugger
                .read_memory(pid, address, content.len(), kernel)?;
            let readback = self.store.save("readback", &actual, metadata, "bin")?;
            ensure!(
                actual == content,
                "Write readback mismatch; no rollback or retry; readback saved at {}",
                readback["path"]
            );
            Ok(
                json!({"verified":true,"backup":backup,"replacement":replacement,"readback":readback,
                "warning":"Non-atomic compare/write/readback; target may change concurrently"}),
            )
        })();
        self.audit_result("memory_write", &result)?;
        result
    }

    pub fn audit_result(&self, action: &str, result: &Result<Value>) -> Result<()> {
        match result {
            Ok(value) => self.store.audit(&format!("{action}_result"), json!({"result":value})),
            Err(error) => self.store.audit(&format!("{action}_uncertain"), json!({"error":error.to_string(),"console_state":"uncertain","automatic_retry":false})),
        }
    }
}

impl Drop for Workbench {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn desktop_status() -> Result<Value> {
    let ida = PathBuf::from(
        std::env::var("PS4_IDA_DIRECTORY")
            .unwrap_or_else(|_| "C:/Program Files/IDA Professional 9.5".into()),
    );
    let ghidra = PathBuf::from(
        std::env::var("PS4_GHIDRA_DIRECTORY")
            .unwrap_or_else(|_| "C:/Users/Admin/Desktop/Ghidra".into()),
    );
    let properties = ghidra.join("Ghidra/application.properties");
    let version = if properties.is_file() {
        let content = read_bounded(&properties, 65536)?;
        String::from_utf8_lossy(&content).lines().find_map(|line| {
            line.strip_prefix("application.version=")
                .map(|value| value.trim().to_owned())
        })
    } else {
        None
    };
    Ok(
        json!({"ida":{"directory":ida,"installed":ida.join("ida.exe").is_file(),"gdb_plugin_present":ida.join("plugins/gdb_user.dll").is_file(),"supported_adapter":"IDA Pro 9.5 / IDAPython"},
        "ghidra":{"directory":ghidra,"installed":properties.is_file(),"version":version,"supported_adapter":"Ghidra Java agent; optional PyGhidra","native_debugger_requires":"GDB with Python and Ghidra trace-agent dependencies"},
        "note":"Discovery only; no application launch, console connection or license inspection"}),
    )
}
