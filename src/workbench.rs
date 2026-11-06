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
    pub internals: crate::internals::Internals,
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
            internals: Default::default(),
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

    /// Passive per-service health plus payload rate-limit policy. `probe` adds an
    /// explicit reachability check (never of the payload port) and a local TCP :755
    /// callback bind check for `ps4debug` debug-event delivery.
    pub fn link_status(&self, probe: bool) -> Result<Value> {
        let probed = if probe {
            Some(transports::probe_services(&self.profile)?)
        } else {
            None
        };
        let callback_755 = if !probe {
            json!({"port": 755, "state": "not_probed"})
        } else if let Some(pid) = self.debugger.attached_pid {
            json!({"port": 755, "state": "held_by_active_debugger_session", "attached_pid": pid})
        } else {
            match std::net::TcpListener::bind("0.0.0.0:755") {
                Ok(listener) => {
                    drop(listener);
                    json!({"port": 755, "state": "bindable"})
                }
                Err(error) => json!({
                    "port": 755,
                    "state": "bind_failed",
                    "error": error.to_string(),
                    "hint": "debug_attach requires inbound TCP 755 from the PS4 to this host; check elevated port permissions, conflicting listeners, and host firewall rules",
                }),
            }
        };
        Ok(json!({"health":crate::link::snapshot(),"probe":probed,
            "callback_port_755": callback_755,
            "policy":{"idempotent_retry":"reads, listings and connection setup: up to 3 attempts with 150/450 ms backoff",
                "never_retried":["payload_execute","payload_stage","payload_recover","payload_rpc","payload_shutdown","ftp_upload","memory_write","memory_patch","memory_alloc","memory_free","memory_protect","kernel_write","debug_control"],
                "ftp":"each session sends QUIT on close; downloads stream directly to disk; ftp_extract reuses one session with NOOP revalidation",
                "payload":"validated before send, serialized, cooldown enforced, graceful close; loader cannot be restarted from the PC",
                "background_probing":false},
            "hardware_compatibility_guaranteed":false}))
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
            "link":crate::link::snapshot(),
            "permissions":self.profile.data["permissions"],"hardware_compatibility_guaranteed":false,
            "implementation":"native-rust","version":env!("CARGO_PKG_VERSION")}),
        )
    }

    pub fn ftp_download(&self, path: &str) -> Result<Value> {
        transports::ftp_download_to_store(&self.profile, &self.store, path)
    }

    pub fn ftp_extract(&self, paths: &[String]) -> Result<Value> {
        ensure!(
            !paths.is_empty() && paths.len() <= 64,
            "Extract needs 1-64 explicit paths"
        );
        let mut normalized = std::collections::BTreeSet::new();
        for path in paths {
            ensure!(
                normalized.insert(transports::remote_path(path)?),
                "Duplicate extract path: {path}"
            );
        }
        let mut files = Vec::new();
        let mut total = 0usize;
        let mut complete = true;
        let transfer_cap = self.profile.limit("transfer_bytes");
        let mut session = transports::FtpBatch::new(&self.profile);
        for path in paths {
            let remaining = transfer_cap.saturating_sub(total);
            let result = (|| -> Result<Value> {
                ensure!(remaining > 0, "Cumulative transfer limit exceeded");
                let (artifact, written) = session.download_to_store(&self.store, path, remaining)?;
                total += written;
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
        let validation =
            transports::validate_payload(&content, self.profile.limit("transfer_bytes"))?;
        ensure!(
            regex::Regex::new("^[0-9a-f]{40}$")?
                .is_match(record["source_commit"].as_str().unwrap_or("")),
            "Payload needs source commit"
        );
        Ok(
            json!({"manifest":record,"actual_sha256":hash,"size":content.len(),"validation":validation,"execution_verified":false}),
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

    /// Audited instruction/hex patch with prewrite backup artifact and readback check.
    pub fn memory_patch(
        &mut self,
        pid: u32,
        address: u64,
        assembly: Option<&str>,
        data_hex: Option<&str>,
        nop_pad: bool,
        comment: Option<String>,
    ) -> Result<Value> {
        self.debugger.require_qualified_debugger("process_write")?;
        self.store.audit(
            "memory_patch_intent",
            json!({
                "pid": pid,
                "address": format!("{address:#x}"),
                "assembly": assembly,
                "data_hex": data_hex,
                "nop_pad": nop_pad,
                "comment": comment,
            }),
        )?;
        let result = self
            .debugger
            .apply_patch(pid, address, assembly, data_hex, nop_pad, comment);
        if let Ok(ref val) = result
            && let Some(orig_hex) = val["original_hex"].as_str()
            && let Ok(orig_bytes) = hex::decode(orig_hex)
        {
            let _ = self.store.save(
                "prewrite",
                &orig_bytes,
                json!({"pid": pid, "address": address, "patch_id": val["id"]}),
                "bin",
            );
        }
        self.audit_result("memory_patch", &result)?;
        result
    }

    /// Audited restoration of a recorded patch.
    pub fn patch_restore(&mut self, id: u32) -> Result<Value> {
        self.debugger.require_qualified_debugger("process_write")?;
        self.store
            .audit("patch_restore_intent", json!({"patch_id": id}))?;
        let result = self.debugger.patch_restore(id);
        self.audit_result("patch_restore", &result)?;
        result
    }

    /// Audited virtual-memory allocation in target process.
    pub fn memory_alloc(
        &mut self,
        pid: u32,
        length: usize,
        address_hint: Option<u64>,
    ) -> Result<Value> {
        self.debugger.require_qualified_debugger("process_write")?;
        self.store.audit(
            "memory_alloc_intent",
            json!({
                "pid": pid,
                "length": length,
                "address_hint": address_hint.map(|a| format!("{a:#x}")),
            }),
        )?;
        let result = self.debugger.memory_alloc(pid, length, address_hint);
        self.audit_result("memory_alloc", &result)?;
        result
    }

    /// Audited virtual-memory release in target process.
    pub fn memory_free(&mut self, pid: u32, address: u64, length: usize) -> Result<Value> {
        self.debugger.require_qualified_debugger("process_write")?;
        self.store.audit(
            "memory_free_intent",
            json!({"pid": pid, "address": format!("{address:#x}"), "length": length}),
        )?;
        let result = self.debugger.memory_free(pid, address, length);
        self.audit_result("memory_free", &result)?;
        result
    }

    /// Audited memory protection change (`VM_PROT_*` 0..=7) with `maps` readback.
    pub fn memory_protect(
        &mut self,
        pid: u32,
        address: u64,
        length: usize,
        protection: u32,
    ) -> Result<Value> {
        self.debugger.require_qualified_debugger("process_write")?;
        self.store.audit(
            "memory_protect_intent",
            json!({
                "pid": pid,
                "address": format!("{address:#x}"),
                "length": length,
                "protection": protection,
            }),
        )?;
        let result = self
            .debugger
            .memory_protect(pid, address, length, protection);
        self.audit_result("memory_protect", &result)?;
        result
    }

    /// Audited FPU/XMM/YMM register write (`CMD_DEBUG_SETREGS` float=1).
    pub fn debug_registers_fpu_set(&mut self, lwpid: u32, values: &Value) -> Result<Value> {
        self.debugger.require_qualified_debugger("debug_control")?;
        let keys = values
            .as_object()
            .map(|m| m.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        self.store.audit(
            "debug_registers_fpu_set_intent",
            json!({"lwpid": lwpid, "fields": keys}),
        )?;
        let result = self.debugger.set_fpu_registers(lwpid, values);
        self.audit_result("debug_registers_fpu_set", &result)?;
        result
    }

    /// Audited FSBASE / GSBASE write (`CMD_DEBUG_SETTLS`).
    pub fn debug_tls_set(
        &mut self,
        lwpid: u32,
        fsbase: Option<u64>,
        gsbase: Option<u64>,
    ) -> Result<Value> {
        self.debugger.require_qualified_debugger("debug_control")?;
        self.store.audit(
            "debug_tls_set_intent",
            json!({
                "lwpid": lwpid,
                "fsbase": fsbase.map(|v| format!("{v:#x}")),
                "gsbase": gsbase.map(|v| format!("{v:#x}")),
            }),
        )?;
        let result = self.debugger.set_tls_bases(lwpid, fsbase, gsbase);
        self.audit_result("debug_tls_set", &result)?;
        result
    }

    /// Persist debugger user labels to a contained JSON artifact.
    pub fn debug_label_save(&self) -> Result<Value> {
        let exported = self.debugger.labels_export();
        let count = exported["labels"]
            .as_array()
            .map(|items| items.len())
            .unwrap_or(0);
        let bytes = serde_json::to_vec_pretty(&exported)?;
        let artifact = self
            .store
            .save("labels", &bytes, json!({"count": count}), "json")?;
        Ok(json!({
            "artifact": artifact,
            "count": count,
        }))
    }

    /// Restore debugger user labels from a previously saved JSON artifact.
    pub fn debug_label_load(&mut self, artifact: &str, merge: bool) -> Result<Value> {
        let bytes = self.read_artifact(artifact, 1024 * 1024)?;
        let payload: Value = serde_json::from_slice(&bytes)?;
        let mut imported = self.debugger.labels_import(&payload, !merge)?;
        imported["artifact"] = json!(artifact);
        Ok(imported)
    }

    /// Translate addresses bidirectionally between live ASLR runtime VA, static
    /// analyzer VA (`0x0`, `0x400000`, or ELF `min_vaddr`), and `module+offset`.
    /// A runtime address is also correlated with the process map that contains
    /// it; when no module-list entry covers the address, the map file offset
    /// supplies an estimated image base (`basis: process_maps_estimate`).
    #[allow(clippy::too_many_arguments)]
    pub fn address_rebase(
        &mut self,
        pid: Option<u32>,
        module: Option<&str>,
        runtime_address: Option<u64>,
        static_address: Option<u64>,
        offset: Option<u64>,
        static_base: Option<u64>,
        artifact: Option<&str>,
        module_sha256: Option<&str>,
        application_version: Option<&str>,
    ) -> Result<Value> {
        if let Some(hash) = module_sha256 {
            crate::config::require_hash(hash, "module_sha256")?;
        }
        let supplied = u8::from(runtime_address.is_some())
            + u8::from(static_address.is_some())
            + u8::from(offset.is_some());
        ensure!(
            supplied == 1,
            "Provide exactly one of runtime_address, static_address, or offset"
        );

        let inferred_static_base = if let Some(sb) = static_base {
            sb
        } else if let Some(art) = artifact {
            let head = self.read_artifact(art, self.profile.limit("transfer_bytes"))?;
            if head.starts_with(b"\x7fELF") {
                crate::analysis::elf_info(&head)
                    .ok()
                    .and_then(|info| {
                        info["image_base"]
                            .as_str()
                            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    })
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        let target_pid = pid.or(self.debugger.attached_pid);
        let mut resolved_mod_name: Option<String> = module.map(str::to_owned);
        let mut runtime_base: Option<u64> = None;
        let mut runtime_end: Option<u64> = None;

        if let Some(p) = target_pid {
            let listing = self.debugger.module_list(p)?;
            if let Some(mods) = listing.as_array() {
                let parse_bounds = |m: &Value| -> Option<(u64, u64)> {
                    let b = m["base"]
                        .as_str()
                        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;
                    let sz = m["size"].as_u64().unwrap_or(0);
                    Some((b, b.saturating_add(sz)))
                };
                let chosen = if let Some(want) = module {
                    let needle = want.to_ascii_lowercase();
                    mods.iter()
                        .find(|m| {
                            m["name"]
                                .as_str()
                                .is_some_and(|n| n.eq_ignore_ascii_case(want))
                        })
                        .or_else(|| {
                            mods.iter().find(|m| {
                                m["name"]
                                    .as_str()
                                    .is_some_and(|n| n.to_ascii_lowercase().contains(&needle))
                            })
                        })
                } else if let Some(rt) = runtime_address {
                    mods.iter().find(|m| {
                        matches!(parse_bounds(m), Some((start, stop)) if start <= rt && rt < stop)
                    })
                } else {
                    mods.iter()
                        .find(|m| m["name"].as_str() == Some("eboot.bin"))
                        .or_else(|| mods.first())
                };
                if let Some(m) = chosen {
                    resolved_mod_name =
                        m["name"].as_str().map(str::to_owned).or(resolved_mod_name);
                    if let Some((b, e)) = parse_bounds(m) {
                        runtime_base = Some(b);
                        runtime_end = Some(e);
                    }
                }
            }
        }

        let mut basis = runtime_base.map(|_| "module_list");
        let mapping = match (target_pid, runtime_address) {
            (Some(p), Some(rt)) => self
                .debugger
                .maps(p)
                .ok()
                .and_then(|maps| crate::analysis::correlate_maps(&maps, rt).ok()),
            _ => None,
        };
        if runtime_base.is_none()
            && let Some(map) = &mapping
        {
            let parse = |key: &str| {
                map[key]
                    .as_str()
                    .and_then(|s| s.strip_prefix("0x"))
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
            };
            if let Some(base) = parse("estimated_image_base") {
                runtime_base = Some(base);
                runtime_end = parse("end");
                resolved_mod_name = resolved_mod_name.or_else(|| map["name"].as_str().map(str::to_owned));
                basis = Some("process_maps_estimate");
            }
        }

        let rva = if let Some(off) = offset {
            off
        } else if let Some(st) = static_address {
            ensure!(
                st >= inferred_static_base,
                "static_address {st:#x} precedes static_base {inferred_static_base:#x}"
            );
            st - inferred_static_base
        } else {
            let rt = runtime_address.unwrap();
            let rb = runtime_base.context(
                "Cannot derive RVA from runtime_address: no module or process map of the live pid/attached session contains it",
            )?;
            ensure!(
                rt >= rb,
                "runtime_address {rt:#x} precedes module runtime_base {rb:#x}"
            );
            rt - rb
        };

        let out_static = inferred_static_base
            .checked_add(rva)
            .context("static_address overflow")?;
        let out_runtime = runtime_base.and_then(|rb| rb.checked_add(rva));
        let mod_label = resolved_mod_name
            .clone()
            .unwrap_or_else(|| "module".to_owned());

        Ok(json!({
            "pid": target_pid,
            "module": resolved_mod_name,
            "module_sha256": module_sha256,
            "application_version": application_version,
            "basis": basis,
            "mapping": mapping,
            "runtime_base": runtime_base.map(|v| format!("{v:#x}")),
            "runtime_end": runtime_end.map(|v| format!("{v:#x}")),
            "static_base": format!("{inferred_static_base:#x}"),
            "offset": format!("{rva:#x}"),
            "static_address": format!("{out_static:#x}"),
            "runtime_address": out_runtime.map(|v| format!("{v:#x}")),
            "ghidra_pie_default_0x100000": format!("{:#x}", 0x10_0000u64.saturating_add(rva)),
            "ida_default_0x400000": format!("{:#x}", 0x40_0000u64.saturating_add(rva)),
            "expression": format!("{mod_label}+{rva:#x}"),
            "warning": (basis == Some("process_maps_estimate")).then_some("Image base estimated from map file offset; verify ELF PT_LOAD layout"),
        }))
    }

    /// Reconstruct an offline-analyzable ELF64 file from an in-memory decrypted
    /// PS4 module (`eboot.bin` / `.sprx`) by reading its live ELF header and
    /// `PT_LOAD` segments over `ps4debug`, zeroing unmapped section header pointers.
    pub fn memory_elf_dump(
        &mut self,
        pid: u32,
        module: Option<&str>,
        base_address: Option<u64>,
    ) -> Result<Value> {
        let mut resolved_name = module.map(str::to_owned);
        let module_base = if let Some(addr) = base_address {
            addr
        } else {
            let listing = self.debugger.module_list(pid)?;
            let mods = listing.as_array().context("Expected module array")?;
            let chosen = if let Some(want) = module {
                let needle = want.to_ascii_lowercase();
                mods.iter()
                    .find(|m| {
                        m["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case(want))
                    })
                    .or_else(|| {
                        mods.iter().find(|m| {
                            m["name"]
                                .as_str()
                                .is_some_and(|n| n.to_ascii_lowercase().contains(&needle))
                        })
                    })
                    .with_context(|| format!("Module '{want}' not found in pid {pid}"))?
            } else {
                mods.iter()
                    .find(|m| m["name"].as_str() == Some("eboot.bin"))
                    .or_else(|| mods.first())
                    .context("No mapped modules found in target process")?
            };
            resolved_name = chosen["name"].as_str().map(str::to_owned);
            let base_str = chosen["base"].as_str().context("Module missing base")?;
            u64::from_str_radix(base_str.trim_start_matches("0x"), 16)?
        };

        let mut head = self.debugger.read_memory(pid, module_base, 4096, false)?;
        ensure!(
            head.len() >= 64 && &head[..4] == b"\x7fELF",
            "Memory at {module_base:#x} does not begin with an ELF magic header (\\x7fELF)"
        );
        ensure!(
            head[4] == 2 && head[5] == 1,
            "Only 64-bit little-endian Orbis ELF images are supported"
        );
        let phoff = u64::from_le_bytes(head[32..40].try_into()?);
        let phentsize = u16::from_le_bytes(head[54..56].try_into()?);
        let phnum = u16::from_le_bytes(head[56..58].try_into()?);
        ensure!(
            (56..=256).contains(&phentsize) && (1..=256).contains(&phnum),
            "Invalid ELF64 program header layout (phentsize={phentsize}, phnum={phnum})"
        );
        let ph_end = phoff
            .checked_add(u64::from(phnum) * u64::from(phentsize))
            .context("Program header table overflow")?;
        ensure!(ph_end <= 65536, "Program header table exceeds 64 KiB");
        if ph_end as usize > head.len() {
            head = self
                .debugger
                .read_memory(pid, module_base, ph_end as usize, false)?;
        }

        #[derive(Clone, Debug)]
        struct Seg {
            ph_index: usize,
            p_type: u32,
            p_flags: u32,
            p_offset: u64,
            p_vaddr: u64,
            p_filesz: u64,
            p_memsz: u64,
        }

        let mut phdrs = Vec::with_capacity(phnum as usize);
        for i in 0..phnum as usize {
            let b = phoff as usize + i * phentsize as usize;
            phdrs.push(Seg {
                ph_index: i,
                p_type: u32::from_le_bytes(head[b..b + 4].try_into()?),
                p_flags: u32::from_le_bytes(head[b + 4..b + 8].try_into()?),
                p_offset: u64::from_le_bytes(head[b + 8..b + 16].try_into()?),
                p_vaddr: u64::from_le_bytes(head[b + 16..b + 24].try_into()?),
                p_filesz: u64::from_le_bytes(head[b + 32..b + 40].try_into()?),
                p_memsz: u64::from_le_bytes(head[b + 40..b + 48].try_into()?),
            });
        }

        let loads: Vec<Seg> = phdrs.iter().filter(|s| s.p_type == 1).cloned().collect();
        ensure!(!loads.is_empty(), "ELF header contains no PT_LOAD segments");
        let min_vaddr = loads.iter().map(|s| s.p_vaddr).min().unwrap_or(0);
        let slide = module_base.wrapping_sub(min_vaddr);
        let transfer_cap = self.profile.limit("transfer_bytes");
        let chunk_cap = self.profile.limit("memory_bytes").clamp(4096, 1024 * 1024);

        // Determine whether original file offsets fit within transfer_cap; if not,
        // compact PT_LOAD offsets sequentially on 0x1000 boundaries.
        let max_orig_end = loads
            .iter()
            .filter_map(|s| s.p_offset.checked_add(s.p_filesz.max(s.p_memsz.min(s.p_filesz))))
            .max()
            .unwrap_or(0);
        let preserve_offsets =
            max_orig_end > 0 && (max_orig_end as usize) <= transfer_cap && ph_end <= max_orig_end;

        let mut layout: Vec<(Seg, u64, u64)> = Vec::with_capacity(loads.len());
        let mut cursor = ((ph_end + 0xfff) & !0xfff).max(0x1000);
        for seg in &loads {
            let dump_len = if preserve_offsets {
                seg.p_filesz
            } else {
                seg.p_memsz
            };
            let file_off = if preserve_offsets {
                seg.p_offset
            } else if seg.p_vaddr == min_vaddr && seg.p_offset == 0 {
                0
            } else {
                cursor = (cursor + 0xfff) & !0xfff;
                cursor
            };
            let end_off = file_off
                .checked_add(dump_len)
                .context("Segment offset overflow")?;
            ensure!(
                (end_off as usize) <= transfer_cap,
                "Reconstructed ELF size ({end_off} bytes) exceeds profile transfer_bytes limit ({transfer_cap})"
            );
            cursor = cursor.max(end_off);
            layout.push((seg.clone(), file_off, dump_len));
        }

        let total_size = layout
            .iter()
            .map(|(_, off, len)| (*off + *len) as usize)
            .max()
            .unwrap_or(head.len())
            .max(head.len());
        let mut image = vec![0u8; total_size];
        image[..head.len()].copy_from_slice(&head);

        // Zero section-header pointers in the reconstructed ELF64 header so static
        // tools (IDA/Ghidra/radare2/elf_info) rely on program headers cleanly.
        image[40..48].fill(0); // e_shoff = 0
        image[60..62].fill(0); // e_shnum = 0
        image[62..64].fill(0); // e_shstrndx = 0

        let deadline = Instant::now() + Duration::from_secs(90);
        let mut segment_reports = Vec::with_capacity(layout.len());
        let mut partial_pages = 0usize;

        for (seg, file_off, dump_len) in &layout {
            let seg_rt = slide.wrapping_add(seg.p_vaddr);
            let mut copied = 0u64;
            while copied < *dump_len {
                ensure!(
                    Instant::now() < deadline,
                    "ELF reconstruction exceeded 90-second deadline"
                );
                let ask = ((*dump_len - copied) as usize).min(chunk_cap);
                let dst_start = (*file_off + copied) as usize;
                // Keep our zeroed e_shoff/e_shnum header fields intact if PT_LOAD covers offset 0.
                match self
                    .debugger
                    .read_memory(pid, seg_rt.wrapping_add(copied), ask, false)
                {
                    Ok(bytes) => {
                        image[dst_start..dst_start + bytes.len()].copy_from_slice(&bytes);
                        copied += bytes.len() as u64;
                        if bytes.len() < ask {
                            partial_pages += 1;
                            break;
                        }
                    }
                    Err(_) => {
                        // Fall back to 4 KiB page reads across partially-mapped tails.
                        let step = ask.min(4096);
                        if let Ok(page) = self.debugger.read_memory(
                            pid,
                            seg_rt.wrapping_add(copied),
                            step,
                            false,
                        ) {
                            image[dst_start..dst_start + page.len()].copy_from_slice(&page);
                        } else {
                            partial_pages += 1;
                        }
                        copied += step as u64;
                    }
                }
            }
            // Update PT_LOAD phdr in image with actual file_off and filesz.
            let pb = phoff as usize + seg.ph_index * phentsize as usize;
            if pb + 48 <= image.len() {
                image[pb + 8..pb + 16].copy_from_slice(&file_off.to_le_bytes());
                image[pb + 32..pb + 40].copy_from_slice(&dump_len.to_le_bytes());
            }
            segment_reports.push(json!({
                "vaddr": format!("{:#x}", seg.p_vaddr),
                "runtime_address": format!("{seg_rt:#x}"),
                "file_offset": format!("{file_off:#x}"),
                "dumped_bytes": dump_len,
                "memsz": seg.p_memsz,
                "flags": seg.p_flags,
            }));
        }

        // Re-apply header sanitization in case PT_LOAD[0] overwrote offset 0..64,
        // and update non-PT_LOAD segment file offsets if offsets were compacted.
        image[40..48].fill(0);
        image[60..62].fill(0);
        image[62..64].fill(0);
        if !preserve_offsets {
            for seg in &phdrs {
                if seg.p_type == 1 {
                    continue;
                }
                if let Some((load_seg, load_off, _)) = layout.iter().find(|(l, _, len)| {
                    l.p_vaddr <= seg.p_vaddr && seg.p_vaddr < l.p_vaddr.saturating_add(*len)
                }) {
                    let new_off = load_off + (seg.p_vaddr - load_seg.p_vaddr);
                    let pb = phoff as usize + seg.ph_index * phentsize as usize;
                    if pb + 16 <= image.len() {
                        image[pb + 8..pb + 16].copy_from_slice(&new_off.to_le_bytes());
                    }
                }
            }
        }

        let elf_summary = crate::analysis::elf_info(&image).ok();
        let metadata = json!({
            "pid": pid,
            "module": resolved_name,
            "runtime_base": format!("{module_base:#x}"),
            "static_base": format!("{min_vaddr:#x}"),
            "aslr_slide": format!("{slide:#x}"),
            "preserved_file_offsets": preserve_offsets,
            "partial_or_unmapped_chunks": partial_pages,
            "segments": segment_reports,
            "format": "reconstructed_in_memory_elf64",
        });
        let artifact = self.store.save("elfdump", &image, metadata, "elf")?;
        Ok(json!({
            "artifact": artifact,
            "module": resolved_name,
            "runtime_base": format!("{module_base:#x}"),
            "static_base": format!("{min_vaddr:#x}"),
            "aslr_slide": format!("{slide:#x}"),
            "size": image.len(),
            "segment_count": segment_reports.len(),
            "segments": segment_reports,
            "partial_or_unmapped_chunks": partial_pages,
            "elf_info": elf_summary,
            "note": "In-memory decrypted PT_LOAD image reconstructed as ELF64 (section headers cleared; dynamic relocations/GOT reflect runtime state)",
        }))
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
    let binja = install_directory(
        "PS4_BINJA_DIRECTORY",
        &["C:/Program Files/Vector35/BinaryNinja", "C:/Program Files/Vector 35/Binary Ninja", "%LOCALAPPDATA%/Vector35/BinaryNinja"],
        "binaryninja.exe",
    );
    let iaito = install_directory(
        "PS4_IAITO_DIRECTORY",
        &["%LOCALAPPDATA%/Programs/iaito", "C:/Program Files/iaito", "C:/Program Files/radare2"],
        "iaito.exe",
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
    let gdb = install_directory(
        "PS4_GDB_DIRECTORY",
        &["C:/msys64/mingw64/bin", "C:/msys64/ucrt64/bin"],
        "gdb-multiarch.exe",
    )
    .join("gdb-multiarch.exe");
    Ok(
        json!({"ida":{"directory":ida,"installed":ida.join("ida.exe").is_file(),"gdb_plugin_present":ida.join("plugins/gdb_user.dll").is_file(),"supported_adapter":"IDA Pro 9.5 / IDAPython",
            "live_debugger":"Debugger > Remote GDB debugger -> gdb-server 127.0.0.1:1234"},
        "ghidra":{"directory":ghidra,"installed":properties.is_file(),"version":version,"supported_adapter":"Ghidra Java agent; optional PyGhidra",
            "live_debugger":"Debugger tool, 'gdb remote' launcher: gdb command = gdb_path, target remote 127.0.0.1:1234",
            "gdb_path":gdb,"gdb_present":gdb.is_file(),"native_debugger_requires":"GDB with Python plus protobuf/psutil and Ghidra's ghidragdb/ghidratrace"},
        "binja":{"directory":binja,"installed":binja.join("binaryninja.exe").is_file(),"supported_adapter":"Binary Ninja Python (plugin context or headless binaryninja.load)",
            "live_debugger":"Debugger > Connect to Remote Process, adapter LLDB, stub gdb-remote, 127.0.0.1:1234",
            "lldb_present":binja.join("plugins/liblldb.dll").is_file()},
        "iaito":{"directory":iaito,"installed":iaito.join("iaito.exe").is_file() || iaito.join("r2.exe").is_file() || iaito.join("radare2.exe").is_file(),"supported_adapter":"radare2/iaito via r2pipe (aflj/pdc/axtj); r2 must be on PATH",
            "live_debugger":"open gdb://127.0.0.1:1234/<pid> with debug mode (radare2 gdb io plugin)",
            "r_debug_present":iaito.join("r_debug.dll").is_file()},
        "note":"Discovery only; no application launch, console connection or license inspection"}),
    )
}

/// Environment override, else the first standard location containing `marker`, else the first candidate.
fn install_directory(variable: &str, candidates: &[&str], marker: &str) -> PathBuf {
    if let Ok(directory) = std::env::var(variable) {
        return PathBuf::from(directory);
    }
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let expanded: Vec<PathBuf> = candidates
        .iter()
        .map(|candidate| PathBuf::from(candidate.replace("%LOCALAPPDATA%", &local)))
        .collect();
    expanded.iter().find(|directory| directory.join(marker).is_file()).unwrap_or(&expanded[0]).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ATTESTATION;
    use crate::debugger::fake;

    fn test_profile(directory: &std::path::Path, port: u16) -> Profile {
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
            "profile_sha256": profile.fingerprint(),
            "attestation": ATTESTATION,
            "approved_permissions": ["debug_control", "process_write"],
            "debugger_payload_sha256": "b".repeat(64),
            "payload_sha256_allowlist": [],
            "build_recipe_sha256_allowlist": [],
        });
        std::fs::write(profile.qualification_path(), record.to_string()).unwrap();
        profile
    }

    #[test]
    fn elf_dump_rebase_labels_and_audited_patch_work() {
        let fake = fake::spawn_debuggable();
        let directory = tempfile::tempdir().unwrap();
        let profile = test_profile(directory.path(), fake.port);
        let mut wb = Workbench::new(profile).unwrap();

        // Plant a 64-bit little-endian ELF64 image at eboot.bin base 0x1000.
        let mut elf = vec![0u8; 0x300];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x100u64.to_le_bytes()); // entry RVA 0x100
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff = 64
        elf[40..48].copy_from_slice(&0xdead_beefu64.to_le_bytes()); // bogus shoff (must be zeroed)
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // 1 PT_LOAD
        elf[60..62].copy_from_slice(&9u16.to_le_bytes()); // bogus shnum (must be zeroed)
        let p = 64;
        elf[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        elf[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        elf[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset = 0
        elf[p + 16..p + 24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr = 0
        elf[p + 32..p + 40].copy_from_slice(&0x300u64.to_le_bytes()); // p_filesz
        elf[p + 40..p + 48].copy_from_slice(&0x300u64.to_le_bytes()); // p_memsz
        // Code at RVA 0x100: mov eax, 7; ret
        elf[0x100..0x106].copy_from_slice(&[0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3]);
        wb.debugger.write_memory(77, 0x1000, &elf, false).unwrap();

        // 1. Reconstruct ELF64 from live memory and verify elf_info parses it cleanly.
        let dumped = wb.memory_elf_dump(77, Some("eboot.bin"), None).unwrap();
        assert_eq!(dumped["runtime_base"], "0x1000");
        assert_eq!(dumped["static_base"], "0x0");
        assert_eq!(dumped["elf_info"]["kind"], "elf64");
        assert_eq!(dumped["elf_info"]["section_count"], 0);
        let art_path = dumped["artifact"]["path"].as_str().unwrap().to_owned();

        // 2. Bidirectional address rebase (runtime <-> static <-> module+offset).
        let reb_rt = wb
            .address_rebase(
                Some(77),
                None,
                Some(0x1100),
                None,
                None,
                None,
                Some(&art_path),
                Some(&"a".repeat(64)),
                Some("01.00"),
            )
            .unwrap();
        assert_eq!(reb_rt["basis"], "module_list");
        assert_eq!(reb_rt["mapping"]["name"], "eboot.bin");
        assert_eq!(reb_rt["mapping"]["relative_offset"], "0x100");
        assert_eq!(reb_rt["module_sha256"], "a".repeat(64));
        assert_eq!(reb_rt["module"], "eboot.bin");
        assert_eq!(reb_rt["offset"], "0x100");
        assert_eq!(reb_rt["static_address"], "0x100");
        assert_eq!(reb_rt["expression"], "eboot.bin+0x100");

        let reb_st = wb
            .address_rebase(
                Some(77),
                Some("eboot.bin"),
                None,
                Some(0x400100),
                None,
                Some(0x400000),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(reb_st["runtime_address"], "0x1100");
        assert!(reb_st["mapping"].is_null());

        // Anonymous mapping (no module-list entry): former address_correlate path.
        let reb_map = wb
            .address_rebase(Some(77), None, Some(0x7fff_0020), None, None, None, None, None, None)
            .unwrap();
        assert_eq!(reb_map["basis"], "process_maps_estimate");
        assert_eq!(reb_map["runtime_base"], "0x7fff0000");
        assert_eq!(reb_map["offset"], "0x20");
        assert!(reb_map["warning"].is_string());
        assert!(wb
            .address_rebase(Some(77), None, Some(0x10), None, None, None, None, None, None)
            .is_err());
        assert!(wb
            .address_rebase(Some(77), None, Some(0x1100), None, None, None, None, Some("bad"), None)
            .is_err());

        // 3. Label save & load round-trip via ArtifactStore.
        wb.debugger.label_set("entry_fn", 0x1100).unwrap();
        let saved = wb.debug_label_save().unwrap();
        assert_eq!(saved["count"], 1);
        let lbl_path = saved["artifact"]["path"].as_str().unwrap().to_owned();
        wb.debugger.label_remove("entry_fn").unwrap();
        let loaded = wb.debug_label_load(&lbl_path, false).unwrap();
        assert_eq!(loaded["loaded"], 1);
        assert_eq!(wb.debugger.labels.get("entry_fn"), Some(&0x1100));

        // 4. Audited memory_patch writes audit.jsonl + prewrite backup + restores cleanly.
        let patched = wb
            .memory_patch(
                77,
                0x1100,
                Some("xor eax, eax; ret"),
                None,
                true,
                Some("zero ret".into()),
            )
            .unwrap();
        assert_eq!(patched["verified"], true);
        let patch_id = patched["id"].as_u64().unwrap() as u32;
        let restored = wb.patch_restore(patch_id).unwrap();
        assert_eq!(restored["verified"], true);
        let audit_raw = String::from_utf8(wb.store.read("audit.jsonl").unwrap()).unwrap();
        assert!(audit_raw.contains("memory_patch_intent"));
        assert!(audit_raw.contains("memory_patch_result"));
        assert!(audit_raw.contains("patch_restore_result"));
    }
}
