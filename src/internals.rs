//! Resident ELF payload staging, recovery and its small RPC control plane.
//! Game-specific offsets and features stay in versioned target manifests.

use crate::{
    Result,
    binimage::Image,
    config::{canonical_hash, require_hash},
    debugger::Debugger,
    tools::{ToolRegistry, address},
    workbench::{Workbench, digest},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::{Duration, Instant}};

const TARGET_FORMAT: &str = "ps4wb-internals-target-v1";
const RPC_SYMBOL: &str = "payload_rpc_entry";
const SIGNATURE_SIZE: usize = 16;
const MAX_TARGET_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: u64 = 512 * 1024 * 1024;
const RECOVERY_MAP_LIMIT: u64 = 64 * 1024 * 1024;
const RECOVERY_TOTAL_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Target {
    pub raw: Value,
    pub name: String,
    pub title_id: String,
    pub process_name: String,
    pub process_path: String,
    pub application_version: String,
    pub text_sha256: String,
    pub status_magic: u32,
    pub fingerprints: Vec<(u64, Vec<u8>)>,
    pub pointers: Vec<(u64, u64)>,
    pub rpc_version: Option<u16>,
    pub staging: String,
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("Target needs nonempty {key}"))
}

impl Target {
    pub fn parse(raw: Value) -> Result<Self> {
        ensure!(raw["format"] == TARGET_FORMAT, "Unsupported internals target format");
        let name = text(&raw, "name")?.to_owned();
        let title_id = text(&raw, "title_id")?.to_owned();
        let process_name = text(&raw, "process_name")?.to_owned();
        let process_path = text(&raw, "process_path")?.to_owned();
        let application_version = text(&raw, "application_version")?.to_owned();
        let text_sha256 = require_hash(text(&raw, "executable_text_sha256")?, "executable_text_sha256")?.to_owned();
        let status_magic = address(&raw["status_magic"])?;
        ensure!(status_magic <= u32::MAX as u64, "status_magic must be uint32");
        let mut fingerprints = Vec::new();
        for item in raw["fingerprints"].as_array().into_iter().flatten().take(64) {
            let bytes = hex::decode(item["hex"].as_str().context("Fingerprint needs hex")?)?;
            ensure!((1..=128).contains(&bytes.len()), "Fingerprint must contain 1-128 bytes");
            fingerprints.push((address(&item["address"])?, bytes));
        }
        ensure!(raw["fingerprints"].as_array().map_or(0, Vec::len) <= 64, "Too many fingerprints");
        let mut pointers = Vec::new();
        for item in raw["pointers"].as_array().into_iter().flatten().take(64) {
            pointers.push((address(&item["address"])?, address(&item["expected"])?));
        }
        ensure!(raw["pointers"].as_array().map_or(0, Vec::len) <= 64, "Too many pointer checks");
        let rpc_version = raw["rpc_version"].as_u64().map(|v| v as u16);
        ensure!(raw.get("rpc_version").is_none() || raw["rpc_version"] == 1, "Unsupported RPC version");
        let staging = raw["staging"].as_str().unwrap_or("elf_rpc").to_owned();
        ensure!(["immediate", "elf_rpc"].contains(&staging.as_str()), "Unsupported staging protocol");
        Ok(Self {
            raw,
            name,
            title_id,
            process_name,
            process_path,
            application_version,
            text_sha256,
            status_magic: status_magic as u32,
            fingerprints,
            pointers,
            rpc_version, staging,
        })
    }

    pub fn sha256(&self) -> String {
        canonical_hash(&self.raw)
    }

    fn verify_identity(&self, debugger: &mut Debugger, pid: u32) -> Result<()> {
        let info = debugger.process_info(pid)?;
        ensure!(info["pid"].as_u64() == Some(pid as u64), "Target PID changed during identification");
        ensure!(info["title_id"].as_str() == Some(&self.title_id), "Target title ID does not match {}", self.title_id);
        ensure!(info["name"].as_str() == Some(&self.process_name), "Target process name does not match {}", self.process_name);
        ensure!(info["path"].as_str() == Some(&self.process_path), "Target process path does not match {}", self.process_path);
        Ok(())
    }

    fn is_text_map(&self, map: &Value) -> bool {
        let name = map["name"].as_str().unwrap_or("");
        name == "executable"
            || name == self.process_name
            || name.strip_suffix(&self.process_name).is_some_and(|prefix| prefix.ends_with('/'))
    }

    fn verify(&self, debugger: &mut Debugger, pid: u32) -> Result<Vec<Value>> {
        self.verify_identity(debugger, pid)?;
        let maps = debugger.maps(pid)?;
        let mut ranges = Vec::new();
        for map in maps.as_array().into_iter().flatten().filter(|map| self.is_text_map(map)) {
            let protection = map["protection"].as_u64().unwrap_or(0);
            if protection & 4 == 0 {
                continue;
            }
            ensure!(protection & 1 != 0, "Target executable text is not readable");
            let start = map["start"].as_u64().context("Invalid text map start")?;
            let end = map["end"].as_u64().context("Invalid text map end")?;
            ensure!(start < end && end - start <= MAX_TEXT_BYTES, "Invalid target text mapping");
            ranges.push((start, end));
        }
        ranges.sort_unstable();
        let mut previous_end = None;
        let mut total = 0u64;
        let mut hasher = Sha256::new();
        for (start, end) in ranges {
            if let Some(previous) = previous_end {
                ensure!(start >= previous, "Overlapping target text mappings");
            }
            previous_end = Some(end);
            total = total.checked_add(end - start).context("Target text size overflow")?;
            ensure!(total <= MAX_TEXT_BYTES, "Target text exceeds 512 MiB");
            let mut position = start;
            while position < end {
                let length = ((end - position) as usize).min(debugger.profile.limit("memory_bytes"));
                let bytes = debugger.read_memory(pid, position, length, false)?;
                ensure!(bytes.len() == length, "Short target text read");
                hasher.update(&bytes);
                position += length as u64;
            }
        }
        ensure!(total > 0, "No executable target text mappings found");
        ensure!(hex::encode(hasher.finalize()) == self.text_sha256, "Target executable-text SHA-256 mismatch");
        for (address, expected) in &self.fingerprints {
            let actual = debugger.read_memory(pid, *address, expected.len(), false)?;
            ensure!(actual == *expected, "Target fingerprint mismatch at {address:#x}");
        }
        for (address, expected) in &self.pointers {
            let actual = debugger.read_memory(pid, *address, 8, false)?;
            let actual: [u8; 8] = actual.as_slice().try_into()?;
            ensure!(u64::from_le_bytes(actual) == *expected, "Target pointer mismatch at {address:#x}");
        }
        maps.as_array().cloned().context("Target maps must be an array")
    }
}

#[derive(Clone, Debug)]
pub struct PayloadImage {
    pub sha256: String,
    pub size: usize,
    pub image_entry: u64,
    pub rpc_value: u64,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl PayloadImage {
    pub fn parse(bytes: &[u8], expected_sha256: &str) -> Result<Self> {
        require_hash(expected_sha256, "sha256")?;
        ensure!(digest(bytes) == expected_sha256, "Payload SHA-256 mismatch");
        ensure!(bytes.len() >= 64 && bytes.starts_with(b"\x7fELF"), "Payload is not ELF64");
        ensure!(bytes[4] == 2 && bytes[5] == 1 && bytes[6] == 1, "Payload must be little-endian ELF64 version 1");
        ensure!(u16::from_le_bytes(bytes[16..18].try_into()?) == 3, "Payload must be ET_DYN");
        ensure!(u16::from_le_bytes(bytes[18..20].try_into()?) == 62, "Payload must be x86-64");
        let image = Image::from_elf(bytes, Some("internals-payload".into()))?;
        let image_entry = image.entry.context("Payload ELF entry is not executable")?;
        let mut rpc_value = None;
        for symbol in image.symbols.iter().filter(|symbol| {
            symbol.raw == RPC_SYMBOL && symbol.defined && symbol.kind == 2 && image.is_exec(symbol.value)
        }) {
            if rpc_value.is_some_and(|value| value != symbol.value) {
                bail!("Payload contains conflicting {RPC_SYMBOL} symbols");
            }
            rpc_value = Some(symbol.value);
        }
        let rpc_value = rpc_value.context("Payload needs one defined executable payload_rpc_entry")?;
        let signature: [u8; SIGNATURE_SIZE] = image
            .read(rpc_value, SIGNATURE_SIZE)
            .context("Cannot read payload RPC signature")?
            .try_into()?;
        Ok(Self {
            sha256: expected_sha256.to_owned(),
            size: bytes.len(),
            image_entry,
            rpc_value,
            signature,
        })
    }

    fn rpc_entry(&self, relocated_entry: u64) -> Result<u64> {
        let offset = i128::from(self.rpc_value) - i128::from(self.image_entry);
        u64::try_from(i128::from(relocated_entry) + offset).context("Relocated RPC entry overflow")
    }
}

#[derive(Clone, Debug)]
struct Resident {
    target: Target,
    payload: PayloadImage,
    rpc_entry: u64,
}

#[derive(Default)]
pub struct Internals {
    residents: BTreeMap<u32, Resident>,
    rpc_stubs: BTreeMap<u32, u64>,
}

fn load_inputs(workbench: &Workbench, target: &str, payload: &str, sha256: &str) -> Result<(Target, PayloadImage, Vec<u8>)> {
    let target: Target = Target::parse(serde_json::from_slice(&workbench.read_artifact(target, MAX_TARGET_BYTES)?)?)?;
    let bytes = workbench.read_artifact(payload, workbench.profile.limit("transfer_bytes"))?;
    let image = PayloadImage::parse(&bytes, sha256)?;
    Ok((target, image, bytes))
}

fn find_signature<'a>(haystack: &'a [u8], signature: &'a [u8; SIGNATURE_SIZE]) -> impl Iterator<Item = usize> + 'a {
    haystack.windows(SIGNATURE_SIZE).enumerate().filter_map(move |(index, window)| (window == signature).then_some(index))
}

fn recover_entry(workbench: &mut Workbench, pid: u32, payload: &PayloadImage, maps: &[Value]) -> Result<Option<u64>> {
    let mut found = None;
    let mut scanned = 0u64;
    for map in maps {
        if !map["name"].as_str().unwrap_or("").is_empty() || map["protection"].as_u64().unwrap_or(0) & 5 != 5 {
            continue;
        }
        let start = map["start"].as_u64().context("Invalid recovery map")?;
        let end = map["end"].as_u64().context("Invalid recovery map")?;
        ensure!(start < end && end - start <= RECOVERY_MAP_LIMIT, "Anonymous executable recovery map is too large");
        let size = end - start;
        ensure!(size <= RECOVERY_TOTAL_LIMIT && scanned <= RECOVERY_TOTAL_LIMIT - size, "Anonymous executable recovery scan limit exceeded");
        scanned += size;
        let mut position = start;
        let mut carry = Vec::new();
        while position < end {
            let length = ((end - position) as usize).min(workbench.profile.limit("memory_bytes"));
            let bytes = workbench.debugger.read_memory(pid, position, length, false)?;
            let carry_length = carry.len();
            let mut data = carry;
            data.extend(bytes);
            for offset in find_signature(&data, &payload.signature) {
                let candidate = position - carry_length as u64 + offset as u64;
                ensure!(found.is_none_or(|entry| entry == candidate), "Multiple payload RPC signatures found; refusing to select one");
                found = Some(candidate);
            }
            carry = data[data.len().saturating_sub(SIGNATURE_SIZE - 1)..].to_vec();
            position += length as u64;
        }
    }
    Ok(found)
}

fn status_value(target: &Target, raw: u64) -> Result<Value> {
    ensure!((raw >> 32) as u32 == target.status_magic, "Payload status magic mismatch: {raw:#x}");
    let lifecycle = raw & 0xff;
    ensure!(lifecycle <= 4, "Payload returned invalid lifecycle {lifecycle}");
    Ok(json!({
        "raw": format!("{raw:#x}"),
        "lifecycle": lifecycle,
        "lifecycle_name": (["absent", "starting", "ready", "failed", "disabled"])[lifecycle as usize],
        "initialization_stage": (raw >> 8) & 0xff,
        "heartbeat": (raw >> 16) & 0xffff,
    }))
}

impl Workbench {
    fn verify_resident_protocol(&mut self, pid: u32) -> Result<()> {
        let version = self.internals.residents.get(&pid).context("No recovered payload")?.target.rpc_version;
        if let Some(version) = version {
            let descriptor = self.call_resident(pid, 7, 0, 0)?;
            ensure!(descriptor >> 32 == 0x50535742 && ((descriptor >> 16) & 0xffff) == version as u64 && descriptor & 0xff == 0xff,
                "Payload RPC protocol mismatch; no control command dispatched");
        }
        Ok(())
    }
    fn rpc_stub(&mut self, pid: u32) -> Result<u64> {
        if let Some(stub) = self.internals.rpc_stubs.get(&pid) {
            return Ok(*stub);
        }
        let stub = self.debugger.install_rpc(pid)?;
        self.internals.rpc_stubs.insert(pid, stub);
        Ok(stub)
    }

    fn call_resident(&mut self, pid: u32, command: u64, argument: u64, argument2: u64) -> Result<u64> {
        let resident = self.internals.residents.get(&pid).cloned().context("No recovered payload for this PID; call payload_stage or payload_recover first")?;
        resident.target.verify_identity(&mut self.debugger, pid)?;
        let signature = self.debugger.read_memory(pid, resident.rpc_entry, SIGNATURE_SIZE, false)?;
        ensure!(signature == resident.payload.signature, "Resident payload signature changed; refusing RPC");
        let stub = self.rpc_stub(pid)?;
        self.debugger.call_rpc(pid, stub, resident.rpc_entry, [command, argument, argument2, 0, 0, 0])
    }

    pub fn payload_stage(&mut self, pid: u32, target: &str, payload: &str, sha256: &str) -> Result<Value> {
        let qualification = self.profile.require("process_inject")?;
        ensure!(self.debugger.attached_pid.is_none(), "Detach the active debugger before ELF staging");
        let (target, image, bytes) = load_inputs(self, target, payload, sha256)?;
        ensure!(qualification["payload_sha256_allowlist"].as_array().is_some_and(|items| items.iter().any(|item| item.as_str() == Some(sha256))), "ELF is not in the hardware-qualified payload hash allowlist");
        self.store.audit("payload_stage_intent", json!({"pid":pid,"target":target.name,"payload_sha256":sha256}))?;
        let result = (|| -> Result<Value> {
            let maps = target.verify(&mut self.debugger, pid)?;
            ensure!(recover_entry(self, pid, &image, &maps)?.is_none(), "Payload is already resident; refusing a second ELF_RPC upload");
            let stub = self.rpc_stub(pid)?;
            let (image_entry, rpc_entry) = if target.staging == "immediate" {
                self.debugger.load_elf(pid, &bytes)?; // exactly one uncertain mutation
                let deadline = Instant::now() + Duration::from_secs(10);
                let entry = loop {
                    let maps = self.debugger.maps(pid)?.as_array().cloned().context("Invalid maps")?;
                    if let Some(entry) = recover_entry(self, pid, &image, &maps)? { break entry; }
                    ensure!(Instant::now() < deadline && !crate::sessions::cancelled(), "Immediate ELF readiness uncertain; recover explicitly, never re-upload automatically");
                    std::thread::sleep(Duration::from_millis(50));
                };
                (0, entry)
            } else {
                let image_entry = self.debugger.load_elf_rpc(pid, &bytes)?;
                (image_entry, image.rpc_entry(image_entry)?)
            };
            let actual = self.debugger.read_memory(pid, rpc_entry, SIGNATURE_SIZE, false)?;
            ensure!(actual == image.signature, "Relocated payload RPC signature mismatch; state is uncertain");
            let resident = Resident { target: target.clone(), payload: image.clone(), rpc_entry };
            self.internals.residents.insert(pid, resident);
            self.verify_resident_protocol(pid)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                let raw = self.call_resident(pid, 0, 0, 0)?;
                let status = status_value(&target, raw)?;
                if status["lifecycle"] == 2 {
                    break status;
                }
                ensure!(status["lifecycle"] != 3 && status["lifecycle"] != 4, "Payload initialization failed: {status}");
                ensure!(Instant::now() < deadline, "Payload readiness deadline expired; resident state is uncertain");
                std::thread::sleep(Duration::from_millis(50));
            };
            Ok(json!({
                "pid":pid,"target":target.name,"application_version":target.application_version,
                "target_sha256":target.sha256(),"payload_sha256":image.sha256,"payload_size":image.size,
                "image_entry":format!("{image_entry:#x}"),"rpc_entry":format!("{rpc_entry:#x}"),"rpc_stub":format!("{stub:#x}"),
                "status":status,"staging":target.staging,"rpc_version":target.rpc_version,"raw_entry_called":false,"automatic_retry":false,"hardware_compatibility_guaranteed":false,
            }))
        })();
        self.audit_result("payload_stage", &result)?;
        result
    }

    pub fn payload_recover(&mut self, pid: u32, target: &str, payload: &str, sha256: &str) -> Result<Value> {
        let qualification = self.profile.require("process_inject")?;
        let (target, image, _) = load_inputs(self, target, payload, sha256)?;
        ensure!(qualification["payload_sha256_allowlist"].as_array().is_some_and(|items| items.iter().any(|item| item.as_str() == Some(sha256))), "ELF is not in the hardware-qualified payload hash allowlist");
        let maps = target.verify(&mut self.debugger, pid)?;
        let rpc_entry = recover_entry(self, pid, &image, &maps)?.context("Payload RPC signature was not found in anonymous executable mappings")?;
        let stub = self.rpc_stub(pid)?;
        self.internals.residents.insert(pid, Resident { target: target.clone(), payload: image.clone(), rpc_entry });
        self.verify_resident_protocol(pid)?;
        let raw = self.call_resident(pid, 0, 0, 0)?;
        let status = status_value(&target, raw)?;
        Ok(json!({"pid":pid,"recovered":true,"rpc_entry":format!("{rpc_entry:#x}"),"rpc_stub":format!("{stub:#x}"),"payload_sha256":image.sha256,"status":status}))
    }

    pub fn payload_status(&mut self, pid: u32) -> Result<Value> {
        self.profile.require("process_inject")?;
        self.verify_resident_protocol(pid)?;
        let target = self.internals.residents.get(&pid).map(|resident| resident.target.clone()).context("No recovered payload for this PID")?;
        let raw = self.call_resident(pid, 0, 0, 0)?;
        let mut status = status_value(&target, raw)?;
        status["pid"] = json!(pid);
        status["rpc_entry"] = json!(format!("{:#x}", self.internals.residents[&pid].rpc_entry));
        Ok(status)
    }

    pub fn payload_rpc(&mut self, pid: u32, command: u64, argument: u64, argument2: u64) -> Result<Value> {
        self.profile.require("process_inject")?;
        self.verify_resident_protocol(pid)?;
        if self.internals.residents.get(&pid).is_some_and(|r| r.target.rpc_version.is_some()) {
            ensure!(command <= 7, "Unsupported negotiated RPC command");
        }
        ensure!(command != 1 || argument <= u32::MAX as u64, "Feature mask exceeds uint32");
        self.store.audit("payload_rpc_intent", json!({"pid":pid,"command":command,"argument":format!("{argument:#x}"),"argument2":format!("{argument2:#x}")}))?;
        let result = self.call_resident(pid, command, argument, argument2);
        self.audit_result(
            "payload_rpc",
            &result.as_ref().map(|raw| json!({"raw":format!("{raw:#x}")})).map_err(|error| anyhow::anyhow!(error.to_string())),
        )?;
        let raw = result?;
        let target = self.internals.residents.get(&pid).map(|resident| resident.target.clone()).context("No recovered payload")?;
        Ok(json!({"pid":pid,"command":command,"raw":format!("{raw:#x}"),"status":(command == 0 || command == 2).then(|| status_value(&target, raw)).transpose()?}))
    }

    pub fn payload_shutdown(&mut self, pid: u32) -> Result<Value> {
        self.payload_rpc(pid, 2, 0, 0)
    }

    /// One-shot ELF execution (CMD_PROC_ELF): the server spawns the raw image
    /// entry. No target manifest or RPC symbol is required; the ELF is still
    /// hash-qualified and audited. Never use this for resident RPC payloads.
    pub fn payload_run(&mut self, pid: u32, payload: &str, sha256: &str) -> Result<Value> {
        let qualification = self.profile.require("process_inject")?;
        ensure!(self.debugger.attached_pid.is_none(), "Detach the active debugger before ELF execution");
        let bytes = self.read_artifact(payload, self.profile.limit("transfer_bytes"))?;
        require_hash(sha256, "sha256")?;
        ensure!(digest(&bytes) == sha256, "Payload SHA-256 mismatch");
        ensure!(bytes.len() >= 64 && bytes.starts_with(b"\x7fELF"), "Payload is not ELF64");
        ensure!(bytes[4] == 2 && bytes[5] == 1 && bytes[6] == 1, "Payload must be little-endian ELF64 version 1");
        ensure!(u16::from_le_bytes(bytes[16..18].try_into()?) == 3, "Payload must be ET_DYN");
        ensure!(u16::from_le_bytes(bytes[18..20].try_into()?) == 62, "Payload must be x86-64");
        ensure!(qualification["payload_sha256_allowlist"].as_array().is_some_and(|items| items.iter().any(|item| item.as_str() == Some(sha256))), "ELF is not in the hardware-qualified payload hash allowlist");
        self.store.audit("payload_run_intent", json!({"pid":pid,"payload_sha256":sha256}))?;
        let result = (|| -> Result<Value> {
            self.debugger.load_elf(pid, &bytes)?;
            Ok(json!({
                "pid":pid,"payload_sha256":sha256,"payload_size":bytes.len(),
                "server_spawned_entry":true,"automatic_retry":false,"hardware_compatibility_guaranteed":false,
            }))
        })();
        self.audit_result("payload_run", &result)?;
        result
    }

    /// Call a fingerprint-pinned function in the target process through the RPC
    /// stub (CMD_PROC_CALL). The target manifest must contain a fingerprint at
    /// exactly `address`; its expected bytes are re-verified before every call.
    pub fn process_call(&mut self, pid: u32, target: &str, address: u64, arguments: Vec<u64>) -> Result<Value> {
        self.profile.require("process_inject")?;
        ensure!(address != 0, "Call address must be nonzero");
        ensure!(arguments.len() <= 6, "At most six SysV arguments");
        let target = Target::parse(serde_json::from_slice(&self.read_artifact(target, MAX_TARGET_BYTES)?)?)?;
        target.verify_identity(&mut self.debugger, pid)?;
        let fingerprint = target
            .fingerprints
            .iter()
            .find(|(at, _)| *at == address)
            .context("Target manifest must pin the call address with a fingerprint")?;
        let actual = self.debugger.read_memory(pid, address, fingerprint.1.len(), false)?;
        ensure!(actual == fingerprint.1, "Callee fingerprint mismatch at {address:#x}; refusing to call");
        self.store.audit("process_call_intent", json!({
            "pid":pid,"target":target.name,"address":format!("{address:#x}"),
            "arguments":arguments.iter().map(|a|format!("{a:#x}")).collect::<Vec<_>>(),
        }))?;
        let stub = self.rpc_stub(pid)?;
        let mut args = [0u64; 6];
        args[..arguments.len()].copy_from_slice(&arguments);
        let result = self.debugger.call_rpc(pid, stub, address, args);
        self.audit_result("process_call", &result.as_ref().map(|rax| json!({"rax":format!("{rax:#x}")})).map_err(|error| anyhow::anyhow!(error.to_string())))?;
        let rax = result?;
        Ok(json!({
            "pid":pid,"target":target.name,"address":format!("{address:#x}"),
            "rax":format!("{rax:#x}"),"fingerprint_verified":true,"automatic_retry":false,
        }))
    }
}

pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if !matches!(name, "payload_stage" | "payload_recover" | "payload_status" | "payload_rpc" | "payload_shutdown" | "payload_run" | "process_call") {
        return None;
    }
    Some((|| {
        match name {
            "payload_run" => registry.workbench.payload_run(
                crate::tools::number(args, "pid")? as u32,
                crate::tools::string(args, "payload")?,
                crate::tools::string(args, "sha256")?,
            ),
            "process_call" => registry.workbench.process_call(
                crate::tools::number(args, "pid")? as u32,
                crate::tools::string(args, "target")?,
                address(&args["address"])?,
                args["arguments"]
                    .as_array()
                    .map(|items| items.iter().map(address).collect::<Result<Vec<_>>>())
                    .transpose()?
                    .unwrap_or_default(),
            ),
            "payload_stage" => registry.workbench.payload_stage(
                crate::tools::number(args, "pid")? as u32,
                crate::tools::string(args, "target")?,
                crate::tools::string(args, "payload")?,
                crate::tools::string(args, "sha256")?,
            ),
            "payload_recover" => registry.workbench.payload_recover(
                crate::tools::number(args, "pid")? as u32,
                crate::tools::string(args, "target")?,
                crate::tools::string(args, "payload")?,
                crate::tools::string(args, "sha256")?,
            ),
            "payload_status" => registry.workbench.payload_status(crate::tools::number(args, "pid")? as u32),
            "payload_rpc" => registry.workbench.payload_rpc(
                crate::tools::number(args, "pid")? as u32,
                crate::tools::number(args, "command")?,
                args.get("argument").map_or(Ok(0), address)?,
                args.get("argument2").map_or(Ok(0), address)?,
            ),
            "payload_shutdown" => registry.workbench.payload_shutdown(crate::tools::number(args, "pid")? as u32),
            _ => unreachable!(),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binimage::testelf::Builder;

    #[test]
    fn payload_parser_finds_export_and_rejects_wrong_hash() {
        let mut builder = Builder::new(0);
        builder.text = (0u8..64).collect();
        builder.symbols.push((RPC_SYMBOL.into(), builder.text_va(), 64));
        let elf = builder.build();
        let hash = digest(&elf);
        let image = PayloadImage::parse(&elf, &hash).unwrap();
        assert_eq!(image.image_entry, image.rpc_value);
        assert_eq!(image.signature, builder.text[..16]);
        assert!(PayloadImage::parse(&elf, &"0".repeat(64)).is_err());
        assert!(PayloadImage::parse(b"not an elf", &digest(b"not an elf")).is_err());
        let mut later_entry=elf.clone();
        later_entry[24..32].copy_from_slice(&(builder.text_va()+32).to_le_bytes());
        let earlier=PayloadImage::parse(&later_entry,&digest(&later_entry)).unwrap();
        assert_eq!(earlier.rpc_entry(0x800020).unwrap(),0x800000);
        assert!(earlier.rpc_entry(1).is_err());
    }

    #[test]
    fn signature_search_crosses_chunk_boundaries() {
        let signature = *b"0123456789abcdef";
        let mut bytes = b"prefix-0123456789abcdef-suffix".to_vec();
        assert_eq!(find_signature(&bytes, &signature).collect::<Vec<_>>(), vec![7]);
        bytes.clear();
        assert_eq!(find_signature(&bytes, &signature).count(), 0);
    }

    #[test]
    fn status_is_checked_against_target_magic() {
        let target = Target::parse(json!({
            "format":TARGET_FORMAT,"name":"test","title_id":"CUSA00000","process_name":"eboot.bin",
            "process_path":"/app0/eboot.bin","application_version":"1.0","executable_text_sha256":"a".repeat(64),
            "status_magic":"0x41584553","fingerprints":[],"pointers":[]
        })).unwrap();
        let status = status_value(&target, 0x4158_4553_0002_0002).unwrap();
        assert_eq!(status["lifecycle_name"], "ready");
        assert!(status_value(&target, 0).is_err());
    }
}
