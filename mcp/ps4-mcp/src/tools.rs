use crate::{
    Result, analysis,
    development::Development,
    workbench::{Workbench, desktop_status},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum Toolset {
    /// Offline, read-only tools only (no console or network access).
    Static,
    /// Read-only tools, including live inspection; mutating tools stay hidden.
    ReadOnly,
    /// Read-only tools plus process writes and debugger control.
    Debug,
    /// Every tool allowed by the profile permissions.
    Full,
}

impl Toolset {
    pub fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::ReadOnly => "read-only",
            Self::Debug => "debug",
            Self::Full => "full",
        }
    }

    pub fn allows(self, tool: &Value) -> bool {
        let permission = tool["permission"].as_str();
        let read_only = tool["annotations"]["readOnlyHint"].as_bool() == Some(true);
        let offline = tool["annotations"]["openWorldHint"].as_bool() == Some(false);
        match self {
            Self::Full => true,
            Self::ReadOnly => permission.is_none() && read_only,
            Self::Static => permission.is_none() && read_only && offline,
            Self::Debug => {
                (permission.is_none() && read_only)
                    || matches!(
                        permission,
                        Some("debug_control" | "process_write" | "kernel_read")
                    )
            }
        }
    }
}

pub struct ToolRegistry {
    pub workbench: Workbench,
    catalog: Vec<Value>,
    validators: std::collections::HashMap<String, jsonschema::Validator>,
    development: Development,
    toolset: Toolset,
}

pub fn address(value: &Value) -> Result<u64> {
    let value = value.as_str().context("Address must be a string")?;
    Ok(if let Some(number) = value.strip_prefix("0x") {
        u64::from_str_radix(number, 16)?
    } else {
        value.parse()?
    })
}

pub fn string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key]
        .as_str()
        .with_context(|| format!("Missing string argument: {key}"))
}

pub fn number(args: &Value, key: &str) -> Result<u64> {
    args[key]
        .as_u64()
        .with_context(|| format!("Missing unsigned argument: {key}"))
}

impl ToolRegistry {
    pub fn new(workbench: Workbench) -> Result<Self> {
        Self::with_toolset(workbench, Toolset::ReadOnly)
    }

    pub fn with_toolset(workbench: Workbench, toolset: Toolset) -> Result<Self> {
        let mut catalog: Vec<Value> = crate::extensions::full_catalog()?;
        let mut validators = std::collections::HashMap::new();
        for tool in &mut catalog {
            let properties = &mut tool["inputSchema"]["properties"];
            if properties.get("length").is_some() {
                match tool["name"].as_str() {
                    Some("memory_region_dump") => {
                        tool["inputSchema"]["properties"]["length"]["maximum"] =
                            json!(workbench.profile.limit("transfer_bytes"));
                    }
                    Some("memory_peek") => {
                        tool["inputSchema"]["properties"]["length"]["maximum"] =
                            json!(workbench.profile.limit("memory_bytes").min(8192));
                    }
                    Some("memory_read" | "memory_snapshot" | "memory_search" | "kernel_read" | "kernel_search") => {
                        tool["inputSchema"]["properties"]["length"]["maximum"] =
                            json!(workbench.profile.limit("memory_bytes"));
                    }
                    _ => {}
                }
            }
            if tool["name"] == "klog_capture" {
                tool["inputSchema"]["properties"]["seconds"]["maximum"] =
                    json!(workbench.profile.limit("log_seconds"));
            }
            let validator = jsonschema::validator_for(&tool["inputSchema"])?;
            validators.insert(
                tool["name"].as_str().context("Tool needs name")?.to_owned(),
                validator,
            );
        }
        let development = Development::new(workbench.profile.clone(), workbench.store.clone());
        Ok(Self {
            workbench,
            catalog,
            validators,
            development,
            toolset,
        })
    }

    pub fn toolset(&self) -> Toolset {
        self.toolset
    }

    pub fn available(&self) -> Vec<Value> {
        self.catalog
            .iter()
            .filter(|tool| {
                self.toolset.allows(tool)
                    && tool["permission"].as_str().is_none_or(|permission| {
                        self.workbench.profile.data["permissions"][permission] == true
                    })
            })
            .map(|tool| {
                let mut tool = tool.clone();
                tool.as_object_mut().unwrap().remove("permission");
                tool
            })
            .collect()
    }

    pub fn call(&mut self, name: &str, args: Value) -> Result<Value> {
        let tool = self
            .catalog
            .iter()
            .find(|tool| tool["name"] == name)
            .context("Unknown tool")?;
        if let Some(permission) = tool["permission"].as_str() {
            ensure!(
                self.workbench.profile.data["permissions"][permission] == true,
                "Locally disabled tool: {name}"
            );
        }
        ensure!(
            self.toolset.allows(tool),
            "Tool {name} is excluded by the '{}' toolset",
            self.toolset.label()
        );
        self.validators
            .get(name)
            .context("Missing schema")?
            .validate(&args)
            .map_err(|error| anyhow::anyhow!("Invalid arguments: {error}"))?;
        if let Some(permission) = tool["permission"].as_str() {
            self.workbench.profile.require(permission)?;
        }
        let result = crate::config::json_safe(self.execute(name, &args)?);
        // Best-effort provenance: never fail a completed tool call because the
        // project index could not be updated.
        if let Err(error) = crate::project::auto_record(&self.workbench.store, name, &args, &result)
        {
            eprintln!("project auto-record skipped for {name}: {error:#}");
        }
        let content = serde_json::to_vec(&result)?;
        if content.len() > 24576 {
            let artifact =
                self.workbench
                    .store
                    .save("tool-result", &content, json!({"tool":name}), "json")?;
            return Ok(
                json!({"result_saved":artifact,"note":"Large result saved locally; use artifact_read for bounded chunks"}),
            );
        }
        Ok(result)
    }

    fn execute(&mut self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "console_status" => self
                .workbench
                .status(args["probe"].as_bool().unwrap_or(false)),
            "desktop_status" => desktop_status(),
            "debugger_info" => self.workbench.debugger.probe(),
            "link_status" => self
                .workbench
                .link_status(args["probe"].as_bool().unwrap_or(false)),
            "ftp_list" => crate::transports::ftp_list(
                &self.workbench.profile,
                args["path"].as_str().unwrap_or("/"),
            ),
            "ftp_download" => self.workbench.ftp_download(string(args, "path")?),
            "ftp_extract" => {
                let paths = args["paths"]
                    .as_array()
                    .context("Missing paths")?
                    .iter()
                    .map(|path| {
                        path.as_str()
                            .context("Path must be string")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.workbench.ftp_extract(&paths)
            }
            "ftp_upload" => self.workbench.ftp_upload(
                string(args, "artifact")?,
                string(args, "path")?,
                string(args, "sha256")?,
            ),
            "klog_capture" => {
                let seconds = args["seconds"].as_u64().unwrap_or(5);
                let capture = crate::transports::klog_capture(&self.workbench.profile, seconds)?;
                let mut saved = self.workbench.store.save(
                    "klog",
                    &capture.content,
                    json!({"seconds":seconds,"reconnects":capture.reconnects,
                        "ended_early":capture.ended_early}),
                    "bin",
                )?;
                saved["reconnects"] = json!(capture.reconnects);
                saved["ended_early"] = json!(capture.ended_early);
                saved["crash_lines"] = json!(crate::transports::klog_crash_lines(&capture.content));
                Ok(saved)
            }
            "payload_inspect" => self.workbench.inspect_payload(string(args, "manifest")?),
            "payload_execute" => self
                .workbench
                .send_payload(string(args, "manifest")?, string(args, "sha256")?),
            "process_list" => self.workbench.debugger.processes(),
            "process_info" => self
                .workbench
                .debugger
                .process_info(number(args, "pid")? as u32),
            "process_maps" => self.workbench.debugger.maps(number(args, "pid")? as u32),
            "memory_read" => self.workbench.memory_read(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
            ),
            "memory_peek" => self.workbench.memory_peek(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
            ),
            "memory_region_dump" => self.workbench.region_dump(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
            ),
            "memory_typed" => {
                let kind = string(args, "value_type")?;
                let length = match kind {
                    "u8" | "i8" => 1,
                    "u16" | "i16" => 2,
                    "u32" | "i32" | "f32" => 4,
                    "u64" | "i64" | "f64" => 8,
                    _ => bail!("Unknown value type"),
                };
                let content = self.workbench.debugger.read_memory(
                    number(args, "pid")? as u32,
                    address(&args["address"])?,
                    length,
                    false,
                )?;
                analysis::typed_value(&content, kind)
            }
            "memory_snapshot" => {
                let pid = number(args, "pid")? as u32;
                let start = address(&args["address"])?;
                let length = number(args, "length")? as usize;
                let info = self.workbench.debugger.process_info(pid)?;
                let maps = self.workbench.debugger.maps(pid)?;
                let content = self
                    .workbench
                    .debugger
                    .read_memory(pid, start, length, false)?;
                self.workbench.store.save("memory",&content,json!({"pid":pid,"address":start,"length":length,
                    "application_version":args["application_version"],"module_sha256":args["module_sha256"],"process":info,"maps":maps,
                    "runtime_identity":self.workbench.debugger.identity,"atomic_snapshot":false,"module_hash_source":"user_supplied"}),"bin")
            }
            "memory_diff" => analysis::diff(
                &self.workbench.store,
                string(args, "before")?,
                string(args, "after")?,
            ),
            "pattern_scan" => analysis::scan_pattern(
                &self.workbench.read_artifact(
                    string(args, "artifact")?,
                    self.workbench.profile.limit("memory_bytes"),
                )?,
                string(args, "pattern")?,
                1024,
            ),
            "memory_write" | "kernel_write" => self.workbench.memory_write(
                args["pid"].as_u64().unwrap_or(0) as u32,
                address(&args["address"])?,
                string(args, "hex_data")?,
                string(args, "expected_hex")?,
                name == "kernel_write",
            ),
            "kernel_read" => {
                let start = address(&args["address"])?;
                let content = self.workbench.debugger.read_memory(
                    0,
                    start,
                    number(args, "length")? as usize,
                    true,
                )?;
                self.workbench.store.save(
                    "kernel",
                    &content,
                    json!({"address":start,"runtime_identity":self.workbench.debugger.identity}),
                    "bin",
                )
            }
            "kernel_base" => self.workbench.debugger.kernel_base(),
            "kernel_search" => self.workbench.debugger.kernel_search(
                address(&args["address"])?,
                number(args, "length")? as usize,
                string(args, "pattern")?,
                args["max_results"].as_u64().unwrap_or(256) as usize,
            ),
            "debug_attach" | "debug_detach" | "debug_control" | "debug_breakpoint"
            | "debug_watchpoint" => {
                self.workbench.store.audit(
                    "debug_control_intent",
                    json!({"method":name,"arguments":args}),
                )?;
                let result = match name {
                    "debug_attach" => self
                        .workbench
                        .debugger
                        .attach(number(args, "pid")? as u32, string(args, "listen_address")?),
                    "debug_detach" => self.workbench.debugger.detach(),
                    "debug_control" => self.workbench.debugger.control(
                        string(args, "action")?,
                        args["thread_id"].as_u64().unwrap_or(0) as u32,
                    ),
                    "debug_breakpoint" => self.workbench.debugger.breakpoint_ex(
                        number(args, "index")? as u32,
                        address(&args["address"])?,
                        args["enabled"].as_bool().unwrap_or(true),
                        args["condition"].as_str().map(str::to_owned),
                        args["log"].as_str().map(str::to_owned),
                        args["stop_after"].as_u64().unwrap_or(0),
                    ),
                    _ => self.workbench.debugger.watchpoint(
                        number(args, "index")? as u32,
                        address(&args["address"])?,
                        number(args, "length")? as u32,
                        string(args, "access")?,
                        args["enabled"].as_bool().unwrap_or(true),
                    ),
                };
                self.workbench.audit_result("debug_control", &result)?;
                result
            }
            "debug_threads" => self.workbench.debugger.threads(),
            "debug_registers" => self
                .workbench
                .debugger
                .get_registers(number(args, "thread_id")? as u32),
            "debug_events" => self.workbench.debugger.poll_events(),
            "debug_registers_fpu" => self
                .workbench
                .debugger
                .fpu_registers(number(args, "thread_id")? as u32),
            "debug_registers_dr" => {
                self.workbench
                    .debugger
                    .hardware_debug_registers(number(args, "thread_id")? as u32)
            }
            "debug_breakpoint_list" => Ok(self.workbench.debugger.breakpoint_list()),
            "debug_stack" => self.workbench.debugger.stack_trace(
                number(args, "thread_id")? as u32,
                args["max_frames"].as_u64().unwrap_or(32) as usize,
            ),
            "debug_eval" => self.workbench.debugger.evaluate(
                string(args, "expression")?,
                args["pid"].as_u64().map(|pid| pid as u32),
                args["thread_id"].as_u64().map(|thread| thread as u32),
            ),
            "disassemble" => self.workbench.debugger.disassemble_live(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                args["count"].as_u64().unwrap_or(32) as usize,
            ),
            "module_list" => self
                .workbench
                .debugger
                .module_list(number(args, "pid")? as u32),
            "code_xrefs" => {
                let range = if args["address"].is_string() || args["length"].is_u64() {
                    let start = address(&args["address"])
                        .context("code_xrefs range filter requires both address and length")?;
                    let len = number(args, "length")
                        .context("code_xrefs range filter requires both address and length")?
                        as usize;
                    Some((start, len))
                } else {
                    None
                };
                self.workbench.debugger.code_xrefs_filtered(
                    number(args, "pid")? as u32,
                    address(&args["target_address"])?,
                    args["max_results"].as_u64().unwrap_or(256) as usize,
                    args["module"].as_str(),
                    range,
                )
            }
            "memory_search" => self.workbench.debugger.memory_search(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
                string(args, "pattern")?,
                args["max_results"].as_u64().unwrap_or(256) as usize,
            ),
            "memory_scan_server" => {
                let value_type = match string(args, "value_type")? {
                    "u8" => 0u8, "i8" => 1, "u16" => 2, "i16" => 3, "u32" => 4, "i32" => 5,
                    "u64" => 6, "i64" => 7, "float" => 8, "double" => 9, "bytes" => 10, "string" => 11,
                    other => bail!("Unsupported value_type: {other}"),
                };
                let data = hex::decode(string(args, "data_hex")?)?;
                ensure!(!data.is_empty(), "data_hex must be nonempty");
                self.workbench.debugger.scan_process(
                    number(args, "pid")? as u32,
                    value_type,
                    &data,
                    args["max_results"].as_u64().unwrap_or(256) as usize,
                )
            }
            "process_find" => {
                let needle = string(args, "name")?.to_ascii_lowercase();
                ensure!(!needle.is_empty(), "name must be nonempty");
                let processes = self.workbench.debugger.processes()?;
                let matches: Vec<Value> = processes
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|p| p["name"].as_str().unwrap_or("").to_ascii_lowercase().contains(&needle))
                    .cloned()
                    .collect();
                Ok(json!({"name": args["name"], "matches": matches, "count": matches.len()}))
            }
            "debug_label" => match string(args, "action")? {
                "set" => self
                    .workbench
                    .debugger
                    .label_set(string(args, "name")?, address(&args["address"])?),
                "remove" => self.workbench.debugger.label_remove(string(args, "name")?),
                "list" => Ok(self.workbench.debugger.label_list()),
                other => bail!("Unsupported label action: {other}"),
            },
            "debug_breakpoint_save" => Ok(self.workbench.debugger.breakpoints_export()),
            "debug_watchpoint_list" => Ok(self.workbench.debugger.watchpoint_list()),
            "debug_breakpoint_load" => {
                self.workbench.store.audit(
                    "debug_control_intent",
                    json!({"method":name,"arguments":args}),
                )?;
                let result = self
                    .workbench
                    .debugger
                    .breakpoints_import(&args["document"]);
                self.workbench.audit_result("debug_control", &result)?;
                result
            }
            "debug_step" | "debug_run" | "debug_registers_set" => {
                self.workbench.store.audit(
                    "debug_control_intent",
                    json!({"method":name,"arguments":args}),
                )?;
                let timeout = Duration::from_secs(
                    args["timeout_seconds"].as_u64().unwrap_or(10).clamp(1, 60),
                );
                let result = match name {
                    "debug_step" => self.workbench.debugger.step(
                        string(args, "action")?,
                        number(args, "thread_id")? as u32,
                        timeout,
                    ),
                    "debug_run" => self.workbench.debugger.run(
                        if args["target_address"].is_string() {
                            Some(address(&args["target_address"])?)
                        } else {
                            None
                        },
                        args["condition"].as_str(),
                        args["max_stops"].as_u64().unwrap_or(1) as u32,
                        timeout,
                    ),
                    _ => {
                        let changes = args["changes"]
                            .as_array()
                            .context("Missing changes")?
                            .iter()
                            .map(|change| {
                                Ok((
                                    string(change, "name")?.to_owned(),
                                    address(&change["value"])?,
                                ))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        self.workbench
                            .debugger
                            .set_registers(number(args, "thread_id")? as u32, &changes)
                    }
                };
                self.workbench.audit_result("debug_control", &result)?;
                result
            }
            "assemble" => {
                let base = if args["base_address"].is_string() {
                    address(&args["base_address"])?
                } else {
                    0
                };
                crate::asm::assemble_json(string(args, "assembly")?, base)
            }
            "memory_patch" => self.workbench.memory_patch(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                args["assembly"].as_str(),
                args["data_hex"].as_str(),
                args["nop_pad"].as_bool().unwrap_or(false),
                args["comment"].as_str().map(str::to_owned),
            ),
            "patch_list" => Ok(self
                .workbench
                .debugger
                .patch_list(args["pid"].as_u64().map(|p| p as u32))),
            "patch_restore" => self.workbench.patch_restore(number(args, "id")? as u32),
            "memory_scan" => self.workbench.debugger.memory_scan(args),
            "memory_alloc" => self.workbench.memory_alloc(
                number(args, "pid")? as u32,
                number(args, "length")? as usize,
                if args["address_hint"].is_string() {
                    Some(address(&args["address_hint"])?)
                } else {
                    None
                },
            ),
            "memory_free" => self.workbench.memory_free(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
            ),
            "memory_protect" => self.workbench.memory_protect(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
                number(args, "protection")? as u32,
            ),
            "memory_elf_dump" => self.workbench.memory_elf_dump(
                number(args, "pid")? as u32,
                args["module"].as_str(),
                if args["base_address"].is_string() {
                    Some(address(&args["base_address"])?)
                } else {
                    None
                },
            ),
            "debug_registers_fpu_set" => self
                .workbench
                .debug_registers_fpu_set(number(args, "thread_id")? as u32, &args["changes"]),
            "debug_tls" => self
                .workbench
                .debugger
                .tls_bases(number(args, "thread_id")? as u32),
            "debug_tls_set" => self.workbench.debug_tls_set(
                number(args, "thread_id")? as u32,
                if args["fsbase"].is_string() {
                    Some(address(&args["fsbase"])?)
                } else {
                    None
                },
                if args["gsbase"].is_string() {
                    Some(address(&args["gsbase"])?)
                } else {
                    None
                },
            ),
            "debug_label_save" => self.workbench.debug_label_save(),
            "debug_label_load" => self.workbench.debug_label_load(
                string(args, "artifact")?,
                args["merge"].as_bool().unwrap_or(false),
            ),
            "nid_resolve" => {
                let symbols = match args.get("symbols") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .context("symbols[] must be string")
                                .map(str::to_owned)
                        })
                        .collect::<Result<Vec<_>>>()?,
                    _ => Vec::new(),
                };
                let nids = match args.get("nids") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .context("nids[] must be string")
                                .map(str::to_owned)
                        })
                        .collect::<Result<Vec<_>>>()?,
                    _ => Vec::new(),
                };
                let custom = if let Some(dict_art) = args["dictionary_artifact"].as_str() {
                    let raw = self.workbench.read_artifact(dict_art, 16 * 1024 * 1024)?;
                    Some(crate::nid::parse_dictionary(&raw)?)
                } else {
                    None
                };
                crate::nid::resolve_batch(&symbols, &nids, custom.as_ref())
            }
            "address_rebase" => self.workbench.address_rebase(
                args["pid"].as_u64().map(|p| p as u32),
                args["module"].as_str(),
                if args["runtime_address"].is_string() {
                    Some(address(&args["runtime_address"])?)
                } else {
                    None
                },
                if args["static_address"].is_string() {
                    Some(address(&args["static_address"])?)
                } else {
                    None
                },
                if args["offset"].is_string() {
                    Some(address(&args["offset"])?)
                } else {
                    None
                },
                if args["static_base"].is_string() {
                    Some(address(&args["static_base"])?)
                } else {
                    None
                },
                args["artifact"].as_str(),
                args["module_sha256"].as_str(),
                args["application_version"].as_str(),
            ),
            "artifact_info" => analysis::artifact_info(&self.workbench.read_artifact(
                string(args, "artifact")?,
                self.workbench.profile.limit("transfer_bytes"),
            )?),
            "artifact_disasm" => {
                let data = self.workbench.read_artifact(
                    string(args, "artifact")?,
                    self.workbench.profile.limit("transfer_bytes"),
                )?;
                let offset = args["offset"].as_u64().unwrap_or(0);
                let base = if args["address"].is_string() {
                    address(&args["address"])?
                } else {
                    offset
                };
                analysis::disassemble_artifact(
                    &data,
                    offset as usize,
                    base,
                    args["count"].as_u64().unwrap_or(32) as usize,
                )
            }
            "artifact_strings" => {
                let data = self.workbench.read_artifact(
                    string(args, "artifact")?,
                    self.workbench.profile.limit("transfer_bytes"),
                )?;
                analysis::strings(
                    &data,
                    args["min_length"].as_u64().unwrap_or(6) as usize,
                    args["max_results"].as_u64().unwrap_or(256) as usize,
                )
            }
            "annotation_save" => analysis::annotate(
                &self.workbench.store,
                string(args, "artifact")?,
                string(args, "module_sha256")?,
                address(&args["rva"])?,
                string(args, "text")?,
                args["symbol"].as_str().unwrap_or(""),
            ),
            "ghidra_export" => analysis::ghidra_export(
                &self.workbench.store,
                string(args, "artifact")?,
                address(&args["image_base"])?,
                string(args, "module_sha256")?,
            ),
            "artifact_list" => self.workbench.store.inventory(),
            "artifact_read" => {
                let offset = args["offset"].as_u64().unwrap_or(0);
                let length = args["length"].as_u64().unwrap_or(256);
                let mut stream =
                    std::fs::File::open(self.workbench.store.path(string(args, "artifact")?)?)?;
                stream.seek(SeekFrom::Start(offset))?;
                let mut content = Vec::new();
                stream.take(length).read_to_end(&mut content)?;
                Ok(
                    json!({"offset":offset,"length":content.len(),"hex":hex::encode(&content),"utf8":String::from_utf8_lossy(&content)}),
                )
            }
            "experiment_bundle" => {
                let paths = args["paths"]
                    .as_array()
                    .context("Missing paths")?
                    .iter()
                    .map(|path| {
                        path.as_str()
                            .context("Path must be string")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.workbench.store.bundle(&paths, string(args, "notes")?)
            }
            "sdk_status" => self.development.status(),
            "sdk_scaffold" => self
                .development
                .scaffold(string(args, "kind")?, string(args, "name")?),
            "sdk_build" => self
                .development
                .build(string(args, "recipe")?, string(args, "sha256")?),
            _ => match crate::extensions::dispatch(self, name, args) {
                Some(result) => result,
                None => bail!("No implementation for tool: {name}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    #[test]
    fn address_precision_and_overflow() {
        assert_eq!(address(&json!("0xffffffffffffffff")).unwrap(), u64::MAX);
        assert!(address(&json!("18446744073709551616")).is_err());
        assert!(address(&json!(123)).is_err());
    }

    #[test]
    fn catalog_covers_existing_tools_and_policy() {
        let catalog: Vec<Value> = crate::extensions::full_catalog().unwrap();
        let mut names: Vec<&str> = catalog
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate tool names in catalog");
        for expected in [
            "debug_step",
            "debug_run",
            "debug_stack",
            "debug_eval",
            "disassemble",
            "module_list",
            "debug_registers_set",
            "debug_registers_fpu",
            "debug_registers_dr",
            "debug_breakpoint_list",
            "artifact_info",
            "artifact_disasm",
            "artifact_strings",
            "code_xrefs",
            "memory_search",
            "debug_label",
            "debug_breakpoint_save",
            "debug_breakpoint_load",
            "debug_watchpoint_list",
            "assemble",
            "memory_patch",
            "patch_list",
            "patch_restore",
            "memory_scan",
            "memory_alloc",
            "memory_free",
            "memory_protect",
            "memory_elf_dump",
            "debug_registers_fpu_set",
            "debug_tls",
            "debug_tls_set",
            "debug_label_save",
            "debug_label_load",
            "nid_resolve",
            "address_rebase",
        ] {
            assert!(
                catalog.iter().any(|tool| tool["name"] == expected),
                "{expected}"
            );
        }
        for tool in catalog {
            let validator = jsonschema::validator_for(&tool["inputSchema"]).unwrap();
            assert!(!validator.is_valid(&json!({"unexpected":true})));
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }

    #[test]
    fn offline_tools_dispatch_and_preserve_large_length_caps() {
        let dir = tempfile::tempdir().unwrap();
        let mut data: Value =
            serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        data["permissions"]["process_write"] = json!(true);
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, data.to_string()).unwrap();
        let profile = Profile::load(&profile_path).unwrap();
        let mut reg =
            ToolRegistry::with_toolset(Workbench::new(profile).unwrap(), Toolset::Full).unwrap();

        // memory_alloc length max should remain 64 MiB (not clamped to 1 MiB memory_bytes)
        let alloc_schema = reg
            .available()
            .into_iter()
            .find(|t| t["name"] == "memory_alloc")
            .unwrap();
        assert_eq!(
            alloc_schema["inputSchema"]["properties"]["length"]["maximum"],
            json!(67_108_864)
        );

        let asm = reg
            .call(
                "assemble",
                json!({"assembly": "xor eax, eax; ret", "base_address": "0x401000"}),
            )
            .unwrap();
        assert_eq!(asm["bytes"], "31c0c3");

        let nid = reg
            .call(
                "nid_resolve",
                json!({"symbols": ["sceKernelUsleep"], "nids": ["1jfXLRVzisc#libkernel#libkernel"]}),
            )
            .unwrap();
        assert_eq!(nid["encoded"][0]["nid"], "1jfXLRVzisc");
        assert_eq!(nid["decoded"][0]["symbol"], "sceKernelUsleep");

        reg.call(
            "debug_label",
            json!({"action": "set", "name": "player_tick", "address": "0x401234"}),
        )
        .unwrap();
        let saved = reg.call("debug_label_save", json!({})).unwrap();
        assert_eq!(saved["count"], 1);
        let loaded = reg
            .call(
                "debug_label_load",
                json!({"artifact": saved["artifact"]["path"], "merge": false}),
            )
            .unwrap();
        assert_eq!(loaded["loaded"], 1);
    }

    #[test]
    fn toolsets_are_an_additional_policy_gate() {
        let dir = tempfile::tempdir().unwrap();
        let mut data: Value =
            serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        data["permissions"]["debug_control"] = json!(true);
        data["permissions"]["process_write"] = json!(true);
        data["permissions"]["payload_execute"] = json!(true);
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, data.to_string()).unwrap();
        let profile = Profile::load(&profile_path).unwrap();

        let mut readonly =
            ToolRegistry::with_toolset(Workbench::new(profile.clone()).unwrap(), Toolset::ReadOnly)
                .unwrap();
        let readonly_names: Vec<_> = readonly
            .available()
            .into_iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        assert!(readonly_names.iter().any(|name| name == "artifact_info"));
        assert!(!readonly_names.iter().any(|name| name == "debug_attach"));
        assert!(!readonly_names.iter().any(|name| name == "memory_write"));
        assert!(
            readonly
                .call("debug_attach", json!({"pid": 7}))
                .unwrap_err()
                .to_string()
                .contains("toolset")
        );

        let debug =
            ToolRegistry::with_toolset(Workbench::new(profile.clone()).unwrap(), Toolset::Debug)
                .unwrap();
        let debug_names: Vec<_> = debug
            .available()
            .into_iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        assert!(debug_names.iter().any(|name| name == "debug_attach"));
        assert!(debug_names.iter().any(|name| name == "memory_write"));
        assert!(!debug_names.iter().any(|name| name == "payload_execute"));

        let full =
            ToolRegistry::with_toolset(Workbench::new(profile).unwrap(), Toolset::Full).unwrap();
        assert!(
            full.available()
                .iter()
                .any(|tool| tool["name"] == "payload_execute")
        );
    }
}
