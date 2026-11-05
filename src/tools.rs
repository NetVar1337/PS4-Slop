use crate::{
    Result, analysis,
    development::Development,
    workbench::{Workbench, desktop_status},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

pub struct ToolRegistry {
    pub workbench: Workbench,
    catalog: Vec<Value>,
    validators: std::collections::HashMap<String, jsonschema::Validator>,
    development: Development,
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
        let mut catalog: Vec<Value> = serde_json::from_str(include_str!("tool_catalog.json"))?;
        let mut validators = std::collections::HashMap::new();
        for tool in &mut catalog {
            let properties = &mut tool["inputSchema"]["properties"];
            if properties.get("length").is_some() {
                let limit = if tool["name"] == "memory_region_dump" {
                    workbench.profile.limit("transfer_bytes")
                } else if tool["name"] == "memory_peek" {
                    workbench.profile.limit("memory_bytes").min(8192)
                } else {
                    workbench.profile.limit("memory_bytes")
                };
                if tool["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("memory_") || name == "kernel_read")
                {
                    tool["inputSchema"]["properties"]["length"]["maximum"] = json!(limit);
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
        })
    }

    pub fn available(&self) -> Vec<Value> {
        self.catalog
            .iter()
            .filter(|tool| {
                tool["permission"].as_str().is_none_or(|permission| {
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
        self.validators
            .get(name)
            .context("Missing schema")?
            .validate(&args)
            .map_err(|error| anyhow::anyhow!("Invalid arguments: {error}"))?;
        if let Some(permission) = tool["permission"].as_str() {
            self.workbench.profile.require(permission)?;
        }
        let result = self.execute(name, &args)?;
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
            "debug_registers_dr" => self
                .workbench
                .debugger
                .hardware_debug_registers(number(args, "thread_id")? as u32),
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
            "code_xrefs" => self.workbench.debugger.code_xrefs(
                number(args, "pid")? as u32,
                address(&args["target_address"])?,
                args["max_results"].as_u64().unwrap_or(256) as usize,
            ),
            "memory_search" => self.workbench.debugger.memory_search(
                number(args, "pid")? as u32,
                address(&args["address"])?,
                number(args, "length")? as usize,
                string(args, "pattern")?,
                args["max_results"].as_u64().unwrap_or(256) as usize,
            ),
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
                let result = self.workbench.debugger.breakpoints_import(&args["document"]);
                self.workbench.audit_result("debug_control", &result)?;
                result
            }
            "debug_step" | "debug_run" | "debug_registers_set" => {
                self.workbench.store.audit(
                    "debug_control_intent",
                    json!({"method":name,"arguments":args}),
                )?;
                let timeout =
                    Duration::from_secs(args["timeout_seconds"].as_u64().unwrap_or(10).clamp(1, 60));
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
            "address_correlate" => {
                let start = address(&args["address"])?;
                let maps = self.workbench.debugger.maps(number(args, "pid")? as u32)?;
                let selected = maps
                    .as_array()
                    .context("Expected maps")?
                    .iter()
                    .find(|entry| {
                        entry["start"].as_u64().is_some_and(|base| base <= start)
                            && entry["end"].as_u64().is_some_and(|end| start < end)
                    })
                    .context("Address not mapped")?;
                let base = selected["start"]
                    .as_u64()
                    .context("Invalid start")?
                    .checked_sub(selected["offset"].as_u64().context("Invalid offset")?)
                    .context("Map offset exceeds start")?;
                Ok(
                    json!({"pid":args["pid"],"module_name":selected["name"],"module_sha256":args["module_sha256"],"application_version":args["application_version"],
                    "absolute_address":format!("{start:#x}"),"mapping_base":format!("{:#x}",selected["start"].as_u64().unwrap()),
                    "mapping_relative_offset":format!("{:#x}",start-selected["start"].as_u64().unwrap()),"estimated_image_base":format!("{base:#x}"),"estimated_rva":format!("{:#x}",start-base),"warning":"Estimated from map offset; verify ELF PT_LOAD layout"}),
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
            _ => bail!("No implementation for tool: {name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_precision_and_overflow() {
        assert_eq!(address(&json!("0xffffffffffffffff")).unwrap(), u64::MAX);
        assert!(address(&json!("18446744073709551616")).is_err());
        assert!(address(&json!(123)).is_err());
    }

    #[test]
    fn catalog_covers_existing_tools_and_policy() {
        let catalog: Vec<Value> = serde_json::from_str(include_str!("tool_catalog.json")).unwrap();
        assert_eq!(catalog.len(), 61);
        for expected in [
            "debug_step", "debug_run", "debug_stack", "debug_eval", "disassemble",
            "module_list", "debug_registers_set", "debug_registers_fpu",
            "debug_registers_dr", "debug_breakpoint_list", "artifact_info",
            "artifact_disasm", "artifact_strings", "code_xrefs", "memory_search",
            "debug_label", "debug_breakpoint_save", "debug_breakpoint_load",
            "debug_watchpoint_list",
        ] {
            assert!(catalog.iter().any(|tool| tool["name"] == expected), "{expected}");
        }
        for tool in catalog {
            let validator = jsonschema::validator_for(&tool["inputSchema"]).unwrap();
            assert!(!validator.is_valid(&json!({"unexpected":true})));
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }
}
