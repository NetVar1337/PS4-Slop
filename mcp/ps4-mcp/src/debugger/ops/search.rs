//! Live code xrefs, memory/kernel search, byte patches and memory scans.

use super::*;

impl Debugger {

    // ---- xrefs, search, patches, scanner, labels, persistence --------------

    /// Read a code range without re-validating maps per chunk; own breakpoint
    /// bytes are restored, same as `read_code`.
    fn read_code_fast(&mut self, pid: u32, address: u64, length: usize) -> Result<Vec<u8>> {
        let step_cap = self.profile.limit("memory_bytes").clamp(4096, 262_144);
        let mut content = Vec::with_capacity(length);
        let mut cursor = address;
        let mut remaining = length;
        while remaining > 0 {
            let ask = remaining.min(step_cap);
            let chunk = self.read_memory(pid, cursor, ask, false)?;
            let got = chunk.len();
            content.extend(chunk);
            if got == 0 {
                break;
            }
            cursor = cursor.saturating_add(got as u64);
            remaining -= got;
        }
        for record in self.breakpoints.values().filter(|record| record.enabled) {
            if let Some(original) = record.original
                && record.address >= address
                && ((record.address - address) as usize) < content.len()
            {
                content[(record.address - address) as usize] = original;
            }
        }
        Ok(content)
    }

    pub fn code_xrefs(&mut self, pid: u32, target: u64, max_results: usize) -> Result<Value> {
        self.code_xrefs_filtered(pid, target, max_results, None, None)
    }

    /// Find instructions whose branch target or rip-relative memory operand is
    /// `target`, decoded locally over readable+executable mappings with optional
    /// module or `[address, address + length)` filtering.
    pub fn code_xrefs_filtered(
        &mut self,
        pid: u32,
        target: u64,
        max_results: usize,
        module_filter: Option<&str>,
        range_filter: Option<(u64, usize)>,
    ) -> Result<Value> {
        ensure!((1..=1024).contains(&max_results), "max_results must be 1-1024");
        Self::pid(pid)?;
        let maps = self.maps(pid)?;
        let entries = maps.as_array().context("Expected maps")?;
        let mod_needle = module_filter.map(|s| s.to_ascii_lowercase());
        let mut exec = Vec::new();
        for entry in entries {
            let protection = entry["protection"].as_u64().unwrap_or(0);
            if protection & 5 != 5 {
                continue;
            }
            let mut start = entry["start"].as_u64().unwrap_or(0);
            let mut end = entry["end"].as_u64().unwrap_or(0);
            let name = entry["name"].as_str().unwrap_or("").to_owned();
            if let Some(ref needle) = mod_needle
                && !name.to_ascii_lowercase().contains(needle)
            {
                continue;
            }
            if let Some((r_start, r_len)) = range_filter {
                let r_end = r_start.saturating_add(r_len as u64);
                start = start.max(r_start);
                end = end.min(r_end);
            }
            if start < end {
                exec.push((start, end, name));
            }
        }
        let cap = if module_filter.is_some() || range_filter.is_some() {
            self.profile
                .limit("transfer_bytes")
                .max(self.profile.limit("memory_bytes"))
                .min(16 * 1024 * 1024) as u64
        } else {
            self.profile.limit("memory_bytes").max(4096) as u64
        };
        let mut refs = Vec::new();
        let mut scanned = 0u64;
        'outer: for (start, end, name) in exec {
            let length = (end - start).min(cap.saturating_sub(scanned));
            if length == 0 {
                break;
            }
            let bytes = self.read_code_fast(pid, start, length as usize)?;
            scanned += bytes.len() as u64;
            let mut position = 0usize;
            while position < bytes.len() {
                let items = disasm::decode(
                    &bytes[position..],
                    start + position as u64,
                    disasm::MAX_INSTRUCTIONS,
                );
                if items.is_empty() {
                    position += 1;
                    continue;
                }
                let last = items.last().unwrap();
                let consumed =
                    ((last.address + last.length as u64) - (start + position as u64)) as usize;
                for item in &items {
                    if item.branch_target == Some(target) || item.memory_target == Some(target) {
                        if refs.len() >= max_results {
                            break 'outer;
                        }
                        let kind = if item.branch_target == Some(target) {
                            match item.flow {
                                "call" | "indirect_call" => "call",
                                _ => "jump",
                            }
                        } else {
                            "rip_relative"
                        };
                        refs.push(json!({"address":format!("{:#x}",item.address),"module":name,
                            "instruction":item.text,"kind":kind,"target":format!("{target:#x}")}));
                    }
                }
                position += consumed.max(1);
            }
            if scanned >= cap {
                break;
            }
        }
        let modules = self.module_bases(pid).unwrap_or_default();
        let target_symbol = Self::annotate(target, &modules).or_else(|| {
            self.labels
                .iter()
                .find(|(_, value)| **value == target)
                .map(|(name, _)| name.clone())
        });
        Ok(json!({
            "target": format!("{target:#x}"),
            "target_symbol": target_symbol,
            "module_filter": module_filter,
            "references": refs,
            "count": refs.len(),
            "scanned_bytes": scanned,
            "truncated": refs.len() >= max_results || scanned >= cap,
            "note": "Decoded locally over readable+executable mappings with own int3 bytes masked",
        }))
    }

    /// Live pattern search (hex bytes with `??` wildcards) over a bounded range,
    /// chunked by page with `(pattern_len - 1)` overlap carry so matches straddling
    /// 4 KiB page boundaries are never missed.
    pub fn memory_search(
        &mut self,
        pid: u32,
        address: u64,
        length: usize,
        pattern: &str,
        max_matches: usize,
    ) -> Result<Value> {
        ensure!((1..=4096).contains(&max_matches), "max_matches must be 1-4096");
        address_range(address, length, self.profile.limit("memory_bytes"))?;
        // Validate pattern once up-front and determine byte width for page-boundary carry.
        let pat_len = crate::analysis::pattern_len(pattern)?;
        let overlap = pat_len.saturating_sub(1);

        let mut matches = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        let mut carry: Vec<u8> = Vec::new();
        let mut carry_addr = address;

        for (chunk_address, chunk_length) in Self::page_chunks(address, length) {
            let content = self.read_memory(pid, chunk_address, chunk_length, false)?;
            scanned += content.len();
            let base = if carry.is_empty() {
                chunk_address
            } else {
                carry_addr
            };
            let mut window = Vec::with_capacity(carry.len() + content.len());
            window.extend_from_slice(&carry);
            window.extend_from_slice(&content);

            let found = crate::analysis::scan_pattern_at(
                &window,
                pattern,
                base,
                max_matches - matches.len(),
            )?;
            if let Some(items) = found["matches"].as_array() {
                for item in items {
                    if !matches.contains(item) {
                        matches.push(item.clone());
                        if matches.len() >= max_matches {
                            break;
                        }
                    }
                }
            }
            if matches.len() >= max_matches {
                truncated = true;
                break;
            }
            let keep = overlap.min(window.len());
            carry.clear();
            if keep > 0 {
                carry.extend_from_slice(&window[window.len() - keep..]);
                carry_addr = base + (window.len() - keep) as u64;
            }
        }
        Ok(json!({
            "address": format!("{address:#x}"),
            "length": length,
            "pattern": pattern,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned,
            "truncated": truncated,
            "note": "Local scan of chunked reads with full 4 KiB page-boundary overlap",
        }))
    }

    /// Kernel-space counterpart of [`Self::memory_search`]: local pattern scan over
    /// chunked `CMD_KERNEL_READ` (0xbdcc0002) reads; never sends a kernel write.
    pub fn kernel_search(
        &mut self,
        address: u64,
        length: usize,
        pattern: &str,
        max_matches: usize,
    ) -> Result<Value> {
        ensure!((1..=4096).contains(&max_matches), "max_matches must be 1-4096");
        address_range(address, length, self.profile.limit("memory_bytes"))?;
        let pat_len = crate::analysis::pattern_len(pattern)?;
        let overlap = pat_len.saturating_sub(1);

        let mut matches = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        let mut carry: Vec<u8> = Vec::new();
        let mut carry_addr = address;

        for (chunk_address, chunk_length) in Self::page_chunks(address, length) {
            let content = self.read_memory(0, chunk_address, chunk_length, true)?;
            scanned += content.len();
            let base = if carry.is_empty() {
                chunk_address
            } else {
                carry_addr
            };
            let mut window = Vec::with_capacity(carry.len() + content.len());
            window.extend_from_slice(&carry);
            window.extend_from_slice(&content);

            let found = crate::analysis::scan_pattern_at(
                &window,
                pattern,
                base,
                max_matches - matches.len(),
            )?;
            if let Some(items) = found["matches"].as_array() {
                for item in items {
                    if !matches.contains(item) {
                        matches.push(item.clone());
                        if matches.len() >= max_matches {
                            break;
                        }
                    }
                }
            }
            if matches.len() >= max_matches {
                truncated = true;
                break;
            }
            let keep = overlap.min(window.len());
            carry.clear();
            if keep > 0 {
                carry.extend_from_slice(&window[window.len() - keep..]);
                carry_addr = base + (window.len() - keep) as u64;
            }
        }
        Ok(json!({
            "address": format!("{address:#x}"),
            "length": length,
            "pattern": pattern,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned,
            "truncated": truncated,
            "kernel": true,
            "note": "Local scan of chunked kernel reads with full 4 KiB page-boundary overlap",
        }))
    }

    /// Assemble or hex-decode a patch at `address`, optionally NOP-pad to the
    /// overwritten instruction boundary, record original bytes, write, and readback-verify.
    pub fn apply_patch(
        &mut self,
        pid: u32,
        address: u64,
        assembly: Option<&str>,
        bytes_hex: Option<&str>,
        nop_pad: bool,
        comment: Option<String>,
    ) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        Self::pid(pid)?;
        ensure!(
            assembly.is_some() ^ bytes_hex.is_some(),
            "Provide exactly one of 'assembly' or 'data_hex'"
        );
        let raw_patch = if let Some(src) = assembly {
            asm::assemble(src, address)?
        } else {
            let s = bytes_hex.unwrap().trim();
            let decoded = hex::decode(s.strip_prefix("0x").unwrap_or(s))?;
            ensure!(
                !decoded.is_empty() && decoded.len() <= asm::MAX_ASM_BYTES,
                "Patch must be 1..={} bytes",
                asm::MAX_ASM_BYTES
            );
            decoded
        };

        let inspect_len = (raw_patch.len() + 15).min(self.profile.limit("memory_bytes"));
        let existing = self.read_memory(pid, address, inspect_len, false)?;
        let (final_patch, nop_padded) =
            asm::pad_patch_over_code(&raw_patch, &existing, address, nop_pad)?;
        ensure!(
            existing.len() >= final_patch.len(),
            "Insufficient readable bytes at {address:#x} to capture original patch window"
        );
        let original = existing[..final_patch.len()].to_vec();

        self.write_memory(pid, address, &final_patch, false)?;
        let readback = self.read_memory(pid, address, final_patch.len(), false)?;
        ensure!(
            readback == final_patch,
            "Patch readback mismatch at {address:#x}; target memory may not be writable (call memory_protect first)"
        );

        let id = self.next_patch_id;
        self.next_patch_id += 1;
        let record = PatchRecord {
            id,
            pid,
            address,
            original: original.clone(),
            patched: final_patch.clone(),
            assembly: assembly.map(str::to_owned),
            nop_padded,
            active: true,
            comment: comment.clone(),
        };
        self.patches.insert(id, record);
        let decoded = disasm::decode(&final_patch, address, disasm::MAX_INSTRUCTIONS);
        Ok(json!({
            "id": id,
            "patch_id": id,
            "pid": pid,
            "address": format!("{address:#x}"),
            "byte_length": final_patch.len(),
            "nop_padded": nop_padded,
            "original_hex": hex::encode(&original),
            "patched_hex": hex::encode(&final_patch),
            "assembly": assembly,
            "comment": comment,
            "instructions": disasm::to_json(&decoded),
            "verified": true,
        }))
    }

    pub fn patch_list(&self, pid: Option<u32>) -> Value {
        let items: Vec<Value> = self
            .patches
            .values()
            .filter(|r| pid.is_none_or(|p| r.pid == p))
            .map(|r| {
                json!({
                    "id": r.id,
                    "patch_id": r.id,
                    "pid": r.pid,
                    "address": format!("{:#x}", r.address),
                    "byte_length": r.patched.len(),
                    "nop_padded": r.nop_padded,
                    "original_hex": hex::encode(&r.original),
                    "patched_hex": hex::encode(&r.patched),
                    "assembly": r.assembly,
                    "comment": r.comment,
                    "active": r.active,
                })
            })
            .collect();
        json!({ "count": items.len(), "patches": items })
    }

    pub fn patch_restore(&mut self, patch_id: u32) -> Result<Value> {
        self.require_qualified_debugger("process_write")?;
        let record = self
            .patches
            .get(&patch_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Patch {patch_id} not found"))?;
        ensure!(record.active, "Patch {patch_id} is already restored");
        self.write_memory(record.pid, record.address, &record.original, false)?;
        let readback =
            self.read_memory(record.pid, record.address, record.original.len(), false)?;
        ensure!(
            readback == record.original,
            "Patch restore readback mismatch at {:#x}",
            record.address
        );
        if let Some(entry) = self.patches.get_mut(&patch_id) {
            entry.active = false;
        }
        Ok(json!({
            "patch_id": patch_id,
            "pid": record.pid,
            "address": format!("{:#x}", record.address),
            "restored_hex": hex::encode(&record.original),
            "verified": true,
        }))
    }

    /// Stateful multi-pass memory value scanner (`first`, `next`, `get`, `list`, `reset`).
    pub fn memory_scan(&mut self, arguments: &Value) -> Result<Value> {
        let action = arguments["action"]
            .as_str()
            .unwrap_or("first")
            .to_ascii_lowercase();
        let session_id = arguments["session_id"]
            .as_str()
            .unwrap_or("default")
            .to_owned();
        ensure!(
            !session_id.is_empty() && session_id.len() <= 64,
            "session_id must be 1..=64 chars"
        );
        let limit = arguments["limit"]
            .as_u64()
            .map(|n| n as usize)
            .unwrap_or(crate::scanner::DEFAULT_PAGE_LIMIT);
        let offset = arguments["offset"].as_u64().unwrap_or(0) as usize;

        match action.as_str() {
            "list" => return Ok(self.scans.list()),
            "reset" => return Ok(self.scans.reset(&session_id)),
            "get" => {
                let refresh = arguments["refresh"].as_bool().unwrap_or(false);
                if refresh {
                    let pid = arguments["pid"]
                        .as_u64()
                        .map(|n| n as u32)
                        .or(self.attached_pid)
                        .context("pid required when refresh=true without active attachment")?;
                    Self::pid(pid)?;
                    let scans = std::mem::take(&mut self.scans);
                    let mut reader = |addr: u64, len: usize| self.read_memory(pid, addr, len, false);
                    let res = scans.get(&session_id, offset, limit, Some(&mut reader));
                    self.scans = scans;
                    return res;
                }
                return self.scans.get(&session_id, offset, limit, None);
            }
            "first" | "next" => {}
            other => bail!("Unsupported memory_scan action '{other}' (use first, next, get, list, reset)"),
        }

        let pid = arguments["pid"]
            .as_u64()
            .map(|n| n as u32)
            .or(self.attached_pid)
            .context("pid is required when not attached")?;
        Self::pid(pid)?;

        let value_type = match arguments.get("value_type").and_then(Value::as_str) {
            Some(s) => Some(ScanValueType::parse(s)?),
            None => None,
        };
        let default_cmp = if action == "first" || arguments.get("value").is_some_and(|v| !v.is_null()) {
            "exact"
        } else {
            "changed"
        };
        let comparison = ScanComparison::parse(
            arguments["comparison"].as_str().unwrap_or(default_cmp),
        )?;
        let stringify = |v: &Value| -> Option<String> {
            match v {
                Value::Null => None,
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(u8::from(*b).to_string()),
                _ => None,
            }
        };
        let req = ScanRequest {
            session_id,
            value_type,
            comparison,
            value: arguments.get("value").and_then(stringify),
            value_max: arguments.get("value_max").and_then(stringify),
            float_epsilon: arguments["float_epsilon"].as_f64().unwrap_or(0.0001),
            case_insensitive: arguments["case_insensitive"].as_bool().unwrap_or(false),
            alignment: arguments["alignment"].as_u64().map(|n| n as usize),
            max_candidates: arguments["max_candidates"]
                .as_u64()
                .map(|n| n as usize)
                .unwrap_or(100_000),
            limit,
            offset,
        };

        let chunk_cap = self.profile.limit("memory_bytes").clamp(4096, 262_144);
        let max_scan_bytes = self
            .profile
            .limit("transfer_bytes")
            .max(chunk_cap)
            .min(64 * 1024 * 1024);

        if action == "first" {
            let writable_only = arguments["writable_only"].as_bool().unwrap_or(false);
            let module_filter = arguments["module"].as_str().map(str::to_ascii_lowercase);
            let explicit_start = match arguments.get("address") {
                Some(Value::Null) | None => None,
                Some(v) => Some(
                    v.as_u64()
                        .or_else(|| parse_hex(v))
                        .context("Invalid scan start address")?,
                ),
            };
            let explicit_len = arguments["length"].as_u64();

            let maps = self.maps(pid)?;
            let mut regions = Vec::new();
            for entry in maps.as_array().context("Expected maps")? {
                let prot = entry["protection"].as_u64().unwrap_or(0) as u32;
                if prot & 1 == 0 || (writable_only && prot & 2 == 0) {
                    continue;
                }
                let name = entry["name"].as_str().unwrap_or("").to_owned();
                if let Some(ref mf) = module_filter
                    && !name.to_ascii_lowercase().contains(mf)
                {
                    continue;
                }
                let mut start = entry["start"].as_u64().unwrap_or(0);
                let mut end = entry["end"].as_u64().unwrap_or(0);
                if let Some(es) = explicit_start {
                    start = start.max(es);
                    if let Some(el) = explicit_len {
                        end = end.min(es.saturating_add(el));
                    }
                }
                if start < end {
                    regions.push(ScanRegion {
                        start,
                        end,
                        name,
                        prot,
                    });
                }
            }
            let mut scans = std::mem::take(&mut self.scans);
            let res = scans.first_scan(
                pid,
                &req,
                &regions,
                chunk_cap,
                max_scan_bytes,
                |addr, len| self.read_memory(pid, addr, len, false),
            );
            self.scans = scans;
            res
        } else {
            let mut scans = std::mem::take(&mut self.scans);
            let res = scans.next_scan(pid, &req, chunk_cap, |addr, len| {
                self.read_memory(pid, addr, len, false)
            });
            self.scans = scans;
            res
        }
    }
}
