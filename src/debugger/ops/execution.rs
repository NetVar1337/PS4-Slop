//! Stopping, stepping, running and CFI/frame-pointer stack unwinding.

use super::*;

impl Debugger {

    // ---- DWARF .eh_frame CFI support ---------------------------------------

    fn load_module_eh_frame(
        &mut self,
        pid: u32,
        module_base: u64,
        module_end: u64,
    ) -> Option<(u64, Vec<u8>)> {
        if let Some(cached) = self.eh_cache.get(&(pid, module_base)) {
            return cached.clone();
        }
        let found = (|| -> Option<(u64, Vec<u8>)> {
            let hdr_len = (module_end.saturating_sub(module_base)).min(4096) as usize;
            if hdr_len < 64 {
                return None;
            }
            let header = self.read_memory(pid, module_base, hdr_len, false).ok()?;
            let (eh_va, max_len) = ehframe::find_eh_frame_from_elf_header(
                &header,
                module_base,
                module_end,
                |va, len| self.read_memory(pid, va, len, false),
            )?;
            let cap = max_len.min(self.profile.limit("memory_bytes")).min(262_144);
            let mut bytes = Vec::new();
            for (chunk_va, chunk_len) in Self::page_chunks(eh_va, cap) {
                match self.read_memory(pid, chunk_va, chunk_len, false) {
                    Ok(part) => bytes.extend(part),
                    Err(_) => break,
                }
            }
            if bytes.len() < 16 {
                return None;
            }
            Some((eh_va, bytes))
        })();
        self.eh_cache.insert((pid, module_base), found.clone());
        found
    }

    fn dwarf_regs_from_raw(raw: &[u8]) -> [Option<u64>; 17] {
        let f = RegisterFile(raw);
        [
            f.get("rax"),
            f.get("rdx"),
            f.get("rcx"),
            f.get("rbx"),
            f.get("rsi"),
            f.get("rdi"),
            f.get("rbp"),
            f.get("rsp"),
            f.get("r8"),
            f.get("r9"),
            f.get("r10"),
            f.get("r11"),
            f.get("r12"),
            f.get("r13"),
            f.get("r14"),
            f.get("r15"),
            f.get("rip"),
        ]
    }

    /// Attempt to unwind one frame at `lookup_pc` using DWARF `.eh_frame` CFI.
    /// Returns `Some((caller_rip, cfa, updated_dwarf_regs))`.
    fn unwind_cfi_once(
        &mut self,
        pid: u32,
        lookup_pc: u64,
        regs: &[Option<u64>; 17],
        modules: &[(String, u64, u64)],
    ) -> Option<(u64, u64, [Option<u64>; 17])> {
        let (_, base, end) = modules
            .iter()
            .find(|(_, b, e)| *b <= lookup_pc && lookup_pc < *e)?;
        let (eh_va, eh_bytes) = self.load_module_eh_frame(pid, *base, *end)?;
        let (row, ret_reg) = ehframe::unwind_at_pc(&eh_bytes, eh_va, lookup_pc).ok()??;
        let cfa_base = (*regs.get(row.cfa_reg as usize)?)?;
        let cfa = (cfa_base as i128 + row.cfa_offset as i128) as u64;
        if cfa == 0 {
            return None;
        }
        let eval_rule = |debugger: &mut Self, reg_idx: u8, rule: ehframe::RegRule| -> Option<u64> {
            match rule {
                ehframe::RegRule::Undefined => None,
                ehframe::RegRule::SameValue => *regs.get(reg_idx as usize)?,
                ehframe::RegRule::Offset(off) => {
                    let addr = (cfa as i128 + off as i128) as u64;
                    let bytes = debugger.read_memory(pid, addr, 8, false).ok()?;
                    Some(qword(&bytes, 0))
                }
                ehframe::RegRule::ValOffset(off) => Some((cfa as i128 + off as i128) as u64),
            }
        };
        let ret_rule = row.regs.get(&ret_reg).copied()?;
        let caller_rip = eval_rule(self, ret_reg, ret_rule)?;
        let mut next = [None; 17];
        // Callee-saved System V / Orbis registers default to SameValue unless overridden by FDE
        for preserved in [3usize, 6, 12, 13, 14, 15] {
            next[preserved] = regs[preserved];
        }
        for (&reg_idx, &rule) in &row.regs {
            if (reg_idx as usize) < 17 {
                next[reg_idx as usize] = eval_rule(self, reg_idx, rule);
            }
        }
        next[ehframe::DWARF_RSP as usize] = Some(cfa);
        next[ehframe::DWARF_RIP as usize] = Some(caller_rip);
        Some((caller_rip, cfa, next))
    }

    // ---- execution control -------------------------------------------------

    /// Wait for the next stop callback. Consumed events are stashed so that
    /// `poll_events` (and the broker's event journal) still sees them.
    pub fn wait_stop(&mut self, timeout: Duration) -> Result<Option<Value>> {
        self.session()?;
        let deadline = Instant::now() + timeout;
        loop {
            let events = self.read_events()?;
            if !events.is_empty() {
                let first = events[0].clone();
                self.stash.extend(events);
                return Ok(Some(first));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn live_state(&mut self, thread_id: u32) -> Result<Value> {
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(0);
        let pid = self.attached()?;
        let modules = self.module_bases(pid).unwrap_or_default();
        Ok(json!({"thread_id":thread_id,"rip":format!("{rip:#x}"),
            "rsp":format!("{:#x}",file.get("rsp").unwrap_or(0)),
            "location":Self::annotate(rip, &modules),"registers":registers(&raw)?}))
    }

    /// Slot of an already-tracked enabled breakpoint at `address`, if any.
    fn target_slot_for(&self, address: u64) -> Option<u32> {
        self.breakpoints
            .iter()
            .find(|(_, record)| record.enabled && record.address == address)
            .map(|(slot, _)| *slot)
    }

    /// Temporary breakpoint in a free slot, tracked as internal so it never
    /// shows up in `breakpoint_list` and is always cleared by the caller.
    pub(in crate::debugger) fn set_internal_breakpoint(&mut self, address: u64) -> Result<u32> {
        let slot = self.free_slot()?;
        self.breakpoint_ex(slot, address, true, None, None, 0)?;
        if let Some(record) = self.breakpoints.get_mut(&slot) {
            record.internal = true;
        }
        Ok(slot)
    }

    pub(in crate::debugger) fn clear_internal_breakpoint(&mut self, slot: u32) -> Result<()> {
        let result = self.breakpoint(slot, 0, false).map(|_| ());
        self.breakpoints.remove(&slot);
        result
    }

    /// Step one instruction (`into`), over calls and repeated string ops
    /// (`over`), or out of the current function (`out`). Over/out fall back to a
    /// temporary breakpoint at the next instruction / caller return address
    /// (resolved via DWARF `.eh_frame` CFI -> `[rbp+8]` -> `[rsp]`).
    pub fn step(&mut self, mode: &str, thread_id: u32, timeout: Duration) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.attached()?;
        Self::pid(thread_id)?;
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").context("Thread has no rip")?;
        let plan = match mode {
            "into" => disasm::StepPlan::Single,
            "over" => {
                let bytes = self.read_code(pid, rip, 16)?;
                disasm::step_over_plan(&bytes, rip)?
            }
            "out" => {
                let bytes = self.read_code(pid, rip, 16)?;
                if disasm::is_return(&bytes, rip) {
                    disasm::StepPlan::Single
                } else {
                    let maps = self.maps(pid)?;
                    let is_exec = |addr: u64| -> bool {
                        maps.as_array().is_some_and(|arr| {
                            arr.iter().any(|entry| {
                                entry["protection"].as_u64().unwrap_or(0) & 4 != 0
                                    && entry["start"].as_u64().unwrap_or(0) <= addr
                                    && addr < entry["end"].as_u64().unwrap_or(0)
                            })
                        })
                    };
                    let modules = self.module_bases(pid).unwrap_or_default();
                    let dwarf_regs = Self::dwarf_regs_from_raw(&raw);
                    let mut target_opt = self
                        .unwind_cfi_once(pid, rip, &dwarf_regs, &modules)
                        .map(|(ret, _, _)| ret)
                        .filter(|&ret| is_exec(ret));

                    let rsp = file.get("rsp").context("Thread has no rsp")?;
                    let rbp = file.get("rbp").unwrap_or(0);
                    if target_opt.is_none()
                        && rbp >= rsp
                        && rbp.is_multiple_of(8)
                        && let Ok(pair) = self.read_memory(pid, rbp, 16, false)
                    {
                        let ret = qword(&pair, 8);
                        if is_exec(ret) {
                            target_opt = Some(ret);
                        }
                    }
                    if target_opt.is_none()
                        && let Ok(top) = self.read_memory(pid, rsp, 8, false)
                    {
                        let ret = qword(&top, 0);
                        if is_exec(ret) {
                            target_opt = Some(ret);
                        }
                    }
                    let target = target_opt.ok_or_else(|| {
                        anyhow::anyhow!(
                            "Could not resolve an executable return address via .eh_frame, [rbp+8], or [rsp]; step out refused"
                        )
                    })?;
                    disasm::StepPlan::RunTo(target)
                }
            }
            other => bail!("Unsupported step mode: {other} (use into, over or out)"),
        };
        let (stop, note) = match plan {
            disasm::StepPlan::Single => {
                self.control("step_thread", thread_id)?;
                (self.wait_stop(timeout)?, "single_step")
            }
            disasm::StepPlan::RunTo(target) => {
                let internal = match self.target_slot_for(target) {
                    Some(_) => None,
                    None => Some(self.set_internal_breakpoint(target)?),
                };
                let resumed = self.control("resume", 0);
                let stopped = self.wait_stop(timeout);
                let cleared = internal.map_or(Ok(()), |slot| self.clear_internal_breakpoint(slot));
                resumed?;
                let stop = stopped?;
                cleared?;
                (
                    stop,
                    "run_to_temp_breakpoint: the server executes the instruction at the breakpoint before reporting the stop, so live rip can be one instruction past the target",
                )
            }
        };
        let state = self.live_state(thread_id).ok();
        Ok(json!({"mode":mode,"thread_id":thread_id,"plan":note,"stop":stop,"state":state}))
    }

    /// Resume all threads and report stop events. Evaluates both per-breakpoint
    /// conditions/logs/`stop_after` thresholds and optional run-level `condition`.
    /// Bounded by `max_stops` events and `timeout`; never resumes after the final stop.
    pub fn run(
        &mut self,
        target: Option<u64>,
        condition: Option<&str>,
        max_stops: u32,
        timeout: Duration,
    ) -> Result<Value> {
        self.require_qualified_debugger("debug_control")?;
        let pid = self.attached()?;
        if let Some(text) = condition {
            expr::validate(text)?;
        }
        ensure!((1..=64).contains(&max_stops), "max_stops must be 1-64");
        let (target_slot, internal) = match target {
            Some(address) => match self.target_slot_for(address) {
                Some(slot) => (Some(slot), false),
                None => (Some(self.set_internal_breakpoint(address)?), true),
            },
            None => (None, false),
        };
        let outcome = self.run_loop(pid, target, target_slot, condition, max_stops, timeout);
        if internal
            && let Some(slot) = target_slot
            && let Err(error) = self.clear_internal_breakpoint(slot)
            && outcome.is_ok()
        {
            return Err(error.context("Run finished but the temporary breakpoint could not be cleared; console state uncertain"));
        }
        outcome
    }

    fn run_loop(
        &mut self,
        pid: u32,
        target: Option<u64>,
        target_slot: Option<u32>,
        condition: Option<&str>,
        max_stops: u32,
        timeout: Duration,
    ) -> Result<Value> {
        self.control("resume", 0)?;
        let deadline = Instant::now() + timeout;
        let mut stops = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("Run timeout; threads may still be running; call debug_control halt")?;
            let Some(event) = self.wait_stop(remaining)? else {
                break;
            };
            let event_thread = event["thread_id"].as_u64().unwrap_or(0) as u32;
            let event_rip = parse_hex(&event["registers"]["rip"]).unwrap_or(0);
            let mut hit_slot = None;
            let mut bp_cond_expr: Option<String> = None;
            let mut bp_log_tpl: Option<String> = None;
            let mut bp_stop_after = 0u64;
            let mut bp_hits = 0u64;
            for (slot, record) in self.breakpoints.iter_mut() {
                if record.enabled
                    && (record.address == event_rip || record.address + 1 == event_rip)
                {
                    record.hits += 1;
                    hit_slot = Some(*slot);
                    bp_cond_expr = record.condition.clone();
                    bp_log_tpl = record.log.clone();
                    bp_stop_after = record.stop_after;
                    bp_hits = record.hits;
                }
            }
            let state = self.live_state(event_thread).ok();
            let log_message = bp_log_tpl
                .as_deref()
                .map(|tpl| self.interpolate_log(tpl, pid, event_thread));

            let mut bp_condition_value = Value::Null;
            let mut bp_condition_met = true;
            if let Some(bp_expr) = bp_cond_expr.as_deref() {
                match self.evaluate(bp_expr, Some(pid), Some(event_thread)) {
                    Ok(value) => {
                        bp_condition_value = value["value"].clone();
                        bp_condition_met = parse_hex(&value["value"]).unwrap_or(0) != 0;
                    }
                    Err(error) => {
                        return Err(error.context(
                            "Breakpoint condition evaluation failed; stopped without resuming",
                        ));
                    }
                }
            }

            let mut condition_value = Value::Null;
            let mut condition_met = true;
            if let Some(text) = condition {
                match self.evaluate(text, Some(pid), Some(event_thread)) {
                    Ok(value) => {
                        condition_value = value["value"].clone();
                        condition_met = parse_hex(&value["value"]).unwrap_or(0) != 0;
                    }
                    Err(error) => {
                        return Err(error.context(
                            "Condition evaluation failed; stopped without resuming",
                        ));
                    }
                }
            }

            let stop_after_hit = bp_stop_after > 0 && bp_hits >= bp_stop_after && bp_condition_met;
            let target_hit = hit_slot.is_some_and(|slot| Some(slot) == target_slot);
            let mut stop_obj = json!({
                "event": event,
                "hit_breakpoint": hit_slot,
                "target_hit": target_hit,
                "condition": condition_value,
                "condition_met": condition_met,
                "breakpoint_condition": bp_condition_value,
                "breakpoint_condition_met": bp_condition_met,
                "stop_after_hit": stop_after_hit,
                "state": state,
            });
            if let Some(msg) = log_message {
                stop_obj["log_message"] = json!(msg);
            }
            stops.push(stop_obj);

            let bp_cond_unsatisfied = bp_cond_expr.is_some() && !bp_condition_met && !target_hit;
            let bp_hits_pending = bp_stop_after > 1 && bp_hits < bp_stop_after && !target_hit;
            let run_cond_unsatisfied =
                condition.is_some() && !condition_met && !stop_after_hit && !target_hit;
            let keep_running = (bp_cond_unsatisfied || bp_hits_pending || run_cond_unsatisfied)
                && stops.len() < max_stops as usize;
            if !keep_running {
                break;
            }
            self.control("resume", 0)?;
        }
        Ok(json!({
            "stop_count":stops.len(),"stops":stops,
            "target":target.map(|address| format!("{address:#x}")),
            "condition":condition,
            "breakpoints":self.breakpoint_list(),
            "note":"All-stop model: resume continues every thread. Event registers can be stale; each stop carries re-read live registers in state.",
        }))
    }

    /// Call-stack unwind for one thread:
    /// 1. DWARF `.eh_frame` CFI unwind (handles `-fomit-frame-pointer` PS4 Clang code)
    /// 2. Frame-pointer (`rbp`) chain
    /// 3. Bounded stack scan for return addresses inside executable mappings.
    pub fn stack_trace(&mut self, thread_id: u32, max_frames: usize) -> Result<Value> {
        ensure!((1..=64).contains(&max_frames), "max_frames must be 1-64");
        let pid = self.attached()?;
        Self::pid(thread_id)?;
        let raw = self.get_registers_raw(thread_id)?;
        let file = RegisterFile(&raw);
        let rip = file.get("rip").unwrap_or(0);
        let rbp = file.get("rbp").unwrap_or(0);
        let rsp = file.get("rsp").unwrap_or(0);
        let maps = self.maps(pid)?;
        let modules = self.module_bases(pid)?;
        let entries = maps.as_array().context("Expected maps")?;
        let executable: Vec<(u64, u64)> = entries
            .iter()
            .filter(|entry| entry["protection"].as_u64().unwrap_or(0) & 4 != 0)
            .map(|entry| {
                (
                    entry["start"].as_u64().unwrap_or(0),
                    entry["end"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        let in_executable =
            |address: u64| executable.iter().any(|(start, end)| *start <= address && address < *end);
        let stack_entry = entries
            .iter()
            .find(|entry| {
                let protection = entry["protection"].as_u64().unwrap_or(0);
                let (start, end) = (
                    entry["start"].as_u64().unwrap_or(0),
                    entry["end"].as_u64().unwrap_or(0),
                );
                protection & 1 != 0 && protection & 4 == 0 && start <= rsp && rsp < end
            })
            .cloned();
        let stack_end = stack_entry
            .as_ref()
            .and_then(|entry| entry["end"].as_u64())
            .unwrap_or(rsp);
        let mut frames = vec![json!({"depth":0,"address":format!("{rip:#x}"),
            "symbol":Self::annotate(rip, &modules),"via":"current_rip"})];

        // Phase 1: DWARF .eh_frame CFI unwind
        let mut dwarf_regs = Self::dwarf_regs_from_raw(&raw);
        let mut cfi_pc = rip;
        let mut cfi_cfas = std::collections::HashSet::new();
        let mut fp_seed_rbp = rbp;
        let mut fp_seed_rsp = rsp;
        while frames.len() < max_frames {
            let Some((ret_addr, cfa, next_regs)) =
                self.unwind_cfi_once(pid, cfi_pc, &dwarf_regs, &modules)
            else {
                break;
            };
            if !in_executable(ret_addr) || !cfi_cfas.insert(cfa) {
                break;
            }
            frames.push(json!({
                "depth": frames.len(),
                "address": format!("{ret_addr:#x}"),
                "symbol": Self::annotate(ret_addr, &modules),
                "via": "eh_frame_cfi",
                "cfa": format!("{cfa:#x}"),
            }));
            dwarf_regs = next_regs;
            fp_seed_rsp = cfa;
            if let Some(restored_rbp) = dwarf_regs[ehframe::DWARF_RBP as usize] {
                fp_seed_rbp = restored_rbp;
            }
            cfi_pc = ret_addr.saturating_sub(1);
        }

        // Phase 2: Frame-pointer chain fallback
        let mut chain_complete = true;
        let mut current = fp_seed_rbp;
        let mut visited = std::collections::HashSet::new();
        while frames.len() < max_frames
            && current >= fp_seed_rsp
            && current < stack_end
            && current.is_multiple_of(8)
            && visited.insert(current)
        {
            let Ok(pair) = self.read_memory(pid, current, 16, false) else {
                chain_complete = false;
                break;
            };
            let next = qword(&pair, 0);
            let return_address = qword(&pair, 8);
            if !in_executable(return_address) {
                chain_complete = false;
                break;
            }
            if !frames
                .iter()
                .any(|f| parse_hex(&f["address"]) == Some(return_address))
            {
                frames.push(json!({"depth":frames.len(),"address":format!("{return_address:#x}"),
                    "symbol":Self::annotate(return_address, &modules),"via":"frame_pointer",
                    "frame_pointer":format!("{current:#x}")}));
            }
            if next <= current || next >= stack_end {
                chain_complete = false;
                break;
            }
            current = next;
        }

        // Phase 3: Bounded stack scan fallback
        let scan_start = fp_seed_rsp.max(rsp);
        let scan_end = stack_end.min(scan_start.saturating_add(16384));
        let mut scanned = 0u64;
        if scan_end > scan_start {
            for (chunk_address, length) in
                Self::page_chunks(scan_start, (scan_end - scan_start) as usize)
            {
                if frames.len() >= max_frames {
                    break;
                }
                let Ok(content) = self.read_memory(pid, chunk_address, length, false) else {
                    break;
                };
                scanned += length as u64;
                for offset in (0..content.len().saturating_sub(7)).step_by(8) {
                    if frames.len() >= max_frames {
                        break;
                    }
                    let candidate = qword(&content, offset);
                    if in_executable(candidate)
                        && !frames
                            .iter()
                            .any(|frame| parse_hex(&frame["address"]) == Some(candidate))
                    {
                        frames.push(json!({"depth":frames.len(),"address":format!("{candidate:#x}"),
                            "symbol":Self::annotate(candidate, &modules),"via":"stack_scan",
                            "stack_address":format!("{:#x}", chunk_address + offset as u64)}));
                    }
                }
            }
        }
        Ok(json!({"thread_id":thread_id,"rip":format!("{rip:#x}"),"rsp":format!("{rsp:#x}"),
            "rbp":format!("{rbp:#x}"),"frames":frames,"frame_pointer_complete":chain_complete,
            "stack_scanned_bytes":scanned,
            "note":"Unwound via DWARF .eh_frame CFI when available, falling back to frame-pointer chain plus bounded stack scan"}))
    }
}
