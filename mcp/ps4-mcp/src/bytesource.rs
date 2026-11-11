//! Shared byte-source abstraction for the engine/metadata recovery tools.
//!
//! A [`Source`] is either an offline artifact (read as raw file bytes, or mapped
//! by its ELF64 `PT_LOAD` segments with dynamic relocations applied, or a raw
//! memory dump placed at a caller-supplied base) or live process memory read
//! through the read-only ps4debug APIs. Live reads are fetched in aligned blocks,
//! cached, and charged against a byte budget (never more than the profile's
//! `transfer_bytes`); per-request reads are bounded by `memory_bytes`.
use crate::{Result, debugger::Debugger, workbench::Workbench};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Hard cap for offline artifacts loaded by these tools.
pub const ARTIFACT_MAX: usize = 512 << 20;
/// Live fetch granularity (cache block size).
const BLOCK: u64 = 0x4000;
/// Cap on relocations applied when mapping an ELF artifact.
const MAX_RELOCATIONS: usize = 8_000_000;

pub const PROT_R: u8 = 1;
pub const PROT_W: u8 = 2;
pub const PROT_X: u8 = 4;

#[derive(Clone, Debug)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub prot: u8,
    pub name: String,
}

impl Region {
    pub fn contains(&self, va: u64) -> bool {
        self.start <= va && va < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Artifact bytes addressed by file offset (YARA / crypto semantics).
    File,
    /// Artifact mapped like a loaded image (ELF segments, or raw dump at `base`).
    Mapped,
}

/// Where the bytes come from, parsed from the common tool arguments.
#[derive(Clone, Debug, Default)]
pub struct TargetSpec {
    pub artifact: Option<String>,
    pub base: u64,
    pub pid: Option<u32>,
    pub module: Option<String>,
    pub address: Option<u64>,
    pub length: Option<u64>,
    pub max_bytes: Option<usize>,
}

impl TargetSpec {
    /// Parse `artifact`/`base` or `pid`/`module`/`address`/`length`/`max_bytes`
    /// using the given key names for the artifact and module fields.
    pub fn from_args(args: &Value, artifact_key: &str, module_key: &str) -> Result<Self> {
        let opt_addr = |key: &str| -> Result<Option<u64>> {
            args.get(key)
                .filter(|v| !v.is_null())
                .map(crate::tools::address)
                .transpose()
        };
        let spec = Self {
            artifact: args[artifact_key].as_str().map(str::to_owned),
            base: opt_addr("base")?.unwrap_or(0),
            pid: args["pid"].as_u64().map(|pid| pid as u32),
            module: args[module_key].as_str().map(str::to_owned),
            address: opt_addr("address")?,
            length: args["length"].as_u64(),
            max_bytes: args["max_bytes"].as_u64().map(|v| v as usize),
        };
        Ok(spec)
    }

    pub fn is_specified(&self) -> bool {
        self.artifact.is_some() || self.pid.is_some()
    }
}

pub struct Source<'a> {
    /// `artifact-file`, `artifact-elf`, `artifact-raw` or `live`.
    pub kind: &'static str,
    pub label: String,
    pub image_base: u64,
    /// Every readable region (for live: all process maps).
    pub regions: Vec<Region>,
    /// Ranges selected for linear scans.
    pub selection: Vec<(u64, u64)>,
    /// Import relocation slots (static ELF): slot VA -> symbol name.
    pub imports: HashMap<u64, String>,
    /// ELF file-offset -> VA mapping for `artifact-file` sources: (offset, filesz, vaddr).
    pub file_segments: Vec<(u64, u64, u64)>,
    pub file_size: u64,
    pub notes: Vec<String>,
    data: Vec<Vec<u8>>,
    live: Option<(&'a mut Debugger, u32)>,
    cache: HashMap<u64, Option<Vec<u8>>>,
    chunk: usize,
    pub budget: usize,
    pub fetched: usize,
    pub exhausted: bool,
    pub read_failures: usize,
}

impl<'a> Source<'a> {
    pub fn open(workbench: &'a mut Workbench, spec: &TargetSpec, mode: Mode) -> Result<Self> {
        let transfer = workbench.profile.limit("transfer_bytes").max(1);
        let budget = spec.max_bytes.unwrap_or(transfer).clamp(1, transfer);
        let chunk = workbench.profile.limit("memory_bytes").clamp(0x1000, 1 << 20);
        if let Some(artifact) = &spec.artifact {
            ensure!(spec.pid.is_none(), "Give either an artifact or a pid, not both");
            let bytes = workbench.read_artifact(artifact, ARTIFACT_MAX)?;
            let mut source = match mode {
                Mode::File => Self::from_file(artifact, bytes),
                Mode::Mapped if bytes.starts_with(b"\x7fELF") => Self::from_elf(artifact, bytes)?,
                Mode::Mapped if bytes.starts_with(b"{") && serde_json::from_slice::<Value>(&bytes).ok().is_some_and(|v| v["format"] == "ps4wb-memory-image-v1") => Self::from_sparse(workbench, artifact, &bytes)?,
                Mode::Mapped => Self::from_raw(artifact, bytes, spec.base),
            };
            source.budget = budget;
            source.chunk = chunk;
            return Ok(source);
        }
        let pid = spec.pid.context("Give an artifact or a pid")?;
        let maps = workbench.debugger.maps(pid)?;
        let mut regions = Vec::new();
        for entry in maps.as_array().context("Expected maps array")? {
            let (start, end) = (entry["start"].as_u64().unwrap_or(0), entry["end"].as_u64().unwrap_or(0));
            let prot = entry["protection"].as_u64().unwrap_or(0) as u8;
            if end > start && prot != 0 {
                regions.push(Region { start, end, prot, name: entry["name"].as_str().unwrap_or("").to_owned() });
            }
        }
        regions.sort_by_key(|region| region.start);
        let mut image_base = 0;
        let mut selection: Vec<(u64, u64)>;
        let mut label = format!("pid {pid}");
        if let Some(module) = &spec.module {
            let pick = |predicate: &dyn Fn(&str) -> bool| -> Vec<(u64, u64)> {
                regions.iter().filter(|r| predicate(&r.name)).map(|r| (r.start, r.end)).collect()
            };
            selection = pick(&|name| name == module);
            if selection.is_empty() {
                selection = pick(&|name| name.eq_ignore_ascii_case(module));
            }
            if selection.is_empty() {
                let lower = module.to_ascii_lowercase();
                selection = pick(&|name| !name.is_empty() && name.to_ascii_lowercase().contains(&lower));
            }
            if selection.is_empty() {
                let mut names: Vec<&str> = regions.iter().map(|r| r.name.as_str()).filter(|n| !n.is_empty()).collect();
                names.sort_unstable();
                names.dedup();
                names.truncate(64);
                bail!("No map named like {module:?} in pid {pid}; known names: {names:?}");
            }
            image_base = selection.iter().map(|range| range.0).min().unwrap_or(0);
            label = format!("pid {pid} module {module}");
        } else {
            selection = regions.iter().map(|r| (r.start, r.end)).collect();
        }
        if let Some(address) = spec.address {
            let length = spec.length.context("address requires length")?;
            ensure!(length > 0, "length must be positive");
            let end = address.checked_add(length).context("Range overflows")?;
            selection = selection
                .into_iter()
                .filter_map(|(s, e)| {
                    let (s, e) = (s.max(address), e.min(end));
                    (s < e).then_some((s, e))
                })
                .collect();
            ensure!(!selection.is_empty(), "Range {address:#x}+{length:#x} does not intersect any selected map");
            if spec.module.is_none() {
                image_base = address;
            }
            label = format!("{label} range {address:#x}+{length:#x}");
        } else if spec.length.is_some() {
            bail!("length requires address");
        }
        Ok(Self {
            kind: "live",
            label,
            image_base,
            regions,
            selection,
            imports: HashMap::new(),
            file_segments: Vec::new(),
            file_size: 0,
            notes: Vec::new(),
            data: Vec::new(),
            live: Some((&mut workbench.debugger, pid)),
            cache: HashMap::new(),
            chunk,
            budget,
            fetched: 0,
            exhausted: false,
            read_failures: 0,
        })
    }

    fn empty(kind: &'static str, label: &str) -> Self {
        Self {
            kind,
            label: label.to_owned(),
            image_base: 0,
            regions: Vec::new(),
            selection: Vec::new(),
            imports: HashMap::new(),
            file_segments: Vec::new(),
            file_size: 0,
            notes: Vec::new(),
            data: Vec::new(),
            live: None,
            cache: HashMap::new(),
            chunk: 1 << 20,
            budget: usize::MAX,
            fetched: 0,
            exhausted: false,
            read_failures: 0,
        }
    }

    /// Replay discontiguous captured module/heap regions without a console.
    /// Missing pages remain holes, and every referenced capture is hash-checked.
    fn from_sparse(workbench: &Workbench, label: &str, bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 8 << 20, "Memory image manifest exceeds 8 MiB");
        let document: Value = serde_json::from_slice(bytes)?;
        let mut source = Self::empty("artifact-sparse", label);
        source.image_base = crate::tools::address(&document["image_base"])?;
        let regions = document["regions"].as_array().context("Missing memory image regions")?;
        ensure!(regions.len() <= 16384, "Too many memory image regions");
        let mut pairs = Vec::new(); let mut total = 0usize;
        for item in regions {
            let path = item["artifact"]["path"].as_str().context("Missing region artifact")?;
            let data = workbench.read_artifact(path, ARTIFACT_MAX)?;
            total = total.checked_add(data.len()).context("Memory image size overflow")?;
            ensure!(total <= ARTIFACT_MAX && !data.is_empty(), "Memory image exceeds budget or contains an empty region");
            ensure!(crate::config::sha256_hex(&data) == item["artifact"]["sha256"], "Memory image region changed: {path}");
            let start = crate::tools::address(&item["address"])?;
            let end = start.checked_add(data.len() as u64).context("Region address overflow")?;
            let protection = item["protection"].as_u64().context("Missing region protection")?;
            ensure!(protection & 1 != 0 && protection <= 7, "Invalid region protection");
            let region = Region {start,end,prot:protection as u8,name:item["name"].as_str().unwrap_or("").to_owned()};
            pairs.push((region,data,item["selected"].as_bool().unwrap_or(true)));
        }
        pairs.sort_by_key(|p| p.0.start);
        let mut previous = 0;
        for (region,data,selected) in pairs {
            ensure!(region.start >= previous, "Overlapping memory image captures");previous=region.end;
            if selected { source.selection.push((region.start,region.end)); }
            source.regions.push(region);source.data.push(data);
        }
        source.file_size=total as u64;
        if document["missing"].as_array().is_some_and(|r| !r.is_empty()) { source.notes.push("Capture has missing regions; absent bytes are never synthesized".into()); }
        Ok(source)
    }

    /// In-memory bytes addressed by file offset.
    pub fn from_file(label: &str, bytes: Vec<u8>) -> Self {
        let mut source = Self::empty("artifact-file", label);
        source.file_size = bytes.len() as u64;
        if bytes.starts_with(b"\x7fELF")
            && let Ok(elf) = Elf::parse(&bytes)
        {
            source.file_segments = elf.loads.iter().map(|l| (l.offset, l.filesz, l.vaddr)).collect();
        }
        source.regions.push(Region { start: 0, end: bytes.len() as u64, prot: PROT_R, name: label.to_owned() });
        source.selection.push((0, bytes.len() as u64));
        source.data.push(bytes);
        source
    }

    /// A raw memory dump placed at `base` (treated as rwx).
    pub fn from_raw(label: &str, bytes: Vec<u8>, base: u64) -> Self {
        let mut source = Self::empty("artifact-raw", label);
        source.file_size = bytes.len() as u64;
        source.image_base = base;
        let end = base.saturating_add(bytes.len() as u64);
        source.regions.push(Region { start: base, end, prot: PROT_R | PROT_W | PROT_X, name: label.to_owned() });
        source.selection.push((base, end));
        source.data.push(bytes);
        source
    }

    /// An ELF64 image mapped by its PT_LOAD segments, with RELATIVE and
    /// defined-symbol relocations applied (link-time VAs, so B = 0).
    pub fn from_elf(label: &str, bytes: Vec<u8>) -> Result<Self> {
        let elf = Elf::parse(&bytes)?;
        let mut source = Self::empty("artifact-elf", label);
        source.file_size = bytes.len() as u64;
        source.image_base = elf.loads.iter().map(|l| l.vaddr).min().unwrap_or(0);
        let mut mapped_total = 0usize;
        for load in &elf.loads {
            let mem = load.memsz.max(load.filesz).min(ARTIFACT_MAX as u64) as usize;
            mapped_total += mem;
            ensure!(mapped_total <= ARTIFACT_MAX, "ELF segments map more than {ARTIFACT_MAX} bytes");
            ensure!(load.vaddr.checked_add(mem as u64).is_some(), "ELF segment address overflows");
            let mut content = vec![0u8; mem];
            let start = load.offset as usize;
            let end = load.offset.saturating_add(load.filesz).min(bytes.len() as u64) as usize;
            if start < end {
                let take = (end - start).min(mem);
                content[..take].copy_from_slice(&bytes[start..start + take]);
            }
            let prot = (if load.flags & 4 != 0 { PROT_R } else { 0 })
                | (if load.flags & 2 != 0 { PROT_W } else { 0 })
                | (if load.flags & 1 != 0 { PROT_X } else { 0 });
            source.regions.push(Region {
                start: load.vaddr,
                end: load.vaddr + content.len() as u64,
                prot: prot | PROT_R,
                name: format!("{label}:{}", segment_label(prot)),
            });
            source.selection.push((load.vaddr, load.vaddr + content.len() as u64));
            source.data.push(content);
        }
        let (applied, imports, notes) = elf.apply_relocations(&bytes, &mut source)?;
        source.imports = imports;
        source.notes.extend(notes);
        source.notes.push(format!("{applied} relocations applied (link-time addresses, load bias 0)"));
        Ok(source)
    }

    pub fn region_of(&self, va: u64) -> Option<&Region> {
        self.regions.iter().find(|region| region.contains(va))
    }

    pub fn is_exec(&self, va: u64) -> bool {
        self.region_of(va).is_some_and(|r| r.prot & PROT_X != 0)
    }

    pub fn is_mapped(&self, va: u64) -> bool {
        self.region_of(va).is_some()
    }

    pub fn is_live(&self) -> bool {
        self.live.is_some()
    }

    /// Read `len` bytes at `va`; `None` if any byte is unmapped, unreadable or
    /// the live budget is exhausted.
    pub fn read(&mut self, va: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        if len > (64 << 20) {
            return None;
        }
        let end = va.checked_add(len as u64)?;
        let mut out = Vec::with_capacity(len);
        let mut cursor = va;
        while cursor < end {
            let index = self.regions.iter().position(|r| r.contains(cursor))?;
            let region_end = self.regions[index].end;
            let piece_end = end.min(region_end);
            if self.live.is_none() {
                let data = &self.data[index];
                let offset = (cursor - self.regions[index].start) as usize;
                let stop = (piece_end - self.regions[index].start) as usize;
                out.extend_from_slice(data.get(offset..stop)?);
                cursor = piece_end;
                continue;
            }
            let region_start = self.regions[index].start;
            while cursor < piece_end {
                let block = cursor & !(BLOCK - 1);
                let block_start = block.max(region_start);
                let from = (cursor - block_start) as usize;
                let to = (piece_end.min(block + BLOCK) - block_start) as usize;
                let content = self.block(block_start, index)?;
                out.extend_from_slice(content.get(from..to)?);
                cursor = block_start + to as u64;
            }
        }
        Some(out)
    }

    /// Fetch (or reuse) the cached block starting at `start` (a BLOCK-aligned
    /// address clipped to the start of `region`).
    fn block(&mut self, start: u64, region: usize) -> Option<&Vec<u8>> {
        let block = start;
        if !self.cache.contains_key(&block) {
            let end = ((start & !(BLOCK - 1)) + BLOCK).min(self.regions[region].end);
            let length = (end - start) as usize;
            if self.fetched + length > self.budget {
                self.exhausted = true;
                return None;
            }
            self.fetched += length;
            let (debugger, pid) = self.live.as_mut()?;
            let content = match debugger.read_memory(*pid, start, length, false) {
                Ok(bytes) if bytes.len() == length => Some(bytes),
                _ => {
                    self.read_failures += 1;
                    None
                }
            };
            self.cache.insert(block, content);
        }
        self.cache.get(&block)?.as_ref()
    }

    /// Small read for heuristic probing: static sources and cached live blocks
    /// are served directly; otherwise exactly `len` live bytes are fetched
    /// (charged to the budget, not cached) so scattered probes stay cheap.
    pub fn probe(&mut self, va: u64, len: usize) -> Option<Vec<u8>> {
        if self.live.is_none() || len > 4096 {
            return self.read(va, len);
        }
        let end = va.checked_add(len as u64)?;
        let region = self.regions.iter().position(|r| r.contains(va) && end <= r.end)?;
        let block_start = (va & !(BLOCK - 1)).max(self.regions[region].start);
        if end <= (va & !(BLOCK - 1)) + BLOCK
            && let Some(Some(content)) = self.cache.get(&block_start)
        {
            let from = (va - block_start) as usize;
            return content.get(from..from + len).map(<[u8]>::to_vec);
        }
        if self.fetched + len > self.budget {
            self.exhausted = true;
            return None;
        }
        self.fetched += len;
        let (debugger, pid) = self.live.as_mut()?;
        match debugger.read_memory(*pid, va, len, false) {
            Ok(bytes) if bytes.len() == len => Some(bytes),
            _ => {
                self.read_failures += 1;
                None
            }
        }
    }

    pub fn probe_u64(&mut self, va: u64) -> Option<u64> {
        self.probe(va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u64(&mut self, va: u64) -> Option<u64> {
        self.read(va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u32(&mut self, va: u64) -> Option<u32> {
        self.read(va, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u16(&mut self, va: u64) -> Option<u16> {
        self.read(va, 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    }

    /// NUL-terminated byte string of at most `max` bytes (without the NUL).
    pub fn cstr(&mut self, va: u64, max: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor = va;
        while out.len() < max {
            let step = (64 - (cursor % 64) as usize).min(max - out.len() + 1);
            let bytes = self.read(cursor, step).or_else(|| self.read(cursor, 1))?;
            for byte in &bytes {
                if *byte == 0 {
                    return Some(out);
                }
                out.push(*byte);
                if out.len() >= max {
                    return None;
                }
            }
            cursor += bytes.len() as u64;
        }
        None
    }

    /// Linear scan of `ranges` (default: the selection). `visit(va, bytes)`
    /// receives contiguous chunks; consecutive live chunks overlap by `overlap`
    /// bytes. Return `false` from `visit` to stop.
    pub fn scan(
        &mut self,
        ranges: Option<&[(u64, u64)]>,
        overlap: usize,
        mut visit: impl FnMut(u64, &[u8]) -> bool,
    ) -> Result<()> {
        let ranges: Vec<(u64, u64)> = ranges.map(<[_]>::to_vec).unwrap_or_else(|| self.selection.clone());
        for (start, end) in ranges {
            if self.live.is_none() {
                for (index, region) in self.regions.iter().enumerate() {
                    let (s, e) = (start.max(region.start), end.min(region.end));
                    if s >= e {
                        continue;
                    }
                    let data = &self.data[index];
                    let from = (s - region.start) as usize;
                    let to = ((e - region.start) as usize).min(data.len());
                    if from < to && !visit(s, &data[from..to]) {
                        return Ok(());
                    }
                }
                continue;
            }
            let mut carry: Vec<u8> = Vec::new();
            let mut cursor = start;
            while cursor < end {
                let length = ((end - cursor) as usize).min(self.chunk);
                if self.fetched + length > self.budget {
                    self.exhausted = true;
                    return Ok(());
                }
                self.fetched += length;
                let (debugger, pid) = self.live.as_mut().context("live source")?;
                match debugger.read_memory(*pid, cursor, length, false) {
                    Ok(bytes) if bytes.len() == length => {
                        let chunk_va = cursor - carry.len() as u64;
                        carry.extend_from_slice(&bytes);
                        if !visit(chunk_va, &carry) {
                            return Ok(());
                        }
                        let keep = overlap.min(carry.len());
                        carry.drain(..carry.len() - keep);
                    }
                    _ => {
                        self.read_failures += 1;
                        carry.clear();
                    }
                }
                cursor += length as u64;
            }
        }
        Ok(())
    }

    /// Aligned 8-byte slots in `ranges` whose value is in `targets`, as
    /// sorted `(slot, value)` pairs (at most `cap`).
    pub fn find_pointers(
        &mut self,
        ranges: &[(u64, u64)],
        targets: &std::collections::HashSet<u64>,
        cap: usize,
    ) -> Result<Vec<(u64, u64)>> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        if targets.is_empty() {
            return Ok(out);
        }
        self.scan(Some(ranges), 8, |va, chunk| {
            let mut offset = ((8 - (va % 8)) % 8) as usize;
            while offset + 8 <= chunk.len() {
                let value = u64::from_le_bytes(chunk[offset..offset + 8].try_into().unwrap());
                if targets.contains(&value) && seen.insert(va + offset as u64) {
                    out.push((va + offset as u64, value));
                    if out.len() >= cap {
                        return false;
                    }
                }
                offset += 8;
            }
            true
        })?;
        out.sort_unstable();
        Ok(out)
    }

    /// Ranges of the selection whose protection matches `want` (all bits) and
    /// excludes `deny` (any bit).
    pub fn ranges_with(&self, want: u8, deny: u8) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for &(start, end) in &self.selection {
            for region in &self.regions {
                if region.prot & want == want && region.prot & deny == 0 {
                    let (s, e) = (start.max(region.start), end.min(region.end));
                    if s < e {
                        out.push((s, e));
                    }
                }
            }
        }
        out
    }

    /// VA of a file offset (artifact-file sources with ELF segments).
    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64> {
        self.file_segments
            .iter()
            .find(|(off, size, _)| *off <= offset && offset < off + size)
            .map(|(off, _, vaddr)| vaddr + (offset - off))
    }

    /// Describe a location: file offset (+ ELF VA) or VA (+ module/offset, RVA).
    pub fn describe(&self, va: u64) -> Value {
        match self.kind {
            "artifact-file" => {
                let mut out = json!({"offset": hex(va)});
                if let Some(mapped) = self.file_offset_to_va(va) {
                    out["va"] = json!(hex(mapped));
                }
                out
            }
            _ => {
                let mut out = json!({"address": hex(va)});
                if va >= self.image_base && self.kind != "live" {
                    out["rva"] = json!(hex(va - self.image_base));
                }
                if let Some(region) = self.region_of(va)
                    && self.kind == "live"
                    && !region.name.is_empty()
                {
                    let base = self
                        .regions
                        .iter()
                        .filter(|r| r.name == region.name)
                        .map(|r| r.start)
                        .min()
                        .unwrap_or(region.start);
                    out["module"] = json!(region.name);
                    out["module_offset"] = json!(hex(va - base));
                }
                out
            }
        }
    }

    pub fn summary(&self) -> Value {
        json!({
            "kind": self.kind, "label": self.label, "image_base": hex(self.image_base),
            "regions": self.regions.len(), "selected_ranges": self.selection.len(),
            "bytes_fetched": self.fetched, "budget": if self.live.is_some() { json!(self.budget) } else { Value::Null },
            "budget_exhausted": self.exhausted, "read_failures": self.read_failures,
            "notes": self.notes,
        })
    }
}

pub fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn segment_label(prot: u8) -> String {
    format!(
        "{}{}{}",
        if prot & PROT_R != 0 { 'r' } else { '-' },
        if prot & PROT_W != 0 { 'w' } else { '-' },
        if prot & PROT_X != 0 { 'x' } else { '-' }
    )
}

// ---- minimal ELF64 parser for mapping + relocations --------------------------

#[derive(Clone, Debug)]
struct Load {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

struct Elf {
    loads: Vec<Load>,
    dynamic: Option<(u64, u64)>,
    /// PT_SCE_DYNLIBDATA (0x61000000) file span, holds Orbis dynamic tables.
    dynlibdata: Option<(u64, u64)>,
}

fn rd<const N: usize>(data: &[u8], at: u64) -> Option<[u8; N]> {
    let at = usize::try_from(at).ok()?;
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}
fn rd64(data: &[u8], at: u64) -> Option<u64> {
    rd::<8>(data, at).map(u64::from_le_bytes)
}
fn rd32(data: &[u8], at: u64) -> Option<u32> {
    rd::<4>(data, at).map(u32::from_le_bytes)
}
fn rd16(data: &[u8], at: u64) -> Option<u16> {
    rd::<2>(data, at).map(u16::from_le_bytes)
}

impl Elf {
    fn parse(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 64 && data.starts_with(b"\x7fELF"), "Not an ELF file");
        ensure!(data[4] == 2 && data[5] == 1, "Only little-endian ELF64 is supported");
        let phoff = rd64(data, 32).context("phoff")?;
        let phentsize = rd16(data, 54).context("phentsize")? as u64;
        let phnum = rd16(data, 56).context("phnum")? as u64;
        ensure!(phentsize >= 56 && phnum <= 256, "Unsupported program header table");
        let mut elf = Self { loads: Vec::new(), dynamic: None, dynlibdata: None };
        for index in 0..phnum {
            let base = phoff + index * phentsize;
            let p_type = rd32(data, base).context("Program header past end of file")?;
            let flags = rd32(data, base + 4).context("phdr")?;
            let offset = rd64(data, base + 8).context("phdr")?;
            let vaddr = rd64(data, base + 16).context("phdr")?;
            let filesz = rd64(data, base + 32).context("phdr")?;
            let memsz = rd64(data, base + 40).context("phdr")?;
            match p_type {
                // PT_LOAD, and the Orbis PT_SCE_RELRO (0x61000010) which is loaded too.
                1 | 0x6100_0010 if memsz > 0 => elf.loads.push(Load { vaddr, offset, filesz, memsz, flags }),
                2 => elf.dynamic = Some((offset, filesz)),
                0x6100_0000 => elf.dynlibdata = Some((offset, filesz)),
                _ => {}
            }
        }
        ensure!(!elf.loads.is_empty(), "ELF has no loadable segments");
        Ok(elf)
    }

    fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        self.loads
            .iter()
            .find(|l| l.vaddr <= vaddr && vaddr < l.vaddr + l.filesz)
            .map(|l| l.offset + (vaddr - l.vaddr))
    }

    /// Apply `R_X86_64_RELATIVE` (8) and `R_X86_64_64`/`GLOB_DAT`/`JUMP_SLOT`
    /// (1/6/7) against defined symbols; record undefined-symbol slots as imports.
    /// Tables come from standard DT_RELA/DT_JMPREL (VAs) or the Orbis
    /// DT_SCE_RELA (0x6100002F) / DT_SCE_JMPREL (0x61000029) / DT_SCE_SYMTAB
    /// (0x61000039) / DT_SCE_STRTAB (0x61000035) tags, whose values are offsets
    /// into PT_SCE_DYNLIBDATA (tag values per the OpenOrbis toolchain `elf.h`
    /// and shadPS4 `core/loader/elf.h`).
    #[allow(clippy::type_complexity)]
    fn apply_relocations(
        &self,
        data: &[u8],
        source: &mut Source,
    ) -> Result<(usize, HashMap<u64, String>, Vec<String>)> {
        let mut notes = Vec::new();
        let mut imports = HashMap::new();
        let Some((dyn_off, dyn_size)) = self.dynamic else {
            notes.push("No PT_DYNAMIC; pointers are used as stored in the file".to_owned());
            return Ok((0, imports, notes));
        };
        let mut tags: HashMap<u64, u64> = HashMap::new();
        for index in 0..(dyn_size / 16).min(4096) {
            let (Some(tag), Some(value)) = (rd64(data, dyn_off + index * 16), rd64(data, dyn_off + index * 16 + 8))
            else {
                break;
            };
            if tag == 0 {
                break;
            }
            tags.entry(tag).or_insert(value);
        }
        let sce = |tag: u64| -> Option<u64> {
            let (base, size) = self.dynlibdata?;
            let value = *tags.get(&tag)?;
            (value <= size).then_some(base + value)
        };
        let std_va = |tag: u64| tags.get(&tag).and_then(|va| self.vaddr_to_offset(*va));
        let symtab = sce(0x6100_0039).or_else(|| std_va(6));
        let strtab = sce(0x6100_0035).or_else(|| std_va(5));
        let strsz = tags.get(&0x6100_0037).or_else(|| tags.get(&10)).copied().unwrap_or(0);
        let mut tables = Vec::new();
        if let (Some(off), Some(size)) = (sce(0x6100_002F), tags.get(&0x6100_0031)) {
            tables.push((off, *size));
        } else if let (Some(off), Some(size)) = (std_va(7), tags.get(&8)) {
            tables.push((off, *size));
        }
        if let (Some(off), Some(size)) = (sce(0x6100_0029), tags.get(&0x6100_002D)) {
            tables.push((off, *size));
        } else if let (Some(off), Some(size)) = (std_va(23), tags.get(&2)) {
            tables.push((off, *size));
        }
        let symbol = |index: u64| -> Option<(String, bool, u64)> {
            let at = symtab? + index * 24;
            let name_off = rd32(data, at)? as u64;
            let shndx = rd16(data, at + 6)?;
            let value = rd64(data, at + 8)?;
            let mut name = String::new();
            if let Some(str_base) = strtab
                && (strsz == 0 || name_off < strsz)
            {
                let start = (str_base + name_off) as usize;
                if let Some(rest) = data.get(start..) {
                    let end = rest.iter().take(1024).position(|b| *b == 0).unwrap_or(0);
                    name = String::from_utf8_lossy(&rest[..end]).into_owned();
                }
            }
            Some((name, shndx != 0, value))
        };
        let mut applied = 0usize;
        let mut total = 0usize;
        for (offset, size) in tables {
            for index in 0..size / 24 {
                total += 1;
                if total > MAX_RELOCATIONS {
                    notes.push("Relocation cap reached; remaining relocations ignored".to_owned());
                    return Ok((applied, imports, notes));
                }
                let at = offset + index * 24;
                let (Some(r_offset), Some(r_info), Some(addend)) = (rd64(data, at), rd64(data, at + 8), rd64(data, at + 16))
                else {
                    break;
                };
                let (kind, sym) = (r_info & 0xffff_ffff, r_info >> 32);
                let value = match kind {
                    8 => Some(addend),
                    1 | 6 | 7 => match symbol(sym) {
                        Some((_, true, value)) => Some(if kind == 1 { value.wrapping_add(addend) } else { value }),
                        Some((name, false, _)) => {
                            imports.insert(r_offset, name);
                            None
                        }
                        None => None,
                    },
                    _ => None,
                };
                if let Some(value) = value
                    && source.write_static(r_offset, &value.to_le_bytes())
                {
                    applied += 1;
                }
            }
        }
        Ok((applied, imports, notes))
    }
}

impl Source<'_> {
    fn write_static(&mut self, va: u64, bytes: &[u8]) -> bool {
        let Some(index) = self.regions.iter().position(|r| r.contains(va)) else {
            return false;
        };
        let offset = (va - self.regions[index].start) as usize;
        match self.data[index].get_mut(offset..offset + bytes.len()) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
pub mod testutil {
    //! Synthetic ELF64 builder for offline tests.

    /// Build an ELF64 with one PT_LOAD per segment `(vaddr, flags(PF_R=4,W=2,X=1), bytes)`
    /// at page-aligned file offsets, plus PT_DYNAMIC with DT_RELA for `relas`
    /// `(r_offset, r_info, addend)` and an optional symbol table `(name, defined, value)`.
    pub fn build_elf(
        segments: &[(u64, u32, Vec<u8>)],
        relas: &[(u64, u64, u64)],
        symbols: &[(&str, bool, u64)],
    ) -> Vec<u8> {
        let mut out = vec![0u8; 0x1000];
        let mut phdrs = Vec::new();
        for (vaddr, flags, bytes) in segments {
            let offset = out.len() as u64;
            out.extend_from_slice(bytes);
            while !out.len().is_multiple_of(0x1000) {
                out.push(0);
            }
            phdrs.push((1u32, *flags, offset, *vaddr, bytes.len() as u64, bytes.len() as u64));
        }
        // Dynamic tables live in the file only (no PT_LOAD), addressed via an
        // extra non-overlapping "vaddr" identical to the file offset; map them
        // with a read-only PT_LOAD so DT_* VAs resolve.
        let tables_off = out.len() as u64;
        let tables_va = 0x7000_0000u64;
        let mut tables = Vec::new();
        let rela_at = tables.len() as u64;
        for (offset, info, addend) in relas {
            tables.extend(offset.to_le_bytes());
            tables.extend(info.to_le_bytes());
            tables.extend(addend.to_le_bytes());
        }
        let mut strtab = vec![0u8];
        let sym_at = tables.len() as u64;
        tables.extend([0u8; 24]);
        let mut names = Vec::new();
        for (name, _, _) in symbols {
            names.push(strtab.len() as u32);
            strtab.extend(name.as_bytes());
            strtab.push(0);
        }
        for ((_, defined, value), name) in symbols.iter().zip(names) {
            tables.extend(name.to_le_bytes());
            tables.push(0x12);
            tables.push(0);
            tables.extend((if *defined { 1u16 } else { 0 }).to_le_bytes());
            tables.extend(value.to_le_bytes());
            tables.extend(0u64.to_le_bytes());
        }
        let str_at = tables.len() as u64;
        tables.extend(&strtab);
        while !tables.len().is_multiple_of(8) {
            tables.push(0);
        }
        let dyn_at = tables.len() as u64;
        for (tag, value) in [
            (7u64, tables_va + rela_at),
            (8, relas.len() as u64 * 24),
            (9, 24),
            (6, tables_va + sym_at),
            (5, tables_va + str_at),
            (10, strtab.len() as u64),
            (0, 0),
        ] {
            tables.extend(tag.to_le_bytes());
            tables.extend(value.to_le_bytes());
        }
        out.extend(&tables);
        phdrs.push((1, 4, tables_off, tables_va, tables.len() as u64, tables.len() as u64));
        let dyn_phdr = (2u32, 4u32, tables_off + dyn_at, tables_va + dyn_at, 7 * 16, 7 * 16);
        let mut all = phdrs;
        all.push(dyn_phdr);
        // ELF header
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        out[16..18].copy_from_slice(&3u16.to_le_bytes());
        out[18..20].copy_from_slice(&62u16.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&(all.len() as u16).to_le_bytes());
        for (index, (p_type, flags, offset, vaddr, filesz, memsz)) in all.iter().enumerate() {
            let at = 64 + index * 56;
            out[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            out[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            out[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            out[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
            out[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            out[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            out[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_mapping_applies_relative_and_symbol_relocations() {
        let data = vec![0u8; 0x40];
        let elf = testutil::build_elf(
            &[(0x1000, 5, vec![0xc3; 0x10]), (0x2000, 6, data)],
            &[(0x2000, 8, 0x1004), (0x2008, (1 << 32) | 1, 0x10), (0x2010, (2 << 32) | 6, 0)],
            &[("defined", true, 0x1008), ("imported#A#B", false, 0)],
        );
        let mut source = Source::from_elf("t", elf).unwrap();
        assert_eq!(source.image_base, 0x1000);
        assert_eq!(source.u64(0x2000), Some(0x1004));
        assert_eq!(source.u64(0x2008), Some(0x1018));
        assert_eq!(source.imports.get(&0x2010).map(String::as_str), Some("imported#A#B"));
        assert!(source.is_exec(0x1004));
        assert!(!source.is_exec(0x2000));
        assert_eq!(source.cstr(0x1000, 4), None);
        assert_eq!(source.describe(0x1004)["rva"], "0x4");
    }

    #[test]
    fn raw_and_file_sources() {
        let mut raw = Source::from_raw("dump", b"abc\0def\0".to_vec(), 0x5000);
        assert_eq!(raw.cstr(0x5004, 16).unwrap(), b"def".to_vec());
        assert_eq!(raw.read(0x5007, 2), None);
        let file = Source::from_file("f", b"xyz".to_vec());
        assert_eq!(file.describe(1)["offset"], "0x1");
    }
}
