//! Multi-level pointer scanning (Cheat Engine style) as pure functions over an
//! in-memory snapshot. The live side (`Debugger::pointer_snapshot`) only gathers
//! the snapshot; everything here is deterministic and unit-testable.
//!
//! Path semantics: `[[module+off] + o1] + o2 ...`: read the qword at the static
//! root, then for every offset but the last add it and dereference again; the
//! final offset is added without dereferencing. A path with `n` offsets performs
//! `n` dereferences.
use crate::Result;
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};

pub const FORMAT: &str = "ps4wb-pointers-v1";
pub const MAX_DEPTH: usize = 6;
pub const MAX_OFFSET: u64 = 0x4000;
pub const MAX_RESULTS: usize = 10_000;
/// Bound on the number of intermediate nodes explored (memory and time guard).
pub const MAX_NODES: usize = 200_000;

/// One captured memory region.
#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub data: Vec<u8>,
}

/// A loaded module image (`base..end`) whose locations count as static roots.
#[derive(Debug, Clone, PartialEq)]
pub struct Module {
    pub name: String,
    pub base: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub regions: Vec<Region>,
    /// Ranges a pointer may point into (all readable mappings, captured or not).
    pub readable: Vec<(u64, u64)>,
    pub modules: Vec<Module>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub max_offset: u64,
    pub max_results: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerPath {
    pub module: String,
    pub module_offset: u64,
    pub offsets: Vec<u64>,
}

impl PointerPath {
    pub fn text(&self) -> String {
        let mut text = format!("[{}+{:#x}]", self.module, self.module_offset);
        for offset in &self.offsets {
            text.push_str(&format!(" -> +{offset:#x}"));
        }
        text
    }

    pub fn to_json(&self) -> Value {
        json!({"base":format!("{}+{:#x}", self.module, self.module_offset),"module":self.module,
            "module_offset":format!("{:#x}", self.module_offset),
            "offsets":self.offsets.iter().map(|offset| format!("{offset:#x}")).collect::<Vec<_>>(),
            "depth":self.offsets.len(),"text":self.text()})
    }

    pub fn from_json(value: &Value) -> Result<Self> {
        let hex = |text: &Value| -> Result<u64> {
            let text = text.as_str().context("Expected hex string")?;
            Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
        };
        let offsets = value["offsets"]
            .as_array()
            .context("Path needs offsets")?
            .iter()
            .map(hex)
            .collect::<Result<Vec<_>>>()?;
        ensure!(!offsets.is_empty() && offsets.len() <= MAX_DEPTH, "Invalid path depth");
        Ok(Self {
            module: value["module"].as_str().context("Path needs module")?.to_owned(),
            module_offset: hex(&value["module_offset"])?,
            offsets,
        })
    }
}

impl Snapshot {
    fn is_readable(&self, address: u64) -> bool {
        self.readable.iter().any(|(start, end)| *start <= address && address < *end)
    }

    fn module_of(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|module| module.base <= address && address < module.end)
    }

    /// Read a captured qword (`None` outside captured regions).
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        self.regions.iter().find_map(|region| {
            let offset = address.checked_sub(region.start)? as usize;
            let bytes = region.data.get(offset..offset.checked_add(8)?)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        })
    }

    /// Sorted `(value, location)` index of every 8-byte aligned captured qword
    /// that points into readable memory.
    pub fn pointer_index(&self) -> Vec<(u64, u64)> {
        let mut index = Vec::new();
        for region in &self.regions {
            let skip = ((8 - (region.start % 8)) % 8) as usize;
            let mut offset = skip;
            while offset + 8 <= region.data.len() {
                let value = u64::from_le_bytes(region.data[offset..offset + 8].try_into().unwrap());
                if value >= 0x10000 && self.is_readable(value) {
                    index.push((value, region.start + offset as u64));
                }
                offset += 8;
            }
        }
        index.sort_unstable();
        index
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub paths: Vec<PointerPath>,
    pub index_entries: usize,
    pub nodes_explored: usize,
    pub truncated: bool,
}

/// Backward breadth-first search from `target`: at each level find every
/// location holding a value in `[t - max_offset, t]`; locations inside a module
/// image become results (static roots), others become the next level's targets.
/// Shorter paths are found first; each address is expanded at most once.
pub fn scan(snapshot: &Snapshot, target: u64, options: ScanOptions) -> ScanOutcome {
    let index = snapshot.pointer_index();
    let mut outcome = ScanOutcome { index_entries: index.len(), ..Default::default() };
    let max_depth = options.max_depth.clamp(1, MAX_DEPTH);
    let max_results = options.max_results.clamp(1, MAX_RESULTS);
    let max_offset = options.max_offset.min(MAX_OFFSET);
    let mut seen_paths = HashSet::new();
    let mut visited = HashSet::new();
    visited.insert(target);
    // (address to reach, offsets suffix applied after reaching it)
    let mut frontier: VecDeque<(u64, Vec<u64>)> = VecDeque::from([(target, Vec::new())]);
    for _depth in 0..max_depth {
        let mut next = VecDeque::new();
        while let Some((wanted, suffix)) = frontier.pop_front() {
            let low = wanted.saturating_sub(max_offset);
            let start = index.partition_point(|(value, _)| *value < low);
            for (value, location) in index[start..].iter().take_while(|(value, _)| *value <= wanted) {
                let mut offsets = Vec::with_capacity(suffix.len() + 1);
                offsets.push(wanted - value);
                offsets.extend(&suffix);
                if let Some(module) = snapshot.module_of(*location) {
                    let path = PointerPath {
                        module: module.name.clone(),
                        module_offset: location - module.base,
                        offsets,
                    };
                    if seen_paths.insert(path.clone()) {
                        outcome.paths.push(path);
                        if outcome.paths.len() >= max_results {
                            outcome.truncated = true;
                            return outcome;
                        }
                    }
                } else if visited.insert(*location) {
                    outcome.nodes_explored += 1;
                    if outcome.nodes_explored >= MAX_NODES {
                        outcome.truncated = true;
                        return outcome;
                    }
                    next.push_back((*location, offsets));
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    outcome
}

/// Resolve a path against current module bases and a qword reader; `None` when
/// the module is not loaded or a dereference fails.
pub fn resolve(
    path: &PointerPath,
    module_base: impl Fn(&str) -> Option<u64>,
    mut read: impl FnMut(u64) -> Option<u64>,
) -> Option<u64> {
    let root = module_base(&path.module)?.checked_add(path.module_offset)?;
    let mut value = read(root)?;
    let (last, middle) = path.offsets.split_last()?;
    for offset in middle {
        value = read(value.checked_add(*offset)?)?;
    }
    value.checked_add(*last)
}

/// Group module bases by name for rescans (`HashMap<name, base>`).
pub fn module_map(modules: &[Module]) -> HashMap<String, u64> {
    modules.iter().map(|module| (module.name.clone(), module.base)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(start: u64, qwords: &[(u64, u64)], size: usize) -> Region {
        let mut data = vec![0u8; size];
        for (address, value) in qwords {
            let offset = (address - start) as usize;
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Region { start, data }
    }

    /// module data at 0x10000.., heap at 0x200000..; chain:
    /// [game+0x100] = 0x200000 ; [0x200000+0x18] = 0x200800 ; target = 0x200800+0x40
    fn snapshot() -> Snapshot {
        Snapshot {
            regions: vec![
                region(0x10000, &[(0x10100, 0x200000), (0x10200, 0x200840 - 0x10)], 0x1000),
                region(0x200000, &[(0x200018, 0x200800), (0x200900, 0x200000)], 0x1000),
            ],
            readable: vec![(0x10000, 0x11000), (0x200000, 0x201000)],
            modules: vec![Module { name: "game.elf".into(), base: 0x8000, end: 0x11000 }],
        }
    }

    #[test]
    fn finds_static_paths_shortest_first_and_resolves_them() {
        let snapshot = snapshot();
        let target = 0x200840;
        let outcome = scan(&snapshot, target, ScanOptions { max_depth: 3, max_offset: 0x100, max_results: 100 });
        let texts: Vec<String> = outcome.paths.iter().map(PointerPath::text).collect();
        assert_eq!(texts[0], "[game.elf+0x8200] -> +0x10", "{texts:?}");
        assert!(texts.contains(&"[game.elf+0x8100] -> +0x18 -> +0x40".to_owned()), "{texts:?}");
        let bases = module_map(&snapshot.modules);
        for path in &outcome.paths {
            let value = resolve(path, |name| bases.get(name).copied(), |address| snapshot.read_u64(address));
            assert_eq!(value, Some(target), "{}", path.text());
        }
        // Round-trip through JSON.
        let parsed = PointerPath::from_json(&outcome.paths[1].to_json()).unwrap();
        assert_eq!(parsed, outcome.paths[1]);
    }

    #[test]
    fn rescan_rejects_paths_that_no_longer_reach_the_target() {
        let snapshot = snapshot();
        let path = PointerPath { module: "game.elf".into(), module_offset: 0x8100, offsets: vec![0x18, 0x40] };
        // Module moved: base +0x1000 means root now reads elsewhere (unmapped -> None).
        let moved = resolve(&path, |_| Some(0x9000), |address| snapshot.read_u64(address));
        assert_ne!(moved, Some(0x200840));
        assert_eq!(resolve(&path, |_| None, |address| snapshot.read_u64(address)), None);
    }

    #[test]
    fn max_results_and_depth_are_bounded() {
        let snapshot = snapshot();
        let outcome = scan(&snapshot, 0x200840, ScanOptions { max_depth: 1, max_offset: 0x100, max_results: 1 });
        assert_eq!(outcome.paths.len(), 1);
        assert!(outcome.paths.iter().all(|path| path.offsets.len() == 1));
    }
}
