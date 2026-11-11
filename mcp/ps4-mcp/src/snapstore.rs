//! Content-addressed memory snapshot timeline.
//!
//! Each capture splits the selected ranges at absolute 4 KiB page boundaries,
//! hashes every page with SHA-256 and writes the page once to
//! `snapshots/chunks/<aa>/<sha256>.bin` inside the artifact store. A snapshot is
//! only a manifest (`snapshots/manifests/<id>.json`) listing
//! `[page address, length, sha256]`, so unchanged pages cost nothing on repeated
//! captures. The timeline compares manifests page-by-page and only loads the
//! chunks of pages whose hash changed.

use crate::{Result, artifacts::ArtifactStore, debugger::Debugger};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

pub const PAGE: u64 = 4096;
pub const FORMAT: &str = "ps4-memsnap-v1";
const MAX_MANIFEST_BYTES: usize = 128 * 1024 * 1024;
const MAX_TRACKED_WORDS: usize = 1_000_000;

/// A requested capture range.
#[derive(Clone, Debug)]
pub struct Range {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

pub fn valid_id(id: &str) -> bool {
    regex::Regex::new("^snap-[0-9]{1,20}-[0-9a-f]{8}$").unwrap().is_match(id)
}

fn chunk_rel(sha: &str) -> String {
    format!("snapshots/chunks/{}/{sha}.bin", &sha[..2])
}

fn manifest_rel(id: &str) -> String {
    format!("snapshots/manifests/{id}.json")
}

/// Store `bytes` as a chunk; returns `(sha256, newly_written)`.
pub fn put_chunk(store: &ArtifactStore, bytes: &[u8]) -> Result<(String, bool)> {
    let sha = hex::encode(Sha256::digest(bytes));
    let rel = chunk_rel(&sha);
    let path = store.new_path(&rel)?;
    if path.is_file() {
        return Ok((sha, false));
    }
    let parent = path.parent().context("chunk path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = store.new_path(&format!("{rel}.tmp-{}", uuid::Uuid::new_v4().simple()))?;
    {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
    }
    if let Err(error) = std::fs::rename(&temporary, &path) {
        let _ = std::fs::remove_file(&temporary);
        if !path.is_file() {
            return Err(error.into());
        }
        return Ok((sha, false));
    }
    Ok((sha, true))
}

pub fn get_chunk(store: &ArtifactStore, sha: &str) -> Result<Vec<u8>> {
    ensure!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "Invalid chunk hash");
    let bytes = store.read_bounded(&chunk_rel(sha), PAGE as usize)?;
    ensure!(hex::encode(Sha256::digest(&bytes)) == sha, "Snapshot chunk {sha} is corrupted");
    Ok(bytes)
}

pub fn load_manifest(store: &ArtifactStore, id: &str) -> Result<Value> {
    ensure!(valid_id(id), "Invalid snapshot id: {id}");
    let bytes = store
        .read_bounded(&manifest_rel(id), MAX_MANIFEST_BYTES)
        .with_context(|| format!("Snapshot {id} not found"))?;
    let manifest: Value = serde_json::from_slice(&bytes)?;
    ensure!(manifest["format"] == FORMAT, "Unsupported snapshot format in {id}");
    Ok(manifest)
}

/// Capture `ranges` of `pid`, bounded by `budget` bytes total.
pub fn capture(
    store: &ArtifactStore,
    debugger: &mut Debugger,
    pid: u32,
    ranges: &[Range],
    label: &str,
    budget: u64,
    read_chunk: usize,
) -> Result<Value> {
    ensure!(!ranges.is_empty(), "No ranges selected for the snapshot");
    let read_chunk = (read_chunk as u64).max(PAGE) / PAGE * PAGE;
    let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
    let id = format!("snap-{millis}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let mut pages: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let mut range_rows = Vec::new();
    let (mut total, mut new_chunks, mut reused, mut new_bytes) = (0u64, 0u64, 0u64, 0u64);
    let started = std::time::Instant::now();
    for range in ranges {
        let mut status = "complete";
        let mut address = range.start;
        while address < range.end {
            if total >= budget {
                status = "truncated_budget";
                break;
            }
            if started.elapsed() > std::time::Duration::from_secs(300) {
                status = "truncated_deadline";
                break;
            }
            // Read up to the next read_chunk-aligned boundary, capped by range end and budget.
            let boundary = (address / read_chunk + 1) * read_chunk;
            let stop = boundary.min(range.end).min(address + (budget - total));
            let length = (stop - address) as usize;
            let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
            match debugger.read_memory(pid, address, length, false) {
                Ok(bytes) if bytes.len() == length => pieces.push((address, bytes)),
                _ => {
                    // Per-page fallback so one bad page does not lose the chunk.
                    let failed_before = failed.len();
                    let mut at = address;
                    while at < stop {
                        let page_end = ((at / PAGE) + 1) * PAGE;
                        let len = (page_end.min(stop) - at) as usize;
                        match debugger.read_memory(pid, at, len, false) {
                            Ok(bytes) if bytes.len() == len => pieces.push((at, bytes)),
                            Ok(bytes) => failed.push(json!({"address":format!("{at:#x}"),"length":len,"error":format!("short read ({} bytes)",bytes.len())})),
                            Err(error) => failed.push(json!({"address":format!("{at:#x}"),"length":len,"error":error.to_string()})),
                        }
                        at += len as u64;
                    }
                    if failed.len() > failed_before {
                        status = "partial";
                    }
                }
            }
            for (base, bytes) in pieces {
                let mut offset = 0usize;
                while offset < bytes.len() {
                    let at = base + offset as u64;
                    let page_end = ((at / PAGE) + 1) * PAGE;
                    let len = ((page_end - at) as usize).min(bytes.len() - offset);
                    let (sha, fresh) = put_chunk(store, &bytes[offset..offset + len])?;
                    if fresh {
                        new_chunks += 1;
                        new_bytes += len as u64;
                    } else {
                        reused += 1;
                    }
                    pages.push(json!([format!("{at:#x}"), len, sha]));
                    offset += len;
                }
            }
            total += length as u64;
            address = stop;
        }
        range_rows.push(json!({"start":format!("{:#x}",range.start),"end":format!("{:#x}",range.end),
            "name":range.name,"status":status,"captured_to":format!("{address:#x}")}));
    }
    let manifest = json!({
        "format": FORMAT,
        "id": id,
        "label": label,
        "pid": pid,
        "created_at": crate::artifacts::utc_now(),
        "page_size": PAGE,
        "atomic_snapshot": false,
        "runtime_identity": debugger.identity,
        "ranges": range_rows,
        "bytes": total,
        "page_count": pages.len(),
        "new_chunks": new_chunks,
        "reused_chunks": reused,
        "new_bytes_written": new_bytes,
        "failed": failed,
        "pages": pages,
    });
    let path = store.new_path(&manifest_rel(&id))?;
    std::fs::create_dir_all(path.parent().context("manifest dir")?)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(&serde_json::to_vec(&manifest)?)?;
    store.audit("memory_snapshot_capture", json!({"id":id,"pid":pid,"bytes":total,"new_chunks":new_chunks}))?;
    Ok(json!({
        "id": id, "label": label, "pid": pid, "manifest": manifest_rel(&id),
        "bytes": total, "page_count": manifest["page_count"], "new_chunks": new_chunks,
        "reused_chunks": reused, "new_bytes_written": new_bytes,
        "failed": manifest["failed"], "ranges": manifest["ranges"], "atomic_snapshot": false,
    }))
}

pub fn list(store: &ArtifactStore, pid: Option<u32>, label: Option<&str>, limit: usize) -> Result<Value> {
    let dir = store.new_path("snapshots/manifests")?;
    let mut rows = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)?.take(1_000_000) {
            let name = entry?.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else { continue };
            if !valid_id(id) {
                continue;
            }
            let manifest = match load_manifest(store, id) {
                Ok(manifest) => manifest,
                Err(error) => {
                    rows.push(json!({"id":id,"error":error.to_string()}));
                    continue;
                }
            };
            if pid.is_some_and(|p| manifest["pid"] != p) || label.is_some_and(|l| manifest["label"] != l) {
                continue;
            }
            rows.push(json!({
                "id": id, "label": manifest["label"], "pid": manifest["pid"],
                "created_at": manifest["created_at"], "bytes": manifest["bytes"],
                "page_count": manifest["page_count"], "new_chunks": manifest["new_chunks"],
                "ranges": manifest["ranges"].as_array().map(Vec::len), "failed": manifest["failed"].as_array().map(Vec::len),
            }));
        }
    }
    rows.sort_by(|a, b| {
        (a["created_at"].as_str(), a["id"].as_str()).cmp(&(b["created_at"].as_str(), b["id"].as_str()))
    });
    let total = rows.len();
    if rows.len() > limit {
        rows.drain(..rows.len() - limit);
    }
    Ok(json!({"snapshots": rows, "total": total, "truncated": total > limit}))
}

fn parse_hex(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
}

/// `page address -> (length, sha)` restricted to `filter` overlap.
fn page_map(manifest: &Value, filter: Option<(u64, u64)>) -> BTreeMap<u64, (u64, String)> {
    let mut map = BTreeMap::new();
    for page in manifest["pages"].as_array().into_iter().flatten() {
        let (Some(at), Some(len), Some(sha)) = (parse_hex(&page[0]), page[1].as_u64(), page[2].as_str()) else {
            continue;
        };
        if let Some((start, end)) = filter
            && (at + len <= start || at >= end)
        {
            continue;
        }
        map.insert(at, (len, sha.to_owned()));
    }
    map
}

struct ChunkCache<'a> {
    store: &'a ArtifactStore,
    cache: HashMap<String, Vec<u8>>,
}

impl ChunkCache<'_> {
    fn get(&mut self, sha: &str) -> Result<&[u8]> {
        if !self.cache.contains_key(sha) {
            if self.cache.len() > 4096 {
                self.cache.clear();
            }
            let bytes = get_chunk(self.store, sha)?;
            self.cache.insert(sha.to_owned(), bytes);
        }
        Ok(&self.cache[sha])
    }
}

fn value_at(bytes: &[u8], page: u64, address: u64, size: usize) -> Option<&[u8]> {
    let offset = address.checked_sub(page)? as usize;
    bytes.get(offset..offset + size)
}

fn interpretations(page_bytes: &[u8], page: u64, address: u64) -> Value {
    let u8v = value_at(page_bytes, page, address, 1).map(|b| b[0]);
    let a4 = address & !3;
    let a8 = address & !7;
    let u32v = value_at(page_bytes, page, a4, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64v = value_at(page_bytes, page, a8, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    let f32v = u32v.map(f32::from_bits).filter(|f| f.is_finite()).map(|f| f as f64);
    json!({"u8":u8v,"u32":u32v,"f32":f32v,"u64":u64v.map(|v| format!("{v:#x}"))})
}

pub struct TimelineOptions {
    pub filter: Option<(u64, u64)>,
    pub max_regions_per_step: usize,
    pub max_values_per_step: usize,
    pub top_addresses: usize,
    pub series_addresses: usize,
}

/// Compare snapshots in the given order.
pub fn timeline(store: &ArtifactStore, ids: &[String], options: &TimelineOptions) -> Result<Value> {
    ensure!((2..=64).contains(&ids.len()), "Provide 2-64 snapshot ids");
    let manifests = ids.iter().map(|id| load_manifest(store, id)).collect::<Result<Vec<_>>>()?;
    let pids: BTreeSet<String> = manifests.iter().map(|m| m["pid"].to_string()).collect();
    let mut warnings = Vec::new();
    if pids.len() > 1 {
        warnings.push("Snapshots come from different pids; addresses may not be comparable".to_owned());
    }
    let maps: Vec<_> = manifests.iter().map(|m| page_map(m, options.filter)).collect();
    let mut cache = ChunkCache { store, cache: HashMap::new() };
    let mut word_counts: BTreeMap<u64, u32> = BTreeMap::new();
    let mut tracking_truncated = false;
    let mut steps = Vec::new();
    for step in 1..maps.len() {
        let (before, after) = (&maps[step - 1], &maps[step]);
        let added: Vec<u64> = after.keys().filter(|a| !before.contains_key(a)).copied().collect();
        let removed: Vec<u64> = before.keys().filter(|a| !after.contains_key(a)).copied().collect();
        let mut changed_pages = Vec::new();
        let mut regions: Vec<(u64, u64)> = Vec::new();
        let mut values = Vec::new();
        let mut changed_bytes = 0u64;
        let mut step_words = BTreeSet::new();
        for (page, (len, sha)) in after {
            let Some((old_len, old_sha)) = before.get(page) else { continue };
            if old_sha == sha {
                continue;
            }
            changed_pages.push(*page);
            let old = cache.get(old_sha)?.to_vec();
            let new = cache.get(sha)?.to_vec();
            let common = (*len).min(*old_len) as usize;
            let mut index = 0usize;
            while index < common {
                if old[index] == new[index] {
                    index += 1;
                    continue;
                }
                let start = index;
                while index < common && old[index] != new[index] {
                    index += 1;
                }
                let (run_start, run_end) = (page + start as u64, page + index as u64);
                if let Some((filter_start, filter_end)) = options.filter
                    && (run_end <= filter_start || run_start >= filter_end)
                {
                    continue;
                }
                changed_bytes += run_end - run_start;
                match regions.last_mut() {
                    Some(last) if last.1 == run_start => last.1 = run_end,
                    _ => regions.push((run_start, run_end)),
                }
                let mut word = run_start & !3;
                while word < run_end {
                    step_words.insert(word);
                    word += 4;
                }
                if run_end - run_start <= 8 && values.len() < options.max_values_per_step {
                    values.push(json!({
                        "address": format!("{run_start:#x}"), "length": run_end - run_start,
                        "before": interpretations(&old, *page, run_start),
                        "after": interpretations(&new, *page, run_start),
                    }));
                }
            }
        }
        for word in step_words {
            if word_counts.len() >= MAX_TRACKED_WORDS && !word_counts.contains_key(&word) {
                tracking_truncated = true;
                continue;
            }
            *word_counts.entry(word).or_insert(0) += 1;
        }
        let region_count = regions.len();
        steps.push(json!({
            "from": ids[step - 1], "to": ids[step],
            "changed_pages": changed_pages.len(),
            "changed_bytes": changed_bytes,
            "added_pages": added.len(), "removed_pages": removed.len(),
            "changed_regions": regions.iter().take(options.max_regions_per_step)
                .map(|(s, e)| json!({"start":format!("{s:#x}"),"end":format!("{e:#x}"),"length":e - s})).collect::<Vec<_>>(),
            "changed_regions_total": region_count,
            "changed_regions_truncated": region_count > options.max_regions_per_step,
            "small_value_changes": values,
        }));
    }
    let transitions = (maps.len() - 1) as u32;
    let mut histogram: BTreeMap<u32, u64> = BTreeMap::new();
    for count in word_counts.values() {
        *histogram.entry(*count).or_insert(0) += 1;
    }
    let mut ranked: Vec<(u64, u32)> = word_counts.iter().map(|(a, c)| (*a, *c)).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top: Vec<Value> = ranked
        .iter()
        .take(options.top_addresses)
        .map(|(a, c)| json!({"address":format!("{a:#x}"),"changed_in":c,"of_transitions":transitions}))
        .collect();
    // Value series (u32/f32 per snapshot) for the most frequently changing words.
    let mut series = Vec::new();
    for (address, count) in ranked.iter().take(options.series_addresses) {
        let mut row = Vec::with_capacity(maps.len());
        for map in &maps {
            let page = address / PAGE * PAGE;
            let entry = map.range(..=*address).next_back().filter(|(at, (len, _))| *address + 4 <= **at + *len);
            let value = match entry {
                Some((at, (_, sha))) => {
                    let bytes = cache.get(sha)?.to_vec();
                    value_at(&bytes, *at, *address, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                }
                None => None,
            };
            let _ = page;
            row.push(json!({"u32":value,"f32":value.map(f32::from_bits).filter(|f| f.is_finite()).map(|f| f as f64)}));
        }
        series.push(json!({"address":format!("{address:#x}"),"changed_in":count,"values":row}));
    }
    if tracking_truncated {
        warnings.push(format!("Change counting stopped tracking new words after {MAX_TRACKED_WORDS} addresses"));
    }
    Ok(json!({
        "snapshots": ids,
        "transitions": transitions,
        "filter": options.filter.map(|(s, e)| json!({"start":format!("{s:#x}"),"end":format!("{e:#x}")})),
        "steps": steps,
        "change_frequency": {
            "granularity": "aligned 4-byte words",
            "histogram": histogram.iter().map(|(c, n)| json!({"changed_in":c,"of_transitions":transitions,"words":n})).collect::<Vec<_>>(),
            "changed_every_transition": word_counts.values().filter(|c| **c == transitions).count(),
            "top": top,
        },
        "value_series": series,
        "warnings": warnings,
    }))
}

/// Parse `[{address,length}]` JSON ranges.
pub fn ranges_from_args(items: &[Value]) -> Result<Vec<Range>> {
    let mut out = Vec::new();
    for item in items {
        let start = crate::tools::address(&item["address"])?;
        let length = item["length"].as_u64().context("range length")?;
        let Some(end) = start.checked_add(length) else { bail!("Range overflows") };
        out.push(Range { start, end, name: item["name"].as_str().unwrap_or("").to_owned() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::fake;

    #[test]
    fn repeated_snapshots_dedupe_and_timeline_reports_changes() {
        let mut heap = vec![0u8; 0x3000];
        heap[0x10..0x14].copy_from_slice(&100u32.to_le_bytes());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fake::Fixture {
            pid: 77,
            thread_id: 101,
            base: 0x40_0000,
            image: vec![0x90; 0x1000],
            rip: 0x40_0000,
            extra_maps: vec![(0x9000_0000, 0x9000_3000, 3, "heap".into())],
            extra_memory: vec![(0x9000_0000, heap)],
            ..Default::default()
        };
        let server = fake::spawn_fixture(listener, fixture);
        let directory = tempfile::tempdir().unwrap();
        let profile = fake::qualified_profile(directory.path(), server.port);
        let mut wb = crate::workbench::Workbench::new(profile).unwrap();
        let ranges = vec![Range { start: 0x9000_0000, end: 0x9000_3000, name: "heap".into() }];
        let store = wb.store.clone();
        let first = capture(&store, &mut wb.debugger, 77, &ranges, "t0", 1 << 20, 0x10000).unwrap();
        assert_eq!(first["page_count"], 3);
        let second = capture(&store, &mut wb.debugger, 77, &ranges, "t1", 1 << 20, 0x10000).unwrap();
        assert_eq!(second["new_chunks"], 0, "unchanged pages must not be rewritten");
        assert_eq!(second["reused_chunks"], 3);
        wb.debugger.write_memory(77, 0x9000_0010, &99u32.to_le_bytes(), false).unwrap();
        let third = capture(&store, &mut wb.debugger, 77, &ranges, "t2", 1 << 20, 0x10000).unwrap();
        assert_eq!(third["new_chunks"], 1);
        wb.debugger.write_memory(77, 0x9000_0010, &98u32.to_le_bytes(), false).unwrap();
        let fourth = capture(&store, &mut wb.debugger, 77, &ranges, "t3", 1 << 20, 0x10000).unwrap();
        let ids: Vec<String> = [&first, &second, &third, &fourth].iter().map(|s| s["id"].as_str().unwrap().to_owned()).collect();

        let listed = list(&store, Some(77), None, 100).unwrap();
        assert_eq!(listed["total"], 4);

        let options = TimelineOptions { filter: None, max_regions_per_step: 16, max_values_per_step: 16, top_addresses: 8, series_addresses: 4 };
        let result = timeline(&store, &ids, &options).unwrap();
        assert_eq!(result["transitions"], 3);
        assert_eq!(result["steps"][0]["changed_pages"], 0);
        assert_eq!(result["steps"][1]["changed_pages"], 1);
        let change = &result["steps"][1]["small_value_changes"][0];
        assert_eq!(change["address"], "0x90000010");
        assert_eq!(change["before"]["u32"], 100);
        assert_eq!(change["after"]["u32"], 99);
        assert_eq!(result["change_frequency"]["top"][0]["address"], "0x90000010");
        assert_eq!(result["change_frequency"]["top"][0]["changed_in"], 2);
        let values: Vec<u64> = result["value_series"][0]["values"].as_array().unwrap().iter().map(|v| v["u32"].as_u64().unwrap()).collect();
        assert_eq!(values, vec![100, 100, 99, 98]);
        // Range filter excluding the change yields no changed bytes.
        let filtered = timeline(&store, &ids, &TimelineOptions { filter: Some((0x9000_1000, 0x9000_2000)), ..options }).unwrap();
        assert_eq!(filtered["steps"][1]["changed_bytes"], 0);
        assert!(timeline(&store, &ids[..1], &TimelineOptions { filter: None, max_regions_per_step: 1, max_values_per_step: 1, top_addresses: 1, series_addresses: 1 }).is_err());
        assert!(load_manifest(&store, "../evil").is_err());
    }
}
