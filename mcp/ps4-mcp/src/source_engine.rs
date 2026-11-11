//! Source-engine metadata recovery (Valve Source and derived engines such as
//! Respawn's fork used by Titanfall / Apex Legends).
//!
//! Recovers the engine's self-describing runtime metadata from a loaded module
//! (live `pid` + `module`, default `eboot.bin`) or a mapped artifact:
//!
//! * the `ClientClass` linked list (network class name, class id, RecvTable),
//! * `RecvTable` / `RecvProp` network tables (prop names, offsets, nesting),
//! * `datamap_t` / `typedescription_t` data descriptions,
//! * the `ConCommandBase` (ConVar / ConCommand) linked list,
//! * the `InterfaceReg` (`CreateInterface`) linked list.
//!
//! Engine forks reorder and extend these structures, so nothing here assumes a
//! fixed layout. Each structure is located from anchor strings (`C*` class names,
//! `DT_*` tables, `m_*` members, cvar-style names, `Name###` interface versions)
//! and its field offsets are *inferred* by scoring candidate layouts on how
//! consistently they link up; results carry the chosen layout, its evidence and
//! runner-up candidates, and every offset can be overridden (`layout`). The public
//! Source SDK 2013 (64-bit) layouts are used only as tie-breakers and to label
//! `layout_matches_sdk2013`; field-type enums differ between forks and are
//! reported raw. Read-only.
use crate::bytesource::{Mode, PROT_R, PROT_X, Source, TargetSpec, hex};
use crate::engines::{artifact_ref, save_json, save_text};
use crate::{Result, workbench::Workbench};
use anyhow::ensure;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

pub const FORMAT: &str = "ps4wb-source-v1";
const MAX_NAME: usize = 127;
const POINTER_CAP: usize = 2_000_000;
const STRING_CAP: usize = 4_000_000;
const SECTIONS: [&str; 5] = ["client_classes", "recv_tables", "datamaps", "convars", "interfaces"];

// ---- name predicates ---------------------------------------------------------

fn ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Network class name, e.g. `CPlayer`, `CAI_BaseNPC`.
fn is_class_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    (3..=96).contains(&bytes.len())
        && bytes[0] == b'C'
        && (bytes[1].is_ascii_uppercase() || bytes[1] == b'_')
        && bytes.iter().all(|b| ident_char(*b))
}

fn is_table_name(text: &str) -> bool {
    text.len() > 3 && text.len() <= 96 && text.starts_with("DT_") && text.bytes().all(ident_char)
}

fn is_member_name(text: &str) -> bool {
    text.len() > 2 && text.starts_with("m_") && is_field_name(text)
}

/// RecvProp / typedescription names: identifiers, array elements (`000`),
/// and indexed or dotted members (`m_hMyWeapons[0]`, `m_vec.x`).
fn is_field_name(text: &str) -> bool {
    (1..=MAX_NAME).contains(&text.len())
        && text.bytes().all(|b| ident_char(b) || matches!(b, b'[' | b']' | b'.' | b':'))
}

/// Strict cvar anchor: lowercase with an underscore or dot (`sv_cheats`, `mat_fullbright`).
fn is_cvar_anchor(text: &str) -> bool {
    (4..=64).contains(&text.len())
        && text.as_bytes()[0].is_ascii_lowercase()
        && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.'))
        && text.bytes().any(|b| matches!(b, b'_' | b'.'))
}

/// Loose predicate while walking the ConCommandBase chain (`quit`, `+attack`).
fn is_command_name(text: &str) -> bool {
    (1..=96).contains(&text.len())
        && text.bytes().all(|b| ident_char(b) || matches!(b, b'.' | b'+' | b'-'))
}

/// Interface version string, e.g. `VClient018`, `VEngineClient014`.
fn is_interface_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 5
        && bytes.len() <= 64
        && bytes[0].is_ascii_uppercase()
        && bytes[bytes.len() - 3..].iter().all(u8::is_ascii_digit)
        && bytes[..bytes.len() - 3].iter().all(|b| b.is_ascii_alphabetic() || *b == b'_')
}

fn is_identifier(text: &str) -> bool {
    (1..=96).contains(&text.len()) && text.bytes().all(ident_char)
}

const KIND_CLASS: u8 = 1;
const KIND_TABLE: u8 = 2;
const KIND_MEMBER: u8 = 4;
const KIND_CVAR: u8 = 8;
const KIND_IFACE: u8 = 16;

fn classify(text: &str) -> u8 {
    let mut kind = 0;
    if is_class_name(text) {
        kind |= KIND_CLASS;
    }
    if is_table_name(text) {
        kind |= KIND_TABLE;
    }
    if is_member_name(text) {
        kind |= KIND_MEMBER;
    }
    if is_cvar_anchor(text) {
        kind |= KIND_CVAR;
    }
    if is_interface_name(text) {
        kind |= KIND_IFACE;
    }
    kind
}

// ---- layout overrides -----------------------------------------------------------

fn candidates(layout: &Value, key: &str, default: impl Iterator<Item = u64>) -> Vec<u64> {
    match layout.get(key).and_then(Value::as_u64) {
        Some(value) => vec![value],
        None => default.collect(),
    }
}

fn qwords(max: u64) -> impl Iterator<Item = u64> {
    (0..=max).step_by(8)
}

fn overlaps(at: u64, width: u64, taken: &[(u64, u64)]) -> bool {
    taken.iter().any(|(start, size)| at < start + size && *start < at + width)
}

// ---- context ----------------------------------------------------------------------

struct Ctx<'a> {
    src: Source<'a>,
    /// Classified anchor strings found in the scanned ranges.
    strings: HashMap<u64, (String, u8)>,
    names: HashMap<u64, Option<String>>,
    /// Non-executable readable ranges searched for strings and pointers.
    ranges: Vec<(u64, u64)>,
    heuristics: Vec<String>,
    layout: Value,
    /// Name slots already attributed to RecvProps (kept out of datamap inference).
    claimed: HashSet<u64>,
}

impl Ctx<'_> {
    fn name(&mut self, pointer: u64) -> Option<String> {
        if let Some((text, _)) = self.strings.get(&pointer) {
            return Some(text.clone());
        }
        if let Some(known) = self.names.get(&pointer) {
            return known.clone();
        }
        let text = (pointer != 0 && self.src.is_mapped(pointer))
            .then(|| self.src.cstr(pointer, MAX_NAME))
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|text| !text.is_empty() && text.bytes().all(|b| (0x20..0x7f).contains(&b)));
        self.names.insert(pointer, text.clone());
        text
    }

    fn named(&mut self, field: u64, predicate: fn(&str) -> bool) -> Option<String> {
        let pointer = self.src.u64(field)?;
        self.name(pointer).filter(|text| predicate(text))
    }

    /// Readable text at `pointer` (empty allowed), for help strings.
    fn text(&mut self, pointer: u64, max: usize) -> Option<String> {
        if pointer == 0 || !self.src.is_mapped(pointer) {
            return None;
        }
        let bytes = self.src.cstr(pointer, max)?;
        String::from_utf8(bytes).ok().filter(|t| t.bytes().all(|b| b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b)))
    }

    /// Pass 1: classified identifier strings in the non-executable ranges.
    fn index_strings(&mut self) -> Result<()> {
        let ranges = self.ranges.clone();
        let starts: HashSet<u64> = ranges.iter().map(|range| range.0).collect();
        let mut found: HashMap<u64, (String, u8)> = HashMap::new();
        let mut truncated = false;
        self.src.scan(Some(&ranges), MAX_NAME + 1, |va, chunk| {
            for index in 0..chunk.len() {
                let start_ok = if index == 0 { starts.contains(&va) } else { chunk[index - 1] == 0 };
                if !start_ok || !(ident_char(chunk[index]) || chunk[index] == b'+') {
                    continue;
                }
                let window = &chunk[index..chunk.len().min(index + MAX_NAME + 1)];
                let Some(end) = window.iter().position(|b| *b == 0) else { continue };
                let Ok(text) = std::str::from_utf8(&window[..end]) else { continue };
                let kind = classify(text);
                if kind != 0 {
                    found.entry(va + index as u64).or_insert_with(|| (text.to_owned(), kind));
                    if found.len() >= STRING_CAP {
                        truncated = true;
                        return false;
                    }
                }
            }
            true
        })?;
        self.heuristics.push(format!(
            "Indexed {} anchor strings in {} non-executable ranges{}",
            found.len(),
            ranges.len(),
            if truncated { " (string cap reached)" } else { "" }
        ));
        self.strings = found;
        Ok(())
    }

    /// Pass 2: aligned pointer slots to anchor strings, grouped by kind.
    fn anchor_slots(&mut self) -> Result<HashMap<u8, Vec<u64>>> {
        let targets: HashSet<u64> = self.strings.keys().copied().collect();
        let ranges = self.ranges.clone();
        let pairs = self.src.find_pointers(&ranges, &targets, POINTER_CAP)?;
        if pairs.len() >= POINTER_CAP {
            self.heuristics.push("Anchor pointer cap reached; results may be incomplete".into());
        }
        let mut slots: HashMap<u8, Vec<u64>> = HashMap::new();
        for (slot, value) in pairs {
            if let Some((_, kind)) = self.strings.get(&value) {
                for bit in [KIND_CLASS, KIND_TABLE, KIND_MEMBER, KIND_CVAR, KIND_IFACE] {
                    if kind & bit != 0 {
                        slots.entry(bit).or_default().push(slot);
                    }
                }
            }
        }
        Ok(slots)
    }

    // ---- linked lists (ClientClass, ConCommandBase, InterfaceReg) ------------------

    fn infer_chain(
        &mut self,
        anchors: &[u64],
        walk: fn(&str) -> bool,
        name_offsets: &[u64],
        next_offsets: &[u64],
    ) -> Option<Chain> {
        let sample: Vec<u64> = sample(anchors, 64);
        let mut scored: Vec<Chain> = Vec::new();
        for &name in name_offsets {
            for &next in next_offsets {
                if next == name {
                    continue;
                }
                let mut edges = 0usize;
                for &slot in &sample {
                    let Some(mut node) = slot.checked_sub(name) else { continue };
                    for _ in 0..6 {
                        let Some(following) = self.src.u64(node + next) else { break };
                        if following == 0 || following == node || self.named(following + name, walk).is_none() {
                            break;
                        }
                        edges += 1;
                        node = following;
                    }
                }
                if edges > 0 {
                    scored.push(Chain { name, next, edges });
                }
            }
        }
        scored.sort_by(|a, b| b.edges.cmp(&a.edges).then(a.name.cmp(&b.name)));
        scored.first().copied().filter(|best| best.edges >= 2)
    }

    /// Ordered nodes of every chain containing an anchor, longest chain first.
    /// Walks forward from every anchored node first so that non-anchor members
    /// (e.g. `quit` among cvars) still link chains together before heads are chosen.
    fn collect_chain(&mut self, anchors: &[u64], chain: Chain, walk: fn(&str) -> bool, max: usize) -> Vec<u64> {
        let mut next_of: HashMap<u64, u64> = HashMap::new();
        let budget = max.saturating_mul(4).max(1024);
        for &slot in anchors.iter().take(200_000) {
            let Some(mut node) = slot.checked_sub(chain.name) else { continue };
            while node != 0 && !next_of.contains_key(&node) && next_of.len() < budget {
                if self.named(node + chain.name, walk).is_none() {
                    break;
                }
                let following = self.src.u64(node + chain.next).unwrap_or(0);
                next_of.insert(node, following);
                node = following;
            }
        }
        let targeted: HashSet<u64> = next_of.values().copied().collect();
        let mut heads: Vec<u64> = next_of.keys().copied().filter(|node| !targeted.contains(node)).collect();
        heads.sort_unstable();
        let mut chains: Vec<Vec<u64>> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        for head in heads {
            let mut list = Vec::new();
            let mut node = head;
            while list.len() < max && next_of.contains_key(&node) && visited.insert(node) {
                list.push(node);
                node = next_of[&node];
            }
            if list.len() >= 2 {
                chains.push(list);
            }
        }
        chains.sort_by_key(|list| std::cmp::Reverse(list.len()));
        chains.into_iter().flatten().take(max).collect()
    }

    /// Qword field (excluding `taken`) that holds a pointer satisfying `accept`
    /// for the most nodes; returns (offset, hits).
    fn pointer_field(&mut self, nodes: &[u64], offsets: &[u64], taken: &[(u64, u64)], mut accept: impl FnMut(&mut Self, u64) -> bool) -> Option<(u64, usize)> {
        let sample = sample(nodes, 96);
        let mut best: Option<(u64, usize)> = None;
        for &offset in offsets {
            if overlaps(offset, 8, taken) {
                continue;
            }
            let mut hits = 0;
            for &node in &sample {
                if let Some(value) = self.src.u64(node + offset)
                    && value != 0
                    && accept(self, value)
                {
                    hits += 1;
                }
            }
            if hits > best.map_or(0, |b| b.1) {
                best = Some((offset, hits));
            }
        }
        best
    }

    /// Bytes `[0, width)` of up to `limit` records.
    fn records(&mut self, addresses: &[u64], width: u64, limit: usize) -> Vec<Vec<u8>> {
        addresses
            .iter()
            .take(limit)
            .filter_map(|address| self.src.read(*address, width as usize))
            .collect()
    }

    /// Qword offsets that look like pointers (mapped) in most records.
    fn pointer_like(&self, rows: &[Vec<u8>], width: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for offset in (0..width.saturating_sub(7)).step_by(8) {
            let mapped = rows
                .iter()
                .filter(|row| {
                    let value = u64::from_le_bytes(row[offset as usize..offset as usize + 8].try_into().unwrap());
                    value != 0 && self.src.is_mapped(value)
                })
                .count();
            if mapped * 2 > rows.len() {
                out.push((offset, 8));
            }
        }
        out
    }
}

/// `(desc, count, name, class)` offsets of a datamap_t candidate layout.
type MapLayout = (u64, u64, u64, u64);

#[derive(Clone, Copy, Debug)]
struct Chain {
    name: u64,
    next: u64,
    edges: usize,
}

fn sample(items: &[u64], count: usize) -> Vec<u64> {
    if items.len() <= count {
        return items.to_vec();
    }
    let step = items.len() / count;
    items.iter().step_by(step.max(1)).take(count).copied().collect()
}

fn word(row: &[u8], offset: u64) -> u32 {
    u32::from_le_bytes(row[offset as usize..offset as usize + 4].try_into().unwrap())
}

/// Integer-field inference over raw records: the 4-byte field (not overlapping
/// `taken`) whose values are all `<= max_value`, ranked by `score`. Returns the
/// winner plus up to three runners-up as `(offset, score)`.
fn int_field(rows: &[Vec<u8>], width: u64, taken: &[(u64, u64)], max_value: u32, score: impl Fn(&[u32]) -> f64) -> Vec<(u64, f64)> {
    let mut scored: Vec<(u64, f64)> = Vec::new();
    if rows.is_empty() {
        return scored;
    }
    for offset in (0..width.saturating_sub(3)).step_by(4) {
        if overlaps(offset, 4, taken) {
            continue;
        }
        let values: Vec<u32> = rows.iter().map(|row| word(row, offset)).collect();
        if values.iter().all(|v| *v <= max_value) {
            let value = score(&values);
            if value > 0.0 {
                scored.push((offset, value));
            }
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
    scored.truncate(4);
    scored
}

/// Field offsets: many distinct, mostly 4-byte aligned values.
fn offset_score(values: &[u32]) -> f64 {
    let distinct = values.iter().collect::<HashSet<_>>().len();
    if values.len() >= 4 && distinct < 2 {
        return 0.0;
    }
    let aligned = values.iter().filter(|v| *v % 4 == 0).count() as f64 / values.len() as f64;
    distinct as f64 * (0.5 + aligned)
}

/// Small enums (prop/field types): at least two distinct values when possible.
fn enum_score(values: &[u32]) -> f64 {
    let distinct = values.iter().collect::<HashSet<_>>().len();
    if values.len() >= 4 && distinct < 2 {
        return 0.0;
    }
    1.0 + distinct as f64 / 64.0
}

fn alternatives(scored: &[(u64, f64)]) -> Value {
    json!(scored.iter().skip(1).map(|(offset, score)| json!({"offset": hex(*offset), "score": (score * 100.0).round() / 100.0})).collect::<Vec<_>>())
}

fn confidence(scored: &[(u64, f64)]) -> &'static str {
    match scored {
        [] => "none",
        [_] => "high",
        [first, second, ..] if first.1 >= second.1 * 1.5 => "high",
        _ => "medium",
    }
}

/// SDK 2013 SendPropType names (Valve public SDK `dt_common.h`); forks may differ.
fn sdk2013_prop_type(value: u32) -> Option<&'static str> {
    ["DPT_Int", "DPT_Float", "DPT_Vector", "DPT_VectorXY", "DPT_String", "DPT_Array", "DPT_DataTable", "DPT_Int64"]
        .get(value as usize)
        .copied()
}

// ---- array layout inference (RecvProp / typedescription_t) ----------------------

#[derive(Clone, Copy, Debug)]
struct ArrayLayout {
    stride: u64,
    name: u64,
}

impl Ctx<'_> {
    fn infer_array(&mut self, arrays: &[(u64, usize)], strides: &[u64], names: Option<u64>) -> Option<(ArrayLayout, usize)> {
        let arrays: Vec<(u64, usize)> = arrays.iter().filter(|(_, count)| *count > 0).take(48).copied().collect();
        let mut quick: Vec<(ArrayLayout, usize)> = Vec::new();
        for &stride in strides {
            let name_offsets: Vec<u64> = match names {
                Some(name) => vec![name],
                None => (0..stride).step_by(8).collect(),
            };
            for name in name_offsets {
                let mut ok = 0;
                for &(base, count) in &arrays {
                    let probe = count.min(2);
                    if (0..probe).all(|i| self.named(base + i as u64 * stride + name, is_field_name).is_some()) {
                        ok += 1;
                    }
                }
                if ok > 0 {
                    quick.push((ArrayLayout { stride, name }, ok));
                }
            }
        }
        quick.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.stride.cmp(&b.0.stride)));
        let mut best: Option<(ArrayLayout, usize)> = None;
        for (layout, _) in quick.into_iter().take(12) {
            let mut full = 0;
            for &(base, count) in &arrays {
                if (0..count.min(64)).all(|i| self.named(base + i as u64 * layout.stride + layout.name, is_field_name).is_some()) {
                    full += 1;
                }
            }
            if full > best.map_or(0, |b| b.1) || (full == best.map_or(0, |b| b.1) && best.is_some_and(|b| layout.stride < b.0.stride)) {
                best = Some((layout, full));
            }
        }
        best.filter(|b| b.1 > 0)
    }
}

// ---- ClientClass + RecvTable ------------------------------------------------------

struct NetTables {
    classes: Vec<Value>,
    tables: Vec<Value>,
    layout: Value,
}

impl Ctx<'_> {
    fn client_classes(&mut self, anchors: &[u64], limits: &Limits) -> Result<Option<NetTables>> {
        let names = candidates(&self.layout, "cc_name", qwords(0x30));
        let nexts = candidates(&self.layout, "cc_next", qwords(0x48));
        let Some(chain) = self.infer_chain(anchors, is_class_name, &names, &nexts) else {
            self.heuristics.push(format!("ClientClass: no linked list found among {} class-name pointers", anchors.len()));
            return Ok(None);
        };
        let nodes = self.collect_chain(anchors, chain, is_class_name, limits.classes);
        self.heuristics.push(format!(
            "ClientClass: name@{:#x} next@{:#x} chosen from {} linked edges; {} classes",
            chain.name,
            chain.next,
            chain.edges,
            nodes.len()
        ));
        // RecvTable pointer + RecvTable name offset: the pair under which most
        // classes point at a struct naming a `DT_*` table.
        let table_names = candidates(&self.layout, "rt_name", qwords(0x60));
        let recv_offsets = candidates(&self.layout, "cc_recv_table", qwords(0x48));
        let taken = [(chain.name, 8), (chain.next, 8)];
        let mut recv: Option<(u64, u64, usize)> = None;
        for &table_name in &table_names {
            if let Some((offset, hits)) = self.pointer_field(&nodes, &recv_offsets, &taken, |ctx, table| ctx.named(table + table_name, is_table_name).is_some())
                && hits > recv.map_or(0, |r| r.2)
            {
                recv = Some((offset, table_name, hits));
            }
        }
        let rows = self.records(&nodes, 0x50, 4096);
        let mut taken_ids = taken.to_vec();
        if let Some((offset, _, _)) = recv {
            taken_ids.push((offset, 8));
        }
        taken_ids.extend(self.pointer_like(&rows, 0x50));
        let id_override = self.layout.get("cc_class_id").and_then(Value::as_u64);
        let ids = match id_override {
            Some(offset) => vec![(offset, 1.0)],
            None => int_field(&rows, 0x50, &taken_ids, 0xffff, |values| {
                let distinct = values.iter().collect::<HashSet<_>>().len();
                if distinct * 10 < values.len() * 9 {
                    return 0.0;
                }
                let permutation = values.iter().all(|v| (*v as usize) < values.len() + 1);
                distinct as f64 + if permutation { values.len() as f64 } else { 0.0 }
            }),
        };
        let class_id = ids.first().map(|(offset, _)| *offset);

        let mut classes = Vec::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        for &node in &nodes {
            let name = self.named(node + chain.name, is_class_name).unwrap_or_default();
            let table = recv.and_then(|(offset, _, _)| self.src.u64(node + offset)).filter(|t| *t != 0);
            let table_name = match (table, recv) {
                (Some(table), Some((_, name_offset, _))) => self.named(table + name_offset, is_table_name),
                _ => None,
            };
            if let Some(table) = table {
                queue.push_back(table);
            }
            classes.push(json!({
                "name": name,
                "class_id": class_id.and_then(|offset| self.src.u32(node + offset)),
                "address": self.src.describe(node),
                "recv_table": table_name,
            }));
        }
        let class_layout = json!({
            "name": hex(chain.name), "next": hex(chain.next),
            "recv_table": recv.map(|r| hex(r.0)),
            "class_id": class_id.map(hex), "class_id_confidence": confidence(&ids), "class_id_alternatives": alternatives(&ids),
            "linked_edges_scored": chain.edges,
            "layout_matches_sdk2013": chain.name == 0x10 && chain.next == 0x20 && recv.is_some_and(|r| r.0 == 0x18) && class_id == Some(0x28),
        });
        let Some((_, table_name_offset, _)) = recv else {
            self.heuristics.push("RecvTable: no ClientClass field points at a DT_* named table".into());
            return Ok(Some(NetTables { classes, tables: Vec::new(), layout: json!({"client_class": class_layout}) }));
        };
        let (tables, table_layout) = self.recv_tables(queue, table_name_offset, limits)?;
        Ok(Some(NetTables { classes, tables, layout: json!({"client_class": class_layout, "recv_table": table_layout["recv_table"], "recv_prop": table_layout["recv_prop"]}) }))
    }

    fn recv_tables(&mut self, mut queue: VecDeque<u64>, name_offset: u64, limits: &Limits) -> Result<(Vec<Value>, Value)> {
        // Seed tables (from ClientClass) decide the RecvTable props/count layout.
        let seeds: Vec<u64> = queue.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
        let prop_offsets = candidates(&self.layout, "rt_props", qwords(0x48));
        let count_offsets = candidates(&self.layout, "rt_count", (0..=0x4c).step_by(4));
        let strides = candidates(&self.layout, "rp_stride", (0x10..=0x100).step_by(8));
        let prop_name = self.layout.get("rp_name").and_then(Value::as_u64);
        let mut best: Option<(u64, u64, ArrayLayout, usize)> = None;
        for &props in &prop_offsets {
            if props == name_offset {
                continue;
            }
            for &count in &count_offsets {
                if overlaps(count, 4, &[(props, 8), (name_offset, 8)]) {
                    continue;
                }
                let mut arrays = Vec::new();
                let mut plausible = true;
                for &table in seeds.iter().take(48) {
                    let (Some(pointer), Some(n)) = (self.src.u64(table + props), self.src.u32(table + count)) else {
                        plausible = false;
                        break;
                    };
                    if n > 4096 || (n > 0 && !self.src.is_mapped(pointer)) {
                        plausible = false;
                        break;
                    }
                    arrays.push((pointer, n as usize));
                }
                if !plausible || arrays.iter().all(|(_, n)| *n == 0) {
                    continue;
                }
                if let Some((layout, score)) = self.infer_array(&arrays, &strides, prop_name)
                    && score > best.map_or(0, |b| b.3)
                {
                    best = Some((props, count, layout, score));
                }
            }
        }
        let Some((props_offset, count_offset, prop, score)) = best else {
            self.heuristics.push("RecvTable: no props-array/count layout validated".into());
            return Ok((Vec::new(), json!({})));
        };
        self.heuristics.push(format!(
            "RecvTable: name@{name_offset:#x} props@{props_offset:#x} count@{count_offset:#x}; RecvProp stride {:#x} name@{:#x} ({score} tables validated)",
            prop.stride, prop.name
        ));
        // Sample props across seed tables to infer the remaining RecvProp fields.
        let mut entries = Vec::new();
        for &table in seeds.iter().take(256) {
            let pointer = self.src.u64(table + props_offset).unwrap_or(0);
            let count = self.src.u32(table + count_offset).unwrap_or(0).min(64) as u64;
            entries.extend((0..count).map(|i| pointer + i * prop.stride));
        }
        let rows = self.records(&entries, prop.stride, 2048);
        // Nested table pointer: 0 or a struct with a DT_* name.
        let data_table = match self.layout.get("rp_data_table").and_then(Value::as_u64) {
            Some(offset) => Some(offset),
            None => {
                let mut best: Option<(u64, usize)> = None;
                for offset in (0..prop.stride).step_by(8) {
                    if offset == prop.name {
                        continue;
                    }
                    let (mut good, mut bad) = (0, 0);
                    for row in &rows {
                        let value = u64::from_le_bytes(row[offset as usize..offset as usize + 8].try_into().unwrap());
                        if value == 0 {
                            continue;
                        }
                        if self.named(value + name_offset, is_table_name).is_some() {
                            good += 1;
                        } else {
                            bad += 1;
                        }
                    }
                    if good > 0 && bad * 20 <= good && good > best.map_or(0, |b| b.1) {
                        best = Some((offset, good));
                    }
                }
                best.map(|b| b.0)
            }
        };
        let mut taken = vec![(prop.name, 8)];
        if let Some(offset) = data_table {
            taken.push((offset, 8));
        }
        taken.extend(self.pointer_like(&rows, prop.stride));
        let offsets = match self.layout.get("rp_offset").and_then(Value::as_u64) {
            Some(offset) => vec![(offset, 1.0)],
            None => int_field(&rows, prop.stride, &taken, 0x40_0000, offset_score),
        };
        let offset_field = offsets.first().map(|o| o.0);
        if let Some(offset) = offset_field {
            taken.push((offset, 4));
        }
        let types = match self.layout.get("rp_type").and_then(Value::as_u64) {
            Some(offset) => vec![(offset, 1.0)],
            None => int_field(&rows, prop.stride, &taken, 15, enum_score),
        };
        let type_field = types.first().map(|t| t.0);

        let mut tables = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut total_props = 0usize;
        while let Some(table) = queue.pop_front() {
            if !seen.insert(table) || tables.len() >= limits.tables {
                continue;
            }
            let Some(name) = self.named(table + name_offset, is_table_name) else { continue };
            let pointer = self.src.u64(table + props_offset).unwrap_or(0);
            let count = self.src.u32(table + count_offset).unwrap_or(0).min(4096) as u64;
            let mut props = Vec::new();
            for i in 0..count {
                if total_props >= limits.props {
                    break;
                }
                let entry = pointer + i * prop.stride;
                let Some(prop_name) = self.named(entry + prop.name, is_field_name) else { break };
                self.claimed.insert(entry + prop.name);
                let nested = data_table.and_then(|offset| self.src.u64(entry + offset)).filter(|t| *t != 0);
                let nested_name = nested.and_then(|t| self.named(t + name_offset, is_table_name));
                if let (Some(table), Some(_)) = (nested, &nested_name) {
                    queue.push_back(table);
                }
                let kind = type_field.and_then(|offset| self.src.u32(entry + offset));
                props.push(json!({
                    "name": prop_name,
                    "offset": offset_field.and_then(|offset| self.src.u32(entry + offset)).map(|v| hex(v as u64)),
                    "type": kind,
                    "data_table": nested_name,
                }));
                total_props += 1;
            }
            tables.push(json!({"name": name, "address": self.src.describe(table), "prop_count": count, "props": props}));
        }
        let layout = json!({
            "recv_table": {"name": hex(name_offset), "props": hex(props_offset), "count": hex(count_offset), "tables_validated": score},
            "recv_prop": {
                "stride": hex(prop.stride), "name": hex(prop.name),
                "data_table": data_table.map(hex),
                "offset": offset_field.map(hex), "offset_confidence": confidence(&offsets), "offset_alternatives": alternatives(&offsets),
                "type": type_field.map(hex), "type_confidence": confidence(&types), "type_alternatives": alternatives(&types),
                "type_enum_note": "Raw values; the SDK 2013 SendPropType names are given as type_sdk2013 in the listing and may not match engine forks",
                "layout_matches_sdk2013": prop.stride == 0x60 && prop.name == 0 && offset_field == Some(0x48) && data_table == Some(0x40),
            },
        });
        Ok((tables, layout))
    }
}

// ---- datamaps -----------------------------------------------------------------------

impl Ctx<'_> {
    fn datamaps(&mut self, member_slots: &[u64], limits: &Limits) -> Result<Option<(Vec<Value>, Value)>> {
        let member_slots: Vec<u64> = member_slots.iter().copied().filter(|slot| !self.claimed.contains(slot)).collect();
        let member_slots = member_slots.as_slice();
        if member_slots.len() < 2 {
            self.heuristics.push("Datamaps: too few m_* member-name pointers".into());
            return Ok(None);
        }
        // Element stride: the most common gap between consecutive member-name slots.
        let stride = match self.layout.get("td_stride").and_then(Value::as_u64) {
            Some(stride) => stride,
            None => {
                let mut sorted = member_slots.to_vec();
                sorted.sort_unstable();
                let mut gaps: HashMap<u64, usize> = HashMap::new();
                for pair in sorted.windows(2) {
                    let gap = pair[1] - pair[0];
                    if (0x10..=0x100).contains(&gap) && gap % 8 == 0 {
                        *gaps.entry(gap).or_default() += 1;
                    }
                }
                let Some((gap, _)) = gaps.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))) else {
                    self.heuristics.push("Datamaps: no regular stride between member-name pointers".into());
                    return Ok(None);
                };
                gap
            }
        };
        let name_offsets = candidates(&self.layout, "td_name", (0..stride).step_by(8));
        // Candidate array starts: element k (0..4) of an array whose element
        // name lives at a member slot, for every candidate name offset.
        let mut starts: HashMap<u64, Vec<u64>> = HashMap::new();
        for &slot in member_slots.iter().take(500_000) {
            for &name in &name_offsets {
                for k in 0..4u64 {
                    if let Some(start) = slot.checked_sub(name + k * stride) {
                        starts.entry(start).or_default().push(name);
                    }
                }
            }
        }
        let targets: HashSet<u64> = starts.keys().copied().collect();
        let ranges = self.ranges.clone();
        let hits = self.src.find_pointers(&ranges, &targets, POINTER_CAP)?;
        let desc_offsets = candidates(&self.layout, "dm_desc", qwords(0x18));
        let count_offsets = candidates(&self.layout, "dm_count", (0..=0x24).step_by(4));
        let class_offsets = candidates(&self.layout, "dm_class", qwords(0x30));
        // Score (desc, count, name, class) layouts by fully validated datamaps.
        let mut tally: HashMap<(u64, u64, u64, u64), Vec<u64>> = HashMap::new();
        for &(slot, value) in hits.iter().take(100_000) {
            let Some(names) = starts.get(&value) else { continue };
            let names: BTreeSet<u64> = names.iter().copied().collect();
            for &desc in &desc_offsets {
                let Some(map) = slot.checked_sub(desc) else { continue };
                for &count_offset in &count_offsets {
                    if overlaps(count_offset, 4, &[(desc, 8)]) {
                        continue;
                    }
                    let Some(count) = self.src.u32(map + count_offset) else { continue };
                    if !(1..=4096).contains(&count) {
                        continue;
                    }
                    for &name in &names {
                        let valid = (0..count.min(48) as u64).all(|i| self.named(value + i * stride + name, is_field_name).is_some());
                        if !valid {
                            continue;
                        }
                        for &class in &class_offsets {
                            if overlaps(class, 8, &[(desc, 8), (count_offset, 4)]) {
                                continue;
                            }
                            if self.named(map + class, is_identifier).is_some_and(|text| !text.starts_with("DT_")) {
                                tally.entry((desc, count_offset, name, class)).or_default().push(map);
                            }
                        }
                    }
                }
            }
        }
        // Several start offsets can validate the same structs (a layout shifted by
        // 8 bytes reads the same fields). Base-map pointers point at true struct
        // starts, so rank layouts by validated maps plus resolved base links.
        let mut ranked: Vec<(MapLayout, Vec<u64>)> = tally.into_iter().collect();
        ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        let top = ranked.first().map_or(0, |r| r.1.len());
        let base_override = self.layout.get("dm_base").and_then(Value::as_u64);
        let mut best: Option<(MapLayout, Vec<u64>, Option<u64>, usize)> = None;
        for (key, mut maps) in ranked.into_iter().filter(|r| r.1.len() * 2 >= top).take(16) {
            maps.sort_unstable();
            maps.dedup();
            let (desc, count_offset, _, class) = key;
            let set: HashSet<u64> = maps.iter().copied().collect();
            let (base, links) = match base_override {
                Some(offset) => (Some(offset), maps.iter().filter(|m| self.src.u64(**m + offset).is_some_and(|b| set.contains(&b))).count()),
                None => self
                    .pointer_field(&maps, &qwords(0x30).collect::<Vec<_>>(), &[(desc, 8), (count_offset, 4), (class, 8)], |_, value| set.contains(&value))
                    .map_or((None, 0), |(offset, hits)| (Some(offset), hits)),
            };
            let score = maps.len() + links;
            if score > best.as_ref().map_or(0, |b| b.1.len() + b.3) {
                best = Some((key, maps, base, links));
            }
        }
        let Some(((desc, count_offset, name, class), mut maps, base, links)) = best else {
            self.heuristics.push(format!("Datamaps: no datamap_t validated (stride {stride:#x})"));
            return Ok(None);
        };
        maps.truncate(limits.datamaps);
        let map_set: HashSet<u64> = maps.iter().copied().collect();
        self.heuristics.push(format!("Datamaps: layout chosen by {} validated maps + {links} base links", maps.len()));
        // typedescription_t integer fields from sampled entries.
        let mut entries = Vec::new();
        for &map in maps.iter().take(256) {
            let pointer = self.src.u64(map + desc).unwrap_or(0);
            let count = self.src.u32(map + count_offset).unwrap_or(0).min(64) as u64;
            entries.extend((0..count).map(|i| pointer + i * stride));
        }
        let rows = self.records(&entries, stride, 2048);
        let mut taken = vec![(name, 8)];
        taken.extend(self.pointer_like(&rows, stride));
        let offsets = match self.layout.get("td_offset").and_then(Value::as_u64) {
            Some(offset) => vec![(offset, 1.0)],
            None => int_field(&rows, stride, &taken, 0x40_0000, offset_score),
        };
        let offset_field = offsets.first().map(|o| o.0);
        if let Some(offset) = offset_field {
            taken.push((offset, 4));
        }
        let types = match self.layout.get("td_type").and_then(Value::as_u64) {
            Some(offset) => vec![(offset, 1.0)],
            None => int_field(&rows, stride, &taken, 64, enum_score),
        };
        let type_field = types.first().map(|t| t.0);
        self.heuristics.push(format!(
            "Datamaps: {} maps; datamap desc@{desc:#x} count@{count_offset:#x} class@{class:#x}; typedescription stride {stride:#x} name@{name:#x}",
            maps.len()
        ));
        let mut out = Vec::new();
        let mut total = 0usize;
        for &map in &maps {
            let pointer = self.src.u64(map + desc).unwrap_or(0);
            let count = self.src.u32(map + count_offset).unwrap_or(0) as u64;
            let mut fields = Vec::new();
            for i in 0..count.min(4096) {
                if total >= limits.props {
                    break;
                }
                let entry = pointer + i * stride;
                let Some(field) = self.named(entry + name, is_field_name) else { break };
                fields.push(json!({
                    "name": field,
                    "offset": offset_field.and_then(|offset| self.src.u32(entry + offset)).map(|v| hex(v as u64)),
                    "type": type_field.and_then(|offset| self.src.u32(entry + offset)),
                }));
                total += 1;
            }
            let base_map = base.and_then(|offset| self.src.u64(map + offset)).filter(|b| map_set.contains(b));
            let base_name = base_map.and_then(|b| self.named(b + class, is_identifier));
            out.push(json!({
                "class": self.named(map + class, is_identifier),
                "base": base_name,
                "address": self.src.describe(map),
                "field_count": count,
                "fields": fields,
            }));
        }
        let layout = json!({
            "datamap": {"desc": hex(desc), "count": hex(count_offset), "class": hex(class), "base": base.map(hex)},
            "typedescription": {
                "stride": hex(stride), "name": hex(name),
                "offset": offset_field.map(hex), "offset_confidence": confidence(&offsets), "offset_alternatives": alternatives(&offsets),
                "type": type_field.map(hex), "type_confidence": confidence(&types), "type_alternatives": alternatives(&types),
            },
        });
        Ok(Some((out, layout)))
    }

    // ---- ConVars / ConCommands ------------------------------------------------------

    fn convars(&mut self, anchors: &[u64], limits: &Limits) -> Option<(Vec<Value>, Value)> {
        let names = candidates(&self.layout, "cv_name", qwords(0x30));
        let nexts = candidates(&self.layout, "cv_next", qwords(0x30));
        let Some(chain) = self.infer_chain(anchors, is_command_name, &names, &nexts) else {
            self.heuristics.push(format!("ConCommandBase: no linked list among {} cvar-name pointers", anchors.len()));
            return None;
        };
        let nodes = self.collect_chain(anchors, chain, is_command_name, limits.convars);
        let taken = [(chain.name, 8), (chain.next, 8)];
        let help = match self.layout.get("cv_help").and_then(Value::as_u64) {
            Some(offset) => Some(offset),
            None => {
                // Most nodes must point at readable text; prefer the field with the
                // most non-empty strings (a vtable pointer can read as "").
                let sample = sample(&nodes, 96);
                let mut best: Option<(u64, usize, usize)> = None;
                for offset in qwords(0x40) {
                    if overlaps(offset, 8, &taken) {
                        continue;
                    }
                    let (mut hits, mut filled) = (0, 0);
                    for &node in &sample {
                        let Some(value) = self.src.u64(node + offset).filter(|v| *v != 0 && !self.src.is_exec(*v)) else { continue };
                        if let Some(text) = self.text(value, 1024) {
                            hits += 1;
                            filled += usize::from(!text.is_empty());
                        }
                    }
                    if hits * 2 >= sample.len() && filled > 0 && (filled, hits) > best.map_or((0, 0), |b| (b.2, b.1)) {
                        best = Some((offset, hits, filled));
                    }
                }
                best.map(|b| b.0)
            }
        };
        let sdk = chain.name == 0x18 && chain.next == 0x8 && help == Some(0x20);
        self.heuristics.push(format!(
            "ConCommandBase: name@{:#x} next@{:#x} help@{}; {} entries{}",
            chain.name,
            chain.next,
            help.map_or("?".into(), hex),
            nodes.len(),
            if sdk { "; SDK 2013 layout, flags read at 0x28" } else { "" }
        ));
        let entries = nodes
            .iter()
            .map(|&node| {
                let name = self.named(node + chain.name, is_command_name);
                let help_text = help.and_then(|offset| self.src.u64(node + offset)).and_then(|p| self.text(p, 1024));
                let flags = sdk.then(|| self.src.u32(node + 0x28)).flatten();
                json!({"name": name, "help": help_text, "flags": flags.map(|f| hex(f as u64)), "address": self.src.describe(node)})
            })
            .collect();
        let layout = json!({"name": hex(chain.name), "next": hex(chain.next), "help": help.map(hex),
            "flags": sdk.then(|| hex(0x28)), "layout_matches_sdk2013": sdk, "linked_edges_scored": chain.edges});
        Some((entries, layout))
    }

    // ---- InterfaceReg -------------------------------------------------------------------

    fn interfaces(&mut self, anchors: &[u64], limits: &Limits) -> Option<(Vec<Value>, Value)> {
        let names = candidates(&self.layout, "if_name", qwords(0x18));
        let nexts = candidates(&self.layout, "if_next", qwords(0x18));
        let Some(chain) = self.infer_chain(anchors, is_interface_name, &names, &nexts) else {
            self.heuristics.push(format!("InterfaceReg: no linked list among {} interface-name pointers", anchors.len()));
            return None;
        };
        let nodes = self.collect_chain(anchors, chain, is_interface_name, limits.interfaces);
        let create = match self.layout.get("if_create").and_then(Value::as_u64) {
            Some(offset) => Some(offset),
            None => self
                .pointer_field(&nodes, &qwords(0x18).collect::<Vec<_>>(), &[(chain.name, 8), (chain.next, 8)], |ctx, value| ctx.src.is_exec(value))
                .map(|b| b.0),
        };
        self.heuristics.push(format!("InterfaceReg: name@{:#x} next@{:#x}; {} interfaces", chain.name, chain.next, nodes.len()));
        let entries = nodes
            .iter()
            .map(|&node| {
                let name = self.named(node + chain.name, is_interface_name);
                let function = create.and_then(|offset| self.src.u64(node + offset)).filter(|f| self.src.is_exec(*f));
                json!({"name": name, "create_fn": function.map(|f| self.src.describe(f)), "address": self.src.describe(node)})
            })
            .collect();
        let layout = json!({"name": hex(chain.name), "next": hex(chain.next), "create_fn": create.map(hex),
            "layout_matches_sdk2013": chain.name == 0x8 && chain.next == 0x10 && create == Some(0)});
        Some((entries, layout))
    }
}

// ---- tool entry -------------------------------------------------------------------------

struct Limits {
    classes: usize,
    tables: usize,
    props: usize,
    datamaps: usize,
    convars: usize,
    interfaces: usize,
}

fn listing(result: &Value) -> String {
    let mut out = String::new();
    let line = |out: &mut String, text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    line(&mut out, format!("// {FORMAT} — offsets are inferred; see layouts + heuristics in the JSON artifact"));
    for class in result["client_classes"].as_array().into_iter().flatten() {
        line(&mut out, format!("class {} id={} table={}", class["name"].as_str().unwrap_or("?"), class["class_id"], class["recv_table"].as_str().unwrap_or("-")));
    }
    for table in result["recv_tables"].as_array().into_iter().flatten() {
        line(&mut out, format!("\ntable {}", table["name"].as_str().unwrap_or("?")));
        for prop in table["props"].as_array().into_iter().flatten() {
            let kind = prop["type"].as_u64().map(|t| {
                sdk2013_prop_type(t as u32).map_or(format!("type={t}"), |name| format!("type={t} ({name} in SDK 2013)"))
            });
            line(&mut out, format!(
                "  {:<40} {:>10}  {}{}",
                prop["name"].as_str().unwrap_or("?"),
                prop["offset"].as_str().unwrap_or("?"),
                kind.unwrap_or_default(),
                prop["data_table"].as_str().map(|t| format!(" -> {t}")).unwrap_or_default()
            ));
        }
    }
    for map in result["datamaps"].as_array().into_iter().flatten() {
        line(&mut out, format!("\ndatamap {} : {}", map["class"].as_str().unwrap_or("?"), map["base"].as_str().unwrap_or("-")));
        for field in map["fields"].as_array().into_iter().flatten() {
            line(&mut out, format!("  {:<40} {:>10}  type={}", field["name"].as_str().unwrap_or("?"), field["offset"].as_str().unwrap_or("?"), field["type"]));
        }
    }
    if let Some(convars) = result["convars"].as_array().filter(|c| !c.is_empty()) {
        line(&mut out, "\nconvars/concommands".into());
        for cvar in convars {
            line(&mut out, format!("  {:<40} {}", cvar["name"].as_str().unwrap_or("?"), cvar["help"].as_str().unwrap_or("").replace('\n', " ")));
        }
    }
    if let Some(interfaces) = result["interfaces"].as_array().filter(|i| !i.is_empty()) {
        line(&mut out, "\ninterfaces".into());
        for interface in interfaces {
            line(&mut out, format!("  {:<40} {}", interface["name"].as_str().unwrap_or("?"), interface["create_fn"]["address"].as_str().unwrap_or("-")));
        }
    }
    out
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let mut spec = TargetSpec::from_args(args, "artifact", "module")?;
    ensure!(spec.is_specified(), "Give a mapped artifact (ELF, or raw dump with base) or a pid");
    if spec.pid.is_some() && spec.module.is_none() {
        spec.module = Some("eboot.bin".into());
    }
    let sections: Vec<String> = match args["sections"].as_array() {
        Some(items) => items.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        None => SECTIONS.iter().map(|s| (*s).to_owned()).collect(),
    };
    let want = |section: &str| sections.iter().any(|s| s == section);
    let limit = |key: &str, default: u64| args[key].as_u64().unwrap_or(default) as usize;
    let limits = Limits {
        classes: limit("max_classes", 4096),
        tables: limit("max_tables", 8192),
        props: limit("max_props", 500_000),
        datamaps: limit("max_datamaps", 8192),
        convars: limit("max_convars", 20_000),
        interfaces: limit("max_interfaces", 1024),
    };
    let source = Source::open(workbench, &spec, Mode::Mapped)?;
    let mut ranges = source.ranges_with(PROT_R, PROT_X);
    ranges.sort_unstable();
    let mut ctx = Ctx {
        src: source,
        strings: HashMap::new(),
        names: HashMap::new(),
        ranges,
        heuristics: Vec::new(),
        layout: args.get("layout").cloned().unwrap_or(json!({})),
        claimed: HashSet::new(),
    };
    ensure!(!ctx.ranges.is_empty(), "No readable non-executable ranges selected");
    ctx.index_strings()?;
    let slots = ctx.anchor_slots()?;
    let empty = Vec::new();
    let slots_of = |kind: u8| slots.get(&kind).unwrap_or(&empty);

    let mut layouts = json!({});
    let mut result = json!({"format": FORMAT, "image_base": hex(ctx.src.image_base)});
    if (want("client_classes") || want("recv_tables"))
        && let Some(net) = ctx.client_classes(slots_of(KIND_CLASS), &limits)?
    {
        for (key, value) in net.layout.as_object().into_iter().flatten() {
            layouts[key] = value.clone();
        }
        result["client_classes"] = if want("client_classes") { json!(net.classes) } else { json!([]) };
        result["recv_tables"] = if want("recv_tables") { json!(net.tables) } else { json!([]) };
    }
    if want("datamaps")
        && let Some((maps, layout)) = ctx.datamaps(slots_of(KIND_MEMBER), &limits)?
    {
        result["datamaps"] = json!(maps);
        for (key, value) in layout.as_object().into_iter().flatten() {
            layouts[key] = value.clone();
        }
    }
    if want("convars")
        && let Some((convars, layout)) = ctx.convars(slots_of(KIND_CVAR), &limits)
    {
        result["convars"] = json!(convars);
        layouts["concommandbase"] = layout;
    }
    if want("interfaces")
        && let Some((interfaces, layout)) = ctx.interfaces(slots_of(KIND_IFACE), &limits)
    {
        result["interfaces"] = json!(interfaces);
        layouts["interface_reg"] = layout;
    }
    for key in SECTIONS {
        if result.get(key).is_none() {
            result[key] = json!([]);
        }
    }
    result["layouts"] = layouts;
    result["heuristics"] = json!(ctx.heuristics);
    result["source"] = ctx.src.summary();
    result["note"] = json!("Layouts are inferred from how anchor strings link up, not assumed; check the per-field confidence and alternatives, and pin offsets with `layout` when a fork disagrees. Type enums are raw values.");

    let counts = json!({
        "client_classes": result["client_classes"].as_array().map_or(0, Vec::len),
        "recv_tables": result["recv_tables"].as_array().map_or(0, Vec::len),
        "recv_props": result["recv_tables"].as_array().into_iter().flatten().map(|t| t["props"].as_array().map_or(0, Vec::len)).sum::<usize>(),
        "datamaps": result["datamaps"].as_array().map_or(0, Vec::len),
        "convars": result["convars"].as_array().map_or(0, Vec::len),
        "interfaces": result["interfaces"].as_array().map_or(0, Vec::len),
    });
    let metadata = json!({"tool": "source_dump", "format": FORMAT, "source": ctx.src.label, "counts": counts});
    let saved = save_json(workbench, "source-dump", &result, metadata.clone())?;
    let text = save_text(workbench, "source-dump-listing", &listing(&result), "txt", metadata)?;
    Ok(json!({
        "artifact": artifact_ref(&saved),
        "listing": artifact_ref(&text),
        "counts": counts,
        "layouts": result["layouts"],
        "heuristics": result["heuristics"],
        "source": result["source"],
        "sample_classes": result["client_classes"].as_array().map(|c| c.iter().take(16).cloned().collect::<Vec<_>>()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytesource::testutil::build_elf;
    use crate::config::Profile;
    use crate::tools::ToolRegistry;

    /// Field offsets for one synthetic engine variant.
    struct Variant {
        cc_size: u64,
        cc_name: u64,
        cc_next: u64,
        cc_table: u64,
        cc_id: u64,
        rt_size: u64,
        rt_props: u64,
        rt_count: u64,
        rt_name: u64,
        rp_stride: u64,
        rp_name: u64,
        rp_type: u64,
        rp_table: u64,
        rp_offset: u64,
        cv_size: u64,
        cv_name: u64,
        cv_next: u64,
        cv_help: u64,
        if_size: u64,
        if_create: u64,
        if_name: u64,
        if_next: u64,
        dm_desc: u64,
        dm_count: u64,
        dm_class: u64,
        dm_base: u64,
        td_stride: u64,
        td_name: u64,
        td_offset: u64,
        td_type: u64,
    }

    /// Public Source SDK 2013 (64-bit) layouts.
    const SDK2013: Variant = Variant {
        cc_size: 0x30, cc_name: 0x10, cc_next: 0x20, cc_table: 0x18, cc_id: 0x28,
        rt_size: 0x28, rt_props: 0x0, rt_count: 0x8, rt_name: 0x18,
        rp_stride: 0x60, rp_name: 0x0, rp_type: 0x8, rp_table: 0x40, rp_offset: 0x48,
        cv_size: 0x30, cv_name: 0x18, cv_next: 0x8, cv_help: 0x20,
        if_size: 0x18, if_create: 0x0, if_name: 0x8, if_next: 0x10,
        dm_desc: 0x0, dm_count: 0x8, dm_class: 0x10, dm_base: 0x18,
        td_stride: 0x80, td_name: 0x8, td_offset: 0x10, td_type: 0x0,
    };

    /// A deliberately reshuffled fork layout (not a claim about any real engine).
    const FORK: Variant = Variant {
        cc_size: 0x48, cc_name: 0x28, cc_next: 0x8, cc_table: 0x38, cc_id: 0x44,
        rt_size: 0x40, rt_props: 0x10, rt_count: 0x30, rt_name: 0x20,
        rp_stride: 0x38, rp_name: 0x18, rp_type: 0x0, rp_table: 0x28, rp_offset: 0x30,
        cv_size: 0x50, cv_name: 0x30, cv_next: 0x10, cv_help: 0x40,
        if_size: 0x20, if_create: 0x10, if_name: 0x0, if_next: 0x18,
        dm_desc: 0x8, dm_count: 0x18, dm_class: 0x10, dm_base: 0x20,
        td_stride: 0x48, td_name: 0x10, td_offset: 0x20, td_type: 0x4,
    };

    const TEXT: u64 = 0x40_0000;
    const RODATA: u64 = 0x50_0000;
    const DATA: u64 = 0x60_0000;

    struct Image {
        rodata: Vec<u8>,
        data: Vec<u8>,
    }

    impl Image {
        fn string(&mut self, text: &str) -> u64 {
            let at = RODATA + self.rodata.len() as u64;
            self.rodata.extend_from_slice(text.as_bytes());
            self.rodata.push(0);
            at
        }
        fn alloc(&mut self, size: u64) -> u64 {
            while !self.data.len().is_multiple_of(16) {
                self.data.push(0);
            }
            let at = DATA + self.data.len() as u64;
            self.data.resize(self.data.len() + size as usize, 0);
            at
        }
        fn q(&mut self, at: u64, value: u64) {
            let o = (at - DATA) as usize;
            self.data[o..o + 8].copy_from_slice(&value.to_le_bytes());
        }
        fn d(&mut self, at: u64, value: u32) {
            let o = (at - DATA) as usize;
            self.data[o..o + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// Build an image with 3 client classes / nested recv tables, 2 datamaps,
    /// 4 convars and 3 interfaces in variant `v`'s layout.
    fn image(v: &Variant) -> Vec<u8> {
        let mut img = Image { rodata: vec![0], data: Vec::new() };
        // Recv tables: DT_BaseEntity (2 props), DT_Local (nested, 2 props), DT_Player (3 props incl. nested).
        let table = |img: &mut Image, name: &str, props: &[(&str, u32, u32, u64)]| -> u64 {
            let array = img.alloc(v.rp_stride * props.len() as u64);
            for (i, (prop, kind, offset, nested)) in props.iter().enumerate() {
                let entry = array + i as u64 * v.rp_stride;
                let name = img.string(prop);
                img.q(entry + v.rp_name, name);
                img.d(entry + v.rp_type, *kind);
                img.d(entry + v.rp_offset, *offset);
                img.q(entry + v.rp_table, *nested);
            }
            let table = img.alloc(v.rt_size);
            let name = img.string(name);
            img.q(table + v.rt_props, array);
            img.d(table + v.rt_count, props.len() as u32);
            img.q(table + v.rt_name, name);
            table
        };
        let base = table(&mut img, "DT_BaseEntity", &[("m_vecOrigin", 2, 0x14c, 0), ("m_iTeamNum", 0, 0x3f4, 0)]);
        let local = table(&mut img, "DT_Local", &[("m_iHideHUD", 0, 0x4, 0), ("m_flFOVRate", 1, 0x10, 0)]);
        let player = table(&mut img, "DT_Player", &[("baseclass", 6, 0, base), ("m_Local", 6, 0x1200, local), ("m_iHealth", 0, 0x4a8, 0)]);
        let weapon = table(&mut img, "DT_WeaponX", &[("baseclass", 6, 0, base), ("m_ammoInClip", 0, 0x1650, 0)]);
        // Client classes (linked list, head = last allocated).
        let mut next = 0u64;
        for (index, (name, recv)) in [("CBaseEntity", base), ("CPlayer", player), ("CWeaponX", weapon)].iter().enumerate() {
            let node = img.alloc(v.cc_size);
            let name = img.string(name);
            img.q(node + v.cc_name, name);
            img.q(node + v.cc_table, *recv);
            img.q(node + v.cc_next, next);
            img.d(node + v.cc_id, index as u32);
            next = node;
        }
        // Datamaps: C_BaseEntity (3 fields) <- C_Player (2 fields).
        let datamap = |img: &mut Image, class: &str, fields: &[(&str, u32, u32)], base_map: u64| -> u64 {
            let array = img.alloc(v.td_stride * fields.len() as u64);
            for (i, (field, kind, offset)) in fields.iter().enumerate() {
                let entry = array + i as u64 * v.td_stride;
                let name = img.string(field);
                img.q(entry + v.td_name, name);
                img.d(entry + v.td_type, *kind);
                img.d(entry + v.td_offset, *offset);
            }
            let map = img.alloc(0x40);
            let class = img.string(class);
            img.q(map + v.dm_desc, array);
            img.d(map + v.dm_count, fields.len() as u32);
            img.q(map + v.dm_class, class);
            img.q(map + v.dm_base, base_map);
            map
        };
        let entity = datamap(&mut img, "C_BaseEntity", &[("m_vecAbsOrigin", 3, 0x58), ("m_fFlags", 5, 0x98), ("m_iEFlags", 5, 0x9c)], 0);
        datamap(&mut img, "C_Player", &[("m_flMaxspeed", 1, 0x2b0), ("m_hGroundEntity", 13, 0x2c4)], entity);
        // ConVars.
        // One shared ConVar vtable in read-only data (as compilers emit it).
        while !img.rodata.len().is_multiple_of(8) {
            img.rodata.push(0);
        }
        let vtable = RODATA + img.rodata.len() as u64;
        for slot in 0..4u64 {
            img.rodata.extend_from_slice(&(TEXT + 0x10 * (slot + 1)).to_le_bytes());
        }
        let mut next = 0u64;
        for (name, help) in [("sv_cheats", "Allow cheats on server"), ("mat_fullbright", ""), ("quit", "Exit the engine."), ("cl_showfps", "Draw fps meter")] {
            let node = img.alloc(v.cv_size);
            img.q(node, vtable);
            let (name, help) = (img.string(name), img.string(help));
            img.q(node + v.cv_name, name);
            img.q(node + v.cv_help, help);
            img.q(node + v.cv_next, next);
            next = node;
        }
        // Interfaces.
        let mut next = 0u64;
        for (index, name) in ["VClient018", "VEngineClient014", "VModelInfoClient004"].iter().enumerate() {
            let node = img.alloc(v.if_size);
            let name = img.string(name);
            img.q(node + v.if_name, name);
            img.q(node + v.if_create, TEXT + 0x100 * (index as u64 + 1));
            img.q(node + v.if_next, next);
            next = node;
        }
        build_elf(&[(TEXT, 5, vec![0xc3; 0x1000]), (RODATA, 4, img.rodata), (DATA, 6, img.data)], &[], &[])
    }

    fn registry(directory: &std::path::Path) -> ToolRegistry {
        let mut data: Value = serde_json::from_str(include_str!("../tests/fixtures/profile.json")).unwrap();
        data["artifact_directory"] = json!("artifacts");
        data["qualification_file"] = json!("qualification.json");
        let path = directory.join("profile.json");
        std::fs::write(&path, data.to_string()).unwrap();
        ToolRegistry::new(Workbench::new(Profile::load(&path).unwrap()).unwrap()).unwrap()
    }

    fn dump(registry: &mut ToolRegistry, elf: &[u8], extra: Value) -> Value {
        let saved = registry.workbench.store.save("module", elf, json!({}), "elf").unwrap();
        let mut args = json!({"artifact": saved["path"]});
        for (key, value) in extra.as_object().into_iter().flatten() {
            args[key] = value.clone();
        }
        let summary = registry.call("source_dump", args).unwrap();
        let path = summary["artifact"]["path"].as_str().unwrap().to_owned();
        serde_json::from_slice(&registry.workbench.store.read(&path).unwrap()).unwrap()
    }

    fn check(variant: &Variant, result: &Value) {
        let layouts = &result["layouts"];
        assert_eq!(layouts["client_class"]["name"], hex(variant.cc_name), "{layouts:#}");
        assert_eq!(layouts["client_class"]["next"], hex(variant.cc_next));
        assert_eq!(layouts["client_class"]["recv_table"], hex(variant.cc_table));
        assert_eq!(layouts["client_class"]["class_id"], hex(variant.cc_id));
        assert_eq!(layouts["recv_table"]["props"], hex(variant.rt_props));
        assert_eq!(layouts["recv_table"]["count"], hex(variant.rt_count));
        assert_eq!(layouts["recv_prop"]["stride"], hex(variant.rp_stride));
        assert_eq!(layouts["recv_prop"]["name"], hex(variant.rp_name));
        assert_eq!(layouts["recv_prop"]["data_table"], hex(variant.rp_table));
        assert_eq!(layouts["recv_prop"]["offset"], hex(variant.rp_offset));
        assert_eq!(layouts["recv_prop"]["type"], hex(variant.rp_type));

        let classes: Vec<&str> = result["client_classes"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(classes, ["CWeaponX", "CPlayer", "CBaseEntity"]);
        assert_eq!(result["client_classes"][1]["class_id"], 1);
        assert_eq!(result["client_classes"][1]["recv_table"], "DT_Player");
        let tables = result["recv_tables"].as_array().unwrap();
        assert_eq!(tables.len(), 4, "nested DT_Local and DT_BaseEntity are reached");
        let player = tables.iter().find(|t| t["name"] == "DT_Player").unwrap();
        assert_eq!(player["props"][1], json!({"name": "m_Local", "offset": "0x1200", "type": 6, "data_table": "DT_Local"}));
        assert_eq!(player["props"][2]["offset"], "0x4a8");

        let maps = result["datamaps"].as_array().unwrap();
        assert_eq!(maps.len(), 2, "{:#}", result["heuristics"]);
        let player_map = maps.iter().find(|m| m["class"] == "C_Player").unwrap();
        assert_eq!(player_map["base"], "C_BaseEntity", "{:#}", layouts["datamap"]);
        assert_eq!(player_map["fields"][0], json!({"name": "m_flMaxspeed", "offset": "0x2b0", "type": 1}));
        assert_eq!(layouts["typedescription"]["stride"], hex(variant.td_stride));

        let convars: Vec<&str> = result["convars"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(convars, ["cl_showfps", "quit", "mat_fullbright", "sv_cheats"], "{:#}", layouts["concommandbase"]);
        assert_eq!(result["convars"][3]["help"], "Allow cheats on server");
        assert_eq!(layouts["concommandbase"]["help"], hex(variant.cv_help));

        let interfaces: Vec<&str> = result["interfaces"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap()).collect();
        assert_eq!(interfaces, ["VModelInfoClient004", "VEngineClient014", "VClient018"]);
        assert_eq!(result["interfaces"][2]["create_fn"]["address"], hex(TEXT + 0x100));
    }

    #[test]
    fn recovers_sdk2013_layout() {
        let directory = tempfile::tempdir().unwrap();
        let mut registry = registry(directory.path());
        let result = dump(&mut registry, &image(&SDK2013), json!({}));
        check(&SDK2013, &result);
        assert_eq!(result["layouts"]["client_class"]["layout_matches_sdk2013"], true);
        assert_eq!(result["layouts"]["recv_prop"]["layout_matches_sdk2013"], true);
        assert_eq!(result["convars"][3]["flags"], "0x0", "SDK layout exposes flags");
    }

    #[test]
    fn infers_reshuffled_fork_layout_without_hints() {
        let directory = tempfile::tempdir().unwrap();
        let mut registry = registry(directory.path());
        let result = dump(&mut registry, &image(&FORK), json!({}));
        check(&FORK, &result);
        assert_eq!(result["layouts"]["client_class"]["layout_matches_sdk2013"], false);
        assert!(result["convars"][0]["flags"].is_null(), "flags are not guessed for unknown layouts");
    }

    #[test]
    fn overrides_and_section_selection() {
        let directory = tempfile::tempdir().unwrap();
        let mut registry = registry(directory.path());
        let result = dump(&mut registry, &image(&FORK), json!({"sections": ["convars"], "layout": {"cv_name": 0x30, "cv_next": 0x10}}));
        assert_eq!(result["convars"].as_array().unwrap().len(), 4);
        assert_eq!(result["client_classes"], json!([]));
        assert_eq!(result["layouts"]["concommandbase"]["name"], "0x30");
        // A wrong override is honoured (no silent fallback) and finds nothing.
        let wrong = dump(&mut registry, &image(&FORK), json!({"sections": ["interfaces"], "layout": {"if_name": 0x8}}));
        assert_eq!(wrong["interfaces"], json!([]));
    }

    #[test]
    fn name_predicates() {
        assert!(is_class_name("CPlayer") && is_class_name("CAI_BaseNPC") && !is_class_name("Cplayer"));
        assert!(is_table_name("DT_Player") && !is_table_name("DT_"));
        assert!(is_cvar_anchor("sv_cheats") && !is_cvar_anchor("quit") && is_command_name("+attack"));
        assert!(is_interface_name("VClient018") && !is_interface_name("VClient18"));
        assert!(is_field_name("m_hMyWeapons[0]") && is_field_name("000") && !is_field_name("bad name"));
    }

    #[test]
    fn live_dump_through_fixture() {
        // Serve the SDK image's segments as process memory of module eboot.bin.
        let elf = image(&SDK2013);
        // Rebuild process memory from the ELF program headers.
        let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;
        let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
        let mut extra_maps = Vec::new();
        let mut extra_memory = Vec::new();
        for i in 0..phnum {
            let ph = &elf[phoff + i * 56..phoff + (i + 1) * 56];
            if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
                continue;
            }
            let flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
            let offset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let size = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
            if !(TEXT..=DATA).contains(&vaddr) {
                continue;
            }
            let prot = (if flags & 4 != 0 { 1 } else { 0 }) | (if flags & 2 != 0 { 2 } else { 0 }) | (if flags & 1 != 0 { 4 } else { 0 });
            extra_maps.push((vaddr, vaddr + ((size as u64 + 0xfff) & !0xfff), prot, "eboot.bin".to_owned()));
            extra_memory.push((vaddr, elf[offset..offset + size].to_vec()));
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = crate::debugger::fake::spawn_fixture(
            listener,
            crate::debugger::fake::Fixture { pid: 95, base: 0x10_0000, image: vec![0xc3; 0x100], extra_maps, extra_memory, ..Default::default() },
        );
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), fake.port);
        let mut registry = ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let summary = registry.call("source_dump", json!({"pid": 95})).unwrap();
        assert_eq!(summary["counts"]["client_classes"], 3, "{summary:#}");
        assert_eq!(summary["counts"]["interfaces"], 3);
        assert_eq!(summary["source"]["kind"], "live");
        let listing = registry.workbench.store.read(summary["listing"]["path"].as_str().unwrap()).unwrap();
        let listing = String::from_utf8(listing).unwrap();
        assert!(listing.contains("table DT_Player") && listing.contains("m_iHealth"), "{listing}");
        assert!(summary["sample_classes"][0]["address"]["module"] == "eboot.bin");
    }
}
