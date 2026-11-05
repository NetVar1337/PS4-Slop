//! Function matching between two builds of a module, and porting of names /
//! annotations through a diff result.

use iced_x86::FlowControl;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

use crate::binimage::Image;
use crate::cfg::{Discovery, decode_at, hex, near_target};
use crate::sigmaker::mask_for;

pub const DIFF_FORMAT: &str = "ps4wb-bindiff-v1";
pub const PORT_FORMAT: &str = "ps4wb-ported-annotations-v1";
const MAX_ALIGN: usize = 4000;

#[derive(Clone, Debug, Default)]
pub struct Features {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub exact: String,
    pub mnemonic_hash: String,
    pub mnemonics: Vec<u16>,
    pub insn_addrs: Vec<u64>,
    pub blocks: usize,
    pub edges: usize,
    pub calls: usize,
    pub constants: BTreeSet<u64>,
    pub strings: BTreeSet<String>,
    pub callees: Vec<u64>,
    pub imports: Vec<String>,
}

fn c_string(image: &Image, va: u64) -> Option<String> {
    if image.is_exec(va) {
        return None;
    }
    let bytes = image.bytes_from(va)?;
    let len = bytes.iter().take(257).position(|b| *b == 0)?;
    let text = &bytes[..len];
    (len >= 4 && text.iter().all(|b| b.is_ascii_graphic() || *b == b' ')).then(|| String::from_utf8_lossy(text).into_owned())
}

pub fn features(image: &Image, discovery: &Discovery) -> Vec<Features> {
    discovery
        .functions
        .iter()
        .map(|function| {
            let mut exact = Sha256::new();
            let mut mnemonic = Sha256::new();
            let mut item = Features {
                start: function.start,
                end: function.end,
                name: function.name.clone(),
                blocks: function.cfg.blocks.len(),
                edges: function.cfg.edge_count(),
                calls: function.cfg.calls.len(),
                insn_addrs: function.cfg.insn_addrs.clone(),
                ..Default::default()
            };
            for &va in &function.cfg.insn_addrs {
                let Some((instruction, offsets)) = decode_at(image, va) else { continue };
                let bytes = image.read(va, instruction.len()).unwrap_or_default();
                let mask = mask_for(image, &instruction, &offsets, false);
                let masked: Vec<u8> = bytes.iter().zip(&mask).map(|(b, w)| if *w { 0 } else { *b }).collect();
                exact.update(&masked);
                let code = instruction.mnemonic() as u16;
                mnemonic.update(code.to_le_bytes());
                item.mnemonics.push(code);
                if instruction.is_ip_rel_memory_operand()
                    && let Some(text) = c_string(image, instruction.ip_rel_memory_address())
                    && item.strings.len() < 64
                {
                    item.strings.insert(text);
                }
                if near_target(&instruction).is_none() && offsets.has_immediate() && !mask.iter().any(|w| *w) {
                    for op in 0..instruction.op_count() {
                        if let Ok(value) = instruction.try_immediate(op)
                            && value >= 0x100
                            && value != u64::MAX
                            && value != u32::MAX as u64
                            && item.constants.len() < 64
                        {
                            item.constants.insert(value);
                        }
                    }
                }
                if instruction.flow_control() == FlowControl::Call
                    && let Some(target) = near_target(&instruction)
                    && !item.callees.contains(&target)
                {
                    item.callees.push(target);
                }
            }
            for call in &function.cfg.calls {
                if let Some(import) = &call.import {
                    item.imports.push(import.clone());
                }
            }
            item.exact = hex::encode(&exact.finalize()[..16]);
            item.mnemonic_hash = hex::encode(&mnemonic.finalize()[..16]);
            item
        })
        .collect()
}

/// Jaccard similarity of mnemonic trigram sets.
pub fn similarity(a: &[u16], b: &[u16]) -> f64 {
    let grams = |seq: &[u16]| -> BTreeSet<(u16, u16, u16)> {
        if seq.len() < 3 {
            return seq.iter().map(|m| (*m, 0, 0)).collect();
        }
        seq.windows(3).map(|w| (w[0], w[1], w[2])).collect()
    };
    let (ga, gb) = (grams(a), grams(b));
    if ga.is_empty() && gb.is_empty() {
        return 1.0;
    }
    let shared = ga.intersection(&gb).count() as f64;
    shared / (ga.len() + gb.len()) as f64 * 2.0
}

#[derive(Clone, Debug)]
pub struct Match {
    pub a: usize,
    pub b: usize,
    pub method: &'static str,
    pub confidence: f64,
}

struct Matcher<'a> {
    fa: &'a [Features],
    fb: &'a [Features],
    a_to_b: HashMap<usize, usize>,
    b_to_a: HashMap<usize, usize>,
    matches: Vec<Match>,
}

impl Matcher<'_> {
    fn add(&mut self, a: usize, b: usize, method: &'static str, confidence: f64) {
        if self.a_to_b.contains_key(&a) || self.b_to_a.contains_key(&b) {
            return;
        }
        self.a_to_b.insert(a, b);
        self.b_to_a.insert(b, a);
        self.matches.push(Match { a, b, method, confidence });
    }

    /// Pair unmatched functions whose `key` is unique on both sides.
    fn unique_by<K: Hash + Eq>(&mut self, method: &'static str, confidence: f64, key: impl Fn(&Features) -> Option<K>) {
        let mut left: HashMap<K, Vec<usize>> = HashMap::new();
        for (index, item) in self.fa.iter().enumerate() {
            if !self.a_to_b.contains_key(&index)
                && let Some(k) = key(item)
            {
                left.entry(k).or_default().push(index);
            }
        }
        let mut right: HashMap<K, Vec<usize>> = HashMap::new();
        for (index, item) in self.fb.iter().enumerate() {
            if !self.b_to_a.contains_key(&index)
                && let Some(k) = key(item)
            {
                right.entry(k).or_default().push(index);
            }
        }
        let mut pairs: Vec<(usize, usize)> = left
            .iter()
            .filter_map(|(k, a)| {
                let b = right.get(k)?;
                (a.len() == 1 && b.len() == 1).then(|| (a[0], b[0]))
            })
            .collect();
        pairs.sort_unstable();
        for (a, b) in pairs {
            let ratio = size_ratio(&self.fa[a], &self.fb[b]);
            if ratio >= 0.5 || method == "symbol" {
                self.add(a, b, method, confidence);
            }
        }
    }
}

fn size_ratio(a: &Features, b: &Features) -> f64 {
    let (x, y) = (a.insn_addrs.len().max(1) as f64, b.insn_addrs.len().max(1) as f64);
    x.min(y) / x.max(y)
}

pub fn match_functions(fa: &[Features], fb: &[Features]) -> Vec<Match> {
    let mut matcher = Matcher { fa, fb, a_to_b: HashMap::new(), b_to_a: HashMap::new(), matches: Vec::new() };
    matcher.unique_by("symbol", 1.0, |f| f.name.clone());
    matcher.unique_by("exact_bytes", 1.0, |f| Some((f.exact.clone(), f.insn_addrs.len())));
    matcher.unique_by("mnemonics", 0.9, |f| (f.insn_addrs.len() >= 4).then(|| f.mnemonic_hash.clone()));
    matcher.unique_by("constants_strings", 0.8, |f| {
        (!f.strings.is_empty() || f.constants.len() >= 2).then(|| (f.strings.clone(), f.constants.clone(), f.imports.clone()))
    });
    matcher.unique_by("cfg_shape", 0.7, |f| {
        (f.blocks >= 3).then(|| (f.blocks, f.edges, f.calls, f.imports.clone(), f.insn_addrs.len() / 8))
    });
    // Call-graph neighbourhood propagation.
    let index_a: HashMap<u64, usize> = fa.iter().enumerate().map(|(i, f)| (f.start, i)).collect();
    let index_b: HashMap<u64, usize> = fb.iter().enumerate().map(|(i, f)| (f.start, i)).collect();
    let mut callers_a: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut callers_b: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, f) in fa.iter().enumerate() {
        for c in &f.callees {
            if let Some(&j) = index_a.get(c) {
                callers_a.entry(j).or_default().push(i);
            }
        }
    }
    for (i, f) in fb.iter().enumerate() {
        for c in &f.callees {
            if let Some(&j) = index_b.get(c) {
                callers_b.entry(j).or_default().push(i);
            }
        }
    }
    for _round in 0..10 {
        let before = matcher.matches.len();
        let pairs: Vec<(usize, usize)> = matcher.matches.iter().map(|m| (m.a, m.b)).collect();
        for (a, b) in pairs {
            let neighbours = [
                (
                    fa[a].callees.iter().filter_map(|c| index_a.get(c).copied()).collect::<Vec<_>>(),
                    fb[b].callees.iter().filter_map(|c| index_b.get(c).copied()).collect::<Vec<_>>(),
                ),
                (callers_a.get(&a).cloned().unwrap_or_default(), callers_b.get(&b).cloned().unwrap_or_default()),
            ];
            for (left, right) in neighbours {
                let left: Vec<usize> = left.into_iter().filter(|i| !matcher.a_to_b.contains_key(i)).collect();
                let right: Vec<usize> = right.into_iter().filter(|i| !matcher.b_to_a.contains_key(i)).collect();
                if left.len() != right.len() || left.is_empty() || left.len() > 32 {
                    continue;
                }
                for (x, y) in left.iter().zip(&right) {
                    let score = similarity(&fa[*x].mnemonics, &fb[*y].mnemonics);
                    if (left.len() == 1 && score >= 0.3) || score >= 0.6 {
                        matcher.add(*x, *y, "callgraph", (0.4 + 0.3 * score).min(0.7));
                    }
                }
            }
        }
        if matcher.matches.len() == before {
            break;
        }
    }
    matcher.matches
}

fn module_json(image: &Image) -> Value {
    json!({"name": image.name, "sha256": image.sha256, "image_base": hex(image.base)})
}

/// Full diff document (`ps4wb-bindiff-v1`), RVAs relative to each image base.
pub fn diff_document(image_a: &Image, disc_a: &Discovery, image_b: &Image, disc_b: &Discovery) -> Value {
    let fa = features(image_a, disc_a);
    let fb = features(image_b, disc_b);
    let matches = match_functions(&fa, &fb);
    let rva_a = |i: usize| hex(fa[i].start - image_a.base);
    let rva_b = |i: usize| hex(fb[i].start - image_b.base);
    let mut by_method: BTreeMap<&str, usize> = BTreeMap::new();
    let mut identical = 0usize;
    let mut rows = Vec::new();
    for m in &matches {
        *by_method.entry(m.method).or_default() += 1;
        let same = fa[m.a].exact == fb[m.b].exact && fa[m.a].insn_addrs.len() == fb[m.b].insn_addrs.len();
        identical += usize::from(same);
        rows.push(json!({
            "a": rva_a(m.a), "b": rva_b(m.b),
            "end_a": hex(fa[m.a].end - image_a.base), "end_b": hex(fb[m.b].end - image_b.base),
            "name_a": fa[m.a].name, "name_b": fb[m.b].name,
            "method": m.method, "confidence": m.confidence, "identical": same,
            "similarity": if same { 1.0 } else { (similarity(&fa[m.a].mnemonics, &fb[m.b].mnemonics) * 1000.0).round() / 1000.0 },
        }));
    }
    rows.sort_by(|x, y| x["a"].as_str().cmp(&y["a"].as_str()));
    let matched_a: BTreeSet<usize> = matches.iter().map(|m| m.a).collect();
    let matched_b: BTreeSet<usize> = matches.iter().map(|m| m.b).collect();
    let functions = |image: &Image, list: &[Features]| -> Vec<Value> {
        list.iter()
            .map(|f| json!({"start": hex(f.start - image.base), "end": hex(f.end - image.base), "name": f.name}))
            .collect()
    };
    json!({
        "format": DIFF_FORMAT,
        "module_a": module_json(image_a), "module_b": module_json(image_b),
        "summary": {
            "functions_a": fa.len(), "functions_b": fb.len(), "matched": matches.len(),
            "identical": identical, "changed": matches.len() - identical,
            "unmatched_a": fa.len() - matched_a.len(), "unmatched_b": fb.len() - matched_b.len(),
            "by_method": by_method,
            "truncated": disc_a.truncated || disc_b.truncated,
        },
        "matches": rows,
        "unmatched_a": (0..fa.len()).filter(|i| !matched_a.contains(i)).map(|i| json!({"rva": rva_a(i), "name": fa[i].name})).collect::<Vec<_>>(),
        "unmatched_b": (0..fb.len()).filter(|i| !matched_b.contains(i)).map(|i| json!({"rva": rva_b(i), "name": fb[i].name})).collect::<Vec<_>>(),
        "functions_a": functions(image_a, &fa),
        "functions_b": functions(image_b, &fb),
    })
}

// ---- annotation porting -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SourceItem {
    pub rva: u64,
    pub symbol: Option<String>,
    pub comment: Option<String>,
    pub source: String,
}

fn parse_rva(value: &Value) -> Option<u64> {
    match value {
        Value::String(text) => text
            .strip_prefix("0x")
            .map_or_else(|| text.parse().ok(), |hex| u64::from_str_radix(hex, 16).ok()),
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// Instruction-level alignment (LCS over mnemonics) to translate an offset
/// inside a changed function. Returns the B instruction address.
fn align(fa: &Features, fb: &Features, va_a: u64) -> Option<u64> {
    let index_a = fa.insn_addrs.partition_point(|addr| *addr <= va_a).checked_sub(1)?;
    let (n, m) = (fa.mnemonics.len(), fb.mnemonics.len());
    if n == 0 || m == 0 || n > MAX_ALIGN || m > MAX_ALIGN || n != fa.insn_addrs.len() || m != fb.insn_addrs.len() {
        return None;
    }
    let mut table = vec![0u16; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[at(i, j)] = if fa.mnemonics[i] == fb.mnemonics[j] {
                table[at(i + 1, j + 1)] + 1
            } else {
                table[at(i + 1, j)].max(table[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if fa.mnemonics[i] == fb.mnemonics[j] {
            if i == index_a {
                return Some(fb.insn_addrs[j] + (va_a - fa.insn_addrs[i]));
            }
            i += 1;
            j += 1;
        } else if table[at(i + 1, j)] >= table[at(i, j + 1)] {
            if i == index_a {
                return None;
            }
            i += 1;
        } else {
            j += 1;
        }
    }
    None
}

/// Port items through `diff`. `images` (A, B with discoveries) enable
/// instruction alignment inside changed functions.
pub fn port(diff: &Value, items: &[SourceItem], images: Option<(&Image, &Discovery, &Image, &Discovery)>, min_confidence: f64) -> (Vec<Value>, Vec<Value>) {
    let mut ported = Vec::new();
    let mut unported = Vec::new();
    let functions_a: Vec<(u64, u64)> = diff["functions_a"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| Some((parse_rva(&f["start"])?, parse_rva(&f["end"])?)))
        .collect();
    let matches: HashMap<u64, &Value> = diff["matches"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((parse_rva(&m["a"])?, m)))
        .collect();
    let features = images.map(|(ia, da, ib, db)| {
        let fa: HashMap<u64, Features> = features(ia, da).into_iter().map(|f| (f.start - ia.base, f)).collect();
        let fb: HashMap<u64, Features> = features(ib, db).into_iter().map(|f| (f.start - ib.base, f)).collect();
        (fa, fb, ia.base, ib.base)
    });
    for item in items {
        let reject = |reason: &str| json!({"source_rva": hex(item.rva), "symbol": item.symbol, "source": item.source, "reason": reason});
        let Some(&(start, _)) = functions_a.iter().filter(|(s, e)| *s <= item.rva && item.rva < *e).max_by_key(|(s, _)| *s) else {
            unported.push(reject("not inside a discovered function of module A (data or undiscovered code)"));
            continue;
        };
        let Some(entry) = matches.get(&start) else {
            unported.push(reject("containing function has no match in module B"));
            continue;
        };
        let start_b = parse_rva(&entry["b"]).unwrap_or_default();
        let base_confidence = entry["confidence"].as_f64().unwrap_or(0.0);
        let offset = item.rva - start;
        let identical = entry["identical"].as_bool().unwrap_or(false);
        let (rva_b, confidence, method) = if offset == 0 {
            (Some(start_b), base_confidence, "function_start")
        } else if identical {
            (Some(start_b + offset), base_confidence, "identical_function_offset")
        } else if let Some((fa, fb, base_a, base_b)) = &features
            && let (Some(a), Some(b)) = (fa.get(&start), fb.get(&start_b))
        {
            match align(a, b, base_a + item.rva) {
                Some(va) => (Some(va - base_b), base_confidence * 0.8, "instruction_alignment"),
                None => (None, 0.0, "instruction_not_aligned"),
            }
        } else {
            (None, 0.0, "changed_function_needs_artifacts")
        };
        let Some(rva_b) = rva_b else {
            unported.push(reject(match method {
                "instruction_not_aligned" => "instruction has no counterpart in the changed function",
                _ => "function changed; pass artifact_a/artifact_b for instruction-level alignment",
            }));
            continue;
        };
        let confidence = (confidence * 1000.0).round() / 1000.0;
        if confidence < min_confidence {
            unported.push(reject(&format!("confidence {confidence} below min_confidence")));
            continue;
        }
        ported.push(json!({
            "rva": hex(rva_b), "symbol": item.symbol, "comment": item.comment,
            "confidence": confidence, "method": method, "match_method": entry["method"],
            "source_rva": hex(item.rva), "source": item.source,
        }));
    }
    (ported, unported)
}

/// Extract items from one source document (`annotation_save` evidence,
/// `debug_label_save` export, a previous ported set, or `{rva: name}`).
pub fn source_items(document: &Value, source: &str, module_a_sha256: Option<&str>, label_base: Option<u64>, allow_hash_mismatch: bool) -> crate::Result<Vec<SourceItem>> {
    let check_hash = |hash: Option<&str>| -> crate::Result<()> {
        if let (Some(have), Some(want)) = (hash, module_a_sha256)
            && have != want
            && !allow_hash_mismatch
        {
            anyhow::bail!("{source}: module_sha256 {have} does not match diff module A {want} (set allow_hash_mismatch to override)");
        }
        Ok(())
    };
    let evidence = |entry: &Value| -> Option<SourceItem> {
        Some(SourceItem {
            rva: parse_rva(&entry["rva"])?,
            symbol: entry["symbol"].as_str().filter(|s| !s.is_empty()).map(str::to_owned),
            comment: entry["comment"].as_str().filter(|s| !s.is_empty()).map(str::to_owned),
            source: source.to_owned(),
        })
    };
    if document["format"] == PORT_FORMAT {
        check_hash(document["module_sha256"].as_str())?;
        return Ok(document["annotations"].as_array().into_iter().flatten().filter_map(evidence).collect());
    }
    if document.get("rva").is_some() && document.get("module_sha256").is_some() {
        check_hash(document["module_sha256"].as_str())?;
        return Ok(evidence(document).into_iter().collect());
    }
    if let Some(list) = document.as_array() {
        let mut items = Vec::new();
        for entry in list {
            check_hash(entry["module_sha256"].as_str())?;
            items.extend(evidence(entry));
        }
        return Ok(items);
    }
    if document["version"] == 1 && document["labels"].is_array() {
        let base = label_base.ok_or_else(|| anyhow::anyhow!("{source}: debugger label exports hold runtime addresses; pass label_base (module A runtime base)"))?;
        return Ok(document["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|label| {
                let address = parse_rva(&label["address"])?;
                Some(SourceItem {
                    rva: address.checked_sub(base)?,
                    symbol: label["name"].as_str().map(str::to_owned),
                    comment: None,
                    source: source.to_owned(),
                })
            })
            .collect());
    }
    if let Some(map) = document.as_object() {
        let mut items = Vec::new();
        for (key, value) in map {
            let rva = parse_rva(&Value::from(key.as_str())).ok_or_else(|| anyhow::anyhow!("{source}: key {key:?} is not an RVA"))?;
            let symbol = value.as_str().ok_or_else(|| anyhow::anyhow!("{source}: value for {key} must be a name string"))?;
            items.push(SourceItem { rva, symbol: Some(symbol.to_owned()), comment: None, source: source.to_owned() });
        }
        return Ok(items);
    }
    anyhow::bail!("{source}: unrecognised annotation source format")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{DiscoverOptions, discover, tests::sample};

    #[test]
    fn diff_matches_shifted_build_and_ports_names() {
        let (builder_a, f0, f1, _) = sample(0x400000);
        let image_a = Image::from_elf(&builder_a.build(), Some("a".into())).unwrap();
        // Build B: shift code by 16 bytes of padding and drop the symbol.
        let (mut builder_b, _, _, _) = crate::cfg::tests::sample_with(0x400000, 16);
        builder_b.symbols.clear();
        builder_b.eh_frame.clear();
        let image_b = Image::from_elf(&builder_b.build(), Some("b".into())).unwrap();
        let disc_a = discover(&image_a, &DiscoverOptions::default());
        let disc_b = discover(&image_b, &DiscoverOptions { prologues: true, ..Default::default() });
        let doc = diff_document(&image_a, &disc_a, &image_b, &disc_b);
        assert_eq!(doc["format"], DIFF_FORMAT);
        let matches = doc["matches"].as_array().unwrap();
        let main = matches.iter().find(|m| m["a"] == hex(f0 - 0x400000)).expect("dispatch matched");
        assert_eq!(main["b"], hex(f0 - 0x400000 + 16));
        // RIP-relative/rel32 changes are masked, so the shifted copy is still identical.
        assert_eq!(main["identical"], true);
        assert!(matches.iter().any(|m| m["a"] == hex(f1 - 0x400000)));

        let items = source_items(&json!({"0x1000": "dispatch", "0x1004": "after_prologue", "0x9999": "data"}), "user", None, None, false).unwrap();
        let (ported, unported) = port(&doc, &items, None, 0.0);
        assert_eq!(ported.len(), 2);
        assert!(ported.iter().any(|p| p["rva"] == "0x1014" && p["symbol"] == "after_prologue"));
        assert_eq!(unported.len(), 1);

        let labels = json!({"version": 1, "labels": [{"name": "x", "address": "0x81001000"}]});
        assert!(source_items(&labels, "l", None, None, false).is_err());
        let items = source_items(&labels, "l", None, Some(0x8100_0000), false).unwrap();
        assert_eq!(items[0].rva, 0x1000);
        let evidence = json!({"rva": "0x1000", "module_sha256": "b".repeat(64), "comment": "c", "symbol": "s"});
        assert!(source_items(&evidence, "e", Some(&"a".repeat(64)), None, false).is_err());
    }

    #[test]
    fn alignment_maps_instruction_in_changed_function() {
        let fa = Features { mnemonics: vec![1, 2, 3, 4], insn_addrs: vec![0x10, 0x11, 0x13, 0x16], ..Default::default() };
        let fb = Features { mnemonics: vec![1, 9, 2, 3, 4], insn_addrs: vec![0x20, 0x21, 0x25, 0x27, 0x2a], ..Default::default() };
        assert_eq!(align(&fa, &fb, 0x13), Some(0x27));
        assert_eq!(align(&fa, &fb, 0x14), Some(0x28));
    }
}
