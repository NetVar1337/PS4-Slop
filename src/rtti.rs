//! Itanium C++ ABI RTTI and vtable recovery (PS4 titles are built with Clang,
//! which follows the Itanium ABI; reference: "Itanium C++ ABI", §2.5 Virtual
//! Table Layout, §2.9.4–2.9.5 RTTI layout, §5.1 Mangling).
//!
//! Layout facts used (64-bit):
//! * `std::type_info` = `{ vptr, const char* __type_name }` (16 bytes); the name
//!   is the mangled type without the `_ZTS` prefix (e.g. `N2ns3FooE`, `3Bar`).
//! * `__si_class_type_info` adds `const __class_type_info* __base_type` (+16).
//! * `__vmi_class_type_info` adds `u32 __flags; u32 __base_count;` (+16, +20)
//!   followed by `__base_class_type_info { const __class_type_info* __base_type;
//!   long __offset_flags; }` entries (+24, 16 bytes each); `__offset_flags`
//!   low bits: 0x1 virtual, 0x2 public; offset = value >> 8.
//! * A vtable is `{ [vcall/vbase offsets…], ptrdiff_t offset_to_top,
//!   type_info* rtti, fn0, fn1, … }`; objects point at `fn0` (the address point).
//!
//! Detection is structural: find mangled class names in non-executable data,
//! find 8-aligned slots that point at them (the `__type_name` field), and
//! validate the vptr one slot earlier (import symbol of the `__cxxabiv1`
//! type_info vtables in static ELFs, a mapped pointer when live, a pointer value
//! shared by several candidates, or an explicit override).
use crate::{
    Result,
    bytesource::{Mode, PROT_R, PROT_X, Source, TargetSpec, hex},
    workbench::Workbench,
};
use anyhow::ensure;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_NAME: usize = 1024;
const KIND_SYMBOLS: [(&str, &str); 3] = [
    ("class", "_ZTVN10__cxxabiv117__class_type_infoE"),
    ("si", "_ZTVN10__cxxabiv120__si_class_type_infoE"),
    ("vmi", "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
];

// ---- Itanium demangler subset ----------------------------------------------------

struct Demangler<'a> {
    s: &'a [u8],
    pos: usize,
    subs: Vec<String>,
    depth: usize,
}

/// Demangle a type name as stored in a type_info (`_ZTS` suffix). Supports
/// nested/unscoped names, `St`/standard abbreviations, substitutions,
/// template arguments (types, integer/bool literals, packs), builtin types,
/// pointers/references/cv-qualifiers, arrays, function and member-pointer
/// types, and anonymous namespaces. Returns `None` when unsure.
pub fn demangle_type(name: &str) -> Option<String> {
    let mut d = Demangler { s: name.as_bytes(), pos: 0, subs: Vec::new(), depth: 0 };
    let out = d.ty()?;
    (d.pos == d.s.len()).then_some(out)
}

fn builtin(c: u8) -> Option<&'static str> {
    Some(match c {
        b'v' => "void",
        b'w' => "wchar_t",
        b'b' => "bool",
        b'c' => "char",
        b'a' => "signed char",
        b'h' => "unsigned char",
        b's' => "short",
        b't' => "unsigned short",
        b'i' => "int",
        b'j' => "unsigned int",
        b'l' => "long",
        b'm' => "unsigned long",
        b'x' => "long long",
        b'y' => "unsigned long long",
        b'n' => "__int128",
        b'o' => "unsigned __int128",
        b'f' => "float",
        b'd' => "double",
        b'e' => "long double",
        b'g' => "__float128",
        b'z' => "...",
        _ => return None,
    })
}

impl Demangler<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<u8> {
        self.s.get(self.pos + 1).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        std::str::from_utf8(&self.s[start..self.pos]).ok()?.parse().ok()
    }

    fn source_name(&mut self) -> Option<String> {
        let length = self.number()?;
        if length == 0 || self.pos + length > self.s.len() {
            return None;
        }
        let id = std::str::from_utf8(&self.s[self.pos..self.pos + length]).ok()?;
        if !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'.') {
            return None;
        }
        self.pos += length;
        Some(if id.starts_with("_GLOBAL__N") { "(anonymous namespace)".to_owned() } else { id.to_owned() })
    }

    fn substitution(&mut self) -> Option<String> {
        // Caller saw 'S'.
        self.pos += 1;
        let c = self.peek()?;
        let fixed = match c {
            b'a' => Some("std::allocator"),
            b'b' => Some("std::basic_string"),
            b's' => Some("std::string"),
            b'i' => Some("std::istream"),
            b'o' => Some("std::ostream"),
            b'd' => Some("std::iostream"),
            _ => None,
        };
        if let Some(fixed) = fixed {
            self.pos += 1;
            return Some(fixed.to_owned());
        }
        let mut index = 0usize;
        if c != b'_' {
            while let Some(c) = self.peek() {
                if c == b'_' {
                    break;
                }
                let digit = match c {
                    b'0'..=b'9' => (c - b'0') as usize,
                    b'A'..=b'Z' => (c - b'A') as usize + 10,
                    _ => return None,
                };
                index = index.checked_mul(36)?.checked_add(digit)?;
                self.pos += 1;
            }
            index += 1;
        }
        if !self.eat(b'_') {
            return None;
        }
        self.subs.get(index).cloned()
    }

    fn template_args(&mut self) -> Option<String> {
        // Caller saw 'I'.
        self.pos += 1;
        let mut args = Vec::new();
        while !self.eat(b'E') {
            args.push(self.template_arg()?);
            if args.len() > 64 {
                return None;
            }
        }
        Some(format!("<{}>", args.join(", ")))
    }

    fn template_arg(&mut self) -> Option<String> {
        match self.peek()? {
            b'L' => {
                self.pos += 1;
                if self.peek() == Some(b'_') {
                    return None; // external names (L_Z…E) are unsupported
                }
                let ty = self.ty()?;
                let negative = self.eat(b'n');
                let value = self.number()?;
                if !self.eat(b'E') {
                    return None;
                }
                Some(match ty.as_str() {
                    "bool" => (if value == 0 { "false" } else { "true" }).to_owned(),
                    "int" => format!("{}{value}", if negative { "-" } else { "" }),
                    _ => format!("({ty}){}{value}", if negative { "-" } else { "" }),
                })
            }
            b'J' => {
                self.pos += 1;
                let mut items = Vec::new();
                while !self.eat(b'E') {
                    items.push(self.template_arg()?);
                }
                Some(items.join(", "))
            }
            b'X' => None,
            _ => self.ty(),
        }
    }

    /// <unscoped-name> / <nested-name> / <substitution> (+ template args).
    fn name(&mut self) -> Option<String> {
        match self.peek()? {
            b'N' => self.nested(),
            b'Z' => None,
            b'S' if self.peek2() == Some(b't') => {
                self.pos += 2;
                let mut out = format!("std::{}", self.source_name()?);
                if self.peek() == Some(b'I') {
                    self.subs.push(out.clone());
                    out += &self.template_args()?;
                }
                Some(out)
            }
            b'S' => {
                let mut out = self.substitution()?;
                if self.peek() == Some(b'I') {
                    out += &self.template_args()?;
                }
                Some(out)
            }
            c if c.is_ascii_digit() => {
                let mut out = self.source_name()?;
                if self.peek() == Some(b'I') {
                    self.subs.push(out.clone());
                    out += &self.template_args()?;
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn nested(&mut self) -> Option<String> {
        self.pos += 1; // 'N'
        while matches!(self.peek(), Some(b'r' | b'V' | b'K' | b'R' | b'O')) {
            self.pos += 1;
        }
        let mut prefix = String::new();
        let mut components = 0;
        loop {
            match self.peek()? {
                b'E' => {
                    self.pos += 1;
                    return (components > 0).then_some(prefix);
                }
                b'S' if components == 0 && self.peek2() == Some(b't') => {
                    self.pos += 2;
                    prefix = "std".to_owned();
                    components += 1;
                    continue; // "std" itself is not a substitution candidate
                }
                b'S' if components == 0 => prefix = self.substitution()?,
                b'I' if components > 0 => prefix += &self.template_args()?,
                b'L' => {
                    self.pos += 1;
                    continue;
                }
                c if c.is_ascii_digit() => {
                    let id = self.source_name()?;
                    prefix = if prefix.is_empty() { id } else { format!("{prefix}::{id}") };
                }
                _ => return None,
            }
            components += 1;
            // Every non-final prefix is a substitution candidate; a prefix that was
            // itself produced by a substitution reference is not re-added.
            if self.peek() != Some(b'E') && !self.subs.contains(&prefix) {
                self.subs.push(prefix.clone());
            }
        }
    }

    fn ty(&mut self) -> Option<String> {
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let c = self.peek()?;
        let out = if let Some(b) = builtin(c) {
            self.pos += 1;
            b.to_owned()
        } else {
            match c {
                b'P' | b'R' | b'O' => {
                    self.pos += 1;
                    let inner = self.ty()?;
                    let suffix = match c {
                        b'P' => "*",
                        b'R' => "&",
                        _ => "&&",
                    };
                    let out = format!("{inner}{suffix}");
                    self.subs.push(out.clone());
                    out
                }
                b'K' | b'V' | b'r' => {
                    let mut quals = Vec::new();
                    while let Some(q @ (b'r' | b'V' | b'K')) = self.peek() {
                        quals.push(match q {
                            b'K' => "const",
                            b'V' => "volatile",
                            _ => "restrict",
                        });
                        self.pos += 1;
                    }
                    let inner = self.ty()?;
                    quals.reverse();
                    let out = format!("{inner} {}", quals.join(" "));
                    self.subs.push(out.clone());
                    out
                }
                b'A' => {
                    self.pos += 1;
                    let n = self.number()?;
                    if !self.eat(b'_') {
                        return None;
                    }
                    let inner = self.ty()?;
                    let out = format!("{inner} [{n}]");
                    self.subs.push(out.clone());
                    out
                }
                b'F' => {
                    self.pos += 1;
                    self.eat(b'Y');
                    let ret = self.ty()?;
                    let mut params = Vec::new();
                    while !self.eat(b'E') {
                        if self.peek() == Some(b'R') && self.peek2() == Some(b'E')
                            || self.peek() == Some(b'O') && self.peek2() == Some(b'E')
                        {
                            self.pos += 1;
                            continue;
                        }
                        params.push(self.ty()?);
                    }
                    if params == ["void"] {
                        params.clear();
                    }
                    let out = format!("{ret} ({})", params.join(", "));
                    self.subs.push(out.clone());
                    out
                }
                b'M' => {
                    self.pos += 1;
                    let class = self.ty()?;
                    let member = self.ty()?;
                    let out = format!("{member} {class}::*");
                    self.subs.push(out.clone());
                    out
                }
                b'D' => {
                    self.pos += 1;
                    let out = match self.peek()? {
                        b'n' => "decltype(nullptr)".to_owned(),
                        b's' => "char16_t".to_owned(),
                        b'i' => "char32_t".to_owned(),
                        b'u' => "char8_t".to_owned(),
                        b'a' => "auto".to_owned(),
                        b'p' => {
                            self.pos += 1;
                            let inner = self.ty()?;
                            self.depth -= 1;
                            return Some(format!("{inner}..."));
                        }
                        _ => return None,
                    };
                    self.pos += 1;
                    out
                }
                b'T' => {
                    self.pos += 1;
                    let n = if self.peek() == Some(b'_') { 0 } else { self.number()? + 1 };
                    if !self.eat(b'_') {
                        return None;
                    }
                    format!("T{n}")
                }
                b'S' if self.peek2() != Some(b't') => {
                    let sub = self.substitution()?;
                    if self.peek() == Some(b'I') {
                        let out = sub + self.template_args()?.as_str();
                        self.subs.push(out.clone());
                        out
                    } else {
                        sub
                    }
                }
                _ => {
                    let out = self.name()?;
                    self.subs.push(out.clone());
                    out
                }
            }
        };
        self.depth -= 1;
        Some(out)
    }
}

/// Is `bytes` a plausible class type_info name? Returns the demangled name.
fn class_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() > MAX_NAME {
        return None;
    }
    let first = bytes[0];
    if !(first == b'N' || first.is_ascii_digit() && first != b'0' || bytes.starts_with(b"St")) {
        return None;
    }
    if !bytes.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'.')) {
        return None;
    }
    demangle_type(std::str::from_utf8(bytes).ok()?)
}

// ---- recovery ------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct TypeInfo {
    address: u64,
    mangled: String,
    name: String,
    vptr: u64,
    kind: &'static str,
    kind_source: &'static str,
    bases: Vec<(u64, i64, u8)>,
    size: u64,
}

pub struct Options {
    pub max_classes: usize,
    pub max_virtuals: usize,
    pub overrides: HashMap<u64, &'static str>,
}

fn kind_of_symbol(name: &str) -> Option<&'static str> {
    let nid = name.split('#').next().unwrap_or(name);
    KIND_SYMBOLS
        .iter()
        .find(|(_, symbol)| name == *symbol || nid == crate::nid::encode_nid(symbol))
        .map(|(kind, _)| *kind)
}

pub fn recover(source: &mut Source, options: &Options) -> Result<Value> {
    let mut data_ranges = source.ranges_with(PROT_R, PROT_X);
    let mut notes: Vec<String> = Vec::new();
    if data_ranges.is_empty() {
        data_ranges = source.selection.clone();
        notes.push("No non-executable ranges selected; scanning all selected ranges for data".into());
    }
    let image_lo = source.selection.iter().map(|r| r.0).min().unwrap_or(0);
    let image_hi = source.selection.iter().map(|r| r.1).max().unwrap_or(0);

    // 1. Mangled class-name strings.
    let mut names: HashMap<u64, (String, String)> = HashMap::new();
    source.scan(Some(&data_ranges), MAX_NAME + 1, |va, chunk| {
        let mut i = 0;
        while i < chunk.len() {
            let starts = i == 0 || chunk[i - 1] == 0;
            let c = chunk[i];
            if starts && (c == b'N' || c == b'S' || (b'1'..=b'9').contains(&c)) {
                let end = chunk[i..].iter().take(MAX_NAME + 1).position(|b| *b == 0);
                if let Some(end) = end {
                    if let Some(name) = class_name(&chunk[i..i + end]) {
                        let mangled = String::from_utf8_lossy(&chunk[i..i + end]).into_owned();
                        names.entry(va + i as u64).or_insert((mangled, name));
                        if names.len() >= 400_000 {
                            return false;
                        }
                    }
                    i += end.max(1);
                    continue;
                }
            }
            i += 1;
        }
        true
    })?;

    // 2. type_info candidates: slots pointing at a name, vptr one slot earlier.
    let name_set: HashSet<u64> = names.keys().copied().collect();
    let slots = source.find_pointers(&data_ranges, &name_set, 1_000_000)?;
    let mut candidates: BTreeMap<u64, TypeInfo> = BTreeMap::new();
    for (slot, name_va) in slots {
        let address = slot - 8;
        let Some(vptr) = source.u64(address) else { continue };
        let (mangled, name) = names[&name_va].clone();
        candidates.insert(
            address,
            TypeInfo { address, mangled, name, vptr, kind: "class", kind_source: "structure", bases: Vec::new(), size: 16 },
        );
    }
    let addresses: HashSet<u64> = candidates.keys().copied().collect();
    let mut vptr_votes: HashMap<u64, usize> = HashMap::new();
    for ti in candidates.values() {
        *vptr_votes.entry(ti.vptr).or_default() += 1;
    }

    // 3. Kind: import symbol / override, else structure.
    let keys: Vec<u64> = candidates.keys().copied().collect();
    for address in &keys {
        let vptr = candidates[address].vptr;
        let declared = source
            .imports
            .get(address)
            .and_then(|symbol| kind_of_symbol(symbol))
            .map(|kind| (kind, "import-symbol"))
            .or_else(|| options.overrides.get(&vptr).map(|kind| (*kind, "override")));
        let structural = {
            let q2 = source.u64(address + 16);
            if q2.is_some_and(|base| addresses.contains(&base)) {
                Some(("si", vec![(q2.unwrap(), 0i64, 2u8)]))
            } else {
                vmi_bases(source, *address, Some(&addresses))
            }
        };
        let ti = candidates.get_mut(address).unwrap();
        match (declared, structural) {
            (Some((kind, from)), _) => {
                ti.kind = kind;
                ti.kind_source = from;
            }
            (None, Some((kind, _))) => ti.kind = kind,
            _ => {}
        }
        let parsed = match ti.kind {
            "si" => source.u64(address + 16).map(|base| vec![(base, 0i64, 2u8)]),
            "vmi" => vmi_bases(source, *address, None).map(|v| v.1),
            _ => Some(Vec::new()),
        };
        let ti = candidates.get_mut(address).unwrap();
        ti.bases = parsed.unwrap_or_default();
        ti.size = match ti.kind {
            "si" => 24,
            "vmi" => 24 + 16 * ti.bases.len() as u64,
            _ => 16,
        };
    }

    // Majority structural kind per vptr value promotes lone "class" guesses.
    let mut per_vptr: HashMap<u64, HashMap<&str, usize>> = HashMap::new();
    for ti in candidates.values() {
        *per_vptr.entry(ti.vptr).or_default().entry(ti.kind).or_default() += 1;
    }
    let mut accepted: BTreeMap<u64, TypeInfo> = BTreeMap::new();
    for (address, mut ti) in candidates {
        let votes = vptr_votes.get(&ti.vptr).copied().unwrap_or(0);
        let mapped = ti.vptr != 0 && source.is_mapped(ti.vptr);
        // Shared-vptr evidence only counts for pointer-like values (relocation
        // tables and small-integer records also repeat values).
        let valid = ti.kind_source != "structure" || mapped || (votes >= 2 && ti.vptr > 0xffff);
        if !valid {
            continue;
        }
        if ti.kind == "class"
            && ti.kind_source == "structure"
            && let Some(kinds) = per_vptr.get(&ti.vptr)
        {
            let si = kinds.get("si").copied().unwrap_or(0);
            let vmi = kinds.get("vmi").copied().unwrap_or(0);
            let class = kinds.get("class").copied().unwrap_or(0);
            if si > class + vmi && si >= 2 {
                if let Some(base) = source.u64(address + 16) {
                    ti.kind = "si";
                    ti.kind_source = "vptr-cluster";
                    ti.bases = vec![(base, 0, 2)];
                    ti.size = 24;
                }
            } else if vmi > class + si
                && vmi >= 2
                && let Some((_, bases)) = vmi_bases(source, address, None)
            {
                ti.kind = "vmi";
                ti.kind_source = "vptr-cluster";
                ti.size = 24 + 16 * bases.len() as u64;
                ti.bases = bases;
            }
        }
        accepted.insert(address, ti);
        if accepted.len() >= options.max_classes {
            notes.push(format!("Class cap {} reached", options.max_classes));
            break;
        }
    }

    // 4. vtables: slots pointing at accepted type_infos.
    let ti_set: HashSet<u64> = accepted.keys().copied().collect();
    let spans: Vec<(u64, u64)> = accepted.values().map(|ti| (ti.address, ti.address + ti.size)).collect();
    let refs = source.find_pointers(&data_ranges, &ti_set, 2_000_000)?;
    let mut vtables: HashMap<u64, Vec<(u64, i64)>> = HashMap::new();
    for (slot, ti) in refs {
        if spans.iter().any(|(s, e)| *s <= slot && slot < *e) {
            continue;
        }
        let Some(top) = source.u64(slot - 8).map(|v| v as i64) else { continue };
        if top.unsigned_abs() >= 0x10_0000 || top % 4 != 0 {
            continue;
        }
        vtables.entry(ti).or_default().push((slot, top));
    }

    // 5. Assemble.
    let image_base = source.image_base;
    let rva = |va: u64| hex(va.wrapping_sub(image_base));
    let mut classes = Vec::new();
    let mut with_vtable = 0usize;
    for ti in accepted.values() {
        let base_names: Vec<Value> = ti
            .bases
            .iter()
            .map(|(base, offset, flags)| {
                let name = accepted.get(base).map(|b| b.name.clone()).or_else(|| {
                    let name_ptr = source.u64(base + 8)?;
                    let raw = source.cstr(name_ptr, MAX_NAME)?;
                    class_name(&raw)
                });
                json!({"name": name.clone().unwrap_or_else(|| hex(*base)), "typeinfo": rva(*base),
                    "offset": offset, "virtual": flags & 1 != 0, "public": flags & 2 != 0})
            })
            .collect();
        let mut tables = vtables.get(&ti.address).cloned().unwrap_or_default();
        tables.sort_by_key(|(slot, top)| (*top != 0, *slot));
        let mut vtable_json = Value::Null;
        let mut virtuals = Vec::new();
        let mut secondary = Vec::new();
        for (index, (slot, top)) in tables.iter().enumerate() {
            let mut entries = Vec::new();
            let mut cursor = slot + 8;
            while entries.len() < options.max_virtuals {
                let import = source.imports.get(&cursor).cloned();
                let Some(target) = source.u64(cursor) else { break };
                if import.is_none() && !source.is_exec(target) {
                    break;
                }
                if ti_set.contains(&target) {
                    break;
                }
                let inside = (image_lo..image_hi).contains(&target);
                let mut entry = json!({"index": entries.len(),
                    "target": if import.is_none() && inside { json!(rva(target)) } else { Value::Null }});
                if let Some(import) = import {
                    entry["import"] = json!(import);
                } else if !inside {
                    entry["external"] = json!(hex(target));
                }
                entries.push(entry);
                cursor += 8;
            }
            if index == 0 && *top == 0 {
                vtable_json = json!(rva(slot - 8));
                virtuals = entries;
            } else {
                secondary.push(json!({"vtable": rva(slot - 8), "offset_to_top": top,
                    "address_point": rva(slot + 8), "virtuals": entries}));
            }
        }
        if !vtable_json.is_null() || !secondary.is_empty() {
            with_vtable += 1;
        }
        let confidence = match (ti.kind_source, vtable_json.is_null()) {
            ("import-symbol" | "override", false) => "high",
            ("import-symbol" | "override", true) | (_, false) => "medium",
            _ => "low",
        };
        classes.push(json!({
            "name": ti.name, "mangled": ti.mangled, "typeinfo": rva(ti.address),
            "typeinfo_kind": ti.kind, "kind_evidence": ti.kind_source,
            "vtable": vtable_json,
            "address_point": if vtable_json.is_null() { Value::Null } else { json!(rva(tables[0].0 + 8)) },
            "bases": base_names.iter().map(|b| b["name"].clone()).collect::<Vec<_>>(),
            "base_details": base_names,
            "virtuals": virtuals,
            "secondary_vtables": secondary,
            "confidence": confidence,
        }));
    }
    notes.push("vtable = address of the offset-to-top slot of the primary vtable (address_point - 16); virtual-base/vcall offsets above it are not included.".into());
    notes.push("virtual target is an RVA inside the image; out-of-image targets are given as `external` (absolute) or `import` (static ELF relocation symbol) with target null.".into());
    Ok(json!({
        "format": "ps4wb-classes-v1",
        "image_base": hex(image_base),
        "classes": classes,
        "stats": {"name_strings": names.len(), "typeinfos": accepted.len(), "with_vtable": with_vtable},
        "notes": notes,
    }))
}

/// Parse a `__vmi_class_type_info` base list at `address`; with `known`, every
/// base must be a known candidate (structural detection).
#[allow(clippy::type_complexity)]
fn vmi_bases(source: &mut Source, address: u64, known: Option<&HashSet<u64>>) -> Option<(&'static str, Vec<(u64, i64, u8)>)> {
    let flags = source.u32(address + 16)?;
    let count = source.u32(address + 20)?;
    if flags > 3 || count == 0 || count > 64 {
        return None;
    }
    let mut bases = Vec::new();
    for index in 0..count as u64 {
        let base = source.u64(address + 24 + index * 16)?;
        let offset_flags = source.u64(address + 32 + index * 16)? as i64;
        if known.is_some_and(|set| !set.contains(&base)) || offset_flags & 0xfc != 0 {
            return None;
        }
        bases.push((base, offset_flags >> 8, (offset_flags & 3) as u8));
    }
    Some(("vmi", bases))
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let spec = TargetSpec::from_args(args, "artifact", "module")?;
    ensure!(spec.is_specified(), "Give an ELF/raw artifact or pid + module");
    if spec.pid.is_some() {
        ensure!(spec.module.is_some(), "Live RTTI recovery needs a module");
    }
    let mut overrides = HashMap::new();
    for (key, kind) in [("class_typeinfo_vtable", "class"), ("si_typeinfo_vtable", "si"), ("vmi_typeinfo_vtable", "vmi")] {
        if let Some(value) = args.get(key).filter(|v| !v.is_null()) {
            overrides.insert(crate::tools::address(value)?, kind);
        }
    }
    let options = Options {
        max_classes: args["max_classes"].as_u64().unwrap_or(50_000) as usize,
        max_virtuals: args["max_virtuals"].as_u64().unwrap_or(512) as usize,
        overrides,
    };
    let mut source = Source::open(workbench, &spec, Mode::Mapped)?;
    let result = recover(&mut source, &options)?;
    let summary = source.summary();
    drop(source);
    let saved = crate::engines::save_json(workbench, "rtti-classes", &result, json!({"tool": "rtti_recover"}))?;
    let preview: Vec<Value> = result["classes"]
        .as_array()
        .map(|c| c.iter().take(20).map(|c| json!({"name": c["name"], "typeinfo": c["typeinfo"], "vtable": c["vtable"], "bases": c["bases"], "virtuals": c["virtuals"].as_array().map_or(0, Vec::len)})).collect())
        .unwrap_or_default();
    Ok(json!({
        "format": "ps4wb-classes-v1", "artifact": crate::engines::artifact_ref(&saved),
        "image_base": result["image_base"], "stats": result["stats"], "preview": preview,
        "notes": result["notes"], "source": summary,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytesource::testutil::build_elf;

    #[test]
    fn demangles_common_shapes() {
        for (mangled, expected) in [
            ("3Foo", "Foo"),
            ("N2ns3FooE", "ns::Foo"),
            ("N2ns3BazIiEE", "ns::Baz<int>"),
            ("NSt3__16vectorIiNS_9allocatorIiEEEE", "std::__1::vector<int, std::__1::allocator<int>>"),
            ("N12_GLOBAL__N_15LocalE", "(anonymous namespace)::Local"),
            ("St9exception", "std::exception"),
            ("N1a1bIPKcLi3ELb1EEE", "a::b<char const*, 3, true>"),
            ("NSt3__110__function6__funcIZN1A1fEvE3$_0NS_9allocatorIS4_EEFvvEEE", ""),
            ("N1A1BIFviEEE", "A::B<void (int)>"),
        ] {
            let got = demangle_type(mangled);
            if expected.is_empty() {
                assert_eq!(got, None, "{mangled}");
            } else {
                assert_eq!(got.as_deref(), Some(expected), "{mangled}");
            }
        }
        assert_eq!(class_name(b"Pv"), None);
        assert_eq!(class_name(b"3Fo"), None);
    }

    fn q(out: &mut Vec<u8>, value: u64) {
        out.extend(value.to_le_bytes());
    }

    #[test]
    fn recovers_classes_from_relocated_elf() {
        let text = vec![0xc3u8; 0x100];
        let rodata = b"3Foo\0N2ns3BarE\0N2ns3BazIiEE\0".to_vec();
        let (foo_n, bar_n, baz_n) = (0x2000u64, 0x2005, 0x200f);
        let (ti_foo, ti_bar, ti_baz) = (0x3000u64, 0x3010, 0x3028);
        let (vt_foo, vt_bar, vt_baz) = (0x3060u64, 0x3090, 0x30c8);
        // Contents are zero; RELATIVE relocations fill in every pointer.
        let mut data = vec![0u8; 0x120];
        let mut relas = Vec::new();
        let rel = |at: u64, value: u64| (at, 8u64, value);
        let vmi_nid = format!("{}#C#C", crate::nid::encode_nid("_ZTVN10__cxxabiv121__vmi_class_type_infoE"));
        relas.push((ti_foo, (1 << 32) | 1, 16));
        relas.push(rel(ti_foo + 8, foo_n));
        relas.push((ti_bar, (2 << 32) | 1, 16));
        relas.push(rel(ti_bar + 8, bar_n));
        relas.push(rel(ti_bar + 16, ti_foo));
        relas.push((ti_baz, (3 << 32) | 1, 16));
        relas.push(rel(ti_baz + 8, baz_n));
        let off = (ti_baz - 0x3000) as usize;
        data[off + 20..off + 24].copy_from_slice(&2u32.to_le_bytes());
        relas.push(rel(ti_baz + 24, ti_foo));
        data[off + 32..off + 40].copy_from_slice(&2u64.to_le_bytes());
        relas.push(rel(ti_baz + 40, ti_bar));
        data[off + 48..off + 56].copy_from_slice(&((8u64 << 8) | 2).to_le_bytes());
        // vtables
        relas.push(rel(vt_foo + 8, ti_foo));
        relas.push(rel(vt_foo + 16, 0x1000));
        relas.push(rel(vt_foo + 24, 0x1010));
        relas.push(rel(vt_bar + 8, ti_bar));
        relas.push(rel(vt_bar + 16, 0x1020));
        relas.push(rel(vt_bar + 24, 0x1010));
        relas.push((vt_bar + 32, (4 << 32) | 1, 0)); // pure virtual import
        relas.push(rel(vt_baz + 8, ti_baz));
        relas.push(rel(vt_baz + 16, 0x1040));
        let sec = (vt_baz + 24 - 0x3000) as usize;
        data[sec..sec + 8].copy_from_slice(&(-8i64).to_le_bytes());
        relas.push(rel(vt_baz + 32, ti_baz));
        relas.push(rel(vt_baz + 40, 0x1050));
        let elf = build_elf(
            &[(0x1000, 5, text), (0x2000, 4, rodata), (0x3000, 6, data)],
            &relas,
            &[
                ("_ZTVN10__cxxabiv117__class_type_infoE", false, 0),
                ("_ZTVN10__cxxabiv120__si_class_type_infoE", false, 0),
                (&vmi_nid, false, 0),
                ("__cxa_pure_virtual", false, 0),
            ],
        );
        let mut source = Source::from_elf("t", elf).unwrap();
        let options = Options { max_classes: 100, max_virtuals: 64, overrides: HashMap::new() };
        let result = recover(&mut source, &options).unwrap();
        assert_eq!(result["format"], "ps4wb-classes-v1");
        assert_eq!(result["image_base"], "0x1000");
        let classes = result["classes"].as_array().unwrap();
        assert_eq!(classes.len(), 3, "{result:#}");
        let find = |name: &str| classes.iter().find(|c| c["name"] == name).unwrap().clone();
        let foo = find("Foo");
        assert_eq!(foo["typeinfo"], "0x2000");
        assert_eq!(foo["vtable"], "0x2060");
        assert_eq!(foo["virtuals"], json!([{"index":0,"target":"0x0"},{"index":1,"target":"0x10"}]));
        assert_eq!(foo["confidence"], "high");
        let bar = find("ns::Bar");
        assert_eq!(bar["typeinfo_kind"], "si");
        assert_eq!(bar["bases"], json!(["Foo"]));
        assert_eq!(bar["virtuals"][2]["import"], "__cxa_pure_virtual");
        let baz = find("ns::Baz<int>");
        assert_eq!(baz["typeinfo_kind"], "vmi");
        assert_eq!(baz["bases"], json!(["Foo", "ns::Bar"]));
        assert_eq!(baz["base_details"][1]["offset"], 8);
        assert_eq!(baz["virtuals"].as_array().unwrap().len(), 1);
        assert_eq!(baz["secondary_vtables"][0]["offset_to_top"], -8);
    }

    #[test]
    fn live_module_recovery_through_fixture() {
        let base = 0x40_0000u64;
        let data_va = base + 0x1000;
        let libc = 0x9000_0000u64;
        let mut image = vec![0xc3u8; 0x100];
        image.resize(0x1000, 0);
        let mut data = Vec::new();
        // names at data_va
        data.extend(b"4Base\x007Derived\0");
        data.resize(0x20, 0);
        let (ti_base, ti_derived) = (data_va + 0x20, data_va + 0x30);
        q(&mut data, libc + 0x10);
        q(&mut data, data_va);
        q(&mut data, libc + 0x40);
        q(&mut data, data_va + 6);
        q(&mut data, ti_base);
        data.resize(0x60, 0);
        q(&mut data, 0);
        q(&mut data, ti_derived);
        q(&mut data, base + 0x10);
        q(&mut data, libc + 0x800); // external (libc) code pointer
        q(&mut data, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = crate::debugger::fake::spawn_fixture(
            listener,
            crate::debugger::fake::Fixture {
                pid: 90,
                base,
                image,
                extra_maps: vec![
                    (data_va, data_va + 0x1000, 3, "fixture.elf".into()),
                    (libc, libc + 0x1000, 5, "libc.prx".into()),
                ],
                extra_memory: vec![(data_va, data)],
                ..Default::default()
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), fake.port);
        let mut registry = crate::tools::ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let result = registry
            .call("rtti_recover", json!({"pid": 90, "module": "fixture.elf"}))
            .unwrap();
        assert_eq!(result["stats"]["typeinfos"], 2, "{result:#}");
        let path = result["artifact"]["path"].as_str().unwrap();
        let full: Value = serde_json::from_slice(&registry.workbench.read_artifact(path, 1 << 20).unwrap()).unwrap();
        let derived = full["classes"].as_array().unwrap().iter().find(|c| c["name"] == "Derived").unwrap();
        assert_eq!(derived["bases"], json!(["Base"]));
        assert_eq!(derived["vtable"], "0x1060");
        assert_eq!(derived["virtuals"][0]["target"], "0x10");
        assert_eq!(derived["virtuals"][1]["external"], format!("{:#x}", libc + 0x800));
    }
}
