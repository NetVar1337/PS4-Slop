//! Unity IL2CPP metadata recovery (`global-metadata.dat`).
//!
//! Struct layouts follow Il2CppDumper's `Il2Cpp/MetadataClass.cs` (Perfare,
//! MIT) which mirrors Unity's `vm/GlobalMetadataFileInternals.h`; each field is
//! listed with the `[Version(Min, Max)]` range Il2CppDumper uses, so the record
//! size is derived per version instead of hard-coded. Version 24 sub-versions
//! are disambiguated the way Il2CppDumper's `Metadata.cs` does it
//! (`stringLiteralOffset == 264` ⇒ 24.2; else image tokens ≠ 1 ⇒ 24.1).
//! Every table is additionally sanity-checked and alternative layouts are tried
//! if the expected one does not validate.
//!
//! Method addresses come from the game binary: for v24.2+ the
//! `Il2CppCodeRegistration.codeGenModules` array is located like Il2CppDumper's
//! `FindCodeRegistration2019` (pointer chain mscorlib.dll string → module →
//! module array preceded by the image count), and a method pointer is
//! `module.methodPointers[(token & 0xFFFFFF) - 1]`; for ≤24.1 the global
//! `methodPointers[methodIndex]` array is found by its count. Type names for
//! fields/parameters/returns use `Il2CppMetadataRegistration.types` located
//! like `FindMetadataRegistrationV21` (typeDefinitionsSizesCount ==
//! fieldOffsetsCount == type count, struct start = that field − 12 pointers).
use crate::{
    Result,
    bytesource::{Mode, PROT_X, Source, TargetSpec, hex},
    workbench::Workbench,
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub const MAGIC: u32 = 0xFAB1_1BAF;
const MAX_STRING: usize = 4096;

/// `(field, size, min_version, max_version)`; versions ×10 (24.1 → 241).
type FieldSpec = (&'static str, usize, u32, u32);
const ANY: u32 = 999;

const TYPE_DEFINITION: &[FieldSpec] = &[
    ("nameIndex", 4, 0, ANY),
    ("namespaceIndex", 4, 0, ANY),
    ("customAttributeIndex", 4, 0, 240),
    ("byvalTypeIndex", 4, 0, ANY),
    ("byrefTypeIndex", 4, 0, 245),
    ("declaringTypeIndex", 4, 0, ANY),
    ("parentIndex", 4, 0, ANY),
    ("elementTypeIndex", 4, 0, ANY),
    ("rgctxStartIndex", 4, 0, 241),
    ("rgctxCount", 4, 0, 241),
    ("genericContainerIndex", 4, 0, ANY),
    ("flags", 4, 0, ANY),
    ("fieldStart", 4, 0, ANY),
    ("methodStart", 4, 0, ANY),
    ("eventStart", 4, 0, ANY),
    ("propertyStart", 4, 0, ANY),
    ("nestedTypesStart", 4, 0, ANY),
    ("interfacesStart", 4, 0, ANY),
    ("vtableStart", 4, 0, ANY),
    ("interfaceOffsetsStart", 4, 0, ANY),
    ("method_count", 2, 0, ANY),
    ("property_count", 2, 0, ANY),
    ("field_count", 2, 0, ANY),
    ("event_count", 2, 0, ANY),
    ("nested_type_count", 2, 0, ANY),
    ("vtable_count", 2, 0, ANY),
    ("interfaces_count", 2, 0, ANY),
    ("interface_offsets_count", 2, 0, ANY),
    ("bitfield", 4, 0, ANY),
    ("token", 4, 0, ANY),
];

const METHOD_DEFINITION: &[FieldSpec] = &[
    ("nameIndex", 4, 0, ANY),
    ("declaringType", 4, 0, ANY),
    ("returnType", 4, 0, ANY),
    ("parameterStart", 4, 0, ANY),
    ("customAttributeIndex", 4, 0, 240),
    ("genericContainerIndex", 4, 0, ANY),
    ("methodIndex", 4, 0, 241),
    ("invokerIndex", 4, 0, 241),
    ("delegateWrapperIndex", 4, 0, 241),
    ("rgctxStartIndex", 4, 0, 241),
    ("rgctxCount", 4, 0, 241),
    ("token", 4, 0, ANY),
    ("flags", 2, 0, ANY),
    ("iflags", 2, 0, ANY),
    ("slot", 2, 0, ANY),
    ("parameterCount", 2, 0, ANY),
];

const FIELD_DEFINITION: &[FieldSpec] =
    &[("nameIndex", 4, 0, ANY), ("typeIndex", 4, 0, ANY), ("customAttributeIndex", 4, 0, 240), ("token", 4, 0, ANY)];

const PARAMETER_DEFINITION: &[FieldSpec] =
    &[("nameIndex", 4, 0, ANY), ("token", 4, 0, ANY), ("customAttributeIndex", 4, 0, 240), ("typeIndex", 4, 0, ANY)];

const IMAGE_DEFINITION: &[FieldSpec] = &[
    ("nameIndex", 4, 0, ANY),
    ("assemblyIndex", 4, 0, ANY),
    ("typeStart", 4, 0, ANY),
    ("typeCount", 4, 0, ANY),
    ("exportedTypeStart", 4, 0, ANY),
    ("exportedTypeCount", 4, 0, ANY),
    ("entryPointIndex", 4, 0, ANY),
    ("token", 4, 0, ANY),
    ("customAttributeStart", 4, 241, ANY),
    ("customAttributeCount", 4, 241, ANY),
];

/// `Il2CppGenericParameter`: ownerIndex, nameIndex, constraintsStart(i16),
/// constraintsCount(i16), num(u16), flags(u16) — 16 bytes for 24–29.
const GENERIC_PARAMETER_SIZE: usize = 16;

#[derive(Clone, Debug)]
struct Layout {
    offsets: HashMap<&'static str, (usize, usize)>,
    size: usize,
}

impl Layout {
    fn new(fields: &[FieldSpec], version: u32) -> Self {
        let mut offsets = HashMap::new();
        let mut size = 0;
        for (name, width, min, max) in fields {
            if (*min..=*max).contains(&version) {
                offsets.insert(*name, (size, *width));
                size += width;
            }
        }
        Self { offsets, size }
    }
    fn has(&self, field: &str) -> bool {
        self.offsets.contains_key(field)
    }
}

/// Header table indices (pairs of u32 offset/size starting at byte 8).
const T_STRING_LITERAL: usize = 0;
const T_STRING_LITERAL_DATA: usize = 1;
const T_STRING: usize = 2;
const T_METHODS: usize = 5;
const T_PARAMETERS: usize = 10;
const T_FIELDS: usize = 11;
const T_GENERIC_PARAMETERS: usize = 12;
const T_NESTED_TYPES: usize = 15;
const T_TYPE_DEFINITIONS: usize = 19;

#[derive(Debug)]
pub struct Metadata<'m> {
    data: &'m [u8],
    pub version: u32,
    images_table: usize,
    typedef: Layout,
    method: Layout,
    field: Layout,
    param: Layout,
    image: Layout,
    pub notes: Vec<String>,
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Plausible header: magic, version, and table spans inside `limit` bytes.
pub fn header_plausible(head: &[u8]) -> Option<(u32, usize)> {
    if u32_at(head, 0)? != MAGIC {
        return None;
    }
    let version = u32_at(head, 4)?;
    if !(24..=31).contains(&version) {
        return None;
    }
    let first = u32_at(head, 8)? as usize;
    if !(0xa0..=0x200).contains(&first) || !first.is_multiple_of(4) {
        return None;
    }
    let mut total = first;
    for pair in 0..(first - 8) / 8 {
        let (offset, size) = (u32_at(head, 8 + pair * 8)? as usize, u32_at(head, 12 + pair * 8)? as usize);
        if offset == 0 && size == 0 {
            continue;
        }
        if offset < first || offset > (1 << 30) || size > (1 << 30) {
            return None;
        }
        total = total.max(offset + size);
    }
    Some((version, total))
}

impl<'m> Metadata<'m> {
    pub fn parse(data: &'m [u8], version_override: Option<f64>) -> Result<Self> {
        ensure!(data.len() >= 0x100, "Metadata too small");
        ensure!(u32_at(data, 0) == Some(MAGIC), "Bad global-metadata magic (expected 0xFAB11BAF)");
        let raw_version = u32_at(data, 4).unwrap();
        let mut notes = Vec::new();
        let version = match version_override {
            Some(v) => (v * 10.0).round() as u32,
            None => {
                ensure!(
                    (24..=29).contains(&raw_version),
                    "Metadata version {raw_version} unsupported (24-29); pass `version` to force a layout"
                );
                if raw_version == 24 {
                    if u32_at(data, 8) == Some(264) {
                        notes.push("v24 with stringLiteralOffset == 264 => 24.2 (Il2CppDumper rule)".into());
                        242
                    } else {
                        // 24.0/24.1 keep rgctxEntries in the header, so images follow at 176.
                        let layout = Layout::new(IMAGE_DEFINITION, 240);
                        let (offset, size) = (u32_at(data, 176).unwrap_or(0) as usize, u32_at(data, 180).unwrap_or(0) as usize);
                        let count = size / layout.size;
                        let all_one = (0..count.min(4096))
                            .all(|i| u32_at(data, offset + i * layout.size + 28) == Some(1));
                        notes.push(format!("v24 sub-version from image tokens: {}", if all_one { "24.0" } else { "24.1" }));
                        if all_one { 240 } else { 241 }
                    }
                } else {
                    raw_version * 10
                }
            }
        };
        let mut candidates = vec![version];
        for alternative in [242, 241, 240, 270, 290] {
            if !candidates.contains(&alternative) && (alternative / 10 == version / 10 || version_override.is_none()) {
                candidates.push(alternative);
            }
        }
        let mut last_error = None;
        for (attempt, v) in candidates.into_iter().enumerate() {
            let metadata = Self {
                data,
                version: v,
                images_table: if v <= 241 { 21 } else { 20 },
                typedef: Layout::new(TYPE_DEFINITION, v),
                method: Layout::new(METHOD_DEFINITION, v),
                field: Layout::new(FIELD_DEFINITION, v),
                param: Layout::new(PARAMETER_DEFINITION, v),
                image: Layout::new(IMAGE_DEFINITION, v),
                notes: notes.clone(),
            };
            match metadata.validate() {
                Ok(()) => {
                    let mut metadata = metadata;
                    if attempt > 0 {
                        metadata.notes.push(format!("Expected layout {version} failed validation; using {v}"));
                    }
                    return Ok(metadata);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap().context("No metadata layout validated"))
    }

    fn table(&self, index: usize) -> (usize, usize) {
        let at = 8 + index * 8;
        (u32_at(self.data, at).unwrap_or(0) as usize, u32_at(self.data, at + 4).unwrap_or(0) as usize)
    }

    fn validate(&self) -> Result<()> {
        let (_, string_size) = self.table(T_STRING);
        for (index, layout, what) in [
            (T_TYPE_DEFINITIONS, &self.typedef, "typeDefinitions"),
            (T_METHODS, &self.method, "methods"),
            (T_FIELDS, &self.field, "fields"),
            (T_PARAMETERS, &self.param, "parameters"),
            (self.images_table, &self.image, "images"),
        ] {
            let (offset, size) = self.table(index);
            ensure!(offset + size <= self.data.len(), "{what} table exceeds the file");
            ensure!(size % layout.size == 0, "{what} size {size} is not a multiple of {}", layout.size);
            let count = size / layout.size;
            for i in (0..count).step_by((count / 64).max(1)) {
                let name = self.field_u32(index, layout, i, "nameIndex").context("record")? as usize;
                ensure!(name < string_size, "{what}[{i}] name index out of range");
            }
        }
        let images = self.count(self.images_table, &self.image);
        let types = self.count(T_TYPE_DEFINITIONS, &self.typedef);
        ensure!(images > 0 && types > 0, "No images or types");
        for i in 0..images {
            let start = self.field_u32(self.images_table, &self.image, i, "typeStart").unwrap_or(u32::MAX) as usize;
            let count = self.field_u32(self.images_table, &self.image, i, "typeCount").unwrap_or(u32::MAX) as usize;
            ensure!(start.saturating_add(count) <= types, "image {i} type range exceeds type count");
        }
        Ok(())
    }

    fn count(&self, table: usize, layout: &Layout) -> usize {
        self.table(table).1 / layout.size
    }

    fn field_raw(&self, table: usize, layout: &Layout, index: usize, field: &str) -> Option<u32> {
        let (offset, width) = *layout.offsets.get(field)?;
        let at = self.table(table).0 + index * layout.size + offset;
        match width {
            2 => self.data.get(at..at + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()) as u32),
            _ => u32_at(self.data, at),
        }
    }

    fn field_u32(&self, table: usize, layout: &Layout, index: usize, field: &str) -> Option<u32> {
        self.field_raw(table, layout, index, field)
    }

    fn field_i32(&self, table: usize, layout: &Layout, index: usize, field: &str) -> Option<i32> {
        self.field_raw(table, layout, index, field).map(|v| v as i32)
    }

    pub fn string(&self, index: u32) -> String {
        let (offset, size) = self.table(T_STRING);
        let start = offset + index as usize;
        let end = (offset + size).min(self.data.len());
        if start >= end {
            return String::new();
        }
        let slice = &self.data[start..end.min(start + MAX_STRING)];
        let length = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..length]).into_owned()
    }

    pub fn type_count(&self) -> usize {
        self.count(T_TYPE_DEFINITIONS, &self.typedef)
    }

    fn string_literals(&self, max: usize) -> Vec<Value> {
        let (offset, size) = self.table(T_STRING_LITERAL);
        let (data_offset, data_size) = self.table(T_STRING_LITERAL_DATA);
        (0..size / 8)
            .take(max)
            .filter_map(|i| {
                let length = u32_at(self.data, offset + i * 8)? as usize;
                let index = u32_at(self.data, offset + i * 8 + 4)? as usize;
                if index + length > data_size {
                    return None;
                }
                let bytes = self.data.get(data_offset + index..data_offset + index + length)?;
                Some(json!({"index": i, "value": String::from_utf8_lossy(bytes)}))
            })
            .collect()
    }

    fn generic_parameter_name(&self, index: u64) -> Option<String> {
        let (offset, size) = self.table(T_GENERIC_PARAMETERS);
        let index = index as usize;
        if index >= size / GENERIC_PARAMETER_SIZE {
            return None;
        }
        Some(self.string(u32_at(self.data, offset + index * GENERIC_PARAMETER_SIZE + 4)?))
    }
}

// ---- binary registration ---------------------------------------------------------------

struct Registration<'s, 'a> {
    source: &'s mut Source<'a>,
    types: Option<(u64, u64)>,
    /// image name -> (methodPointers, count)
    modules: HashMap<String, (u64, u64)>,
    method_pointers: Option<(u64, u64)>,
    metadata_va: Option<u64>,
    notes: Vec<String>,
}

fn data_ranges(source: &Source) -> Vec<(u64, u64)> {
    let ranges = source.ranges_with(0, PROT_X);
    if ranges.is_empty() { source.selection.clone() } else { ranges }
}

fn find_string(source: &mut Source, ranges: &[(u64, u64)], needle: &[u8]) -> Result<Vec<u64>> {
    let finder = aho_corasick::AhoCorasick::new([needle])?;
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    source.scan(Some(ranges), needle.len(), |va, chunk| {
        for m in finder.find_iter(chunk) {
            let at = va + m.start() as u64;
            let preceded = m.start() == 0 || chunk[m.start() - 1] == 0;
            if preceded && seen.insert(at) {
                hits.push(at);
            }
        }
        hits.len() < 64
    })?;
    Ok(hits)
}

/// Locate `codeGenModules` (v24.2+): returns (array address, count).
fn find_code_gen_modules(source: &mut Source, image_count: u64) -> Result<Option<(u64, u64)>> {
    let ranges = data_ranges(source);
    let names = find_string(source, &ranges, b"mscorlib.dll\0")?;
    let name_set: HashSet<u64> = names.into_iter().collect();
    let modules: HashSet<u64> = source.find_pointers(&ranges, &name_set, 64)?.into_iter().map(|p| p.0).collect();
    let refs = source.find_pointers(&ranges, &modules, 256)?;
    let mut starts = HashSet::new();
    for (slot, _) in &refs {
        for k in 0..image_count.min(4096) {
            if let Some(start) = slot.checked_sub(8 * k) {
                starts.insert(start);
            }
        }
    }
    for (slot, array) in source.find_pointers(&ranges, &starts, 4096)? {
        if source.u64(slot - 8) == Some(image_count) {
            return Ok(Some((array, image_count)));
        }
    }
    Ok(None)
}

/// Locate the ≤24.1 `methodPointers` array by its count.
fn find_method_pointers(source: &mut Source, count: u64) -> Result<Option<(u64, u64)>> {
    let ranges = data_ranges(source);
    let targets: HashSet<u64> = [count].into_iter().collect();
    for (slot, _) in source.find_pointers(&ranges, &targets, 4096)? {
        let Some(array) = source.u64(slot + 8) else { continue };
        let probe = count.min(16);
        let ok = (0..probe).all(|i| source.u64(array + i * 8).is_some_and(|p| p == 0 || source.is_exec(p)));
        let nonzero = (0..probe).any(|i| source.u64(array + i * 8).is_some_and(|p| p != 0));
        if ok && nonzero {
            return Ok(Some((array, count)));
        }
    }
    Ok(None)
}

/// Locate `Il2CppMetadataRegistration` and return its `types` (array, count).
fn find_metadata_registration(source: &mut Source, type_count: u64) -> Result<Option<(u64, u64)>> {
    let ranges = data_ranges(source);
    let targets: HashSet<u64> = [type_count].into_iter().collect();
    for (slot, _) in source.find_pointers(&ranges, &targets, 4096)? {
        // slot = typeDefinitionsSizesCount (field 12); fieldOffsetsCount is field 10.
        if source.u64(slot.wrapping_sub(16)) != Some(type_count) {
            continue;
        }
        let Some(sizes) = source.u64(slot + 8) else { continue };
        let probe = type_count.min(8);
        if !(0..probe).all(|i| source.u64(sizes + i * 8).is_some_and(|p| source.is_mapped(p))) {
            continue;
        }
        let start = slot - 96;
        if let Some(found) = types_from_registration(source, start) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn types_from_registration(source: &mut Source, start: u64) -> Option<(u64, u64)> {
    let count = source.u64(start + 48)?;
    let array = source.u64(start + 56)?;
    let first = source.u64(array)?;
    (count > 0 && count < 10_000_000 && source.is_mapped(first)).then_some((array, count))
}

impl Registration<'_, '_> {
    fn method_pointer(&mut self, image: &str, token: u32, method_index: Option<i32>) -> Option<u64> {
        let pointer = if let Some((array, count)) = self.method_pointers {
            let index = method_index.filter(|i| *i >= 0)? as u64;
            if index >= count {
                return None;
            }
            self.source.u64(array + index * 8)?
        } else {
            let (array, count) = *self.modules.get(image)?;
            let rid = (token & 0x00ff_ffff) as u64;
            if rid == 0 || rid > count {
                return None;
            }
            self.source.u64(array + (rid - 1) * 8)?
        };
        (pointer != 0).then_some(pointer)
    }

    fn type_name(&mut self, metadata: &Metadata, names: &[String], index: i32, depth: usize) -> String {
        let fallback = format!("type#{index}");
        let Some((array, count)) = self.types else { return fallback };
        if index < 0 || index as u64 >= count {
            return fallback;
        }
        self.source
            .u64(array + index as u64 * 8)
            .and_then(|pointer| self.il2cpp_type(metadata, names, pointer, depth))
            .unwrap_or(fallback)
    }

    /// Render an `Il2CppType*`: `{ data (8 bytes), u32 bits }` with
    /// `type = (bits >> 16) & 0xff` (Il2CppTypeEnum = ECMA-335 CorElementType).
    fn il2cpp_type(&mut self, metadata: &Metadata, names: &[String], pointer: u64, depth: usize) -> Option<String> {
        if depth > 6 {
            return Some("?".into());
        }
        let data = self.source.u64(pointer)?;
        let bits = self.source.u32(pointer + 8)?;
        let kind = (bits >> 16) & 0xff;
        let byref = if bits & (1 << 30) != 0 { "&" } else { "" };
        let primitive = match kind {
            0x01 => Some("void"),
            0x02 => Some("bool"),
            0x03 => Some("char"),
            0x04 => Some("sbyte"),
            0x05 => Some("byte"),
            0x06 => Some("short"),
            0x07 => Some("ushort"),
            0x08 => Some("int"),
            0x09 => Some("uint"),
            0x0a => Some("long"),
            0x0b => Some("ulong"),
            0x0c => Some("float"),
            0x0d => Some("double"),
            0x0e => Some("string"),
            0x16 => Some("TypedReference"),
            0x18 => Some("IntPtr"),
            0x19 => Some("UIntPtr"),
            0x1c => Some("object"),
            _ => None,
        };
        if let Some(name) = primitive {
            return Some(format!("{name}{byref}"));
        }
        let name = match kind {
            0x11 | 0x12 => self.typedef_from_handle(metadata, data).and_then(|i| names.get(i).cloned())?,
            0x0f => format!("{}*", self.il2cpp_type(metadata, names, data, depth + 1)?),
            0x1d => format!("{}[]", self.il2cpp_type(metadata, names, data, depth + 1)?),
            0x14 => {
                let element = self.source.u64(data)?;
                let rank = self.source.read(data + 8, 1)?[0].max(1);
                let inner = self.il2cpp_type(metadata, names, element, depth + 1)?;
                format!("{inner}[{}]", ",".repeat(rank as usize - 1))
            }
            0x13 | 0x1e => {
                let index = if data < 0x100_0000 { Some(data) } else { None };
                index.and_then(|i| metadata.generic_parameter_name(i)).unwrap_or_else(|| "T".into())
            }
            0x15 => {
                // Il2CppGenericClass: <27: { i64 typeDefinitionIndex; context{class_inst, method_inst}; cached }
                // ≥27: { Il2CppType* type; context… }
                let head = self.source.u64(data)?;
                let base = if metadata.version >= 270 {
                    self.il2cpp_type(metadata, names, head, depth + 1)?
                } else {
                    names.get(head as usize)?.clone()
                };
                let base = base.split('`').next().unwrap_or(&base).to_owned();
                let inst = self.source.u64(data + 8)?;
                let argc = self.source.u64(inst)?.min(32);
                let argv = self.source.u64(inst + 8)?;
                let mut args = Vec::new();
                for i in 0..argc {
                    let arg = self.source.u64(argv + i * 8)?;
                    args.push(self.il2cpp_type(metadata, names, arg, depth + 1).unwrap_or_else(|| "?".into()));
                }
                format!("{base}<{}>", args.join(", "))
            }
            _ => return None,
        };
        Some(format!("{name}{byref}"))
    }

    /// Class/valuetype data: a type-definition index on disk; in a dumped (live)
    /// v27+ image a pointer into the loaded metadata (Il2CppDumper
    /// `GetTypeDefinitionFromIl2CppType`).
    fn typedef_from_handle(&self, metadata: &Metadata, data: u64) -> Option<usize> {
        let count = metadata.type_count() as u64;
        if data < count {
            return Some(data as usize);
        }
        let base = self.metadata_va? + metadata.table(T_TYPE_DEFINITIONS).0 as u64;
        let offset = data.checked_sub(base)?;
        (offset.is_multiple_of(metadata.typedef.size as u64) && offset / (metadata.typedef.size as u64) < count)
            .then(|| (offset / metadata.typedef.size as u64) as usize)
    }
}

// ---- dump --------------------------------------------------------------------------

fn access(flags: u32) -> &'static str {
    // ECMA-335 II.23.1.10 MethodAttributes / II.23.1.5 FieldAttributes access mask 0x7.
    match flags & 7 {
        1 => "private",
        2 => "private protected",
        3 => "internal",
        4 => "protected",
        5 => "protected internal",
        6 => "public",
        _ => "",
    }
}

fn type_keyword(flags: u32) -> (&'static str, &'static str) {
    // ECMA-335 II.23.1.15 TypeAttributes.
    let visibility = match flags & 7 {
        1 | 2 => "public",
        3 => "private",
        4 => "protected",
        5 => "internal",
        6 => "private protected",
        7 => "protected internal",
        _ => "internal",
    };
    let kind = if flags & 0x20 != 0 {
        "interface"
    } else if flags & 0x80 != 0 && flags & 0x100 != 0 {
        "static class"
    } else if flags & 0x80 != 0 {
        "abstract class"
    } else if flags & 0x100 != 0 {
        "sealed class"
    } else {
        "class"
    };
    (visibility, kind)
}

pub struct DumpOptions {
    pub max_literals: usize,
}

/// Parse metadata (+ optional binary registration) into the JSON format and dump.cs text.
fn dump(metadata: &Metadata, mut registration: Option<Registration>, options: &DumpOptions) -> (Value, String) {
    let types = metadata.type_count();
    let images = metadata.count(metadata.images_table, &metadata.image);
    let td = &metadata.typedef;
    let get = |index: usize, field: &str| metadata.field_u32(T_TYPE_DEFINITIONS, td, index, field).unwrap_or(0);
    let short_names: Vec<String> = (0..types).map(|i| metadata.string(get(i, "nameIndex"))).collect();
    let namespaces: Vec<String> = (0..types).map(|i| metadata.string(get(i, "namespaceIndex"))).collect();
    // Nesting from the nestedTypes table (TypeDefinitionIndex entries).
    let (nested_offset, nested_size) = metadata.table(T_NESTED_TYPES);
    let mut parent: HashMap<usize, usize> = HashMap::new();
    for i in 0..types {
        let start = get(i, "nestedTypesStart") as usize;
        for k in 0..get(i, "nested_type_count") as usize {
            let at = (start + k) * 4;
            if at + 4 <= nested_size
                && let Some(child) = u32_at(metadata.data, nested_offset + at)
                && (child as usize) < types
            {
                parent.insert(child as usize, i);
            }
        }
    }
    let mut class_names = short_names.clone();
    for (i, class_name) in class_names.iter_mut().enumerate() {
        let mut chain = vec![short_names[i].clone()];
        let mut cursor = i;
        while let Some(p) = parent.get(&cursor) {
            if chain.len() > 16 {
                break;
            }
            chain.push(short_names[*p].clone());
            cursor = *p;
        }
        chain.reverse();
        *class_name = chain.join(".");
    }
    let mut image_of = vec![String::new(); types];
    let mut image_json = Vec::new();
    for i in 0..images {
        let field = |f| metadata.field_u32(metadata.images_table, &metadata.image, i, f).unwrap_or(0);
        let name = metadata.string(field("nameIndex"));
        let (start, count) = (field("typeStart") as usize, field("typeCount") as usize);
        for slot in image_of.iter_mut().skip(start).take(count) {
            slot.clone_from(&name);
        }
        image_json.push(json!({"index": i, "name": name, "type_start": start, "type_count": count}));
    }
    // Full names (namespace.Outer.Inner) for type rendering.
    let full_names: Vec<String> = (0..types)
        .map(|i| {
            let root = (0..17).try_fold(i, |c, _| parent.get(&c).copied().ok_or(c)).unwrap_or_else(|c| c);
            if namespaces[root].is_empty() { class_names[i].clone() } else { format!("{}.{}", namespaces[root], class_names[i]) }
        })
        .collect();
    let render_names: Vec<String> = class_names.clone();

    let mut methods_json = Vec::new();
    let mut types_json = Vec::new();
    let mut text = String::new();
    let mut resolved = 0usize;
    for (i, image) in image_json.iter().enumerate() {
        text += &format!("// Image {i}: {} - {}\n", image["name"].as_str().unwrap_or(""), image["type_start"]);
    }
    text.push('\n');
    let mp = &metadata.method;
    let fd = &metadata.field;
    let pd = &metadata.param;
    for t in 0..types {
        let flags = get(t, "flags");
        let (visibility, kind) = type_keyword(flags);
        let root = (0..17).try_fold(t, |c, _| parent.get(&c).copied().ok_or(c)).unwrap_or_else(|c| c);
        let namespace = namespaces[root].clone();
        text += &format!("// Namespace: {namespace}\n{visibility} {kind} {} // TypeDefIndex: {t}\n{{\n", class_names[t]);
        let mut fields_json = Vec::new();
        let field_start = get(t, "fieldStart") as usize;
        let field_count = get(t, "field_count") as usize;
        if field_count > 0 {
            text += "\t// Fields\n";
        }
        for f in field_start..field_start + field_count {
            let name = metadata.string(metadata.field_u32(T_FIELDS, fd, f, "nameIndex").unwrap_or(0));
            let type_index = metadata.field_i32(T_FIELDS, fd, f, "typeIndex").unwrap_or(-1);
            let type_name = match registration.as_mut() {
                Some(r) => r.type_name(metadata, &render_names, type_index, 0),
                None => format!("type#{type_index}"),
            };
            text += &format!("\t{type_name} {name};\n");
            fields_json.push(json!({"name": name, "type": type_name, "type_index": type_index}));
        }
        let method_start = get(t, "methodStart") as usize;
        let method_count = get(t, "method_count") as usize;
        if method_count > 0 {
            text += "\n\t// Methods\n";
        }
        for m in method_start..method_start + method_count {
            let mget = |f| metadata.field_u32(T_METHODS, mp, m, f).unwrap_or(0);
            let name = metadata.string(mget("nameIndex"));
            let mflags = mget("flags");
            let token = mget("token");
            let method_index = mp.has("methodIndex").then(|| mget("methodIndex") as i32);
            let ret_index = mget("returnType") as i32;
            let (pstart, pcount) = (mget("parameterStart") as usize, mget("parameterCount") as usize);
            let mut params = Vec::new();
            for p in pstart..pstart + pcount.min(256) {
                let pname = metadata.string(metadata.field_u32(T_PARAMETERS, pd, p, "nameIndex").unwrap_or(0));
                let ptype = metadata.field_i32(T_PARAMETERS, pd, p, "typeIndex").unwrap_or(-1);
                let ptype = match registration.as_mut() {
                    Some(r) => r.type_name(metadata, &render_names, ptype, 0),
                    None => format!("type#{ptype}"),
                };
                params.push(format!("{ptype} {pname}"));
            }
            let ret = match registration.as_mut() {
                Some(r) => r.type_name(metadata, &render_names, ret_index, 0),
                None => format!("type#{ret_index}"),
            };
            let mut modifiers = vec![access(mflags)];
            if mflags & 0x10 != 0 {
                modifiers.push("static");
            }
            if mflags & 0x400 != 0 {
                modifiers.push("abstract");
            } else if mflags & 0x40 != 0 {
                modifiers.push("virtual");
            }
            let modifiers: Vec<&str> = modifiers.into_iter().filter(|m| !m.is_empty()).collect();
            let signature = format!("{} {ret} {name}({})", modifiers.join(" "), params.join(", ")).trim().to_owned();
            let pointer = registration.as_mut().and_then(|r| r.method_pointer(&image_of[t], token, method_index));
            let image_base = registration.as_ref().map_or(0, |r| r.source.image_base);
            let rva = pointer.map(|p| hex(p.wrapping_sub(image_base)));
            if pointer.is_some() {
                resolved += 1;
            }
            match (&rva, pointer) {
                (Some(rva), Some(va)) => text += &format!("\t// RVA: {rva} VA: {}\n", hex(va)),
                _ => text += "\t// RVA: -1\n",
            }
            text += &format!("\t{signature} {{ }}\n");
            methods_json.push(json!({
                "rva": rva, "va": pointer.map(hex), "name": name, "class": class_names[t], "namespace": namespace,
                "signature": signature, "token": format!("{token:#010x}"), "image": image_of[t], "type_index": t,
            }));
        }
        text += "}\n\n";
        types_json.push(json!({
            "index": t, "name": class_names[t], "namespace": namespace, "full_name": full_names[t],
            "image": image_of[t], "flags": format!("{flags:#x}"), "kind": kind, "visibility": visibility,
            "token": format!("{:#010x}", get(t, "token")),
            "fields": fields_json, "method_start": method_start, "method_count": method_count,
        }));
    }
    let (image_base, registration_json) = match registration {
        Some(r) => (
            Some(hex(r.source.image_base)),
            json!({
                "types": r.types.map(|(a, c)| json!({"address": hex(a), "count": c})),
                "code_gen_modules": r.modules.iter().map(|(k, (a, c))| json!({"image": k, "method_pointers": hex(*a), "count": c})).collect::<Vec<_>>(),
                "method_pointers": r.method_pointers.map(|(a, c)| json!({"address": hex(a), "count": c})),
                "notes": r.notes, "source": r.source.summary(),
            }),
        ),
        None => (None, Value::Null),
    };
    let value = json!({
        "format": "ps4wb-il2cpp-v1",
        "metadata_version": metadata.version as f64 / 10.0,
        "image_base": image_base,
        "images": image_json,
        "types": types_json,
        "methods": methods_json,
        "string_literals": metadata.string_literals(options.max_literals),
        "registration": registration_json,
        "stats": {"types": types, "methods": metadata.count(T_METHODS, mp), "methods_with_rva": resolved},
        "notes": metadata.notes,
    });
    (value, text)
}

// ---- tool ---------------------------------------------------------------------------

fn locate_live_metadata(source: &mut Source) -> Result<Option<(u64, usize)>> {
    let ranges = source.ranges_with(0, PROT_X);
    let magic = MAGIC.to_le_bytes();
    let mut found = Vec::new();
    source.scan(Some(&ranges), 0x200, |va, chunk| {
        let mut offset = ((4 - (va % 4)) % 4) as usize;
        while offset + 4 <= chunk.len() {
            if chunk[offset..offset + 4] == magic
                && let Some(head) = chunk.get(offset..(offset + 0x200).min(chunk.len()))
                && let Some((_, total)) = header_plausible(head)
            {
                found.push((va + offset as u64, total));
                return false;
            }
            offset += 4;
        }
        true
    })?;
    Ok(found.into_iter().next())
}

fn read_live(source: &mut Source, address: u64, total: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(total);
    let mut cursor = address;
    while out.len() < total {
        let take = (total - out.len()).min(1 << 20);
        let piece = source.read(cursor, take).with_context(|| {
            format!(
                "Cannot read metadata at {cursor:#x} ({} of {total} bytes read; budget exhausted: {}). Raise max_bytes/transfer_bytes or dump it with memory_region_dump and pass metadata_artifact.",
                out.len(),
                source.exhausted
            )
        })?;
        out.extend(piece);
        cursor += take as u64;
    }
    Ok(out)
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let version = args["version"].as_f64();
    let pid = args["pid"].as_u64().map(|p| p as u32);
    let max_bytes = args["max_bytes"].as_u64().map(|v| v as usize);
    let mut notes: Vec<String> = Vec::new();
    // 1. Metadata bytes.
    let (bytes, metadata_va, metadata_from) = if let Some(artifact) = args["metadata_artifact"].as_str() {
        (workbench.read_artifact(artifact, crate::bytesource::ARTIFACT_MAX)?, None, json!({"artifact": artifact}))
    } else {
        let pid = pid.context("Give metadata_artifact or pid")?;
        let spec = TargetSpec { pid: Some(pid), max_bytes, ..Default::default() };
        let mut source = Source::open(workbench, &spec, Mode::Mapped)?;
        let (address, total) = match args.get("metadata_address").filter(|v| !v.is_null()) {
            Some(value) => {
                let address = crate::tools::address(value)?;
                let head = source.read(address, 0x200).context("Cannot read metadata_address")?;
                let (_, total) = header_plausible(&head).context("No plausible IL2CPP metadata header at metadata_address")?;
                (address, total)
            }
            None => locate_live_metadata(&mut source)?.with_context(|| {
                format!(
                    "global-metadata magic not found in readable non-executable maps (bytes scanned {}, budget exhausted: {})",
                    source.fetched, source.exhausted
                )
            })?,
        };
        let bytes = read_live(&mut source, address, total)?;
        notes.push(format!("Metadata read live from {address:#x} ({total} bytes)"));
        (bytes, Some(address), json!({"pid": pid, "address": hex(address), "size": total}))
    };
    let metadata = Metadata::parse(&bytes, version)?;

    // 2. Optional binary.
    let binary_spec = if let Some(artifact) = args["binary_artifact"].as_str() {
        let base = args.get("binary_base").filter(|v| !v.is_null()).map(crate::tools::address).transpose()?;
        Some(TargetSpec { artifact: Some(artifact.to_owned()), base: base.unwrap_or(0), ..Default::default() })
    } else if let Some(module) = args["module"].as_str() {
        Some(TargetSpec { pid: Some(pid.context("module requires pid")?), module: Some(module.to_owned()), max_bytes, ..Default::default() })
    } else {
        None
    };
    let options = DumpOptions { max_literals: 200_000 };
    let override_addr = |key: &str| args.get(key).filter(|v| !v.is_null()).map(crate::tools::address).transpose();
    let (value, text) = if let Some(spec) = binary_spec {
        let mut source = Source::open(workbench, &spec, Mode::Mapped)?;
        let mut registration = Registration {
            source: &mut source,
            types: None,
            modules: HashMap::new(),
            method_pointers: None,
            metadata_va,
            notes: Vec::new(),
        };
        let image_count = metadata.count(metadata.images_table, &metadata.image) as u64;
        if metadata.version <= 241 {
            let count = (0..metadata.count(T_METHODS, &metadata.method))
                .filter_map(|m| metadata.field_i32(T_METHODS, &metadata.method, m, "methodIndex"))
                .max()
                .map_or(0, |max| (max + 1).max(0) as u64);
            registration.method_pointers = match override_addr("method_pointers")? {
                Some(address) => Some((address, count)),
                None => find_method_pointers(registration.source, count)?,
            };
            registration.notes.push(match registration.method_pointers {
                Some((a, _)) => format!("methodPointers array at {a:#x} (count {count})"),
                None => "methodPointers array not found (heuristic: count followed by exec pointer array)".into(),
            });
        } else {
            let found = match override_addr("code_gen_modules")? {
                Some(address) => Some((address, image_count)),
                None => find_code_gen_modules(registration.source, image_count)?,
            };
            match found {
                Some((array, count)) => {
                    registration.notes.push(format!("codeGenModules at {array:#x} ({count} modules)"));
                    for i in 0..count {
                        let source = &mut *registration.source;
                        let Some(module) = source.u64(array + i * 8) else { continue };
                        let (Some(name_ptr), Some(method_count), Some(pointers)) =
                            (source.u64(module), source.u64(module + 8), source.u64(module + 16))
                        else {
                            continue;
                        };
                        let Some(name) = source.cstr(name_ptr, 256) else { continue };
                        if method_count < 10_000_000 {
                            registration.modules.insert(String::from_utf8_lossy(&name).into_owned(), (pointers, method_count));
                        }
                    }
                }
                None => registration.notes.push(
                    "Il2CppCodeRegistration.codeGenModules not found (mscorlib.dll module chain heuristic); pass code_gen_modules".into(),
                ),
            }
        }
        registration.types = match override_addr("metadata_registration")? {
            Some(address) => types_from_registration(registration.source, address),
            None => find_metadata_registration(registration.source, metadata.type_count() as u64)?,
        };
        if registration.types.is_none() {
            registration.notes.push("Il2CppMetadataRegistration.types not found; type names shown as type#N".into());
        }
        dump(&metadata, Some(registration), &options)
    } else {
        notes.push("No binary given: names/types only; method RVAs and type names need binary_artifact or pid+module".into());
        dump(&metadata, None, &options)
    };
    let saved = crate::engines::save_json(workbench, "il2cpp", &value, json!({"tool": "il2cpp_dump"}))?;
    let dump_cs = if args["include_dump_cs"].as_bool().unwrap_or(true) {
        Some(crate::engines::artifact_ref(&crate::engines::save_text(workbench, "il2cpp-dump", &text, "cs", json!({"tool": "il2cpp_dump"}))?))
    } else {
        None
    };
    let preview: Vec<Value> = value["methods"]
        .as_array()
        .map(|m| m.iter().filter(|m| !m["rva"].is_null()).take(10).cloned().collect())
        .unwrap_or_default();
    Ok(json!({
        "format": "ps4wb-il2cpp-v1",
        "json": crate::engines::artifact_ref(&saved),
        "dump_cs": dump_cs,
        "metadata": metadata_from,
        "metadata_version": value["metadata_version"],
        "image_base": value["image_base"],
        "stats": value["stats"],
        "registration": value["registration"],
        "preview_methods": preview,
        "notes": notes.into_iter().chain(metadata.notes.iter().cloned()).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    struct Builder {
        strings: Vec<u8>,
    }
    impl Builder {
        fn s(&mut self, text: &str) -> u32 {
            let at = self.strings.len() as u32;
            self.strings.extend(text.as_bytes());
            self.strings.push(0);
            at
        }
    }

    fn record(layout: &Layout, values: &[(&str, u32)]) -> Vec<u8> {
        let mut out = vec![0u8; layout.size];
        for (name, value) in values {
            let (offset, width) = layout.offsets[name];
            out[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        out
    }

    /// Synthetic v24.2 metadata: images mscorlib.dll (System.Object) and
    /// Game.dll (Game.Player with nested Inner).
    pub fn sample_metadata() -> Vec<u8> {
        let v = 242;
        let (td, md, fd, pd, im) = (
            Layout::new(TYPE_DEFINITION, v),
            Layout::new(METHOD_DEFINITION, v),
            Layout::new(FIELD_DEFINITION, v),
            Layout::new(PARAMETER_DEFINITION, v),
            Layout::new(IMAGE_DEFINITION, v),
        );
        let mut b = Builder { strings: vec![0] };
        let (system, object, game, player, inner) = (b.s("System"), b.s("Object"), b.s("Game"), b.s("Player"), b.s("Inner"));
        let (ctor, update, get_health, run, dt, health) =
            (b.s(".ctor"), b.s("Update"), b.s("get_Health"), b.s("Run"), b.s("dt"), b.s("health"));
        let (mscorlib, game_dll) = (b.s("mscorlib.dll"), b.s("Game.dll"));
        let mut types = Vec::new();
        types.extend(record(&td, &[("nameIndex", object), ("namespaceIndex", system), ("flags", 1), ("methodStart", 0), ("method_count", 1), ("nested_type_count", 0)]));
        types.extend(record(&td, &[("nameIndex", player), ("namespaceIndex", game), ("flags", 1), ("methodStart", 1), ("method_count", 2), ("fieldStart", 0), ("field_count", 1), ("nestedTypesStart", 0), ("nested_type_count", 1)]));
        types.extend(record(&td, &[("nameIndex", inner), ("namespaceIndex", 0), ("flags", 2 | 0x100), ("methodStart", 3), ("method_count", 1)]));
        let mut methods = Vec::new();
        methods.extend(record(&md, &[("nameIndex", ctor), ("returnType", 0), ("token", 0x0600_0001), ("flags", 6)]));
        methods.extend(record(&md, &[("nameIndex", update), ("returnType", 0), ("parameterStart", 0), ("parameterCount", 1), ("token", 0x0600_0001), ("flags", 6 | 0x40)]));
        methods.extend(record(&md, &[("nameIndex", get_health), ("returnType", 2), ("token", 0x0600_0002), ("flags", 6)]));
        methods.extend(record(&md, &[("nameIndex", run), ("returnType", 5), ("token", 0x0600_0003), ("flags", 1 | 0x10)]));
        let params = record(&pd, &[("nameIndex", dt), ("typeIndex", 1)]);
        let fields = record(&fd, &[("nameIndex", health), ("typeIndex", 2)]);
        let mut images = Vec::new();
        images.extend(record(&im, &[("nameIndex", mscorlib), ("typeStart", 0), ("typeCount", 1), ("token", 1)]));
        images.extend(record(&im, &[("nameIndex", game_dll), ("typeStart", 1), ("typeCount", 2), ("token", 1)]));
        let nested = 2u32.to_le_bytes().to_vec();
        let literal_data = b"HelloWorld".to_vec();
        let mut literals = Vec::new();
        for (length, index) in [(5u32, 0u32), (5, 5)] {
            literals.extend(length.to_le_bytes());
            literals.extend(index.to_le_bytes());
        }
        let mut tables: Vec<(usize, Vec<u8>)> = vec![
            (T_STRING_LITERAL, literals),
            (T_STRING_LITERAL_DATA, literal_data),
            (T_STRING, b.strings.clone()),
            (T_METHODS, methods),
            (T_PARAMETERS, params),
            (T_FIELDS, fields),
            (T_NESTED_TYPES, nested),
            (T_TYPE_DEFINITIONS, types),
            (20, images),
        ];
        let mut out = vec![0u8; 264];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&24u32.to_le_bytes());
        for (index, content) in tables.iter_mut() {
            let offset = out.len() as u32;
            out[8 + *index * 8..12 + *index * 8].copy_from_slice(&offset.to_le_bytes());
            out[12 + *index * 8..16 + *index * 8].copy_from_slice(&(content.len() as u32).to_le_bytes());
            out.extend(content.iter());
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
        out
    }

    /// Raw binary dump at `base` with code-gen modules, metadata registration and types.
    pub fn sample_binary(base: u64) -> Vec<u8> {
        let mut image = vec![0u8; 0x2000];
        let put = |image: &mut Vec<u8>, at: u64, value: u64| {
            let at = (at - base) as usize;
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        image[0x100..0x200].fill(0xc3);
        let strings = base + 0x400;
        image[0x400..0x40d].copy_from_slice(b"mscorlib.dll\0");
        image[0x410..0x419].copy_from_slice(b"Game.dll\0");
        // methodPointers arrays
        let (mp_core, mp_game) = (base + 0x600, base + 0x620);
        put(&mut image, mp_core, base + 0x100);
        put(&mut image, mp_game, base + 0x110);
        put(&mut image, mp_game + 8, base + 0x120);
        put(&mut image, mp_game + 16, base + 0x130);
        // Il2CppCodeGenModule { name, methodPointerCount, methodPointers }
        let (mod_core, mod_game) = (base + 0x700, base + 0x740);
        put(&mut image, mod_core, strings);
        put(&mut image, mod_core + 8, 1);
        put(&mut image, mod_core + 16, mp_core);
        put(&mut image, mod_game, strings + 0x10);
        put(&mut image, mod_game + 8, 3);
        put(&mut image, mod_game + 16, mp_game);
        let modules = base + 0x800;
        put(&mut image, modules, mod_game);
        put(&mut image, modules + 8, mod_core);
        // CodeRegistration tail: codeGenModulesCount, codeGenModules
        put(&mut image, base + 0x900, 2);
        put(&mut image, base + 0x908, modules);
        // Il2CppType entries {data, bits}
        let ty = |kind: u64| kind << 16;
        let types_at = base + 0xa00;
        let entries = [(0u64, ty(1)), (0, ty(0x0c)), (0, ty(0x08)), (1, ty(0x12)), (2, ty(0x12)), (0, ty(0x0e)), (types_at + 0x20, ty(0x1d))];
        let type_ptrs = base + 0xb00;
        for (i, (data, bits)) in entries.iter().enumerate() {
            put(&mut image, types_at + i as u64 * 16, *data);
            put(&mut image, types_at + i as u64 * 16 + 8, *bits);
            put(&mut image, type_ptrs + i as u64 * 8, types_at + i as u64 * 16);
        }
        // Il2CppMetadataRegistration (14 qwords)
        let reg = base + 0xc00;
        let sizes = base + 0xd00;
        for i in 0..3 {
            put(&mut image, sizes + i * 8, base + 0xe00);
        }
        put(&mut image, reg + 48, entries.len() as u64);
        put(&mut image, reg + 56, type_ptrs);
        put(&mut image, reg + 80, 3);
        put(&mut image, reg + 88, sizes);
        put(&mut image, reg + 96, 3);
        put(&mut image, reg + 104, sizes);
        image
    }

    #[test]
    fn parses_metadata_layouts() {
        let data = sample_metadata();
        let metadata = Metadata::parse(&data, None).unwrap();
        assert_eq!(metadata.version, 242);
        assert_eq!(metadata.type_count(), 3);
        assert_eq!(Layout::new(TYPE_DEFINITION, 240).size, 104);
        assert_eq!(Layout::new(TYPE_DEFINITION, 241).size, 100);
        assert_eq!(Layout::new(TYPE_DEFINITION, 242).size, 92);
        assert_eq!(Layout::new(TYPE_DEFINITION, 270).size, 88);
        assert_eq!(Layout::new(METHOD_DEFINITION, 240).size, 56);
        assert_eq!(Layout::new(METHOD_DEFINITION, 242).size, 32);
        let (value, text) = dump(&metadata, None, &DumpOptions { max_literals: 10 });
        assert_eq!(value["types"][2]["name"], "Player.Inner");
        assert_eq!(value["types"][2]["full_name"], "Game.Player.Inner");
        assert_eq!(value["methods"][1]["signature"], "public virtual type#0 Update(type#1 dt)");
        assert_eq!(value["string_literals"][1]["value"], "World");
        assert!(text.contains("public class Player // TypeDefIndex: 1"));
        assert!(Metadata::parse(&data[..0x80], None).is_err());
        let mut bad = data.clone();
        bad[4] = 23;
        assert!(Metadata::parse(&bad, None).unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn dumps_with_binary_artifact_through_registry() {
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), 1);
        let mut registry = crate::tools::ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let base = 0x80_0000u64;
        let store = registry.workbench.store.clone();
        let metadata = store.save("test", &sample_metadata(), json!({}), "dat").unwrap();
        let binary = store.save("test", &sample_binary(base), json!({}), "bin").unwrap();
        let result = registry
            .call(
                "il2cpp_dump",
                json!({"metadata_artifact": metadata["path"], "binary_artifact": binary["path"], "binary_base": format!("{base:#x}")}),
            )
            .unwrap();
        assert_eq!(result["stats"]["methods_with_rva"], 4, "{result:#}");
        let full: Value =
            serde_json::from_slice(&registry.workbench.read_artifact(result["json"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        let methods = full["methods"].as_array().unwrap();
        let update = methods.iter().find(|m| m["name"] == "Update").unwrap();
        assert_eq!(update["rva"], "0x110");
        assert_eq!(update["class"], "Player");
        assert_eq!(update["namespace"], "Game");
        assert_eq!(update["signature"], "public virtual void Update(float dt)");
        let run = methods.iter().find(|m| m["name"] == "Run").unwrap();
        assert_eq!(run["rva"], "0x130");
        assert_eq!(run["signature"], "private static string Run()");
        assert_eq!(methods.iter().find(|m| m["name"] == ".ctor").unwrap()["rva"], "0x100");
        assert_eq!(full["types"][1]["fields"][0]["type"], "int");
        let cs = registry.workbench.read_artifact(result["dump_cs"]["path"].as_str().unwrap(), 1 << 20).unwrap();
        assert!(String::from_utf8(cs).unwrap().contains("// RVA: 0x110"));
    }

    #[test]
    fn finds_metadata_in_live_memory() {
        let metadata = sample_metadata();
        let at = 0x2000_0000u64;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = crate::debugger::fake::spawn_fixture(
            listener,
            crate::debugger::fake::Fixture {
                pid: 91,
                base: 0x40_0000,
                image: vec![0xc3; 0x100],
                extra_maps: vec![(at - 0x1000, at + 0x1000, 1, "anon:metadata".into())],
                extra_memory: vec![(at, metadata)],
                ..Default::default()
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), fake.port);
        let mut registry = crate::tools::ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let result = registry.call("il2cpp_dump", json!({"pid": 91, "include_dump_cs": false})).unwrap();
        assert_eq!(result["metadata"]["address"], format!("{at:#x}"), "{result:#}");
        assert_eq!(result["stats"]["types"], 3);
        assert_eq!(result["dump_cs"], Value::Null);
    }
}
