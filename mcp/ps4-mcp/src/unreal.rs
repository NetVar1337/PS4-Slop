//! Unreal Engine name/object recovery (GNames / GObjects) and a best-effort
//! SDK-style class/property listing.
//!
//! Layouts (64-bit, shipping builds), from the Unreal Engine source:
//! * 4.23+/UE5 `FNamePool` (`Core/Private/UObject/UnrealNames.cpp`):
//!   `FNameEntryAllocator { FRWLock Lock; uint32 CurrentBlock; uint32
//!   CurrentByteCursor; uint8* Blocks[8192]; }`; entries are 2-byte aligned
//!   (`Stride = alignof(FNameEntry) = 2`), `FNameBlockOffsetBits = 16`, so an
//!   `FNameEntryId` is `(block << 16) | (offset / 2)`. `FNameEntryHeader` is
//!   `uint16 bIsWide:1, LowercaseProbeHash:5, Len:10` (no case-preserving names).
//!   The tool's `gnames` for this kind is the address of `Blocks[0]` (the lock
//!   size is platform-specific, so the pool start is not needed).
//! * <4.23 `TNameEntryArray = TStaticIndirectArrayThreadSafeRead<FNameEntry,
//!   2*1024*1024, 16384>` (`UObject/NameTypes.h`, 4.22): `FNameEntry** Chunks[128];
//!   int32 NumElements; int32 NumChunks;` and `FNameEntry { NAME_INDEX Index;
//!   FNameEntry* HashNext; union { ANSICHAR/WIDECHAR Name[1024]; } }` — name at
//!   +0x10 (auto-detected among common offsets; override `name_entry_string`),
//!   `Index & 1` = wide.
//! * `FUObjectArray` (`UObject/UObjectArray.h`, 4.20+): `int32 ObjFirstGCIndex,
//!   ObjLastNonGCIndex, MaxObjectsNotConsideredByGC; bool OpenForDisregardForGC;`
//!   then `FChunkedFixedUObjectArray ObjObjects` at +0x10: `FUObjectItem**
//!   Objects; FUObjectItem* PreAllocatedObjects; int32 MaxElements, NumElements,
//!   MaxChunks, NumChunks;` with 65536 items per chunk; `FUObjectItem { UObject*
//!   Object; int32 Flags, ClusterRootIndex, SerialNumber; }` = 24 bytes. Older
//!   `FFixedUObjectArray { FUObjectItem* Objects; int32 MaxElements, NumElements; }`.
//! * `UObjectBase` (`UObject/UObjectBase.h`): vtable, `EObjectFlags` (+0x08),
//!   `InternalIndex` (+0x0C), `ClassPrivate` (+0x10), `NamePrivate` (+0x18),
//!   `OuterPrivate` (+0x20).
//! * SDK (best-effort, override via `offsets`): `UStruct` SuperStruct/Children/
//!   ChildProperties/PropertiesSize at 0x40/0x48/0x50/0x58 (4.25+), 0x40/0x48/-/0x50
//!   (4.22–4.24), 0x30/0x38/-/0x40 (<4.22); `FField` ClassPrivate 0x08, Next 0x20,
//!   NamePrivate 0x28; `FProperty` ElementSize 0x3C, Offset_Internal 0x4C (4.25+);
//!   `UProperty` (UField::Next 0x28) ElementSize 0x34, Offset_Internal 0x44 (<4.25).
use crate::{
    Result,
    bytesource::{Mode, PROT_W, Source, TargetSpec, hex},
    workbench::Workbench,
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;

const POOL_BLOCK_BYTES: u64 = 0x20000;
const ARRAY_CHUNK: u64 = 16384;
const OBJECT_CHUNK: u64 = 65536;
const MAX_CANDIDATES: usize = 200_000;
const NAME_STRING_OFFSETS: [u64; 5] = [0x10, 0x0c, 0x08, 0x14, 0x18];

#[derive(Clone, Debug)]
struct Offsets {
    object_class: u64,
    object_name: u64,
    object_outer: u64,
    objobjects: u64,
    item_size: u64,
    name_entry_string: Option<u64>,
    struct_super: u64,
    struct_children: u64,
    struct_child_properties: Option<u64>,
    struct_size: u64,
    field_next: u64,
    field_name: u64,
    field_class: u64,
    property_element_size: u64,
    property_offset: u64,
}

fn parse_version(text: Option<&str>) -> Option<(u32, u32)> {
    let mut parts = text?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|m| m.parse().ok()).unwrap_or(if major >= 5 { 0 } else { 27 });
    Some((major, minor))
}

impl Offsets {
    fn for_version(version: Option<(u32, u32)>, overrides: &Value) -> Self {
        let v = version.unwrap_or((4, 25));
        let fproperty = v >= (4, 25);
        let chain = v >= (4, 22);
        let mut out = Self {
            object_class: 0x10,
            object_name: 0x18,
            object_outer: 0x20,
            objobjects: 0x10,
            item_size: 24,
            name_entry_string: None,
            struct_super: if chain { 0x40 } else { 0x30 },
            struct_children: if chain { 0x48 } else { 0x38 },
            struct_child_properties: fproperty.then_some(0x50),
            struct_size: if fproperty { 0x58 } else if chain { 0x50 } else { 0x40 },
            field_next: if fproperty { 0x20 } else { 0x28 },
            field_name: if fproperty { 0x28 } else { 0x18 },
            field_class: if fproperty { 0x08 } else { 0x10 },
            property_element_size: if fproperty { 0x3c } else { 0x34 },
            property_offset: if fproperty { 0x4c } else { 0x44 },
        };
        let get = |key: &str| overrides.get(key).and_then(Value::as_u64);
        macro_rules! apply {
            ($($field:ident),*) => { $( if let Some(v) = get(stringify!($field)) { out.$field = v; } )* };
        }
        apply!(object_class, object_name, object_outer, objobjects, item_size, struct_super, struct_children,
            struct_size, field_next, field_name, field_class, property_element_size, property_offset);
        if let Some(v) = get("name_entry_string") {
            out.name_entry_string = Some(v);
        }
        if let Some(v) = get("struct_child_properties") {
            out.struct_child_properties = Some(v);
        }
        out
    }

    fn json(&self) -> Value {
        json!({
            "object_class": self.object_class, "object_name": self.object_name, "object_outer": self.object_outer,
            "objobjects": self.objobjects, "item_size": self.item_size, "name_entry_string": self.name_entry_string,
            "struct_super": self.struct_super, "struct_children": self.struct_children,
            "struct_child_properties": self.struct_child_properties, "struct_size": self.struct_size,
            "field_next": self.field_next, "field_name": self.field_name, "field_class": self.field_class,
            "property_element_size": self.property_element_size, "property_offset": self.property_offset,
        })
    }
}

#[derive(Clone, Debug)]
enum Names {
    Pool { blocks: u64, current_block: u32, cursor: u32 },
    Array { array: u64, string_offset: u64, count: u32 },
}

struct Ctx<'s, 'a> {
    source: &'s mut Source<'a>,
    names: Names,
    cache: HashMap<u32, Option<String>>,
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units)
}

/// Read a pool entry at `entry`: (string, entry byte size).
fn pool_entry(source: &mut Source, entry: u64) -> Option<(String, u64)> {
    let header = source.u16(entry)?;
    let (wide, len) = (header & 1 != 0, (header >> 6) as u64);
    if len == 0 {
        return None;
    }
    let bytes = source.read(entry + 2, (len * if wide { 2 } else { 1 }) as usize)?;
    let text = if wide { utf16(&bytes) } else { String::from_utf8_lossy(&bytes).into_owned() };
    let size = 2 + bytes.len() as u64;
    Some((text, size + (size & 1)))
}

fn probe_pool_entry(source: &mut Source, entry: u64, expect: &str) -> bool {
    let Some(bytes) = source.probe(entry, 2 + expect.len()) else { return false };
    let header = u16::from_le_bytes([bytes[0], bytes[1]]);
    header & 1 == 0 && (header >> 6) as usize == expect.len() && &bytes[2..] == expect.as_bytes()
}

fn array_entry(source: &mut Source, entry: u64, string_offset: u64) -> Option<String> {
    let index = source.u32(entry)?;
    if index & 1 != 0 {
        let mut units = Vec::new();
        let mut cursor = entry + string_offset;
        while units.len() < 1024 {
            let unit = source.u16(cursor)?;
            if unit == 0 {
                break;
            }
            units.push(unit);
            cursor += 2;
        }
        Some(String::from_utf16_lossy(&units))
    } else {
        source.cstr(entry + string_offset, 1024).map(|b| String::from_utf8_lossy(&b).into_owned())
    }
}

impl Ctx<'_, '_> {
    fn name(&mut self, id: u32) -> Option<String> {
        if let Some(hit) = self.cache.get(&id) {
            return hit.clone();
        }
        let value = match self.names.clone() {
            Names::Pool { blocks, .. } => {
                let block = (id >> 16) as u64;
                let offset = (id & 0xffff) as u64 * 2;
                self.source.u64(blocks + block * 8).filter(|p| *p != 0).and_then(|base| pool_entry(self.source, base + offset).map(|e| e.0))
            }
            Names::Array { array, string_offset, count } => {
                if id >= count {
                    None
                } else {
                    let chunk = self.source.u64(array + (id as u64 / ARRAY_CHUNK) * 8).filter(|p| *p != 0);
                    chunk
                        .and_then(|c| self.source.u64(c + (id as u64 % ARRAY_CHUNK) * 8))
                        .filter(|p| *p != 0)
                        .and_then(|entry| array_entry(self.source, entry, string_offset))
                }
            }
        };
        self.cache.insert(id, value.clone());
        value
    }

    /// FName at `va`: `{ ComparisonIndex, Number }`.
    fn fname(&mut self, va: u64) -> Option<String> {
        let index = self.source.u32(va)?;
        let number = self.source.u32(va + 4)?;
        let base = self.name(index)?;
        Some(if number > 0 { format!("{base}_{}", number - 1) } else { base })
    }

    fn enumerate(&mut self, max: usize) -> (Vec<Value>, bool) {
        let mut out = Vec::new();
        match self.names.clone() {
            Names::Pool { blocks, current_block, cursor } => {
                for block in 0..=current_block.min(8191) as u64 {
                    let Some(base) = self.source.u64(blocks + block * 8).filter(|p| *p != 0) else { break };
                    let limit = if block == current_block as u64 && cursor > 0 { cursor as u64 } else { POOL_BLOCK_BYTES };
                    let mut offset = 0;
                    while offset + 2 <= limit {
                        let Some((text, size)) = pool_entry(self.source, base + offset) else { break };
                        let id = ((block << 16) | (offset / 2)) as u32;
                        self.cache.insert(id, Some(text.clone()));
                        out.push(json!({"id": id, "name": text}));
                        if out.len() >= max {
                            return (out, true);
                        }
                        offset += size;
                    }
                }
            }
            Names::Array { count, .. } => {
                for id in 0..count {
                    if let Some(text) = self.name(id) {
                        out.push(json!({"id": id, "name": text}));
                        if out.len() >= max {
                            return (out, true);
                        }
                    }
                }
            }
        }
        (out, false)
    }
}

fn search_ranges(source: &Source) -> Vec<(u64, u64)> {
    let ranges = source.ranges_with(PROT_W, 0);
    if ranges.is_empty() { source.selection.clone() } else { ranges }
}

/// Candidate slots: `(slot, value, prev_qword, inline_words)` gathered in one pass
/// with cheap in-chunk filters; `inline_words` holds the next 0x408 bytes when available.
struct Slots {
    pool: Vec<(u64, u64, u64)>,
    array_ptr: Vec<(u64, u64)>,
    array_inline: Vec<u64>,
    objects: Vec<(u64, u64, bool)>,
    truncated: bool,
}

fn gather(source: &mut Source, ranges: &[(u64, u64)], want_array: bool) -> Result<Slots> {
    let mut slots = Slots { pool: Vec::new(), array_ptr: Vec::new(), array_inline: Vec::new(), objects: Vec::new(), truncated: false };
    let regions: Vec<(u64, u64)> = source.regions.iter().map(|r| (r.start, r.end)).collect();
    let mapped = |value: u64| regions.iter().any(|(s, e)| *s <= value && value < *e);
    source.scan(Some(ranges), 0x410, |va, chunk| {
        let qword = |at: usize| chunk.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        let dword = |at: usize| chunk.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
        let mut offset = ((8 - (va % 8)) % 8) as usize;
        while offset + 8 <= chunk.len() {
            let value = qword(offset).unwrap();
            let slot = va + offset as u64;
            if value != 0 && value.is_multiple_of(2) && mapped(value) {
                // FNamePool Blocks[0]: preceded by {CurrentBlock, CurrentByteCursor}.
                if let Some(prev) = offset.checked_sub(8).and_then(qword) {
                    let (block, cursor) = (prev as u32, (prev >> 32) as u32);
                    if block < 8192 && cursor as u64 <= POOL_BLOCK_BYTES {
                        slots.pool.push((slot, value, prev));
                    }
                }
                if want_array && value.is_multiple_of(8) {
                    slots.array_ptr.push((slot, value));
                }
                // Chunked ObjObjects {Objects, PreAllocated, Max, Num, MaxChunks, NumChunks}.
                if value.is_multiple_of(8)
                    && let (Some(max), Some(num), Some(max_chunks), Some(num_chunks)) =
                        (dword(offset + 16), dword(offset + 20), dword(offset + 24), dword(offset + 28))
                    && num > 0
                    && num <= max
                    && max <= 0x0400_0000
                    && num_chunks as u64 == (num as u64).div_ceil(OBJECT_CHUNK)
                    && max_chunks >= num_chunks
                {
                    slots.objects.push((slot, value, true));
                }
                // Fixed ObjObjects {Objects, Max, Num}.
                if value.is_multiple_of(8)
                    && let (Some(max), Some(num)) = (dword(offset + 8), dword(offset + 12))
                    && num > 1
                    && num <= max
                    && max <= 0x0400_0000
                {
                    slots.objects.push((slot, value, false));
                }
            }
            // Inline TNameEntryArray: NumElements/NumChunks at +0x400.
            if want_array
                && value != 0
                && let (Some(num), Some(chunks)) = (dword(offset + 0x400), dword(offset + 0x404))
                && num > 1
                && num <= 0x20_0000
                && chunks as u64 == (num as u64).div_ceil(ARRAY_CHUNK)
            {
                slots.array_inline.push(slot);
            }
            let total = slots.pool.len() + slots.array_ptr.len() + slots.array_inline.len() + slots.objects.len();
            if total >= MAX_CANDIDATES {
                slots.truncated = true;
                return false;
            }
            offset += 8;
        }
        true
    })?;
    Ok(slots)
}

fn find_pool(source: &mut Source, slots: &Slots) -> Option<Names> {
    for &(slot, value, prev) in &slots.pool {
        if probe_pool_entry(source, value, "None") && probe_pool_entry(source, value + 6, "ByteProperty") {
            return Some(Names::Pool { blocks: slot, current_block: prev as u32, cursor: (prev >> 32) as u32 });
        }
    }
    None
}

fn array_at(source: &mut Source, array: u64, forced_offset: Option<u64>) -> Option<Names> {
    let chunk0 = source.probe_u64(array).filter(|p| *p != 0)?;
    let e0 = source.probe_u64(chunk0).filter(|p| *p != 0)?;
    let e1 = source.probe_u64(chunk0 + 8).filter(|p| *p != 0)?;
    let offsets: Vec<u64> = forced_offset.map_or(NAME_STRING_OFFSETS.to_vec(), |o| vec![o]);
    for off in offsets {
        if source.probe(e0 + off, 5).as_deref() == Some(b"None\0")
            && source.probe(e1 + off, 13).as_deref() == Some(b"ByteProperty\0")
        {
            let count = source.probe(array + 0x400, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
            let count = if (2..=0x20_0000).contains(&count) { count } else { 0x20_0000 };
            return Some(Names::Array { array, string_offset: off, count });
        }
    }
    None
}

fn find_array(source: &mut Source, slots: &Slots, forced_offset: Option<u64>) -> Option<(Names, u64)> {
    for &slot in &slots.array_inline {
        if let Some(names) = array_at(source, slot, forced_offset) {
            return Some((names, slot));
        }
    }
    for &(slot, value) in &slots.array_ptr {
        // GNames global is a pointer to the heap TNameEntryArray: cheap count check first.
        let Some(counts) = source.probe(value + 0x400, 8) else { continue };
        let num = u32::from_le_bytes(counts[..4].try_into().unwrap()) as u64;
        let chunks = u32::from_le_bytes(counts[4..].try_into().unwrap()) as u64;
        if !(2..=0x20_0000).contains(&num) || chunks != num.div_ceil(ARRAY_CHUNK) {
            continue;
        }
        if let Some(names) = array_at(source, value, forced_offset) {
            return Some((names, slot));
        }
    }
    None
}

#[derive(Clone, Debug)]
struct ObjectArray {
    address: u64,
    objects: u64,
    num: u32,
    max: u32,
    chunked: bool,
}

fn object_array_at(source: &mut Source, slot: u64, chunked: bool, offsets: &Offsets) -> Option<ObjectArray> {
    let objects = source.probe_u64(slot)?;
    let header = source.probe(slot + 8, 24)?;
    let word = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    let (max, num) = if chunked { (word(8), word(12)) } else { (word(0), word(4)) };
    if num == 0 || num > max {
        return None;
    }
    let items = if chunked { source.probe_u64(objects).filter(|p| *p != 0)? } else { objects };
    for index in 0..num.min(2) as u64 {
        let object = source.probe_u64(items + index * offsets.item_size).filter(|p| *p != 0)?;
        let internal = source.probe(object + 0x0c, 4)?;
        if u32::from_le_bytes(internal.try_into().unwrap()) as u64 != index {
            return None;
        }
    }
    Some(ObjectArray { address: slot.wrapping_sub(offsets.objobjects), objects, num, max, chunked })
}

fn object_at(source: &mut Source, array: &ObjectArray, index: u64, offsets: &Offsets) -> Option<u64> {
    let item = if array.chunked {
        source.u64(array.objects + (index / OBJECT_CHUNK) * 8).filter(|p| *p != 0)? + (index % OBJECT_CHUNK) * offsets.item_size
    } else {
        array.objects + index * offsets.item_size
    };
    source.u64(item).filter(|p| *p != 0)
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let spec = TargetSpec::from_args(args, "artifact", "module")?;
    ensure!(spec.is_specified(), "Give a raw memory-dump artifact (with base) or a pid");
    let version = parse_version(args["version"].as_str());
    let offsets = Offsets::for_version(version, &args["offsets"]);
    let max_names = args["max_names"].as_u64().unwrap_or(100_000) as usize;
    let max_objects = args["max_objects"].as_u64().unwrap_or(50_000) as usize;
    let want_sdk = args["sdk"].as_bool().unwrap_or(true);
    let kind = args["gnames_kind"].as_str().unwrap_or("auto");
    let override_addr = |key: &str| args.get(key).filter(|v| !v.is_null()).map(crate::tools::address).transpose();
    let (gnames_override, gobjects_override) = (override_addr("gnames")?, override_addr("gobjects")?);
    let mut source = Source::open(workbench, &spec, Mode::Mapped)?;
    let mut heuristics: Vec<String> = Vec::new();
    let ranges = search_ranges(&source);
    let want_array = kind != "name_pool" && version.is_none_or(|v| v < (4, 23));
    let slots = if gnames_override.is_none() || gobjects_override.is_none() {
        let slots = gather(&mut source, &ranges, want_array)?;
        heuristics.push(format!(
            "Scanned {} writable ranges: {} pool / {} array / {} object-array candidate slots{}",
            ranges.len(),
            slots.pool.len(),
            slots.array_ptr.len() + slots.array_inline.len(),
            slots.objects.len(),
            if slots.truncated { " (candidate cap reached)" } else { "" }
        ));
        slots
    } else {
        Slots { pool: Vec::new(), array_ptr: Vec::new(), array_inline: Vec::new(), objects: Vec::new(), truncated: false }
    };

    // GNames.
    let (names, gnames_json) = match gnames_override {
        Some(address) => {
            let names = match kind {
                "name_array" => array_at(&mut source, address, offsets.name_entry_string),
                "name_pool" => source.u64(address - 8).map(|prev| Names::Pool { blocks: address, current_block: (prev as u32).min(8191), cursor: (prev >> 32) as u32 }),
                _ => {
                    let pool = source.u64(address).filter(|p| probe_pool_entry(&mut source, *p, "None"));
                    match pool {
                        Some(_) => source.u64(address - 8).map(|prev| Names::Pool { blocks: address, current_block: (prev as u32).min(8191), cursor: (prev >> 32) as u32 }),
                        None => array_at(&mut source, address, offsets.name_entry_string),
                    }
                }
            }
            .with_context(|| format!("No GNames structure recognised at {address:#x} (kind {kind})"))?;
            heuristics.push("GNames from explicit override".into());
            (names, json!({"address": hex(address), "evidence": "override"}))
        }
        None => {
            let pool = if kind == "name_array" { None } else { find_pool(&mut source, &slots) };
            match pool {
                Some(names) => {
                    let Names::Pool { blocks, .. } = names else { unreachable!() };
                    heuristics.push("FNamePool: Blocks[0] entry 0 is \"None\", entry 1 \"ByteProperty\"".into());
                    (names, json!({"address": hex(blocks), "evidence": "first-entries"}))
                }
                None => match want_array.then(|| find_array(&mut source, &slots, offsets.name_entry_string)).flatten() {
                    Some((names, slot)) => {
                        heuristics.push("TNameEntryArray: chunk 0 entries 0/1 are \"None\"/\"ByteProperty\"".into());
                        (names, json!({"address": hex(slot), "evidence": "first-entries"}))
                    }
                    None => bail!(
                        "GNames not found (bytes fetched {}, budget exhausted: {}). Pass gnames/gnames_kind or a version hint.",
                        source.fetched,
                        source.exhausted
                    ),
                },
            }
        }
    };
    let mut gnames_json = gnames_json;
    match &names {
        Names::Pool { blocks, current_block, cursor } => {
            gnames_json["kind"] = json!("FNamePool");
            gnames_json["blocks"] = json!(hex(*blocks));
            gnames_json["current_block"] = json!(current_block);
            gnames_json["current_byte_cursor"] = json!(cursor);
        }
        Names::Array { array, string_offset, count } => {
            gnames_json["kind"] = json!("TNameEntryArray");
            gnames_json["array"] = json!(hex(*array));
            gnames_json["name_string_offset"] = json!(string_offset);
            gnames_json["num_elements"] = json!(count);
        }
    }
    let mut ctx = Ctx { source: &mut source, names, cache: HashMap::new() };
    let (name_list, names_truncated) = ctx.enumerate(max_names);

    // GObjects.
    let array = match gobjects_override {
        Some(address) => {
            let slot = address + offsets.objobjects;
            let found = object_array_at(ctx.source, slot, true, &offsets).or_else(|| object_array_at(ctx.source, slot, false, &offsets));
            heuristics.push("GObjects from explicit override".into());
            Some(found.with_context(|| format!("No FUObjectArray recognised at {address:#x}"))?)
        }
        None => {
            let mut found = None;
            for &(slot, _, chunked) in &slots.objects {
                if version.is_some_and(|v| v < (4, 20)) && chunked {
                    continue;
                }
                if let Some(array) = object_array_at(ctx.source, slot, chunked, &offsets) {
                    found = Some(array);
                    break;
                }
            }
            if found.is_some() {
                heuristics.push("FUObjectArray: objects 0 and 1 have InternalIndex 0 and 1".into());
            } else {
                heuristics.push("GObjects not found; pass gobjects".into());
            }
            found
        }
    };
    let mut objects = Vec::new();
    let mut sdk = Vec::new();
    let mut sdk_text = String::new();
    let mut objects_truncated = false;
    if let Some(array) = &array {
        let mut path_cache: HashMap<u64, String> = HashMap::new();
        for index in 0..array.num as u64 {
            if objects.len() >= max_objects {
                objects_truncated = true;
                break;
            }
            let Some(object) = object_at(ctx.source, array, index, &offsets) else {
                if ctx.source.exhausted {
                    break;
                }
                continue;
            };
            let name = ctx.fname(object + offsets.object_name);
            let class = ctx.source.u64(object + offsets.object_class).filter(|c| *c != 0);
            let class_name = class.and_then(|c| ctx.fname(c + offsets.object_name));
            let outer = ctx.source.u64(object + offsets.object_outer).filter(|o| *o != 0);
            let mut path = name.clone().unwrap_or_default();
            let mut cursor = outer;
            for _ in 0..8 {
                let Some(o) = cursor else { break };
                let outer_name = match path_cache.get(&o) {
                    Some(n) => n.clone(),
                    None => {
                        let n = ctx.fname(o + offsets.object_name).unwrap_or_else(|| hex(o));
                        path_cache.insert(o, n.clone());
                        n
                    }
                };
                path = format!("{outer_name}.{path}");
                cursor = ctx.source.u64(o + offsets.object_outer).filter(|p| *p != 0);
            }
            if want_sdk && matches!(class_name.as_deref(), Some("Class" | "ScriptStruct" | "BlueprintGeneratedClass")) {
                let entry = sdk_entry(&mut ctx, object, &offsets, name.clone().unwrap_or_default(), &path, class_name.as_deref().unwrap_or(""));
                sdk_text += &entry.1;
                sdk.push(entry.0);
            }
            objects.push(json!({
                "index": index, "address": hex(object), "name": name, "class": class_name,
                "outer": outer.map(hex), "path": path,
            }));
        }
    }
    let summary = ctx.source.summary();
    let image_base = hex(ctx.source.image_base);
    drop(ctx);
    drop(source);
    let gobjects_json = array.as_ref().map(|a| {
        json!({"address": hex(a.address), "objects": hex(a.objects), "num_elements": a.num, "max_elements": a.max,
            "layout": if a.chunked { "FChunkedFixedUObjectArray" } else { "FFixedUObjectArray" }})
    });
    let result = json!({
        "format": "ps4wb-unreal-v1",
        "image_base": image_base,
        "version_hint": args["version"],
        "gnames": gnames_json,
        "gobjects": gobjects_json,
        "names": name_list,
        "names_truncated": names_truncated,
        "objects": objects,
        "objects_truncated": objects_truncated,
        "sdk": sdk,
        "offsets": offsets.json(),
        "heuristics": heuristics,
        "notes": ["SDK layout is best-effort: UStruct/FProperty offsets vary by engine version and game; verify and override via `offsets`."],
    });
    let saved = crate::engines::save_json(workbench, "unreal", &result, json!({"tool": "unreal_dump"}))?;
    let sdk_saved = if want_sdk && !sdk_text.is_empty() {
        Some(crate::engines::artifact_ref(&crate::engines::save_text(workbench, "unreal-sdk", &sdk_text, "txt", json!({"tool": "unreal_dump"}))?))
    } else {
        None
    };
    Ok(json!({
        "format": "ps4wb-unreal-v1",
        "json": crate::engines::artifact_ref(&saved),
        "sdk_text": sdk_saved,
        "gnames": result["gnames"],
        "gobjects": result["gobjects"],
        "counts": {"names": result["names"].as_array().map_or(0, Vec::len), "objects": result["objects"].as_array().map_or(0, Vec::len), "sdk_classes": result["sdk"].as_array().map_or(0, Vec::len)},
        "heuristics": result["heuristics"],
        "source": summary,
    }))
}

fn sdk_entry(ctx: &mut Ctx, object: u64, offsets: &Offsets, name: String, path: &str, kind: &str) -> (Value, String) {
    let super_struct = ctx.source.u64(object + offsets.struct_super).filter(|p| *p != 0);
    let super_name = super_struct.and_then(|s| ctx.fname(s + offsets.object_name));
    let size = ctx.source.u32(object + offsets.struct_size).map(|v| v as i32);
    let mut properties = Vec::new();
    let mut field = match offsets.struct_child_properties {
        Some(at) => ctx.source.u64(object + at),
        None => ctx.source.u64(object + offsets.struct_children),
    }
    .filter(|p| *p != 0);
    while let Some(f) = field {
        if properties.len() >= 512 {
            break;
        }
        let class = ctx.source.u64(f + offsets.field_class).filter(|p| *p != 0);
        // FFieldClass starts with its FName; UClass carries it at object_name.
        let class_name_at = if offsets.struct_child_properties.is_some() { 0 } else { offsets.object_name };
        let type_name = class.and_then(|c| ctx.fname(c + class_name_at));
        let field_name = ctx.fname(f + offsets.field_name);
        let is_property = type_name.as_deref().is_some_and(|t| t.ends_with("Property"));
        if is_property {
            let element = ctx.source.u32(f + offsets.property_element_size).map(|v| v as i32);
            let offset = ctx.source.u32(f + offsets.property_offset).map(|v| v as i32);
            properties.push(json!({"name": field_name, "type": type_name, "offset": offset, "size": element}));
        }
        field = ctx.source.u64(f + offsets.field_next).filter(|p| *p != 0);
    }
    let mut text = format!(
        "// {kind} {path}\n// Size: {}\n{} {name}{} {{\n",
        size.map_or("?".into(), |s| format!("{s:#x}")),
        if kind == "ScriptStruct" { "struct" } else { "class" },
        super_name.as_ref().map_or(String::new(), |s| format!(" : public {s}"))
    );
    for p in &properties {
        text += &format!(
            "\t{} {}; // {:#x} ({:#x})\n",
            p["type"].as_str().unwrap_or("?"),
            p["name"].as_str().unwrap_or("?"),
            p["offset"].as_i64().unwrap_or(0),
            p["size"].as_i64().unwrap_or(0)
        );
    }
    text += "};\n\n";
    (json!({"name": name, "path": path, "kind": kind, "super": super_name, "size": size, "properties": properties}), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dump {
        base: u64,
        bytes: Vec<u8>,
    }
    impl Dump {
        fn q(&mut self, at: u64, value: u64) {
            let at = (at - self.base) as usize;
            self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        fn d(&mut self, at: u64, value: u32) {
            let at = (at - self.base) as usize;
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn raw(&mut self, at: u64, data: &[u8]) {
            let at = (at - self.base) as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
        }
    }

    /// FNamePool + chunked FUObjectArray + FField-based class layout (4.25+).
    fn pool_dump(base: u64) -> Vec<u8> {
        let mut dump = Dump { base, bytes: vec![0u8; 0x4000] };
        let block = base + 0x1000;
        let mut ids = HashMap::new();
        let mut offset = 0u64;
        for name in ["None", "ByteProperty", "IntProperty", "Class", "Object", "/Script/CoreUObject", "MyActor", "Health", "Package"] {
            let header = (name.len() as u16) << 6;
            dump.raw(block + offset, &header.to_le_bytes());
            dump.raw(block + offset + 2, name.as_bytes());
            ids.insert(name, (offset / 2) as u32);
            let size = 2 + name.len() as u64;
            offset += size + (size & 1);
        }
        dump.q(base + 0xf8, offset << 32); // CurrentBlock 0, cursor
        dump.q(base + 0x100, block);
        // FUObjectArray at base+0x200, ObjObjects at +0x10.
        let (chunks, items) = (base + 0x300, base + 0x400);
        dump.q(base + 0x210, chunks);
        dump.d(base + 0x220, 100);
        dump.d(base + 0x224, 4);
        dump.d(base + 0x228, 1);
        dump.d(base + 0x22c, 1);
        dump.q(chunks, items);
        let objects = [base + 0x2000, base + 0x2100, base + 0x2200, base + 0x2300];
        let named = ["/Script/CoreUObject", "Class", "Object", "MyActor"];
        for (i, (object, name)) in objects.iter().zip(named).enumerate() {
            dump.q(items + i as u64 * 24, *object);
            dump.d(object + 0x0c, i as u32);
            dump.d(object + 0x18, ids[name]);
            if i > 0 {
                dump.q(object + 0x10, objects[1]);
                dump.q(object + 0x20, objects[0]);
            } else {
                dump.q(object + 0x10, objects[1]);
            }
        }
        // MyActor : Object, one IntProperty Health at 0x30.
        let my_actor = objects[3];
        dump.q(my_actor + 0x40, objects[2]);
        dump.q(my_actor + 0x50, base + 0x3100);
        dump.d(my_actor + 0x58, 0x34);
        dump.d(base + 0x3000, ids["IntProperty"]);
        dump.q(base + 0x3100 + 0x08, base + 0x3000);
        dump.d(base + 0x3100 + 0x28, ids["Health"]);
        dump.d(base + 0x3100 + 0x3c, 4);
        dump.d(base + 0x3100 + 0x4c, 0x30);
        dump.bytes
    }

    #[test]
    fn name_pool_objects_and_sdk_from_dump_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), 1);
        let mut registry = crate::tools::ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let base = 0x1_0000_0000u64;
        let saved = registry.workbench.store.save("test", &pool_dump(base), json!({}), "bin").unwrap();
        let result = registry
            .call("unreal_dump", json!({"artifact": saved["path"], "base": format!("{base:#x}")}))
            .unwrap();
        assert_eq!(result["gnames"]["kind"], "FNamePool", "{result:#}");
        assert_eq!(result["gnames"]["blocks"], format!("{:#x}", base + 0x100));
        assert_eq!(result["gobjects"]["address"], format!("{:#x}", base + 0x200));
        assert_eq!(result["counts"]["names"], 9);
        let full: Value =
            serde_json::from_slice(&registry.workbench.read_artifact(result["json"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert_eq!(full["names"][1]["name"], "ByteProperty");
        let my_actor = &full["objects"][3];
        assert_eq!(my_actor["class"], "Class");
        assert_eq!(my_actor["path"], "/Script/CoreUObject.MyActor");
        let sdk = full["sdk"].as_array().unwrap().iter().find(|s| s["name"] == "MyActor").unwrap().clone();
        assert_eq!(sdk["super"], "Object");
        assert_eq!(sdk["size"], 0x34);
        assert_eq!(sdk["properties"][0], json!({"name": "Health", "type": "IntProperty", "offset": 0x30, "size": 4}));
        let text = registry.workbench.read_artifact(result["sdk_text"]["path"].as_str().unwrap(), 1 << 20).unwrap();
        assert!(String::from_utf8(text).unwrap().contains("class MyActor : public Object {\n\tIntProperty Health; // 0x30 (0x4)"));
        let exported = registry.call("engine_sdk_export", json!({"unreal":result["json"]["path"]})).unwrap();
        let hpp = registry.workbench.read_artifact(exported["artifact"]["path"].as_str().unwrap(), 1 << 20).unwrap();
        std::fs::write(directory.path().join("engine.hpp"), hpp).unwrap();
        let bytes = pool_dump(base);
        std::fs::write(directory.path().join("image.bin"), bytes).unwrap();
        let image_path = serde_json::to_string(&directory.path().join("image.bin").to_string_lossy()).unwrap();
        let source = format!(r#"
#include "engine.hpp"
#include <cassert>
#include <fstream>
#include <vector>
#include <cstring>
int main() {{
    std::ifstream file({image_path}, std::ios::binary);
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), {{}});
    const auto base = reinterpret_cast<std::uintptr_t>(bytes.data());
    for (std::size_t i=0;i+8<=bytes.size();i+=8) {{
        std::uint64_t value=0; std::memcpy(&value,bytes.data()+i,8);
        if (value >= 0x100000000ULL && value < 0x100000000ULL + bytes.size()) {{ value = base + value - 0x100000000ULL; std::memcpy(bytes.data()+i,&value,8); }}
    }}
    internals::ReadableRange range{{base,base+bytes.size()}};
    internals::MappedMemory memory{{&range,1}};
    ue4::Store store(base,game::kUe4Offsets,memory.Reader());
    assert(store.available());
    std::size_t named=0;
    const auto count=store.for_each([&](std::size_t, std::uintptr_t object) {{ std::uint32_t index=0; char text[128]; assert(store.name_index_of(object,index)); assert(store.name_of(index,text,sizeof(text))>0); ++named; }});
    assert(count == 4 && named == count);
    char text[8]; assert(store.name_of(0,text,sizeof(text))==4); assert(std::strcmp(text,"None")==0);
    assert(store.name_of(0xffffffff,text,sizeof(text))==0);
}}
"#);
        crate::test_support::compile_run(directory.path(), &source, false);
    }

    #[test]
    fn name_array_layout_and_live_source() {
        let base = 0x5000_0000u64;
        let mut dump = Dump { base, bytes: vec![0u8; 0x3000] };
        // GNames global at base+0x80 -> heap TNameEntryArray at base+0x1000.
        let array = base + 0x1000;
        dump.q(base + 0x80, array);
        let chunk = base + 0x1800;
        dump.q(array, chunk);
        dump.d(array + 0x400, 3);
        dump.d(array + 0x404, 1);
        for (i, name) in ["None", "ByteProperty", "Wide"].iter().enumerate() {
            let entry = base + 0x2000 + i as u64 * 0x40;
            dump.q(chunk + i as u64 * 8, entry);
            if i == 2 {
                dump.d(entry, (2 << 1) | 1);
                let wide: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                dump.raw(entry + 0x10, &wide);
            } else {
                dump.d(entry, (i as u32) << 1);
                dump.raw(entry + 0x10, name.as_bytes());
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = crate::debugger::fake::spawn_fixture(
            listener,
            crate::debugger::fake::Fixture {
                pid: 92,
                base: 0x40_0000,
                image: vec![0xc3; 0x100],
                extra_maps: vec![(base, base + 0x3000, 3, "game.prx".into())],
                extra_memory: vec![(base, dump.bytes)],
                ..Default::default()
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::debugger::fake::qualified_profile(directory.path(), fake.port);
        let mut registry = crate::tools::ToolRegistry::new(Workbench::new(profile).unwrap()).unwrap();
        let result = registry.call("unreal_dump", json!({"pid": 92, "module": "game.prx", "version": "4.22"})).unwrap();
        assert_eq!(result["gnames"]["kind"], "TNameEntryArray", "{result:#}");
        assert_eq!(result["gnames"]["array"], format!("{:#x}", base + 0x1000));
        assert_eq!(result["gnames"]["name_string_offset"], 0x10);
        assert_eq!(result["counts"]["names"], 3);
        assert!(result["gobjects"].is_null());
        let full: Value =
            serde_json::from_slice(&registry.workbench.read_artifact(result["json"]["path"].as_str().unwrap(), 1 << 20).unwrap()).unwrap();
        assert_eq!(full["names"][2]["name"], "Wide");
        assert_eq!(full["offsets"]["property_offset"], 0x44);
    }

    #[test]
    fn sparse_module_and_heap_replay_is_hash_checked() {
        let dir=tempfile::tempdir().unwrap();
        let mut registry=crate::tools::ToolRegistry::new(Workbench::new(crate::artifacts::tests::test_profile(dir.path())).unwrap()).unwrap();
        let base=0x100000000u64;
        let bytes=pool_dump(base);
        let module=registry.workbench.store.save("module",&bytes[..0x2000],json!({}),"bin").unwrap();
        let heap=registry.workbench.store.save("heap",&bytes[0x2000..],json!({}),"bin").unwrap();
        let document=json!({"format":"ps4wb-memory-image-v1","image_base":format!("{base:#x}"),"regions":[{"address":format!("{base:#x}"),"artifact":module,"protection":3,"selected":true},{"address":format!("{:#x}",base+0x2000),"artifact":heap,"protection":3,"selected":false}],"missing":[]});
        let image=registry.workbench.store.save("memory-image",&serde_json::to_vec(&document).unwrap(),json!({}),"json").unwrap();
        let result=registry.call("unreal_dump",json!({"artifact":image["path"]})).unwrap();
        assert_eq!(result["counts"]["objects"],4);
        assert_eq!(result["counts"]["names"],9);
        std::fs::write(registry.workbench.store.path(document["regions"][1]["artifact"]["path"].as_str().unwrap()).unwrap(),"changed").unwrap();
        assert!(registry.call("unreal_dump",json!({"artifact":image["path"]})).unwrap_err().to_string().contains("region changed"));
    }
}
