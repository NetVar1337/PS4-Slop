//! Evidence-preserving C++ views. Never invent types for fork-specific enums.
use crate::Result;
use anyhow::ensure;
use serde_json::{Value, json};
use std::collections::BTreeSet;

trait Notes {
    fn note(&mut self, value: Value);
}
impl Notes for Vec<Value> {
    fn note(&mut self, value: Value) {
        if self.len() < 256 {
            self.push(value);
        }
    }
}

pub fn ident(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    // Prefixing all generated members also avoids C++ keywords and reserved names.
    format!("wb_{out}")
}
pub fn safe_ident(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    if [
        "class",
        "struct",
        "namespace",
        "template",
        "typename",
        "auto",
        "const",
        "volatile",
        "public",
        "private",
        "protected",
        "using",
        "enum",
        "union",
        "int",
        "char",
        "float",
        "double",
        "long",
        "short",
        "void",
        "bool",
        "return",
        "new",
        "delete",
        "operator",
        "virtual",
        "override",
        "final",
        "static",
        "inline",
        "constexpr",
        "consteval",
        "constinit",
        "thread_local",
        "extern",
        "export",
        "import",
        "module",
        "requires",
        "concept",
        "decltype",
        "if",
        "else",
        "switch",
        "case",
        "default",
        "for",
        "while",
        "do",
        "break",
        "continue",
        "goto",
        "try",
        "catch",
        "throw",
        "noexcept",
        "sizeof",
        "alignof",
        "alignas",
        "static_assert",
        "this",
        "true",
        "false",
        "nullptr",
        "signed",
        "unsigned",
        "wchar_t",
        "char8_t",
        "char16_t",
        "char32_t",
        "and",
        "or",
        "not",
        "xor",
        "bitand",
        "bitor",
        "compl",
        "and_eq",
        "or_eq",
        "xor_eq",
        "not_eq",
        "friend",
        "mutable",
        "register",
        "explicit",
        "dynamic_cast",
        "static_cast",
        "reinterpret_cast",
        "const_cast",
        "typeid",
        "co_await",
        "co_return",
        "co_yield",
    ]
    .contains(&out.as_str())
        || out.starts_with("__")
    {
        out.push_str("_wb");
    }
    out
}
fn start(ns: &str) -> String {
    format!(
        "\n#include <array>\n#include <cstddef>\n#include <cstdint>\n#include <internals/memory.hpp>\nnamespace {ns}::types {{\n"
    )
}
fn field_type(name: &str, size: u64) -> Option<&'static str> {
    match (name, size) {
        ("IntProperty", 4) => Some("std::int32_t"),
        ("UInt32Property", 4) => Some("std::uint32_t"),
        ("Int64Property", 8) => Some("std::int64_t"),
        ("UInt64Property", 8) => Some("std::uint64_t"),
        ("FloatProperty", 4) => Some("float"),
        ("DoubleProperty", 8) => Some("double"),
        ("ByteProperty", 1) => Some("std::uint8_t"),
        ("Int16Property", 2) => Some("std::int16_t"),
        ("ObjectProperty" | "ClassProperty", 8) => Some("std::uintptr_t"),
        _ => None, // BoolProperty may be packed; never fabricate a bool accessor.
    }
}
pub fn unreal(doc: &Value, ns: &str) -> Result<(String, Vec<Value>)> {
    let mut out = start(ns);
    let mut notes = Vec::new();
    let mut names = BTreeSet::new();
    for class in doc["sdk"].as_array().into_iter().flatten().take(50_000) {
        let name = ident(
            class["path"]
                .as_str()
                .or_else(|| class["name"].as_str())
                .unwrap_or("unnamed"),
        );
        if !names.insert(name.clone()) {
            continue;
        }
        let Some(size) = class["size"].as_u64().filter(|s| *s > 0 && *s <= 1 << 20) else {
            notes.note(json!({"class":name,"reason":"unknown/invalid class size"}));
            continue;
        };
        out.push_str(&format!(
            "struct {name} {{\n    std::array<std::byte, {size}> storage;\n"
        ));
        let mut members = BTreeSet::new();
        for prop in class["properties"]
            .as_array()
            .into_iter()
            .flatten()
            .take(512)
        {
            let field = ident(prop["name"].as_str().unwrap_or("unnamed"));
            if !members.insert(field.clone()) {
                continue;
            }
            let (Some(offset), Some(width)) = (prop["offset"].as_u64(), prop["size"].as_u64())
            else {
                continue;
            };
            if !width.checked_add(offset).is_some_and(|end| end <= size) {
                notes.note(json!({"class":name,"field":field,"reason":"field outside class"}));
                continue;
            }
            out.push_str(&format!("    static constexpr std::size_t {field} = {offset};\n    static_assert({field} + {width} <= {size});\n"));
            if let Some(kind) = field_type(prop["type"].as_str().unwrap_or(""), width) {
                out.push_str(&format!("    static bool read_{field}(internals::MemoryReader reader, std::uintptr_t object, {kind}& value) noexcept {{ return object <= UINTPTR_MAX - {field} && reader.Get(object + {field}, value); }}\n"));
            } else {
                notes.note(json!({"class":name,"field":field,"reason":"opaque, packed, or unresolved type; offset only"}));
            }
        }
        out.push_str(&format!("}};\nstatic_assert(sizeof({name}) == {size});\n"));
        if let Some(parent) = class["super"].as_str() {
            out.push_str(&format!(
                "// {name} superclass: {} (layout remains explicit)\n",
                ident(parent)
            ));
        }
    }
    // Optional explicitly recovered enums. Unrecovered enums do not get guessed.
    for enumeration in doc["enums"].as_array().into_iter().flatten().take(4096) {
        let name = ident(enumeration["name"].as_str().unwrap_or("enum"));
        if !names.insert(name.clone()) {
            continue;
        }
        out.push_str(&format!("enum class {name} : std::int64_t {{\n"));
        let mut entries = BTreeSet::new();
        for entry in enumeration["values"]
            .as_array()
            .into_iter()
            .flatten()
            .take(4096)
        {
            let member = ident(entry["name"].as_str().unwrap_or("entry"));
            if let Some(value) = entry["value"].as_i64()
                && entries.insert(member.clone())
            {
                out.push_str(&format!("    {member} = {value},\n"));
            }
        }
        out.push_str("};\n");
    }
    out.push_str("}\n");
    Ok((out, notes))
}
pub fn source(doc: &Value, ns: &str) -> Result<(String, Vec<Value>)> {
    let mut out = start(ns);
    let mut notes = Vec::new();
    let tables: std::collections::BTreeMap<&str, &Value> = doc["recv_tables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| Some((v["name"].as_str()?, v)))
        .collect();
    struct Position<'a> {
        base: u64,
        prefix: &'a str,
        depth: usize,
    }
    fn walk(
        out: &mut String,
        notes: &mut Vec<Value>,
        tables: &std::collections::BTreeMap<&str, &Value>,
        table: &Value,
        position: Position<'_>,
        seen: &mut BTreeSet<String>,
    ) -> Result<()> {
        if out.len() >= 8 << 20 {
            return Ok(());
        }
        let Position {
            base,
            prefix,
            depth,
        } = position;
        ensure!(depth <= 32, "Nested RecvTable depth exceeds 32");
        for prop in table["props"].as_array().into_iter().flatten().take(4096) {
            if out.len() >= 8 << 20 {
                notes.note(json!({"reason":"Nested SDK export capped at 8 MiB"}));
                break;
            }
            let name = format!("{prefix}{}", ident(prop["name"].as_str().unwrap_or("prop")));
            let Some(local) = prop["offset"]
                .as_str()
                .and_then(|s| crate::tools::address(&json!(s)).ok())
            else {
                continue;
            };
            let Some(offset) = base.checked_add(local) else {
                continue;
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            out.push_str(&format!(
                "    static constexpr std::size_t {name} = {offset:#x};\n"
            ));
            if let Some(nested) = prop["data_table"].as_str().and_then(|n| tables.get(n)) {
                if depth < 32 {
                    walk(
                        out,
                        notes,
                        tables,
                        nested,
                        Position {
                            base: offset,
                            prefix: &format!("{name}_"),
                            depth: depth + 1,
                        },
                        seen,
                    )?;
                } else {
                    notes.note(json!({"field":name,"reason":"nested table depth/cycle limit"}));
                }
            }
        }
        Ok(())
    }
    for (name, table) in &tables {
        if out.len() >= 8 << 20 {
            break;
        }
        out.push_str(&format!("struct {} {{\n", ident(name)));
        walk(
            &mut out,
            &mut notes,
            &tables,
            table,
            Position {
                base: 0,
                prefix: "",
                depth: 0,
            },
            &mut BTreeSet::new(),
        )?;
        out.push_str("};\n");
    }
    notes.note(json!({"reason":"Source fork raw type enums are not portable; typed accessors require a typed finding"}));
    out.push_str("}\n");
    Ok((out, notes))
}
