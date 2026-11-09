//! JSON schemas for analysis tools and the validator the broker applies to requests.

use super::*;

fn text_schema(description: &str, maximum: usize) -> Value {
    json!({"type": "string", "description": description, "maxLength": maximum})
}

fn bounded_text_schema(description: &str, minimum: usize, maximum: usize) -> Value {
    json!({"type": "string", "description": description, "minLength": minimum, "maxLength": maximum})
}

fn integer_schema(minimum: i64, maximum: i64) -> Value {
    json!({"type": "integer", "minimum": minimum, "maximum": maximum})
}

pub(super) fn address_schema() -> Value {
    json!({"type": "string", "description": "Unsigned address or RVA, e.g. 0x400000; string avoids JSON precision loss",
        "maxLength": 20, "pattern": "^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$"})
}

pub fn analysis_tools() -> Vec<Value> {
    let mut target = text_schema("Live static-analysis application", 4096);
    target["enum"] = json!(["ida", "ghidra", "binja", "iaito"]);
    let mut direction = text_schema("Reference direction", 32);
    direction["enum"] = json!(["to", "from", "both"]);
    let mut sync_dir = text_schema("Annotation sync direction", 64);
    sync_dir["enum"] = json!(["import_from_static", "export_to_static", "bidirectional"]);
    let pid_schema = integer_schema(1, 2_147_483_647);
    let mod_schema = bounded_text_schema("Module name for runtime_address rebasing", 1, 256);
    let filter_schema = bounded_text_schema("Case-insensitive substring filter", 1, 256);

    let operations = [
        (
            "analysis_status",
            "Connected IDA/Ghidra/Binary Ninja/iaito (radare2) analysis agents; no application is launched automatically.",
            json!({}),
            json!([]),
            true,
        ),
        (
            "analysis_decompile",
            "Decompile a function in a connected IDA/Ghidra/Binary Ninja/iaito database. Supply static address or runtime_address.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_functions",
            "List a bounded page of functions from a connected static-analysis database.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_xrefs",
            "List bounded references to/from a static database address.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "limit": integer_schema(1, 100),
                "direction": direction,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_disasm",
            "Disassemble instructions at a static database address in IDA/Ghidra/Binary Ninja/iaito.",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "count": integer_schema(1, 256),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_strings",
            "List strings in a connected static-analysis database.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
                "min_length": integer_schema(1, 256),
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_imports",
            "List imported symbols in a connected static-analysis database, automatically enriched with Orbis NID demangling.",
            json!({
                "target": target,
                "offset": integer_schema(0, 1_000_000),
                "limit": integer_schema(1, 100),
                "filter": filter_schema,
            }),
            json!(["target"]),
            true,
        ),
        (
            "analysis_rename",
            "Rename a function or label in a connected static-analysis database (local database only; never touches console).",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "name": bounded_text_schema("New symbol identifier", 1, 256),
            }),
            json!(["target", "name"]),
            false,
        ),
        (
            "analysis_comment",
            "Set or clear a comment at an address in a connected static-analysis database (local database only; never touches console).",
            json!({
                "target": target,
                "address": address_schema(),
                "runtime_address": address_schema(),
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "text": text_schema("Comment text", 2048),
            }),
            json!(["target", "text"]),
            false,
        ),
        (
            "analysis_sync_annotations",
            "Synchronize host debugger labels/breakpoints and static-analysis function names/comments with automatic ASLR rebasing.",
            json!({
                "target": target,
                "direction": sync_dir,
                "pid": pid_schema,
                "module": mod_schema,
                "static_base": address_schema(),
                "max_items": integer_schema(1, 500),
            }),
            json!(["target"]),
            false,
        ),
        (
            "analysis_apply_prototypes",
            "Apply a ps4wb-prototypes-v1 artifact (e.g. from orbis_prototypes) as function types on matching import/function names in a connected analyzer (local database only; never touches console).",
            apply_properties(&target, json!({
                "filter": filter_schema,
                "overwrite": {"type": "boolean", "description": "Replace existing user-defined types"},
                "max_items": integer_schema(1, 20_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_struct",
            "Create or update a struct type from a ps4wb-struct-v1 artifact in a connected analyzer (local database only).",
            apply_properties(&target, json!({
                "overwrite": {"type": "boolean", "description": "Replace an existing type with the same name"},
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_coverage",
            "Colour (and optionally comment) covered basic blocks from a ps4wb-coverage-v1 artifact; clear=true removes that colouring. RVAs are rebased to static_base or the analyzer's image base.",
            apply_properties(&target, json!({
                "clear": {"type": "boolean", "description": "Remove colour/coverage comments for the listed blocks instead of applying"},
                "color": {"type": "string", "description": "Highlight colour 0xRRGGBB", "maxLength": 8, "pattern": "^0x[0-9a-fA-F]{6}$"},
                "comment": {"type": "boolean", "description": "Also add a hit-count comment at each block start"},
                "min_hits": integer_schema(0, 2_147_483_647),
                "max_blocks": integer_schema(1, 100_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_classes",
            "Label vtables/typeinfo from a ps4wb-classes-v1 artifact (e.g. rtti_recover) and name unnamed virtual functions Class::vfN in a connected analyzer.",
            apply_properties(&target, json!({
                "overwrite": {"type": "boolean", "description": "Rename vtable/typeinfo labels even when already named"},
                "max_items": integer_schema(1, 50_000),
            })),
            json!(["target", "artifact"]),
            false,
        ),
        (
            "analysis_apply_symbols",
            "Rename/comment addresses from a {rva: name} map, a ps4wb symbols list or a ported annotation set (artifact or inline symbols) in a connected analyzer.",
            apply_properties(&target, json!({
                "symbols": {"type": "object", "description": "Inline {\"0x<rva>\": \"name\"} map (instead of artifact)"},
                "overwrite": {"type": "boolean", "description": "Rename even when the address already has a user-defined name"},
                "max_items": integer_schema(1, 50_000),
            })),
            json!(["target"]),
            false,
        ),
    ];
    operations
        .into_iter()
        .map(|(name, description, properties, required, read_only)| {
            json!({
                "name": name,
                "description": description,
                "inputSchema": {"type": "object", "properties": properties, "required": required, "additionalProperties": false},
                "annotations": {"readOnlyHint": read_only, "destructiveHint": false, "openWorldHint": true}
            })
        })
        .collect()
}

/// Shared `analysis_apply_*` arguments plus tool-specific `extra` properties.
fn apply_properties(target: &Value, extra: Value) -> Value {
    let mut properties = json!({
        "target": target,
        "artifact": bounded_text_schema("Relative path of the JSON artifact inside the artifact directory", 1, 1024),
        "static_base": address_schema(),
        "dry_run": {"type": "boolean", "description": "Validate and show the batches without contacting the analyzer"},
        "allow_hash_mismatch": {"type": "boolean", "description": "Apply even when the artifact module_sha256 differs from the analyzer's input hash"},
    });
    if let (Some(fields), Some(more)) = (properties.as_object_mut(), extra.as_object()) {
        fields.extend(more.clone());
    }
    properties
}

fn python_list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|item| format!("'{item}'")).collect::<Vec<_>>().join(", "))
}

pub fn validate(value: &Value, schema: &Value, location: &str) -> Result<()> {
    let expected = schema.get("type").and_then(Value::as_str).unwrap_or("object");
    let matches = match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_f64() || value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if !matches {
        bail!("{location} must be {expected}");
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value)
    {
        bail!("{location} must be one of {}", Value::Array(choices.clone()));
    }
    match value {
        Value::Object(fields) => {
            let has_properties = schema.get("properties").and_then(Value::as_object).is_some();
            let closed = schema.get("additionalProperties") == Some(&Value::Bool(false)) || has_properties;
            let properties = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
            if closed {
                let mut unknown: Vec<String> = fields.keys().filter(|key| !properties.contains_key(*key)).cloned().collect();
                if !unknown.is_empty() {
                    unknown.sort();
                    bail!("Unknown {location} fields: {}", python_list(&unknown));
                }
            }
            for field in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
                let field = field.as_str().unwrap_or_default();
                if !fields.contains_key(field) {
                    bail!("Missing {location}.{field}");
                }
            }
            for (field, supplied) in fields {
                if let Some(prop_schema) = properties.get(field) {
                    validate(supplied, prop_schema, &format!("{location}.{field}"))?;
                }
            }
        }
        Value::String(text) => {
            let length = text.chars().count() as u64;
            let minimum = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
            let maximum = schema.get("maxLength").and_then(Value::as_u64).unwrap_or(4096);
            if length < minimum || length > maximum {
                bail!("{location} length out of bounds");
            }
            if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                let expression = regex::Regex::new(&format!("^(?:{pattern})$"))?;
                if !expression.is_match(text) {
                    bail!("{location} has invalid syntax");
                }
            }
        }
        Value::Number(num) => {
            if expected == "number" {
                let val = num.as_f64().ok_or_else(|| anyhow!("{location} must be finite"))?;
                let minimum = schema.get("minimum").and_then(Value::as_f64).unwrap_or(f64::NEG_INFINITY);
                let maximum = schema.get("maximum").and_then(Value::as_f64).unwrap_or(f64::INFINITY);
                if !val.is_finite() || val < minimum || val > maximum {
                    bail!("{location} out of bounds");
                }
            } else {
                let minimum = schema.get("minimum").and_then(Value::as_i64).map_or(0, i128::from);
                let maximum = schema.get("maximum").and_then(Value::as_i64).map_or(2_147_483_647, i128::from);
                require_integer(value, location, minimum, maximum).map_err(|_| anyhow!("{location} out of bounds"))?;
            }
        }
        Value::Array(items) => {
            let length = items.len() as u64;
            let minimum = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let maximum = schema.get("maxItems").and_then(Value::as_u64).unwrap_or(100);
            if length < minimum || length > maximum {
                bail!("{location} item count out of bounds");
            }
            let item_schema = schema.get("items").cloned().unwrap_or_else(|| json!({}));
            for item in items {
                validate(item, &item_schema, &format!("{location}[]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}
