//! Feature-area extension point. Each area owns `src/catalog/<area>.json` (tool
//! schemas, same format as `tool_catalog.json`) and a `dispatch` function that
//! returns `None` for tool names it does not own.
use crate::{Result, tools::ToolRegistry};
use serde_json::Value;

pub const CATALOGS: &[(&str, &str)] = &[
    ("dumping", include_str!("catalog/dumping.json")),
    ("engines", include_str!("catalog/engines.json")),
    ("trace", include_str!("catalog/trace.json")),
    ("access", include_str!("catalog/access.json")),
    ("binstatic", include_str!("catalog/binstatic.json")),
    ("project", include_str!("catalog/project.json")),
    ("jailbreak", include_str!("catalog/jailbreak.json")),
    ("internals", include_str!("catalog/internals.json")),
];

/// Every tool schema: the base catalog followed by all extension catalogs.
pub fn full_catalog() -> Result<Vec<Value>> {
    let mut catalog: Vec<Value> = serde_json::from_str(include_str!("tool_catalog.json"))?;
    for (area, text) in CATALOGS {
        let tools: Vec<Value> = serde_json::from_str(text)
            .map_err(|error| anyhow::anyhow!("catalog/{area}.json: {error}"))?;
        catalog.extend(tools);
    }
    Ok(catalog)
}

pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    crate::dumping::dispatch(registry, name, args)
        .or_else(|| crate::engines::dispatch(registry, name, args))
        .or_else(|| crate::dyntrace::dispatch(registry, name, args))
        .or_else(|| crate::dynaccess::dispatch(registry, name, args))
        .or_else(|| crate::binstatic::dispatch(registry, name, args))
        .or_else(|| crate::project::dispatch(registry, name, args))
        .or_else(|| crate::jailbreak::dispatch(registry, name, args))
        .or_else(|| crate::internals::dispatch(registry, name, args))
}
