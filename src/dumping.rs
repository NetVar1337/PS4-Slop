//! Process/module dumping: ELF rebuild, whole-process dumps, ELF core files, deduplicated snapshot timeline.
use crate::{Result, tools::ToolRegistry};
use serde_json::Value;

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(_registry: &mut ToolRegistry, _name: &str, _args: &Value) -> Option<Result<Value>> {
    None
}
