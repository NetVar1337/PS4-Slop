//! Engine and runtime metadata recovery: Unity IL2CPP, Unreal names/objects, Itanium C++ RTTI/vtables, YARA-subset and crypto-constant scanning.
use crate::{Result, tools::ToolRegistry};
use serde_json::Value;

/// Returns `None` when `name` is not a tool owned by this area.
pub fn dispatch(_registry: &mut ToolRegistry, _name: &str, _args: &Value) -> Option<Result<Value>> {
    None
}
