#![forbid(unsafe_code)]

pub mod config;
pub mod jailbreak;
pub mod internals;
pub mod offsetscan;
pub mod artifacts;
pub mod analysis;
pub mod development;
pub mod debugger;
pub mod link;
pub mod asm;
pub mod disasm;
pub mod ehframe;
pub mod expr;
pub mod nid;
pub mod scanner;
pub mod transports;
pub mod workbench;
pub mod tools;
pub mod agents;
pub mod broker;
pub mod client;
pub mod rsp;
pub mod mcp;
pub mod extensions;
pub mod dumping;
pub mod engines;
pub mod sdkgen;
pub mod research;
pub mod sessions;
pub mod hooks;
pub mod scaffold;
pub mod games;
pub mod replay;
#[cfg(test)]
pub mod test_support;
pub mod dyntrace;
pub mod dynaccess;
pub mod binstatic;
pub mod project;

pub type Result<T> = anyhow::Result<T>;

// Dumping area (process/module dumps, ELF rebuild, core files, snapshots).
pub mod orbisdyn;
pub mod elfrebuild;
pub mod coredump;
pub mod snapstore;
// Engine & metadata recovery area (src/engines.rs).
pub mod bytesource;
pub mod il2cpp;
pub mod unreal;
pub mod rtti;
pub mod yara;
pub mod cryptoscan;
pub mod source_engine;
// trace area (run-loop tracing & coverage)
pub mod tracekit;
// Access/crash/pointer/struct/script feature area.
pub mod pointerscan;
pub mod structinfer;
pub mod hostscript;
// Native static analysis (binstatic area).
pub mod binimage;
pub mod cfg;
pub mod sigmaker;
pub mod bindiff;
pub mod prototypes;
// Project area modules.
pub mod recipes;
pub mod analysis_apply;
