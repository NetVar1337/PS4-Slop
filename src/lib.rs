#![forbid(unsafe_code)]

pub mod config;
pub mod artifacts;
pub mod analysis;
pub mod development;
pub mod debugger;
pub mod link;
pub mod disasm;
pub mod expr;
pub mod transports;
pub mod workbench;
pub mod tools;
pub mod agents;
pub mod broker;
pub mod client;
pub mod rsp;
pub mod mcp;

pub type Result<T> = anyhow::Result<T>;
