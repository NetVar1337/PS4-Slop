//! Sandboxed host-side breakpoint scripts (Rhai).
//!
//! A script defines `fn on_stop(ctx)` which runs on the host after each stop and
//! returns `"continue"` / `"stop"` (or `true` = stop, `false`/`()` = continue).
//! The sandbox exposes only read-only target access through `ctx`:
//! `ctx.reg(name)`, `ctx.read_u8/u16/u32/u64/i32/f32/f64(addr)`,
//! `ctx.read_bytes(addr, n)`, `ctx.read_cstring(addr, max)`, hit metadata
//! (`ctx.bp_name`, `ctx.bp_address`, `ctx.hits`, `ctx.total_hits`,
//! `ctx.thread_id`, `ctx.rip`, `ctx.location`), `log(msg)` / `ctx.log(msg)` and a
//! persistent map `ctx.state` (write through the chain: `ctx.state.n += 1`, or
//! `ctx.get(key)` / `ctx.set(key, value)`).
//!
//! There are no filesystem, network, process, module-import or `eval` facilities,
//! and no memory or register writes. Operations, call depth, string/array/map
//! sizes, per-hit wall time, per-hit memory reads and log volume are bounded.
use crate::Result;
use anyhow::{Context as _, bail, ensure};
use rhai::{Blob, Dynamic, Engine, EvalAltResult, FLOAT, INT, ImmutableString, Map, Scope, AST};
use serde_json::{Value, json};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};

pub const MAX_SOURCE: usize = 16 * 1024;
const MAX_LOG_LINE: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_operations: u64,
    pub per_hit: Duration,
    pub max_reads: usize,
    pub max_read_bytes: usize,
    pub max_logs: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_operations: 1_000_000,
            per_hit: Duration::from_millis(250),
            max_reads: 256,
            max_read_bytes: 64 * 1024,
            max_logs: 2000,
        }
    }
}

/// Read-only target memory for scripts.
pub trait ScriptMemory {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>>;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// The memory provider is installed only while `on_stop` runs; a `ctx` kept by a
/// script past its hit sees an empty slot and every read fails.
pub type MemorySlot = Rc<RefCell<Option<Box<dyn ScriptMemory>>>>;

#[derive(Debug, Clone, Default)]
pub struct Hit {
    pub registers: BTreeMap<String, u64>,
    pub bp_name: String,
    pub bp_address: u64,
    pub hits: u64,
    pub total_hits: u64,
    pub thread_id: u32,
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Continue,
    Stop,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub decision: Decision,
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub elapsed_ms: u128,
    pub reads: usize,
}

impl Outcome {
    pub fn to_json(&self) -> Value {
        json!({"decision":if self.decision == Decision::Stop {"stop"} else {"continue"},
            "error":self.error,"logs":self.logs,"elapsed_ms":self.elapsed_ms as u64,"memory_reads":self.reads})
    }
}

struct Shared {
    memory: MemorySlot,
    state: RefCell<Map>,
    logs: RefCell<Vec<String>>,
    total_logs: Cell<usize>,
    reads: Cell<usize>,
    read_bytes: Cell<usize>,
    limits: Limits,
}

type Fallible<T> = std::result::Result<T, Box<EvalAltResult>>;

impl Shared {
    fn log(&self, message: &str) {
        if self.total_logs.get() >= self.limits.max_logs {
            return;
        }
        self.total_logs.set(self.total_logs.get() + 1);
        let mut line: String = message.chars().take(MAX_LOG_LINE).collect();
        if line.len() < message.len() {
            line.push('…');
        }
        self.logs.borrow_mut().push(line);
    }

    fn read(&self, address: INT, length: usize) -> Fallible<Vec<u8>> {
        let address = address as u64;
        if length == 0 {
            return Ok(Vec::new());
        }
        if self.reads.get() >= self.limits.max_reads
            || self.read_bytes.get() + length > self.limits.max_read_bytes
        {
            return Err("per-hit memory read budget exhausted".into());
        }
        self.reads.set(self.reads.get() + 1);
        self.read_bytes.set(self.read_bytes.get() + length);
        let mut slot = self.memory.borrow_mut();
        let memory = slot.as_mut().ok_or("target memory is only readable during on_stop")?;
        memory
            .read(address, length)
            .map_err(|error| format!("read {length} bytes at {address:#x} failed: {error}").into())
    }

    fn read_le(&self, address: INT, length: usize) -> Fallible<u64> {
        let bytes = self.read(address, length)?;
        let mut padded = [0u8; 8];
        padded[..length].copy_from_slice(&bytes[..length]);
        Ok(u64::from_le_bytes(padded))
    }
}

#[derive(Clone)]
struct ScriptCtx {
    hit: Rc<Hit>,
    shared: Rc<Shared>,
}

pub struct ScriptHost {
    engine: Engine,
    ast: AST,
    shared: Rc<Shared>,
    deadline: Rc<Cell<Option<Instant>>>,
}

fn register_api(engine: &mut Engine, shared: &Rc<Shared>) {
    engine.register_type_with_name::<ScriptCtx>("Ctx");
    engine.register_fn("reg", |ctx: &mut ScriptCtx, name: &str| -> Fallible<INT> {
        ctx.hit
            .registers
            .get(&name.to_ascii_lowercase())
            .map(|value| *value as INT)
            .ok_or_else(|| format!("unknown register {name}").into())
    });
    macro_rules! reader {
        ($name:literal, $length:expr, $convert:expr) => {
            engine.register_fn($name, |ctx: &mut ScriptCtx, address: INT| -> Fallible<_> {
                let raw = ctx.shared.read_le(address, $length)?;
                Ok($convert(raw))
            });
        };
    }
    reader!("read_u8", 1, |raw: u64| raw as INT);
    reader!("read_u16", 2, |raw: u64| raw as INT);
    reader!("read_u32", 4, |raw: u64| raw as INT);
    reader!("read_i32", 4, |raw: u64| raw as u32 as i32 as INT);
    reader!("read_u64", 8, |raw: u64| raw as INT);
    reader!("read_f32", 4, |raw: u64| f32::from_bits(raw as u32) as FLOAT);
    reader!("read_f64", 8, |raw: u64| f64::from_bits(raw) as FLOAT);
    engine.register_fn("read_bytes", |ctx: &mut ScriptCtx, address: INT, length: INT| -> Fallible<Blob> {
        if !(0..=4096).contains(&length) {
            return Err("read_bytes length must be 0..=4096".into());
        }
        ctx.shared.read(address, length as usize)
    });
    engine.register_fn("read_cstring", |ctx: &mut ScriptCtx, address: INT, max: INT| -> Fallible<String> {
        if !(1..=4096).contains(&max) {
            return Err("read_cstring max must be 1..=4096".into());
        }
        let mut content = Vec::new();
        let mut cursor = address as u64;
        while content.len() < max as usize {
            let page_left = 0x1000 - (cursor & 0xfff) as usize;
            let chunk = page_left.min(256).min(max as usize - content.len());
            let bytes = ctx.shared.read(cursor as INT, chunk)?;
            if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
                content.extend(&bytes[..end]);
                return Ok(String::from_utf8_lossy(&content).into_owned());
            }
            content.extend(&bytes);
            cursor = cursor.wrapping_add(chunk as u64);
        }
        Ok(String::from_utf8_lossy(&content).into_owned())
    });
    engine.register_get("bp_name", |ctx: &mut ScriptCtx| -> ImmutableString { ctx.hit.bp_name.clone().into() });
    engine.register_get("bp_address", |ctx: &mut ScriptCtx| ctx.hit.bp_address as INT);
    engine.register_get("hits", |ctx: &mut ScriptCtx| ctx.hit.hits as INT);
    engine.register_get("total_hits", |ctx: &mut ScriptCtx| ctx.hit.total_hits as INT);
    engine.register_get("thread_id", |ctx: &mut ScriptCtx| ctx.hit.thread_id as INT);
    engine.register_get("rip", |ctx: &mut ScriptCtx| ctx.hit.registers.get("rip").copied().unwrap_or(0) as INT);
    engine.register_get("location", |ctx: &mut ScriptCtx| -> Dynamic {
        ctx.hit.location.clone().map_or(Dynamic::UNIT, Dynamic::from)
    });
    engine.register_get_set(
        "state",
        |ctx: &mut ScriptCtx| ctx.shared.state.borrow().clone(),
        |ctx: &mut ScriptCtx, value: Map| *ctx.shared.state.borrow_mut() = value,
    );
    engine.register_fn("get", |ctx: &mut ScriptCtx, key: &str| -> Dynamic {
        ctx.shared.state.borrow().get(key).cloned().unwrap_or(Dynamic::UNIT)
    });
    engine.register_fn("set", |ctx: &mut ScriptCtx, key: &str, value: Dynamic| {
        ctx.shared.state.borrow_mut().insert(key.into(), value);
    });
    engine.register_fn("log", |ctx: &mut ScriptCtx, message: &str| ctx.shared.log(message));
    engine.register_fn("hex", |value: INT| format!("{:#x}", value as u64));
    let logger = shared.clone();
    engine.register_fn("log", move |message: &str| logger.log(message));
    let printer = shared.clone();
    engine.on_print(move |text| printer.log(text));
    let debugger = shared.clone();
    engine.on_debug(move |text, _, _| debugger.log(text));
}

impl ScriptHost {
    pub fn new(source: &str, limits: Limits, memory: MemorySlot) -> Result<Self> {
        ensure!(!source.is_empty() && source.len() <= MAX_SOURCE, "Script must be 1..=16384 bytes");
        let shared = Rc::new(Shared {
            memory,
            state: RefCell::new(Map::new()),
            logs: RefCell::new(Vec::new()),
            total_logs: Cell::new(0),
            reads: Cell::new(0),
            read_bytes: Cell::new(0),
            limits,
        });
        let mut engine = Engine::new();
        engine.set_max_operations(limits.max_operations.max(1));
        engine.set_max_call_levels(32);
        engine.set_max_expr_depths(64, 32);
        engine.set_max_string_size(64 * 1024);
        engine.set_max_array_size(4096);
        engine.set_max_map_size(1024);
        engine.disable_symbol("eval");
        let deadline: Rc<Cell<Option<Instant>>> = Rc::new(Cell::new(None));
        let clock = deadline.clone();
        engine.on_progress(move |_| match clock.get() {
            Some(deadline) if Instant::now() > deadline => Some(Dynamic::from("per-hit time budget exceeded")),
            _ => None,
        });
        register_api(&mut engine, &shared);
        let ast = engine.compile(source).map_err(|error| anyhow::anyhow!("Script compile error: {error}"))?;
        ensure!(
            ast.iter_functions().any(|function| function.name == "on_stop" && function.params.len() == 1),
            "Script must define fn on_stop(ctx)"
        );
        let host = Self { engine, ast, shared, deadline };
        // Top-level statements run once (initialisation), under the same limits.
        host.deadline.set(Some(Instant::now() + limits.per_hit));
        let initial = host.engine.run_ast_with_scope(&mut Scope::new(), &host.ast);
        host.deadline.set(None);
        if let Err(error) = initial {
            bail!("Script initialisation failed: {error}");
        }
        Ok(host)
    }

    /// Run `on_stop` for one hit. Script errors, budget exhaustion and invalid
    /// return values all decide `Stop` (the safe default: the target stays halted).
    pub fn on_stop(&mut self, hit: Hit) -> Outcome {
        self.shared.reads.set(0);
        self.shared.read_bytes.set(0);
        let started = Instant::now();
        self.deadline.set(Some(started + self.shared.limits.per_hit));
        let ctx = ScriptCtx { hit: Rc::new(hit), shared: self.shared.clone() };
        let options = rhai::CallFnOptions::new().eval_ast(false).rewind_scope(true);
        let result = self
            .engine
            .call_fn_with_options::<Dynamic>(options, &mut Scope::new(), &self.ast, "on_stop", (ctx,));
        self.deadline.set(None);
        let (decision, error) = match result {
            Ok(value) => Self::decide(value),
            Err(error) => (Decision::Stop, Some(error.to_string())),
        };
        Outcome {
            decision,
            error,
            logs: std::mem::take(&mut *self.shared.logs.borrow_mut()),
            elapsed_ms: started.elapsed().as_millis(),
            reads: self.shared.reads.get(),
        }
    }

    fn decide(value: Dynamic) -> (Decision, Option<String>) {
        if value.is_unit() {
            return (Decision::Continue, None);
        }
        if let Some(flag) = value.clone().try_cast::<bool>() {
            return (if flag { Decision::Stop } else { Decision::Continue }, None);
        }
        if let Ok(text) = value.clone().into_immutable_string() {
            return match text.as_str() {
                "stop" => (Decision::Stop, None),
                "continue" => (Decision::Continue, None),
                other => (Decision::Stop, Some(format!("on_stop returned unknown decision {other:?}"))),
            };
        }
        (Decision::Stop, Some(format!("on_stop returned unsupported type {}", value.type_name())))
    }

    /// Persistent script state, as JSON (non-JSON values are stringified).
    pub fn state_json(&self) -> Value {
        let state = self.shared.state.borrow();
        let mut out = serde_json::Map::new();
        for (key, value) in state.iter() {
            out.insert(key.to_string(), dynamic_json(value));
        }
        Value::Object(out)
    }
}

fn dynamic_json(value: &Dynamic) -> Value {
    if let Ok(number) = value.as_int() {
        return json!(number);
    }
    if let Ok(flag) = value.as_bool() {
        return json!(flag);
    }
    if let Ok(number) = value.as_float() {
        return json!(number);
    }
    if value.is_string() {
        return json!(value.clone().into_string().unwrap_or_default());
    }
    if value.is_unit() {
        return Value::Null;
    }
    json!(value.to_string())
}

/// Parse a breakpoint list argument entry name (bounded, printable).
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(name.len() <= 64 && name.chars().all(|c| c.is_ascii_graphic()), "Breakpoint names must be <= 64 printable ASCII characters");
    Ok(())
}

/// Convert a `Box<dyn ScriptMemory>` back into its concrete type.
pub fn recover<T: 'static>(memory: Box<dyn ScriptMemory>) -> Result<T> {
    memory.into_any().downcast::<T>().map(|boxed| *boxed).ok().context("Script memory provider type mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeMemory(BTreeMap<u64, u8>);
    impl ScriptMemory for FakeMemory {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
            (0..length as u64)
                .map(|i| self.0.get(&(address + i)).copied().context("unmapped"))
                .collect()
        }
        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    fn slot() -> MemorySlot {
        let mut bytes = BTreeMap::new();
        for (i, byte) in b"hello\0".iter().enumerate() {
            bytes.insert(0x1000 + i as u64, *byte);
        }
        for (i, byte) in 0xdeadbeefu32.to_le_bytes().iter().enumerate() {
            bytes.insert(0x2000 + i as u64, *byte);
        }
        for (i, byte) in 2.5f32.to_le_bytes().iter().enumerate() {
            bytes.insert(0x3000 + i as u64, *byte);
        }
        Rc::new(RefCell::new(Some(Box::new(FakeMemory(bytes)))))
    }

    fn hit(rax: u64) -> Hit {
        Hit {
            registers: [("rax".to_owned(), rax), ("rip".to_owned(), 0x401000)].into(),
            bp_name: "update".into(),
            bp_address: 0x401000,
            hits: 1,
            total_hits: 1,
            thread_id: 7,
            location: Some("eboot.bin+0x1000".into()),
        }
    }

    #[test]
    fn script_reads_memory_keeps_state_and_decides() {
        let source = r#"
            fn on_stop(ctx) {
                ctx.state.count = (ctx.state.count ?? 0) + 1;
                ctx.set("last", ctx.reg("rax"));
                let name = ctx.read_cstring(0x1000, 6);
                log(`${ctx.bp_name} ${name} ${hex(ctx.read_u32(0x2000))} ${ctx.read_f32(0x3000)} at ${ctx.location}`);
                print("printed");
                if ctx.state.count >= 2 { "stop" } else { "continue" }
            }
        "#;
        let mut host = ScriptHost::new(source, Limits::default(), slot()).unwrap();
        let first = host.on_stop(hit(5));
        assert_eq!(first.decision, Decision::Continue, "{first:?}");
        assert_eq!(first.logs[0], "update hello 0xdeadbeef 2.5 at eboot.bin+0x1000");
        assert_eq!(first.logs[1], "printed");
        let second = host.on_stop(hit(9));
        assert_eq!(second.decision, Decision::Stop);
        assert_eq!(host.state_json()["count"], 2);
        assert_eq!(host.state_json()["last"], 9);
    }

    #[test]
    fn sandbox_limits_stop_runaway_and_hostile_scripts() {
        // Infinite loop: terminated by the operation limit / per-hit deadline.
        let mut host = ScriptHost::new("fn on_stop(ctx) { loop {} }", Limits::default(), slot()).unwrap();
        let outcome = host.on_stop(hit(0));
        assert_eq!(outcome.decision, Decision::Stop);
        assert!(outcome.error.is_some());
        // eval is disabled, modules are not compiled in, and on_stop is mandatory.
        assert!(ScriptHost::new("fn on_stop(ctx) { eval(\"1\") }", Limits::default(), slot()).is_err());
        assert!(ScriptHost::new("import \"x\" as y; fn on_stop(ctx) {}", Limits::default(), slot()).is_err());
        assert!(ScriptHost::new("fn other() {}", Limits::default(), slot()).is_err());
        // Read budget and unmapped reads become script errors -> stop.
        let limits = Limits { max_reads: 1, ..Limits::default() };
        let mut host =
            ScriptHost::new("fn on_stop(ctx) { ctx.read_u8(0x1000); ctx.read_u8(0x1001) }", limits, slot()).unwrap();
        let outcome = host.on_stop(hit(0));
        assert!(outcome.error.unwrap().contains("budget"));
        let mut host = ScriptHost::new("fn on_stop(ctx) { ctx.read_u64(0x9999); true }", Limits::default(), slot()).unwrap();
        assert!(host.on_stop(hit(0)).error.unwrap().contains("failed"));
        // Booleans: false continues; unknown strings stop with an error.
        let mut host = ScriptHost::new("fn on_stop(ctx) { false }", Limits::default(), slot()).unwrap();
        assert_eq!(host.on_stop(hit(0)).decision, Decision::Continue);
        let mut host = ScriptHost::new("fn on_stop(ctx) { \"maybe\" }", Limits::default(), slot()).unwrap();
        assert!(host.on_stop(hit(0)).error.is_some());
        // Memory provider removed after the hit: retained ctx cannot read.
        let memory = slot();
        let mut host = ScriptHost::new("fn on_stop(ctx) { ctx.read_u8(0x1000); () }", Limits::default(), memory.clone()).unwrap();
        memory.borrow_mut().take();
        assert!(host.on_stop(hit(0)).error.unwrap().contains("only readable"));
    }
}
