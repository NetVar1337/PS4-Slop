//! Host-side x86-64 disassembly (iced-x86). Pure functions: no console access.
//!
//! Decoding is always local, so it works on live memory reads and on extracted
//! artifacts alike, and it never depends on optional console-side extensions.

use crate::Result;
use anyhow::ensure;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic,
    OpKind, Register,
};
use serde_json::{Value, json};

pub const MAX_INSTRUCTIONS: usize = 512;

#[derive(Debug, Clone)]
pub struct Decoded {
    pub address: u64,
    pub length: usize,
    pub bytes: Vec<u8>,
    pub text: String,
    pub flow: &'static str,
    pub branch_target: Option<u64>,
    pub memory_target: Option<u64>,
    pub valid: bool,
}

fn flow_name(flow: FlowControl) -> &'static str {
    match flow {
        FlowControl::Next => "next",
        FlowControl::UnconditionalBranch => "jump",
        FlowControl::IndirectBranch => "indirect_jump",
        FlowControl::ConditionalBranch => "conditional_jump",
        FlowControl::Return => "return",
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "indirect_call",
        FlowControl::Interrupt => "interrupt",
        FlowControl::XbeginXabortXend => "transaction",
        FlowControl::Exception => "exception",
    }
}

fn near_target(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16
    )
    .then(|| instruction.near_branch_target())
}

/// Decode up to `count` instructions from `bytes`, which start at `base`. An
/// undecodable byte is reported as a one-byte invalid entry so callers can
/// resynchronize; decoding also stops at the end of the buffer (a truncated
/// final instruction is dropped, never guessed).
pub fn decode(bytes: &[u8], base: u64, count: usize) -> Vec<Decoded> {
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_branch_leading_zeros(false);
    formatter.options_mut().set_rip_relative_addresses(true);
    let mut result = Vec::new();
    let mut instruction = Instruction::default();
    while decoder.can_decode() && result.len() < count.min(MAX_INSTRUCTIONS) {
        let offset = decoder.position();
        decoder.decode_out(&mut instruction);
        let length = instruction.len();
        if length == 0 || offset + length > bytes.len() {
            break;
        }
        let valid = !instruction.is_invalid();
        let mut text = String::new();
        if valid {
            formatter.format(&instruction, &mut text);
        } else {
            text = format!("db 0x{:02x}", bytes[offset]);
        }
        result.push(Decoded {
            address: instruction.ip(),
            length: if valid { length } else { 1 },
            bytes: bytes[offset..offset + if valid { length } else { 1 }].to_vec(),
            text,
            flow: if valid {
                flow_name(instruction.flow_control())
            } else {
                "invalid"
            },
            branch_target: valid.then(|| near_target(&instruction)).flatten(),
            memory_target: (valid && instruction.is_ip_rel_memory_operand())
                .then(|| instruction.ip_rel_memory_address()),
            valid,
        });
        if !valid {
            // `decode_out` consumed the whole invalid encoding; rewind to the next byte.
            decoder
                .set_position(offset + 1)
                .expect("position within buffer");
            decoder.set_ip(base + (offset as u64) + 1);
        }
    }
    result
}

pub fn to_json(items: &[Decoded]) -> Value {
    json!(
        items
            .iter()
            .map(|item| {
                let mut entry = json!({
                    "address": format!("{:#x}", item.address),
                    "length": item.length,
                    "bytes": hex::encode(&item.bytes),
                    "text": item.text,
                    "flow": item.flow,
                });
                if let Some(target) = item.branch_target {
                    entry["branch_target"] = json!(format!("{target:#x}"));
                }
                if let Some(target) = item.memory_target {
                    entry["rip_relative_target"] = json!(format!("{target:#x}"));
                }
                if !item.valid {
                    entry["invalid"] = json!(true);
                }
                entry
            })
            .collect::<Vec<_>>()
    )
}

/// How a "step over" must be performed for the instruction at the start of `bytes`.
#[derive(Debug, PartialEq, Eq)]
pub enum StepPlan {
    /// Execute exactly one instruction (the single-step command is enough).
    Single,
    /// Calls and repeated string operations: run to the next instruction.
    RunTo(u64),
}

pub fn step_over_plan(bytes: &[u8], address: u64) -> Result<StepPlan> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    ensure!(
        !instruction.is_invalid(),
        "Cannot decode an instruction at {address:#x}; step over refused"
    );
    let repeats = instruction.has_rep_prefix()
        || instruction.has_repe_prefix()
        || instruction.has_repne_prefix();
    let string_op = instruction.is_string_instruction();
    Ok(
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) || (repeats && string_op)
        {
            StepPlan::RunTo(instruction.next_ip())
        } else {
            StepPlan::Single
        },
    )
}

/// True when the instruction at the start of `bytes` is a `ret`/`retf`/`iret`.
pub fn is_return(bytes: &[u8], address: u64) -> bool {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    !instruction.is_invalid() && instruction.flow_control() == FlowControl::Return
}

/// Classification used by the frame-pointer unwinder: does `bytes` begin with the
/// canonical `push rbp; mov rbp, rsp` prologue?
pub fn has_frame_prologue(bytes: &[u8], address: u64) -> bool {
    let items = decode_raw(bytes, address, 3);
    let mut index = 0;
    // Skip an `endbr64` landing pad.
    if items
        .get(index)
        .is_some_and(|item| item.mnemonic() == Mnemonic::Endbr64)
    {
        index += 1;
    }
    let push = items.get(index);
    let mov = items.get(index + 1);
    matches!((push, mov), (Some(push), Some(mov))
        if push.mnemonic() == Mnemonic::Push
            && push.op0_register() == Register::RBP
            && mov.mnemonic() == Mnemonic::Mov
            && mov.op0_register() == Register::RBP
            && mov.op1_register() == Register::RSP)
}

fn decode_raw(bytes: &[u8], address: u64, count: usize) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut result = Vec::new();
    while decoder.can_decode() && result.len() < count {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        result.push(instruction);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // push rbp; mov rbp,rsp; call +0x10 (rel32); xor eax,eax; ret
    const CODE: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0x10, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xc3,
    ];

    #[test]
    fn decodes_text_flow_and_branch_targets() {
        let items = decode(CODE, 0x401000, 16);
        let text: Vec<_> = items.iter().map(|item| item.text.as_str()).collect();
        assert_eq!(
            text,
            ["push rbp", "mov rbp, rsp", "call 0x401019", "xor eax, eax", "ret"]
        );
        assert_eq!(items[2].flow, "call");
        assert_eq!(items[2].branch_target, Some(0x401019));
        assert_eq!(items[4].flow, "return");
        assert_eq!(items[1].address, 0x401001);
        assert_eq!(items[1].bytes, [0x48, 0x89, 0xe5]);
    }

    #[test]
    fn rip_relative_memory_operand_is_resolved() {
        // lea rax, [rip+0x100]  => target = next_ip + 0x100
        let items = decode(&[0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00], 0x1000, 1);
        assert_eq!(items[0].memory_target, Some(0x1000 + 7 + 0x100));
    }

    #[test]
    fn invalid_bytes_resynchronize_and_truncation_is_dropped() {
        // 0x06 is invalid in 64-bit mode; the following nop must still decode.
        let items = decode(&[0x06, 0x90], 0x2000, 8);
        assert!(!items[0].valid);
        assert_eq!(items[0].length, 1);
        assert_eq!(items[1].text, "nop");
        assert_eq!(items[1].address, 0x2001);
        // A truncated call has no complete instruction and yields nothing.
        assert!(decode(&[0xe8, 0x10], 0x3000, 8).iter().all(|item| !item.valid));
    }

    #[test]
    fn step_over_runs_to_next_instruction_only_for_calls_and_rep_strings() {
        assert_eq!(
            step_over_plan(&CODE[4..], 0x401004).unwrap(),
            StepPlan::RunTo(0x401009)
        );
        assert_eq!(step_over_plan(&CODE[9..], 0x401009).unwrap(), StepPlan::Single);
        // rep movsb
        assert_eq!(
            step_over_plan(&[0xf3, 0xa4], 0x5000).unwrap(),
            StepPlan::RunTo(0x5002)
        );
        // call qword ptr [rax]
        assert_eq!(
            step_over_plan(&[0xff, 0x10], 0x5000).unwrap(),
            StepPlan::RunTo(0x5002)
        );
        assert!(step_over_plan(&[0x06], 0x5000).is_err());
    }

    #[test]
    fn return_and_prologue_detection() {
        assert!(is_return(&[0xc3], 0));
        assert!(!is_return(&[0x90], 0));
        assert!(has_frame_prologue(CODE, 0));
        assert!(has_frame_prologue(
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5],
            0
        ));
        assert!(!has_frame_prologue(&[0x48, 0x83, 0xec, 0x20], 0));
    }
}
