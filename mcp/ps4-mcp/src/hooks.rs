//! Local x86-64 detour planning. Execution stays in the qualified payload.
use crate::{
    Result,
    tools::{ToolRegistry, address, string},
};
use anyhow::{Context, ensure};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, InstructionBlock};
use serde_json::{Value, json};

fn jump(target: u64) -> Vec<u8> {
    let mut bytes = vec![0xff, 0x25, 0, 0, 0, 0];
    bytes.extend_from_slice(&target.to_le_bytes());
    bytes
}
pub fn plan(bytes: &[u8], target: u64, detour: u64, trampoline: u64) -> Result<Value> {
    ensure!(
        target != 0 && detour != 0 && trampoline != 0,
        "Hook addresses must be nonzero"
    );
    let mut decoder = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut length = 0;
    while length < 14 {
        ensure!(decoder.can_decode(), "Insufficient hook bytes");
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid()
                && !matches!(
                    instruction.flow_control(),
                    iced_x86::FlowControl::Return | iced_x86::FlowControl::Exception
                ),
            "Hook prefix contains invalid/terminal instruction"
        );
        length += instruction.len();
        instructions.push(instruction);
        ensure!(length <= 128, "Hook prefix too large");
    }
    let end = target
        .checked_add(length as u64)
        .context("Hook address overflow")?;
    for instruction in &instructions {
        if instruction.is_ip_rel_memory_operand() {
            let referenced = instruction.ip_rel_memory_address();
            ensure!(
                referenced < target || referenced >= end,
                "RIP-relative data references overwritten hook bytes"
            );
        }
    }
    // Include the return branch in the encoded block so far-branch pointer data
    // is placed after it, never on the fall-through execution path.
    instructions.push(iced_x86::Instruction::with_branch(
        iced_x86::Code::Jmp_rel32_64,
        end,
    )?);
    let relocated = BlockEncoder::encode(
        64,
        InstructionBlock::new(&instructions, trampoline),
        BlockEncoderOptions::NONE,
    )
    .map_err(|e| anyhow::anyhow!("Cannot relocate hook: {e}"))?
    .code_buffer;
    ensure!(relocated.len() <= 1024, "Trampoline exceeds 1024 bytes");
    let trampoline_end=trampoline.checked_add(relocated.len() as u64).context("Trampoline address overflow")?;
    ensure!(trampoline >= end || trampoline_end <= target,"Trampoline overlaps overwritten target instructions");
    ensure!(detour < target || detour >= end,"Detour points inside overwritten target instructions");
    let mut replacement = jump(detour);
    replacement.resize(length, 0x90);
    Ok(
        json!({"format":"ps4wb-hook-v1","target":format!("{target:#x}"),"detour":format!("{detour:#x}"),"trampoline":format!("{trampoline:#x}"),"expected":hex::encode(&bytes[..length]),"replacement":hex::encode(replacement),"relocated":hex::encode(relocated),"overwritten":length,"requires_quiescence":true,"hardware_verified":false}),
    )
}
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if name != "hook_plan" {
        return None;
    }
    Some((|| {
        let path = string(args, "artifact")?;
        let bytes = registry
            .workbench
            .read_artifact(path, crate::bytesource::ARTIFACT_MAX)?;
        let image = if bytes.starts_with(b"\x7fELF") {
            crate::binimage::Image::from_elf(&bytes, None)?
        } else {
            crate::binimage::Image::from_raw(
                args["base"]
                    .as_str()
                    .map(|s| address(&json!(s)))
                    .transpose()?
                    .unwrap_or(0),
                bytes,
                None,
            )
        };
        let target = address(&args["address"])?;
        ensure!(image.is_exec(target), "Hook target is not executable");
        let document = plan(
            image
                .bytes_from(target)
                .context("Hook target is not file-backed")?,
            target,
            address(&args["detour"])?,
            address(&args["trampoline"])?,
        )?;
        let artifact = registry.workbench.store.save(
            "hook-plan",
            &serde_json::to_vec_pretty(&document)?,
            json!({"source":path,"module_sha256":image.sha256}),
            "json",
        )?;
        Ok(json!({"artifact":artifact,"plan":document}))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relocates_rip_relative_code_and_checks_owned_restoration() {
        let mut bytes = vec![0x90; 64];
        bytes[..7].copy_from_slice(&[0x48, 0x8b, 0x05, 0x19, 0, 0, 0]);
        let plan = plan(&bytes, 0x400000, 0x500000, 0x410000).unwrap();
        let relocated = hex::decode(plan["relocated"].as_str().unwrap()).unwrap();
        let instruction = Decoder::with_ip(64, &relocated, 0x410000, DecoderOptions::NONE).decode();
        assert_eq!(instruction.ip_rel_memory_address(), 0x400020);
        assert!(super::plan(&[0xc3; 64], 0x400000, 0x500000, 0x410000).is_err());
        assert!(
            super::plan(
                &[
                    0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
                ],
                0x400000,
                0x500000,
                0x410000
            )
            .is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::compile_run(
            dir.path(),
            include_str!("../tests/fixtures/hook_smoke.cpp"),
            true,
        );
    }
}
