//! Bounded sparse memory capture, usable by all mapped engine readers offline.
use crate::{Result, tools::ToolRegistry};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
pub fn dispatch(registry: &mut ToolRegistry, name: &str, args: &Value) -> Option<Result<Value>> {
    if name == "module_capture" {
        return Some(capture_module(registry, args));
    }
    if name != "memory_image_capture" {
        return None;
    }
    Some((|| {
        let wb = &mut registry.workbench;
        let pid = args["pid"].as_u64().context("Missing pid")? as u32;
        let module = args["module"].as_str().unwrap_or("eboot.bin");
        let maps = wb.debugger.maps(pid)?;
        let maps = maps.as_array().context("Invalid maps")?;
        let matching = |name: &str| {
            name == module || name == "executable" || name.ends_with(&format!("/{module}"))
        };
        let base = maps
            .iter()
            .filter(|m| matching(m["name"].as_str().unwrap_or("")))
            .filter_map(|m| m["start"].as_u64())
            .min()
            .context("No module mappings")?;
        let budget = (args["max_bytes"]
            .as_u64()
            .unwrap_or(wb.profile.limit("transfer_bytes") as u64) as usize)
            .min(wb.profile.limit("transfer_bytes"))
            .min(crate::bytesource::ARTIFACT_MAX);
        let mut ranges = Vec::new();
        if let Some(explicit) = args["ranges"].as_array() {
            for range in explicit {
                let start = crate::tools::address(&range["address"])?;
                let length = range["length"].as_u64().context("Missing range length")?;
                let end = start.checked_add(length).context("Range overflow")?;
                ensure!(length > 0, "Empty capture range");
                let map = maps
                    .iter()
                    .find(|m| {
                        m["start"].as_u64().is_some_and(|s| s <= start)
                            && m["end"].as_u64().is_some_and(|e| e >= end)
                            && m["protection"].as_u64().unwrap_or(0) & 1 != 0
                    })
                    .context("Capture range is not contained in a readable mapping")?;
                ranges.push((start, end, map));
            }
        } else {
            for map in maps.iter().filter(|m| {
                matching(m["name"].as_str().unwrap_or(""))
                    && m["protection"].as_u64().unwrap_or(0) & 1 != 0
            }) {
                ranges.push((
                    map["start"].as_u64().context("Invalid start")?,
                    map["end"].as_u64().context("Invalid end")?,
                    map,
                ));
            }
        }
        ranges.sort_by_key(|r| r.0);
        let mut previous = 0;
        for (start, end, _) in &ranges {
            ensure!(
                *start >= previous && end > start,
                "Overlapping/invalid capture ranges"
            );
            previous = *end;
        }
        let mut used = 0;
        let mut regions = Vec::new();
        let mut missing = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        for (start, end, map) in ranges {
            let mut at = start;
            while at < end {
                if used >= budget
                    || regions.len() >= 16384
                    || crate::sessions::cancelled()
                    || std::time::Instant::now() >= deadline
                {
                    missing.push(json!({"address":format!("{at:#x}"),"length":end-at,"reason":"budget, deadline or cancellation"}));
                    break;
                }
                let length = ((end - at) as usize)
                    .min(wb.profile.limit("memory_bytes"))
                    .min(budget - used);
                // Charge attempted reads too, so bad pages cannot bypass budgets.
                used += length;
                match wb.debugger.read_memory(pid,at,length,false) {
                    Ok(bytes) if bytes.len()==length=>{
                        let saved=wb.store.save("memory-image-region",&bytes,json!({"pid":pid,"address":format!("{at:#x}"),"module":module}),"bin")?;
                        regions.push(json!({"address":format!("{at:#x}"),"artifact":saved,"protection":map["protection"],"name":map["name"],"selected":matching(map["name"].as_str().unwrap_or(""))}));
                    },
                    result=>missing.push(json!({"address":format!("{at:#x}"),"length":length,"reason":result.err().map(|e|e.to_string()).unwrap_or_else(||"short read".into())})),
                }
                at += length as u64;
            }
        }
        let document = json!({"format":"ps4wb-memory-image-v1","pid":pid,"module":module,"image_base":format!("{base:#x}"),"regions":regions,"missing":missing,"atomic":false,"hardware_verified":false});
        let saved = wb.store.save(
            "memory-image",
            &serde_json::to_vec_pretty(&document)?,
            json!({"tool":name,"pid":pid,"module":module}),
            "json",
        )?;
        Ok(
            json!({"artifact":saved,"regions":regions.len(),"missing":missing.len(),"bytes_attempted":used,"complete":missing.is_empty()}),
        )
    })())
}

fn capture_module(registry: &mut ToolRegistry, args: &Value) -> Result<Value> {
    let wb = &mut registry.workbench;
    let pid = args["pid"].as_u64().context("Missing pid")? as u32;
    let module = args["module"].as_str().unwrap_or("eboot.bin");
    match wb.memory_elf_dump(pid, Some(module), None) {
        Ok(result) => {
            ensure!(
                result["partial_or_unmapped_chunks"] == 0,
                "Captured ELF is incomplete; use explicit sparse capture for diagnostics"
            );
            return Ok(result);
        }
        Err(error) => ensure!(
            error
                .to_string()
                .contains("does not begin with an ELF magic"),
            "Module capture failed: {error:#}"
        ),
    }
    // Some games do not map their ELF headers. Preserve the observed mappings
    // in a new ELF container rather than guessing missing original headers.
    let maps = wb.debugger.maps(pid)?;
    let mut ranges: Vec<_> = maps
        .as_array()
        .context("Invalid maps")?
        .iter()
        .filter(|m| {
            let name = m["name"].as_str().unwrap_or("");
            (name == module || name == "executable" || name.ends_with(&format!("/{module}")))
                && m["protection"].as_u64().unwrap_or(0) & 1 != 0
        })
        .collect();
    ranges.sort_by_key(|m| m["start"].as_u64());
    ensure!(
        !ranges.is_empty() && ranges.len() <= 128,
        "Module needs 1-128 readable mappings"
    );
    let base = ranges[0]["start"].as_u64().context("Invalid base")?;
    let mut image = vec![0u8; 0x1000];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    image[7] = 9;
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&(ranges.len() as u16).to_le_bytes());
    if 64 + ranges.len() * 56 > image.len() {
        image.resize((64 + ranges.len() * 56 + 4095) & !4095, 0);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let budget = wb
        .profile
        .limit("transfer_bytes")
        .saturating_sub(4096)
        .min(crate::bytesource::ARTIFACT_MAX);
    let mut previous = 0;
    for (index, map) in ranges.iter().enumerate() {
        let start = map["start"].as_u64().context("Invalid start")?;
        let end = map["end"].as_u64().context("Invalid end")?;
        ensure!(
            end > start && start >= previous,
            "Invalid/overlapping module maps"
        );
        previous = end;
        let length = usize::try_from(end - start)?;
        let offset = (image.len() + 4095) & !4095;
        ensure!(
            offset.checked_add(length).is_some_and(|n| n <= budget),
            "Module maps exceed capture budget; select explicit sparse ranges instead"
        );
        image.resize(offset, 0);
        let protection = map["protection"].as_u64().unwrap_or(0);
        let flags = ((protection & 1) << 2) | (protection & 2) | ((protection & 4) >> 2);
        let header = 64 + index * 56;
        image[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        image[header + 4..header + 8].copy_from_slice(&(flags as u32).to_le_bytes());
        for (at, value) in [
            (8, offset as u64),
            (16, start),
            (24, start),
            (32, length as u64),
            (40, length as u64),
            (48, 4096),
        ] {
            image[header + at..header + at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut cursor = start;
        while cursor < end {
            ensure!(
                !crate::sessions::cancelled() && std::time::Instant::now() < deadline,
                "Module capture cancelled or timed out"
            );
            let count = ((end - cursor) as usize).min(wb.profile.limit("memory_bytes"));
            let bytes = wb.debugger.read_memory(pid, cursor, count, false)?;
            ensure!(
                bytes.len() == count,
                "Incomplete module capture; no bytes synthesized"
            );
            image.extend_from_slice(&bytes);
            cursor += count as u64;
        }
    }
    let saved=wb.store.save("elfdump",&image,json!({"tool":"module_capture","module":module,"pid":pid,"runtime_base":format!("{base:#x}"),"format":"synthetic_mapping_elf","original_elf_headers_available":false}),"elf")?;
    Ok(
        json!({"artifact":saved,"module":module,"runtime_base":format!("{base:#x}"),"static_base":format!("{base:#x}"),"partial_or_unmapped_chunks":0,"original_elf_headers_available":false,"note":"Observed mapped bytes in a synthetic ELF container; original symbols/dynamic metadata were not invented"}),
    )
}
