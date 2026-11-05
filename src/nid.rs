//! Sony PS4 / Orbis OS NID (Name Identifier) hashing and symbol resolution.
//!
//! Orbis dynamic linking replaces exported C/C++ symbol names in `.dynsym` with
//! 11-character NID strings (often formatted as `<11-char-nid>#<lib>#<mod>`).
//!
//! Algorithm:
//! 1. Compute `SHA-1(symbol_bytes || ORBIS_NID_SUFFIX)` where `ORBIS_NID_SUFFIX`
//!    is `518D64A635DED8C1E6B039B1C3E55230` (16 bytes).
//! 2. Take the first 8 bytes of the digest in little-endian byte order as a
//!    64-bit integer, or equivalently reverse bytes `[0..8]` into big-endian
//!    order `[d7, d6, d5, d4, d3, d2, d1, d0]` with a trailing `0x00` pad byte,
//!    encode 9 bytes -> 12 Base64 chars using alphabet
//!    `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`, drop
//!    the 12th char, and replace `/` with `-` (note: `+` stays `+`).

use crate::Result;
use anyhow::{bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Sony Orbis NID salt appended to symbol names before SHA-1.
pub const ORBIS_NID_SUFFIX: [u8; 16] = [
    0x51, 0x8d, 0x64, 0xa6, 0x35, 0xde, 0xd8, 0xc1,
    0xe6, 0xb0, 0x39, 0xb1, 0xc3, 0xe5, 0x52, 0x30,
];

const NID_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

/// Minimal pure-Rust RFC 3174 SHA-1 implementation (avoids adding external crates).
fn sha1(chunks: &[&[u8]]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    let total_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut msg = Vec::with_capacity(total_len + 72);
    for chunk in chunks {
        msg.extend_from_slice(chunk);
    }
    let bit_len = (total_len as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Compute the 11-character Orbis NID for `symbol`.
pub fn encode_nid(symbol: &str) -> String {
    let digest = sha1(&[symbol.as_bytes(), &ORBIS_NID_SUFFIX]);
    let raw = [
        digest[7], digest[6], digest[5], digest[4],
        digest[3], digest[2], digest[1], digest[0], 0u8,
    ];
    let mut out = Vec::with_capacity(12);
    for group in raw.chunks_exact(3) {
        let triple = ((group[0] as u32) << 16) | ((group[1] as u32) << 8) | (group[2] as u32);
        out.push(NID_ALPHABET[((triple >> 18) & 0x3f) as usize]);
        out.push(NID_ALPHABET[((triple >> 12) & 0x3f) as usize]);
        out.push(NID_ALPHABET[((triple >> 6) & 0x3f) as usize]);
        out.push(NID_ALPHABET[(triple & 0x3f) as usize]);
    }
    out.truncate(11);
    String::from_utf8(out).expect("ASCII NID alphabet")
}

/// Curated Orbis OS symbol corpus covering common `libkernel`, `libSce*`,
/// `libc`, pthread, memory, file I/O, pad, video, audio, network, and sysmodule APIs.
const BUILTIN_SYMBOLS: &[&str] = &[
    // libkernel: memory, modules, files, time, syscalls
    "sceKernelAllocateDirectMemory",
    "sceKernelAllocateMainDirectMemory",
    "sceKernelAvailableDirectMemorySize",
    "sceKernelCheckedReleaseDirectMemory",
    "sceKernelDirectMemoryQuery",
    "sceKernelGetDirectMemorySize",
    "sceKernelGetDirectMemoryType",
    "sceKernelMapDirectMemory",
    "sceKernelMapFlexibleMemory",
    "sceKernelMapNamedDirectMemory",
    "sceKernelMapNamedFlexibleMemory",
    "sceKernelMapNamedSystemFlexibleMemory",
    "sceKernelMunmap",
    "sceKernelMprotect",
    "sceKernelMsync",
    "sceKernelQueryMemoryProtection",
    "sceKernelReleaseDirectMemory",
    "sceKernelReleaseFlexibleMemory",
    "sceKernelReserveVirtualRange",
    "sceKernelBatchMap",
    "sceKernelBatchMap2",
    "sceKernelSetVirtualRangeName",
    "sceKernelLoadStartModule",
    "sceKernelStopUnloadModule",
    "sceKernelDlsym",
    "sceKernelGetModuleInfo",
    "sceKernelGetModuleInfoForUnwind",
    "sceKernelGetModuleInfoFromAddr",
    "sceKernelGetModuleList",
    "sceKernelGetProcParam",
    "sceKernelIsNeoMode",
    "sceKernelGetCpuTemperature",
    "sceKernelGetSocSensorTemperature",
    "sceKernelGetSystemSwVersion",
    "sceKernelUsleep",
    "sceKernelSleep",
    "sceKernelNanosleep",
    "sceKernelReadTsc",
    "sceKernelGetTscFrequency",
    "sceKernelGetProcessTime",
    "sceKernelGetProcessTimeCounter",
    "sceKernelGetProcessTimeCounterFrequency",
    "sceKernelClockGettime",
    "sceKernelGettimeofday",
    "sceKernelOpen",
    "sceKernelClose",
    "sceKernelRead",
    "sceKernelWrite",
    "sceKernelPread",
    "sceKernelPwrite",
    "sceKernelLseek",
    "sceKernelStat",
    "sceKernelFstat",
    "sceKernelMkdir",
    "sceKernelRmdir",
    "sceKernelUnlink",
    "sceKernelRename",
    "sceKernelFsync",
    "sceKernelFtruncate",
    "sceKernelGetdents",
    "sceKernelGetdirentries",
    "sceKernelCreateEqueue",
    "sceKernelDeleteEqueue",
    "sceKernelWaitEqueue",
    "sceKernelAddUserEvent",
    "sceKernelTriggerUserEvent",
    "sceKernelDeleteUserEvent",
    "sceKernelCreateEventFlag",
    "sceKernelDeleteEventFlag",
    "sceKernelWaitEventFlag",
    "sceKernelSetEventFlag",
    "sceKernelClearEventFlag",
    "sceKernelCreateSema",
    "sceKernelDeleteSema",
    "sceKernelWaitSema",
    "sceKernelSignalSema",
    "sceKernelNotificationRequest",
    "sceKernelDebugOutText",
    "sceKernelGetCurrentCpu",
    "sceKernelError",
    "__error",
    // scePthread
    "scePthreadCreate",
    "scePthreadExit",
    "scePthreadJoin",
    "scePthreadDetach",
    "scePthreadSelf",
    "scePthreadEqual",
    "scePthreadYield",
    "scePthreadGetname",
    "scePthreadSetname",
    "scePthreadGetprio",
    "scePthreadSetprio",
    "scePthreadSetaffinity",
    "scePthreadGetaffinity",
    "scePthreadMutexInit",
    "scePthreadMutexDestroy",
    "scePthreadMutexLock",
    "scePthreadMutexTrylock",
    "scePthreadMutexUnlock",
    "scePthreadCondInit",
    "scePthreadCondDestroy",
    "scePthreadCondWait",
    "scePthreadCondTimedwait",
    "scePthreadCondSignal",
    "scePthreadCondBroadcast",
    "scePthreadRwlockInit",
    "scePthreadRwlockDestroy",
    "scePthreadRwlockRdlock",
    "scePthreadRwlockWrlock",
    "scePthreadRwlockUnlock",
    "scePthreadKeyCreate",
    "scePthreadKeyDelete",
    "scePthreadGetspecific",
    "scePthreadSetspecific",
    "scePthreadOnce",
    // libSceVideoOut / libSceGnmDriver
    "sceVideoOutOpen",
    "sceVideoOutClose",
    "sceVideoOutRegisterBuffers",
    "sceVideoOutSubmitFlip",
    "sceVideoOutSetFlipRate",
    "sceVideoOutGetFlipStatus",
    "sceVideoOutGetResolutionStatus",
    "sceVideoOutAddFlipEvent",
    "sceVideoOutWaitVblank",
    "sceGnmSubmitCommandBuffers",
    "sceGnmSubmitAndFlipCommandBuffers",
    "sceGnmSubmitDone",
    "sceGnmFlushGarlic",
    "sceGnmMapComputeQueue",
    "sceGnmUnmapComputeQueue",
    "sceGnmDingDong",
    // libScePad / libSceUserService / libSceSystemService / libSceSysmodule
    "scePadInit",
    "scePadOpen",
    "scePadClose",
    "scePadRead",
    "scePadReadState",
    "scePadSetLightBar",
    "scePadResetLightBar",
    "scePadSetVibration",
    "sceUserServiceInitialize",
    "sceUserServiceTerminate",
    "sceUserServiceGetInitialUser",
    "sceUserServiceGetLoginUserIdList",
    "sceUserServiceGetUserName",
    "sceSystemServiceHideSplashScreen",
    "sceSystemServiceGetStatus",
    "sceSystemServiceReceiveEvent",
    "sceSystemServiceLoadExec",
    "sceSysmoduleLoadModule",
    "sceSysmoduleUnloadModule",
    "sceSysmoduleIsLoaded",
    "sceSysmoduleLoadModuleInternal",
    "sceSysmoduleUnloadModuleInternal",
    // libSceAudioOut
    "sceAudioOutInit",
    "sceAudioOutOpen",
    "sceAudioOutClose",
    "sceAudioOutOutput",
    "sceAudioOutSetVolume",
    // libSceNet / libSceHttp / libSceSsl
    "sceNetInit",
    "sceNetTerm",
    "sceNetPoolCreate",
    "sceNetPoolDestroy",
    "sceNetSocket",
    "sceNetSocketClose",
    "sceNetBind",
    "sceNetListen",
    "sceNetAccept",
    "sceNetConnect",
    "sceNetSend",
    "sceNetRecv",
    "sceNetSendto",
    "sceNetRecvfrom",
    "sceNetSetsockopt",
    "sceNetGetsockopt",
    "sceNetInetPton",
    "sceNetInetNtop",
    "sceNetHtons",
    "sceNetHtonl",
    "sceHttpInit",
    "sceHttpTerm",
    "sceSslInit",
    "sceSslTerm",
    // libSceSaveData / libSceAppContent
    "sceSaveDataInitialize3",
    "sceSaveDataMount2",
    "sceSaveDataUmount",
    "sceAppContentInitialize",
    "sceAppContentAppParamGetInt",
    // Standard C / POSIX exports often NID-encoded in libSceLibcInternal / libkernel
    "malloc",
    "calloc",
    "realloc",
    "free",
    "posix_memalign",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strcat",
    "strstr",
    "strchr",
    "snprintf",
    "vsnprintf",
    "printf",
    "fprintf",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "fflush",
    "open",
    "close",
    "read",
    "write",
    "lseek",
    "mmap",
    "munmap",
    "mprotect",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "recv",
    "exit",
    "_exit",
    "abort",
    "getenv",
    "qsort",
    "bsearch",
];

static BUILTIN_MAP: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::with_capacity(BUILTIN_SYMBOLS.len());
    for &symbol in BUILTIN_SYMBOLS {
        map.insert(encode_nid(symbol), symbol);
    }
    map
});

pub fn is_valid_nid_prefix(candidate: &str) -> bool {
    candidate.len() == 11
        && candidate.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'-'
        })
}

/// Extract `(11-char-nid, optional_lib_tag, optional_mod_tag)` from an Orbis
/// `.dynsym` name such as `"1jfXLRVzisc#A#B"` or bare `"1jfXLRVzisc"`.
pub fn split_orbis_symbol(raw: &str) -> Option<(&str, Option<&str>, Option<&str>)> {
    if let Some((nid, rest)) = raw.split_once('#') {
        if is_valid_nid_prefix(nid) {
            let (lib, module) = match rest.split_once('#') {
                Some((l, m)) => (Some(l), Some(m)),
                None => (Some(rest), None),
            };
            return Some((nid, lib, module));
        }
        return None;
    }
    if is_valid_nid_prefix(raw) {
        Some((raw, None, None))
    } else {
        None
    }
}

/// Resolve a bare 11-char NID or `NID#lib#mod` string using the built-in table
/// and an optional caller-provided custom map (`nid -> symbol`).
pub fn lookup_nid<'a>(
    raw: &str,
    custom: Option<&'a HashMap<String, String>>,
) -> Option<&'a str> {
    let (nid, _, _) = split_orbis_symbol(raw)?;
    if let Some(map) = custom
        && let Some(found) = map.get(nid)
    {
        return Some(found.as_str());
    }
    BUILTIN_MAP.get(nid).copied()
}

/// Parse a custom dictionary artifact (either a JSON object `{"nid": "symbol"}`
/// or `{"symbols": ["sym1", ...]}`, a JSON array of symbol names, or line-based
/// `<nid> <symbol>` / `<symbol>` text). Bounded to 200_000 entries.
pub fn parse_dictionary(data: &[u8]) -> Result<HashMap<String, String>> {
    ensure!(data.len() <= 16 * 1024 * 1024, "NID dictionary exceeds 16 MiB");
    let text = std::str::from_utf8(data)
        .map_err(|_| anyhow::anyhow!("NID dictionary must be valid UTF-8"))?;
    let trimmed = text.trim();
    let mut out = HashMap::new();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let parsed: Value = serde_json::from_str(trimmed)?;
        match parsed {
            Value::Array(items) => {
                ensure!(items.len() <= 200_000, "Dictionary exceeds 200000 symbols");
                for item in items {
                    if let Some(sym) = item.as_str()
                        && !sym.is_empty()
                        && sym.len() <= 512
                    {
                        out.insert(encode_nid(sym), sym.to_owned());
                    }
                }
            }
            Value::Object(fields) => {
                if let Some(Value::Array(items)) = fields.get("symbols") {
                    ensure!(items.len() <= 200_000, "Dictionary exceeds 200000 symbols");
                    for item in items {
                        if let Some(sym) = item.as_str()
                            && !sym.is_empty()
                            && sym.len() <= 512
                        {
                            out.insert(encode_nid(sym), sym.to_owned());
                        }
                    }
                } else {
                    ensure!(fields.len() <= 200_000, "Dictionary exceeds 200000 entries");
                    for (key, value) in fields {
                        if let Some(val_str) = value.as_str() {
                            if is_valid_nid_prefix(&key) && val_str.len() <= 512 {
                                out.insert(key, val_str.to_owned());
                            } else if is_valid_nid_prefix(val_str) && key.len() <= 512 {
                                out.insert(val_str.to_owned(), key);
                            }
                        }
                    }
                }
            }
            _ => bail!("Unsupported JSON NID dictionary layout"),
        }
        return Ok(out);
    }

    for (count, line) in trimmed.lines().enumerate() {
        ensure!(count < 200_000, "Dictionary exceeds 200000 lines");
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let first = parts.next().unwrap_or("");
        if let Some(second) = parts.next() {
            if is_valid_nid_prefix(first) && second.len() <= 512 {
                out.insert(first.to_owned(), second.to_owned());
                continue;
            }
            if is_valid_nid_prefix(second) && first.len() <= 512 {
                out.insert(second.to_owned(), first.to_owned());
                continue;
            }
        }
        if first.len() <= 512 {
            out.insert(encode_nid(first), first.to_owned());
        }
    }
    Ok(out)
}

/// Batch NID computation + reverse lookup for the `nid_resolve` tool.
pub fn resolve_batch(
    symbols: &[String],
    nids: &[String],
    custom: Option<&HashMap<String, String>>,
) -> Result<Value> {
    ensure!(
        symbols.len() <= 1024 && nids.len() <= 1024,
        "Supply at most 1024 symbols and 1024 NIDs per call"
    );
    ensure!(
        !symbols.is_empty() || !nids.is_empty(),
        "Provide at least one entry in symbols or nids"
    );
    let mut encoded = Vec::with_capacity(symbols.len());
    for sym in symbols {
        ensure!(!sym.is_empty() && sym.len() <= 512, "Symbol length must be 1..=512");
        encoded.push(json!({
            "symbol": sym,
            "nid": encode_nid(sym),
        }));
    }
    let mut decoded = Vec::with_capacity(nids.len());
    let mut resolved_count = 0usize;
    for raw in nids {
        ensure!(!raw.is_empty() && raw.len() <= 512, "NID query length must be 1..=512");
        let (nid, lib, module) = match split_orbis_symbol(raw) {
            Some(parts) => parts,
            None => bail!("Invalid Orbis NID or symbol format: {raw}"),
        };
        let symbol = lookup_nid(nid, custom);
        if symbol.is_some() {
            resolved_count += 1;
        }
        let source = if custom.is_some_and(|m| m.contains_key(nid)) {
            "custom_dictionary"
        } else if symbol.is_some() {
            "builtin_dictionary"
        } else {
            "unresolved"
        };
        decoded.push(json!({
            "input": raw,
            "nid": nid,
            "library_tag": lib,
            "module_tag": module,
            "symbol": symbol,
            "source": source,
        }));
    }
    Ok(json!({
        "encoded": encoded,
        "decoded": decoded,
        "resolved_count": resolved_count,
        "builtin_dictionary_size": BUILTIN_MAP.len(),
        "custom_dictionary_size": custom.map_or(0, HashMap::len),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_orbis_nid_vectors_match() {
        assert_eq!(encode_nid("sceKernelUsleep"), "1jfXLRVzisc");
        assert_eq!(encode_nid("sceKernelReadTsc"), "-2IRUCO--PM");
        assert_eq!(encode_nid("sceVideoOutOpen"), "Up36PTk687E");
        assert_eq!(encode_nid("scePadRead"), "q1cHNfGycLI");
        assert_eq!(encode_nid("sceKernelAllocateDirectMemory"), "rTXw65xmLIA");
    }

    #[test]
    fn lookup_and_custom_dictionary_formats() {
        assert_eq!(
            lookup_nid("1jfXLRVzisc#libkernel#libkernel", None),
            Some("sceKernelUsleep")
        );
        assert_eq!(lookup_nid("-2IRUCO--PM", None), Some("sceKernelReadTsc"));

        let dict = parse_dictionary(br#"{"symbols": ["myCustomOrbisExport"]}"#).unwrap();
        let nid = encode_nid("myCustomOrbisExport");
        let result = resolve_batch(
            &["scePadRead".to_owned()],
            &[format!("{nid}#A#B"), "AAAAAAAAAAA".to_owned()],
            Some(&dict),
        )
        .unwrap();
        assert_eq!(result["encoded"][0]["nid"], "q1cHNfGycLI");
        assert_eq!(result["decoded"][0]["symbol"], "myCustomOrbisExport");
        assert_eq!(result["decoded"][0]["source"], "custom_dictionary");
        assert_eq!(result["decoded"][1]["symbol"], Value::Null);
        assert_eq!(result["resolved_count"], 1);
    }
}
