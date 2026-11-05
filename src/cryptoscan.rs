//! FindCrypt-style detection of cryptographic / compression constants.
//!
//! Every table is *generated* from its defining algorithm rather than typed in:
//! AES tables from GF(2^8) arithmetic (FIPS-197 §5.1.1, OpenSSL `aes_core.c`
//! Te/Td layout), SHA-1/SHA-2 constants from integer square/cube roots of
//! primes (FIPS 180-4 §4.2, §5.3), MD5 T[i] = floor(|sin(i+1)|·2^32)
//! (RFC 1321 §3.4), CRC-32 tables from their polynomials, Blowfish P/S init
//! from the hexadecimal digits of π (Schneier 1993) via the BBP formula, and
//! the DEFLATE length/distance bases from RFC 1951 §3.2.5. Unit tests pin the
//! generated values against well-known first entries.
use crate::{
    Result,
    bytesource::{Mode, Source, TargetSpec},
    workbench::Workbench,
};
use aho_corasick::AhoCorasick;
use anyhow::ensure;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const PREFIX: usize = 32;
const SPARSE_WINDOW: usize = 4096;

struct Signature {
    algorithm: &'static str,
    name: String,
    /// Element width in bytes (1, 2, 4, 8).
    width: usize,
    values: Vec<u64>,
    /// Generic constants that also occur outside crypto code.
    weak: bool,
    /// Match the elements individually within a window (immediates in code).
    sparse: bool,
}

struct Encoded {
    signature: usize,
    encoding: &'static str,
    bytes: Vec<u8>,
}

// ---- generators -------------------------------------------------------------

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

pub fn aes_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for (x, slot) in sbox.iter_mut().enumerate() {
        // Multiplicative inverse as x^254 (0 maps to 0).
        let mut inverse = 1u8;
        for _ in 0..254 {
            inverse = gf_mul(inverse, x as u8);
        }
        if x == 0 {
            inverse = 0;
        }
        let b = inverse;
        *slot = b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
    }
    sbox
}

fn aes_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];
    for (x, s) in sbox.iter().enumerate() {
        inverse[*s as usize] = x as u8;
    }
    inverse
}

fn word(bytes: [u8; 4]) -> u64 {
    u32::from_be_bytes(bytes) as u64
}

pub fn aes_te0() -> Vec<u64> {
    aes_sbox().iter().map(|s| word([gf_mul(*s, 2), *s, *s, gf_mul(*s, 3)])).collect()
}

pub fn aes_td0() -> Vec<u64> {
    aes_inv_sbox(&aes_sbox())
        .iter()
        .map(|s| word([gf_mul(*s, 0x0e), gf_mul(*s, 0x09), gf_mul(*s, 0x0d), gf_mul(*s, 0x0b)]))
        .collect()
}

fn rotr(table: &[u64], bits: u32) -> Vec<u64> {
    table.iter().map(|v| (*v as u32).rotate_right(bits) as u64).collect()
}

fn primes(count: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut n = 2u64;
    while out.len() < count {
        if (2..n).take_while(|d| d * d <= n).all(|d| !n.is_multiple_of(d)) {
            out.push(n);
        }
        n += 1;
    }
    out
}

fn big_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len() + b.len()];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, y) in b.iter().enumerate() {
            let t = out[i + j] as u128 + (*x as u128) * (*y as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + b.len()] = carry as u64;
    }
    out
}

fn big_le(a: &[u64], b: &[u64]) -> bool {
    let len = a.len().max(b.len());
    for i in (0..len).rev() {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    true
}

/// floor(p^(1/k) · 2^bits), exact (bits ≤ 64, k ∈ {2,3}).
pub fn iroot_scaled(p: u64, k: u32, bits: u32) -> u128 {
    let shift = k * bits;
    let mut target = vec![0u64; (shift / 64) as usize + 2];
    let (limb, offset) = ((shift / 64) as usize, shift % 64);
    target[limb] = p << offset;
    if offset != 0 {
        target[limb + 1] = p >> (64 - offset);
    }
    let mut root = 0u128;
    for bit in (0..bits + 8).rev() {
        let candidate = root | (1u128 << bit);
        let limbs = [candidate as u64, (candidate >> 64) as u64];
        let mut power = limbs.to_vec();
        for _ in 1..k {
            power = big_mul(&power, &limbs);
        }
        if big_le(&power, &target) {
            root = candidate;
        }
    }
    root
}

fn frac64(p: u64, k: u32) -> u64 {
    iroot_scaled(p, k, 64) as u64
}

pub fn sha256_k() -> Vec<u64> {
    primes(64).iter().map(|p| frac64(*p, 3) >> 32).collect()
}
pub fn sha256_init() -> Vec<u64> {
    primes(8).iter().map(|p| frac64(*p, 2) >> 32).collect()
}
fn sha224_init() -> Vec<u64> {
    primes(16)[8..].iter().map(|p| frac64(*p, 2) & 0xffff_ffff).collect()
}
pub fn sha512_k() -> Vec<u64> {
    primes(80).iter().map(|p| frac64(*p, 3)).collect()
}
pub fn sha512_init() -> Vec<u64> {
    primes(8).iter().map(|p| frac64(*p, 2)).collect()
}
fn sha384_init() -> Vec<u64> {
    primes(16)[8..].iter().map(|p| frac64(*p, 2)).collect()
}
pub fn sha1_k() -> Vec<u64> {
    [2u64, 3, 5, 10].iter().map(|n| iroot_scaled(*n, 2, 30) as u64).collect()
}

pub fn md5_t() -> Vec<u64> {
    (1..=64).map(|i: i32| ((i as f64).sin().abs() * 4294967296.0).floor() as u64).collect()
}

pub fn crc32_reflected(poly: u32) -> Vec<u64> {
    (0..256u32)
        .map(|n| {
            let mut c = n;
            for _ in 0..8 {
                c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            }
            c as u64
        })
        .collect()
}

pub fn crc32_normal(poly: u32) -> Vec<u64> {
    (0..256u32)
        .map(|n| {
            let mut c = n << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 { (c << 1) ^ poly } else { c << 1 };
            }
            c as u64
        })
        .collect()
}

fn modpow16(exponent: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let (mut result, mut base, mut e) = (1u64, 16 % modulus, exponent);
    while e > 0 {
        if e & 1 != 0 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        e >>= 1;
    }
    result
}

fn bbp_series(j: u64, n: u64) -> f64 {
    let mut sum = 0.0f64;
    for k in 0..=n {
        let r = 8 * k + j;
        sum += modpow16(n - k, r) as f64 / r as f64;
        sum -= sum.floor();
    }
    let mut k = n + 1;
    loop {
        let term = 16f64.powi(-((k - n) as i32)) / (8 * k + j) as f64;
        if term < 1e-17 {
            break;
        }
        sum += term;
        k += 1;
    }
    sum - sum.floor()
}

/// Hex digit `n` (0-based, after the point) of π via Bailey–Borwein–Plouffe.
pub fn pi_hex_digit(n: u64) -> u8 {
    let x = 4.0 * bbp_series(1, n) - 2.0 * bbp_series(4, n) - bbp_series(5, n) - bbp_series(6, n);
    let frac = x - x.floor();
    (frac * 16.0).floor() as u8
}

/// The first `count` 32-bit words of π's fractional hex expansion (Blowfish init).
pub fn pi_words(count: usize) -> Vec<u64> {
    (0..count)
        .map(|w| (0..8).fold(0u64, |acc, d| (acc << 4) | pi_hex_digit((w * 8 + d) as u64) as u64))
        .collect()
}

fn signatures() -> Vec<Signature> {
    let sig = |algorithm, name: &str, width, values: Vec<u64>| Signature {
        algorithm,
        name: name.to_owned(),
        width,
        values,
        weak: false,
        sparse: false,
    };
    let bytes = |text: &[u8]| text.iter().map(|b| *b as u64).collect::<Vec<_>>();
    let sbox = aes_sbox();
    let te0 = aes_te0();
    let td0 = aes_td0();
    let blowfish = pi_words(18 + 256);
    let mut out = vec![
        sig("AES", "S-box (forward)", 1, sbox.iter().map(|b| *b as u64).collect()),
        sig("AES", "inverse S-box", 1, aes_inv_sbox(&sbox).iter().map(|b| *b as u64).collect()),
        sig("AES", "Te0 table", 4, te0.clone()),
        sig("AES", "Te1 table", 4, rotr(&te0, 8)),
        sig("AES", "Te2 table", 4, rotr(&te0, 16)),
        sig("AES", "Te3 table", 4, rotr(&te0, 24)),
        sig("AES", "Td0 table", 4, td0.clone()),
        sig("AES", "Td1 table", 4, rotr(&td0, 8)),
        sig("AES", "Td2 table", 4, rotr(&td0, 16)),
        sig("AES", "Td3 table", 4, rotr(&td0, 24)),
        sig("AES", "key-schedule rcon (u32, byte in MSB)", 4, [1u64, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36].iter().map(|b| b << 24).collect()),
        sig("SHA-1", "initial state H0..H4", 4, vec![0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]),
        sig("SHA-256", "initial state H0..H7", 4, sha256_init()),
        sig("SHA-224", "initial state H0..H7", 4, sha224_init()),
        sig("SHA-256", "round constants K[0..64]", 4, sha256_k()),
        sig("SHA-512", "initial state H0..H7", 8, sha512_init()),
        sig("SHA-384", "initial state H0..H7", 8, sha384_init()),
        sig("SHA-512", "round constants K[0..80]", 8, sha512_k()),
        sig("MD5", "sine table T[1..64]", 4, md5_t()),
        sig("CRC-32", "table (reflected, poly 0xEDB88320)", 4, crc32_reflected(0xEDB8_8320)),
        sig("CRC-32", "table (normal/MSB-first, poly 0x04C11DB7)", 4, crc32_normal(0x04C1_1DB7)),
        sig("CRC-32C", "table (reflected, poly 0x82F63B78)", 4, crc32_reflected(0x82F6_3B78)),
        sig("Blowfish", "P-array init (pi)", 4, blowfish[..18].to_vec()),
        sig("Blowfish", "S-box 0 init (pi)", 4, blowfish[18..].to_vec()),
        sig("ChaCha/Salsa20", "sigma \"expand 32-byte k\"", 1, bytes(b"expand 32-byte k")),
        sig("ChaCha/Salsa20", "tau \"expand 16-byte k\"", 1, bytes(b"expand 16-byte k")),
        sig("RSA/PKCS#1", "DigestInfo prefix SHA-1", 1, bytes(&[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])),
        sig("RSA/PKCS#1", "DigestInfo prefix SHA-256", 1, bytes(&[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])),
        sig("RSA/PKCS#1", "DigestInfo prefix SHA-512", 1, bytes(&[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40])),
        sig("RSA", "rsaEncryption OID 1.2.840.113549.1.1.1 (DER)", 1, bytes(&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])),
        sig("PEM", "\"-----BEGIN \" armor", 1, bytes(b"-----BEGIN ")),
    ];
    let deflate_length: Vec<u64> = vec![3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    let deflate_distance: Vec<u64> = vec![
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577,
    ];
    let code_order: Vec<u64> = vec![16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    for width in [2usize, 4] {
        out.push(sig("zlib/DEFLATE", "length base table (RFC 1951 3.2.5)", width, deflate_length.clone()));
        out.push(sig("zlib/DEFLATE", "distance base table (RFC 1951 3.2.5)", width, deflate_distance.clone()));
    }
    for width in [1usize, 2] {
        out.push(sig("zlib/DEFLATE", "code-length code order (RFC 1951 3.2.7)", width, code_order.clone()));
    }
    let mut weak = sig("MD5/SHA-1", "initial state A..D (shared prefix)", 4, vec![0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]);
    weak.weak = true;
    out.push(weak);
    let mut sparse = sig("SHA-1", "round constants K0..K3 (immediates)", 4, sha1_k());
    sparse.sparse = true;
    out.push(sparse);
    let mut sparse = sig("SHA-256", "initial state as immediates", 4, sha256_init());
    sparse.sparse = true;
    out.push(sparse);
    let mut sparse = sig("MD5", "T[1..4] as immediates", 4, md5_t()[..4].to_vec());
    sparse.sparse = true;
    out.push(sparse);
    out
}

fn encode(values: &[u64], width: usize, big: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * width);
    for value in values {
        let le = value.to_le_bytes();
        if big {
            out.extend(le[..width].iter().rev());
        } else {
            out.extend(&le[..width]);
        }
    }
    out
}

fn encodings(signatures: &[Signature]) -> Vec<Encoded> {
    let mut out = Vec::new();
    for (index, signature) in signatures.iter().enumerate() {
        if signature.sparse {
            continue;
        }
        if signature.width == 1 {
            out.push(Encoded { signature: index, encoding: "bytes", bytes: encode(&signature.values, 1, false) });
            continue;
        }
        let (le, be) = match signature.width {
            2 => ("u16le", "u16be"),
            4 => ("u32le", "u32be"),
            _ => ("u64le", "u64be"),
        };
        let little = encode(&signature.values, signature.width, false);
        let big = encode(&signature.values, signature.width, true);
        if big != little {
            out.push(Encoded { signature: index, encoding: be, bytes: big });
        }
        out.push(Encoded { signature: index, encoding: le, bytes: little });
    }
    out
}

pub fn scan(source: &mut Source, max_results: usize, min_confidence: &str) -> Result<Value> {
    let signatures = signatures();
    let encoded = encodings(&signatures);
    let automaton = AhoCorasick::new(encoded.iter().map(|e| &e.bytes[..e.bytes.len().min(PREFIX)]))?;
    // Sparse: every element value (LE u32) as its own pattern.
    let mut sparse_patterns: Vec<(usize, usize, [u8; 4])> = Vec::new();
    for (index, signature) in signatures.iter().enumerate().filter(|(_, s)| s.sparse) {
        for (element, value) in signature.values.iter().enumerate() {
            sparse_patterns.push((index, element, (*value as u32).to_le_bytes()));
        }
    }
    let sparse_automaton = AhoCorasick::new(sparse_patterns.iter().map(|p| p.2))?;
    let overlap = encoded.iter().map(|e| e.bytes.len()).max().unwrap_or(0).max(SPARSE_WINDOW);
    let rank = |c: &str| match c {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    };
    let floor = rank(min_confidence);
    let mut findings: Vec<(u64, Value)> = Vec::new();
    let mut seen: HashSet<(usize, &'static str, u64)> = HashSet::new();
    let mut truncated = false;
    let mut hits: Vec<(u64, usize, &'static str, usize, &'static str)> = Vec::new();
    let live = source.is_live();
    source.scan(None, overlap, |va, chunk| {
        for m in automaton.find_overlapping_iter(chunk) {
            let e = &encoded[m.pattern().as_usize()];
            let signature = &signatures[e.signature];
            let available = &chunk[m.start()..];
            let matched_bytes = e.bytes.iter().zip(available).take_while(|(a, b)| a == b).count();
            let matched = matched_bytes / signature.width;
            let total = signature.values.len();
            if live && matched_bytes == available.len() && available.len() < e.bytes.len() {
                // Truncated by the chunk end; the overlapping next chunk sees it whole.
                continue;
            }
            let confidence = if matched == total {
                if signature.weak || e.bytes.len() < 16 { "medium" } else { "high" }
            } else if matched * 2 >= total {
                "medium"
            } else {
                "low"
            };
            if rank(confidence) < floor || !seen.insert((e.signature, e.encoding, va + m.start() as u64)) {
                continue;
            }
            hits.push((va + m.start() as u64, e.signature, e.encoding, matched, confidence));
        }
        // Sparse signatures: all elements within a window.
        let mut positions: HashMap<usize, Vec<Vec<usize>>> = HashMap::new();
        for m in sparse_automaton.find_overlapping_iter(chunk) {
            let (signature, element, _) = sparse_patterns[m.pattern().as_usize()];
            let slots = positions
                .entry(signature)
                .or_insert_with(|| vec![Vec::new(); signatures[signature].values.len()]);
            if slots[element].len() < 4096 {
                slots[element].push(m.start());
            }
        }
        for (signature, slots) in positions {
            if slots.iter().any(Vec::is_empty) {
                continue;
            }
            for &start in &slots[0] {
                let window = start.saturating_sub(SPARSE_WINDOW)..start + SPARSE_WINDOW;
                if slots.iter().all(|list| list.iter().any(|p| window.contains(p))) {
                    if rank("low") >= floor && seen.insert((signature, "u32le-immediates", va + start as u64)) {
                        hits.push((va + start as u64, signature, "u32le-immediates", signatures[signature].values.len(), "low"));
                    }
                    break;
                }
            }
        }
        true
    })?;
    hits.sort_by_key(|h| h.0);
    for (address, signature, encoding, matched, confidence) in hits {
        if findings.len() >= max_results {
            truncated = true;
            break;
        }
        let s = &signatures[signature];
        let mut entry = source.describe(address);
        entry["algorithm"] = json!(s.algorithm);
        entry["constant"] = json!(s.name);
        entry["encoding"] = json!(encoding);
        entry["matched_elements"] = json!(matched);
        entry["total_elements"] = json!(s.values.len());
        entry["confidence"] = json!(confidence);
        findings.push((address, entry));
    }
    let mut by_algorithm: HashMap<String, usize> = HashMap::new();
    for (_, finding) in &findings {
        *by_algorithm.entry(finding["algorithm"].as_str().unwrap_or("").to_owned()).or_default() += 1;
    }
    Ok(json!({
        "findings": findings.into_iter().map(|f| f.1).collect::<Vec<_>>(),
        "by_algorithm": by_algorithm,
        "signatures": signatures.len(),
        "truncated": truncated,
        "notes": [
            "high: complete table/sequence; medium: complete but generic/short constant, or >=50% of a table; low: shorter partial match or immediates found within a 4 KiB window.",
            "Tables are matched in byte form and as little/big-endian 16/32/64-bit words.",
        ],
    }))
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let spec = TargetSpec::from_args(args, "artifact", "module")?;
    ensure!(spec.is_specified(), "Give an artifact or a pid target");
    if spec.pid.is_some() {
        ensure!(spec.module.is_some() || spec.address.is_some(), "Live scans need a module or an address/length range");
    }
    let max_results = args["max_results"].as_u64().unwrap_or(500) as usize;
    let min_confidence = args["min_confidence"].as_str().unwrap_or("low").to_owned();
    let mut source = Source::open(workbench, &spec, Mode::File)?;
    let mut result = scan(&mut source, max_results, &min_confidence)?;
    result["source"] = source.summary();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tables_match_published_values() {
        let sbox = aes_sbox();
        assert_eq!(&sbox[..4], &[0x63, 0x7c, 0x77, 0x7b]);
        assert_eq!(sbox[255], 0x16);
        assert_eq!(aes_inv_sbox(&sbox)[0], 0x52);
        assert_eq!(&aes_te0()[..2], &[0xc66363a5, 0xf87c7c84]);
        assert_eq!(aes_td0()[0], 0x51f4a750);
        assert_eq!(sha256_init()[0], 0x6a09e667);
        assert_eq!(sha256_init()[7], 0x5be0cd19);
        assert_eq!(&sha256_k()[..2], &[0x428a2f98, 0x71374491]);
        assert_eq!(sha256_k()[63], 0xc67178f2);
        assert_eq!(sha224_init()[0], 0xc1059ed8);
        assert_eq!(sha512_init()[0], 0x6a09e667f3bcc908);
        assert_eq!(sha512_k()[0], 0x428a2f98d728ae22);
        assert_eq!(sha512_k()[79], 0x6c44198c4a475817);
        assert_eq!(sha384_init()[0], 0xcbbb9d5dc1059ed8);
        assert_eq!(sha1_k(), vec![0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]);
        let t = md5_t();
        assert_eq!((t[0], t[1], t[63]), (0xd76aa478, 0xe8c7b756, 0xeb86d391));
        assert_eq!(crc32_reflected(0xEDB8_8320)[1], 0x77073096);
        assert_eq!(crc32_reflected(0xEDB8_8320)[255], 0x2d02ef8d);
        assert_eq!(crc32_normal(0x04C1_1DB7)[1], 0x04c11db7);
        let pi = pi_words(19);
        assert_eq!(&pi[..2], &[0x243f6a88, 0x85a308d3]);
        assert_eq!(pi[17], 0x8979fb1b);
        assert_eq!(pi[18], 0xd1310ba6);
    }

    #[test]
    fn finds_tables_in_both_endiannesses() {
        let mut data = vec![0x11u8; 64];
        data.extend(aes_sbox());
        data.extend([0u8; 13]);
        data.extend(encode(&sha256_k(), 4, true));
        data.extend(b"..expand 32-byte k..");
        data.extend(encode(&crc32_reflected(0xEDB8_8320)[..64], 4, false));
        data.extend([0u8; 7]);
        data.extend(encode(&sha512_init(), 8, false));
        let mut source = Source::from_file("t", data);
        let result = scan(&mut source, 100, "low").unwrap();
        let findings = result["findings"].as_array().unwrap();
        let find = |constant: &str, encoding: &str| {
            findings.iter().find(|f| {
                (f["constant"].as_str().unwrap().contains(constant) || f["algorithm"] == constant) && f["encoding"] == encoding
            })
        };
        let sbox = find("S-box (forward)", "bytes").expect("sbox");
        assert_eq!(sbox["offset"], "0x40");
        assert_eq!(sbox["confidence"], "high");
        assert_eq!(find("round constants K[0..64]", "u32be").unwrap()["confidence"], "high");
        assert!(find("expand 32-byte k", "bytes").is_some());
        let crc = find("0xEDB88320", "u32le").unwrap();
        assert_eq!(crc["confidence"], "low");
        assert_eq!(crc["matched_elements"], 64);
        assert_eq!(find("SHA-512", "u64le").map(|f| f["algorithm"].clone()), Some(json!("SHA-512")));
        let high = scan(&mut Source::from_file("t", aes_sbox().to_vec()), 100, "high").unwrap();
        assert_eq!(high["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sparse_immediates() {
        let mut code = Vec::new();
        for k in sha1_k() {
            code.extend([0x8d, 0x84, 0x08]);
            code.extend((k as u32).to_le_bytes());
            code.extend([0x90; 20]);
        }
        let result = scan(&mut Source::from_file("t", code), 10, "low").unwrap();
        let findings = result["findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f["encoding"] == "u32le-immediates" && f["algorithm"] == "SHA-1"));
    }
}
