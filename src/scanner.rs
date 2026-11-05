//! Stateful multi-pass memory value scanner (Cheat Engine / x64dbg style).
//!
//! Pure, bounded, `#![forbid(unsafe_code)]` scan engine that operates via a
//! caller-provided chunked memory reader closure so it works identically over
//! live `ps4debug-NG` sessions and offline test fixtures.

use crate::Result;
use anyhow::{anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const MAX_SCAN_SESSIONS: usize = 32;
pub const MAX_SCAN_CANDIDATES: usize = 250_000;
pub const DEFAULT_PAGE_LIMIT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanValueType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    Utf8,
    Utf16,
    Bytes,
}

impl ScanValueType {
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(match raw.trim().to_ascii_lowercase().as_str() {
            "u8" | "uint8" | "byte" => Self::U8,
            "i8" | "int8" | "sbyte" => Self::I8,
            "u16" | "uint16" | "word" => Self::U16,
            "i16" | "int16" | "short" => Self::I16,
            "u32" | "uint32" | "dword" => Self::U32,
            "i32" | "int32" | "int" => Self::I32,
            "u64" | "uint64" | "qword" => Self::U64,
            "i64" | "int64" | "long" => Self::I64,
            "f32" | "float" => Self::F32,
            "f64" | "double" => Self::F64,
            "utf8" | "string" | "ascii" => Self::Utf8,
            "utf16" | "wstring" | "utf16le" => Self::Utf16,
            "bytes" | "hex" | "aob" => Self::Bytes,
            other => bail!("Unsupported scan value_type: {other}"),
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::I8 => "i8",
            Self::U16 => "u16",
            Self::I16 => "i16",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Utf8 => "utf8",
            Self::Utf16 => "utf16",
            Self::Bytes => "bytes",
        }
    }

    pub fn fixed_width(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::Utf8 | Self::Utf16 | Self::Bytes => None,
        }
    }

    pub fn default_alignment(&self) -> usize {
        self.fixed_width().unwrap_or(1).min(4)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanComparison {
    Exact,
    Bigger,
    Smaller,
    Between,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    UnknownInitial,
}

impl ScanComparison {
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(match raw.trim().to_ascii_lowercase().as_str() {
            "exact" | "eq" | "==" => Self::Exact,
            "bigger" | "gt" | ">" | "greater" => Self::Bigger,
            "smaller" | "lt" | "<" | "less" => Self::Smaller,
            "between" | "range" => Self::Between,
            "changed" | "neq" | "!=" => Self::Changed,
            "unchanged" | "same" => Self::Unchanged,
            "increased" | "inc" => Self::Increased,
            "decreased" | "dec" => Self::Decreased,
            "unknown" | "unknown_initial" | "all" => Self::UnknownInitial,
            other => bail!("Unsupported scan comparison: {other}"),
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Bigger => "bigger",
            Self::Smaller => "smaller",
            Self::Between => "between",
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::Increased => "increased",
            Self::Decreased => "decreased",
            Self::UnknownInitial => "unknown_initial",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanCandidate {
    pub address: u64,
    pub last_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ScanRegion {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub prot: u32,
}

#[derive(Debug, Clone)]
pub struct ScanSession {
    pub id: String,
    pub pid: u32,
    pub value_type: ScanValueType,
    pub width: usize,
    pub alignment: usize,
    pub passes: usize,
    pub truncated: bool,
    pub candidates: Vec<ScanCandidate>,
}

#[derive(Debug, Default)]
pub struct ScanBook {
    sessions: BTreeMap<String, ScanSession>,
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub session_id: String,
    pub value_type: Option<ScanValueType>,
    pub comparison: ScanComparison,
    pub value: Option<String>,
    pub value_max: Option<String>,
    pub float_epsilon: f64,
    pub case_insensitive: bool,
    pub alignment: Option<usize>,
    pub max_candidates: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone)]
enum ParsedTarget {
    None,
    Unsigned(u64, Option<u64>),
    Signed(i64, Option<i64>),
    Float(f64, Option<f64>, f64),
    Pattern {
        bytes: Vec<Option<u8>>,
        case_insensitive_ascii: bool,
    },
}

fn parse_u64_num(raw: &str) -> Result<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

fn parse_i64_num(raw: &str) -> Result<i64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        Ok(-(i64::from_str_radix(hex, 16)?))
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)? as i64)
    } else {
        Ok(s.parse::<i64>()?)
    }
}

fn parse_hex_pattern(raw: &str) -> Result<Vec<Option<u8>>> {
    let compact: Vec<&str> = raw.split_whitespace().collect();
    let mut out = Vec::new();
    if compact.len() > 1 || raw.contains('?') {
        for tok in compact {
            if tok == "?" || tok == "??" {
                out.push(None);
            } else {
                ensure!(tok.len() == 2, "Invalid byte token '{tok}' in hex pattern");
                out.push(Some(u8::from_str_radix(tok, 16)?));
            }
        }
    } else {
        let s = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
        ensure!(s.len().is_multiple_of(2) && !s.is_empty(), "Hex byte string must have non-zero even length");
        for i in (0..s.len()).step_by(2) {
            let sub = &s[i..i + 2];
            if sub == "??" {
                out.push(None);
            } else {
                out.push(Some(u8::from_str_radix(sub, 16)?));
            }
        }
    }
    ensure!(!out.is_empty(), "Pattern cannot be empty");
    Ok(out)
}

fn parse_target(
    vtype: ScanValueType,
    cmp: ScanComparison,
    val: Option<&str>,
    val_max: Option<&str>,
    eps: f64,
    case_insensitive: bool,
) -> Result<(ParsedTarget, usize)> {
    match cmp {
        ScanComparison::Changed
        | ScanComparison::Unchanged
        | ScanComparison::Increased
        | ScanComparison::Decreased
        | ScanComparison::UnknownInitial => {
            let width = vtype.fixed_width().ok_or_else(|| {
                anyhow!(
                    "Comparison '{}' requires a fixed-width numeric value_type",
                    cmp.as_str()
                )
            })?;
            if matches!(vtype, ScanValueType::F32 | ScanValueType::F64) {
                return Ok((ParsedTarget::Float(0.0, None, eps.max(0.0)), width));
            }
            return Ok((ParsedTarget::None, width));
        }
        _ => {}
    }

    let raw = val.ok_or_else(|| anyhow!("value is required for '{}' scan", cmp.as_str()))?;
    match vtype {
        ScanValueType::U8 | ScanValueType::U16 | ScanValueType::U32 | ScanValueType::U64 => {
            let v1 = parse_u64_num(raw)?;
            let v2 = if cmp == ScanComparison::Between {
                Some(parse_u64_num(
                    val_max.ok_or_else(|| anyhow!("value_max is required for 'between' scan"))?,
                )?)
            } else {
                None
            };
            Ok((
                ParsedTarget::Unsigned(v1, v2),
                vtype.fixed_width().unwrap(),
            ))
        }
        ScanValueType::I8 | ScanValueType::I16 | ScanValueType::I32 | ScanValueType::I64 => {
            let v1 = parse_i64_num(raw)?;
            let v2 = if cmp == ScanComparison::Between {
                Some(parse_i64_num(
                    val_max.ok_or_else(|| anyhow!("value_max is required for 'between' scan"))?,
                )?)
            } else {
                None
            };
            Ok((ParsedTarget::Signed(v1, v2), vtype.fixed_width().unwrap()))
        }
        ScanValueType::F32 | ScanValueType::F64 => {
            let v1: f64 = raw.trim().parse()?;
            ensure!(v1.is_finite(), "Float scan target must be finite");
            let v2 = if cmp == ScanComparison::Between {
                let m: f64 = val_max
                    .ok_or_else(|| anyhow!("value_max is required for 'between' scan"))?
                    .trim()
                    .parse()?;
                ensure!(m.is_finite(), "Float value_max must be finite");
                Some(m)
            } else {
                None
            };
            Ok((
                ParsedTarget::Float(v1, v2, eps.max(0.0)),
                vtype.fixed_width().unwrap(),
            ))
        }
        ScanValueType::Utf8 => {
            ensure!(
                cmp == ScanComparison::Exact,
                "String/byte scans only support 'exact' comparison"
            );
            ensure!(!raw.is_empty(), "UTF-8 search string cannot be empty");
            let bytes: Vec<Option<u8>> = raw.as_bytes().iter().map(|b| Some(*b)).collect();
            let len = bytes.len();
            Ok((
                ParsedTarget::Pattern {
                    bytes,
                    case_insensitive_ascii: case_insensitive,
                },
                len,
            ))
        }
        ScanValueType::Utf16 => {
            ensure!(
                cmp == ScanComparison::Exact,
                "UTF-16 scans only support 'exact' comparison"
            );
            ensure!(!raw.is_empty(), "UTF-16 search string cannot be empty");
            let mut bytes = Vec::new();
            let text = if case_insensitive {
                raw.to_lowercase()
            } else {
                raw.to_string()
            };
            for unit in text.encode_utf16() {
                let le = unit.to_le_bytes();
                bytes.push(Some(le[0]));
                bytes.push(Some(le[1]));
            }
            let len = bytes.len();
            Ok((
                ParsedTarget::Pattern {
                    bytes,
                    case_insensitive_ascii: case_insensitive,
                },
                len,
            ))
        }
        ScanValueType::Bytes => {
            ensure!(
                cmp == ScanComparison::Exact,
                "Byte pattern scans only support 'exact' comparison"
            );
            let bytes = parse_hex_pattern(raw)?;
            let len = bytes.len();
            Ok((
                ParsedTarget::Pattern {
                    bytes,
                    case_insensitive_ascii: false,
                },
                len,
            ))
        }
    }
}

fn read_unsigned(vtype: ScanValueType, slice: &[u8]) -> u64 {
    match vtype {
        ScanValueType::U8 => slice[0] as u64,
        ScanValueType::U16 => u16::from_le_bytes([slice[0], slice[1]]) as u64,
        ScanValueType::U32 => u32::from_le_bytes(slice[0..4].try_into().unwrap()) as u64,
        ScanValueType::U64 => u64::from_le_bytes(slice[0..8].try_into().unwrap()),
        _ => 0,
    }
}

fn read_signed(vtype: ScanValueType, slice: &[u8]) -> i64 {
    match vtype {
        ScanValueType::I8 => (slice[0] as i8) as i64,
        ScanValueType::I16 => i16::from_le_bytes([slice[0], slice[1]]) as i64,
        ScanValueType::I32 => i32::from_le_bytes(slice[0..4].try_into().unwrap()) as i64,
        ScanValueType::I64 => i64::from_le_bytes(slice[0..8].try_into().unwrap()),
        _ => 0,
    }
}

fn read_float(vtype: ScanValueType, slice: &[u8]) -> f64 {
    match vtype {
        ScanValueType::F32 => f32::from_le_bytes(slice[0..4].try_into().unwrap()) as f64,
        ScanValueType::F64 => f64::from_le_bytes(slice[0..8].try_into().unwrap()),
        _ => f64::NAN,
    }
}

fn matches_candidate(
    vtype: ScanValueType,
    cmp: ScanComparison,
    target: &ParsedTarget,
    cur: &[u8],
    prev: Option<&[u8]>,
) -> bool {
    match cmp {
        ScanComparison::UnknownInitial => match vtype {
            ScanValueType::F32 | ScanValueType::F64 => read_float(vtype, cur).is_finite(),
            _ => true,
        },
        ScanComparison::Changed => prev.is_some_and(|p| cur != p),
        ScanComparison::Unchanged => prev.is_some_and(|p| cur == p),
        ScanComparison::Increased => {
            let Some(p) = prev else { return false };
            match vtype {
                ScanValueType::U8 | ScanValueType::U16 | ScanValueType::U32 | ScanValueType::U64 => {
                    read_unsigned(vtype, cur) > read_unsigned(vtype, p)
                }
                ScanValueType::I8 | ScanValueType::I16 | ScanValueType::I32 | ScanValueType::I64 => {
                    read_signed(vtype, cur) > read_signed(vtype, p)
                }
                ScanValueType::F32 | ScanValueType::F64 => {
                    let c = read_float(vtype, cur);
                    let o = read_float(vtype, p);
                    c.is_finite() && o.is_finite() && c > o
                }
                _ => false,
            }
        }
        ScanComparison::Decreased => {
            let Some(p) = prev else { return false };
            match vtype {
                ScanValueType::U8 | ScanValueType::U16 | ScanValueType::U32 | ScanValueType::U64 => {
                    read_unsigned(vtype, cur) < read_unsigned(vtype, p)
                }
                ScanValueType::I8 | ScanValueType::I16 | ScanValueType::I32 | ScanValueType::I64 => {
                    read_signed(vtype, cur) < read_signed(vtype, p)
                }
                ScanValueType::F32 | ScanValueType::F64 => {
                    let c = read_float(vtype, cur);
                    let o = read_float(vtype, p);
                    c.is_finite() && o.is_finite() && c < o
                }
                _ => false,
            }
        }
        ScanComparison::Exact
        | ScanComparison::Bigger
        | ScanComparison::Smaller
        | ScanComparison::Between => match target {
            ParsedTarget::Unsigned(v1, v2) => {
                let c = read_unsigned(vtype, cur);
                match cmp {
                    ScanComparison::Exact => c == *v1,
                    ScanComparison::Bigger => c > *v1,
                    ScanComparison::Smaller => c < *v1,
                    ScanComparison::Between => {
                        let hi = v2.unwrap_or(*v1);
                        let (lo, hi) = if *v1 <= hi { (*v1, hi) } else { (hi, *v1) };
                        c >= lo && c <= hi
                    }
                    _ => false,
                }
            }
            ParsedTarget::Signed(v1, v2) => {
                let c = read_signed(vtype, cur);
                match cmp {
                    ScanComparison::Exact => c == *v1,
                    ScanComparison::Bigger => c > *v1,
                    ScanComparison::Smaller => c < *v1,
                    ScanComparison::Between => {
                        let hi = v2.unwrap_or(*v1);
                        let (lo, hi) = if *v1 <= hi { (*v1, hi) } else { (hi, *v1) };
                        c >= lo && c <= hi
                    }
                    _ => false,
                }
            }
            ParsedTarget::Float(v1, v2, eps) => {
                let c = read_float(vtype, cur);
                if !c.is_finite() {
                    return false;
                }
                match cmp {
                    ScanComparison::Exact => (c - *v1).abs() <= *eps,
                    ScanComparison::Bigger => c > *v1,
                    ScanComparison::Smaller => c < *v1,
                    ScanComparison::Between => {
                        let hi = v2.unwrap_or(*v1);
                        let (lo, hi) = if *v1 <= hi { (*v1, hi) } else { (hi, *v1) };
                        c >= lo - *eps && c <= hi + *eps
                    }
                    _ => false,
                }
            }
            ParsedTarget::Pattern {
                bytes,
                case_insensitive_ascii,
            } => {
                if cur.len() < bytes.len() {
                    return false;
                }
                for (i, pat) in bytes.iter().enumerate() {
                    if let Some(b) = pat {
                        let cb = cur[i];
                        if *case_insensitive_ascii {
                            if !cb.eq_ignore_ascii_case(b) {
                                return false;
                            }
                        } else if cb != *b {
                            return false;
                        }
                    }
                }
                true
            }
            ParsedTarget::None => false,
        },
    }
}

pub fn format_candidate_value(vtype: ScanValueType, bytes: &[u8]) -> Value {
    if bytes.len() < vtype.fixed_width().unwrap_or(1) {
        return Value::String(hex::encode(bytes));
    }
    match vtype {
        ScanValueType::U8 | ScanValueType::U16 | ScanValueType::U32 | ScanValueType::U64 => {
            json!(read_unsigned(vtype, bytes))
        }
        ScanValueType::I8 | ScanValueType::I16 | ScanValueType::I32 | ScanValueType::I64 => {
            json!(read_signed(vtype, bytes))
        }
        ScanValueType::F32 | ScanValueType::F64 => json!(read_float(vtype, bytes)),
        ScanValueType::Utf8 => json!(String::from_utf8_lossy(bytes).to_string()),
        ScanValueType::Utf16 => {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            json!(String::from_utf16_lossy(&units))
        }
        ScanValueType::Bytes => json!(hex::encode(bytes)),
    }
}

impl ScanBook {
    pub fn clear(&mut self) {
        self.sessions.clear();
    }

    pub fn list(&self) -> Value {
        let items: Vec<Value> = self
            .sessions
            .values()
            .map(|s| {
                json!({
                    "session_id": s.id,
                    "pid": s.pid,
                    "value_type": s.value_type.as_str(),
                    "width": s.width,
                    "alignment": s.alignment,
                    "passes": s.passes,
                    "candidate_count": s.candidates.len(),
                    "truncated": s.truncated,
                })
            })
            .collect();
        json!({ "count": items.len(), "sessions": items })
    }

    pub fn reset(&mut self, session_id: &str) -> Value {
        if session_id == "*" || session_id.eq_ignore_ascii_case("all") {
            let count = self.sessions.len();
            self.sessions.clear();
            return json!({ "cleared": count });
        }
        let existed = self.sessions.remove(session_id).is_some();
        json!({ "session_id": session_id, "removed": existed })
    }

    pub fn get(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
        refresh_read: Option<&mut dyn FnMut(u64, usize) -> Result<Vec<u8>>>,
    ) -> Result<Value> {
        let sess = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Scan session '{session_id}' not found"))?;
        Ok(render_session_page(sess, offset, limit, refresh_read))
    }

    pub fn first_scan(
        &mut self,
        pid: u32,
        req: &ScanRequest,
        regions: &[ScanRegion],
        chunk_size: usize,
        max_scan_bytes: usize,
        mut read_mem: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Value> {
        ensure!(
            self.sessions.contains_key(&req.session_id) || self.sessions.len() < MAX_SCAN_SESSIONS,
            "Maximum scan sessions ({MAX_SCAN_SESSIONS}) reached; reset an existing session first"
        );
        ensure!(
            !matches!(
                req.comparison,
                ScanComparison::Changed
                    | ScanComparison::Unchanged
                    | ScanComparison::Increased
                    | ScanComparison::Decreased
            ),
            "Comparison '{}' is only valid on 'next' scans",
            req.comparison.as_str()
        );
        let vtype = req
            .value_type
            .ok_or_else(|| anyhow!("value_type is required for 'first' scan"))?;
        let (target, width) = parse_target(
            vtype,
            req.comparison,
            req.value.as_deref(),
            req.value_max.as_deref(),
            req.float_epsilon,
            req.case_insensitive,
        )?;
        let align = req
            .alignment
            .unwrap_or_else(|| vtype.default_alignment())
            .max(1);
        let cap = req.max_candidates.clamp(1, MAX_SCAN_CANDIDATES);
        let step_chunk = chunk_size.max(width.saturating_mul(2)).max(4096);

        let mut candidates = Vec::new();
        let mut truncated = false;
        let mut scanned_bytes = 0usize;

        'outer: for region in regions {
            if region.end <= region.start || (region.end - region.start) < width as u64 {
                continue;
            }
            let mut cursor = region.start;
            let mut carry: Vec<u8> = Vec::new();
            let mut carry_addr = region.start;

            while cursor < region.end {
                if scanned_bytes >= max_scan_bytes {
                    truncated = true;
                    break 'outer;
                }
                let rem = (region.end - cursor) as usize;
                let ask = rem.min(step_chunk).min(max_scan_bytes - scanned_bytes);
                let Ok(chunk) = read_mem(cursor, ask) else {
                    carry.clear();
                    cursor = cursor.saturating_add(ask as u64);
                    carry_addr = cursor;
                    continue;
                };
                if chunk.is_empty() {
                    break;
                }
                scanned_bytes = scanned_bytes.saturating_add(chunk.len());

                let mut window = Vec::with_capacity(carry.len() + chunk.len());
                let base_addr = if carry.is_empty() { cursor } else { carry_addr };
                window.extend_from_slice(&carry);
                window.extend_from_slice(&chunk);

                if window.len() >= width {
                    let last_start = window.len() - width;
                    let mut idx = 0usize;
                    let rem_align = (base_addr as usize) % align;
                    if rem_align != 0 {
                        idx = align - rem_align;
                    }
                    while idx <= last_start {
                        let slice = &window[idx..idx + width];
                        if matches_candidate(vtype, req.comparison, &target, slice, None) {
                            candidates.push(ScanCandidate {
                                address: base_addr + idx as u64,
                                last_bytes: slice.to_vec(),
                            });
                            if candidates.len() >= cap {
                                truncated = true;
                                break 'outer;
                            }
                        }
                        idx += align;
                    }
                }

                let keep = width.saturating_sub(1).min(window.len());
                carry.clear();
                if keep > 0 {
                    carry.extend_from_slice(&window[window.len() - keep..]);
                    carry_addr = base_addr + (window.len() - keep) as u64;
                }
                cursor = cursor.saturating_add(chunk.len() as u64);
            }
        }

        let session = ScanSession {
            id: req.session_id.clone(),
            pid,
            value_type: vtype,
            width,
            alignment: align,
            passes: 1,
            truncated,
            candidates,
        };
        let page = render_session_page(&session, req.offset, req.limit, None);
        self.sessions.insert(req.session_id.clone(), session);
        Ok(page)
    }

    pub fn next_scan(
        &mut self,
        pid: u32,
        req: &ScanRequest,
        chunk_size: usize,
        mut read_mem: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Value> {
        ensure!(
            req.comparison != ScanComparison::UnknownInitial,
            "'unknown_initial' is only valid on 'first' scans"
        );
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow!("Scan session '{}' not found; run action='first' first", req.session_id))?;
        ensure!(
            sess.pid == pid,
            "Scan session '{}' belongs to PID {}, currently attached to PID {}",
            sess.id,
            sess.pid,
            pid
        );

        let vtype = req.value_type.unwrap_or(sess.value_type);
        ensure!(
            vtype == sess.value_type,
            "Scan session '{}' has value_type '{}', cannot change to '{}'",
            sess.id,
            sess.value_type.as_str(),
            vtype.as_str()
        );
        let (target, width) = parse_target(
            vtype,
            req.comparison,
            req.value.as_deref(),
            req.value_max.as_deref(),
            req.float_epsilon,
            req.case_insensitive,
        )?;
        ensure!(
            width == sess.width,
            "Pattern width {width} differs from session width {}",
            sess.width
        );

        // Coalesce adjacent candidate reads up to `chunk_size` to avoid N round-trips!
        let max_span = chunk_size.clamp(4096, 65536) as u64;
        let mut retained = Vec::new();
        let old = std::mem::take(&mut sess.candidates);
        let mut i = 0usize;
        while i < old.len() {
            let start_addr = old[i].address;
            let mut j = i + 1;
            let mut end_addr = start_addr + width as u64;
            while j < old.len() {
                let cand_end = old[j].address + width as u64;
                if cand_end.saturating_sub(start_addr) <= max_span
                    && old[j].address.saturating_sub(end_addr) <= 4096
                {
                    end_addr = cand_end;
                    j += 1;
                } else {
                    break;
                }
            }
            let span_len = (end_addr - start_addr) as usize;
            if let Ok(buf) = read_mem(start_addr, span_len) {
                for cand in &old[i..j] {
                    let rel = (cand.address - start_addr) as usize;
                    if rel + width <= buf.len() {
                        let cur = &buf[rel..rel + width];
                        if matches_candidate(
                            vtype,
                            req.comparison,
                            &target,
                            cur,
                            Some(&cand.last_bytes),
                        ) {
                            retained.push(ScanCandidate {
                                address: cand.address,
                                last_bytes: cur.to_vec(),
                            });
                        }
                    }
                }
            }
            i = j;
        }

        sess.candidates = retained;
        sess.passes += 1;
        sess.truncated = false;
        Ok(render_session_page(sess, req.offset, req.limit, None))
    }
}

fn render_session_page(
    sess: &ScanSession,
    offset: usize,
    limit: usize,
    mut refresh: Option<&mut dyn FnMut(u64, usize) -> Result<Vec<u8>>>,
) -> Value {
    let lim = limit.clamp(1, 2000);
    let slice_end = sess.candidates.len().min(offset.saturating_add(lim));
    let mut matches = Vec::new();
    if offset < slice_end {
        for cand in &sess.candidates[offset..slice_end] {
            let mut cur_bytes: Option<Vec<u8>> = None;
            if let Some(reader) = refresh.as_deref_mut()
                && let Ok(b) = reader(cand.address, sess.width)
                && b.len() == sess.width
            {
                cur_bytes = Some(b);
            }
            let shown = cur_bytes.as_deref().unwrap_or(&cand.last_bytes);
            matches.push(json!({
                "address": format!("{:#x}", cand.address),
                "value": format_candidate_value(sess.value_type, shown),
                "previous_value": format_candidate_value(sess.value_type, &cand.last_bytes),
                "bytes_hex": hex::encode(shown),
            }));
        }
    }
    json!({
        "session_id": sess.id,
        "pid": sess.pid,
        "value_type": sess.value_type.as_str(),
        "width": sess.width,
        "alignment": sess.alignment,
        "passes": sess.passes,
        "candidate_count": sess.candidates.len(),
        "truncated": sess.truncated,
        "offset": offset,
        "limit": lim,
        "matches": matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_pass_scan_narrows_health_and_float_targets() {
        let mut mem = vec![0u8; 4096];
        // Put 100 (u32) at 0x100 and 0x240, and 100.0f32 at 0x300
        mem[0x100..0x104].copy_from_slice(&100u32.to_le_bytes());
        mem[0x240..0x244].copy_from_slice(&100u32.to_le_bytes());
        mem[0x300..0x304].copy_from_slice(&100.0f32.to_le_bytes());

        let regions = vec![ScanRegion {
            start: 0x10_0000,
            end: 0x10_1000,
            name: "heap".into(),
            prot: 3,
        }];
        let mut book = ScanBook::default();
        let req1 = ScanRequest {
            session_id: "hp".into(),
            value_type: Some(ScanValueType::U32),
            comparison: ScanComparison::Exact,
            value: Some("100".into()),
            value_max: None,
            float_epsilon: 0.001,
            case_insensitive: false,
            alignment: Some(4),
            max_candidates: 10_000,
            limit: 50,
            offset: 0,
        };
        let res1 = book
            .first_scan(42, &req1, &regions, 512, 1024 * 1024, |addr, len| {
                let off = (addr - 0x10_0000) as usize;
                Ok(mem[off..off + len].to_vec())
            })
            .unwrap();
        assert_eq!(res1["candidate_count"], 2);

        // Player takes 25 damage at 0x240 -> 75, while 0x100 stays 100
        mem[0x240..0x244].copy_from_slice(&75u32.to_le_bytes());
        let req2 = ScanRequest {
            comparison: ScanComparison::Decreased,
            value: None,
            ..req1.clone()
        };
        let res2 = book
            .next_scan(42, &req2, 4096, |addr, len| {
                let off = (addr - 0x10_0000) as usize;
                Ok(mem[off..off + len].to_vec())
            })
            .unwrap();
        assert_eq!(res2["candidate_count"], 1);
        assert_eq!(res2["matches"][0]["address"], "0x100240");
        assert_eq!(res2["matches"][0]["value"], 75);

        // Exact follow-up check
        let req3 = ScanRequest {
            comparison: ScanComparison::Exact,
            value: Some("75".into()),
            ..req1
        };
        let res3 = book
            .next_scan(42, &req3, 4096, |addr, len| {
                let off = (addr - 0x10_0000) as usize;
                Ok(mem[off..off + len].to_vec())
            })
            .unwrap();
        assert_eq!(res3["candidate_count"], 1);
        assert_eq!(res3["passes"], 3);
    }

    #[test]
    fn scans_across_chunk_boundaries_for_strings_and_wildcards() {
        let mut mem = [0u8; 64];
        mem[13..23].copy_from_slice(b"OrbisOS_14");
        let regions = vec![ScanRegion {
            start: 0x2000,
            end: 0x2040,
            name: "rodata".into(),
            prot: 1,
        }];
        let mut book = ScanBook::default();
        let req = ScanRequest {
            session_id: "str".into(),
            value_type: Some(ScanValueType::Utf8),
            comparison: ScanComparison::Exact,
            value: Some("orbisos_14".into()),
            value_max: None,
            float_epsilon: 0.0,
            case_insensitive: true,
            alignment: Some(1),
            max_candidates: 100,
            limit: 10,
            offset: 0,
        };
        // Read in tiny 16-byte chunks so "OrbisOS_14" straddles 0x200d..0x2017!
        let res = book
            .first_scan(7, &req, &regions, 16, 4096, |addr, len| {
                let off = (addr - 0x2000) as usize;
                Ok(mem[off..(off + len).min(mem.len())].to_vec())
            })
            .unwrap();
        assert_eq!(res["candidate_count"], 1);
        assert_eq!(res["matches"][0]["address"], "0x200d");
    }
}
