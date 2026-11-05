//! Orbis prototype database: C function declarations parsed from header files
//! the user has (OpenOrbis include directory, header artifacts) or from a user
//! JSON dictionary, keyed by Orbis NID (`nid::encode_nid`).
//!
//! The parser is a best-effort declaration scanner, not a C preprocessor:
//! comments, preprocessor lines, `extern "C"` blocks, attributes and common
//! qualifier macros are handled; bodies, typedefs and initialised variables
//! are skipped.

use anyhow::{bail, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::Result;

pub const FORMAT: &str = "ps4wb-prototypes-v1";
const MAX_FILES: usize = 8192;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DEPTH: usize = 12;
pub const MAX_PROTOTYPES: usize = 200_000;

/// Standard ISO C declarations (PS4 libc exports them under the NID of the
/// plain name) and one SDK function whose signature is well established.
const BUILTIN_HEADER: &str = r#"
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
int printf(const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int puts(const char *s);
void abort(void);
int sceKernelUsleep(unsigned int microseconds);
"#;

#[derive(Clone, Debug, PartialEq)]
pub struct Prototype {
    pub name: String,
    pub nid: String,
    pub library: Option<String>,
    pub declaration: String,
    pub ret: String,
    pub params: Vec<(Option<String>, String)>,
    pub source: String,
}

impl Prototype {
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name, "nid": self.nid, "library": self.library,
            "declaration": self.declaration, "return": self.ret,
            "params": self.params.iter().map(|(name, ty)| json!({"name": name, "type": ty})).collect::<Vec<_>>(),
            "source": self.source,
        })
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        let name = value["name"].as_str()?.to_owned();
        Some(Prototype {
            nid: value["nid"].as_str().map_or_else(|| crate::nid::encode_nid(&name), str::to_owned),
            library: value["library"].as_str().map(str::to_owned),
            declaration: value["declaration"].as_str().unwrap_or_default().to_owned(),
            ret: value["return"].as_str().unwrap_or_default().to_owned(),
            params: value["params"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| (p["name"].as_str().map(str::to_owned), p["type"].as_str().unwrap_or_default().to_owned()))
                .collect(),
            source: value["source"].as_str().unwrap_or("user").to_owned(),
            name,
        })
    }
}

fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            out.push(c as char);
            if c == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
            out.push(' ');
            continue;
        }
        if c == b'"' || c == b'\'' {
            quote = Some(c);
        }
        out.push(if c.is_ascii() { c as char } else { ' ' });
        i += 1;
    }
    out
}

fn strip_preprocessor(text: &str) -> String {
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    joined
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove `name(...)` occurrences with balanced parentheses.
fn remove_call(text: &str, name: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(name) {
        let boundary_before = rest[..at].chars().last().is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after = &rest[at + name.len()..];
        let trimmed = after.trim_start();
        if !boundary_before || !trimmed.starts_with('(') {
            out.push_str(&rest[..at + name.len()]);
            rest = after;
            continue;
        }
        out.push_str(&rest[..at]);
        let open = after.len() - trimmed.len();
        let mut depth = 0usize;
        let mut end = after.len();
        for (index, c) in after[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(' ');
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

const DROP_WORDS: &[&str] = &[
    "extern", "__extension__", "__cdecl", "__stdcall", "__fastcall", "__restrict", "__restrict__", "restrict",
    "_Noreturn", "__noreturn", "noreturn", "__THROW", "__wur", "noexcept", "__nonnull", "register", "__unused",
    "__dead2", "__pure2", "__result_use_check", "__malloc_like",
];

const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "bool", "const",
    "volatile", "struct", "enum", "union",
];

fn is_ident(token: &str) -> bool {
    token.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') && token.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn clean_words(text: &str) -> String {
    let mut text = text.to_owned();
    for call in ["__attribute__", "__attribute", "__declspec", "__asm__", "__asm", "asm", "__nonnull", "__printflike", "__scanflike", "__format_arg", "__alloc_size"] {
        text = remove_call(&text, call);
    }
    while let (Some(open), Some(close)) = (text.find("[["), text.find("]]")) {
        if close < open {
            break;
        }
        text.replace_range(open..close + 2, " ");
    }
    // Space out punctuation so tokens split cleanly.
    let spaced: String = text
        .chars()
        .flat_map(|c| if "*(),[]&".contains(c) { vec![' ', c, ' '] } else { vec![c] })
        .collect();
    spaced
        .split_whitespace()
        .filter(|word| {
            !DROP_WORDS.contains(word)
                && !(is_ident(word)
                    && word.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                    && ["_API", "_EXPORT", "_IMPORT", "_DECL", "_EXTERN", "_CALL"].iter().any(|suffix| word.ends_with(suffix)))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Pretty-print a token string: `const char * x` -> `const char *x`.
fn tidy(tokens: &str) -> String {
    let mut out = tokens.split_whitespace().collect::<Vec<_>>().join(" ");
    for (from, to) in [("* ", "*"), (" )", ")"), ("( ", "("), (" ,", ","), (" [", "["), ("[ ", "["), (" ]", "]")] {
        out = out.replace(from, to);
    }
    out.trim().to_owned()
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() || !parts.is_empty() {
        parts.push(current);
    }
    parts
}

fn parse_param(text: &str) -> (Option<String>, String) {
    let text = text.trim();
    if text == "..." {
        return (Some("...".into()), "...".into());
    }
    // Function pointer: `ret ( * name ) ( args )`.
    if let Some(at) = text.find("( *") {
        let after = &text[at + 3..];
        let name = after.split_whitespace().find(|t| *t != "const" && *t != "*").filter(|t| is_ident(t));
        if let Some(name) = name {
            let ty = text.replacen(&format!(" {name} "), " ", 1);
            return (Some(name.to_owned()), tidy(&ty));
        }
        return (None, tidy(text));
    }
    let (body, array) = match text.find('[') {
        Some(at) => (&text[..at], text[at..].replace(' ', "")),
        None => (text, String::new()),
    };
    let tokens: Vec<&str> = body.split_whitespace().collect();
    if tokens.len() >= 2 {
        let last = tokens[tokens.len() - 1];
        let previous = tokens[tokens.len() - 2];
        if is_ident(last) && !TYPE_WORDS.contains(&last) && !matches!(previous, "struct" | "enum" | "union") {
            return (Some(last.to_owned()), tidy(&format!("{}{}", tokens[..tokens.len() - 1].join(" "), array)));
        }
    }
    (None, tidy(&format!("{body}{array}")))
}

/// Parse one top-level statement (without `;`) as a function declaration.
pub fn parse_declaration(statement: &str, source: &str) -> Option<Prototype> {
    let raw = statement.split_whitespace().collect::<Vec<_>>().join(" ");
    let first = raw.split_whitespace().next()?;
    if matches!(first, "typedef" | "using" | "static" | "inline" | "__inline" | "static_assert" | "_Static_assert" | "template" | "return" | "namespace")
        || raw.contains(" inline ")
        || raw.contains('=')
        || raw.contains('{')
        || raw.contains('"')
    {
        return None;
    }
    let text = clean_words(&raw);
    let tokens: Vec<&str> = text.split(' ').collect();
    let open = tokens.iter().position(|t| *t == "(")?;
    if open < 2 {
        return None;
    }
    let name = tokens[open - 1];
    if !is_ident(name) || TYPE_WORDS.contains(&name) {
        return None;
    }
    let ret_tokens = &tokens[..open - 1];
    if ret_tokens.is_empty() || ret_tokens.iter().any(|t| *t == "(" || *t == ")" || *t == ",") {
        return None;
    }
    // Matching close paren; nothing meaningful may follow.
    let mut depth = 0i32;
    let mut close = None;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match *token {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    close = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    if tokens[close + 1..].iter().any(|t| !matches!(*t, "const" | "override")) {
        return None;
    }
    let inner = tokens[open + 1..close].join(" ");
    let mut params = Vec::new();
    let pieces = split_top_level(&inner);
    if !(pieces.len() == 1 && matches!(pieces[0].trim(), "" | "void")) {
        for piece in pieces {
            if piece.trim().is_empty() {
                return None;
            }
            params.push(parse_param(&piece));
        }
    }
    let ret = tidy(&ret_tokens.join(" "));
    Some(Prototype {
        name: name.to_owned(),
        nid: crate::nid::encode_nid(name),
        library: None,
        declaration: format!("{};", tidy(&tokens[..=close].join(" "))),
        ret,
        params,
        source: source.to_owned(),
    })
}

/// All function declarations in a header's text.
pub fn parse_header(text: &str, source: &str) -> Vec<Prototype> {
    let text = strip_preprocessor(&strip_comments(text));
    let mut found = Vec::new();
    // Brace stack: `true` = transparent (`extern "C"` / namespace) block.
    let mut stack: Vec<bool> = Vec::new();
    let mut statement = String::new();
    let mut discard_statement = false;
    for c in text.chars() {
        let opaque_depth = stack.iter().filter(|transparent| !**transparent).count();
        match c {
            '{' => {
                if opaque_depth == 0 {
                    let head = statement.trim();
                    let transparent = head.ends_with("extern \"C\"") || head.starts_with("namespace") || head == "extern \"C++\"";
                    if transparent {
                        statement.clear();
                    } else if head.ends_with(')') {
                        discard_statement = true; // inline function body
                    }
                    stack.push(transparent);
                } else {
                    stack.push(false);
                }
                continue;
            }
            '}' => {
                let closed = stack.pop();
                if opaque_depth == 1 && closed == Some(false) && discard_statement {
                    statement.clear();
                    discard_statement = false;
                }
                continue;
            }
            _ => {}
        }
        if opaque_depth > 0 {
            continue;
        }
        if c == ';' {
            if !discard_statement
                && let Some(prototype) = parse_declaration(&statement, source)
            {
                found.push(prototype);
            }
            statement.clear();
            discard_statement = false;
        } else {
            statement.push(c);
        }
    }
    found
}

pub fn builtin() -> Vec<Prototype> {
    parse_header(BUILTIN_HEADER, "builtin")
}

/// Header files under `directory` (recursive, bounded).
pub fn header_files(directory: &Path) -> Result<(Vec<PathBuf>, bool)> {
    ensure!(directory.is_dir(), "Include directory does not exist: {}", directory.display());
    let mut files = Vec::new();
    let mut stack = vec![(directory.to_path_buf(), 0usize)];
    let mut truncated = false;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            } else if kind.is_file() && path.extension().is_some_and(|ext| matches!(ext.to_str(), Some("h" | "hpp" | "hh"))) {
                if files.len() >= MAX_FILES {
                    truncated = true;
                    break;
                }
                files.push(path);
            }
        }
    }
    files.sort();
    Ok((files, truncated))
}

/// Parse every header under `directory`; returns prototypes and stats.
pub fn parse_directory(directory: &Path) -> Result<(Vec<Prototype>, Value)> {
    let (files, truncated) = header_files(directory)?;
    let mut prototypes = Vec::new();
    let mut total = 0u64;
    let mut skipped = 0usize;
    for path in &files {
        let Ok(metadata) = std::fs::metadata(path) else { continue };
        if metadata.len() > MAX_FILE_BYTES || total + metadata.len() > MAX_TOTAL_BYTES {
            skipped += 1;
            continue;
        }
        total += metadata.len();
        let Ok(bytes) = std::fs::read(path) else { continue };
        let source = path.to_string_lossy().replace('\\', "/");
        prototypes.extend(parse_header(&String::from_utf8_lossy(&bytes), &source));
        if prototypes.len() >= MAX_PROTOTYPES {
            break;
        }
    }
    Ok((
        prototypes,
        json!({"directory": directory.to_string_lossy(), "files": files.len(), "bytes": total, "skipped_large": skipped, "files_truncated": truncated}),
    ))
}

/// User dictionary: a prototype DB, an array of prototype objects, or
/// `{name: "declaration;"}`.
pub fn parse_user(document: &Value) -> Result<Vec<Prototype>> {
    if document["format"] == FORMAT {
        return Ok(document["prototypes"].as_array().into_iter().flatten().filter_map(Prototype::from_json).collect());
    }
    if let Some(list) = document.as_array() {
        let mut found = Vec::new();
        for entry in list {
            if let Some(declaration) = entry["declaration"].as_str()
                && entry["params"].is_null()
            {
                let mut prototype = parse_declaration(declaration.trim_end_matches(';'), "user")
                    .ok_or_else(|| anyhow::anyhow!("Cannot parse declaration: {declaration}"))?;
                prototype.library = entry["library"].as_str().map(str::to_owned);
                found.push(prototype);
            } else if let Some(mut prototype) = Prototype::from_json(entry) {
                prototype.source = "user".into();
                found.push(prototype);
            }
        }
        return Ok(found);
    }
    if let Some(map) = document.as_object() {
        let mut found = Vec::new();
        for (name, declaration) in map {
            let declaration = declaration.as_str().ok_or_else(|| anyhow::anyhow!("Value for {name} must be a declaration string"))?;
            let prototype = parse_declaration(declaration.trim().trim_end_matches(';'), "user")
                .ok_or_else(|| anyhow::anyhow!("Cannot parse declaration for {name}: {declaration}"))?;
            ensure!(&prototype.name == name, "Declaration for {name} declares {}", prototype.name);
            found.push(prototype);
        }
        return Ok(found);
    }
    bail!("Unrecognised prototype dictionary format")
}

/// Merge in priority order (earlier lists win), keyed by NID.
pub fn merge(lists: Vec<Vec<Prototype>>) -> (Vec<Prototype>, usize) {
    let mut by_nid: BTreeMap<String, Prototype> = BTreeMap::new();
    let mut duplicates = 0usize;
    for list in lists {
        for prototype in list {
            if by_nid.contains_key(&prototype.nid) {
                duplicates += 1;
            } else if by_nid.len() < MAX_PROTOTYPES {
                by_nid.insert(prototype.nid.clone(), prototype);
            }
        }
    }
    let mut merged: Vec<Prototype> = by_nid.into_values().collect();
    merged.sort_by(|a, b| a.name.cmp(&b.name));
    (merged, duplicates)
}

pub fn document(prototypes: &[Prototype]) -> Value {
    json!({"format": FORMAT, "prototypes": prototypes.iter().map(Prototype::to_json).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_sdk_declarations() {
        let header = r#"
#pragma once
#include <stdint.h>
#define SCE_API __attribute__((visibility("default")))
#ifdef __cplusplus
extern "C" {
#endif
/* multi
   line */
typedef struct OrbisPadData { uint32_t buttons; } OrbisPadData;
typedef int (*Callback)(void *arg);
int scePadOpen(int32_t userID, int32_t type, int32_t index, void* param); // trailing
SCE_API int32_t scePadReadState(int handle, OrbisPadData *data) __attribute__((nonnull));
void sceKernelSetCallback(int (*cb)(void *arg, int code), void *arg);
const char * const *sceNames(unsigned int count, char buffer[16]);
int sceKernelPrintf(const char *fmt, ...);
static inline int helper(int x) { return x + 1; }
extern int someGlobal;
int sceUnnamed(int, const char *);
FOO_MACRO(bar);
int (*fnptr)(int);
#ifdef __cplusplus
}
#endif
"#;
        let found = parse_header(header, "orbis/Pad.h");
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["scePadOpen", "scePadReadState", "sceKernelSetCallback", "sceNames", "sceKernelPrintf", "sceUnnamed"]);
        let open = &found[0];
        assert_eq!(open.ret, "int");
        assert_eq!(open.params[3], (Some("param".into()), "void *".into()));
        assert_eq!(open.nid, crate::nid::encode_nid("scePadOpen"));
        assert_eq!(found[1].params[1], (Some("data".into()), "OrbisPadData *".into()));
        assert_eq!(found[2].params[0].0.as_deref(), Some("cb"));
        assert_eq!(found[3].params[1], (Some("buffer".into()), "char[16]".into()));
        assert_eq!(found[4].params[1], (Some("...".into()), "...".into()));
        assert_eq!(found[5].params[0], (None, "int".into()));
        assert_eq!(found[5].params[1], (None, "const char *".into()));
    }

    #[test]
    fn builtin_and_user_dictionaries() {
        let builtins = builtin();
        let usleep = builtins.iter().find(|p| p.name == "sceKernelUsleep").unwrap();
        assert_eq!(usleep.nid, "1jfXLRVzisc");
        assert_eq!(usleep.source, "builtin");
        let user = parse_user(&json!({"sceKernelUsleep": "int sceKernelUsleep(SceKernelUseconds usec);"})).unwrap();
        let (merged, duplicates) = merge(vec![user, builtins]);
        assert_eq!(duplicates, 1);
        assert_eq!(merged.iter().find(|p| p.nid == "1jfXLRVzisc").unwrap().source, "user");
        assert!(parse_user(&json!({"x": "int y(void);"})).is_err());
        let doc = document(&merged);
        assert_eq!(parse_user(&doc).unwrap().len(), merged.len());
    }
}
