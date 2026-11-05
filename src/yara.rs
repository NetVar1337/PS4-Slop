//! A self-contained YARA-subset engine (no libyara / yara-x).
//!
//! Supported (syntax per the YARA documentation, "Writing YARA rules"):
//! `[private] rule name [: tags] { meta: … strings: … condition: … }`;
//! text strings with `nocase`, `wide`, `ascii`, `fullword`, `private`;
//! hex strings with `??`, nibble wildcards (`4?`, `?D`), `~XX`, bounded jumps
//! `[n]`/`[n-m]` and alternatives `( 01 | 02 03 )`; regular expressions
//! `/…/is` (Rust `regex` syntax, byte-oriented); conditions with
//! `and`/`or`/`not`, parentheses, comparisons, `+ - * \ %`, `filesize`,
//! `$a`, `$a at N`, `$a in (A..B)`, `#a`, `#a in (A..B)`, `@a[i]`, `!a[i]`,
//! `all|any|none|N|N% of (them | ($a, $b*))` and references to earlier rules.
//! Anything else (modules/imports, `for` loops, `xor`/`base64`, unbounded
//! jumps, `uintXX()` reads, `global` rules) is rejected with a clear error.
use crate::{
    Result,
    bytesource::{Mode, Source, TargetSpec},
    workbench::Workbench,
};
use anyhow::{Context, anyhow, bail, ensure};
use regex::bytes::Regex;
use serde_json::{Value, json};
use std::collections::HashSet;

const MAX_RULES_TEXT: usize = 1 << 20;
const MAX_MATCHES_PER_STRING: usize = 10_000;
/// Live chunks overlap by this many bytes; longer matches across a chunk
/// boundary can be missed.
const CHUNK_OVERLAP: usize = 4096;

#[derive(Debug)]
pub struct StringDef {
    pub id: String,
    regex: Regex,
    fullword: bool,
    wide: bool,
    pub private: bool,
}

#[derive(Debug, Clone)]
enum Quant {
    All,
    Any,
    None,
    Count(Box<Expr>),
    Percent(Box<Expr>),
}

#[derive(Debug, Clone)]
enum Expr {
    Bool(bool),
    Int(i64),
    Filesize,
    Str(usize),
    StrAt(usize, Box<Expr>),
    StrIn(usize, Box<Expr>, Box<Expr>),
    Count(usize),
    CountIn(usize, Box<Expr>, Box<Expr>),
    Offset(usize, Box<Expr>),
    Length(usize, Box<Expr>),
    Of(Quant, Vec<usize>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    RuleRef(usize),
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, Value)>,
    pub strings: Vec<StringDef>,
    condition: Expr,
    pub private: bool,
}

// ---- parser -----------------------------------------------------------------

struct Parser<'t> {
    text: &'t [u8],
    pos: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Var(char, String),
    Str(Vec<u8>),
    Int(i64),
    Punct(&'static str),
    Eof,
}

const PUNCTS: &[&str] = &[
    "..", "==", "!=", "<=", ">=", "<", ">", "(", ")", "[", "]", "{", "}", ":", "=", ",", "*", "+", "-", "\\", "%",
];

impl<'t> Parser<'t> {
    fn line(&self) -> usize {
        self.text[..self.pos.min(self.text.len())].iter().filter(|b| **b == b'\n').count() + 1
    }

    fn err(&self, message: impl std::fmt::Display) -> anyhow::Error {
        anyhow!("YARA line {}: {message}", self.line())
    }

    fn skip_ws(&mut self) -> Result<()> {
        loop {
            while self.pos < self.text.len() && self.text[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            if self.text[self.pos..].starts_with(b"//") {
                while self.pos < self.text.len() && self.text[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else if self.text[self.pos..].starts_with(b"/*") {
                let end = self.text[self.pos + 2..]
                    .windows(2)
                    .position(|w| w == b"*/")
                    .ok_or_else(|| self.err("unterminated comment"))?;
                self.pos += end + 4;
            } else {
                return Ok(());
            }
        }
    }

    fn next(&mut self) -> Result<Tok> {
        self.skip_ws()?;
        let Some(&c) = self.text.get(self.pos) else { return Ok(Tok::Eof) };
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = self.pos;
            while self.pos < self.text.len() && (self.text[self.pos].is_ascii_alphanumeric() || self.text[self.pos] == b'_') {
                self.pos += 1;
            }
            return Ok(Tok::Ident(String::from_utf8_lossy(&self.text[start..self.pos]).into_owned()));
        }
        if matches!(c, b'$' | b'#' | b'@' | b'!') && !(c == b'!' && self.text.get(self.pos + 1) == Some(&b'=')) {
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.text.len()
                && (self.text[self.pos].is_ascii_alphanumeric() || self.text[self.pos] == b'_' || self.text[self.pos] == b'*')
            {
                self.pos += 1;
            }
            return Ok(Tok::Var(c as char, String::from_utf8_lossy(&self.text[start..self.pos]).into_owned()));
        }
        if c.is_ascii_digit() {
            let start = self.pos;
            let value = if self.text[self.pos..].starts_with(b"0x") {
                self.pos += 2;
                while self.pos < self.text.len() && self.text[self.pos].is_ascii_hexdigit() {
                    self.pos += 1;
                }
                i64::from_str_radix(std::str::from_utf8(&self.text[start + 2..self.pos])?, 16)
                    .map_err(|_| self.err("bad hex number"))?
            } else {
                while self.pos < self.text.len() && self.text[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                std::str::from_utf8(&self.text[start..self.pos])?
                    .parse::<i64>()
                    .map_err(|_| self.err("bad number"))?
            };
            let multiplier = if self.text[self.pos..].starts_with(b"KB") {
                self.pos += 2;
                1024
            } else if self.text[self.pos..].starts_with(b"MB") {
                self.pos += 2;
                1024 * 1024
            } else {
                1
            };
            return Ok(Tok::Int(value.checked_mul(multiplier).ok_or_else(|| self.err("number overflow"))?));
        }
        if c == b'"' {
            return Ok(Tok::Str(self.text_string()?));
        }
        for punct in PUNCTS {
            if self.text[self.pos..].starts_with(punct.as_bytes()) {
                self.pos += punct.len();
                return Ok(Tok::Punct(punct));
            }
        }
        Err(self.err(format!("unexpected character {:?}", c as char)))
    }

    fn peek(&mut self) -> Result<Tok> {
        let save = self.pos;
        let token = self.next();
        self.pos = save;
        token
    }

    fn expect(&mut self, punct: &str) -> Result<()> {
        match self.next()? {
            Tok::Punct(p) if p == punct => Ok(()),
            other => Err(self.err(format!("expected {punct:?}, found {other:?}"))),
        }
    }

    fn expect_ident(&mut self, word: &str) -> Result<()> {
        match self.next()? {
            Tok::Ident(ident) if ident == word => Ok(()),
            other => Err(self.err(format!("expected {word:?}, found {other:?}"))),
        }
    }

    fn text_string(&mut self) -> Result<Vec<u8>> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.text.get(self.pos).ok_or_else(|| self.err("unterminated string"))?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\n' => return Err(self.err("newline in string")),
                b'\\' => {
                    let e = *self.text.get(self.pos).ok_or_else(|| self.err("bad escape"))?;
                    self.pos += 1;
                    out.push(match e {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        b'\\' => b'\\',
                        b'"' => b'"',
                        b'x' => {
                            let digits = self.text.get(self.pos..self.pos + 2).ok_or_else(|| self.err("bad \\x escape"))?;
                            self.pos += 2;
                            u8::from_str_radix(std::str::from_utf8(digits)?, 16).map_err(|_| self.err("bad \\x escape"))?
                        }
                        other => return Err(self.err(format!("unsupported escape \\{}", other as char))),
                    });
                }
                other => out.push(other),
            }
        }
    }

    fn rules(&mut self) -> Result<Vec<Rule>> {
        let mut rules: Vec<Rule> = Vec::new();
        loop {
            let token = self.next()?;
            let mut private = false;
            let token = match token {
                Tok::Eof => return Ok(rules),
                Tok::Ident(word) if word == "import" || word == "include" => {
                    return Err(self.err(format!("`{word}` is unsupported (no YARA modules/includes in this subset)")));
                }
                Tok::Ident(word) if word == "global" => return Err(self.err("global rules are unsupported")),
                Tok::Ident(word) if word == "private" => {
                    private = true;
                    self.next()?
                }
                other => other,
            };
            if token != Tok::Ident("rule".into()) {
                return Err(self.err(format!("expected `rule`, found {token:?}")));
            }
            let Tok::Ident(name) = self.next()? else { return Err(self.err("expected rule name")) };
            ensure!(!rules.iter().any(|r| r.name == name), self.err(format!("duplicate rule {name}")));
            let mut tags = Vec::new();
            if self.peek()? == Tok::Punct(":") {
                self.next()?;
                while let Tok::Ident(tag) = self.peek()? {
                    self.next()?;
                    tags.push(tag);
                }
            }
            self.expect("{")?;
            let mut meta = Vec::new();
            let mut strings: Vec<StringDef> = Vec::new();
            let mut condition = None;
            loop {
                match self.next()? {
                    Tok::Punct("}") => break,
                    Tok::Ident(section) if section == "meta" => {
                        self.expect(":")?;
                        while let Tok::Ident(key) = self.peek()? {
                            if key == "strings" || key == "condition" {
                                break;
                            }
                            self.next()?;
                            self.expect("=")?;
                            let value = match self.next()? {
                                Tok::Str(bytes) => json!(String::from_utf8_lossy(&bytes)),
                                Tok::Int(n) => json!(n),
                                Tok::Punct("-") => match self.next()? {
                                    Tok::Int(n) => json!(-n),
                                    other => return Err(self.err(format!("bad meta value {other:?}"))),
                                },
                                Tok::Ident(b) if b == "true" || b == "false" => json!(b == "true"),
                                other => return Err(self.err(format!("bad meta value {other:?}"))),
                            };
                            meta.push((key, value));
                        }
                    }
                    Tok::Ident(section) if section == "strings" => {
                        self.expect(":")?;
                        while let Tok::Var('$', id) = self.peek()? {
                            self.next()?;
                            let id = if id.is_empty() { format!("anon{}", strings.len()) } else { id };
                            ensure!(!id.contains('*'), self.err("`*` is not allowed in a string identifier"));
                            ensure!(!strings.iter().any(|s| s.id == id), self.err(format!("duplicate string ${id}")));
                            self.expect("=")?;
                            strings.push(self.string_def(id)?);
                        }
                    }
                    Tok::Ident(section) if section == "condition" => {
                        self.expect(":")?;
                        let scope = Scope { strings: &strings, rules: &rules };
                        condition = Some(self.expr(&scope)?);
                    }
                    other => return Err(self.err(format!("unexpected {other:?} in rule {name}"))),
                }
            }
            let condition = condition.ok_or_else(|| self.err(format!("rule {name} has no condition")))?;
            rules.push(Rule { name, tags, meta, strings, condition, private });
        }
    }

    fn string_def(&mut self, id: String) -> Result<StringDef> {
        self.skip_ws()?;
        let c = *self.text.get(self.pos).ok_or_else(|| self.err("missing string value"))?;
        let (kind, body) = match c {
            b'"' => ("text", self.text_string()?),
            b'{' => {
                let end = self.text[self.pos..]
                    .iter()
                    .position(|b| *b == b'}')
                    .ok_or_else(|| self.err("unterminated hex string"))?;
                let body = self.text[self.pos + 1..self.pos + end].to_vec();
                self.pos += end + 1;
                ("hex", body)
            }
            b'/' => {
                self.pos += 1;
                let mut body = Vec::new();
                loop {
                    let c = *self.text.get(self.pos).ok_or_else(|| self.err("unterminated regex"))?;
                    self.pos += 1;
                    match c {
                        b'/' => break,
                        b'\n' => return Err(self.err("newline in regex")),
                        b'\\' => {
                            let next = *self.text.get(self.pos).ok_or_else(|| self.err("bad regex escape"))?;
                            self.pos += 1;
                            if next != b'/' {
                                body.push(b'\\');
                            }
                            body.push(next);
                        }
                        other => body.push(other),
                    }
                }
                ("regex", body)
            }
            _ => return Err(self.err("string value must be \"text\", { hex } or /regex/")),
        };
        let mut flags = String::new();
        if kind == "regex" {
            while let Some(&f) = self.text.get(self.pos) {
                match f {
                    b'i' | b's' => flags.push(f as char),
                    _ => break,
                }
                self.pos += 1;
            }
        }
        let mut modifiers: HashSet<String> = HashSet::new();
        while let Tok::Ident(word) = self.peek()? {
            match word.as_str() {
                "nocase" | "wide" | "ascii" | "fullword" | "private" => {
                    self.next()?;
                    modifiers.insert(word);
                }
                "xor" | "base64" | "base64wide" => return Err(self.err(format!("modifier `{word}` is unsupported"))),
                _ => break,
            }
        }
        let nocase = modifiers.contains("nocase");
        let wide = modifiers.contains("wide");
        let ascii = modifiers.contains("ascii") || !wide;
        let pattern = match kind {
            "text" => {
                ensure!(!body.is_empty(), self.err("empty text string"));
                let narrow: String = body.iter().map(|b| format!("\\x{b:02x}")).collect();
                let widened: String = body.iter().map(|b| format!("\\x{b:02x}\\x00")).collect();
                let core = match (ascii, wide) {
                    (true, true) => format!("(?:{narrow}|{widened})"),
                    (false, true) => widened,
                    _ => narrow,
                };
                format!("(?s-u){}{core}", if nocase { "(?i)" } else { "" })
            }
            "hex" => {
                ensure!(!nocase && !wide && !modifiers.contains("fullword"), self.err("hex strings only accept `private`"));
                format!("(?s-u){}", hex_to_regex(&body).map_err(|e| self.err(e))?)
            }
            _ => {
                ensure!(!wide, self.err("`wide` on regular expressions is unsupported"));
                let body = String::from_utf8(body).map_err(|_| self.err("regex is not UTF-8"))?;
                let mut prefix = String::from("(?-u");
                if nocase || flags.contains('i') {
                    prefix.push('i');
                }
                if flags.contains('s') {
                    prefix.push('s');
                }
                format!("{prefix}){body}")
            }
        };
        let regex = regex::bytes::RegexBuilder::new(&pattern)
            .size_limit(8 << 20)
            .build()
            .map_err(|e| self.err(format!("cannot compile ${id}: {e}")))?;
        Ok(StringDef { id, regex, fullword: modifiers.contains("fullword"), wide, private: modifiers.contains("private") })
    }

    fn expr(&mut self, scope: &Scope) -> Result<Expr> {
        let mut left = self.and_expr(scope)?;
        while self.peek()? == Tok::Ident("or".into()) {
            self.next()?;
            left = Expr::Or(Box::new(left), Box::new(self.and_expr(scope)?));
        }
        Ok(left)
    }

    fn and_expr(&mut self, scope: &Scope) -> Result<Expr> {
        let mut left = self.not_expr(scope)?;
        while self.peek()? == Tok::Ident("and".into()) {
            self.next()?;
            left = Expr::And(Box::new(left), Box::new(self.not_expr(scope)?));
        }
        Ok(left)
    }

    fn not_expr(&mut self, scope: &Scope) -> Result<Expr> {
        if self.peek()? == Tok::Ident("not".into()) {
            self.next()?;
            return Ok(Expr::Not(Box::new(self.not_expr(scope)?)));
        }
        let left = self.additive(scope)?;
        if let Tok::Punct(op @ ("==" | "!=" | "<" | "<=" | ">" | ">=")) = self.peek()? {
            self.next()?;
            let right = self.additive(scope)?;
            return Ok(Expr::Bin(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    fn additive(&mut self, scope: &Scope) -> Result<Expr> {
        let mut left = self.term(scope)?;
        while let Tok::Punct(op @ ("+" | "-")) = self.peek()? {
            self.next()?;
            left = Expr::Bin(op, Box::new(left), Box::new(self.term(scope)?));
        }
        Ok(left)
    }

    fn term(&mut self, scope: &Scope) -> Result<Expr> {
        let mut left = self.unary(scope)?;
        while let Tok::Punct(op @ ("*" | "\\" | "%")) = self.peek()? {
            self.next()?;
            left = Expr::Bin(op, Box::new(left), Box::new(self.unary(scope)?));
        }
        Ok(left)
    }

    fn unary(&mut self, scope: &Scope) -> Result<Expr> {
        if self.peek()? == Tok::Punct("-") {
            self.next()?;
            return Ok(Expr::Neg(Box::new(self.unary(scope)?)));
        }
        self.primary(scope)
    }

    fn range(&mut self, scope: &Scope) -> Result<(Box<Expr>, Box<Expr>)> {
        self.expect("(")?;
        let low = self.additive(scope)?;
        self.expect("..")?;
        let high = self.additive(scope)?;
        self.expect(")")?;
        Ok((Box::new(low), Box::new(high)))
    }

    fn index(&mut self, scope: &Scope) -> Result<Box<Expr>> {
        if self.peek()? == Tok::Punct("[") {
            self.next()?;
            let index = self.additive(scope)?;
            self.expect("]")?;
            Ok(Box::new(index))
        } else {
            Ok(Box::new(Expr::Int(1)))
        }
    }

    fn primary(&mut self, scope: &Scope) -> Result<Expr> {
        let token = self.next()?;
        match token {
            Tok::Punct("(") => {
                let inner = self.expr(scope)?;
                self.expect(")")?;
                Ok(inner)
            }
            Tok::Int(n) => match self.peek()? {
                Tok::Ident(word) if word == "of" => self.of(Quant::Count(Box::new(Expr::Int(n))), scope),
                Tok::Punct("%") => {
                    let save = self.pos;
                    self.next()?;
                    if self.peek()? == Tok::Ident("of".into()) {
                        self.of(Quant::Percent(Box::new(Expr::Int(n))), scope)
                    } else {
                        self.pos = save;
                        Ok(Expr::Int(n))
                    }
                }
                _ => Ok(Expr::Int(n)),
            },
            Tok::Var(sigil, id) => {
                let index = scope.string(&id).map_err(|e| self.err(e))?;
                match sigil {
                    '$' => match self.peek()? {
                        Tok::Ident(word) if word == "at" => {
                            self.next()?;
                            Ok(Expr::StrAt(index, Box::new(self.additive(scope)?)))
                        }
                        Tok::Ident(word) if word == "in" => {
                            self.next()?;
                            let (low, high) = self.range(scope)?;
                            Ok(Expr::StrIn(index, low, high))
                        }
                        _ => Ok(Expr::Str(index)),
                    },
                    '#' => {
                        if self.peek()? == Tok::Ident("in".into()) {
                            self.next()?;
                            let (low, high) = self.range(scope)?;
                            Ok(Expr::CountIn(index, low, high))
                        } else {
                            Ok(Expr::Count(index))
                        }
                    }
                    '@' => Ok(Expr::Offset(index, self.index(scope)?)),
                    _ => Ok(Expr::Length(index, self.index(scope)?)),
                }
            }
            Tok::Ident(word) => match word.as_str() {
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                "filesize" => Ok(Expr::Filesize),
                "all" => self.of(Quant::All, scope),
                "any" => self.of(Quant::Any, scope),
                "none" => self.of(Quant::None, scope),
                "for" => Err(self.err("`for` loops are unsupported")),
                "entrypoint" | "defined" | "matches" | "contains" => Err(self.err(format!("`{word}` is unsupported"))),
                w if w.starts_with("uint") || w.starts_with("int") => {
                    Err(self.err(format!("`{w}()` data reads are unsupported")))
                }
                _ => {
                    let index = scope
                        .rules
                        .iter()
                        .position(|rule| rule.name == word)
                        .ok_or_else(|| self.err(format!("unknown identifier `{word}` (rules must be defined before use)")))?;
                    Ok(Expr::RuleRef(index))
                }
            },
            other => Err(self.err(format!("unexpected {other:?} in condition"))),
        }
    }

    fn of(&mut self, quant: Quant, scope: &Scope) -> Result<Expr> {
        self.expect_ident("of")?;
        let set = match self.next()? {
            Tok::Ident(word) if word == "them" => (0..scope.strings.len()).collect(),
            Tok::Punct("(") => {
                let mut set = Vec::new();
                loop {
                    match self.next()? {
                        Tok::Var('$', pattern) => {
                            let found = scope.matching(&pattern);
                            ensure!(!found.is_empty(), self.err(format!("${pattern} matches no string")));
                            set.extend(found);
                        }
                        other => return Err(self.err(format!("expected $string in set, found {other:?}"))),
                    }
                    match self.next()? {
                        Tok::Punct(",") => continue,
                        Tok::Punct(")") => break,
                        other => return Err(self.err(format!("expected , or ) in set, found {other:?}"))),
                    }
                }
                set.sort_unstable();
                set.dedup();
                set
            }
            other => return Err(self.err(format!("expected `them` or a string set, found {other:?}"))),
        };
        ensure!(!set.is_empty(), self.err("`of them` used in a rule without strings"));
        Ok(Expr::Of(quant, set))
    }
}

struct Scope<'s> {
    strings: &'s [StringDef],
    rules: &'s [Rule],
}

impl Scope<'_> {
    fn string(&self, id: &str) -> std::result::Result<usize, String> {
        ensure_plain(id)?;
        self.strings
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| format!("undefined string ${id}"))
    }

    fn matching(&self, pattern: &str) -> Vec<usize> {
        match pattern.strip_suffix('*') {
            Some(prefix) => self
                .strings
                .iter()
                .enumerate()
                .filter(|(_, s)| s.id.starts_with(prefix))
                .map(|(i, _)| i)
                .collect(),
            None => self.strings.iter().position(|s| s.id == pattern).into_iter().collect(),
        }
    }
}

fn ensure_plain(id: &str) -> std::result::Result<(), String> {
    if id.is_empty() || id.contains('*') {
        Err(format!("`${id}` is not a single string identifier here"))
    } else {
        Ok(())
    }
}

/// Translate a YARA hex string body into a byte regex.
fn hex_to_regex(body: &[u8]) -> std::result::Result<String, String> {
    let text: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = String::new();
    let mut i = 0;
    let mut depth = 0usize;
    let mut tokens = 0usize;
    while i < text.len() {
        let c = text[i];
        match c {
            b'(' => {
                depth += 1;
                out.push_str("(?:");
                i += 1;
            }
            b'|' => {
                if depth == 0 {
                    return Err("`|` outside of an alternative group".into());
                }
                out.push('|');
                i += 1;
            }
            b')' => {
                if depth == 0 {
                    return Err("unbalanced `)` in hex string".into());
                }
                depth -= 1;
                out.push(')');
                i += 1;
            }
            b'[' => {
                let end = text[i..].iter().position(|b| *b == b']').ok_or("unterminated jump")? + i;
                let jump = std::str::from_utf8(&text[i + 1..end]).map_err(|_| "bad jump")?;
                let (low, high) = match jump.split_once('-') {
                    Some((_, "")) => return Err("unbounded jumps `[n-]` are unsupported".into()),
                    Some((low, high)) => (
                        if low.is_empty() { 0 } else { low.parse::<u32>().map_err(|_| "bad jump")? },
                        high.parse::<u32>().map_err(|_| "bad jump")?,
                    ),
                    None => {
                        let n = jump.parse::<u32>().map_err(|_| "bad jump")?;
                        (n, n)
                    }
                };
                if low > high || high > 65536 {
                    return Err(format!("invalid jump [{jump}] (max 65536)"));
                }
                out.push_str(&format!(".{{{low},{high}}}"));
                i = end + 1;
            }
            b'~' => {
                let pair = text.get(i + 1..i + 3).ok_or("truncated ~ byte")?;
                let value = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "bad byte")?, 16)
                    .map_err(|_| "`~` only supports a full byte (~XX)")?;
                out.push_str(&format!("[^\\x{value:02x}]"));
                tokens += 1;
                i += 3;
            }
            _ => {
                let pair = text.get(i..i + 2).ok_or("odd number of hex digits")?;
                let nibble = |n: u8| -> std::result::Result<Option<u8>, String> {
                    match n {
                        b'?' => Ok(None),
                        _ => (n as char).to_digit(16).map(|d| Some(d as u8)).ok_or_else(|| format!("bad hex digit {:?}", n as char)),
                    }
                };
                match (nibble(pair[0])?, nibble(pair[1])?) {
                    (Some(h), Some(l)) => out.push_str(&format!("\\x{:02x}", h << 4 | l)),
                    (None, None) => out.push('.'),
                    (Some(h), None) => out.push_str(&format!("[\\x{:02x}-\\x{:02x}]", h << 4, h << 4 | 0xf)),
                    (None, Some(l)) => {
                        out.push('[');
                        for h in 0..16u8 {
                            out.push_str(&format!("\\x{:02x}", h << 4 | l));
                        }
                        out.push(']');
                    }
                }
                tokens += 1;
                i += 2;
            }
        }
    }
    if depth != 0 {
        return Err("unbalanced `(` in hex string".into());
    }
    if tokens == 0 {
        return Err("empty hex string".into());
    }
    Ok(out)
}

pub fn compile(text: &str) -> Result<Vec<Rule>> {
    let mut parser = Parser { text: text.as_bytes(), pos: 0 };
    let rules = parser.rules()?;
    ensure!(!rules.is_empty(), "No rules found");
    Ok(rules)
}

// ---- evaluation ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Val {
    Int(i64),
    Bool(bool),
    Undef,
}

impl Val {
    fn truthy(self) -> bool {
        match self {
            Val::Bool(b) => b,
            Val::Int(n) => n != 0,
            Val::Undef => false,
        }
    }
    fn int(self) -> Option<i64> {
        match self {
            Val::Int(n) => Some(n),
            Val::Bool(b) => Some(b as i64),
            Val::Undef => None,
        }
    }
}

/// Matches of one rule's strings: per string, sorted `(offset, length)`.
struct Ctx<'c> {
    matches: &'c [Vec<(u64, usize)>],
    filesize: i64,
    rule_results: &'c [bool],
}

fn eval(expr: &Expr, ctx: &Ctx) -> Val {
    let int = |e: &Expr| eval(e, ctx).int();
    match expr {
        Expr::Bool(b) => Val::Bool(*b),
        Expr::Int(n) => Val::Int(*n),
        Expr::Filesize => Val::Int(ctx.filesize),
        Expr::Str(i) => Val::Bool(!ctx.matches[*i].is_empty()),
        Expr::StrAt(i, at) => match int(at) {
            Some(at) => Val::Bool(ctx.matches[*i].iter().any(|m| m.0 as i64 == at)),
            None => Val::Undef,
        },
        Expr::StrIn(i, low, high) => match (int(low), int(high)) {
            (Some(l), Some(h)) => Val::Bool(ctx.matches[*i].iter().any(|m| (l..=h).contains(&(m.0 as i64)))),
            _ => Val::Undef,
        },
        Expr::Count(i) => Val::Int(ctx.matches[*i].len() as i64),
        Expr::CountIn(i, low, high) => match (int(low), int(high)) {
            (Some(l), Some(h)) => Val::Int(ctx.matches[*i].iter().filter(|m| (l..=h).contains(&(m.0 as i64))).count() as i64),
            _ => Val::Undef,
        },
        Expr::Offset(i, k) | Expr::Length(i, k) => {
            let Some(k) = int(k) else { return Val::Undef };
            if k < 1 {
                return Val::Undef;
            }
            match ctx.matches[*i].get(k as usize - 1) {
                Some(m) if matches!(expr, Expr::Offset(..)) => Val::Int(m.0 as i64),
                Some(m) => Val::Int(m.1 as i64),
                None => Val::Undef,
            }
        }
        Expr::Of(quant, set) => {
            let hits = set.iter().filter(|i| !ctx.matches[**i].is_empty()).count() as i64;
            let total = set.len() as i64;
            Val::Bool(match quant {
                Quant::All => hits == total,
                Quant::Any => hits >= 1,
                Quant::None => hits == 0,
                Quant::Count(n) => int(n).is_some_and(|n| hits >= n),
                Quant::Percent(p) => int(p).is_some_and(|p| hits * 100 >= p * total),
            })
        }
        Expr::And(a, b) => Val::Bool(eval(a, ctx).truthy() && eval(b, ctx).truthy()),
        Expr::Or(a, b) => Val::Bool(eval(a, ctx).truthy() || eval(b, ctx).truthy()),
        Expr::Not(a) => match eval(a, ctx) {
            Val::Undef => Val::Undef,
            v => Val::Bool(!v.truthy()),
        },
        Expr::Neg(a) => int(a).map_or(Val::Undef, |n| Val::Int(n.wrapping_neg())),
        Expr::RuleRef(i) => Val::Bool(ctx.rule_results.get(*i).copied().unwrap_or(false)),
        Expr::Bin(op, a, b) => {
            let (Some(x), Some(y)) = (int(a), int(b)) else { return Val::Undef };
            match *op {
                "==" => Val::Bool(x == y),
                "!=" => Val::Bool(x != y),
                "<" => Val::Bool(x < y),
                "<=" => Val::Bool(x <= y),
                ">" => Val::Bool(x > y),
                ">=" => Val::Bool(x >= y),
                "+" => Val::Int(x.wrapping_add(y)),
                "-" => Val::Int(x.wrapping_sub(y)),
                "*" => Val::Int(x.wrapping_mul(y)),
                "\\" => x.checked_div(y).map_or(Val::Undef, Val::Int),
                "%" => x.checked_rem(y).map_or(Val::Undef, Val::Int),
                _ => Val::Undef,
            }
        }
    }
}

fn is_word(byte: Option<&u8>) -> bool {
    byte.is_some_and(|b| b.is_ascii_alphanumeric())
}

/// Scan `source` (its selection) and evaluate every rule once over the target.
pub fn scan(rules: &[Rule], source: &mut Source, max_matches: usize) -> Result<Value> {
    let target_start = match source.kind {
        "artifact-file" => 0,
        _ => source.selection.iter().map(|r| r.0).min().unwrap_or(0),
    };
    let filesize: u64 = match source.kind {
        "artifact-file" => source.file_size,
        _ => source.selection.iter().map(|(s, e)| e - s).sum(),
    };
    // (rule, string) -> matches (va, len, preview)
    let mut found: Vec<Vec<Vec<(u64, usize, String)>>> =
        rules.iter().map(|r| r.strings.iter().map(|_| Vec::new()).collect()).collect();
    let mut seen: HashSet<(usize, usize, u64)> = HashSet::new();
    let mut truncated = false;
    source.scan(None, CHUNK_OVERLAP, |va, chunk| {
        for (ri, rule) in rules.iter().enumerate() {
            for (si, string) in rule.strings.iter().enumerate() {
                let mut pos = 0;
                while pos < chunk.len() {
                    let Some(m) = string.regex.find_at(chunk, pos) else { break };
                    pos = m.start() + 1;
                    if string.fullword {
                        let step = if string.wide { 2 } else { 1 };
                        let before = m.start().checked_sub(step).and_then(|i| chunk.get(i));
                        if is_word(before) || is_word(chunk.get(m.end())) {
                            continue;
                        }
                    }
                    let address = va + m.start() as u64;
                    if !seen.insert((ri, si, address)) {
                        continue;
                    }
                    if found[ri][si].len() >= MAX_MATCHES_PER_STRING {
                        truncated = true;
                        break;
                    }
                    let preview = hex::encode(&m.as_bytes()[..m.len().min(32)]);
                    found[ri][si].push((address, m.len(), preview));
                }
            }
        }
        true
    })?;
    let mut results = Vec::new();
    let mut rule_results = Vec::new();
    let mut reported = 0usize;
    for (ri, rule) in rules.iter().enumerate() {
        for list in &mut found[ri] {
            list.sort_unstable_by_key(|m| m.0);
        }
        let offsets: Vec<Vec<(u64, usize)>> = found[ri]
            .iter()
            .map(|list| list.iter().map(|(va, len, _)| (va - target_start, *len)).collect())
            .collect();
        let ctx = Ctx { matches: &offsets, filesize: filesize as i64, rule_results: &rule_results };
        let hit = eval(&rule.condition, &ctx).truthy();
        rule_results.push(hit);
        if !hit || rule.private {
            continue;
        }
        let mut strings = Vec::new();
        for (si, string) in rule.strings.iter().enumerate() {
            if string.private {
                continue;
            }
            for (va, len, preview) in &found[ri][si] {
                if reported >= max_matches {
                    truncated = true;
                    break;
                }
                reported += 1;
                let mut entry = source.describe(*va);
                entry["string"] = json!(format!("${}", string.id));
                entry["target_offset"] = json!(format!("{:#x}", va - target_start));
                entry["length"] = json!(len);
                entry["data"] = json!(preview);
                strings.push(entry);
            }
        }
        results.push(json!({
            "rule": rule.name, "tags": rule.tags,
            "meta": rule.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<serde_json::Map<_, _>>(),
            "strings": strings,
        }));
    }
    Ok(json!({
        "matched_rules": results,
        "rules_evaluated": rules.len(),
        "filesize": filesize,
        "target_start": format!("{target_start:#x}"),
        "matches_truncated": truncated,
    }))
}

pub fn run(workbench: &mut Workbench, args: &Value) -> Result<Value> {
    let text = match (args["rules"].as_str(), args["rules_artifact"].as_str()) {
        (Some(text), None) => text.to_owned(),
        (None, Some(artifact)) => String::from_utf8(workbench.read_artifact(artifact, MAX_RULES_TEXT)?)
            .context("Rules artifact is not UTF-8")?,
        _ => bail!("Give exactly one of rules or rules_artifact"),
    };
    ensure!(text.len() <= MAX_RULES_TEXT, "Rules text exceeds 1 MiB");
    let rules = compile(&text)?;
    let spec = TargetSpec::from_args(args, "artifact", "module")?;
    ensure!(spec.is_specified(), "Give an artifact or a pid target");
    if spec.pid.is_some() {
        ensure!(spec.module.is_some() || spec.address.is_some(), "Live scans need a module or an address/length range");
    }
    let max_matches = args["max_matches"].as_u64().unwrap_or(1000) as usize;
    let mut source = Source::open(workbench, &spec, Mode::File)?;
    let mut result = scan(&rules, &mut source, max_matches)?;
    result["source"] = source.summary();
    result["engine"] = json!({
        "name": "ps4wb-yara-subset",
        "notes": [
            "Overlapping matches are reported per start offset (capped per string).",
            format!("Live chunks overlap by {CHUNK_OVERLAP} bytes; longer matches across chunk boundaries can be missed."),
            "Offsets in conditions are relative to the target start (file offset 0, or the first selected live range).",
        ],
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_rules(text: &str, data: &[u8]) -> Value {
        let rules = compile(text).unwrap();
        let mut source = Source::from_file("t", data.to_vec());
        scan(&rules, &mut source, 100).unwrap()
    }

    fn names(result: &Value) -> Vec<String> {
        result["matched_rules"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap().to_owned()).collect()
    }

    #[test]
    fn strings_modifiers_and_conditions() {
        let data = b"MZ\x90\x00 hello World! H\x00E\x00L\x00L\x00O\x00 xx\x01\x02\x03\x02yy secret=42 helloworld";
        let rules = r#"
            rule text_any : tag1 tag2 { meta: author = "t" score = 5 ok = true
              strings: $a = "hello" $b = "nothere" condition: any of them }
            rule text_all { strings: $a = "hello" $b = "world" nocase condition: all of them and #a == 2 }
            rule wide_nocase { strings: $w = "hello" wide nocase condition: $w }
            rule hexy { strings: $h = { 4D 5A ?? [0-2] 20 } $j = { 01 ( 02 | 05 ) 0? [1] 79 } condition: $h at 0 and $j }
            rule regex_rule { strings: $r = /secret=[0-9]+/ condition: $r and @r[1] > 10 and !r[1] == 9 }
            rule fullword_rule { strings: $f = "hello" fullword condition: #f == 1 }
            rule counts { strings: $a1 = "hello" $a2 = "World" $b = "zzz" condition: 2 of ($a*) and not $b and filesize < 1KB }
            private rule hidden { strings: $m = "MZ" condition: $m }
            rule uses_hidden { condition: hidden and (filesize > 10) }
            rule percent { strings: $a = "MZ" $b = "nope" condition: 50% of them }
            rule none_rule { strings: $a = "absent" condition: none of them }
            rule failing { strings: $a = "hello" condition: #a > 5 }
            rule in_range { strings: $a = "hello" condition: $a in (0..10) and #a in (0..100) == 2 }
        "#;
        let result = run_rules(rules, data);
        let names = names(&result);
        for expected in [
            "text_any", "text_all", "wide_nocase", "hexy", "regex_rule", "fullword_rule", "counts", "uses_hidden",
            "percent", "none_rule", "in_range",
        ] {
            assert!(names.contains(&expected.to_owned()), "{expected} missing from {names:?}");
        }
        assert!(!names.contains(&"hidden".to_owned()));
        assert!(!names.contains(&"failing".to_owned()));
        let first = &result["matched_rules"][0];
        assert_eq!(first["tags"], json!(["tag1", "tag2"]));
        assert_eq!(first["meta"]["score"], 5);
        assert_eq!(first["strings"][0]["offset"], "0x5");
    }

    #[test]
    fn unsupported_syntax_errors() {
        for (text, needle) in [
            ("import \"pe\" rule a { condition: true }", "unsupported"),
            ("rule a { strings: $a = \"x\" xor condition: $a }", "xor"),
            ("rule a { strings: $a = { 01 [2-] 02 } condition: $a }", "unbounded"),
            ("rule a { condition: for any i in (1..2) : (true) }", "for"),
            ("rule a { condition: uint16(0) == 0x5a4d }", "uint16"),
            ("rule a { condition: $x }", "undefined"),
            ("rule a { strings: $a = \"x\" condition: b }", "unknown identifier"),
            ("global rule a { condition: true }", "global"),
        ] {
            let error = compile(text).unwrap_err().to_string();
            assert!(error.contains(needle), "{text}: {error}");
        }
    }

    #[test]
    fn hex_translation() {
        assert_eq!(hex_to_regex(b"4D 5A").unwrap(), "\\x4d\\x5a");
        assert_eq!(hex_to_regex(b"4? ??").unwrap(), "[\\x40-\\x4f].");
        assert!(hex_to_regex(b"4").is_err());
        assert!(hex_to_regex(b"(01").is_err());
        assert_eq!(hex_to_regex(b"~00 [2]").unwrap(), "[^\\x00].{2,2}");
    }
}
