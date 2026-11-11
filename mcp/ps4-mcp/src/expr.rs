//! x64dbg-style expression evaluator for breakpoint conditions and `debug_eval`.
//!
//! Grammar (C precedence, unsigned 64-bit wrapping arithmetic):
//! numbers (`0x1f`, `42`), registers (`rax`, `eax`, `al`, `rip`, flags `zf`...),
//! symbols (`eboot.bin`, user labels), memory (`[rsp+8]`, `dword [rax]`),
//! unary `- ~ !`, `* / %`, `+ -`, `<< >>`, `< <= > >=`, `== !=`, `& ^ |`, `&& ||`.
//! Comparisons are unsigned. Evaluation is bounded: expression length, nesting
//! depth and the number of memory reads per evaluation are all capped.

use crate::Result;
use anyhow::{bail, ensure};

pub const MAX_EXPRESSION: usize = 512;
const MAX_DEPTH: usize = 32;
pub const MAX_MEMORY_READS: usize = 16;

pub trait Context {
    /// `None` means "not a register name" (fall through to symbol lookup).
    fn register(&mut self, name: &str) -> Result<Option<u64>>;
    fn symbol(&mut self, name: &str) -> Result<Option<u64>>;
    fn read(&mut self, address: u64, size: usize) -> Result<u64>;
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(u64),
    Name(String),
    Op(&'static str),
    Size(usize),
}

const OPERATORS: [&str; 24] = [
    "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", "&", "|", "^", "~",
    "!", "<", ">", "(", ")", "[", "]",
];

fn tokenize(text: &str) -> Result<Vec<Token>> {
    ensure!(text.len() <= MAX_EXPRESSION, "Expression too long");
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let character = bytes[index];
        if character.is_ascii_whitespace() {
            index += 1;
        } else if character.is_ascii_digit() {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            let literal = text[start..index].replace('_', "");
            let value = if let Some(hex) = literal.strip_prefix("0x").or(literal.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16)
            } else {
                literal.parse()
            };
            tokens.push(Token::Number(
                value.map_err(|_| anyhow::anyhow!("Invalid number: {literal}"))?,
            ));
        } else if character.is_ascii_alphabetic() || matches!(character, b'_' | b'$' | b'@') {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.' | b'$' | b'@'))
            {
                index += 1;
            }
            let name = &text[start..index];
            tokens.push(match name.to_ascii_lowercase().as_str() {
                "byte" => Token::Size(1),
                "word" => Token::Size(2),
                "dword" => Token::Size(4),
                "qword" => Token::Size(8),
                _ => Token::Name(name.to_owned()),
            });
        } else {
            let rest = &text[index..];
            let Some(operator) = OPERATORS.iter().find(|operator| rest.starts_with(**operator)) else {
                bail!("Unexpected character {:?} in expression", rest.chars().next().unwrap());
            };
            tokens.push(Token::Op(operator));
            index += operator.len();
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    position: usize,
    context: &'a mut dyn Context,
    reads: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn accept(&mut self, operator: &str) -> bool {
        if matches!(self.peek(), Some(Token::Op(found)) if *found == operator) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn binary(
        &mut self,
        depth: usize,
        operators: &[&str],
        next: fn(&mut Self, usize) -> Result<u64>,
        apply: fn(&str, u64, u64) -> Result<u64>,
    ) -> Result<u64> {
        let mut left = next(self, depth)?;
        'outer: loop {
            for operator in operators {
                if self.accept(operator) {
                    let right = next(self, depth)?;
                    left = apply(operator, left, right)?;
                    continue 'outer;
                }
            }
            return Ok(left);
        }
    }

    fn logical_or(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["||"], Self::logical_and, |_, a, b| Ok(u64::from(a != 0 || b != 0)))
    }
    fn logical_and(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["&&"], Self::bit_or, |_, a, b| Ok(u64::from(a != 0 && b != 0)))
    }
    fn bit_or(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["|"], Self::bit_xor, |_, a, b| Ok(a | b))
    }
    fn bit_xor(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["^"], Self::bit_and, |_, a, b| Ok(a ^ b))
    }
    fn bit_and(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["&"], Self::equality, |_, a, b| Ok(a & b))
    }
    fn equality(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["==", "!="], Self::relational, |op, a, b| {
            Ok(u64::from((op == "==") == (a == b)))
        })
    }
    fn relational(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["<=", ">=", "<", ">"], Self::shift, |op, a, b| {
            Ok(u64::from(match op {
                "<=" => a <= b,
                ">=" => a >= b,
                "<" => a < b,
                _ => a > b,
            }))
        })
    }
    fn shift(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["<<", ">>"], Self::additive, |op, a, b| {
            let amount = u32::try_from(b).unwrap_or(u32::MAX);
            Ok(if amount >= 64 {
                0
            } else if op == "<<" {
                a << amount
            } else {
                a >> amount
            })
        })
    }
    fn additive(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["+", "-"], Self::multiplicative, |op, a, b| {
            Ok(if op == "+" { a.wrapping_add(b) } else { a.wrapping_sub(b) })
        })
    }
    fn multiplicative(&mut self, depth: usize) -> Result<u64> {
        self.binary(depth, &["*", "/", "%"], Self::unary, |op, a, b| match op {
            "*" => Ok(a.wrapping_mul(b)),
            _ => {
                ensure!(b != 0, "Division by zero in expression");
                Ok(if op == "/" { a / b } else { a % b })
            }
        })
    }

    fn unary(&mut self, depth: usize) -> Result<u64> {
        ensure!(depth < MAX_DEPTH, "Expression nested too deeply");
        if self.accept("-") {
            return Ok(self.unary(depth + 1)?.wrapping_neg());
        }
        if self.accept("~") {
            return Ok(!self.unary(depth + 1)?);
        }
        if self.accept("!") {
            return Ok(u64::from(self.unary(depth + 1)? == 0));
        }
        self.primary(depth + 1)
    }

    fn memory(&mut self, size: usize, depth: usize) -> Result<u64> {
        let address = self.logical_or(depth)?;
        ensure!(self.accept("]"), "Missing ] in expression");
        self.reads += 1;
        ensure!(
            self.reads <= MAX_MEMORY_READS,
            "Expression exceeds {MAX_MEMORY_READS} memory reads"
        );
        self.context.read(address, size)
    }

    fn primary(&mut self, depth: usize) -> Result<u64> {
        ensure!(depth < MAX_DEPTH, "Expression nested too deeply");
        let token = self.peek().cloned();
        self.position += usize::from(token.is_some());
        match token {
            Some(Token::Number(value)) => Ok(value),
            Some(Token::Op("(")) => {
                let value = self.logical_or(depth)?;
                ensure!(self.accept(")"), "Missing ) in expression");
                Ok(value)
            }
            Some(Token::Op("[")) => self.memory(8, depth),
            Some(Token::Size(size)) => {
                ensure!(self.accept("["), "Size prefix must be followed by [");
                self.memory(size, depth)
            }
            Some(Token::Name(name)) => {
                if let Some(value) = self.context.register(&name.to_ascii_lowercase())? {
                    return Ok(value);
                }
                match self.context.symbol(&name)? {
                    Some(value) => Ok(value),
                    None => bail!("Unknown register or symbol: {name}"),
                }
            }
            Some(other) => bail!("Unexpected token in expression: {other:?}"),
            None => bail!("Unexpected end of expression"),
        }
    }
}

pub fn eval(text: &str, context: &mut dyn Context) -> Result<u64> {
    let tokens = tokenize(text)?;
    ensure!(!tokens.is_empty(), "Empty expression");
    let mut parser = Parser {
        tokens,
        position: 0,
        context,
        reads: 0,
    };
    let value = parser.logical_or(0)?;
    ensure!(
        parser.position == parser.tokens.len(),
        "Unexpected trailing input in expression"
    );
    Ok(value)
}

/// Syntax-only check (no register, symbol or memory access).
pub fn validate(text: &str) -> Result<()> {
    struct Dry;
    impl Context for Dry {
        fn register(&mut self, _: &str) -> Result<Option<u64>> {
            Ok(Some(1))
        }
        fn symbol(&mut self, _: &str) -> Result<Option<u64>> {
            Ok(Some(1))
        }
        fn read(&mut self, _: u64, _: usize) -> Result<u64> {
            Ok(1)
        }
    }
    // Division by a dry-run value of 1 never fails, so this checks syntax only.
    eval(text, &mut Dry).map(|_| ())
}

const GP64: [(&str, usize); 15] = [
    ("r15", 0), ("r14", 8), ("r13", 16), ("r12", 24), ("r11", 32), ("r10", 40), ("r9", 48),
    ("r8", 56), ("rdi", 64), ("rsi", 72), ("rbp", 80), ("rbx", 88), ("rdx", 96), ("rcx", 104),
    ("rax", 112),
];

/// Byte offsets inside the 176-byte `PT_GETREGS` block (FreeBSD `struct reg`).
pub const RIP_OFFSET: usize = 136;
pub const RFLAGS_OFFSET: usize = 152;
pub const RSP_OFFSET: usize = 160;

/// Architectural register reader over a raw 176-byte GP block.
pub struct RegisterFile<'a>(pub &'a [u8]);

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Offset of a full 64-bit register in the block (`rip`, `rsp`, `rflags` included).
pub fn offset_of(name: &str) -> Option<usize> {
    GP64.iter()
        .find(|(register, _)| *register == name)
        .map(|(_, offset)| *offset)
        .or(match name {
            "rip" => Some(RIP_OFFSET),
            "rflags" | "eflags" => Some(RFLAGS_OFFSET),
            "rsp" => Some(RSP_OFFSET),
            _ => None,
        })
}

impl RegisterFile<'_> {
    pub fn get(&self, name: &str) -> Option<u64> {
        if self.0.len() != 176 {
            return None;
        }
        if let Some(offset) = offset_of(name) {
            return Some(qword(self.0, offset));
        }
        let flag = |bit: u32| Some((qword(self.0, RFLAGS_OFFSET) >> bit) & 1);
        match name {
            "cf" => return flag(0),
            "pf" => return flag(2),
            "af" => return flag(4),
            "zf" => return flag(6),
            "sf" => return flag(7),
            "tf" => return flag(8),
            "df" => return flag(10),
            "of" => return flag(11),
            "ah" | "bh" | "ch" | "dh" => {
                let full = self.get(&format!("r{}x", &name[..1]))?;
                return Some((full >> 8) & 0xff);
            }
            _ => {}
        }
        // Legacy 32/16/8-bit aliases of the 64-bit registers.
        let (base, mask): (String, u64) = if let Some(rest) = name.strip_prefix('e') {
            (format!("r{rest}"), 0xffff_ffff)
        } else if let Some(rest) = name.strip_suffix('d').filter(|_| name.starts_with('r')) {
            (rest.to_owned(), 0xffff_ffff)
        } else if let Some(rest) = name.strip_suffix('w').filter(|_| name.starts_with('r')) {
            (rest.to_owned(), 0xffff)
        } else if let Some(rest) = name.strip_suffix('b').filter(|_| name.starts_with('r')) {
            (rest.to_owned(), 0xff)
        } else {
            let widened = match name {
                "ax" | "bx" | "cx" | "dx" => Some((format!("r{name}"), 0xffff)),
                "si" | "di" | "bp" | "sp" => Some((format!("r{name}"), 0xffff)),
                "al" | "bl" | "cl" | "dl" => Some((format!("r{}x", &name[..1]), 0xff)),
                "sil" | "dil" | "bpl" | "spl" => Some((format!("r{}", &name[..2]), 0xff)),
                _ => None,
            }?;
            return self.get(&widened.0).map(|value| value & widened.1);
        };
        // `esp` -> "rsp", `eax` -> "rax"; `r8d` -> "r8".
        offset_of(&base).map(|offset| qword(self.0, offset) & mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fixture {
        registers: Vec<u8>,
        memory: HashMap<u64, u64>,
        reads: usize,
    }

    impl Fixture {
        fn new() -> Self {
            let mut registers = vec![0u8; 176];
            let mut set = |name: &str, value: u64| {
                let offset = offset_of(name).unwrap();
                registers[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            };
            set("rax", 0x1122_3344_5566_7788);
            set("rsp", 0x7000);
            set("rip", 0x401000);
            set("rflags", 0x246);
            set("r9", 5);
            Self { registers, memory: HashMap::from([(0x7008, 0xdead_beef_0000_0001)]), reads: 0 }
        }
    }

    impl Context for Fixture {
        fn register(&mut self, name: &str) -> Result<Option<u64>> {
            Ok(RegisterFile(&self.registers).get(name))
        }
        fn symbol(&mut self, name: &str) -> Result<Option<u64>> {
            Ok(match name {
                "eboot.bin" => Some(0x400000),
                _ => None,
            })
        }
        fn read(&mut self, address: u64, size: usize) -> Result<u64> {
            self.reads += 1;
            let value = *self.memory.get(&address).ok_or_else(|| anyhow::anyhow!("unmapped {address:#x}"))?;
            Ok(if size == 8 { value } else { value & ((1u64 << (size * 8)) - 1) })
        }
    }

    fn run(text: &str) -> Result<u64> {
        eval(text, &mut Fixture::new())
    }

    #[test]
    fn arithmetic_precedence_and_wrapping() {
        assert_eq!(run("1 + 2 * 3").unwrap(), 7);
        assert_eq!(run("(1 + 2) * 3").unwrap(), 9);
        assert_eq!(run("0 - 1").unwrap(), u64::MAX);
        assert_eq!(run("1 << 63 >> 63").unwrap(), 1);
        assert_eq!(run("1 << 64").unwrap(), 0);
        assert_eq!(run("-1 == 0xffffffffffffffff").unwrap(), 1);
        assert!(run("1 / 0").is_err());
        assert!(run("5 % 0").is_err());
    }

    #[test]
    fn registers_aliases_and_flags() {
        assert_eq!(run("rax").unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(run("eax").unwrap(), 0x5566_7788);
        assert_eq!(run("ax").unwrap(), 0x7788);
        assert_eq!(run("al").unwrap(), 0x88);
        assert_eq!(run("ah").unwrap(), 0x77);
        assert_eq!(run("r9d").unwrap(), 5);
        assert_eq!(run("RIP").unwrap(), 0x401000);
        assert_eq!(run("zf").unwrap(), 1);
        assert_eq!(run("cf").unwrap(), 0);
        assert_eq!(run("rip + 4").unwrap(), 0x401004);
    }

    #[test]
    fn memory_and_symbols() {
        assert_eq!(run("[rsp+8]").unwrap(), 0xdead_beef_0000_0001);
        assert_eq!(run("dword [rsp+8]").unwrap(), 1);
        assert_eq!(run("byte [rsp + 8] == 1 && rax != 0").unwrap(), 1);
        assert_eq!(run("eboot.bin + 0x1000").unwrap(), 0x401000);
        assert!(run("[0x10]").is_err());
        assert!(run("nosuchthing").is_err());
    }

    #[test]
    fn rejects_malformed_and_unbounded_input() {
        for bad in ["", "1 +", "(1", "[rsp", "1 2", "qword rax", "1 $$ 2", "0xzz"] {
            assert!(run(bad).is_err(), "{bad:?}");
        }
        assert!(run(&format!("{}1{}", "(".repeat(40), ")".repeat(40))).is_err());
        let many = vec!["[rsp+8]"; MAX_MEMORY_READS + 1].join(" + ");
        assert!(run(&many).is_err());
        assert!(run(&"1+".repeat(300)).is_err());
        assert!(validate("rax == 5 && [rsp+8] > 0").is_ok());
        assert!(validate("rax ==").is_err());
    }
}
