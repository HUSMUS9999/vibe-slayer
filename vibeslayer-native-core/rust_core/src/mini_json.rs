//! Zero-dependency RFC 8259 JSON parser and serializer.

use std::fmt::Write;

#[derive(Clone, Debug, PartialEq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(Vec<(String, JsonVal)>),
}

impl JsonVal {
    pub fn empty_obj() -> Self {
        JsonVal::Obj(Vec::new())
    }

    pub fn obj(entries: Vec<(&str, JsonVal)>) -> Self {
        JsonVal::Obj(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonVal::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonVal::Int(i) => Some(*i),
            JsonVal::Num(f) if f.is_finite() && f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonVal::Int(i) if *i >= 0 => Some(*i as u64),
            JsonVal::Num(f) if f.is_finite() && *f >= 0.0 && f.fract() == 0.0 => Some(*f as u64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonVal::Int(i) => Some(*i as f64),
            JsonVal::Num(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&Vec<JsonVal>> {
        match self {
            JsonVal::Arr(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_arr_mut(&mut self) -> Option<&mut Vec<JsonVal>> {
        match self {
            JsonVal::Arr(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&Vec<(String, JsonVal)>> {
        match self {
            JsonVal::Obj(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_obj_mut(&mut self) -> Option<&mut Vec<(String, JsonVal)>> {
        match self {
            JsonVal::Obj(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonVal> {
        match self {
            JsonVal::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonVal> {
        match self {
            JsonVal::Obj(entries) => entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, val: JsonVal) {
        let k = key.into();
        if let JsonVal::Obj(entries) = self {
            if let Some((_, existing)) = entries.iter_mut().find(|(ek, _)| ek == &k) {
                *existing = val;
            } else {
                entries.push((k, val));
            }
        }
    }

    pub fn ensure_obj(&mut self, key: &str) -> &mut JsonVal {
        if let JsonVal::Obj(entries) = self {
            if let Some(pos) = entries.iter().position(|(k, _)| k == key) {
                if !matches!(entries[pos].1, JsonVal::Obj(_)) {
                    entries[pos].1 = JsonVal::empty_obj();
                }
                return &mut entries[pos].1;
            }
            entries.push((key.to_string(), JsonVal::empty_obj()));
            return &mut entries.last_mut().unwrap().1;
        }
        *self = JsonVal::obj(vec![(key, JsonVal::empty_obj())]);
        self.get_mut(key).unwrap()
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, String> {
        let b = self.peek().ok_or_else(|| "UNEXPECTED_EOF".to_string())?;
        self.pos += 1;
        Ok(b)
    }

    fn parse_val(&mut self, depth: usize) -> Result<JsonVal, String> {
        if depth > 128 {
            return Err("JSON_MAX_DEPTH".to_string());
        }
        self.skip_ws();
        let b = self.peek().ok_or_else(|| "EMPTY_JSON_VALUE".to_string())?;
        match b {
            b'n' => {
                if self.bytes[self.pos..].starts_with(b"null") {
                    self.pos += 4;
                    Ok(JsonVal::Null)
                } else {
                    Err("BAD_NULL".to_string())
                }
            }
            b't' => {
                if self.bytes[self.pos..].starts_with(b"true") {
                    self.pos += 4;
                    Ok(JsonVal::Bool(true))
                } else {
                    Err("BAD_TRUE".to_string())
                }
            }
            b'f' => {
                if self.bytes[self.pos..].starts_with(b"false") {
                    self.pos += 5;
                    Ok(JsonVal::Bool(false))
                } else {
                    Err("BAD_FALSE".to_string())
                }
            }
            b'"' => Ok(JsonVal::Str(self.parse_str()?)),
            b'[' => self.parse_arr(depth + 1),
            b'{' => self.parse_obj(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_num(),
            _ => Err(format!("UNEXPECTED_CHAR_AT_{}", self.pos)),
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("TRUNCATED_UNICODE_ESCAPE".to_string());
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "BAD_UNICODE_ESCAPE".to_string())?;
        let val = u16::from_str_radix(s, 16).map_err(|_| "BAD_UNICODE_HEX".to_string())?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_str(&mut self) -> Result<String, String> {
        if self.next()? != b'"' {
            return Err("EXPECTED_QUOTE".to_string());
        }
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self.next()?;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let u1 = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&u1) {
                            if self.pos + 2 > self.bytes.len()
                                || self.bytes[self.pos] != b'\\'
                                || self.bytes[self.pos + 1] != b'u'
                            {
                                return Err("UNPAIRED_HIGH_SURROGATE".to_string());
                            }
                            self.pos += 2;
                            let u2 = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&u2) {
                                return Err("INVALID_LOW_SURROGATE".to_string());
                            }
                            let cp =
                                0x10000 + (((u1 as u32 - 0xD800) << 10) | (u2 as u32 - 0xDC00));
                            let ch = char::from_u32(cp)
                                .ok_or_else(|| "INVALID_SURROGATE_CP".to_string())?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&u1) {
                            return Err("UNEXPECTED_LOW_SURROGATE".to_string());
                        } else {
                            let ch = char::from_u32(u1 as u32)
                                .ok_or_else(|| "INVALID_CODEPOINT".to_string())?;
                            out.push(ch);
                        }
                    }
                    _ => return Err("INVALID_ESCAPE".to_string()),
                }
            } else if b < 0x20 {
                return Err("UNESCAPED_CONTROL_CHAR".to_string());
            } else {
                // Consume valid UTF-8 scalar cleanly
                let tail = std::str::from_utf8(&self.bytes[self.pos..])
                    .map_err(|_| "INVALID_UTF8_IN_JSON".to_string())?;
                let mut iter = tail.chars();
                let ch = iter.next().ok_or_else(|| "EOF_IN_STR".to_string())?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("UNTERMINATED_STRING".to_string())
    }

    fn parse_num(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err("INVALID_NUMBER".to_string()),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("INVALID_NUMBER_FRAC".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("INVALID_NUMBER_EXP".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let slice = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "NUM_UTF8".to_string())?;
        if !is_float {
            if let Ok(iv) = slice.parse::<i64>() {
                return Ok(JsonVal::Int(iv));
            }
        }
        let fv = slice
            .parse::<f64>()
            .map_err(|_| "INVALID_F64".to_string())?;
        if !fv.is_finite() {
            return Err("NON_FINITE_JSON_NUMBER".to_string());
        }
        Ok(JsonVal::Num(fv))
    }

    fn parse_arr(&mut self, depth: usize) -> Result<JsonVal, String> {
        self.next()?; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonVal::Arr(items));
        }
        loop {
            items.push(self.parse_val(depth)?);
            self.skip_ws();
            match self.next()? {
                b',' => {}
                b']' => return Ok(JsonVal::Arr(items)),
                _ => return Err("EXPECTED_COMMA_OR_RBRACKET".to_string()),
            }
        }
    }

    fn parse_obj(&mut self, depth: usize) -> Result<JsonVal, String> {
        self.next()?; // '{'
        self.skip_ws();
        let mut entries: Vec<(String, JsonVal)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonVal::Obj(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_str()?;
            self.skip_ws();
            if self.next()? != b':' {
                return Err("EXPECTED_COLON".to_string());
            }
            let val = self.parse_val(depth)?;
            if let Some((_, existing)) = entries.iter_mut().find(|(k, _)| k == &key) {
                *existing = val;
            } else {
                entries.push((key, val));
            }
            self.skip_ws();
            match self.next()? {
                b',' => {}
                b'}' => return Ok(JsonVal::Obj(entries)),
                _ => return Err("EXPECTED_COMMA_OR_RBRACE".to_string()),
            }
        }
    }
}

pub fn parse_json(input: &str) -> Result<JsonVal, String> {
    let mut p = Parser::new(input);
    let val = p.parse_val(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err("TRAILING_JSON_CHARS".to_string());
    }
    Ok(val)
}

pub fn escape_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json(out: &mut String, val: &JsonVal, pretty: bool, indent: usize) {
    match val {
        JsonVal::Null => out.push_str("null"),
        JsonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonVal::Int(i) => {
            let _ = write!(out, "{i}");
        }
        JsonVal::Num(f) => {
            if f.is_finite() {
                let _ = write!(out, "{f}");
            } else {
                out.push_str("null");
            }
        }
        JsonVal::Str(s) => escape_json_str(out, s),
        JsonVal::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    for _ in 0..(indent + 2) {
                        out.push(' ');
                    }
                }
                write_json(out, item, pretty, indent + 2);
            }
            if pretty {
                out.push('\n');
                for _ in 0..indent {
                    out.push(' ');
                }
            }
            out.push(']');
        }
        JsonVal::Obj(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (idx, (k, v)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    for _ in 0..(indent + 2) {
                        out.push(' ');
                    }
                }
                escape_json_str(out, k);
                out.push_str(if pretty { ": " } else { ":" });
                write_json(out, v, pretty, indent + 2);
            }
            if pretty {
                out.push('\n');
                for _ in 0..indent {
                    out.push(' ');
                }
            }
            out.push('}');
        }
    }
}

pub fn to_json_compact(val: &JsonVal) -> String {
    let mut out = String::new();
    write_json(&mut out, val, false, 0);
    out
}

pub fn to_json_pretty(val: &JsonVal) -> String {
    let mut out = String::new();
    write_json(&mut out, val, true, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_escapes_and_surrogates() {
        let src = r#"{
            "ok": true,
            "count": -42,
            "ratio": 7.99902,
            "msg": "line1\n\"quoted\"\t\\slash\\ \uD83D\uDE80",
            "arr": [null, false, {"k": "v"}]
        }"#;
        let parsed = parse_json(src).expect("parse ok");
        assert_eq!(parsed.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(parsed.get("count").and_then(|v| v.as_i64()), Some(-42));
        assert_eq!(
            parsed.get("msg").and_then(|v| v.as_str()),
            Some("line1\n\"quoted\"\t\\slash\\ 🚀")
        );
        let pretty = to_json_pretty(&parsed);
        let reparsed = parse_json(&pretty).expect("reparse ok");
        assert_eq!(parsed, reparsed);
    }
}
