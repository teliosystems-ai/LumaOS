use crate::{
    Error, Format, Result, MAX_CONTENT_BYTES, MAX_CSV_COLUMNS, MAX_CSV_FIELD_BYTES, MAX_CSV_ROWS,
    MAX_JSON_DEPTH, MAX_JSON_NODES,
};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
use std::fmt;

pub(crate) fn content(format: Format, bytes: &[u8]) -> Result<String> {
    if (bytes.is_empty() && format != Format::Utf8Text) || bytes.len() > MAX_CONTENT_BYTES {
        return Err(Error::Bounds);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    if source.starts_with('\u{feff}')
        || source
            .chars()
            .any(|c| c < ' ' && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(Error::InvalidText);
    }
    let canonical = match format {
        Format::Utf8Text => normalize_lines(source)?,
        Format::Json => json(source)?,
        Format::Csv => csv(&normalize_lines(source)?)?,
    };
    if (canonical.is_empty() && format != Format::Utf8Text) || canonical.len() > MAX_CONTENT_BYTES {
        return Err(Error::Bounds);
    }
    Ok(canonical)
}

fn normalize_lines(source: &str) -> Result<String> {
    let normalized = source.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err(Error::InvalidText);
    }
    Ok(normalized)
}

/// Version-one canonical JSON sorts keys by Rust UTF-8 string order and uses the
/// pinned serde_json number representation. This is not an RFC 8785 implementation;
/// numeric spelling is canonicalized only as specified by that representation.
fn json(source: &str) -> Result<String> {
    reject_overflowing_integers(source)?;
    let mut remaining = MAX_JSON_NODES;
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = JsonSeed {
        depth: 0,
        remaining: &mut remaining,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| Error::InvalidJson)?;
    deserializer.end().map_err(|_| Error::InvalidJson)?;
    serde_json::to_string(&value).map_err(|_| Error::InvalidJson)
}

// Integer literals must remain exact. Decimal/exponent literals use serde_json's
// finite IEEE-754 representation and can round; they are not exact-decimal data.
fn reject_overflowing_integers(source: &str) -> Result<()> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut quoted = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            index += 1;
        } else if byte == b'"' {
            quoted = true;
            index += 1;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit()
                    || matches!(bytes[index], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                index += 1;
            }
            let number = &source[start..index];
            if !number.contains(['.', 'e', 'E']) {
                let valid = if number.starts_with('-') {
                    number.parse::<i64>().is_ok()
                } else {
                    number.parse::<u64>().is_ok()
                };
                if !valid {
                    return Err(Error::InvalidJson);
                }
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

struct JsonSeed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH || *self.remaining == 0 {
            return Err(serde::de::Error::custom("JSON structural bound"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        if value.contains('\0') {
            return Err(E::custom("NUL JSON string"));
        }
        Ok(Value::String(value.into()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<Value, E> {
        if value.contains('\0') {
            return Err(E::custom("NUL JSON string"));
        }
        Ok(Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.contains('\0') || values.contains_key(&key) {
                return Err(serde::de::Error::custom("NUL or duplicate JSON key"));
            }
            let value = map.next_value_seed(JsonSeed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        let ordered: Map<String, Value> = values.into_iter().collect();
        Ok(Value::Object(ordered))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Plain,
    Quoted,
    AfterQuote,
}

fn field(row: &mut Vec<String>, value: &mut String) -> Result<()> {
    if row.len() >= MAX_CSV_COLUMNS || value.len() > MAX_CSV_FIELD_BYTES {
        return Err(Error::Bounds);
    }
    row.push(std::mem::take(value));
    Ok(())
}

fn row(rows: &mut Vec<Vec<String>>, value: &mut Vec<String>) -> Result<()> {
    if rows.len() >= MAX_CSV_ROWS {
        return Err(Error::Bounds);
    }
    if rows.first().is_some_and(|first| first.len() != value.len()) {
        return Err(Error::InvalidCsv);
    }
    rows.push(std::mem::take(value));
    Ok(())
}

fn csv(source: &str) -> Result<String> {
    csv_bytes(&csv_rows(source)?)
}

pub(crate) fn csv_rows(source: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut record = Vec::new();
    let mut value = String::new();
    let mut state = State::Start;
    let mut unfinished = false;
    for character in source.chars() {
        unfinished = true;
        match (state, character) {
            (State::Start, '"') => state = State::Quoted,
            (State::Quoted, '"') => state = State::AfterQuote,
            (State::AfterQuote, '"') => {
                value.push('"');
                state = State::Quoted;
            }
            (State::Quoted, _) => value.push(character),
            (State::Start | State::Plain | State::AfterQuote, ',') => {
                field(&mut record, &mut value)?;
                state = State::Start;
            }
            (State::Start | State::Plain | State::AfterQuote, '\n') => {
                field(&mut record, &mut value)?;
                row(&mut rows, &mut record)?;
                state = State::Start;
                unfinished = false;
            }
            (State::Plain, '"') => return Err(Error::InvalidCsv),
            (State::AfterQuote, _) => return Err(Error::InvalidCsv),
            (State::Start | State::Plain, _) => {
                value.push(character);
                state = State::Plain;
            }
        }
        if value.len() > MAX_CSV_FIELD_BYTES {
            return Err(Error::Bounds);
        }
    }
    if state == State::Quoted {
        return Err(Error::InvalidCsv);
    }
    if unfinished {
        field(&mut record, &mut value)?;
        row(&mut rows, &mut record)?;
    }
    if rows.is_empty() {
        return Err(Error::InvalidCsv);
    }
    Ok(rows)
}

pub(crate) fn csv_bytes(rows: &[Vec<String>]) -> Result<String> {
    if rows.is_empty() || rows.len() > MAX_CSV_ROWS {
        return Err(Error::Bounds);
    }
    let columns = rows[0].len();
    if columns == 0 || columns > MAX_CSV_COLUMNS {
        return Err(Error::Bounds);
    }
    let mut output = String::new();
    for record in rows {
        if record.len() != columns {
            return Err(Error::InvalidCsv);
        }
        for (index, value) in record.iter().enumerate() {
            if value.len() > MAX_CSV_FIELD_BYTES {
                return Err(Error::Bounds);
            }
            if index > 0 {
                output.push(',');
            }
            if value.contains([',', '"', '\n']) {
                output.push('"');
                output.push_str(&value.replace('"', "\"\""));
                output.push('"');
            } else {
                output.push_str(&value);
            }
            if output.len() > MAX_CONTENT_BYTES {
                return Err(Error::Bounds);
            }
        }
        output.push('\n');
        if output.len() > MAX_CONTENT_BYTES {
            return Err(Error::Bounds);
        }
    }
    Ok(output)
}
