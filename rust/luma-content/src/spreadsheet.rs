//! Deterministic editable spreadsheet sources, not execution of CSV formulas.
//! Explicit typed expressions use exact six-place decimal arithmetic. There
//! are no scripts, external references, clock, random values or implicit I/O.
use crate::{canonical, sha256, Format, MAX_CONTENT_BYTES, MAX_CSV_FIELD_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_ROWS: usize = 64;
pub const MAX_COLUMNS: usize = 32;
pub const MAX_EXPRESSION_DEPTH: usize = 16;
pub const MAX_REFERENCE_DEPTH: usize = 64;
pub const MAX_EXPRESSION_NODES: usize = 4096;
pub const MAX_EVALUATION_STEPS: usize = 65536;
const SCALE: i128 = 1_000_000;
const MAX_SCALED: i128 = 1_000_000_000_000_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source,
    Bounds,
    Reference,
    Cycle,
    Number,
    Arithmetic,
    Precision,
    NonNumeric,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "invalid closed spreadsheet source",
            Self::Bounds => "spreadsheet structural or evaluation bound exceeded",
            Self::Reference => "spreadsheet reference is outside its exact dimensions",
            Self::Cycle => "spreadsheet contains a reference cycle",
            Self::Number => "invalid bounded fixed-point decimal",
            Self::Arithmetic => "spreadsheet arithmetic overflow or zero divisor",
            Self::Precision => "spreadsheet result is not exact at six decimal places",
            Self::NonNumeric => {
                "spreadsheet numeric expression references text or an empty aggregate"
            }
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema_version: u32,
    pub rows: Vec<Vec<Cell>>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Cell {
    Blank,
    Text { value: String },
    Number { value: String },
    Formula { expression: Expression },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Expression {
    Number {
        value: String,
    },
    Cell {
        row: usize,
        column: usize,
    },
    Negate {
        value: Box<Expression>,
    },
    Binary {
        operator: Operator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Aggregate {
        function: Function,
        start_row: usize,
        start_column: usize,
        end_row: usize,
        end_column: usize,
    },
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operator {
    Add,
    Subtract,
    Multiply,
    Divide,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Function {
    Sum,
    Minimum,
    Maximum,
    Average,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Value {
    Blank,
    Text { value: String },
    Number { value: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct Calculation {
    pub schema_version: u32,
    pub engine: &'static str,
    pub canonical_source: String,
    pub source_sha256: String,
    pub values: Vec<Vec<Value>>,
    pub canonical_csv: String,
    pub csv_sha256: String,
    pub evaluation_steps: usize,
}

fn bounded(value: i128) -> Result<i128> {
    if value.checked_abs().ok_or(Error::Arithmetic)? > MAX_SCALED {
        Err(Error::Arithmetic)
    } else {
        Ok(value)
    }
}
fn number(value: &str) -> Result<i128> {
    if value.is_empty() || value.len() > 40 {
        return Err(Error::Number);
    }
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value),
    };
    let mut parts = unsigned.split('.');
    let whole = parts.next().ok_or(Error::Number)?;
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
    {
        return Err(Error::Number);
    }
    let mut result = whole
        .parse::<i128>()
        .map_err(|_| Error::Number)?
        .checked_mul(SCALE)
        .ok_or(Error::Arithmetic)?;
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > 6
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Number);
        }
        let part = fraction
            .parse::<i128>()
            .map_err(|_| Error::Number)?
            .checked_mul(10i128.pow(6 - fraction.len() as u32))
            .ok_or(Error::Arithmetic)?;
        result = result.checked_add(part).ok_or(Error::Arithmetic)?;
    }
    bounded(if negative { -result } else { result })
}
fn rendered(value: i128) -> String {
    let magnitude = value.abs();
    let whole = magnitude / SCALE;
    let fraction = magnitude % SCALE;
    let sign = if value < 0 { "-" } else { "" };
    if fraction == 0 {
        format!("{sign}{whole}")
    } else {
        format!(
            "{sign}{whole}.{}",
            format!("{fraction:06}").trim_end_matches('0')
        )
    }
}
fn coordinate(row: usize, column: usize, height: usize, width: usize) -> Result<usize> {
    if row >= height || column >= width {
        Err(Error::Reference)
    } else {
        Ok(row * width + column)
    }
}
fn validate_expression(
    e: &Expression,
    depth: usize,
    nodes: &mut usize,
    h: usize,
    w: usize,
) -> Result<()> {
    *nodes = nodes.checked_add(1).ok_or(Error::Bounds)?;
    if depth > MAX_EXPRESSION_DEPTH || *nodes > MAX_EXPRESSION_NODES {
        return Err(Error::Bounds);
    }
    match e {
        Expression::Number { value } => {
            number(value)?;
        }
        Expression::Cell { row, column } => {
            coordinate(*row, *column, h, w)?;
        }
        Expression::Negate { value } => validate_expression(value, depth + 1, nodes, h, w)?,
        Expression::Binary { left, right, .. } => {
            validate_expression(left, depth + 1, nodes, h, w)?;
            validate_expression(right, depth + 1, nodes, h, w)?;
        }
        Expression::Aggregate {
            start_row,
            start_column,
            end_row,
            end_column,
            ..
        } => {
            coordinate(*start_row, *start_column, h, w)?;
            coordinate(*end_row, *end_column, h, w)?;
            if start_row > end_row || start_column > end_column {
                return Err(Error::Reference);
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
enum Evaluated {
    Blank,
    Text(String),
    Number(i128),
}
struct Evaluator<'a> {
    source: &'a Source,
    width: usize,
    states: Vec<u8>,
    values: Vec<Option<Evaluated>>,
    remaining: usize,
}
impl Evaluator<'_> {
    fn tick(&mut self) -> Result<()> {
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::Bounds)?;
        Ok(())
    }
    fn cell(&mut self, row: usize, column: usize, depth: usize) -> Result<Evaluated> {
        self.tick()?;
        let index = coordinate(row, column, self.source.rows.len(), self.width)?;
        if self.states[index] == 1 {
            return Err(Error::Cycle);
        }
        if let Some(value) = &self.values[index] {
            return Ok(value.clone());
        }
        if depth > MAX_REFERENCE_DEPTH {
            return Err(Error::Bounds);
        }
        self.states[index] = 1;
        let value = match &self.source.rows[row][column] {
            Cell::Blank => Evaluated::Blank,
            Cell::Text { value } => Evaluated::Text(
                canonical::content(Format::Utf8Text, value.as_bytes())
                    .map_err(|_| Error::Source)?,
            ),
            Cell::Number { value } => Evaluated::Number(number(value)?),
            Cell::Formula { expression } => Evaluated::Number(self.expression(expression, depth)?),
        };
        self.states[index] = 2;
        self.values[index] = Some(value.clone());
        Ok(value)
    }
    fn numeric_cell(&mut self, row: usize, column: usize, depth: usize) -> Result<i128> {
        match self.cell(row, column, depth + 1)? {
            Evaluated::Blank => Ok(0),
            Evaluated::Number(number) => Ok(number),
            Evaluated::Text(_) => Err(Error::NonNumeric),
        }
    }
    fn expression(&mut self, expression: &Expression, depth: usize) -> Result<i128> {
        self.tick()?;
        match expression {
            Expression::Number { value } => number(value),
            Expression::Cell { row, column } => self.numeric_cell(*row, *column, depth),
            Expression::Negate { value } => bounded(-self.expression(value, depth)?),
            Expression::Binary {
                operator,
                left,
                right,
            } => {
                let a = self.expression(left, depth)?;
                let b = self.expression(right, depth)?;
                let value = match operator {
                    Operator::Add => a.checked_add(b).ok_or(Error::Arithmetic)?,
                    Operator::Subtract => a.checked_sub(b).ok_or(Error::Arithmetic)?,
                    Operator::Multiply => {
                        let product = a.checked_mul(b).ok_or(Error::Arithmetic)?;
                        if product % SCALE != 0 {
                            return Err(Error::Precision);
                        }
                        product / SCALE
                    }
                    Operator::Divide => {
                        if b == 0 {
                            return Err(Error::Arithmetic);
                        }
                        let numerator = a.checked_mul(SCALE).ok_or(Error::Arithmetic)?;
                        if numerator % b != 0 {
                            return Err(Error::Precision);
                        }
                        numerator / b
                    }
                };
                bounded(value)
            }
            Expression::Aggregate {
                function,
                start_row,
                start_column,
                end_row,
                end_column,
            } => {
                let mut sum = 0i128;
                let mut count = 0i128;
                let mut minimum = None;
                let mut maximum = None;
                for row in *start_row..=*end_row {
                    for column in *start_column..=*end_column {
                        match self.cell(row, column, depth + 1)? {
                            Evaluated::Blank => (),
                            Evaluated::Text(_) => return Err(Error::NonNumeric),
                            Evaluated::Number(value) => {
                                if matches!(function, Function::Sum | Function::Average) {
                                    // At most 2048 bounded operands fit the
                                    // wider accumulator. Bound the final sum
                                    // or mean, not a prefix that may cancel.
                                    sum = sum.checked_add(value).ok_or(Error::Arithmetic)?;
                                }
                                count += 1;
                                minimum =
                                    Some(minimum.map_or(value, |prior: i128| prior.min(value)));
                                maximum =
                                    Some(maximum.map_or(value, |prior: i128| prior.max(value)));
                            }
                        }
                    }
                }
                match function {
                    Function::Sum => bounded(sum),
                    Function::Minimum => minimum.ok_or(Error::NonNumeric),
                    Function::Maximum => maximum.ok_or(Error::NonNumeric),
                    Function::Average => {
                        if count == 0 {
                            return Err(Error::NonNumeric);
                        }
                        if sum % count != 0 {
                            return Err(Error::Precision);
                        }
                        bounded(sum / count)
                    }
                }
            }
        }
    }
}

fn csv_field(field: &str, output: &mut String) {
    if field.contains([',', '"', '\n']) {
        output.push('"');
        output.push_str(&field.replace('"', "\"\""));
        output.push('"');
    } else {
        output.push_str(field);
    }
}

/// Parse, validate every source cell/expression, recalculate, and bind both
/// editable source and CSV bytes. No supplied expression text is executed.
pub fn calculate(bytes: &[u8]) -> Result<Calculation> {
    if bytes.is_empty() || bytes.len() > MAX_CONTENT_BYTES {
        return Err(Error::Bounds);
    }
    let canonical_source = canonical::content(Format::Json, bytes).map_err(|_| Error::Source)?;
    let source: Source = serde_json::from_str(&canonical_source).map_err(|_| Error::Source)?;
    // Internally tagged unit variants can otherwise discard extra properties
    // despite deny_unknown_fields. Bind the complete accepted wire record,
    // not just whichever fields the deserializer retained.
    let typed_bytes = serde_json::to_vec(&source).map_err(|_| Error::Source)?;
    if canonical::content(Format::Json, &typed_bytes).map_err(|_| Error::Source)?
        != canonical_source
    {
        return Err(Error::Source);
    }
    let h = source.rows.len();
    let w = source.rows.first().map_or(0, Vec::len);
    if source.schema_version != 1
        || h == 0
        || h > MAX_ROWS
        || w == 0
        || w > MAX_COLUMNS
        || source.rows.iter().any(|row| row.len() != w)
    {
        return Err(Error::Bounds);
    }
    let mut nodes = 0;
    for row in &source.rows {
        for cell in row {
            match cell {
                Cell::Blank => (),
                Cell::Text { value } => {
                    if value.len() > MAX_CSV_FIELD_BYTES {
                        return Err(Error::Bounds);
                    }
                    canonical::content(Format::Utf8Text, value.as_bytes())
                        .map_err(|_| Error::Source)?;
                }
                Cell::Number { value } => {
                    number(value)?;
                }
                Cell::Formula { expression } => {
                    validate_expression(expression, 0, &mut nodes, h, w)?
                }
            }
        }
    }
    let mut evaluator = Evaluator {
        source: &source,
        width: w,
        states: vec![0; h * w],
        values: vec![None; h * w],
        remaining: MAX_EVALUATION_STEPS,
    };
    let mut values = Vec::new();
    let mut csv = String::new();
    for row in 0..h {
        let mut computed = Vec::new();
        for column in 0..w {
            let (value, text) = match evaluator.cell(row, column, 0)? {
                Evaluated::Blank => (Value::Blank, String::new()),
                Evaluated::Text(value) => (
                    Value::Text {
                        value: value.clone(),
                    },
                    value,
                ),
                Evaluated::Number(value) => {
                    let text = rendered(value);
                    (
                        Value::Number {
                            value: text.clone(),
                        },
                        text,
                    )
                }
            };
            if column != 0 {
                csv.push(',');
            }
            csv_field(&text, &mut csv);
            if csv.len() > MAX_CONTENT_BYTES {
                return Err(Error::Bounds);
            }
            computed.push(value);
        }
        csv.push('\n');
        values.push(computed);
    }
    let canonical_csv =
        canonical::content(Format::Csv, csv.as_bytes()).map_err(|_| Error::Bounds)?;
    Ok(Calculation {
        schema_version: 1,
        engine: "luma-exact-spreadsheet-v1",
        source_sha256: sha256(canonical_source.as_bytes()),
        canonical_source,
        csv_sha256: sha256(canonical_csv.as_bytes()),
        canonical_csv,
        values,
        evaluation_steps: MAX_EVALUATION_STEPS - evaluator.remaining,
    })
}

#[cfg(test)]
mod tests;
