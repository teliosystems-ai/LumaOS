//! Pure, bounded invoice CSV to monthly totals calculation.
//! It opens no path, commits no artifact, and confers no workflow authority.
use crate::{bundle, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_ROWS: usize = 10_001; // Header plus at most 10,000 invoices.
const MAX_COLUMNS: usize = 32;
const MAX_FIELD_BYTES: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldState {
    Start,
    Unquoted,
    Quoted,
    AfterQuote,
}

fn finish_field(row: &mut Vec<String>, field: &mut String) -> Result<()> {
    if row.len() >= MAX_COLUMNS {
        return Err("invoice CSV has too many columns".into());
    }
    row.push(std::mem::take(field));
    Ok(())
}

fn finish_row(rows: &mut Vec<Vec<String>>, row: &mut Vec<String>) -> Result<()> {
    if rows.len() >= MAX_ROWS || (row.len() == 1 && row[0].is_empty()) {
        return Err("invoice CSV has an empty row or too many rows".into());
    }
    rows.push(std::mem::take(row));
    Ok(())
}

fn parse_csv(bytes: &[u8]) -> Result<Vec<Vec<String>>> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("empty or oversized invoice CSV".into());
    }
    let source = std::str::from_utf8(bytes)?;
    if source.contains('\0') {
        return Err("invoice CSV contains a NUL byte".into());
    }
    let normalized = source.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err("invoice CSV contains a bare carriage return".into());
    }
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut state = FieldState::Start;
    for ch in normalized.chars() {
        match (state, ch) {
            (FieldState::Start, '"') => state = FieldState::Quoted,
            (FieldState::Quoted, '"') => state = FieldState::AfterQuote,
            (FieldState::AfterQuote, '"') => {
                field.push('"');
                state = FieldState::Quoted;
            }
            (FieldState::Quoted, _) => field.push(ch),
            (FieldState::Start | FieldState::Unquoted | FieldState::AfterQuote, ',') => {
                finish_field(&mut row, &mut field)?;
                state = FieldState::Start;
            }
            (FieldState::Start | FieldState::Unquoted | FieldState::AfterQuote, '\n') => {
                finish_field(&mut row, &mut field)?;
                finish_row(&mut rows, &mut row)?;
                state = FieldState::Start;
            }
            (FieldState::Start, _) => {
                field.push(ch);
                state = FieldState::Unquoted;
            }
            (FieldState::Unquoted, '"') | (FieldState::AfterQuote, _) => {
                return Err("malformed invoice CSV quoting".into());
            }
            (FieldState::Unquoted, _) => field.push(ch),
        }
        if field.len() > MAX_FIELD_BYTES {
            return Err("invoice CSV field exceeds bound".into());
        }
    }
    if state == FieldState::Quoted {
        return Err("unterminated invoice CSV quote".into());
    }
    if !row.is_empty() || !field.is_empty() || state != FieldState::Start {
        finish_field(&mut row, &mut field)?;
        finish_row(&mut rows, &mut row)?;
    }
    if rows.len() < 2 {
        return Err("invoice CSV has no records".into());
    }
    Ok(rows)
}

fn date_month(value: &str) -> Result<String> {
    let b = value.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || b.iter()
            .enumerate()
            .any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit())
    {
        return Err("invoice date must be YYYY-MM-DD".into());
    }
    let year: u32 = value[..4].parse()?;
    let month: u32 = value[5..7].parse()?;
    let day: u32 = value[8..].parse()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        return Err("invalid invoice calendar date".into());
    }
    Ok(value[..7].into())
}

fn cents(value: &str) -> Result<i128> {
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (unsigned, None),
    };
    if whole.is_empty()
        || whole.len() > 12
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction
            .is_some_and(|f| f.is_empty() || f.len() > 2 || !f.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("invoice amount must be an exact decimal with at most two places".into());
    }
    let integer: i128 = whole.parse()?;
    let decimal: i128 = match fraction {
        None => 0,
        Some(f) if f.len() == 1 => f.parse::<i128>()? * 10,
        Some(f) => f.parse()?,
    };
    let amount = integer
        .checked_mul(100)
        .and_then(|v| v.checked_add(decimal))
        .ok_or("invoice amount overflow")?;
    Ok(if negative { -amount } else { amount })
}

fn formatted_cents(value: i128) -> String {
    let prefix = if value < 0 { "-" } else { "" };
    let absolute = value.abs(); // The bounded input and row count cannot reach i128::MIN.
    format!("{prefix}{}.{:02}", absolute / 100, absolute % 100)
}

#[derive(Debug, Serialize)]
struct Group {
    month: String,
    currency: String,
    invoice_count: u32,
    total: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    report_type: &'static str,
    source_sha256: String,
    record_count: u32,
    groups: Vec<Group>,
}

fn calculate(bytes: &[u8]) -> Result<Report> {
    let rows = parse_csv(bytes)?;
    let header = &rows[0];
    let mut names = BTreeSet::new();
    for name in header {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || !names.insert(name.as_str())
        {
            return Err("invalid or duplicate invoice CSV header".into());
        }
    }
    let find = |name: &str| {
        header
            .iter()
            .position(|h| h == name)
            .ok_or("missing invoice CSV column")
    };
    let date = find("invoice_date")?;
    let amount = find("amount")?;
    let currency = find("currency")?;
    let mut totals: BTreeMap<(String, String), (u32, i128)> = BTreeMap::new();
    for row in rows.iter().skip(1) {
        if row.len() != header.len() {
            return Err("ragged invoice CSV record".into());
        }
        let month = date_month(&row[date])?;
        let value = cents(&row[amount])?;
        let code = &row[currency];
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err("invoice currency must be a three-letter uppercase code".into());
        }
        let entry = totals.entry((month, code.clone())).or_insert((0, 0));
        entry.0 = entry.0.checked_add(1).ok_or("invoice count overflow")?;
        entry.1 = entry.1.checked_add(value).ok_or("invoice total overflow")?;
    }
    let groups = totals
        .into_iter()
        .map(|((month, currency), (invoice_count, total))| Group {
            month,
            currency,
            invoice_count,
            total: formatted_cents(total),
        })
        .collect();
    Ok(Report {
        schema_version: 1,
        report_type: "invoice-summary-v1",
        source_sha256: bundle::hex(&Sha256::digest(bytes)),
        record_count: (rows.len() - 1) as u32,
        groups,
    })
}

pub(crate) fn report_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&calculate(bytes)?)?)
}

pub(crate) fn source_stdin() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("oversized invoice CSV".into());
    }
    Ok(bytes)
}

pub fn calculate_stdin() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let bytes = source_stdin()?;
    let result = crate::workflow_resource::calculate(&bytes)?;
    result.recheck(&bytes, &crate::artifacts::installation()?)?;
    let mut output = result.report;
    output.push(b'\n');
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_totals_are_exact_and_bound_to_source() {
        let source = include_bytes!("../../../examples/invoices.csv");
        let report = calculate(source).unwrap();
        assert_eq!(report.record_count, 5);
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].month, "2026-09");
        assert_eq!(report.groups[0].currency, "USD");
        assert_eq!(report.groups[0].total, "1420.20");
        assert_eq!(report.source_sha256, bundle::hex(&Sha256::digest(source)));
        assert_eq!(
            report_bytes(source).unwrap(),
            serde_json::to_vec(&report).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&report).unwrap(),
            serde_json::to_vec(&calculate(source).unwrap()).unwrap()
        );
    }

    #[test]
    fn quoted_fields_crlf_and_sorted_separate_currencies() {
        let data = b"invoice_date,amount,currency,vendor\r\n2026-02-28,-1.5,USD,\"A, B\"\r\n2024-02-29,2,EUR,C\r\n2026-02-01,3.25,USD,D\r\n";
        let report = calculate(data).unwrap();
        assert_eq!(report.record_count, 3);
        assert_eq!(report.groups[0].month, "2024-02");
        assert_eq!(report.groups[0].total, "2.00");
        assert_eq!(report.groups[1].month, "2026-02");
        assert_eq!(report.groups[1].total, "1.75");
    }

    #[test]
    fn malformed_csv_dates_amounts_and_currency_are_denied() {
        let valid = "invoice_date,amount,currency\n2026-09-15,1.25,USD\n";
        for bad in [
            "invoice_date,amount,currency\n2026-09-15,1.25\n",
            "invoice_date,amount,amount,currency\n2026-09-15,1.25,1.25,USD\n",
            "invoice_date,amount,currency\n2026-09-15,1.25,usd\n",
            "invoice_date,amount,currency\n2026-02-29,1.25,USD\n",
            "invoice_date,amount,currency\n2026-09-15,1.234,USD\n",
            "invoice_date,amount,currency\n2026-09-15,NaN,USD\n",
            "invoice_date,amount,currency\n2026-09-15,\"1.25,USD\n",
            "invoice_date,amount,currency\n2026-09-15,1\".25,USD\n",
            "invoice_date,amount,currency\n\n2026-09-15,1.25,USD\n",
        ] {
            assert!(calculate(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(calculate(valid.as_bytes()).is_ok());
        assert!(calculate(&vec![b'x'; MAX_SOURCE_BYTES as usize + 1]).is_err());
        assert!(calculate(b"invoice_date,amount,currency\n2026-09-15,1.25,USD\0\n").is_err());
    }

    #[test]
    fn negative_totals_and_quoted_escaped_text_do_not_enter_report() {
        let data = b"invoice_date,amount,currency,vendor\n2026-01-01,-1.01,USD,\"A \"\"quoted\"\" vendor\"\n2026-01-02,0.01,USD,B\n";
        let report = calculate(data).unwrap();
        assert_eq!(report.groups[0].total, "-1.00");
        assert!(!String::from_utf8(serde_json::to_vec(&report).unwrap())
            .unwrap()
            .contains("vendor"));
    }

    #[test]
    fn field_and_record_limits_are_enforced() {
        let long_vendor = format!(
            "invoice_date,amount,currency,vendor\n2026-01-01,1.00,USD,{}\n",
            "x".repeat(MAX_FIELD_BYTES + 1)
        );
        assert!(calculate(long_vendor.as_bytes()).is_err());
        let many_rows = format!(
            "invoice_date,amount,currency\n{}",
            "2026-01-01,1.00,USD\n".repeat(MAX_ROWS)
        );
        assert!(calculate(many_rows.as_bytes()).is_err());
    }
}
