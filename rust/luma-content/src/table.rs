//! Atomic, deterministic CSV table-edit proposals. No formulas or expressions run.
//!
//! Positions are zero-based and interpreted sequentially, including the first
//! row: there is no inferred header or type coercion. An exact stale base returns
//! a conflict before positions are applied to different bytes. Storage publication,
//! durable audit and authorization remain the caller's responsibility.

use crate::{
    canonical, capture_content, identifier, make_version, nonzero_digest, sha256, ArtifactVersion,
    EditOrigin, Error, Format, OwnerBinding, Provenance, Result, VersionReference,
    MAX_CONTENT_BYTES, MAX_CSV_COLUMNS, MAX_CSV_FIELD_BYTES, MAX_CSV_ROWS,
};
use serde::{Deserialize, Serialize};

pub const MAX_OPERATIONS: usize = 256;
pub const MAX_INPUT_CELLS: usize = MAX_CSV_ROWS * MAX_CSV_COLUMNS;
pub const MAX_REQUEST_BYTES: usize = 8 * MAX_CONTENT_BYTES;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    SetCell {
        row: u32,
        column: u32,
        value: String,
    },
    InsertRow {
        index: u32,
        values: Vec<String>,
    },
    DeleteRow {
        index: u32,
    },
    InsertColumn {
        index: u32,
        values: Vec<String>,
    },
    DeleteColumn {
        index: u32,
    },
}

/// Caller-supplied descriptive provenance, never authentication or a grant.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditMetadata {
    pub request_id: String,
    pub workflow_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TableEditRequest {
    pub binding: OwnerBinding,
    pub expected: VersionReference,
    pub metadata: EditMetadata,
    pub operations: Vec<Operation>,
}

impl TableEditRequest {
    /// Deterministic inert audit input. Positions and shape still need a live base.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::InvalidEdit)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.expected.validate()?;
        if !identifier(&self.metadata.request_id) || !nonzero_digest(&self.metadata.workflow_sha256)
        {
            return Err(Error::InvalidProvenance);
        }
        if self.operations.is_empty() || self.operations.len() > MAX_OPERATIONS {
            return Err(Error::Bounds);
        }
        let mut cells = 0_usize;
        let mut payload = 0_usize;
        let mut visit = |value: &String| -> Result<()> {
            validate_cell(value)?;
            cells = cells.checked_add(1).ok_or(Error::Bounds)?;
            payload = payload.checked_add(value.len()).ok_or(Error::Bounds)?;
            if cells > MAX_INPUT_CELLS || payload > MAX_CONTENT_BYTES {
                return Err(Error::Bounds);
            }
            Ok(())
        };
        for operation in &self.operations {
            match operation {
                Operation::SetCell { row, column, value } => {
                    if *row as u64 >= MAX_CSV_ROWS as u64
                        || *column as u64 >= MAX_CSV_COLUMNS as u64
                    {
                        return Err(Error::InvalidEdit);
                    }
                    visit(value)?;
                }
                Operation::InsertRow { index, values } => {
                    if *index as u64 > MAX_CSV_ROWS as u64
                        || values.is_empty()
                        || values.len() > MAX_CSV_COLUMNS
                    {
                        return Err(Error::InvalidEdit);
                    }
                    for value in values {
                        visit(value)?;
                    }
                }
                Operation::InsertColumn { index, values } => {
                    if *index as u64 > MAX_CSV_COLUMNS as u64
                        || values.is_empty()
                        || values.len() > MAX_CSV_ROWS
                    {
                        return Err(Error::InvalidEdit);
                    }
                    for value in values {
                        visit(value)?;
                    }
                }
                Operation::DeleteRow { index } => {
                    if *index as u64 >= MAX_CSV_ROWS as u64 {
                        return Err(Error::InvalidEdit);
                    }
                }
                Operation::DeleteColumn { index } => {
                    if *index as u64 >= MAX_CSV_COLUMNS as u64 {
                        return Err(Error::InvalidEdit);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    NoChange {
        current: VersionReference,
        edit_sha256: String,
    },
    NewVersion {
        version: ArtifactVersion,
        edit_sha256: String,
    },
    /// Preserve the exact request by its digest; no positional edit was applied.
    Conflict {
        expected: VersionReference,
        current: VersionReference,
        edit_sha256: String,
    },
}

/// Propose all operations together or fail without changing `current`.
///
/// Every intermediate table must fit the same bounds as the final table. A
/// compensating later operation cannot authorize a temporary oversized state.
/// Empty tables are deliberately excluded; at least one row and column remain.
pub fn apply(current: &ArtifactVersion, request: &TableEditRequest) -> Result<Decision> {
    current.validate()?;
    let edit_sha256 = sha256(&request.canonical_bytes()?);
    if current.receipt().binding != request.binding {
        return Err(Error::OwnerMismatch);
    }
    if current.receipt().artifact_id != request.expected.artifact_id {
        return Err(Error::InvalidIdentifier);
    }
    if current.receipt().format != Format::Csv {
        return Err(Error::InvalidEdit);
    }
    let reference = current.reference()?;
    if request.expected != reference {
        return Ok(Decision::Conflict {
            expected: request.expected.clone(),
            current: reference,
            edit_sha256,
        });
    }
    let mut rows = canonical::csv_rows(&current.content)?;
    for operation in &request.operations {
        apply_one(&mut rows, operation)?;
        // Re-render after each operation to enforce quoting-expansion and byte
        // limits as well as structural bounds, without publishing any bytes.
        canonical::csv_bytes(&rows)?;
    }
    let source = canonical::csv_bytes(&rows)?;
    if source == current.content {
        return Ok(Decision::NoChange {
            current: reference,
            edit_sha256,
        });
    }
    let next = current
        .receipt()
        .version
        .checked_add(1)
        .ok_or(Error::VersionOverflow)?;
    let provenance = Provenance {
        request_id: request.metadata.request_id.clone(),
        workflow_sha256: request.metadata.workflow_sha256.clone(),
        source_sha256: sha256(source.as_bytes()),
        origin: EditOrigin::Managed,
    };
    let captured = capture_content(
        &request.binding,
        &request.expected.artifact_id,
        Format::Csv,
        source.as_bytes(),
        provenance,
    )?;
    let version = make_version(
        request.binding.clone(),
        &request.expected.artifact_id,
        next,
        Some(reference),
        captured,
    )?;
    Ok(Decision::NewVersion {
        version,
        edit_sha256,
    })
}

fn validate_cell(value: &str) -> Result<()> {
    if value.len() > MAX_CSV_FIELD_BYTES {
        return Err(Error::Bounds);
    }
    // New cell strings already use canonical LF. Never silently interpret CR,
    // NUL or other C0 controls as a spreadsheet operation or a line separator.
    if value.chars().any(|c| c < ' ' && !matches!(c, '\t' | '\n')) {
        return Err(Error::InvalidText);
    }
    Ok(())
}

fn apply_one(rows: &mut Vec<Vec<String>>, operation: &Operation) -> Result<()> {
    let width = rows[0].len();
    match operation {
        Operation::SetCell { row, column, value } => {
            let target = rows
                .get_mut(*row as usize)
                .and_then(|row| row.get_mut(*column as usize))
                .ok_or(Error::InvalidEdit)?;
            target.clone_from(value);
        }
        Operation::InsertRow { index, values } => {
            if *index as usize > rows.len() || values.len() != width {
                return Err(Error::InvalidEdit);
            }
            if rows.len() >= MAX_CSV_ROWS {
                return Err(Error::Bounds);
            }
            rows.insert(*index as usize, values.clone());
        }
        Operation::DeleteRow { index } => {
            if *index as usize >= rows.len() || rows.len() <= 1 {
                return Err(Error::InvalidEdit);
            }
            rows.remove(*index as usize);
        }
        Operation::InsertColumn { index, values } => {
            if *index as usize > width || values.len() != rows.len() {
                return Err(Error::InvalidEdit);
            }
            if width >= MAX_CSV_COLUMNS {
                return Err(Error::Bounds);
            }
            for (row, value) in rows.iter_mut().zip(values) {
                row.insert(*index as usize, value.clone());
            }
        }
        Operation::DeleteColumn { index } => {
            if *index as usize >= width || width <= 1 {
                return Err(Error::InvalidEdit);
            }
            for row in rows {
                row.remove(*index as usize);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
