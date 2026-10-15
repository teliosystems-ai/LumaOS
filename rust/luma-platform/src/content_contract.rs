//! Unprivileged, bounded data inspection. No filesystem or effect authority.
use crate::Result;
use luma_content::{
    ArtifactVersion, EditDecision, Format, OwnerBinding, Provenance, VersionReference,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};

const MAX_REQUEST: usize = 2 * luma_content::MAX_ENVELOPE_BYTES + 8192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema_version: u32,
    binding: OwnerBinding,
    artifact_id: String,
    format: Format,
    content: String,
    provenance: Provenance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reopen {
    schema_version: u32,
    binding: OwnerBinding,
    envelope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Compare {
    schema_version: u32,
    binding: OwnerBinding,
    current_envelope: String,
    expected: VersionReference,
    content: String,
    provenance: Provenance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableEdit {
    schema_version: u32,
    current_envelope: String,
    edit: luma_content::table::TableEditRequest,
}

fn schema(version: u32) -> Result<()> {
    if version != 1 {
        return Err("unsupported editable-content request schema".into());
    }
    Ok(())
}

fn rendered(version: &ArtifactVersion) -> Result<Value> {
    Ok(
        json!({"receipt":version.receipt(),"reference":version.reference()?,
        "canonical_envelope":String::from_utf8(version.canonical_envelope()?)?}),
    )
}

fn process(command: &str, bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("editable-content request exceeds fixed transport bound".into());
    }
    let result = match command {
        "content-contract-spreadsheet" => {
            let calculation = luma_content::spreadsheet::calculate(bytes)?;
            json!({"operation":"spreadsheet","calculation":calculation,
                "typed_expressions_evaluated":true,"csv_formula_text_executed":false,
                "source_retained":false})
        }
        "content-contract-native-request" => {
            let canonical = crate::content_governed::canonical_request(bytes)?;
            json!({"operation":"native-request","request_sha256":luma_content::sha256(&canonical),
                "canonical_request":String::from_utf8(canonical)?,"private_content_read":false})
        }
        "content-contract-capture" => {
            let request: Capture = serde_json::from_slice(bytes)?;
            schema(request.schema_version)?;
            let version = luma_content::capture(
                request.binding,
                &request.artifact_id,
                request.format,
                request.content.as_bytes(),
                request.provenance,
            )?;
            json!({"operation":"capture","proposed":rendered(&version)?})
        }
        "content-contract-reopen" => {
            let request: Reopen = serde_json::from_slice(bytes)?;
            schema(request.schema_version)?;
            let version = luma_content::reopen(request.envelope.as_bytes(), &request.binding)?;
            json!({"operation":"reopen","validated":rendered(&version)?})
        }
        "content-contract-compare" => {
            let request: Compare = serde_json::from_slice(bytes)?;
            schema(request.schema_version)?;
            let current =
                luma_content::reopen(request.current_envelope.as_bytes(), &request.binding)?;
            match luma_content::compare_external_edit(
                &current,
                &request.expected,
                &request.binding,
                request.content.as_bytes(),
                request.provenance,
            )? {
                EditDecision::NoChange {
                    current,
                    observed_source_sha256,
                } => {
                    json!({"operation":"compare","decision":"no-change", "current":current,
                        "observed_source_sha256":observed_source_sha256})
                }
                EditDecision::NewVersion(proposed) => {
                    json!({"operation":"compare","decision":"new-version","proposed":rendered(&proposed)?})
                }
                EditDecision::Conflict {
                    expected,
                    current,
                    candidate,
                } => {
                    candidate.canonical_bytes()?;
                    json!({"operation":"compare","decision":"conflict","expected":expected,
                        "current":current,"candidate":candidate,"automatically_merged":false})
                }
            }
        }
        "content-contract-table-edit" => {
            let request: TableEdit = serde_json::from_slice(bytes)?;
            schema(request.schema_version)?;
            let current =
                luma_content::reopen(request.current_envelope.as_bytes(), &request.edit.binding)?;
            // Return the canonical edit input as well as its digest. A caller that
            // retains a conflict must preserve these actual bytes, not just a hash.
            let canonical_edit = String::from_utf8(request.edit.canonical_bytes()?)?;
            let decision = match luma_content::table::apply(&current, &request.edit)? {
                luma_content::table::Decision::NoChange {
                    current,
                    edit_sha256,
                } => {
                    json!({"decision":"no-change","current":current,"edit_sha256":edit_sha256})
                }
                luma_content::table::Decision::NewVersion {
                    version,
                    edit_sha256,
                } => {
                    json!({"decision":"new-version","proposed":rendered(&version)?,
                        "edit_sha256":edit_sha256})
                }
                luma_content::table::Decision::Conflict {
                    expected,
                    current,
                    edit_sha256,
                } => {
                    json!({"decision":"conflict","expected":expected,"current":current,
                        "edit_sha256":edit_sha256,"automatically_merged":false})
                }
            };
            json!({"operation":"table-edit","outcome":decision,"canonical_edit":canonical_edit,
                "formulas_executed":false,"request_retained":false})
        }
        _ => return Err("unsupported editable-content operation".into()),
    };
    Ok(
        json!({"schema_version":1,"result":result,"owner_authenticated":false,
        "authority_returned":false,"committed":false,"certified":false,"gate_closing":false}),
    )
}

pub(crate) fn stdin(command: &str) -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let output = serde_json::to_vec(&process(command, &bytes)?)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Value {
        json!({"installation":"a".repeat(64),"owner":"b".repeat(64),"owner_generation":7})
    }
    fn provenance(content: &str, origin: &str) -> Value {
        json!({"request_id":"edit-one","workflow_sha256":"c".repeat(64),
            "source_sha256":luma_content::sha256(content.as_bytes()),"origin":origin})
    }
    fn capture(content: &str) -> Value {
        let request = json!({"schema_version":1,"binding":binding(),"artifact_id":"document-one",
            "format":"utf8-text","content":content,"provenance":provenance(content,"managed")});
        process(
            "content-contract-capture",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn capture_and_reopen_are_deterministic_data_without_owner_or_commit_authority() {
        let captured = capture("Example\n");
        let request = json!({"schema_version":1,"binding":binding(),
            "envelope":captured["result"]["proposed"]["canonical_envelope"]});
        let first = process(
            "content-contract-reopen",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        let second = process(
            "content-contract-reopen",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first["result"]["validated"], captured["result"]["proposed"]);
        for output in [first, captured] {
            for flag in [
                "owner_authenticated",
                "authority_returned",
                "committed",
                "certified",
                "gate_closing",
            ] {
                assert_eq!(output[flag], false);
            }
        }
    }

    #[test]
    fn external_changes_propose_a_new_version_and_stale_saves_preserve_conflicts() {
        let captured = capture("Original\n");
        let base = &captured["result"]["proposed"];
        let mut request = json!({"schema_version":1,"binding":binding(),
            "current_envelope":base["canonical_envelope"],"expected":base["reference"],
            "content":"Changed\n","provenance":provenance("Changed\n","external")});
        let changed = process(
            "content-contract-compare",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        assert_eq!(changed["result"]["decision"], "new-version");
        assert_eq!(changed["result"]["proposed"]["receipt"]["version"], 2);
        request["current_envelope"] = changed["result"]["proposed"]["canonical_envelope"].clone();
        let conflict = process(
            "content-contract-compare",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        assert_eq!(conflict["result"]["decision"], "conflict");
        assert_eq!(conflict["result"]["candidate"]["content"], "Changed\n");
        assert_eq!(conflict["result"]["automatically_merged"], false);
        request["expected"] = changed["result"]["proposed"]["reference"].clone();
        let same = process(
            "content-contract-compare",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        assert_eq!(same["result"]["decision"], "no-change");
    }

    #[test]
    fn malformed_or_mismatched_requests_cannot_reopen_or_bypass_bounds() {
        assert!(process("content-contract-capture", b"").is_err());
        assert!(process("content-contract-capture", &vec![b' '; MAX_REQUEST + 1]).is_err());
        assert!(process("content-contract-execute", b"{}").is_err());
        let captured = capture("Example\n");
        let base = &captured["result"]["proposed"];
        let mut request =
            json!({"schema_version":1,"binding":binding(),"envelope":base["canonical_envelope"]});
        request["binding"]["owner_generation"] = json!(8);
        assert!(process(
            "content-contract-reopen",
            &serde_json::to_vec(&request).unwrap()
        )
        .is_err());
        request["binding"] = binding();
        request["schema_version"] = json!(2);
        assert!(process(
            "content-contract-reopen",
            &serde_json::to_vec(&request).unwrap()
        )
        .is_err());
        request["schema_version"] = json!(1);
        request["grant"] = json!("not-authority");
        assert!(process(
            "content-contract-reopen",
            &serde_json::to_vec(&request).unwrap()
        )
        .is_err());
    }
}
