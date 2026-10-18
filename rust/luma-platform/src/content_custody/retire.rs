//! Reviewed terminal disposition, not healing: no content member is removed,
//! reconstructed or adopted. The protected owner-generation becomes unavailable.
use super::*;
use crate::content_restore::Input;
use crate::finite_grants::{Action, Kind, Selector, Use};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const INSPECT: &str = "content-restore-retire-inspect";
pub(super) const RETIRE: &str = "content-restore-retire";
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Request {
    pub input: Input,
    pub expected_review_sha256: Option<String>,
}
impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            input: Input,
            expected_review_sha256: serde_json::Value,
        }
        let fields = Fields::deserialize(deserializer)?;
        let expected_review_sha256 = match fields.expected_review_sha256 {
            serde_json::Value::Null => None,
            serde_json::Value::String(value) => Some(value),
            _ => {
                return Err(serde::de::Error::custom(
                    "retirement review must be explicitly null or an exact SHA-256 string",
                ))
            }
        };
        Ok(Self {
            input: fields.input,
            expected_review_sha256,
        })
    }
}

fn parse_request(bytes: &[u8], exact: bool) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > crate::content_restore::MAX_REQUEST {
        return Err("retirement request exceeds its fixed public-data bound".into());
    }
    let request: Request = serde_json::from_slice(bytes)?;
    request.validate()?;
    let canonical = serde_json::to_vec(&request)?;
    if canonical.len() > crate::content_restore::MAX_REQUEST || (exact && canonical != bytes) {
        return Err("retirement request is oversized or not exact canonical data".into());
    }
    Ok(request)
}

fn preparation(bytes: &[u8]) -> Result<serde_json::Value> {
    let request = parse_request(bytes, false)?;
    let (command, phase) = if request.expected_review_sha256.is_some() {
        (RETIRE, "recover-exact-protected-review")
    } else {
        (INSPECT, "inspect-protected-retirement")
    };
    let canonical = serde_json::to_vec(&request)?;
    let usage = request.usage(command)?;
    Ok(
        serde_json::json!({"schema_version":1,"canonical_request":String::from_utf8(canonical.clone())?,
        "request_sha256":hash(&canonical),"phase":phase,"usage":usage,
        "protected_review_authenticated":false,"private_authority_read":false,"admin_authenticated":false,
        "grant_issued":false,"owner_marked_unavailable":false,"authority_returned":false}),
    )
}

/// Public DATA preparation only: no filesystem, TPM, principal/session, custody
/// service or grant constructor is consulted, even when a review SHA is present.
pub(crate) fn prepare_stdin() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(crate::content_restore::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    println!("{}", serde_json::to_string(&preparation(&bytes)?)?);
    Ok(())
}
impl Request {
    fn validate(&self) -> Result<()> {
        self.input.validate()?;
        if self.input.review.is_none() {
            return Err("retirement requires an existing exact restore batch review".into());
        }
        if let Some(sha) = &self.expected_review_sha256 {
            digest(sha)?;
        }
        Ok(())
    }
    fn inspection_digest(&self) -> Result<String> {
        self.validate()?;
        let mut input = self.input.clone();
        input.capsule_path = "/runtime-original-snapshot/content-restore.cms".into();
        Ok(hash(&serde_json::to_vec(&(
            "luma-content-restore-retirement-inspection-v1",
            input,
        ))?))
    }
    pub(super) fn usage(&self, command: &str) -> Result<Use> {
        self.validate()?;
        let recover = command == RETIRE;
        let sha = if recover {
            self.expected_review_sha256
                .clone()
                .ok_or("retirement requires the genuine prior protected review")?
        } else {
            if command != INSPECT || self.expected_review_sha256.is_some() {
                return Err("retirement inspection cannot dispatch a reviewed effect".into());
            }
            self.inspection_digest()?
        };
        let usage = Use {
            action: if recover {
                Action::RecoverResource
            } else {
                Action::Read
            },
            selector: Selector {
                kind: if recover { Kind::Resource } else { Kind::File },
                id: if recover {
                    "content-restore-retire-v1"
                } else {
                    "content-restore-retire-read-v1"
                }
                .into(),
                generation: self.input.admin.owner_generation,
                digest: sha,
            },
            input_bytes: 0,
            output_bytes: 8192,
            units: 1,
        };
        scope(command, &usage)?;
        Ok(usage)
    }
}
pub(crate) fn scope(command: &str, usage: &Use) -> Result<()> {
    usage.validate()?;
    let (action, kind, id) = match command {
        INSPECT => (Action::Read, Kind::File, "content-restore-retire-read-v1"),
        RETIRE => (
            Action::RecoverResource,
            Kind::Resource,
            "content-restore-retire-v1",
        ),
        _ => return Err("unsupported closed restore retirement command".into()),
    };
    if usage.action != action
        || usage.selector.kind != kind
        || usage.selector.id != id
        || usage.input_bytes != 0
        || usage.output_bytes != 8192
        || usage.units != 1
    {
        return Err(
            "restore retirement scope differs from exact inspection/recovery action".into(),
        );
    }
    digest(&usage.selector.digest)
}
pub(crate) fn read_request(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > crate::content_restore::MAX_REQUEST as u64
    {
        return Err("retirement request exceeds closed single-link data bound".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(crate::content_restore::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || file_identity(&before) != file_identity(&file.metadata()?)
        || file_identity(&before) != file_identity(&fs::symlink_metadata(path)?)
    {
        return Err("retirement request changed during capture".into());
    }
    parse_request(&bytes, true)?;
    Ok(bytes)
}
pub(crate) fn verify_staged(path: &Path, command: &str, usage: &Use) -> Result<()> {
    if !crate::content_restore::staged_path(path, "content-restore-retire.json")
        || fs::canonicalize(path)? != path
    {
        return Err("retirement requires its exact original launcher namespace".into());
    }
    crate::content_restore::require_stage(path, "content-restore-retire.json")?;
    let request: Request = canonical(&read_request(path)?, crate::content_restore::MAX_REQUEST)?;
    if request.usage(command)? != *usage {
        return Err("retirement staged request differs from original finite scope".into());
    }
    crate::content_restore::require_stage(path, "content-restore-retire.json")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    schema_version: u32,
    purpose: String,
    installation: String,
    binding: OwnerBinding,
    batch_review_sha256: String,
    capsule_sha256: String,
    origin_spki_sha256: String,
    start_sha256: String,
    checkpoint_head: String,
    state: VerifiedState,
    disposition: String,
}
impl Review {
    fn sha256(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retirement {
    review: Review,
    original_authority: Audit,
}
pub(super) fn principal_unavailable(binding: &OwnerBinding, state: &Validated) -> Result<bool> {
    Ok(state.retired.contains(&owner_key(binding)?))
}
pub(super) fn validate_event(
    value: &Retirement,
    installation: &str,
    state: &mut Validated,
) -> Result<()> {
    let review = &value.review;
    let key = owner_key(&review.binding)?;
    let start = state
        .restores
        .get(&key)
        .ok_or("retirement has no exact independently protected restore start")?;
    let expected = start.retirement_review(installation, state)?;
    if serde_json::to_vec(review)? != serde_json::to_vec(&expected)? || state.retired.contains(&key)
    {
        return Err(
            "retirement does not extend its exact current protected batch or repeats a disposition"
                .into(),
        );
    }
    value.original_authority.validate()?;
    scope(RETIRE, &value.original_authority.usage)?;
    if value.original_authority.usage.selector.digest != review.sha256()?
        || value.original_authority.operation_id.is_none()
    {
        return Err("retirement event lacks exact original reviewed Admin recovery".into());
    }
    state.retired.insert(key);
    Ok(())
}
impl super::restore::Start {
    pub(super) fn retirement_review(
        &self,
        installation: &str,
        state: &Validated,
    ) -> Result<Review> {
        self.validate(installation)?;
        let binding = self.input.target.clone();
        let key = owner_key(&binding)?;
        if state.retired.contains(&key) {
            return Err("content owner-generation is already unavailable".into());
        }
        let cut = match state.owners.get(&key) {
            Some(c) => c.clone(),
            None => VerifiedState::empty(&binding)?,
        };
        Ok(Review {
            schema_version: 1,
            purpose: "luma-content-restore-terminal-disposition-v1".into(),
            installation: installation.into(),
            binding,
            batch_review_sha256: self.review()?.review_sha256.clone(),
            capsule_sha256: self.input.capsule_sha256.clone(),
            origin_spki_sha256: self.input.independently_selected_origin_spki_sha256.clone(),
            start_sha256: hash(&serde_json::to_vec(self)?),
            checkpoint_head: bundle::hex(&state.checkpoint),
            state: cut,
            disposition:
                "mark-owner-generation-unavailable-preserve-all-published-pending-quarantine-bytes"
                    .into(),
        })
    }
}
impl<A: Checkpoint> Store<A> {
    fn retirement_review(
        &mut self,
        request: &Request,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Review> {
        request.validate()?;
        self.live(check)?;
        let key = owner_key(&request.input.target)?;
        let start = self
            .state
            .restores
            .get(&key)
            .ok_or("retirement target has no protected restore batch")?;
        if !start.matches_input(&request.input)? {
            return Err("retirement substitutes a different reviewed restore batch".into());
        }
        start.retirement_review(&self.journal.installation, &self.state)
    }
    pub(super) fn execute_retirement(
        &mut self,
        request: &Request,
        command: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        request.validate()?;
        audit.validate()?;
        self.live(check)?;
        if audit.usage != request.usage(command)?
            || audit.subject != request.input.admin.owner
            || audit.subject_generation != request.input.admin.owner_generation
            || audit.operation_id.is_none()
            || request.input.target.installation != self.journal.installation
        {
            return Err(
                "retirement lacks genuine current original-Admin exact scope/installation".into(),
            );
        }
        if command == INSPECT {
            let review = self.retirement_review(request, check)?;
            let sha = review.sha256()?;
            self.live(check)?;
            return Ok(
                serde_json::json!({"schema_version":1,"review":review,"review_sha256":sha,
                "owner_marked_unavailable":false,"content_bytes_changed":false,"TPM_extended":false,"authority_returned":false}),
            );
        }
        if command != RETIRE {
            return Err("unsupported retirement dispatch".into());
        }
        let wanted = request
            .expected_review_sha256
            .as_ref()
            .ok_or("retirement exact review absent")?;
        if let Some(prior) = self.journal.events.iter().find_map(|event| match event {
            Event::RestoreRetired(value) if value.review.binding == request.input.target => {
                Some(value)
            }
            _ => None,
        }) {
            if prior.review.sha256()? != *wanted {
                return Err("retirement retry differs from preserved protected disposition".into());
            }
            let start = self
                .state
                .restores
                .get(&owner_key(&request.input.target)?)
                .ok_or("retired batch missing")?;
            if !start.matches_input(&request.input)? {
                return Err("retirement retry substitutes its original batch".into());
            }
        } else {
            let review = self.retirement_review(request, check)?;
            if review.sha256()? != *wanted {
                return Err("protected restore state changed; inspect and approve a fresh terminal disposition".into());
            }
            self.commit(
                Event::RestoreRetired(Retirement {
                    review,
                    original_authority: audit.clone(),
                }),
                check,
            )?;
        }
        self.live(check)?;
        Ok(
            serde_json::json!({"schema_version":1,"binding":request.input.target,"review_sha256":wanted,
            "owner_marked_unavailable":true,"checkpoint_head":bundle::hex(&self.state.checkpoint),"content_bytes_changed":false,
            "published_records_rolled_back":false,"pending_evidence_removed":false,"damaged_data_healed":false,
            "new_restore_requires_independently_provisioned_fresh_owner_binding":true,"authority_returned":false,"production_qualified":false}),
        )
    }
}
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let proposal = args.first().map(String::as_str) == Some("content-restore-retire-proposal");
    if args.len() != if proposal { 3 } else { 4 }
        || (!proposal && !matches!(args[0].as_str(), INSPECT | RETIRE))
    {
        return Err("expected content-restore-retire-proposal LOGIN REQUEST | content-restore-retire-{inspect|} LOGIN GRANT REQUEST".into());
    }
    let path = Path::new(args.last().ok_or("retirement request absent")?);
    let request: Request = canonical(&read_request(path)?, crate::content_restore::MAX_REQUEST)?;
    if request.input.login != args[1] {
        return Err("retirement login differs from exact request".into());
    }
    let command = if proposal {
        if request.expected_review_sha256.is_some() {
            RETIRE
        } else {
            INSPECT
        }
    } else {
        &args[0]
    };
    let usage = request.usage(command)?;
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"usage":usage,"private_authority_read":false,
        "owner_marked_unavailable":false,"authority_returned":false})
        );
        return Ok(());
    }
    verify_staged(path, command, &usage)?;
    let result =
        crate::admin_governance::with_grant(&request.input.login, &args[2], &usage, |boundary| {
            boundary.require_admin()?;
            if boundary.subject()? != request.input.admin.owner
                || boundary.subject_generation()? != request.input.admin.owner_generation
            {
                return Err("retirement current Admin differs from staged original request".into());
            }
            let pending = if command == RETIRE {
                Some(boundary.effect_begin(
                    &usage.selector.digest,
                    crate::policy_decisions::EffectKind::Recovery,
                )?)
            } else {
                None
            };
            let value =
                crate::service::content_admin::run(command, &usage, boundary, |job, cancel| {
                    super::protocol::admin_retirement_exchange(
                        command,
                        &usage,
                        &request.input.target.installation,
                        &job,
                        request.clone(),
                        cancel,
                    )
                })?;
            boundary.require_admin()?;
            if let Some(pending) = pending {
                boundary.effect_complete(pending, &hash(&serde_json::to_vec(&value)?))?;
            }
            boundary.require_admin()?;
            Ok(value)
        })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use luma_content_store::{RestoreReview, RestoreStepReview};

    fn request() -> Request {
        let origin = OwnerBinding {
            installation: "11".repeat(32),
            owner: "22".repeat(32),
            owner_generation: 1,
        };
        let target = OwnerBinding {
            installation: "33".repeat(32),
            owner: "44".repeat(32),
            owner_generation: 1,
        };
        let mut review = RestoreReview {
            schema_version: 1,
            profile: "luma-fresh-owner-content-restore-v1".into(),
            origin,
            target: target.clone(),
            archive_sha256: "66".repeat(32),
            archive_bytes: 21,
            manifest_sha256: "77".repeat(32),
            origin_head_sha256: "88".repeat(32),
            workflow_sha256: crate::content_restore::graph_sha256(),
            request_namespace: "restore.fixture".into(),
            published_outcomes: 1,
            inert_committed_outcomes: 0,
            inert_pending_directories: 0,
            inert_quarantined_directories: 0,
            planned_storage_bytes: 8192,
            mappings_sha256: "99".repeat(32),
            steps: vec![RestoreStepReview {
                request_id: "restore.fixture.1".into(),
                review_sha256: "aa".repeat(32),
            }],
            review_sha256: String::new(),
        };
        review.review_sha256 = hash(&serde_json::to_vec(&review).unwrap());
        review.validate().unwrap();
        let value = Request {
            input: Input {
                schema_version: 1,
                login: "admin".into(),
                admin: OwnerBinding {
                    installation: target.installation.clone(),
                    owner: "55".repeat(32),
                    owner_generation: 7,
                },
                target_login: "target".into(),
                target,
                independently_selected_origin_spki_sha256: "bb".repeat(32),
                request_namespace: "restore.fixture".into(),
                key_role: crate::content_restore::KeyRole::OfflineAdmin,
                capsule_path: "/not-opened/public-data-only.cms".into(),
                capsule_bytes: 4096,
                capsule_sha256: "cc".repeat(32),
                review: Some(review),
            },
            expected_review_sha256: None,
        };
        value.validate().unwrap();
        value
    }

    #[test]
    fn public_preparation_canonicalizes_only_explicit_phase_data() {
        let mut request = request();
        for (expected, command, phase, action, kind, selector) in [
            (
                None,
                INSPECT,
                "inspect-protected-retirement",
                Action::Read,
                Kind::File,
                "content-restore-retire-read-v1",
            ),
            (
                Some("dd".repeat(32)),
                RETIRE,
                "recover-exact-protected-review",
                Action::RecoverResource,
                Kind::Resource,
                "content-restore-retire-v1",
            ),
        ] {
            request.expected_review_sha256 = expected;
            let canonical = serde_json::to_vec(&request).unwrap();
            let pretty = serde_json::to_vec_pretty(&request).unwrap();
            let prepared = preparation(&pretty).unwrap();
            assert_eq!(prepared["phase"], phase);
            assert_eq!(prepared["request_sha256"], hash(&canonical));
            assert_eq!(
                prepared["canonical_request"],
                String::from_utf8(canonical.clone()).unwrap()
            );
            let parsed = parse_request(&canonical, true).unwrap();
            assert_eq!(serde_json::to_vec(&parsed).unwrap(), canonical);
            let usage: Use = serde_json::from_value(prepared["usage"].clone()).unwrap();
            assert_eq!(usage, request.usage(command).unwrap());
            assert_eq!(usage.action, action);
            assert_eq!(usage.selector.kind, kind);
            assert_eq!(usage.selector.id, selector);
            assert_eq!(usage.selector.generation, 7);
            assert_eq!(
                (usage.input_bytes, usage.output_bytes, usage.units),
                (0, 8192, 1)
            );
            if let Some(expected) = &request.expected_review_sha256 {
                assert_eq!(&usage.selector.digest, expected);
                assert!(request.usage(INSPECT).is_err());
            } else {
                assert!(request.usage(RETIRE).is_err());
            }
            for flag in [
                "protected_review_authenticated",
                "private_authority_read",
                "admin_authenticated",
                "grant_issued",
                "owner_marked_unavailable",
                "authority_returned",
            ] {
                assert_eq!(prepared[flag], false);
            }
            assert!(prepared.get("audit").is_none());
            assert!(prepared.get("signature").is_none());
        }
    }

    #[test]
    fn public_preparation_rejects_ambiguous_duplicate_and_unknown_fields() {
        let bytes = serde_json::to_vec(&request()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replace(
                "\"expected_review_sha256\":null",
                "\"expected_review_sha256\":null,\"expected_review_sha256\":null",
            ),
            text.replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            ),
            text.replace(
                "\"published_outcomes\":1",
                "\"published_outcomes\":1,\"published_outcomes\":1",
            ),
            text.replace(
                "\"request_id\":\"restore.fixture.1\"",
                "\"request_id\":\"restore.fixture.1\",\"request_id\":\"restore.fixture.1\"",
            ),
            text.replacen('{', "{\"unknown\":false,", 1),
            text.replace("\"input\":{", "\"input\":{\"unknown\":false,"),
            text.replace("\"review\":{", "\"review\":{\"unknown\":false,"),
            text.replace(",\"expected_review_sha256\":null", ""),
            "{\"expected_review_sha256\":null}".into(),
        ] {
            assert!(preparation(bad.as_bytes()).is_err(), "accepted {bad}");
        }
        for field in [
            "true",
            "7",
            "{}",
            "[]",
            "\"\"",
            "\"ff\"",
            &format!("\"{}\"", "00".repeat(32)),
            &format!("\"{}\"", "DD".repeat(32)),
            &format!("\"{}\"", "zz".repeat(32)),
        ] {
            let bad = text.replace(
                "\"expected_review_sha256\":null",
                &format!("\"expected_review_sha256\":{field}"),
            );
            assert!(preparation(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn public_preparation_enforces_exact_bounds_and_valid_batch_without_private_io() {
        let request = request();
        let canonical = serde_json::to_vec(&request).unwrap();
        let mut at_limit = canonical.clone();
        at_limit.resize(crate::content_restore::MAX_REQUEST, b' ');
        assert!(preparation(&at_limit).is_ok());
        assert!(parse_request(&at_limit, true).is_err());
        at_limit.push(b' ');
        assert!(preparation(&at_limit).is_err());
        for bytes in [
            Vec::new(),
            b" ".to_vec(),
            [canonical.clone(), canonical.clone()].concat(),
        ] {
            assert!(preparation(&bytes).is_err());
        }
        let mut newline = canonical.clone();
        newline.push(b'\n');
        assert!(preparation(&newline).is_ok());
        assert!(parse_request(&newline, true).is_err());
        let mut data = serde_json::to_value(&request).unwrap();
        data["input"]["review"] = serde_json::Value::Null;
        assert!(preparation(&serde_json::to_vec(&data).unwrap()).is_err());
        data = serde_json::to_value(&request).unwrap();
        data["input"]["review"]["review_sha256"] = "ee".repeat(32).into();
        assert!(preparation(&serde_json::to_vec(&data).unwrap()).is_err());
        data = serde_json::to_value(&request).unwrap();
        data["input"]["target_login"] = "INVALID".into();
        assert!(preparation(&serde_json::to_vec(&data).unwrap()).is_err());
    }
}
