//! Closed human operations. No phase, cursor, map root, builder assertion,
//! arbitrary path, command, authority receipt or implicit retry is accepted.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) schema_version: u32,
    pub(crate) login: String,
    pub(crate) binding: OwnerBinding,
    pub(crate) request_id: String,
    pub(crate) operation: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Operation {
    Status {},
    Start {
        expected_owner_sha256: String,
        expected_selection_sha256: String,
        job_id: String,
        dimensions: u16,
        limits: CorpusIndexLimits,
    },
    Step {
        job_id: String,
        expected_job_sha256: String,
        window: Window,
    },
    Advance {
        job_id: String,
        expected_job_sha256: String,
    },
    Publish {
        job_id: String,
        expected_job_sha256: String,
    },
    Query {
        generation_sha256: String,
        query_kind: QueryKind,
        query: String,
        limit: u8,
        limits: CorpusIndexLimits,
    },
    Retain {
        job_id: String,
        expected_job_sha256: String,
        preparation_sha256: String,
        retained_inventory_sha256: String,
        review_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum QueryKind {
    LexicalAnd,
    FeatureLsa,
}
impl QueryKind {
    pub(crate) fn core(self) -> CorpusQueryKind {
        match self {
            Self::LexicalAnd => CorpusQueryKind::LexicalAnd,
            Self::FeatureLsa => CorpusQueryKind::FeatureLsa,
        }
    }
}

/// A reviewed ceiling, not a requested phase. Its count is interpreted only
/// after C supplies the actual current phase and is bounded again there.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    pub(crate) maximum: u16,
    pub(crate) read_bytes: u64,
    pub(crate) write_bytes: u64,
}
impl Window {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.maximum == 0
            || self.maximum > 8192
            || self.read_bytes == 0
            || self.read_bytes > 64 * 1024 * 1024
            || self.write_bytes > 64 * 1024 * 1024
        {
            return Err("native index window exceeds fixed independent phase ceilings".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Review,
    Status,
    Query,
    Start,
    Step,
    Advance,
    Publish,
    Retain,
}
impl Mode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Status => "status",
            Self::Query => "query",
            Self::Start => "start",
            Self::Step => "step",
            Self::Advance => "advance",
            Self::Publish => "publish",
            Self::Retain => "retain",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "review" => Ok(Self::Review),
            "status" => Ok(Self::Status),
            "query" => Ok(Self::Query),
            "start" => Ok(Self::Start),
            "step" => Ok(Self::Step),
            "advance" => Ok(Self::Advance),
            "publish" => Ok(Self::Publish),
            "retain" => Ok(Self::Retain),
            _ => Err("unknown native index mode".into()),
        }
    }
    pub(crate) fn mutates(self) -> bool {
        !matches!(self, Self::Review | Self::Status | Self::Query)
    }
}

impl Input {
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        identifier(&self.request_id)?;
        if self.schema_version != 1
            || self.login.is_empty()
            || self.login.len() > 32
            || !self.login.as_bytes()[0].is_ascii_lowercase()
            || !self
                .login
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err("native index requires an exact schema and human login".into());
        }
        match &self.operation {
            Operation::Status {} => (),
            Operation::Start {
                expected_owner_sha256,
                expected_selection_sha256,
                job_id,
                dimensions,
                limits,
            } => {
                hash(expected_owner_sha256)?;
                hash(expected_selection_sha256)?;
                identifier(job_id)?;
                limits.validate()?;
                if *dimensions == 0
                    || usize::from(*dimensions) > luma_content_store::corpus_index::MAX_DIMENSIONS
                    || limits.write_bytes == 0
                {
                    return Err(
                        "native index start requires a finite writable dimension profile".into(),
                    );
                }
            }
            Operation::Step {
                job_id,
                expected_job_sha256,
                window,
            } => {
                identifier(job_id)?;
                hash(expected_job_sha256)?;
                window.validate()?;
            }
            Operation::Advance {
                job_id,
                expected_job_sha256,
            }
            | Operation::Publish {
                job_id,
                expected_job_sha256,
            } => {
                identifier(job_id)?;
                hash(expected_job_sha256)?;
            }
            Operation::Query {
                generation_sha256,
                query,
                limit,
                limits,
                ..
            } => {
                hash(generation_sha256)?;
                limits.validate()?;
                let canonical =
                    luma_content_store::canonical_search_query(query, usize::from(*limit))?;
                if canonical != *query
                    || limits.write_bytes != 0
                    || limits.read_bytes > 128 * 1024 * 1024
                    || *limit == 0
                    || *limit > 64
                {
                    return Err(
                        "native index query requires exact canonical text and read-only resources"
                            .into(),
                    );
                }
            }
            Operation::Retain {
                job_id,
                expected_job_sha256,
                preparation_sha256,
                retained_inventory_sha256,
                review_sha256,
            } => {
                identifier(job_id)?;
                hash(expected_job_sha256)?;
                hash(preparation_sha256)?;
                hash(retained_inventory_sha256)?;
                hash(review_sha256)?;
            }
        }
        Ok(())
    }
    pub(crate) fn mode(&self) -> Mode {
        match self.operation {
            Operation::Status {} => Mode::Status,
            Operation::Start { .. } => Mode::Start,
            Operation::Step { .. } => Mode::Step,
            Operation::Advance { .. } => Mode::Advance,
            Operation::Publish { .. } => Mode::Publish,
            Operation::Query { .. } => Mode::Query,
            Operation::Retain { .. } => Mode::Retain,
        }
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_REQUEST {
            return Err("native index request exceeds64KiB".into());
        }
        Ok(bytes)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_REQUEST)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST {
            return Err("native index request exceeds64KiB".into());
        }
        let mut value: Self = serde_json::from_slice(bytes)?;
        // This is the pure human DATA canonicalizer only. Protected parse and
        // every effect/source check still require the resulting exact bytes.
        if let Operation::Query { query, limit, .. } = &mut value.operation {
            *query = luma_content_store::canonical_search_query(query, usize::from(*limit))?;
        }
        value.canonical_bytes()
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    pub(crate) fn profile(&self) -> Result<String> {
        let source = self.sha256()?;
        Ok(format!(
            "{PREFIX}{}-{}-{source}-{source}",
            if self.mode().mutates() {
                Mode::Review
            } else {
                self.mode()
            }
            .name(),
            self.binding.owner_generation,
        ))
    }
    /// A fresh finite effect ceremony binds both the immutable original input
    /// and the exact independently reviewed plan. It does not reuse Read as
    /// permission to write, or make a valid old review current.
    pub(crate) fn effect_profile(&self, review_sha256: &str) -> Result<String> {
        self.validate()?;
        hash(review_sha256)?;
        if !self.mode().mutates() {
            return Err("read-only index request has no effect scope".into());
        }
        Ok(format!(
            "{PREFIX}{}-{}-{}-{review_sha256}",
            self.mode().name(),
            self.binding.owner_generation,
            self.sha256()?
        ))
    }
}

pub(crate) struct Profile<'a> {
    pub(crate) mode: Mode,
    pub(crate) generation: u64,
    pub(crate) source: &'a str,
    pub(crate) review: &'a str,
}
pub(crate) fn parse_profile(value: &str) -> Result<Profile<'_>> {
    let remainder = value
        .strip_prefix(PREFIX)
        .ok_or("not a native index profile")?;
    let (mode, rest) = remainder
        .split_once('-')
        .ok_or("missing exact native index mode")?;
    let (generation, rest) = rest
        .split_once('-')
        .ok_or("missing exact native index digest")?;
    let number: u64 = generation.parse()?;
    if number == 0 || number.to_string() != generation {
        return Err("noncanonical native index owner generation".into());
    }
    let (digest, review) = rest
        .split_once('-')
        .ok_or("missing exact independently reviewed index plan")?;
    hash(digest)?;
    hash(review)?;
    let mode = Mode::parse(mode)?;
    if !mode.mutates() && digest != review {
        return Err("index readonly profile cannot borrow an effect review".into());
    }
    Ok(Profile {
        mode,
        generation: number,
        source: digest,
        review,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Input {
        Input {
            schema_version: 1,
            login: "admin".into(),
            binding: OwnerBinding {
                installation: "1".repeat(64),
                owner: "2".repeat(64),
                owner_generation: 1,
            },
            request_id: "a".repeat(32),
            operation: Operation::Status {},
        }
    }
    #[test]
    fn exact_closed_requests_and_profile_no_phase_or_authority() {
        let value = input();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(Input::parse(&bytes).unwrap(), value);
        let profile = value.profile().unwrap();
        let parsed = parse_profile(&profile).unwrap();
        assert_eq!(parsed.mode, Mode::Status);
        assert_eq!(parsed.source, value.sha256().unwrap());
        assert_eq!(parsed.generation, value.binding.owner_generation);
        for field in ["phase", "cursor", "grant", "saved", "builder"] {
            let mut changed = serde_json::to_value(&value).unwrap();
            changed
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!(true));
            assert!(Input::canonicalize(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let duplicated = String::from_utf8(bytes).unwrap().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert!(Input::canonicalize(duplicated.as_bytes()).is_err());
        assert!(parse_profile(&(profile + "-status")).is_err());
    }
    #[test]
    fn status_operation_direct_serde_and_canonical_input_refuse_unknown_fields() {
        let value = input();
        let mut changed = serde_json::to_value(&value).unwrap();
        changed["operation"]["grant"] = true.into();
        assert!(serde_json::from_value::<Input>(changed.clone()).is_err());
        assert!(Input::canonicalize(&serde_json::to_vec(&changed).unwrap()).is_err());
        assert!(serde_json::from_slice::<Operation>(
            br#"{"kind":"status","cursor":"caller-selected"}"#
        )
        .is_err());
    }
    #[test]
    fn query_is_exact_canonical_read_only_and_bounded() {
        let mut value = input();
        let limits = CorpusIndexLimits {
            read_bytes: 1024 * 1024,
            write_bytes: 0,
            source_bytes: 0,
            postings: 0,
            floating_operations: 1_000_000,
        };
        value.operation = Operation::Query {
            generation_sha256: "b".repeat(64),
            query_kind: QueryKind::LexicalAnd,
            query: "alpha beta".into(),
            limit: 64,
            limits,
        };
        value.validate().unwrap();
        if let Operation::Query { query, .. } = &mut value.operation {
            *query = "Alpha  beta".into();
        }
        assert!(value.validate().is_err());
        if let Operation::Query { query, .. } = &mut value.operation {
            *query = "  BETA alpha ALPHA\t".into();
        }
        let canonical = Input::canonicalize(&serde_json::to_vec(&value).unwrap()).unwrap();
        let normalized = Input::parse(&canonical).unwrap();
        assert!(
            matches!(&normalized.operation, Operation::Query { query, .. } if query == "alpha beta")
        );
        if let Operation::Query { query, limits, .. } = &mut value.operation {
            *query = "alpha".into();
            limits.write_bytes = 1;
        }
        assert!(value.validate().is_err());
    }
    #[test]
    fn review_and_fresh_effect_scopes_bind_both_input_and_exact_plan() {
        let mut value = input();
        value.operation = Operation::Advance {
            job_id: "b".repeat(32),
            expected_job_sha256: "c".repeat(64),
        };
        let read = value.profile().unwrap();
        let reviewed = parse_profile(&read).unwrap();
        assert_eq!(reviewed.mode, Mode::Review);
        assert_eq!(reviewed.source, reviewed.review);
        let effect = value.effect_profile(&"d".repeat(64)).unwrap();
        let selected = parse_profile(&effect).unwrap();
        assert_eq!(selected.mode, Mode::Advance);
        assert_eq!(selected.source, value.sha256().unwrap());
        assert_eq!(selected.review, "d".repeat(64));
        assert_ne!(effect, read);
        let mut copied = read.clone();
        copied.pop();
        copied.push(if read.ends_with('a') { 'b' } else { 'a' });
        assert!(parse_profile(&copied).is_err());
        let mut status = input();
        assert!(status.effect_profile(&"d".repeat(64)).is_err());
        status.login = "other".into();
        assert_ne!(status.profile().unwrap(), input().profile().unwrap());
    }
}
