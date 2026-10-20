//! Canonical C-continuation DATA and immutable archive integrity.
//!
//! Successful validation is not NV selection, event-semantic replay, owner
//! authorization, physical preallocation, or permission to publish. An adapter
//! must independently join all of those to the existing provisioned C authority.
//! This module never opens a file/device, allocates an NV index, or selects a head.
use crate::Result;
use luma_content::sha256;
use serde::{Deserialize, Serialize};

pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;
pub const MAX_SEGMENT_BYTES: usize = 4 * 1024 * 1024;
// Existing v1 held publication includes up to 32KiB commitment + 8KiB record,
// recipient requests permit 49,152B, and restore-start nests a 96KiB request
// and a <=64KiB signed-receipt message. Preserve those exact typed bytes with
// finite headroom for JSON escaping/metadata. Aggregate segment bound is still
// 4MiB: 256 is a record-count ceiling, not a promise 256 maximum events fit.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_SEGMENT_EVENTS: usize = 256;
pub const MAX_ARCHIVED_SEGMENTS: u64 = 1_048_576;
const DESCRIPTOR: &str = "luma-content-custody-continuation-v2";
const SEGMENT: &str = "luma-content-custody-event-segment-v2";

fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value.bytes().all(|b| b == b'0')
    {
        return Err("C data requires a canonical nonzero SHA256".into());
    }
    Ok(())
}
fn canonical<T: Serialize + for<'a> Deserialize<'a>>(bytes: &[u8], bound: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err("C data exceeds its exact byte bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("C data is not exact canonical closed JSON".into());
    }
    Ok(value)
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(value)?))
}
fn decode(value: &str) -> Result<[u8; 32]> {
    hash(value)?;
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(result)
}
/// Existing SHA256 NV-extend commitment, not an actual TPM operation.
pub fn extend_head(previous: &str, event: &str) -> Result<String> {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&decode(previous)?);
    bytes[32..].copy_from_slice(&decode(event)?);
    Ok(sha256(&bytes))
}

/// Hash of the entire separately validated map descriptor, never a page hash.
/// Empty maps still have an exact nonzero descriptor commitment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootCommitment {
    pub sha256: String,
    pub entries: u64,
}
impl RootCommitment {
    pub fn validate(&self) -> Result<()> {
        hash(&self.sha256)
    }
    /// Commit an actual validated owner-map descriptor, including its binding,
    /// kind, count and page reference. This does not verify the map's pages.
    pub fn from_owner_map(root: &super::MapRoot) -> Result<Self> {
        root.validate()?;
        Ok(Self {
            sha256: root.sha256()?,
            entries: root.entry_count,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreReservations {
    pub map: RootCommitment,
    pub publication_count: u64,
    pub terminal_count: u64,
    pub allocated_bytes: u64,
    pub allocated_inodes: u64,
}
impl RestoreReservations {
    pub fn validate(&self) -> Result<()> {
        self.map.validate()?;
        let count = self
            .publication_count
            .checked_add(self.terminal_count)
            .ok_or("restore reservation count overflow")?;
        if count != self.map.entries
            || (count == 0 && (self.allocated_bytes != 0 || self.allocated_inodes != 0))
            || (count != 0 && (self.allocated_bytes == 0 || self.allocated_inodes < count))
        {
            return Err(
                "restore publication/terminal reservations are incomplete or inconsistent".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateRoots {
    pub owner_states: RootCommitment,
    pub recipient_generations: RootCommitment,
    pub signer_generations: RootCommitment,
    pub unavailable_owners: RootCommitment,
    pub restores: RestoreReservations,
}
impl StateRoots {
    pub fn validate(&self) -> Result<()> {
        for root in [
            &self.owner_states,
            &self.recipient_generations,
            &self.signer_generations,
            &self.unavailable_owners,
        ] {
            root.validate()?;
        }
        // A fresh restore target can be unavailable before its first published
        // owner state. Cardinalities alone cannot prove a subset relation.
        self.restores.validate()
    }
}

/// Exact original typed event JSON, retained without sorting its entry fields.
/// The entry's real semantic validation and original authority MUST still be
/// replayed by the existing C adapter. Generic JSON shape is not that replay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventData {
    pub canonical_event: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    RestoreRetired,
    RestoreStart,
    RestorePublication,
    Backup,
    Publication,
    ReceiptSigner,
    Quarantine,
    Recipients,
}
impl EventData {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = Self {
            canonical_event: std::str::from_utf8(bytes)?.into(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        let bytes = self.canonical_event.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
            return Err("C archive event exceeds its byte bound".into());
        }
        canonical_tokens(bytes)?;
        let mut parser = serde_json::Deserializer::from_slice(bytes);
        let value = StrictValue::deserialize(&mut parser)?.0;
        parser.end()?;
        let object = value.as_object().ok_or("C event must be an object")?;
        if object.len() != 2
            || !object
                .get("entry")
                .is_some_and(|entry| entry.as_object().is_some_and(|o| !o.is_empty()))
        {
            return Err("C event requires exact kind and nonempty entry object".into());
        }
        let kind: EventKind =
            serde_json::from_value(object.get("kind").ok_or("C event kind missing")?.clone())?;
        let prefix = format!("{{\"kind\":{},\"entry\":", serde_json::to_string(&kind)?);
        if !self.canonical_event.starts_with(&prefix) {
            return Err("C event fields are not in original typed kind/entry order".into());
        }
        Ok(())
    }
    pub fn event_sha256(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = b"[\"luma-content-custody-event-v1\",".to_vec();
        bytes.extend_from_slice(self.canonical_event.as_bytes());
        bytes.push(b']');
        Ok(sha256(&bytes))
    }
}

// Validate minimal serde JSON token spellings while preserving the ORIGINAL
// typed field order, which is part of the existing C event commitment.
fn canonical_tokens(bytes: &[u8]) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                let start = at;
                at += 1;
                let mut escaped = false;
                let mut ended = false;
                while at < bytes.len() {
                    let byte = bytes[at];
                    at += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        ended = true;
                        break;
                    }
                }
                if !ended {
                    return Err("unterminated C event string".into());
                }
                let value: String = serde_json::from_slice(&bytes[start..at])?;
                if serde_json::to_vec(&value)? != bytes[start..at] {
                    return Err("noncanonical C event string token".into());
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = at;
                at += 1;
                while at < bytes.len() && !matches!(bytes[at], b',' | b']' | b'}' | b':') {
                    at += 1;
                }
                let number: serde_json::Number = serde_json::from_slice(&bytes[start..at])?;
                if number.to_string().as_bytes() != &bytes[start..at] {
                    return Err("noncanonical C event number token".into());
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                return Err("C event contains whitespace outside strings".into())
            }
            _ => at += 1,
        }
    }
    Ok(())
}
struct StrictValue(serde_json::Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictValue(n.into()))
                    .ok_or_else(|| E::custom("nonfinite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                self.visit_none()
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate C event JSON key"));
                    }
                    values.insert(key, access.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEvent {
    pub ordinal: u64,
    pub event: EventData,
    pub event_sha256: String,
    pub previous_nv_head: String,
    pub resulting_nv_head: String,
}
impl ArchivedEvent {
    pub fn from_data(ordinal: u64, previous: &str, event: EventData) -> Result<Self> {
        let event_sha256 = event.event_sha256()?;
        let value = Self {
            ordinal,
            event,
            resulting_nv_head: extend_head(previous, &event_sha256)?,
            event_sha256,
            previous_nv_head: previous.into(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.ordinal == 0
            || self.event_sha256 != self.event.event_sha256()?
            || self.resulting_nv_head != extend_head(&self.previous_nv_head, &self.event_sha256)?
        {
            return Err("archived C event ordinal, exact bytes or NV extension differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventSegment {
    pub schema_version: u32,
    pub purpose: String,
    pub installation: String,
    pub genesis_event: String,
    pub segment_number: u64,
    pub previous_segment_sha256: Option<String>,
    pub first_ordinal: u64,
    pub last_ordinal: u64,
    pub previous_nv_head: String,
    pub final_nv_head: String,
    pub events: Vec<ArchivedEvent>,
}
impl EventSegment {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_SEGMENT_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.installation,
            &self.genesis_event,
            &self.previous_nv_head,
            &self.final_nv_head,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.previous_segment_sha256 {
            hash(value)?;
        }
        if self.schema_version != 2
            || self.purpose != SEGMENT
            || self.segment_number == 0
            || self.segment_number > MAX_ARCHIVED_SEGMENTS
            || (self.segment_number == 1) != self.previous_segment_sha256.is_none()
            || self.events.is_empty()
            || self.events.len() > MAX_SEGMENT_EVENTS
            || self.first_ordinal == 0
            || self.first_ordinal.checked_add(self.events.len() as u64 - 1)
                != Some(self.last_ordinal)
            || serde_json::to_vec(self)?.len() > MAX_SEGMENT_BYTES
        {
            return Err("invalid bounded immutable C event segment".into());
        }
        let mut head = self.previous_nv_head.clone();
        for (index, event) in self.events.iter().enumerate() {
            event.validate()?;
            if event.ordinal != self.first_ordinal + index as u64 || event.previous_nv_head != head
            {
                return Err("C segment event ordering/NV chain is discontinuous".into());
            }
            head.clone_from(&event.resulting_nv_head);
        }
        if head != self.final_nv_head {
            return Err("C segment terminal NV commitment differs".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(sha256(&self.canonical_bytes()?))
    }
}

/// Append-only archive commitment; descriptors and every immutable preceding
/// segment remain required retained evidence. This is not a Merkle map page.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRoot {
    pub segments: u64,
    pub event_count: u64,
    pub last_segment_sha256: Option<String>,
    pub root_sha256: String,
}
impl ArchiveRoot {
    fn validate(&self) -> Result<()> {
        hash(&self.root_sha256)?;
        if self.segments == 0 {
            if self.event_count != 0 || self.last_segment_sha256.is_some() {
                return Err("empty C archive cannot invent an event or segment".into());
            }
            return Ok(());
        }
        hash(
            self.last_segment_sha256
                .as_deref()
                .ok_or("C archive last segment missing")?,
        )?;
        if self.segments > MAX_ARCHIVED_SEGMENTS
            || self.event_count < self.segments
            || self.event_count
                > self
                    .segments
                    .checked_mul(MAX_SEGMENT_EVENTS as u64)
                    .ok_or("archive count overflow")?
        {
            return Err("C archive count is outside its finite format bound".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyCutData {
    pub installation: String,
    pub genesis_event: String,
    pub journal_sha256: String,
    pub selected_nv_head: String,
    pub global_ordinal: u64,
}
impl LegacyCutData {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.installation,
            &self.genesis_event,
            &self.journal_sha256,
            &self.selected_nv_head,
        ] {
            hash(value)?;
        }
        Ok(())
    }
}
fn archive_genesis(base: &LegacyCutData) -> Result<String> {
    base.validate()?;
    digest(&(
        "luma-content-custody-archive-genesis-v2",
        &base.installation,
        &base.genesis_event,
        &base.journal_sha256,
        &base.selected_nv_head,
        base.global_ordinal,
    ))
}
/// A caller's claimed predecessor DATA, not an observed/provisioned C token.
pub enum BaseCutData<'a> {
    Legacy(&'a LegacyCutData),
    Continuation(&'a Descriptor),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub schema_version: u32,
    pub purpose: String,
    pub installation: String,
    pub genesis_event: String,
    pub sequence: u64,
    pub legacy_journal_sha256: String,
    pub previous_descriptor_sha256: Option<String>,
    pub previous_selected_nv_head: String,
    pub extension_event_sha256: String,
    pub selected_nv_head: String,
    pub global_ordinal: u64,
    pub archive: ArchiveRoot,
    pub state: StateRoots,
}
impl Descriptor {
    fn extension(&self) -> Result<String> {
        digest(&(
            DESCRIPTOR,
            self.schema_version,
            &self.installation,
            &self.genesis_event,
            self.sequence,
            &self.legacy_journal_sha256,
            &self.previous_descriptor_sha256,
            &self.previous_selected_nv_head,
            self.global_ordinal,
            &self.archive,
            &self.state,
        ))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_DESCRIPTOR_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.installation,
            &self.genesis_event,
            &self.legacy_journal_sha256,
            &self.previous_selected_nv_head,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.previous_descriptor_sha256 {
            hash(value)?;
        }
        self.archive.validate()?;
        self.state.validate()?;
        if self.schema_version != 2
            || self.purpose != DESCRIPTOR
            || self.sequence == 0
            || !(self.sequence == self.archive.segments
                || self.archive.segments.checked_add(1) == Some(self.sequence))
            || (self.sequence == 1) != self.previous_descriptor_sha256.is_none()
            || self.global_ordinal <= self.archive.event_count
            || self.extension_event_sha256 != self.extension()?
            || self.selected_nv_head
                != extend_head(
                    &self.previous_selected_nv_head,
                    &self.extension_event_sha256,
                )?
            || serde_json::to_vec(self)?.len() > MAX_DESCRIPTOR_BYTES
        {
            return Err("invalid versioned C continuation descriptor commitment".into());
        }
        if self.archive.segments == 0 {
            let base = LegacyCutData {
                installation: self.installation.clone(),
                genesis_event: self.genesis_event.clone(),
                journal_sha256: self.legacy_journal_sha256.clone(),
                selected_nv_head: self.previous_selected_nv_head.clone(),
                global_ordinal: self
                    .global_ordinal
                    .checked_sub(1)
                    .ok_or("C bootstrap ordinal underflow")?,
            };
            if self.sequence != 1 || self.archive.root_sha256 != archive_genesis(&base)? {
                return Err("C empty archive differs from exact retained legacy cut".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(sha256(&self.canonical_bytes()?))
    }
}

/// Bootstrap continuation DATA from the already selected full v1 cut. No new
/// ordinary event is required or replayed: the sole candidate extension is the
/// descriptor itself. The complete original journal remains retained by hash.
pub fn legacy_descriptor_data(base: &LegacyCutData, state: StateRoots) -> Result<Descriptor> {
    base.validate()?;
    state.validate()?;
    let mut value = Descriptor {
        schema_version: 2,
        purpose: DESCRIPTOR.into(),
        installation: base.installation.clone(),
        genesis_event: base.genesis_event.clone(),
        sequence: 1,
        legacy_journal_sha256: base.journal_sha256.clone(),
        previous_descriptor_sha256: None,
        previous_selected_nv_head: base.selected_nv_head.clone(),
        extension_event_sha256: String::new(),
        selected_nv_head: String::new(),
        global_ordinal: base
            .global_ordinal
            .checked_add(1)
            .ok_or("C bootstrap ordinal overflow")?,
        archive: ArchiveRoot {
            segments: 0,
            event_count: 0,
            last_segment_sha256: None,
            root_sha256: archive_genesis(base)?,
        },
        state,
    };
    value.extension_event_sha256 = value.extension()?;
    value.selected_nv_head = extend_head(
        &value.previous_selected_nv_head,
        &value.extension_event_sha256,
    )?;
    value.validate()?;
    Ok(value)
}
/// Pure integrity comparison only; the supplied legacy cut is still DATA and
/// must independently match original retained bytes and actual current NV.
pub fn verify_legacy_descriptor_data(base: &LegacyCutData, bytes: &[u8]) -> Result<Descriptor> {
    let actual = Descriptor::parse(bytes)?;
    if actual != legacy_descriptor_data(base, actual.state.clone())? {
        return Err("C bootstrap descriptor does not preserve exact legacy data cut".into());
    }
    Ok(actual)
}

/// Construct internally consistent candidate bytes only. This does not replay
/// event semantics, infer map deltas, authenticate a legacy cut or advance NV.
pub fn candidate_data(
    base: BaseCutData<'_>,
    segment: &EventSegment,
    state: StateRoots,
) -> Result<Descriptor> {
    segment.validate()?;
    state.validate()?;
    let (installation, genesis, legacy, sequence, previous, head, ordinal, archive) = match base {
        BaseCutData::Legacy(value) => {
            value.validate()?;
            (
                &value.installation,
                &value.genesis_event,
                &value.journal_sha256,
                1,
                None,
                &value.selected_nv_head,
                value.global_ordinal,
                None,
            )
        }
        BaseCutData::Continuation(value) => {
            value.validate()?;
            (
                &value.installation,
                &value.genesis_event,
                &value.legacy_journal_sha256,
                value
                    .sequence
                    .checked_add(1)
                    .ok_or("C descriptor sequence overflow")?,
                Some(value.sha256()?),
                &value.selected_nv_head,
                value.global_ordinal,
                Some(&value.archive),
            )
        }
    };
    let next_segment = archive
        .map_or(0, |a| a.segments)
        .checked_add(1)
        .ok_or("C archive segment number overflow")?;
    if &segment.installation != installation
        || &segment.genesis_event != genesis
        || segment.segment_number != next_segment
        || &segment.previous_nv_head != head
        || ordinal.checked_add(1) != Some(segment.first_ordinal)
        || segment.previous_segment_sha256.as_ref()
            != archive.and_then(|a| a.last_segment_sha256.as_ref())
    {
        return Err("C archive does not extend the exact preceding data cut".into());
    }
    let segment_sha = segment.sha256()?;
    let preceding_archive = match archive {
        Some(value) => value.root_sha256.clone(),
        None => digest(&(
            "luma-content-custody-archive-genesis-v2",
            installation,
            genesis,
            legacy,
            head,
            ordinal,
        ))?,
    };
    let archive = ArchiveRoot {
        segments: next_segment,
        event_count: archive
            .map_or(0, |a| a.event_count)
            .checked_add(segment.events.len() as u64)
            .ok_or("C archive event count overflow")?,
        root_sha256: digest(&(
            "luma-content-custody-archive-append-v2",
            &preceding_archive,
            next_segment,
            &segment_sha,
            segment.first_ordinal,
            segment.last_ordinal,
        ))?,
        last_segment_sha256: Some(segment_sha),
    };
    let mut value = Descriptor {
        schema_version: 2,
        purpose: DESCRIPTOR.into(),
        installation: installation.clone(),
        genesis_event: genesis.clone(),
        sequence,
        legacy_journal_sha256: legacy.clone(),
        previous_descriptor_sha256: previous,
        previous_selected_nv_head: segment.final_nv_head.clone(),
        extension_event_sha256: String::new(),
        selected_nv_head: String::new(),
        global_ordinal: segment
            .last_ordinal
            .checked_add(1)
            .ok_or("C continuation ordinal overflow")?,
        archive,
        state,
    };
    value.extension_event_sha256 = value.extension()?;
    value.selected_nv_head = extend_head(
        &value.previous_selected_nv_head,
        &value.extension_event_sha256,
    )?;
    value.validate()?;
    Ok(value)
}
/// Verify complete candidate/segment bytes against exact supplied predecessor
/// DATA. A successful return is deliberately still named DATA, not Selected.
pub fn verify_transition_data(
    base: BaseCutData<'_>,
    descriptor: &[u8],
    segment: &[u8],
) -> Result<Descriptor> {
    let actual = Descriptor::parse(descriptor)?;
    let segment = EventSegment::parse(segment)?;
    let expected = candidate_data(base, &segment, actual.state.clone())?;
    if actual != expected {
        return Err(
            "C continuation differs from the exact immutable segment/predecessor proof".into(),
        );
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }
    fn legacy() -> LegacyCutData {
        LegacyCutData {
            installation: h(1),
            genesis_event: h(2),
            journal_sha256: h(3),
            selected_nv_head: h(4),
            global_ordinal: 7,
        }
    }
    fn roots() -> StateRoots {
        let empty = RootCommitment {
            sha256: h(5),
            entries: 0,
        };
        StateRoots {
            owner_states: RootCommitment {
                sha256: h(6),
                entries: 1,
            },
            recipient_generations: empty.clone(),
            signer_generations: empty.clone(),
            unavailable_owners: empty.clone(),
            restores: RestoreReservations {
                map: empty,
                publication_count: 0,
                terminal_count: 0,
                allocated_bytes: 0,
                allocated_inodes: 0,
            },
        }
    }
    fn segment(head: &str, ordinal: u64, number: u64, previous: Option<String>) -> EventSegment {
        let event=EventData::parse(br#"{"kind":"publication","entry":{"fixture_data":"not an original grant or semantically validated C publication"}}"#).unwrap();
        let first = ArchivedEvent::from_data(ordinal, head, event).unwrap();
        EventSegment {
            schema_version: 2,
            purpose: SEGMENT.into(),
            installation: h(1),
            genesis_event: h(2),
            segment_number: number,
            previous_segment_sha256: previous,
            first_ordinal: ordinal,
            last_ordinal: ordinal,
            previous_nv_head: head.into(),
            final_nv_head: first.resulting_nv_head.clone(),
            events: vec![first],
        }
    }
    #[test]
    fn canonical_legacy_then_second_segment_preserve_full_predecessor_and_global_ordinals() {
        let base = legacy();
        let first = segment(&base.selected_nv_head, 8, 1, None);
        let one = candidate_data(BaseCutData::Legacy(&base), &first, roots()).unwrap();
        assert_eq!(one.global_ordinal, 9);
        assert_eq!(
            verify_transition_data(
                BaseCutData::Legacy(&base),
                &one.canonical_bytes().unwrap(),
                &first.canonical_bytes().unwrap()
            )
            .unwrap(),
            one
        );
        let second = segment(&one.selected_nv_head, 10, 2, Some(first.sha256().unwrap()));
        let two = candidate_data(BaseCutData::Continuation(&one), &second, roots()).unwrap();
        assert_eq!(two.global_ordinal, 11);
        assert_eq!(two.archive.event_count, 2);
        assert_eq!(two.previous_descriptor_sha256, Some(one.sha256().unwrap()));
        verify_transition_data(
            BaseCutData::Continuation(&one),
            &two.canonical_bytes().unwrap(),
            &second.canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(candidate_data(BaseCutData::Legacy(&base), &second, roots()).is_err());
    }
    #[test]
    fn closed_canonical_descriptor_rejects_whitespace_duplicate_unknown_and_alternate_spellings() {
        let base = legacy();
        let s = segment(&base.selected_nv_head, 8, 1, None);
        let d = candidate_data(BaseCutData::Legacy(&base), &s, roots()).unwrap();
        let text = String::from_utf8(d.canonical_bytes().unwrap()).unwrap();
        for bad in [
            format!(" {text}"),
            format!("{text}\n"),
            text.replacen(
                "\"schema_version\":2",
                "\"schema_version\":2,\"schema_version\":2",
                1,
            ),
            text.replacen(
                "\"schema_version\":2",
                "\"schema_version\":2,\"authority_returned\":true",
                1,
            ),
            text.replacen("\"sequence\":1", "\"sequence\":1.0", 1),
        ] {
            assert!(Descriptor::parse(bad.as_bytes()).is_err());
        }
        assert!(Descriptor::parse(&vec![b'x'; MAX_DESCRIPTOR_BYTES + 1]).is_err());
    }
    #[test]
    fn each_descriptor_commitment_and_reservation_tamper_refuses() {
        let b = legacy();
        let s = segment(&b.selected_nv_head, 8, 1, None);
        let d = candidate_data(BaseCutData::Legacy(&b), &s, roots()).unwrap();
        for case in 0..15 {
            let mut v = d.clone();
            match case {
                0 => v.schema_version = 1,
                1 => v.purpose = "local-tpm2".into(),
                2 => v.sequence = 0,
                3 => v.installation = h(9),
                4 => v.genesis_event = h(9),
                5 => v.legacy_journal_sha256 = h(9),
                6 => v.previous_descriptor_sha256 = Some(h(9)),
                7 => v.previous_selected_nv_head = h(9),
                8 => v.selected_nv_head = h(9),
                9 => v.global_ordinal = 8,
                10 => v.archive.root_sha256 = h(9),
                11 => v.state.owner_states.sha256 = h(9),
                12 => v.state.restores.allocated_bytes = 1,
                13 => v.archive.event_count = 0,
                _ => v.extension_event_sha256 = h(9),
            };
            assert!(v.validate().is_err(), "mutation {case}");
        }
    }
    #[test]
    fn internally_rehashed_wrong_base_or_archive_is_not_a_transition_proof() {
        let b = legacy();
        let s = segment(&b.selected_nv_head, 8, 1, None);
        let d = candidate_data(BaseCutData::Legacy(&b), &s, roots()).unwrap();
        let mut wrong = b.clone();
        wrong.journal_sha256 = h(10);
        assert!(verify_transition_data(
            BaseCutData::Legacy(&wrong),
            &d.canonical_bytes().unwrap(),
            &s.canonical_bytes().unwrap()
        )
        .is_err());
        let mut changed = d.clone();
        changed.archive.root_sha256 = h(11);
        changed.extension_event_sha256 = changed.extension().unwrap();
        changed.selected_nv_head = extend_head(
            &changed.previous_selected_nv_head,
            &changed.extension_event_sha256,
        )
        .unwrap();
        changed.validate().unwrap();
        assert!(verify_transition_data(
            BaseCutData::Legacy(&b),
            &changed.canonical_bytes().unwrap(),
            &s.canonical_bytes().unwrap()
        )
        .is_err());
    }
    #[test]
    fn immutable_segment_refuses_reorder_duplicate_truncation_bounds_and_nv_substitution() {
        let b = legacy();
        let s = segment(&b.selected_nv_head, 8, 1, None);
        for case in 0..10 {
            let mut v = s.clone();
            match case {
                0 => v.events.clear(),
                1 => v.events.push(v.events[0].clone()),
                2 => v.first_ordinal = 0,
                3 => v.last_ordinal = 9,
                4 => v.previous_segment_sha256 = Some(h(8)),
                5 => v.events[0].previous_nv_head = h(8),
                6 => v.events[0].event_sha256 = h(8),
                7 => v.final_nv_head = h(8),
                8 => {
                    v.events[0].event.canonical_event =
                        r#"{"kind":"publication","entry":[]}"#.into()
                }
                _ => v.events[0].event.canonical_event = "x".repeat(MAX_EVENT_BYTES + 1),
            };
            assert!(v.validate().is_err(), "mutation {case}");
        }
        let mut bytes = s.canonical_bytes().unwrap();
        bytes.pop();
        assert!(EventSegment::parse(&bytes).is_err());
        assert!(EventSegment::parse(&vec![b'x'; MAX_SEGMENT_BYTES + 1]).is_err());
    }
    #[test]
    fn canonical_event_uses_exact_existing_c_digest_not_raw_payload_or_new_nv_domain() {
        let event = EventData::parse(br#"{"kind":"backup","entry":{"a":1}}"#).unwrap();
        assert_eq!(
            event.event_sha256().unwrap(),
            sha256(br#"["luma-content-custody-event-v1",{"kind":"backup","entry":{"a":1}}]"#)
        );
        for bad in [
            br#"{"kind":"backup","entry":{"a":1,"a":1}}"#.as_slice(),
            br#"{"kind":"invented","entry":{"a":1}}"#,
            br#"{"kind":"backup","entry":{}}"#,
        ] {
            assert!(EventData::parse(bad).is_err());
        }
        assert!(extend_head(&"A".repeat(64), &h(2)).is_err());
        assert!(extend_head(&h(1), &"0".repeat(64)).is_err());
    }
    #[test]
    fn overflow_and_unrepresented_restore_capacity_refuse_without_lifting_v1_limits() {
        let mut b = legacy();
        b.global_ordinal = u64::MAX;
        let s = segment(&b.selected_nv_head, 8, 1, None);
        assert!(candidate_data(BaseCutData::Legacy(&b), &s, roots()).is_err());
        for case in 0..5 {
            let mut r = roots().restores;
            match case {
                0 => r.publication_count = u64::MAX,
                1 => {
                    r.publication_count = u64::MAX;
                    r.terminal_count = 1
                }
                2 => r.allocated_inodes = 1,
                3 => {
                    r.map.entries = 1;
                    r.publication_count = 1;
                    r.allocated_bytes = 4096
                }
                _ => {
                    r.map.entries = 1;
                    r.publication_count = 1;
                    r.allocated_inodes = 1
                }
            };
            assert!(r.validate().is_err());
        }
        let r = RestoreReservations {
            map: RootCommitment {
                sha256: h(1),
                entries: 2,
            },
            publication_count: 1,
            terminal_count: 1,
            allocated_bytes: 8192,
            allocated_inodes: 2,
        };
        r.validate().unwrap();
        assert_eq!(crate::MAX_OUTCOMES, 256);
        assert_eq!(crate::MAX_REPOSITORY_BYTES, 64 * 1024 * 1024);
    }
    #[test]
    fn exact_typed_entry_order_survives_archive_without_changing_existing_nv_event() {
        let raw =
            r#"{"kind":"publication","entry":{"z":7,"a":{"second":2,"first":1},"literal":"é"}}"#
                .as_bytes();
        let event = EventData::parse(raw).unwrap();
        assert_eq!(event.canonical_event.as_bytes(), raw);
        let mut preimage = b"[\"luma-content-custody-event-v1\",".to_vec();
        preimage.extend_from_slice(raw);
        preimage.push(b']');
        assert_eq!(event.event_sha256().unwrap(), sha256(&preimage));
        let reordered = EventData::parse(
            r#"{"kind":"publication","entry":{"a":{"first":1,"second":2},"literal":"é","z":7}}"#
                .as_bytes(),
        )
        .unwrap();
        assert_ne!(
            event.event_sha256().unwrap(),
            reordered.event_sha256().unwrap()
        );
        for bad in [
            br#"{"kind":"publication","entry":{"z":1,"nested":{"x":1,"x":2}}}"#.as_slice(),
            br#"{"kind":"publication","entry":{"x":"\u0061"}}"#,
            br#"{"kind":"publication", "entry":{"x":1}}"#,
            br#"{"entry":{"x":1},"kind":"publication"}"#,
            br#"{"kind":"publication","entry":{"x":1},"verified":true}"#,
        ] {
            assert!(EventData::parse(bad).is_err());
        }
    }
    #[test]
    fn full_finite_event_boundary_is_verified_and_a_257th_event_is_not_admitted() {
        let b = legacy();
        let mut s = segment(&b.selected_nv_head, 8, 1, None);
        for ordinal in 9..=263 {
            let event = s.events[0].event.clone();
            let previous = s.events.last().unwrap().resulting_nv_head.clone();
            s.events
                .push(ArchivedEvent::from_data(ordinal, &previous, event).unwrap());
        }
        s.last_ordinal = 263;
        s.final_nv_head = s.events.last().unwrap().resulting_nv_head.clone();
        assert_eq!(s.events.len(), MAX_SEGMENT_EVENTS);
        s.validate().unwrap();
        let d = candidate_data(BaseCutData::Legacy(&b), &s, roots()).unwrap();
        assert_eq!(d.archive.event_count, 256);
        verify_transition_data(
            BaseCutData::Legacy(&b),
            &d.canonical_bytes().unwrap(),
            &s.canonical_bytes().unwrap(),
        )
        .unwrap();
        let event = s.events[0].event.clone();
        s.events
            .push(ArchivedEvent::from_data(264, &s.final_nv_head, event).unwrap());
        s.last_ordinal = 264;
        s.final_nv_head = s.events.last().unwrap().resulting_nv_head.clone();
        assert!(s.validate().is_err());
    }
    #[test]
    fn map_commitment_joins_the_whole_owner_kind_bound_descriptor_not_just_its_page() {
        let owner = luma_content::OwnerBinding {
            installation: h(1),
            owner: h(2),
            owner_generation: 1,
        };
        let one = super::super::MapRoot::empty(&owner, super::super::MapKind::Artifacts).unwrap();
        let two = super::super::MapRoot::empty(&owner, super::super::MapKind::History).unwrap();
        let a = RootCommitment::from_owner_map(&one).unwrap();
        let b = RootCommitment::from_owner_map(&two).unwrap();
        assert_eq!(a.entries, 0);
        assert_ne!(a.sha256, b.sha256);
        assert_eq!(a.sha256, one.sha256().unwrap());
        let mut wrong = one;
        wrong.binding.owner_generation = 0;
        assert!(RootCommitment::from_owner_map(&wrong).is_err());
    }
    #[test]
    fn large_existing_recipient_envelope_shape_is_preserved_not_silently_truncated() {
        // DATA-shape regression, deliberately not certificate or Admin proof.
        // Actual recipient validation remains exclusively the original adapter.
        #[derive(Serialize)]
        struct Entry<'a> {
            schema_version: u32,
            purpose: &'a str,
            generation: u64,
            request: Request<'a>,
            original_authority: &'a str,
        }
        #[derive(Serialize)]
        struct Request<'a> {
            schema_version: u32,
            purpose: &'a str,
            owner_certificate_der_hex: &'a str,
            offline_admin_certificate_der_hex: &'a str,
        }
        #[derive(Serialize)]
        struct Envelope<'a> {
            kind: EventKind,
            entry: Entry<'a>,
        }
        let certificate = "ab".repeat(8192);
        let raw = serde_json::to_vec(&Envelope {
            kind: EventKind::Recipients,
            entry: Entry {
                schema_version: 1,
                purpose: "luma-content-recipient-custody-enrollment-v1",
                generation: 1,
                original_authority: "inert shape fixture, not a grant",
                request: Request {
                    schema_version: 1,
                    purpose: "luma-content-encryption-recipients-v1",
                    owner_certificate_der_hex: &certificate,
                    offline_admin_certificate_der_hex: &certificate,
                },
            },
        })
        .unwrap();
        assert!(raw.len() > 32 * 1024);
        assert!(raw.len() < MAX_EVENT_BYTES);
        let data = EventData::parse(&raw).unwrap();
        assert_eq!(data.canonical_event.as_bytes(), raw);
        let b = legacy();
        let mut s = segment(&b.selected_nv_head, 8, 1, None);
        s.events = vec![ArchivedEvent::from_data(8, &b.selected_nv_head, data).unwrap()];
        s.final_nv_head = s.events[0].resulting_nv_head.clone();
        s.validate().unwrap();
        let candidate = candidate_data(BaseCutData::Legacy(&b), &s, roots()).unwrap();
        verify_transition_data(
            BaseCutData::Legacy(&b),
            &candidate.canonical_bytes().unwrap(),
            &s.canonical_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(crate::MAX_OUTCOMES, 256);
    }
    #[test]
    fn full_legacy_cut_bootstraps_without_an_ordinary_event_or_replayed_nv_extension() {
        let mut b = legacy();
        b.global_ordinal = 1024;
        // Bounded retained-byte commitment fixture, not a semantically replayed
        // legacy Journal or an actual observation of enrolled C/NV authority.
        let retained = vec![b'x'; 4 * 1024 * 1024];
        b.journal_sha256 = sha256(&retained);
        let boot = legacy_descriptor_data(&b, roots()).unwrap();
        assert_eq!(boot.sequence, 1);
        assert_eq!(boot.archive.segments, 0);
        assert_eq!(boot.archive.event_count, 0);
        assert_eq!(boot.archive.last_segment_sha256, None);
        assert_eq!(boot.global_ordinal, 1025);
        assert_eq!(boot.previous_selected_nv_head, b.selected_nv_head);
        assert_eq!(boot.legacy_journal_sha256, sha256(&retained));
        assert_eq!(
            boot.selected_nv_head,
            extend_head(&b.selected_nv_head, &boot.extension_event_sha256).unwrap()
        );
        verify_legacy_descriptor_data(&b, &boot.canonical_bytes().unwrap()).unwrap();
        let one = segment(&boot.selected_nv_head, 1026, 1, None);
        let next = candidate_data(BaseCutData::Continuation(&boot), &one, roots()).unwrap();
        assert_eq!(next.sequence, 2);
        assert_eq!(next.archive.segments, 1);
        assert_eq!(next.archive.event_count, 1);
        assert_eq!(next.global_ordinal, 1027);
        assert_eq!(
            next.previous_descriptor_sha256,
            Some(boot.sha256().unwrap())
        );
        verify_transition_data(
            BaseCutData::Continuation(&boot),
            &next.canonical_bytes().unwrap(),
            &one.canonical_bytes().unwrap(),
        )
        .unwrap();
        let two = segment(&next.selected_nv_head, 1028, 2, Some(one.sha256().unwrap()));
        let third = candidate_data(BaseCutData::Continuation(&next), &two, roots()).unwrap();
        assert_eq!(third.sequence, 3);
        assert_eq!(third.archive.segments, 2);
        assert_eq!(third.global_ordinal, 1029);
        assert_eq!(third.legacy_journal_sha256, b.journal_sha256);
    }
    #[test]
    fn bootstrap_requires_exact_legacy_genesis_head_ordinal_and_empty_archive_commitment() {
        let b = legacy();
        let boot = legacy_descriptor_data(&b, roots()).unwrap();
        let bytes = boot.canonical_bytes().unwrap();
        for case in 0..5 {
            let mut other = b.clone();
            match case {
                0 => other.installation = h(9),
                1 => other.genesis_event = h(9),
                2 => other.journal_sha256 = h(9),
                3 => other.selected_nv_head = h(9),
                _ => other.global_ordinal += 1,
            };
            assert!(verify_legacy_descriptor_data(&other, &bytes).is_err());
        }
        for case in 0..3 {
            let mut other = boot.clone();
            match case {
                0 => other.archive.root_sha256 = h(9),
                1 => other.archive.last_segment_sha256 = Some(h(9)),
                _ => other.archive.event_count = 1,
            };
            other.extension_event_sha256 = other.extension().unwrap();
            other.selected_nv_head = extend_head(
                &other.previous_selected_nv_head,
                &other.extension_event_sha256,
            )
            .unwrap();
            assert!(other.validate().is_err());
        }
        let mut exhausted = b;
        exhausted.global_ordinal = u64::MAX;
        assert!(legacy_descriptor_data(&exhausted, roots()).is_err());
    }
    #[test]
    fn archive_after_empty_bootstrap_refuses_dropped_reordered_or_replayed_ordinary_events() {
        let b = legacy();
        let boot = legacy_descriptor_data(&b, roots()).unwrap();
        let mut first = segment(&boot.selected_nv_head, 9, 1, None);
        let next =
            ArchivedEvent::from_data(10, &first.final_nv_head, first.events[0].event.clone())
                .unwrap();
        first.final_nv_head = next.resulting_nv_head.clone();
        first.last_ordinal = 10;
        first.events.push(next);
        let descriptor = candidate_data(BaseCutData::Continuation(&boot), &first, roots()).unwrap();
        for case in 0..3 {
            let mut altered = first.clone();
            match case {
                0 => {
                    altered.events.remove(0);
                }
                1 => altered.events.swap(0, 1),
                _ => altered.events[1] = altered.events[0].clone(),
            };
            assert!(verify_transition_data(
                BaseCutData::Continuation(&boot),
                &descriptor.canonical_bytes().unwrap(),
                &serde_json::to_vec(&altered).unwrap()
            )
            .is_err());
        }
        let mut overflow = b;
        overflow.global_ordinal = u64::MAX - 1;
        let final_descriptor = legacy_descriptor_data(&overflow, roots()).unwrap();
        assert_eq!(final_descriptor.global_ordinal, u64::MAX);
        assert!(candidate_data(
            BaseCutData::Continuation(&final_descriptor),
            &first,
            roots()
        )
        .is_err());
    }
}
