use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotMode {
    Review,
    Export,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBudget {
    pub read_bytes: u64,
    pub output_bytes: u64,
    pub maximum_objects: u64,
    pub maximum_parts: u32,
}
impl SnapshotBudget {
    pub fn validate(&self, mode: SnapshotMode) -> Result<()> {
        if self.read_bytes < 128 * 1024 * 1024
            || self.read_bytes > MAX_SNAPSHOT_READ_BYTES
            || self.output_bytes > MAX_SNAPSHOT_EXPORT_BYTES
            || (mode == SnapshotMode::Review && self.output_bytes != 0)
            || (mode == SnapshotMode::Export && self.output_bytes <= MAX_SNAPSHOT_PACKAGE_OVERHEAD)
            || self.maximum_objects > MAX_SNAPSHOT_OBJECTS
            || self.maximum_parts == 0
            || self.maximum_parts > MAX_SNAPSHOT_PARTS
        {
            return Err("invalid finite whole-snapshot budget".into());
        }
        Ok(())
    }
}
/// The native adapter must retain exact current C selection, independently
/// qualified governed recipients/signer, original purpose/session/grants and a
/// single live resource generation. Nested raw windows never renew that lease.
pub trait SnapshotBoundary: super::super::OwnerBoundary {
    fn admit_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        budget: SnapshotBudget,
    ) -> Result<()>;
    fn check_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        review_sha256: Option<&str>,
    ) -> Result<()>;
    /// Genuine complete semantic/page/blob coverage of ALL nine selected roots,
    /// not a raw hash-directory checksum or caller-supplied completeness flag.
    fn verify_snapshot_head(&mut self, head: &OwnerHeadV2) -> Result<()>;
}
pub trait SnapshotSink: SnapshotPages {
    /// Retain/read back actual encrypted bytes using the existing isolated CMS
    /// runtime under the original live Export purpose. Neither this return value
    /// nor an individual encrypted part is a whole authenticated backup receipt.
    fn retain_part(
        &mut self,
        intent: &SnapshotIntent,
        plaintext: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PartCommitment>;
}
const WINDOW: IoBudget = IoBudget {
    read_bytes: 64 * 1024 * 1024,
    write_bytes: 0,
    new_files: 0,
};
fn check<B: SnapshotBoundary>(
    b: &mut B,
    intent: &SnapshotIntent,
    mode: SnapshotMode,
    review: Option<&str>,
) -> Result<()> {
    b.check(Access::Inspect {
        binding: &intent.head.binding,
    })?;
    b.current_owner_head(&intent.head)?;
    b.check_snapshot(intent, mode, review)
}
struct Observation {
    stream: String,
    last: Option<String>,
    objects: u64,
    bytes: u64,
    read: u64,
}
impl Observation {
    fn new(intent: &SnapshotIntent) -> Result<Self> {
        Ok(Self {
            stream: seed(intent)?,
            last: None,
            objects: 0,
            bytes: 0,
            read: 128 * 1024 * 1024,
        })
    }
    fn add(&mut self, object: &SnapshotObject, budget: SnapshotBudget) -> Result<()> {
        object.validate()?;
        if self
            .last
            .as_ref()
            .is_some_and(|old| old >= &object.object_sha256)
        {
            return Err("whole raw snapshot repeats or reorders an object".into());
        }
        self.objects = self
            .objects
            .checked_add(1)
            .ok_or("snapshot object count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(object.bytes)
            .ok_or("snapshot object bytes overflow")?;
        self.read = self
            .read
            .checked_add(object.bytes + 512)
            .ok_or("snapshot read accounting overflow")?;
        if self.objects > budget.maximum_objects
            || self.bytes > MAX_SNAPSHOT_RAW_BYTES
            || self.read > budget.read_bytes
        {
            return Err("finite whole-snapshot source budget exhausted".into());
        }
        self.stream = extend(&self.stream, object)?;
        self.last = Some(object.object_sha256.clone());
        Ok(())
    }
    fn finish(
        self,
        intent: &SnapshotIntent,
        inventory: PhysicalInventory,
    ) -> Result<SnapshotReview> {
        let mut review = SnapshotReview {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            intent_sha256: intent.sha256()?,
            inventory,
            object_count: self.objects,
            object_bytes: self.bytes,
            stream_sha256: self.stream,
            review_sha256: String::new(),
        };
        review.finish(intent)?;
        Ok(review)
    }
}
pub fn review_snapshot<B: SnapshotBoundary>(
    store: &ObjectStore,
    intent: &SnapshotIntent,
    budget: SnapshotBudget,
    b: &mut B,
) -> Result<SnapshotReview> {
    intent.validate()?;
    store.check_root(&intent.head.roots.artifacts)?;
    budget.validate(SnapshotMode::Review)?;
    b.admit_snapshot(intent, SnapshotMode::Review, budget)?;
    check(b, intent, SnapshotMode::Review, None)?;
    b.verify_snapshot_head(&intent.head)?;
    let mut scan = store.begin_raw_snapshot(WINDOW, b)?;
    let mut observed = Observation::new(intent)?;
    loop {
        check(b, intent, SnapshotMode::Review, None)?;
        let window = scan.next_window(WINDOW, 256, b, |name, allocation, bytes, b| {
            check(b, intent, SnapshotMode::Review, None)?;
            let object = SnapshotObject::measured(name, allocation, bytes)?;
            observed.add(&object, budget)?;
            check(b, intent, SnapshotMode::Review, None)
        })?;
        if window.completed {
            break;
        }
    }
    let review = observed.finish(intent, scan.completed_inventory()?.clone())?;
    b.verify_snapshot_head(&intent.head)?;
    check(b, intent, SnapshotMode::Review, None)?;
    Ok(review)
}
pub fn export_snapshot<B: SnapshotBoundary>(
    store: &ObjectStore,
    intent: &SnapshotIntent,
    review: &SnapshotReview,
    budget: SnapshotBudget,
    b: &mut B,
    sink: &mut impl SnapshotSink,
) -> Result<WholeSnapshotManifest> {
    intent.validate()?;
    store.check_root(&intent.head.roots.artifacts)?;
    review.validate(intent)?;
    budget.validate(SnapshotMode::Export)?;
    b.admit_snapshot(intent, SnapshotMode::Export, budget)?;
    let reviewed = Some(review.review_sha256.as_str());
    check(b, intent, SnapshotMode::Export, reviewed)?;
    b.verify_snapshot_head(&intent.head)?;
    let mut scan = store.begin_raw_snapshot(WINDOW, b)?;
    let mut observed = Observation::new(intent)?;
    let mut objects = Vec::new();
    let mut data = Vec::new();
    let mut builder = directory::Builder::new();
    let mut part_count = 0_u32;
    let mut previous = None;
    let mut plaintext_bytes = 0_u64;
    let mut ciphertext_bytes = 0_u64;
    loop {
        check(b, intent, SnapshotMode::Export, reviewed)?;
        let window = scan.next_window(WINDOW, 256, b, |name, allocation, bytes, b| {
            check(b, intent, SnapshotMode::Export, reviewed)?;
            let object = SnapshotObject::measured(name, allocation, bytes)?;
            observed.add(&object, budget)?;
            objects.push(object);
            data.extend_from_slice(bytes);
            if objects.len() == MAX_PART_OBJECTS {
                flush(
                    intent,
                    review,
                    budget,
                    b,
                    sink,
                    &mut builder,
                    &mut objects,
                    &mut data,
                    &mut part_count,
                    &mut previous,
                    &mut plaintext_bytes,
                    &mut ciphertext_bytes,
                )?;
            }
            check(b, intent, SnapshotMode::Export, reviewed)
        })?;
        if window.completed {
            break;
        }
    }
    let actual = observed.finish(intent, scan.completed_inventory()?.clone())?;
    if &actual != review {
        return Err("whole raw snapshot changed after independent exact review; partial ciphertext remains inert".into());
    }
    if !objects.is_empty() || part_count == 0 {
        flush(
            intent,
            review,
            budget,
            b,
            sink,
            &mut builder,
            &mut objects,
            &mut data,
            &mut part_count,
            &mut previous,
            &mut plaintext_bytes,
            &mut ciphertext_bytes,
        )?;
    }
    b.verify_snapshot_head(&intent.head)?;
    check(b, intent, SnapshotMode::Export, reviewed)?;
    let parts = builder.finish(intent, sink, &mut || {
        check(b, intent, SnapshotMode::Export, reviewed)
    })?;
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent: intent.clone(),
        review: review.clone(),
        parts,
        part_count,
        plaintext_bytes,
        ciphertext_bytes,
        last_plaintext_sha256: previous.ok_or("snapshot encrypted terminal part absent")?,
    };
    manifest.canonical_bytes()?;
    manifest.verify_directory(sink, &mut || {
        check(b, intent, SnapshotMode::Export, reviewed)
    })?;
    check(b, intent, SnapshotMode::Export, reviewed)?;
    Ok(manifest)
}
fn flush<B: SnapshotBoundary>(
    intent: &SnapshotIntent,
    review: &SnapshotReview,
    budget: SnapshotBudget,
    b: &mut B,
    sink: &mut impl SnapshotSink,
    builder: &mut directory::Builder,
    objects: &mut Vec<SnapshotObject>,
    data: &mut Vec<u8>,
    part_count: &mut u32,
    previous: &mut Option<String>,
    plaintext_bytes: &mut u64,
    ciphertext_bytes: &mut u64,
) -> Result<()> {
    if *part_count >= budget.maximum_parts {
        return Err("finite snapshot part budget exhausted".into());
    }
    let bytes = part::encode(
        intent,
        *part_count,
        previous.clone(),
        std::mem::take(objects),
        data,
    )?;
    data.clear();
    if ciphertext_bytes
        .checked_add(bytes.len() as u64 + 65536 + MAX_SNAPSHOT_PACKAGE_OVERHEAD)
        .ok_or("snapshot remaining output overflow")?
        > budget.output_bytes
    {
        return Err("snapshot output budget cannot cover the next bounded encrypted part".into());
    }
    let part = SnapshotPart::parse(&bytes, intent, &mut || {
        check(b, intent, SnapshotMode::Export, Some(&review.review_sha256))
    })?;
    let commitment = sink.retain_part(intent, &bytes, &mut || {
        check(b, intent, SnapshotMode::Export, Some(&review.review_sha256))
    })?;
    commitment.validate()?;
    if commitment.number != *part_count
        || commitment.plaintext_sha256 != part.sha256()
        || commitment.plaintext_bytes != bytes.len() as u64
        || commitment.objects != part.header().objects.len() as u32
        || commitment.previous_plaintext_sha256 != *previous
    {
        return Err("encrypted part readback substitutes measured reviewed plaintext".into());
    }
    *plaintext_bytes = plaintext_bytes
        .checked_add(commitment.plaintext_bytes)
        .ok_or("snapshot plaintext total overflow")?;
    *ciphertext_bytes = ciphertext_bytes
        .checked_add(commitment.ciphertext_bytes)
        .ok_or("snapshot ciphertext total overflow")?;
    if *ciphertext_bytes > budget.output_bytes {
        return Err("finite snapshot ciphertext budget exhausted; no complete receipt".into());
    }
    *previous = Some(commitment.plaintext_sha256.clone());
    builder.push(intent, commitment, sink, &mut || {
        check(b, intent, SnapshotMode::Export, Some(&review.review_sha256))
    })?;
    *part_count += 1;
    check(b, intent, SnapshotMode::Export, Some(&review.review_sha256))
}
