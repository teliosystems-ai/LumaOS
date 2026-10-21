//! Resumable independent full corpus/records/coordinates/posting closure DATA.
//! Every cursor is revalidated against the original live C-selected audit.
use super::*;
use crate::corpus_index::job::statistics::{selected::SelectedPostingReader, DocumentFrequency};
use std::collections::BTreeSet;

const AUDIT_DOMAIN: &str = "luma-corpus-complete-generation-audit-v1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditPhase {
    Coverage,
    Postings,
    Complete,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrequencyAudit {
    pub current: Option<DocumentFrequency>,
    pub last: Option<IngestPosting>,
    pub vocabulary: u64,
    pub bucket: Option<u16>,
    pub bucket_terms: u64,
    pub bucket_key_bytes: u64,
    pub top: Vec<DocumentFrequency>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditProgress {
    pub schema_version: u32,
    pub job_sha256: String,
    pub phase: AuditPhase,
    pub cursor: MapCursor,
    pub posting_offset: u64,
    pub frequencies: FrequencyAudit,
    pub totals: IngestTotals,
}
fn term(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > crate::MAX_SEARCH_TERM_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err("generation audit term violates exact lexical grammar".into());
    }
    Ok(())
}
fn key(value: &IngestPosting) -> (usize, &str, u32) {
    (bucket(&value.term), &value.term, value.document)
}
impl AuditProgress {
    pub fn beginning(job: &GenerationJob) -> Result<Self> {
        job.canonical_bytes()?;
        Ok(Self {
            schema_version: 1,
            job_sha256: job.sha256()?,
            phase: AuditPhase::Coverage,
            cursor: MapCursor::beginning(job.corpus())?,
            posting_offset: 0,
            frequencies: FrequencyAudit::default(),
            totals: job.progress.totals,
        })
    }
    pub fn canonical_bytes(&self, job: &GenerationJob) -> Result<Vec<u8>> {
        job.canonical_bytes()?;
        self.cursor.canonical_bytes(job.corpus())?;
        self.totals.validate(&job.request.limits())?;
        let prior = job.progress.totals;
        let (_, stats) = job.statistics();
        let selected = stats
            .frequencies
            .as_ref()
            .ok_or("complete statistics lacks DF closure")?;
        if self.schema_version != 1
            || self.job_sha256 != job.sha256()?
            || self.posting_offset > prior.postings
            || self.totals.read_bytes < prior.read_bytes
            || self.totals.write_bytes != prior.write_bytes
            || self.totals.work < prior.work
            || self.totals.source_bytes != prior.source_bytes
            || self.totals.postings != prior.postings
            || self.frequencies.top.len() > MAX_FEATURES
            || self.frequencies.vocabulary > prior.postings
            || self.frequencies.bucket_terms > MAX_BUCKET_TERMS as u64
            || self.frequencies.bucket_key_bytes > 8 * 1024 * 1024
        {
            return Err("generation audit substitutes phase/source/cumulative closure".into());
        }
        if self.phase == AuditPhase::Coverage {
            if self.posting_offset != 0 || self.frequencies != FrequencyAudit::default() {
                return Err("coverage audit carries unaudited posting state".into());
            }
        } else if self.cursor.after_count() != job.corpus().entry_count {
            return Err("posting audit precedes complete exact record/coordinate coverage".into());
        }
        for frequency in self
            .frequencies
            .top
            .iter()
            .chain(self.frequencies.current.iter())
        {
            term(&frequency.term)?;
            if frequency.documents == 0 || u64::from(frequency.documents) > job.corpus().entry_count
            {
                return Err("audited DF exceeds exact source corpus".into());
            }
        }
        if self
            .frequencies
            .top
            .windows(2)
            .any(|p| p[0].term >= p[1].term)
        {
            return Err("audited top features are duplicated/unordered".into());
        }
        if let Some(last) = &self.frequencies.last {
            term(&last.term)?;
            if self.posting_offset == 0
                || u64::from(last.document) >= job.corpus().entry_count
                || last.frequency == 0
                || last.frequency > MAX_DOCUMENT_BYTES as u32
                || last.offset >= MAX_DOCUMENT_BYTES as u32
                || self.frequencies.bucket != Some(bucket(&last.term) as u16)
            {
                return Err("audit last posting context is invalid".into());
            }
        } else if self.posting_offset != 0 {
            return Err("audited posting cursor lacks exact predecessor".into());
        }
        if let Some(current) = &self.frequencies.current {
            if self.frequencies.last.as_ref().map(|p| &p.term) != Some(&current.term) {
                return Err("audit unfinished DF differs from posting cursor".into());
            }
        }
        if self.phase == AuditPhase::Complete
            && (self.posting_offset != prior.postings
                || self.frequencies.current.is_some()
                || self.frequencies.vocabulary != selected.vocabulary
                || self.frequencies.top != selected.top)
        {
            return Err(
                "complete audit differs from independently recomputed full DF selection".into(),
            );
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 128 * 1024 {
            return Err("generation audit progress exceeds finite record".into());
        }
        Ok(bytes)
    }
}
pub trait GenerationAuditBoundary: VectorBoundary {
    fn current_generation_audit(
        &mut self,
        job: &GenerationJob,
        progress: &AuditProgress,
    ) -> Result<()>;
    /// Real custody/resource reservation for the next progress event. This
    /// callback does not select it; native C publication remains independent.
    fn verify_audit_reservations(&mut self, value: &AuditCommitment) -> Result<()>;
}
pub(super) struct Current<'a, B: GenerationAuditBoundary> {
    pub(super) job: &'a GenerationJob,
    pub(super) base: &'a AuditProgress,
    pub(super) b: &'a mut B,
}
impl<B: GenerationAuditBoundary> Current<'_, B> {
    pub(super) fn current(&mut self) -> Result<()> {
        self.b.current_generation_audit(self.job, self.base)?;
        super::super::Current {
            request: &self.job.request,
            base: &self.job.progress,
            b: self.b,
        }
        .current()
    }
}
impl<B: GenerationAuditBoundary> Boundary for Current<'_, B> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        if binding != &self.job.corpus().binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("audit reader cannot allocate private files or substitute owner".into());
        }
        self.current()?;
        self.b.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        if !matches!(access, Access::Inspect { .. }) {
            return Err("independent audit traversal is read-only".into());
        }
        self.b.check(access)?;
        self.current()
    }
}
impl<B: GenerationAuditBoundary> CorpusIndexBoundary for Current<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != self.job.corpus() {
            return Err("audit corpus substitution".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        if root != self.job.corpus()
            || builder
                != &self
                    .job
                    .request
                    .projection
                    .covariance
                    .statistics
                    .ingestion
                    .builder
        {
            return Err("audit builder substitution".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, generation: &str) -> Result<()> {
        self.current()?;
        self.b.current_index_generation(root, generation)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: GenerationAuditBoundary> MapCursorBoundary for Current<'_, B> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.current_corpus(root)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditCommitment {
    pub job: GenerationJob,
    pub base: AuditProgress,
    pub next: AuditProgress,
    pub maximum: u16,
    pub window_read_bytes: u64,
    pub review_sha256: String,
}
impl AuditCommitment {
    pub(super) fn review(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            AUDIT_DOMAIN,
            &self.job,
            &self.base,
            &self.next,
            self.maximum,
            self.window_read_bytes,
        ))?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.base.canonical_bytes(&self.job)?;
        self.next.canonical_bytes(&self.job)?;
        if self.base.phase == AuditPhase::Complete
            || self.maximum == 0
            || self.maximum > 4096
            || (self.base.phase == AuditPhase::Coverage && self.maximum > 128)
            || self.window_read_bytes == 0
            || self.window_read_bytes > 64 * 1024 * 1024
            || self.review_sha256 != self.review()?
            || self
                .next
                .totals
                .read_bytes
                .checked_sub(self.base.totals.read_bytes)
                .map_or(true, |n| n > self.window_read_bytes)
            || self.next.totals.work < self.base.totals.work
        {
            return Err("audit commitment substitutes reviewed bounded transition".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("complete audit transition exceeds independently bounded record".into());
        }
        Ok(bytes)
    }
}
fn finish_term(
    df: &mut FrequencyAudit,
    top: &mut BTreeSet<(u32, std::cmp::Reverse<String>)>,
) -> Result<()> {
    if let Some(current) = df.current.take() {
        df.vocabulary = df
            .vocabulary
            .checked_add(1)
            .ok_or("audit vocabulary overflow")?;
        df.bucket_terms = df
            .bucket_terms
            .checked_add(1)
            .ok_or("audit bucket vocabulary overflow")?;
        df.bucket_key_bytes = df
            .bucket_key_bytes
            .checked_add(current.term.len() as u64)
            .ok_or("audit bucket key overflow")?;
        if df.bucket_terms > MAX_BUCKET_TERMS as u64 || df.bucket_key_bytes > 8 * 1024 * 1024 {
            return Err("audited exact bucket vocabulary exceeds fixed profile".into());
        }
        top.insert((current.documents, std::cmp::Reverse(current.term)));
        if top.len() > MAX_FEATURES {
            top.pop_first();
        }
    }
    Ok(())
}
pub fn plan_audit_window<B: GenerationAuditBoundary>(
    store: &dyn IndexReadStore,
    job: &GenerationJob,
    base: &AuditProgress,
    maximum: usize,
    window_read_bytes: u64,
    b: &mut B,
) -> Result<AuditCommitment> {
    base.canonical_bytes(job)?;
    if base.phase == AuditPhase::Complete
        || maximum == 0
        || maximum > 4096
        || (base.phase == AuditPhase::Coverage && maximum > 128)
        || window_read_bytes == 0
        || window_read_bytes > 64 * 1024 * 1024
        || window_read_bytes > job.request.limits().read_bytes - base.totals.read_bytes
    {
        return Err("audit window exceeds original finite cumulative session/job profile".into());
    }
    let mut live = Current { job, base, b };
    live.current()?;
    live.admit(
        &job.corpus().binding,
        ResourceBudget {
            memory_bytes: 192 * 1024 * 1024,
            tasks: 1,
            read_bytes: window_read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    let mut next = base.clone();
    let (read, work) = if base.phase == AuditPhase::Coverage {
        let reserve = VECTOR_MAP_READ + 8 * 1024 * 1024 + 2 * 1024 * 1024;
        if reserve * 2 > window_read_bytes {
            return Err(
                "audit cannot reserve whole independent coverage window before private I/O".into(),
            );
        }
        let source = store.scan_map_window(
            job.corpus(),
            &base.cursor,
            maximum,
            IoBudget {
                read_bytes: VECTOR_MAP_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        let records = super::super::read::read_record_window_data(
            store,
            &job.request,
            &job.progress,
            u32::try_from(base.cursor.after_count())?,
            maximum,
            IoBudget {
                read_bytes: 8 * 1024 * 1024,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        let coordinates = super::super::read::read_coordinate_window_data(
            store,
            &job.request,
            &job.progress,
            u32::try_from(base.cursor.after_count())?,
            maximum,
            IoBudget {
                read_bytes: 2 * 1024 * 1024,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        if source.entries.len() != records.rows.len()
            || records.rows.len() != coordinates.rows.len()
        {
            return Err("full-generation record/coordinate/source coverage differs".into());
        }
        for (((key, bytes), record), coordinate) in source
            .entries
            .iter()
            .zip(&records.rows)
            .zip(&coordinates.rows)
        {
            let actual = CorpusRecord::parse(bytes, job.corpus(), key)?;
            if actual != record.record || record.components != *coordinate {
                return Err("generation record/coordinate differs from exact authoritative corpus/builder vector".into());
            }
            live.current_candidate(job.corpus(), &actual)?;
        }
        next.cursor = source.next;
        if next.cursor.after_count() == job.corpus().entry_count {
            next.phase = AuditPhase::Postings;
        }
        (
            VECTOR_MAP_READ + records.read_bytes + coordinates.read_bytes,
            records.rows.len() as u64 * 32,
        )
    } else {
        let (request, selected) = job.statistics();
        let mut reader = SelectedPostingReader::open(
            store,
            request,
            selected,
            window_read_bytes / 2,
            &mut live,
        )?;
        let rows = reader.range(base.posting_offset, maximum)?;
        let read = reader.read_bytes();
        drop(reader);
        let mut top: BTreeSet<_> = next
            .frequencies
            .top
            .iter()
            .map(|f| (f.documents, std::cmp::Reverse(f.term.clone())))
            .collect();
        for (i, row) in rows.iter().enumerate() {
            if i % 128 == 0 {
                live.current()?;
            }
            if next
                .frequencies
                .last
                .as_ref()
                .is_some_and(|old| key(old) >= key(row))
            {
                return Err("complete audit detects unordered or duplicate global postings".into());
            }
            if next.frequencies.current.as_ref().map(|f| &f.term) != Some(&row.term) {
                finish_term(&mut next.frequencies, &mut top)?;
                let bucket = bucket(&row.term) as u16;
                if next.frequencies.bucket != Some(bucket) {
                    next.frequencies.bucket = Some(bucket);
                    next.frequencies.bucket_terms = 0;
                    next.frequencies.bucket_key_bytes = 0;
                }
                next.frequencies.current = Some(DocumentFrequency {
                    term: row.term.clone(),
                    documents: 1,
                });
            } else {
                let current = next
                    .frequencies
                    .current
                    .as_mut()
                    .ok_or("audit DF state lost its current term")?;
                current.documents = current
                    .documents
                    .checked_add(1)
                    .ok_or("audit document frequency overflow")?;
            }
            next.frequencies.last = Some(row.clone());
            next.posting_offset += 1;
        }
        if next.posting_offset == job.progress.totals.postings {
            finish_term(&mut next.frequencies, &mut top)?;
            next.phase = AuditPhase::Complete;
        }
        next.frequencies.top = top
            .into_iter()
            .map(|(documents, term)| DocumentFrequency {
                term: term.0,
                documents,
            })
            .collect();
        next.frequencies.top.sort_by(|a, b| a.term.cmp(&b.term));
        (read, rows.len() as u64 * 32 + 8192)
    };
    let read = read
        .checked_mul(2)
        .ok_or("audit independent replay read overflow")?;
    if read > window_read_bytes {
        return Err("audit cannot reserve exact independent replay".into());
    }
    next.totals = base.totals.plus(&IngestTotals {
        read_bytes: read,
        write_bytes: 0,
        source_bytes: 0,
        postings: 0,
        work: work
            .checked_mul(2)
            .ok_or("audit independent replay work overflow")?,
    })?;
    next.canonical_bytes(job)?;
    live.current()?;
    let mut value = AuditCommitment {
        job: job.clone(),
        base: base.clone(),
        next,
        maximum: maximum as u16,
        window_read_bytes,
        review_sha256: String::new(),
    };
    value.review_sha256 = value.review()?;
    value.canonical_bytes()?;
    Ok(value)
}
pub struct PreparedAudit {
    value: AuditCommitment,
}
impl PreparedAudit {
    pub fn commitment(&self) -> &AuditCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: GenerationAuditBoundary>(&self, b: &mut B) -> Result<()> {
        Current {
            job: &self.value.job,
            base: &self.value.next,
            b,
        }
        .current()
    }
}
/// Prepares only a guarded DATA transition. The real C publisher must call the
/// independent verifier and durably select next; no callback here mints a grant.
pub fn prepare_audit<B: GenerationAuditBoundary>(
    value: &AuditCommitment,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedAudit> {
    value.canonical_bytes()?;
    if mutation.review_sha256 != value.review_sha256
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != 0
    {
        return Err("generation audit mutation differs from exact reviewed transition".into());
    }
    Current {
        job: &value.job,
        base: &value.base,
        b,
    }
    .current()?;
    b.check(Access::Mutate {
        binding: &value.job.corpus().binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: 0,
        storage_bytes: 0,
    })?;
    b.verify_audit_reservations(value)?;
    Current {
        job: &value.job,
        base: &value.base,
        b,
    }
    .current()?;
    Ok(PreparedAudit {
        value: value.clone(),
    })
}
pub fn verify_audit_data<B: GenerationAuditBoundary>(
    store: &dyn IndexReadStore,
    value: &AuditCommitment,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    if plan_audit_window(
        store,
        &value.job,
        &value.base,
        usize::from(value.maximum),
        value.window_read_bytes,
        b,
    )? != *value
    {
        return Err(
            "generation audit candidate differs from exact independent closure reconstruction"
                .into(),
        );
    }
    b.verify_audit_reservations(value)?;
    Current {
        job: &value.job,
        base: &value.base,
        b,
    }
    .current()
}
