//! Selected-source, resumable covariance DATA. Neither matrix bytes nor a
//! completed phase authorizes projection, query selection, inference or effects.
use super::statistics::{StatisticsBoundary, StatisticsProgress, StatisticsRequest};
use super::*;
pub mod projection;
use crate::v2::{cursor::MapCursorBoundary, BlobReference};

const DOMAIN: &str = "luma-corpus-covariance-v1";
const HEADER: &[u8] = b"LUMA-COVARIANCE-V1\n";
const MAX_DOCUMENTS: usize = 128;
const MAP_READ: u64 = 1024 * 1024;
const MAX_READ: u64 = 64 * 1024 * 1024;
const MAX_WRITE: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CovarianceRequest {
    pub schema_version: u32,
    pub statistics: StatisticsRequest,
    pub selected_statistics: StatisticsProgress,
}
impl CovarianceRequest {
    pub fn validate(&self) -> Result<()> {
        self.selected_statistics.validate(&self.statistics)?;
        if self.schema_version != 1 || !self.selected_statistics.complete {
            return Err("covariance requires complete selected document frequencies".into());
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
    fn features(&self) -> Result<Vec<(String, u32)>> {
        self.validate()?;
        Ok(self
            .selected_statistics
            .frequencies
            .as_ref()
            .ok_or("selected statistics has no frequency state")?
            .top
            .iter()
            .map(|value| (value.term.clone(), value.documents))
            .collect())
    }
    fn corpus(&self) -> &MapRoot {
        &self.statistics.ingestion.corpus
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CovarianceProgress {
    pub schema_version: u32,
    pub request_sha256: String,
    pub cursor: MapCursor,
    pub matrix: Option<BlobReference>,
    pub complete: bool,
    pub totals: IngestTotals,
}
impl CovarianceProgress {
    pub fn beginning(request: &CovarianceRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            schema_version: 1,
            request_sha256: request.sha256()?,
            cursor: MapCursor::beginning(request.corpus())?,
            matrix: None,
            complete: request.features()?.is_empty() || request.corpus().entry_count == 0,
            totals: request.selected_statistics.totals,
        })
    }
    pub fn validate(&self, request: &CovarianceRequest) -> Result<()> {
        request.validate()?;
        self.cursor.canonical_bytes(request.corpus())?;
        self.totals.validate(&request.statistics.ingestion.limits)?;
        let prior = request.selected_statistics.totals;
        let dimensions = request.features()?.len();
        if self.schema_version != 1
            || self.request_sha256 != request.sha256()?
            || self.totals.source_bytes != prior.source_bytes
            || self.totals.postings != prior.postings
            || self.totals.read_bytes < prior.read_bytes
            || self.totals.write_bytes < prior.write_bytes
            || self.totals.work < prior.work
            || self.complete
                != (dimensions == 0 || self.cursor.after_count() == request.corpus().entry_count)
            || (self.matrix.is_none()) != (self.cursor.after_count() == 0)
        {
            return Err(
                "covariance progress substitutes source, matrix or cumulative accounting".into(),
            );
        }
        if dimensions == 0 && self.cursor.after_count() != 0 {
            return Err("zero-feature covariance must not fabricate a document traversal".into());
        }
        if let Some(matrix) = &self.matrix {
            matrix.validate()?;
            if matrix.binding != request.corpus().binding
                || matrix.bytes != binary_size(dimensions)? as u64
            {
                return Err("covariance matrix storage binding/length differs".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, request: &CovarianceRequest) -> Result<Vec<u8>> {
        self.validate(request)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 {
            return Err("covariance progress exceeds16KiB".into());
        }
        Ok(bytes)
    }
}
pub trait CovarianceBoundary: StatisticsBoundary {
    fn current_covariance(
        &mut self,
        request: &CovarianceRequest,
        progress: &CovarianceProgress,
    ) -> Result<()>;
    fn verify_covariance_allocations(&mut self, value: &CovarianceCommitment) -> Result<()>;
}
struct Current<'a, B: CovarianceBoundary> {
    request: &'a CovarianceRequest,
    base: &'a CovarianceProgress,
    b: &'a mut B,
}
impl<B: CovarianceBoundary> Current<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.b.check(Access::Inspect {
            binding: &self.request.corpus().binding,
        })?;
        self.b.current_covariance(self.request, self.base)?;
        self.b
            .current_statistics(&self.request.statistics, &self.request.selected_statistics)?;
        self.b.current_job(
            &self.request.statistics.ingestion,
            &self.request.statistics.ingested,
        )?;
        self.b.current_corpus(self.request.corpus())?;
        self.b.current_builder(
            self.request.corpus(),
            &self.request.statistics.ingestion.builder,
        )
    }
}
impl<B: CovarianceBoundary> Boundary for Current<'_, B> {
    fn admit(&mut self, owner: &luma_content::OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if owner != &self.request.corpus().binding {
            return Err("covariance object namespace differs".into());
        }
        self.current()?;
        self.b.admit(owner, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.b.check(access)?;
        self.current()
    }
}
impl<B: CovarianceBoundary> CorpusIndexBoundary for Current<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != self.request.corpus() {
            return Err("covariance corpus substituted".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()> {
        if root != self.request.corpus() || identity != &self.request.statistics.ingestion.builder {
            return Err("covariance builder substituted".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, hash: &str) -> Result<()> {
        self.current()?;
        self.b.current_index_generation(root, hash)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: CovarianceBoundary> MapCursorBoundary for Current<'_, B> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.current_corpus(root)
    }
}

fn binary_size(n: usize) -> Result<usize> {
    if n > MAX_FEATURES {
        return Err("covariance dimensions exceed fixed feature profile".into());
    }
    Ok(HEADER.len() + 64 + 2 + 8 + n * n * 8)
}
fn encode_matrix(
    request: &CovarianceRequest,
    cursor: &MapCursor,
    matrix: &[Vec<f64>],
) -> Result<Vec<u8>> {
    let n = request.features()?.len();
    validate_matrix(matrix, n)?;
    let mut bytes = Vec::with_capacity(binary_size(n)?);
    bytes.extend_from_slice(HEADER);
    bytes.extend_from_slice(request.sha256()?.as_bytes());
    bytes.extend_from_slice(&(n as u16).to_le_bytes());
    bytes.extend_from_slice(&cursor.after_count().to_le_bytes());
    for row in matrix {
        for value in row {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    Ok(bytes)
}
fn decode_matrix(
    request: &CovarianceRequest,
    cursor: &MapCursor,
    bytes: &[u8],
) -> Result<Vec<Vec<f64>>> {
    let n = request.features()?.len();
    let prefix = HEADER.len() + 64 + 2 + 8;
    if bytes.len() != binary_size(n)?
        || !bytes.starts_with(HEADER)
        || &bytes[HEADER.len()..HEADER.len() + 64] != request.sha256()?.as_bytes()
        || u16::from_le_bytes(bytes[HEADER.len() + 64..HEADER.len() + 66].try_into()?) as usize != n
        || u64::from_le_bytes(bytes[HEADER.len() + 66..prefix].try_into()?) != cursor.after_count()
    {
        return Err("binary covariance context/dimensions/cursor mismatch".into());
    }
    let mut matrix = vec![vec![0.0; n]; n];
    for (i, chunk) in bytes[prefix..].chunks_exact(8).enumerate() {
        matrix[i / n][i % n] = f64::from_bits(u64::from_le_bytes(chunk.try_into()?));
    }
    validate_matrix(&matrix, n)?;
    Ok(matrix)
}
fn validate_matrix(matrix: &[Vec<f64>], n: usize) -> Result<()> {
    if n > MAX_FEATURES
        || matrix.len() != n
        || matrix.iter().any(|row| row.len() != n)
        || matrix.iter().flatten().any(|value| !value.is_finite())
    {
        return Err("covariance matrix is not finite/square".into());
    }
    for i in 0..n {
        if matrix[i][i] < 0.0 {
            return Err("negative covariance diagonal".into());
        }
        for j in 0..i {
            if matrix[i][j].to_bits() != matrix[j][i].to_bits() {
                return Err("covariance matrix must be exactly symmetric".into());
            }
        }
    }
    Ok(())
}
fn blob_read_credit(bytes: u64) -> Result<u64> {
    bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(1024 * 1024))
        .ok_or_else(|| "matrix read reserve overflow".into())
}
fn object_count(bytes: usize) -> Result<u64> {
    let chunks = (bytes as u64 + MAX_INDEX_PAGE_BYTES as u64 - 1) / MAX_INDEX_PAGE_BYTES as u64;
    chunks
        .checked_add((chunks + 63) / 64)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| "matrix object count overflow".into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CovarianceReview {
    pub schema_version: u32,
    pub request_sha256: String,
    pub base_sha256: String,
    pub cursor: MapCursor,
    pub matrix_sha256: String,
    pub matrix_bytes: u64,
    pub source_bytes: u64,
    pub maximum_documents: u8,
    pub window_read_bytes: u64,
    pub window_write_bytes: u64,
    pub read_charge: u64,
    pub write_charge: u64,
    pub work_charge: u64,
}
impl CovarianceReview {
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(DOMAIN, self))?))
    }
}
pub struct CovariancePlan {
    request: CovarianceRequest,
    base: CovarianceProgress,
    review: CovarianceReview,
    bytes: Vec<u8>,
    records: Vec<CorpusRecord>,
}
impl CovariancePlan {
    pub fn review(&self) -> &CovarianceReview {
        &self.review
    }
    pub fn planned_objects(
        &self,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<crate::v2::ObjectWriteSpec>> {
        let plan = crate::v2::BlobObjectPlan::data(
            &self.request.statistics.ingestion.corpus.binding,
            &self.bytes,
            &mut check,
        )?;
        if plan.reference().sha256 != self.review.matrix_sha256
            || plan.reference().bytes != self.review.matrix_bytes
        {
            return Err("covariance blob plan differs from actual reviewed matrix".into());
        }
        plan.write_set(check)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CovarianceCommitment {
    pub request: CovarianceRequest,
    pub base: CovarianceProgress,
    pub next: CovarianceProgress,
    pub review: CovarianceReview,
}
impl CovarianceCommitment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.base.validate(&self.request)?;
        self.next.validate(&self.request)?;
        let review = &self.review;
        hash(&review.matrix_sha256)?;
        if review.schema_version != 1
            || review.request_sha256 != self.request.sha256()?
            || review.base_sha256
                != luma_content::sha256(&self.base.canonical_bytes(&self.request)?)
            || review.cursor != self.next.cursor
            || review.maximum_documents == 0
            || usize::from(review.maximum_documents) > MAX_DOCUMENTS
            || review.window_read_bytes == 0
            || review.window_read_bytes > MAX_READ
            || review.window_write_bytes > MAX_WRITE
            || review.read_charge > review.window_read_bytes
            || review.write_charge > review.window_write_bytes
            || self.next.matrix.as_ref().map(|r| (&r.sha256, r.bytes))
                != Some((&review.matrix_sha256, review.matrix_bytes))
            || self.next.totals
                != self.base.totals.plus(&IngestTotals {
                    read_bytes: review.read_charge,
                    write_bytes: review.write_charge,
                    source_bytes: 0,
                    postings: 0,
                    work: review.work_charge,
                })?
        {
            return Err(
                "covariance commitment differs from reviewed exact semantic transition".into(),
            );
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 160 * 1024 {
            return Err("covariance commitment exceeds bounded envelope".into());
        }
        Ok(bytes)
    }
}
pub struct PreparedCovariance {
    commitment: CovarianceCommitment,
}
impl PreparedCovariance {
    pub fn commitment(&self) -> &CovarianceCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected<B: CovarianceBoundary>(&self, b: &mut B) -> Result<()> {
        b.check(Access::Inspect {
            binding: &self.commitment.request.corpus().binding,
        })?;
        b.current_statistics(
            &self.commitment.request.statistics,
            &self.commitment.request.selected_statistics,
        )?;
        b.current_builder(
            self.commitment.request.corpus(),
            &self.commitment.request.statistics.ingestion.builder,
        )?;
        b.current_covariance(&self.commitment.request, &self.commitment.next)
    }
}

pub fn plan_covariance_window<B: CovarianceBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    request: &CovarianceRequest,
    base: &CovarianceProgress,
    maximum_documents: usize,
    window_read_bytes: u64,
    window_write_bytes: u64,
    content: &mut C,
    b: &mut B,
) -> Result<CovariancePlan> {
    base.validate(request)?;
    if base.complete
        || maximum_documents == 0
        || maximum_documents > MAX_DOCUMENTS
        || window_read_bytes == 0
        || window_read_bytes > MAX_READ
        || window_write_bytes > MAX_WRITE
        || window_read_bytes
            > request.statistics.ingestion.limits.read_bytes - base.totals.read_bytes
        || window_write_bytes
            > request.statistics.ingestion.limits.write_bytes - base.totals.write_bytes
    {
        return Err("covariance requires an unfinished finite cumulative window".into());
    }
    let features = request.features()?;
    let n = features.len();
    let bytes = binary_size(n)?;
    let objects = object_count(bytes)?;
    let write_charge = objects
        .checked_mul(PAGE_WRITE)
        .ok_or("matrix write reserve overflow")?;
    let writer_read = objects
        .checked_mul(RUN_PAGE_READ)
        .ok_or("matrix writer read overflow")?;
    let verify_read = blob_read_credit(bytes as u64)?;
    if write_charge > window_write_bytes {
        return Err("finite covariance window does not reserve matrix storage".into());
    }
    let mut live = Current { request, base, b };
    let mut meter = Meter::new(
        request.corpus(),
        &request.statistics.ingestion.builder,
        CorpusIndexLimits {
            read_bytes: window_read_bytes,
            write_bytes: 0,
            source_bytes: MAX_INDEX_SOURCE_BYTES,
            postings: 0,
            floating_operations: request.statistics.ingestion.limits.floating_operations
                - base.totals.work,
        },
        None,
        &mut live,
    )?;
    let mut matrix = if let Some(reference) = &base.matrix {
        let credit = blob_read_credit(reference.bytes)?;
        meter.read(credit)?;
        let data = store.read_blob(
            reference,
            IoBudget {
                read_bytes: credit,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        decode_matrix(request, &base.cursor, &data)?
    } else {
        vec![vec![0.0; n]; n]
    };
    meter.read(MAP_READ)?;
    let scan = store.scan_map_window(
        request.corpus(),
        &base.cursor,
        maximum_documents,
        IoBudget {
            read_bytes: MAP_READ,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let idfs: Vec<_> = features
        .iter()
        .map(|(_, df)| super::super::build::idf(request.corpus().entry_count, *df))
        .collect();
    let mut records = Vec::new();
    for (key, value) in &scan.entries {
        let record = CorpusRecord::parse(value, request.corpus(), key)?;
        // Include a possible exact-prefix rescan BEFORE deciding to read this
        // source, and reserve the independent complete reconstruction as well.
        let read_after = meter
            .read
            .checked_add(record.content_bytes)
            .and_then(|r| r.checked_add(MAP_READ))
            .and_then(|r| r.checked_mul(2))
            .and_then(|r| r.checked_add(writer_read))
            .and_then(|r| r.checked_add(verify_read));
        if read_after.map_or(true, |r| r > window_read_bytes) {
            break;
        }
        meter.source = meter
            .source
            .checked_add(record.content_bytes)
            .ok_or("covariance source overflow")?;
        let data = read_content(request.corpus(), &record, content, &mut meter, &mut live)?;
        let tf = words(&data, request.corpus(), &mut meter, &mut live)?;
        let vector = super::super::build::weights(&tf, &features, &idfs)?;
        let nonzero: Vec<_> = vector
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, x)| *x != 0.0)
            .collect();
        meter.work(
            (nonzero.len() * nonzero.len()) as u64,
            request.corpus(),
            &mut live,
        )?;
        // Keep the exact existing document/row/column accumulation order.
        for (i, x) in &nonzero {
            for (j, y) in &nonzero {
                matrix[*i][*j] += x * y;
            }
        }
        meter.check(request.corpus(), &mut live)?;
        records.push(record);
    }
    if records.is_empty() {
        return Err("covariance window cannot admit one whole source document".into());
    }
    let cursor = if records.len() == scan.entries.len() {
        scan.next
    } else {
        meter.read(MAP_READ)?;
        let prefix = store.scan_map_window(
            request.corpus(),
            &base.cursor,
            records.len(),
            IoBudget {
                read_bytes: MAP_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        if prefix.entries != scan.entries[..records.len()] {
            return Err("covariance exact source prefix changed".into());
        }
        prefix.next
    };
    let data = encode_matrix(request, &cursor, &matrix)?;
    let read_charge = meter
        .read
        .checked_mul(2)
        .and_then(|r| r.checked_add(writer_read))
        .and_then(|r| r.checked_add(verify_read))
        .ok_or("covariance read charge overflow")?;
    let work_charge = meter
        .work
        .checked_mul(2)
        .ok_or("covariance work charge overflow")?;
    if read_charge > window_read_bytes
        || work_charge > request.statistics.ingestion.limits.floating_operations - base.totals.work
    {
        return Err("covariance window does not reserve independent reconstruction".into());
    }
    let review = CovarianceReview {
        schema_version: 1,
        request_sha256: request.sha256()?,
        base_sha256: luma_content::sha256(&base.canonical_bytes(request)?),
        cursor,
        matrix_sha256: luma_content::sha256(&data),
        matrix_bytes: data.len() as u64,
        source_bytes: meter.source,
        maximum_documents: maximum_documents as u8,
        window_read_bytes,
        window_write_bytes,
        read_charge,
        write_charge,
        work_charge,
    };
    let totals = base.totals.plus(&IngestTotals {
        read_bytes: read_charge,
        write_bytes: write_charge,
        source_bytes: 0,
        postings: 0,
        work: work_charge,
    })?;
    totals.validate(&request.statistics.ingestion.limits)?;
    meter.check(request.corpus(), &mut live)?;
    Ok(CovariancePlan {
        request: request.clone(),
        base: base.clone(),
        review,
        bytes: data,
        records,
    })
}
pub fn prepare_covariance<B: CovarianceBoundary>(
    store: &ObjectStore,
    plan: &CovariancePlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedCovariance> {
    if mutation.review_sha256 != plan.review.sha256()?
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != plan.review.source_bytes
    {
        return Err("covariance effect differs from independently reviewed matrix/window".into());
    }
    let mut live = Current {
        request: &plan.request,
        base: &plan.base,
        b,
    };
    for record in &plan.records {
        live.current_candidate(plan.request.corpus(), record)?;
    }
    let objects = object_count(plan.bytes.len())?;
    let reference = store.prepare_blob(
        &plan.bytes,
        IoBudget {
            read_bytes: objects * RUN_PAGE_READ,
            write_bytes: plan.review.write_charge,
            new_files: u32::try_from(objects * 3)?,
        },
        mutation,
        &mut live,
    )?;
    if reference.sha256 != plan.review.matrix_sha256 || reference.bytes != plan.review.matrix_bytes
    {
        return Err("matrix writer substituted reviewed bytes".into());
    }
    let next = CovarianceProgress {
        schema_version: 1,
        request_sha256: plan.request.sha256()?,
        cursor: plan.review.cursor.clone(),
        matrix: Some(reference),
        complete: plan.review.cursor.after_count() == plan.request.corpus().entry_count,
        totals: plan.base.totals.plus(&IngestTotals {
            read_bytes: plan.review.read_charge,
            write_bytes: plan.review.write_charge,
            source_bytes: 0,
            postings: 0,
            work: plan.review.work_charge,
        })?,
    };
    let commitment = CovarianceCommitment {
        request: plan.request.clone(),
        base: plan.base.clone(),
        next,
        review: plan.review.clone(),
    };
    commitment.canonical_bytes()?;
    live.current()?;
    b.verify_covariance_allocations(&commitment)?;
    b.check(Access::Mutate {
        binding: &plan.request.corpus().binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: mutation.source_bytes,
        storage_bytes: plan.review.write_charge,
    })?;
    b.current_covariance(&plan.request, &plan.base)?;
    Ok(PreparedCovariance { commitment })
}
pub fn verify_covariance_data<B: CovarianceBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    value: &CovarianceCommitment,
    content: &mut C,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let plan = plan_covariance_window(
        store,
        &value.request,
        &value.base,
        usize::from(value.review.maximum_documents),
        value.review.window_read_bytes,
        value.review.window_write_bytes,
        content,
        b,
    )?;
    if plan.review != value.review {
        return Err("covariance candidate differs from independent source reconstruction".into());
    }
    let reference = value
        .next
        .matrix
        .as_ref()
        .ok_or("prepared covariance has no matrix blob")?;
    let mut live = Current {
        request: &value.request,
        base: &value.base,
        b,
    };
    let actual = store.read_blob(
        reference,
        IoBudget {
            read_bytes: blob_read_credit(reference.bytes)?,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    if actual != plan.bytes {
        return Err("prepared covariance binary matrix differs from exact rebuilt values".into());
    }
    decode_matrix(&value.request, &value.next.cursor, &actual)?;
    live.current()?;
    b.verify_covariance_allocations(value)?;
    b.check(Access::Inspect {
        binding: &value.request.corpus().binding,
    })?;
    b.current_covariance(&value.request, &value.base)
}
pub fn read_covariance_matrix<B: CovarianceBoundary>(
    store: &dyn IndexReadStore,
    request: &CovarianceRequest,
    selected: &CovarianceProgress,
    budget: IoBudget,
    b: &mut B,
) -> Result<Vec<Vec<f64>>> {
    selected.validate(request)?;
    budget.validate()?;
    if !selected.complete || budget.write_bytes != 0 || budget.new_files != 0 {
        return Err(
            "matrix read requires a complete selected covariance and finite read-only budget"
                .into(),
        );
    }
    let mut live = Current {
        request,
        base: selected,
        b,
    };
    live.current()?;
    let value = if let Some(reference) = &selected.matrix {
        let bytes = store.read_blob(reference, budget, &mut live)?;
        decode_matrix(request, &selected.cursor, &bytes)?
    } else {
        Vec::new()
    };
    live.current()?;
    Ok(value)
}

#[cfg(test)]
#[path = "covariance/tests.rs"]
mod tests;
