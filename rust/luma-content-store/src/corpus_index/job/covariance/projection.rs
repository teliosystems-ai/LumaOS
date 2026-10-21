//! Resumable, exact cyclic-Jacobi projection DATA over a selected covariance.
//! No partial basis is a successful projection or an admitted index generation.
use super::*;
pub mod vectors;

const PROJECTION_DOMAIN: &str = "luma-corpus-projection-v1";
const PROJECTION_HEADER: &[u8] = b"LUMA-PROJECTION-V1\n";
const MAX_PAIR_VISITS: usize = 8192;
const MAX_PROJECTION_READ: u64 = 64 * 1024 * 1024;
const MAX_PROJECTION_WRITE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequest {
    pub schema_version: u32,
    pub covariance: CovarianceRequest,
    pub selected_covariance: CovarianceProgress,
    pub requested_dimensions: u16,
}
impl ProjectionRequest {
    pub fn validate(&self) -> Result<()> {
        self.selected_covariance.validate(&self.covariance)?;
        if self.schema_version != 1
            || !self.selected_covariance.complete
            || self.requested_dimensions == 0
            || usize::from(self.requested_dimensions) > MAX_DIMENSIONS
        {
            return Err(
                "projection requires exact complete covariance and bounded dimensions".into(),
            );
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
    fn n(&self) -> Result<usize> {
        Ok(self.covariance.features()?.len())
    }
    fn corpus(&self) -> &MapRoot {
        self.covariance.corpus()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JacobiCursor {
    pub sweep: u8,
    pub p: u16,
    pub q: u16,
    pub sweep_open: bool,
    pub changed: bool,
    pub complete: bool,
}
impl JacobiCursor {
    fn beginning() -> Self {
        Self {
            sweep: 0,
            p: 0,
            q: 1,
            sweep_open: false,
            changed: false,
            complete: false,
        }
    }
    fn validate(&self, n: usize) -> Result<()> {
        if self.sweep >= 64 {
            return Err("Jacobi sweep bound exceeded".into());
        }
        if self.complete {
            if self.p != 0 || self.q != 0 || self.sweep_open || self.changed {
                return Err("completed projection retains unfinished Jacobi work".into());
            }
        } else if (n < 2 && (self.p != 0 || self.q != 1))
            || (n >= 2
                && (usize::from(self.p) >= n - 1 || self.q <= self.p || usize::from(self.q) >= n))
            || (!self.sweep_open && (self.p != 0 || self.q != 1 || self.changed))
        {
            return Err("Jacobi cursor skips or aliases pending pair order".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionProgress {
    pub schema_version: u32,
    pub request_sha256: String,
    pub cursor: JacobiCursor,
    pub state: Option<BlobReference>,
    pub totals: IngestTotals,
}
impl ProjectionProgress {
    pub fn beginning(request: &ProjectionRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            schema_version: 1,
            request_sha256: request.sha256()?,
            cursor: JacobiCursor::beginning(),
            state: None,
            totals: request.selected_covariance.totals,
        })
    }
    pub fn canonical_bytes(&self, request: &ProjectionRequest) -> Result<Vec<u8>> {
        request.validate()?;
        self.cursor.validate(request.n()?)?;
        self.totals
            .validate(&request.covariance.statistics.ingestion.limits)?;
        let prior = request.selected_covariance.totals;
        if self.schema_version != 1
            || self.request_sha256 != request.sha256()?
            || self.totals.read_bytes < prior.read_bytes
            || self.totals.write_bytes < prior.write_bytes
            || self.totals.work < prior.work
            || self.totals.source_bytes != prior.source_bytes
            || self.totals.postings != prior.postings
            || (self.state.is_none()
                && (self.cursor != JacobiCursor::beginning() || self.totals != prior))
        {
            return Err(
                "projection progress substitutes source, phase or cumulative accounting".into(),
            );
        }
        if let Some(state) = &self.state {
            state.validate()?;
            if state.binding != request.corpus().binding
                || state.bytes < state_size(request.n()?, 0)? as u64
                || state.bytes
                    > state_size(
                        request.n()?,
                        usize::from(request.requested_dimensions).min(request.n()?),
                    )? as u64
            {
                return Err("projection blob owner/shape differs from fixed matrix profile".into());
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 {
            return Err("projection progress exceeds16KiB".into());
        }
        Ok(bytes)
    }
}
pub trait ProjectionBoundary: CovarianceBoundary {
    fn current_projection(
        &mut self,
        request: &ProjectionRequest,
        progress: &ProjectionProgress,
    ) -> Result<()>;
    fn verify_projection_allocations(&mut self, value: &ProjectionCommitment) -> Result<()>;
}
struct Live<'a, B: ProjectionBoundary> {
    request: &'a ProjectionRequest,
    progress: &'a ProjectionProgress,
    b: &'a mut B,
}
impl<B: ProjectionBoundary> Live<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.b.check(Access::Inspect {
            binding: &self.request.corpus().binding,
        })?;
        self.b.current_projection(self.request, self.progress)?;
        self.b
            .current_covariance(&self.request.covariance, &self.request.selected_covariance)?;
        self.b.current_statistics(
            &self.request.covariance.statistics,
            &self.request.covariance.selected_statistics,
        )?;
        self.b.current_job(
            &self.request.covariance.statistics.ingestion,
            &self.request.covariance.statistics.ingested,
        )?;
        self.b.current_corpus(self.request.corpus())?;
        self.b.current_builder(
            self.request.corpus(),
            &self.request.covariance.statistics.ingestion.builder,
        )
    }
}
impl<B: ProjectionBoundary> Boundary for Live<'_, B> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        if binding != &self.request.corpus().binding {
            return Err("projection storage owner differs".into());
        }
        self.current()?;
        self.b.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.b.check(access)?;
        self.current()
    }
}
impl<B: ProjectionBoundary> CorpusIndexBoundary for Live<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != self.request.corpus() {
            return Err("projection corpus substitution".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        if root != self.request.corpus()
            || builder != &self.request.covariance.statistics.ingestion.builder
        {
            return Err("projection builder substitution".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, digest: &str) -> Result<()> {
        self.current()?;
        self.b.current_index_generation(root, digest)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: ProjectionBoundary> CorpusIndexJobBoundary for Live<'_, B> {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()> {
        if request != &self.request.covariance.statistics.ingestion
            || progress != &self.request.covariance.statistics.ingested
        {
            return Err("projection ingestion substitution".into());
        }
        self.current()
    }
    fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()> {
        self.current()?;
        self.b.verify_ingest_allocations(value)
    }
}
impl<B: ProjectionBoundary> StatisticsBoundary for Live<'_, B> {
    fn current_statistics(
        &mut self,
        request: &StatisticsRequest,
        progress: &StatisticsProgress,
    ) -> Result<()> {
        if request != &self.request.covariance.statistics
            || progress != &self.request.covariance.selected_statistics
        {
            return Err("projection document-frequency substitution".into());
        }
        self.current()
    }
    fn verify_statistics_allocations(
        &mut self,
        value: &super::super::statistics::StatisticsCommitment,
    ) -> Result<()> {
        self.current()?;
        self.b.verify_statistics_allocations(value)
    }
}
impl<B: ProjectionBoundary> CovarianceBoundary for Live<'_, B> {
    fn current_covariance(
        &mut self,
        request: &CovarianceRequest,
        progress: &CovarianceProgress,
    ) -> Result<()> {
        if request != &self.request.covariance || progress != &self.request.selected_covariance {
            return Err("projection covariance substitution".into());
        }
        self.current()
    }
    fn verify_covariance_allocations(&mut self, value: &CovarianceCommitment) -> Result<()> {
        self.current()?;
        self.b.verify_covariance_allocations(value)
    }
}

struct State {
    cursor: JacobiCursor,
    scale: f64,
    matrix: Vec<Vec<f64>>,
    vectors: Vec<Vec<f64>>,
    basis: Vec<Vec<f64>>,
}
fn state_size(n: usize, columns: usize) -> Result<usize> {
    if n > MAX_FEATURES || columns > MAX_DIMENSIONS || columns > n {
        return Err("projection binary dimensions exceed fixed bounds".into());
    }
    Ok(PROJECTION_HEADER.len() + 64 + 2 + 8 + 8 + 2 + (2 * n * n + n * columns) * 8)
}
fn validate_state(request: &ProjectionRequest, state: &State) -> Result<()> {
    let n = request.n()?;
    state.cursor.validate(n)?;
    if !state.scale.is_finite()
        || state.scale < 1.0
        || state.matrix.len() != n
        || state.vectors.len() != n
        || state
            .matrix
            .iter()
            .chain(&state.vectors)
            .any(|row| row.len() != n)
        || state
            .matrix
            .iter()
            .chain(&state.vectors)
            .flatten()
            .any(|value| !value.is_finite())
    {
        return Err("projection binary matrix/eigenvector shape or finite scale invalid".into());
    }
    for p in 0..n {
        for q in 0..p {
            if state.matrix[p][q].to_bits() != state.matrix[q][p].to_bits() {
                return Err("projection matrix lost exact symmetry".into());
            }
        }
    }
    let columns = state.basis.first().map_or(0, Vec::len);
    if !state.cursor.complete {
        if !state.basis.is_empty() {
            return Err("partial projection must not expose a basis".into());
        }
    } else if state.basis.len() != n
        || columns > usize::from(request.requested_dimensions)
        || columns > n
        || state.basis.iter().any(|row| row.len() != columns)
        || state.basis.iter().flatten().any(|value| !value.is_finite())
    {
        return Err("completed projection basis shape invalid".into());
    }
    Ok(())
}
fn encode(request: &ProjectionRequest, state: &State) -> Result<Vec<u8>> {
    validate_state(request, state)?;
    let n = request.n()?;
    let columns = state.basis.first().map_or(0, Vec::len);
    let mut bytes = Vec::with_capacity(state_size(n, columns)?);
    bytes.extend_from_slice(PROJECTION_HEADER);
    bytes.extend_from_slice(request.sha256()?.as_bytes());
    bytes.extend_from_slice(&(n as u16).to_le_bytes());
    bytes.push(state.cursor.sweep);
    bytes.extend_from_slice(&state.cursor.p.to_le_bytes());
    bytes.extend_from_slice(&state.cursor.q.to_le_bytes());
    bytes.extend_from_slice(&[
        u8::from(state.cursor.sweep_open),
        u8::from(state.cursor.changed),
        u8::from(state.cursor.complete),
    ]);
    bytes.extend_from_slice(&state.scale.to_bits().to_le_bytes());
    bytes.extend_from_slice(&(columns as u16).to_le_bytes());
    for matrix in [&state.matrix, &state.vectors, &state.basis] {
        for value in matrix.iter().flatten() {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    Ok(bytes)
}
fn decode(request: &ProjectionRequest, cursor: &JacobiCursor, bytes: &[u8]) -> Result<State> {
    let n = request.n()?;
    let mut at = PROJECTION_HEADER.len();
    if bytes.len() < state_size(n, 0)?
        || !bytes.starts_with(PROJECTION_HEADER)
        || &bytes[at..at + 64] != request.sha256()?.as_bytes()
    {
        return Err("projection binary request/length mismatch".into());
    }
    at += 64;
    if usize::from(u16::from_le_bytes(bytes[at..at + 2].try_into()?)) != n {
        return Err("projection binary feature dimension mismatch".into());
    }
    at += 2;
    if bytes[at + 5..at + 8].iter().any(|value| *value > 1) {
        return Err("noncanonical Jacobi boolean".into());
    }
    let actual = JacobiCursor {
        sweep: bytes[at],
        p: u16::from_le_bytes(bytes[at + 1..at + 3].try_into()?),
        q: u16::from_le_bytes(bytes[at + 3..at + 5].try_into()?),
        sweep_open: bytes[at + 5] == 1,
        changed: bytes[at + 6] == 1,
        complete: bytes[at + 7] == 1,
    };
    at += 8;
    let scale = f64::from_bits(u64::from_le_bytes(bytes[at..at + 8].try_into()?));
    at += 8;
    let columns = usize::from(u16::from_le_bytes(bytes[at..at + 2].try_into()?));
    at += 2;
    if actual != *cursor
        || bytes.len() != state_size(n, columns)?
        || columns > usize::from(request.requested_dimensions)
        || (!actual.complete && columns != 0)
    {
        return Err("projection binary cursor/basis mismatch".into());
    }
    let mut matrix = vec![vec![0.0; n]; n];
    let mut vectors = matrix.clone();
    let mut basis = if actual.complete {
        vec![vec![0.0; columns]; n]
    } else {
        Vec::new()
    };
    for target in [&mut matrix, &mut vectors, &mut basis] {
        for value in target.iter_mut().flatten() {
            *value = f64::from_bits(u64::from_le_bytes(bytes[at..at + 8].try_into()?));
            at += 8;
        }
    }
    let state = State {
        cursor: actual,
        scale,
        matrix,
        vectors,
        basis,
    };
    validate_state(request, &state)?;
    Ok(state)
}
fn add_work(
    total: &mut u64,
    amount: u64,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    *total = total.checked_add(amount).ok_or("Jacobi work overflow")?;
    if *total > limit {
        return Err("Jacobi window exceeds reviewed remaining work".into());
    }
    check()
}
fn finish(
    request: &ProjectionRequest,
    state: &mut State,
    work: &mut u64,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let n = state.matrix.len();
    add_work(work, (n * n) as u64, limit, check)?;
    if state
        .matrix
        .iter()
        .flatten()
        .chain(state.vectors.iter().flatten())
        .any(|v| !v.is_finite())
        || state
            .matrix
            .iter()
            .enumerate()
            .any(|(i, row)| row[i] < -1e-10 * state.scale)
    {
        return Err("bounded projection is nonfinite or not positive semidefinite".into());
    }
    let mut order: Vec<usize> = (0..n)
        .filter(|i| state.matrix[*i][*i] > 1e-10 * state.scale)
        .collect();
    order.sort_by(|a, b| {
        state.matrix[*b][*b]
            .total_cmp(&state.matrix[*a][*a])
            .then(a.cmp(b))
    });
    order.truncate(usize::from(request.requested_dimensions));
    state.basis = vec![vec![0.0; order.len()]; n];
    for (dimension, column) in order.into_iter().enumerate() {
        check()?;
        let pivot = (0..n)
            .max_by(|a, b| {
                state.vectors[*a][column]
                    .abs()
                    .total_cmp(&state.vectors[*b][column].abs())
                    .then(b.cmp(a))
            })
            .ok_or("projection pivot absent")?;
        let sign = if state.vectors[pivot][column] < 0.0 {
            -1.0
        } else {
            1.0
        };
        for i in 0..n {
            state.basis[i][dimension] = state.vectors[i][column] * sign;
        }
    }
    state.cursor = JacobiCursor {
        sweep: state.cursor.sweep,
        p: 0,
        q: 0,
        sweep_open: false,
        changed: false,
        complete: true,
    };
    check()
}
fn advance(
    request: &ProjectionRequest,
    state: &mut State,
    maximum: usize,
    work_limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<u64> {
    let n = request.n()?;
    let mut work = 0_u64;
    let tolerance = 1e-12 * state.scale / n.max(1) as f64;
    if n == 0 {
        finish(request, state, &mut work, work_limit, check)?;
        return Ok(work);
    }
    let mut visited = 0;
    loop {
        if !state.cursor.sweep_open {
            add_work(&mut work, (n * n) as u64, work_limit, check)?;
            state.cursor.sweep_open = true;
        }
        if n < 2 {
            finish(request, state, &mut work, work_limit, check)?;
            return Ok(work);
        }
        if visited == maximum {
            break;
        }
        check()?;
        let (p, q) = (usize::from(state.cursor.p), usize::from(state.cursor.q));
        let off = state.matrix[p][q];
        if off.abs() > tolerance {
            state.cursor.changed = true;
            add_work(&mut work, (8 * n + 32) as u64, work_limit, check)?;
            let angle = 0.5 * (2.0 * off).atan2(state.matrix[q][q] - state.matrix[p][p]);
            let (s, c) = angle.sin_cos();
            let (a, d) = (state.matrix[p][p], state.matrix[q][q]);
            state.matrix[p][p] = c * c * a - 2.0 * s * c * off + s * s * d;
            state.matrix[q][q] = s * s * a + 2.0 * s * c * off + c * c * d;
            state.matrix[p][q] = 0.0;
            state.matrix[q][p] = 0.0;
            for i in 0..n {
                if i != p && i != q {
                    let (x, y) = (state.matrix[i][p], state.matrix[i][q]);
                    state.matrix[i][p] = c * x - s * y;
                    state.matrix[p][i] = state.matrix[i][p];
                    state.matrix[i][q] = s * x + c * y;
                    state.matrix[q][i] = state.matrix[i][q];
                }
                let (x, y) = (state.vectors[i][p], state.vectors[i][q]);
                state.vectors[i][p] = c * x - s * y;
                state.vectors[i][q] = s * x + c * y;
            }
        }
        visited += 1;
        if q + 1 < n {
            state.cursor.q += 1;
        } else if p + 2 < n {
            state.cursor.p += 1;
            state.cursor.q = state.cursor.p + 1;
        } else {
            if !state.cursor.changed {
                finish(request, state, &mut work, work_limit, check)?;
                return Ok(work);
            }
            state.cursor.sweep += 1;
            if state.cursor.sweep == 64 {
                return Err("bounded corpus feature eigensolver did not converge".into());
            }
            state.cursor.p = 0;
            state.cursor.q = 1;
            state.cursor.sweep_open = false;
            state.cursor.changed = false;
            if visited == maximum {
                break;
            }
        }
    }
    check()?;
    Ok(work)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReview {
    pub schema_version: u32,
    pub request_sha256: String,
    pub base_sha256: String,
    pub cursor: JacobiCursor,
    pub state_sha256: String,
    pub state_bytes: u64,
    pub maximum_pair_visits: u16,
    pub window_read_bytes: u64,
    pub window_write_bytes: u64,
    pub read_charge: u64,
    pub write_charge: u64,
    pub work_charge: u64,
}
impl ProjectionReview {
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            PROJECTION_DOMAIN,
            self,
        ))?))
    }
}
pub struct ProjectionPlan {
    request: ProjectionRequest,
    base: ProjectionProgress,
    review: ProjectionReview,
    bytes: Vec<u8>,
}
impl ProjectionPlan {
    pub fn review(&self) -> &ProjectionReview {
        &self.review
    }
    pub fn planned_objects(
        &self,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<crate::v2::ObjectWriteSpec>> {
        let plan = crate::v2::BlobObjectPlan::data(
            &self.request.covariance.statistics.ingestion.corpus.binding,
            &self.bytes,
            &mut check,
        )?;
        if plan.reference().sha256 != self.review.state_sha256
            || plan.reference().bytes != self.review.state_bytes
        {
            return Err("projection blob plan differs from actual reviewed binary state".into());
        }
        plan.write_set(check)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCommitment {
    pub request: ProjectionRequest,
    pub base: ProjectionProgress,
    pub next: ProjectionProgress,
    pub review: ProjectionReview,
}
impl ProjectionCommitment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.base.canonical_bytes(&self.request)?;
        self.next.canonical_bytes(&self.request)?;
        let r = &self.review;
        hash(&r.state_sha256)?;
        if r.schema_version != 1
            || self.base.cursor.complete
            || r.request_sha256 != self.request.sha256()?
            || r.base_sha256 != luma_content::sha256(&self.base.canonical_bytes(&self.request)?)
            || r.cursor != self.next.cursor
            || r.maximum_pair_visits == 0
            || usize::from(r.maximum_pair_visits) > MAX_PAIR_VISITS
            || r.window_read_bytes == 0
            || r.window_read_bytes > MAX_PROJECTION_READ
            || r.window_write_bytes > MAX_PROJECTION_WRITE
            || r.read_charge > r.window_read_bytes
            || r.write_charge > r.window_write_bytes
            || self.next.state.as_ref().map(|s| (&s.sha256, s.bytes))
                != Some((&r.state_sha256, r.state_bytes))
            || self.next.totals
                != self.base.totals.plus(&IngestTotals {
                    read_bytes: r.read_charge,
                    write_bytes: r.write_charge,
                    source_bytes: 0,
                    postings: 0,
                    work: r.work_charge,
                })?
        {
            return Err("projection commitment differs from reviewed exact transition".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 512 * 1024 {
            return Err("projection commitment exceeds bounded envelope".into());
        }
        Ok(bytes)
    }
}

pub fn plan_projection_window<B: ProjectionBoundary>(
    store: &dyn IndexReadStore,
    request: &ProjectionRequest,
    base: &ProjectionProgress,
    maximum_pair_visits: usize,
    window_read_bytes: u64,
    window_write_bytes: u64,
    b: &mut B,
) -> Result<ProjectionPlan> {
    base.canonical_bytes(request)?;
    if base.cursor.complete
        || maximum_pair_visits == 0
        || maximum_pair_visits > MAX_PAIR_VISITS
        || window_read_bytes == 0
        || window_read_bytes > MAX_PROJECTION_READ
        || window_write_bytes == 0
        || window_write_bytes > MAX_PROJECTION_WRITE
    {
        return Err("projection requires an unfinished exact phase and finite window".into());
    }
    let limits = request.covariance.statistics.ingestion.limits;
    if window_read_bytes > limits.read_bytes - base.totals.read_bytes
        || window_write_bytes > limits.write_bytes - base.totals.write_bytes
    {
        return Err("projection window exceeds remaining cumulative I/O".into());
    }
    let mut live = Live {
        request,
        progress: base,
        b,
    };
    live.current()?;
    live.admit(
        &request.corpus().binding,
        ResourceBudget {
            memory_bytes: 192 * 1024 * 1024,
            tasks: 1,
            read_bytes: window_read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    let n = request.n()?;
    let input_bytes = base
        .state
        .as_ref()
        .map(|r| r.bytes)
        .or_else(|| request.selected_covariance.matrix.as_ref().map(|r| r.bytes))
        .unwrap_or(0);
    let input_credit = if input_bytes == 0 {
        0
    } else {
        blob_read_credit(input_bytes)?
    };
    let max_state = state_size(n, usize::from(request.requested_dimensions).min(n))?;
    let write_reserve = object_count(max_state)?
        .checked_mul(PAGE_WRITE)
        .ok_or("projection write reserve overflow")?;
    let read_reserve = input_credit
        .checked_mul(2)
        .and_then(|v| v.checked_add(object_count(max_state).ok()? * RUN_PAGE_READ * 2))
        .and_then(|v| v.checked_add(blob_read_credit(max_state as u64).ok()?))
        .ok_or("projection read reserve overflow")?;
    if read_reserve > window_read_bytes || write_reserve > window_write_bytes {
        return Err("projection window cannot reserve actual state/replay/readback bounds".into());
    }
    let work_limit = (limits.floating_operations - base.totals.work) / 2;
    let mut initialization_work = 0;
    let mut state = if let Some(reference) = &base.state {
        let bytes = store.read_blob(
            reference,
            IoBudget {
                read_bytes: input_credit,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        decode(request, &base.cursor, &bytes)?
    } else {
        let matrix = read_covariance_matrix(
            store,
            &request.covariance,
            &request.selected_covariance,
            IoBudget {
                read_bytes: input_credit.max(1),
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        add_work(
            &mut initialization_work,
            (n * n) as u64,
            work_limit,
            &mut || live.current(),
        )?;
        let scale = matrix
            .iter()
            .enumerate()
            .map(|(i, row)| row[i])
            .sum::<f64>()
            .max(1.0);
        if !scale.is_finite() {
            return Err("covariance trace overflow".into());
        }
        let mut vectors = vec![vec![0.0; n]; n];
        for (i, row) in vectors.iter_mut().enumerate() {
            row[i] = 1.0;
        }
        State {
            cursor: base.cursor.clone(),
            scale,
            matrix,
            vectors,
            basis: Vec::new(),
        }
    };
    let work = advance(
        request,
        &mut state,
        maximum_pair_visits,
        work_limit - initialization_work,
        &mut || live.current(),
    )?
    .checked_add(initialization_work)
    .and_then(|v| v.checked_mul(2))
    .ok_or("projection replay work overflow")?;
    let bytes = encode(request, &state)?;
    let write_charge = object_count(bytes.len())? * PAGE_WRITE;
    let review = ProjectionReview {
        schema_version: 1,
        request_sha256: request.sha256()?,
        base_sha256: luma_content::sha256(&base.canonical_bytes(request)?),
        cursor: state.cursor,
        state_sha256: luma_content::sha256(&bytes),
        state_bytes: bytes.len() as u64,
        maximum_pair_visits: maximum_pair_visits as u16,
        window_read_bytes,
        window_write_bytes,
        read_charge: read_reserve,
        write_charge,
        work_charge: work,
    };
    base.totals
        .plus(&IngestTotals {
            read_bytes: read_reserve,
            write_bytes: write_charge,
            source_bytes: 0,
            postings: 0,
            work,
        })?
        .validate(&limits)?;
    live.current()?;
    Ok(ProjectionPlan {
        request: request.clone(),
        base: base.clone(),
        review,
        bytes,
    })
}
pub struct PreparedProjection {
    value: ProjectionCommitment,
}
impl PreparedProjection {
    pub fn commitment(&self) -> &ProjectionCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: ProjectionBoundary>(&self, b: &mut B) -> Result<()> {
        Live {
            request: &self.value.request,
            progress: &self.value.next,
            b,
        }
        .current()
    }
}
pub fn prepare_projection<B: ProjectionBoundary>(
    store: &ObjectStore,
    plan: &ProjectionPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedProjection> {
    if mutation.review_sha256 != plan.review.sha256()?
        || mutation.source_bytes != 0
        || mutation.decision != crate::DecisionKind::Published
    {
        return Err("projection mutation differs from exact reviewed state".into());
    }
    let mut live = Live {
        request: &plan.request,
        progress: &plan.base,
        b,
    };
    live.current()?;
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
    if reference.sha256 != plan.review.state_sha256 || reference.bytes != plan.review.state_bytes {
        return Err("projection writer changed actual reviewed state bytes".into());
    }
    let value = ProjectionCommitment {
        request: plan.request.clone(),
        base: plan.base.clone(),
        next: ProjectionProgress {
            schema_version: 1,
            request_sha256: plan.request.sha256()?,
            cursor: plan.review.cursor.clone(),
            state: Some(reference),
            totals: plan.base.totals.plus(&IngestTotals {
                read_bytes: plan.review.read_charge,
                write_bytes: plan.review.write_charge,
                source_bytes: 0,
                postings: 0,
                work: plan.review.work_charge,
            })?,
        },
        review: plan.review.clone(),
    };
    value.canonical_bytes()?;
    live.current()?;
    b.verify_projection_allocations(&value)?;
    b.check(Access::Mutate {
        binding: &plan.request.corpus().binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: 0,
        storage_bytes: plan.review.write_charge,
    })?;
    Live {
        request: &plan.request,
        progress: &plan.base,
        b,
    }
    .current()?;
    Ok(PreparedProjection { value })
}
pub fn verify_projection_data<B: ProjectionBoundary>(
    store: &dyn IndexReadStore,
    value: &ProjectionCommitment,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let rebuilt = plan_projection_window(
        store,
        &value.request,
        &value.base,
        usize::from(value.review.maximum_pair_visits),
        value.review.window_read_bytes,
        value.review.window_write_bytes,
        b,
    )?;
    if rebuilt.review != value.review {
        return Err("projection candidate differs from exact independent Jacobi replay".into());
    }
    let reference = value
        .next
        .state
        .as_ref()
        .ok_or("projection candidate has no actual state")?;
    let mut live = Live {
        request: &value.request,
        progress: &value.base,
        b,
    };
    let bytes = store.read_blob(
        reference,
        IoBudget {
            read_bytes: blob_read_credit(reference.bytes)?,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    if bytes != rebuilt.bytes {
        return Err(
            "projection candidate binary differs from independently rebuilt matrix/basis".into(),
        );
    }
    decode(&value.request, &value.next.cursor, &bytes)?;
    live.current()?;
    b.verify_projection_allocations(value)?;
    Live {
        request: &value.request,
        progress: &value.base,
        b,
    }
    .current()
}
pub fn read_projection_basis<B: ProjectionBoundary>(
    store: &dyn IndexReadStore,
    request: &ProjectionRequest,
    selected: &ProjectionProgress,
    budget: IoBudget,
    b: &mut B,
) -> Result<Vec<Vec<f64>>> {
    selected.canonical_bytes(request)?;
    budget.validate()?;
    if !selected.cursor.complete || budget.write_bytes != 0 || budget.new_files != 0 {
        return Err(
            "basis read requires actual complete selected projection and read-only budget".into(),
        );
    }
    let mut live = Live {
        request,
        progress: selected,
        b,
    };
    live.current()?;
    let reference = selected
        .state
        .as_ref()
        .ok_or("selected projection has no actual basis state")?;
    let bytes = store.read_blob(reference, budget, &mut live)?;
    let state = decode(request, &selected.cursor, &bytes)?;
    live.current()?;
    Ok(state.basis)
}

#[cfg(test)]
mod tests;
