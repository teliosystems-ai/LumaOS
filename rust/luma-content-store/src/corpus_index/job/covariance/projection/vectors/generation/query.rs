//! Fast selected-generation reads. Every operation refreshes real current C,
//! builder, original Read resources and final current source/lifecycle checks.
use super::*;
use crate::corpus_index::job::statistics::selected::SelectedPostingReader;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

struct Current<'a, B: CurrentGenerationBoundary> {
    manifest: &'a GenerationManifest,
    b: &'a mut B,
}
impl<B: CurrentGenerationBoundary> Current<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.b.check(Access::Inspect {
            binding: &self.manifest.corpus.binding,
        })?;
        self.b.current_generation(self.manifest)?;
        self.b
            .current_index_generation(&self.manifest.corpus, &self.manifest.sha256()?)?;
        self.b.current_corpus(&self.manifest.corpus)?;
        self.b
            .current_builder(&self.manifest.corpus, &self.manifest.builder)
    }
}
impl<B: CurrentGenerationBoundary> Boundary for Current<'_, B> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        if binding != &self.manifest.corpus.binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("generation query cannot allocate files or substitute owner".into());
        }
        self.current()?;
        self.b.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        if !matches!(access, Access::Inspect { .. }) {
            return Err("selected generation query is read-only".into());
        }
        self.b.check(access)?;
        self.current()
    }
}
impl<B: CurrentGenerationBoundary> CorpusIndexBoundary for Current<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.manifest.corpus {
            return Err("query corpus substitution".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        if root != &self.manifest.corpus || builder != &self.manifest.builder {
            return Err("query builder substitution".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, generation: &str) -> Result<()> {
        if root != &self.manifest.corpus || generation != self.manifest.sha256()? {
            return Err("query generation substitution".into());
        }
        self.current()
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}

/// Parsed immutable DATA only. Query reopens and hashes job/model before using
/// it; cached parsed bytes are neither authorization nor filesystem immutability.
pub struct VerifiedGeneration {
    manifest: GenerationManifest,
    job: GenerationJob,
    model: GenerationModel,
}
impl VerifiedGeneration {
    pub fn open<B: CurrentGenerationBoundary>(
        store: &dyn IndexReadStore,
        manifest_bytes: &[u8],
        selected_sha256: &str,
        limits: CorpusIndexLimits,
        b: &mut B,
    ) -> Result<Self> {
        let manifest: GenerationManifest = crate::corpus_index::decode(manifest_bytes, 16 * 1024)?;
        manifest.canonical_bytes()?;
        if manifest.sha256()? != selected_sha256 {
            return Err(
                "supplied descriptor differs from actual current generation selector".into(),
            );
        }
        let mut live = Current {
            manifest: &manifest,
            b,
        };
        live.current()?;
        if limits.write_bytes != 0 {
            return Err("generation opening requires read-only resources".into());
        }
        let mut meter = Meter::new(
            &manifest.corpus,
            &manifest.builder,
            limits,
            Some(selected_sha256.into()),
            &mut live,
        )?;
        let (job, model) = read_inputs(store, &manifest, &mut meter, &mut live)?;
        live.current()?;
        Ok(Self {
            manifest,
            job,
            model,
        })
    }
    pub fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }
    pub fn query<B: CurrentGenerationBoundary>(
        &self,
        store: &dyn IndexReadStore,
        kind: crate::corpus_index::CorpusQueryKind,
        query: &str,
        limit: usize,
        limits: CorpusIndexLimits,
        b: &mut B,
    ) -> Result<crate::corpus_index::CorpusQueryResults> {
        let canonical = crate::canonical_search_query(query, limit)?;
        if limits.write_bytes != 0 {
            return Err("generation query requires finite read-only resources".into());
        }
        let mut live = Current {
            manifest: &self.manifest,
            b,
        };
        live.current()?;
        let root = &self.manifest.corpus;
        let mut meter = Meter::new(
            root,
            &self.manifest.builder,
            limits,
            Some(self.manifest.sha256()?),
            &mut live,
        )?;
        let (job, model) = read_inputs(store, &self.manifest, &mut meter, &mut live)?;
        if job != self.job || model != self.model {
            return Err("current actual job/model changed from parsed immutable DATA".into());
        }
        let mut top = Top::new(limit, root.entry_count)?;
        match kind {
            crate::corpus_index::CorpusQueryKind::LexicalAnd => {
                lexical(store, &job, &canonical, &mut top, &mut meter, &mut live)?
            }
            crate::corpus_index::CorpusQueryKind::FeatureLsa => semantic(
                store, &job, &model, &canonical, &mut top, &mut meter, &mut live,
            )?,
        }
        meter.work(top.heap.len() as u64 * 16, root, &mut live)?;
        let (total_matches, ranked) = top.finish();
        let mut records = Vec::new();
        let mut matches = Vec::new();
        for Ranked { ordinal, score } in ranked {
            let credit = 9 * RUN_PAGE_READ;
            meter.read(credit)?;
            let mut proof = super::super::read::read_record_window_data(
                store,
                &job.request,
                &job.progress,
                ordinal,
                1,
                IoBudget {
                    read_bytes: credit,
                    write_bytes: 0,
                    new_files: 0,
                },
                &mut live,
            )?;
            let row = proof
                .rows
                .pop()
                .ok_or("query result proof omits exact selected ordinal")?;
            current_record(store, root, &row.record, &mut meter, &mut live)?;
            matches.push(crate::corpus_index::CorpusHit {
                reference: row.record.reference.clone(),
                format: row.record.format,
                score,
            });
            records.push(row.record);
        }
        // A refusal withholds the entire result, including counts. No current
        // ACL observation is cached across candidates or output completion.
        for record in &records {
            current_record(store, root, record, &mut meter, &mut live)?;
        }
        live.current()?;
        let result = crate::corpus_index::CorpusQueryResults {
            schema_version: 1,
            profile: GENERATION_PROFILE.into(),
            kind,
            canonical_query: canonical,
            corpus_sha256: root.sha256()?,
            index_sha256: self.manifest.sha256()?,
            matches,
            total_matches,
            truncated: total_matches > limit as u64,
        };
        if serde_json::to_vec(&result)?.len() > crate::MAX_SEARCH_RESPONSE_BYTES {
            return Err("generation result exceeds exact bounded response".into());
        }
        live.current()?;
        Ok(result)
    }
}
fn read_inputs<B: CurrentGenerationBoundary>(
    store: &dyn IndexReadStore,
    manifest: &GenerationManifest,
    meter: &mut Meter,
    live: &mut Current<'_, B>,
) -> Result<(GenerationJob, GenerationModel)> {
    let job_credit = blob_read_credit(manifest.job.bytes)?;
    meter.read(job_credit)?;
    let job_bytes = store.read_blob(
        &manifest.job,
        IoBudget {
            read_bytes: job_credit,
            write_bytes: 0,
            new_files: 0,
        },
        live,
    )?;
    let job: GenerationJob = crate::corpus_index::decode(&job_bytes, MAX_JOB_BYTES)?;
    manifest.check_job(&job)?;
    let model_credit = blob_read_credit(manifest.model.bytes)?;
    meter.read(model_credit)?;
    let model_bytes = store.read_blob(
        &manifest.model,
        IoBudget {
            read_bytes: model_credit,
            write_bytes: 0,
            new_files: 0,
        },
        live,
    )?;
    let model: GenerationModel = crate::corpus_index::decode(&model_bytes, 256 * 1024)?;
    model.canonical_bytes(&job)?;
    meter.work(
        model.features.len() as u64 * u64::from(manifest.dimensions).pow(2),
        &manifest.corpus,
        live,
    )?;
    live.current()?;
    Ok((job, model))
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Ranked {
    ordinal: u32,
    score: i64,
}
impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| other.ordinal.cmp(&self.ordinal))
    }
}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
struct Top {
    maximum: u64,
    limit: usize,
    total: u64,
    heap: BinaryHeap<Reverse<Ranked>>,
}
impl Top {
    fn new(limit: usize, maximum: u64) -> Result<Self> {
        if limit == 0 || limit > crate::MAX_SEARCH_RESULTS || maximum > MAX_CORPUS_OBJECTS {
            return Err("generation topK exceeds bounded profile".into());
        }
        Ok(Self {
            maximum,
            limit,
            total: 0,
            heap: BinaryHeap::with_capacity(limit),
        })
    }
    fn offer(&mut self, ordinal: u32, score: i64) -> Result<()> {
        if u64::from(ordinal) >= self.maximum || score <= 0 || self.total >= self.maximum {
            return Err("generation rank result exceeds exact positive ordinal coverage".into());
        }
        self.total += 1;
        let row = Ranked { ordinal, score };
        if self.heap.len() < self.limit {
            self.heap.push(Reverse(row));
        } else if let Some(mut worst) = self.heap.peek_mut() {
            if row > worst.0 {
                *worst = Reverse(row);
            }
        }
        Ok(())
    }
    fn finish(mut self) -> (u64, Vec<Ranked>) {
        let mut rows = Vec::with_capacity(self.heap.len());
        while let Some(Reverse(row)) = self.heap.pop() {
            rows.push(row);
        }
        rows.reverse();
        (self.total, rows)
    }
}
fn lexical<B: CurrentGenerationBoundary>(
    store: &dyn IndexReadStore,
    job: &GenerationJob,
    query: &str,
    top: &mut Top,
    meter: &mut Meter,
    live: &mut Current<'_, B>,
) -> Result<()> {
    let root = job.corpus();
    let terms: Vec<_> = query.split(' ').collect();
    let mut counts = vec![(0_u8, 0_u64); root.entry_count as usize];
    let (request, statistics) = job.statistics();
    let credit = meter
        .limits
        .read_bytes
        .checked_sub(meter.read)
        .ok_or("query read allowance exhausted")?
        .min(512 * 1024 * 1024);
    let mut reader = SelectedPostingReader::open(store, request, statistics, credit, live)?;
    for (index, term) in terms.iter().enumerate() {
        let mut after = reader.lower_bound(term, 0)?;
        let end = reader.lower_bound(term, u32::MAX)?;
        while after < end {
            let count = (end - after).min(4096) as usize;
            let rows = reader.range(after, count)?;
            if rows.len() != count {
                return Err("lexical exact term range lost coverage".into());
            }
            for (i, entry) in rows.iter().enumerate() {
                if i % 128 == 0 {
                    reader.with_boundary_checked(|b| meter.work(128, root, b))?;
                }
                if entry.term != *term {
                    return Err("lexical bound crosses another term/bucket".into());
                }
                let row = counts
                    .get_mut(entry.document as usize)
                    .ok_or("lexical document outside exact corpus")?;
                let bit = 1_u8 << index;
                if row.0 & bit != 0 {
                    return Err("lexical selected postings duplicate a query term/document".into());
                }
                row.0 |= bit;
                row.1 = row
                    .1
                    .checked_add(u64::from(entry.frequency))
                    .ok_or("lexical score overflow")?;
            }
            after += rows.len() as u64;
        }
    }
    let read = reader.read_bytes();
    drop(reader);
    meter.read(read)?;
    let all = ((1_u16 << terms.len()) - 1) as u8;
    for (ordinal, (mask, score)) in counts.into_iter().enumerate() {
        meter.work(1, root, live)?;
        if mask == all {
            meter.work(16, root, live)?;
            top.offer(ordinal as u32, i64::try_from(score)?)?;
        }
    }
    Ok(())
}
fn semantic<B: CurrentGenerationBoundary>(
    store: &dyn IndexReadStore,
    job: &GenerationJob,
    model: &GenerationModel,
    query: &str,
    top: &mut Top,
    meter: &mut Meter,
    live: &mut Current<'_, B>,
) -> Result<()> {
    let root = job.corpus();
    let features: Vec<_> = model
        .features
        .iter()
        .map(|f| (f.term.clone(), f.documents))
        .collect();
    let idfs: Vec<_> = model
        .features
        .iter()
        .map(|f| f64::from_bits(f.idf_bits))
        .collect();
    let basis: Vec<Vec<_>> = model
        .features
        .iter()
        .map(|f| {
            f.projection_bits
                .iter()
                .map(|bits| f64::from_bits(*bits))
                .collect()
        })
        .collect();
    let tf = words(query.as_bytes(), root, meter, live)?;
    let weights = crate::corpus_index::build::weights(&tf, &features, &idfs)?;
    let dimensions = usize::from(
        job.progress
            .dimensions
            .ok_or("selected vector dimensions absent")?,
    );
    let latent = crate::corpus_index::build::project(&weights, &basis, dimensions)?;
    if latent.iter().all(|value| *value == 0.0) {
        live.current()?;
        return Ok(());
    }
    let credit = meter
        .limits
        .read_bytes
        .checked_sub(meter.read)
        .ok_or("semantic read allowance exhausted")?
        .min(512 * 1024 * 1024);
    let scan = coordinates::visit_coordinate_blocks_checked(
        store,
        &job.request,
        &job.progress,
        IoBudget {
            read_bytes: credit,
            write_bytes: 0,
            new_files: 0,
        },
        live,
        |first, rows, live| {
            for (i, row) in rows.iter().enumerate() {
                meter.work(row.len() as u64, root, live)?;
                let cosine: f64 = row
                    .iter()
                    .zip(&latent)
                    .map(|(bits, q)| f64::from(f32::from_bits(*bits)) * q)
                    .sum();
                if !cosine.is_finite() {
                    return Err("semantic cosine is not finite".into());
                }
                let score = (cosine.clamp(-1.0, 1.0) * 1_000_000.0).round() as i64;
                if score > 0 {
                    meter.work(16, root, live)?;
                    top.offer(first + i as u32, score)?;
                }
            }
            live.current()
        },
    )?;
    meter.read(scan.read_bytes)?;
    Ok(())
}
fn current_record<B: CurrentGenerationBoundary>(
    store: &dyn IndexReadStore,
    root: &MapRoot,
    record: &CorpusRecord,
    meter: &mut Meter,
    live: &mut Current<'_, B>,
) -> Result<()> {
    let credit = 9 * RUN_PAGE_READ;
    meter.read(credit)?;
    let key = root.corpus_key(&record.reference.artifact_id)?;
    let proof = store.lookup_map(
        root,
        &key,
        IoBudget {
            read_bytes: credit,
            write_bytes: 0,
            new_files: 0,
        },
        live,
    )?;
    let bytes = proof
        .verify(root)?
        .ok_or("selected result is absent from actual current corpus")?;
    if CorpusRecord::parse(&bytes, root, &key)? != *record {
        return Err("selected result current version/lifecycle/format changed".into());
    }
    live.current_candidate(root, record)?;
    live.current()
}
