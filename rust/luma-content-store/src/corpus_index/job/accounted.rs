//! Opt-in actual page debits. The full original page ceiling is durably held
//! before writing; measured DATA cannot create that hold or release it. Native
//! publishers must independently implement every callback against live custody,
//! the original worker/resource generation and real allocation observations.
use super::*;
use crate::v2::PageWriteMeasurement;
use std::cell::Cell;

const ACCOUNTING_DOMAIN: &str = "luma-corpus-measured-pages-v1";
const MAX_ACCOUNTING_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservedPage {
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageReserve {
    pub schema_version: u32,
    pub domain: String,
    pub binding: luma_content::OwnerBinding,
    pub request_sha256: String,
    pub base_sha256: String,
    pub semantic_sha256: String,
    pub source_bytes: u64,
    pub maximum_storage_bytes: u64,
    pub pages: Vec<ReservedPage>,
    pub review_sha256: String,
}
impl PageReserve {
    fn review(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            self.schema_version,
            &self.domain,
            &self.binding,
            &self.request_sha256,
            &self.base_sha256,
            &self.semantic_sha256,
            self.source_bytes,
            self.maximum_storage_bytes,
            &self.pages,
        ))?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.binding.validate()?;
        for digest in [
            &self.request_sha256,
            &self.base_sha256,
            &self.semantic_sha256,
        ] {
            hash(digest)?;
        }
        if self.schema_version != 1
            || self.domain != ACCOUNTING_DOMAIN
            || self.pages.len() > MAX_RUN_PAGES
            || self.source_bytes > crate::v2::MAX_SEGMENT_BYTES
            || self.maximum_storage_bytes != self.pages.len() as u64 * PAGE_WRITE
            || self.review_sha256 != self.review()?
        {
            return Err("measured reserve substitutes exact original page ceiling".into());
        }
        for page in &self.pages {
            hash(&page.sha256)?;
            if page.bytes == 0 || page.bytes > MAX_INDEX_PAGE_BYTES as u64 {
                return Err("measured reserve has an invalid bounded page".into());
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_ACCOUNTING_BYTES {
            return Err("measured reserve exceeds closed envelope".into());
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageDebit {
    pub sha256: String,
    pub read_bytes: u64,
    pub logical_written_bytes: u64,
    pub regular_files: u64,
    pub directories: u64,
    pub logical_allocated_bytes: u64,
    pub allocated_bytes: u64,
}
impl PageDebit {
    fn observed(value: &PageWriteMeasurement, expected: &ReservedPage) -> Result<Self> {
        let allocation = &value.allocation;
        let result = Self {
            sha256: value.sha256.clone(),
            read_bytes: value.read_bytes,
            logical_written_bytes: value.logical_written_bytes,
            regular_files: allocation.regular_files,
            directories: allocation.directories,
            logical_allocated_bytes: allocation.logical_bytes,
            allocated_bytes: allocation.allocated_bytes,
        };
        if allocation.incomplete_objects != 0 {
            return Err(
                "incomplete measured page remains charged and requires reconciliation".into(),
            );
        }
        result.validate(expected)?;
        Ok(result)
    }
    fn validate(&self, expected: &ReservedPage) -> Result<()> {
        hash(&self.sha256)?;
        if self.sha256 != expected.sha256
            || self.read_bytes > RUN_PAGE_READ
            || self.logical_written_bytes > expected.bytes
            || self.regular_files > 1
            || self.directories > 2
            || self.logical_allocated_bytes > expected.bytes
            || self.charge()? > PAGE_WRITE
            || (self.regular_files == 1
                && (self.logical_written_bytes != expected.bytes
                    || self.logical_allocated_bytes != expected.bytes))
            || (self.regular_files == 0
                && (self.logical_written_bytes != 0 || self.logical_allocated_bytes != 0))
        {
            return Err("actual page debit exceeds or substitutes its original finite hold".into());
        }
        Ok(())
    }
    pub fn charge(&self) -> Result<u64> {
        self.logical_written_bytes
            .checked_add(self.allocated_bytes)
            .ok_or_else(|| "measured logical/allocation debit overflow".into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageDebitCommitment {
    pub reserve: PageReserve,
    pub pages: Vec<PageDebit>,
    pub actual_storage_bytes: u64,
}
impl PageDebitCommitment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.reserve.canonical_bytes()?;
        if self.pages.len() != self.reserve.pages.len() {
            return Err("measured page coverage differs from original reservation".into());
        }
        let mut charged = 0_u64;
        for (actual, expected) in self.pages.iter().zip(&self.reserve.pages) {
            actual.validate(expected)?;
            charged = charged
                .checked_add(actual.charge()?)
                .ok_or("measured debit overflow")?;
        }
        if charged != self.actual_storage_bytes || charged > self.reserve.maximum_storage_bytes {
            return Err("measured total differs from exact actual page debits".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_ACCOUNTING_BYTES {
            return Err("measured debit exceeds closed envelope".into());
        }
        Ok(bytes)
    }
}

/// Constructed only by the actual measured writer below. This local Rust value
/// is not a kernel/TPM witness; an installed callback must bind it to its own
/// independently observed original worker, retained allocation and C context.
pub struct CapturedPageMeasurements {
    reserve_sha256: String,
    pages: Vec<PageDebit>,
}
impl CapturedPageMeasurements {
    pub fn reserve_sha256(&self) -> &str {
        &self.reserve_sha256
    }
    pub fn pages(&self) -> &[PageDebit] {
        &self.pages
    }
}

/// There are no default-success methods. `reserve_pages` must durably retain
/// the entire ceiling before the first write and on every subsequent refusal,
/// process loss or unacknowledged publication. Zero-debit page reuse requires
/// proof that the existing physical bytes were already charged to this owner.
pub trait PageAccountingBoundary: Boundary {
    fn reserve_pages(&mut self, reserve: &PageReserve) -> Result<()>;
    fn observe_pages(
        &mut self,
        value: &PageDebitCommitment,
        captured: &CapturedPageMeasurements,
    ) -> Result<()>;
    fn verify_pages(&mut self, value: &PageDebitCommitment) -> Result<()>;
    fn release_pages_after_selection(&mut self, value: &PageDebitCommitment) -> Result<()>;
}

pub(super) fn reserve(
    binding: &luma_content::OwnerBinding,
    request: String,
    base: &[u8],
    semantic: &[u8],
    source_bytes: u64,
    pages: &[(String, Vec<u8>)],
) -> Result<PageReserve> {
    let mut value = PageReserve {
        schema_version: 1,
        domain: ACCOUNTING_DOMAIN.into(),
        binding: binding.clone(),
        request_sha256: request,
        base_sha256: luma_content::sha256(base),
        semantic_sha256: luma_content::sha256(semantic),
        source_bytes,
        maximum_storage_bytes: pages.len() as u64 * PAGE_WRITE,
        pages: pages
            .iter()
            .map(|(sha256, bytes)| ReservedPage {
                sha256: sha256.clone(),
                bytes: bytes.len() as u64,
            })
            .collect(),
        review_sha256: String::new(),
    };
    value.review_sha256 = value.review()?;
    value.canonical_bytes()?;
    Ok(value)
}

pub(super) fn measure(
    store: &ObjectStore,
    reserve: &PageReserve,
    pages: &[(String, Vec<u8>)],
    mutation: &Mutation,
    live: &mut impl Boundary,
) -> Result<(PageDebitCommitment, CapturedPageMeasurements)> {
    reserve.canonical_bytes()?;
    if mutation.review_sha256 != reserve.review_sha256
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != reserve.source_bytes
        || pages.len() != reserve.pages.len()
    {
        return Err("measured mutation differs from original exact reviewed reserve".into());
    }
    let mut debits = Vec::new();
    let mut actual_storage_bytes = 0_u64;
    for ((sha256, bytes), expected) in pages.iter().zip(&reserve.pages) {
        if sha256 != &expected.sha256
            || bytes.len() as u64 != expected.bytes
            || luma_content::sha256(bytes) != *sha256
        {
            return Err("measured writer substituted planned page bytes".into());
        }
        let actual = store.prepare_page_measured(
            bytes,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: PAGE_WRITE,
                new_files: 3,
            },
            mutation,
            PAGE_WRITE,
            live,
        )?;
        let debit = PageDebit::observed(&actual, expected)?;
        actual_storage_bytes = actual_storage_bytes
            .checked_add(debit.charge()?)
            .ok_or("measured writer debit overflow")?;
        debits.push(debit);
    }
    let value = PageDebitCommitment {
        reserve: reserve.clone(),
        pages: debits,
        actual_storage_bytes,
    };
    value.canonical_bytes()?;
    let captured = CapturedPageMeasurements {
        reserve_sha256: luma_content::sha256(&reserve.canonical_bytes()?),
        pages: value.pages.clone(),
    };
    Ok((value, captured))
}

pub(super) fn mutation_check(b: &mut impl Boundary, reserve: &PageReserve) -> Result<()> {
    b.check(Access::Mutate {
        binding: &reserve.binding,
        review_sha256: &reserve.review_sha256,
        decision: crate::DecisionKind::Published,
        source_bytes: reserve.source_bytes,
        storage_bytes: reserve.maximum_storage_bytes,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountedIngestCommitment {
    pub semantic: IngestCommitment,
    pub next: IngestProgress,
    pub accounting: PageDebitCommitment,
}
impl AccountedIngestCommitment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.semantic.canonical_bytes()?;
        self.accounting.canonical_bytes()?;
        let mut expected = self.semantic.next.clone();
        expected.totals.write_bytes = self
            .semantic
            .base
            .totals
            .write_bytes
            .checked_add(self.accounting.actual_storage_bytes)
            .ok_or("actual total overflow")?;
        self.next.validate(&self.semantic.request)?;
        let r = &self.accounting.reserve;
        if self.next != expected
            || r.binding != self.semantic.request.corpus.binding
            || r.request_sha256 != self.semantic.request.sha256()?
            || r.base_sha256
                != luma_content::sha256(
                    &self.semantic.base.canonical_bytes(&self.semantic.request)?,
                )
            || r.semantic_sha256 != luma_content::sha256(&self.semantic.canonical_bytes()?)
            || Some(r.source_bytes)
                != self
                    .semantic
                    .next
                    .totals
                    .source_bytes
                    .checked_sub(self.semantic.base.totals.source_bytes)
            || Some(r.maximum_storage_bytes)
                != self
                    .semantic
                    .next
                    .totals
                    .write_bytes
                    .checked_sub(self.semantic.base.totals.write_bytes)
        {
            return Err(
                "actual ingestion substitutes semantic transition or accounting base".into(),
            );
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_ACCOUNTING_BYTES {
            return Err("actual ingestion envelope too large".into());
        }
        Ok(bytes)
    }
}
pub struct AccountedIngestPlan {
    inner: IngestPlan,
    reserve: PageReserve,
}
impl AccountedIngestPlan {
    pub fn reserve(&self) -> &PageReserve {
        &self.reserve
    }
    pub fn semantic(&self) -> &IngestCommitment {
        &self.inner.commitment
    }
}
pub fn account_ingestion_plan(plan: IngestPlan) -> Result<AccountedIngestPlan> {
    let c = &plan.commitment;
    let reserve = reserve(
        &c.request.corpus.binding,
        c.request.sha256()?,
        &c.base.canonical_bytes(&c.request)?,
        &c.canonical_bytes()?,
        c.next.totals.source_bytes - c.base.totals.source_bytes,
        &plan.pages,
    )?;
    Ok(AccountedIngestPlan {
        inner: plan,
        reserve,
    })
}
pub struct PreparedAccountedIngest {
    value: AccountedIngestCommitment,
    release_started: Cell<bool>,
}
impl PreparedAccountedIngest {
    pub fn commitment(&self) -> &AccountedIngestCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: CorpusIndexJobBoundary + PageAccountingBoundary>(
        &self,
        b: &mut B,
    ) -> Result<()> {
        let mut live = Live {
            request: &self.value.semantic.request,
            progress: &self.value.next,
            boundary: b,
        };
        live.current()?;
        if self.release_started.replace(true) {
            return Err(
                "measured reservation release already dispatched; reconcile uncertainty".into(),
            );
        }
        b.release_pages_after_selection(&self.value.accounting)?;
        Live {
            request: &self.value.semantic.request,
            progress: &self.value.next,
            boundary: b,
        }
        .current()
    }
}
pub fn prepare_accounted_ingestion<B: CorpusIndexJobBoundary + PageAccountingBoundary>(
    store: &ObjectStore,
    plan: &AccountedIngestPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedAccountedIngest> {
    let c = &plan.inner.commitment;
    plan.reserve.canonical_bytes()?;
    if mutation.review_sha256 != plan.reserve.review_sha256
        || mutation.source_bytes != plan.reserve.source_bytes
        || mutation.decision != crate::DecisionKind::Published
    {
        return Err("actual ingestion mutation mismatch".into());
    }
    Live {
        request: &c.request,
        progress: &c.base,
        boundary: b,
    }
    .current()?;
    mutation_check(b, &plan.reserve)?;
    b.reserve_pages(&plan.reserve)?;
    let mut live = Live {
        request: &c.request,
        progress: &c.base,
        boundary: b,
    };
    for record in &plan.inner.records {
        live.current_candidate(&c.request.corpus, record)?;
    }
    let (accounting, captured) =
        measure(store, &plan.reserve, &plan.inner.pages, mutation, &mut live)?;
    for record in &plan.inner.records {
        live.current_candidate(&c.request.corpus, record)?;
    }
    live.current()?;
    let mut next = c.next.clone();
    next.totals.write_bytes = c
        .base
        .totals
        .write_bytes
        .checked_add(accounting.actual_storage_bytes)
        .ok_or("actual ingestion total overflow")?;
    let value = AccountedIngestCommitment {
        semantic: c.clone(),
        next,
        accounting,
    };
    value.canonical_bytes()?;
    b.observe_pages(&value.accounting, &captured)?;
    mutation_check(b, &plan.reserve)?;
    Live {
        request: &c.request,
        progress: &c.base,
        boundary: b,
    }
    .current()?;
    Ok(PreparedAccountedIngest {
        value,
        release_started: Cell::new(false),
    })
}
pub fn verify_accounted_ingestion_data<
    B: CorpusIndexJobBoundary + PageAccountingBoundary,
    C: CorpusContent,
>(
    store: &dyn IndexReadStore,
    value: &AccountedIngestCommitment,
    content: &mut C,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let c = &value.semantic;
    let rebuilt = account_ingestion_plan(plan_ingestion_window(
        store,
        &c.request,
        &c.base,
        c.maximum_documents as usize,
        c.window_limits,
        content,
        b,
    )?)?;
    if rebuilt.inner.commitment != *c || rebuilt.reserve != value.accounting.reserve {
        return Err("actual ingestion differs from independent semantic reconstruction".into());
    }
    let mut live = Live {
        request: &c.request,
        progress: &c.base,
        boundary: b,
    };
    verify_pages(store, &rebuilt.inner.pages, &mut live)?;
    live.current()?;
    b.verify_pages(&value.accounting)?;
    Live {
        request: &c.request,
        progress: &c.base,
        boundary: b,
    }
    .current()
}
pub(super) fn verify_pages(
    store: &dyn IndexReadStore,
    pages: &[(String, Vec<u8>)],
    live: &mut impl Boundary,
) -> Result<()> {
    for (sha256, expected) in pages {
        if store.read_page(
            sha256,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            live,
        )? != *expected
        {
            return Err(
                "actual-debit candidate page differs from independently rebuilt bytes".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
