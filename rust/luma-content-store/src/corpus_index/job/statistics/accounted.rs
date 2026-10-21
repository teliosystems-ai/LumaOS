//! Statistics opt-in actual-debit publication DATA. Legacy statistics methods
//! still charge their full original page ceiling. This path retains that full
//! hold until independent semantic replay and exact live selection succeed.
use super::super::accounted::{self, PageAccountingBoundary, PageDebitCommitment, PageReserve};
use super::*;
use std::cell::Cell;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountedStatisticsCommitment {
    pub semantic: StatisticsCommitment,
    pub next: StatisticsProgress,
    pub accounting: PageDebitCommitment,
}
impl AccountedStatisticsCommitment {
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
            .ok_or("actual statistics total overflow")?;
        self.next.canonical_bytes(&self.semantic.request)?;
        let reserve = &self.accounting.reserve;
        if self.next != expected
            || reserve.binding != self.semantic.request.ingestion.corpus.binding
            || reserve.request_sha256 != self.semantic.request.sha256()?
            || reserve.base_sha256
                != luma_content::sha256(
                    &self.semantic.base.canonical_bytes(&self.semantic.request)?,
                )
            || reserve.semantic_sha256 != luma_content::sha256(&self.semantic.canonical_bytes()?)
            || reserve.source_bytes != 0
            || Some(reserve.maximum_storage_bytes)
                != self
                    .semantic
                    .next
                    .totals
                    .write_bytes
                    .checked_sub(self.semantic.base.totals.write_bytes)
        {
            return Err(
                "actual statistics substitutes semantics or cumulative accounting base".into(),
            );
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 1024 * 1024 {
            return Err("actual statistics envelope exceeds finite limit".into());
        }
        Ok(bytes)
    }
}
pub struct AccountedStatisticsPlan {
    inner: StatisticsPlan,
    reserve: PageReserve,
}
impl AccountedStatisticsPlan {
    pub fn reserve(&self) -> &PageReserve {
        &self.reserve
    }
    pub fn semantic(&self) -> &StatisticsCommitment {
        &self.inner.commitment
    }
}
pub fn account_statistics_plan(plan: StatisticsPlan) -> Result<AccountedStatisticsPlan> {
    let c = &plan.commitment;
    let reserve = accounted::reserve(
        &c.request.ingestion.corpus.binding,
        c.request.sha256()?,
        &c.base.canonical_bytes(&c.request)?,
        &c.canonical_bytes()?,
        0,
        &plan.pages,
    )?;
    Ok(AccountedStatisticsPlan {
        inner: plan,
        reserve,
    })
}
pub struct PreparedAccountedStatistics {
    value: AccountedStatisticsCommitment,
    release_started: Cell<bool>,
}
impl PreparedAccountedStatistics {
    pub fn commitment(&self) -> &AccountedStatisticsCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: StatisticsBoundary + PageAccountingBoundary>(
        &self,
        b: &mut B,
    ) -> Result<()> {
        Current {
            request: &self.value.semantic.request,
            base: &self.value.next,
            b,
        }
        .current()?;
        if self.release_started.replace(true) {
            return Err("statistics release already dispatched; reconcile any uncertainty".into());
        }
        b.release_pages_after_selection(&self.value.accounting)?;
        Current {
            request: &self.value.semantic.request,
            base: &self.value.next,
            b,
        }
        .current()
    }
}
pub fn prepare_accounted_statistics<B: StatisticsBoundary + PageAccountingBoundary>(
    store: &ObjectStore,
    plan: &AccountedStatisticsPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedAccountedStatistics> {
    let c = &plan.inner.commitment;
    plan.reserve.canonical_bytes()?;
    if mutation.review_sha256 != plan.reserve.review_sha256
        || mutation.source_bytes != 0
        || mutation.decision != crate::DecisionKind::Published
    {
        return Err("actual statistics mutation differs from exact reviewed reserve".into());
    }
    Current {
        request: &c.request,
        base: &c.base,
        b,
    }
    .current()?;
    accounted::mutation_check(b, &plan.reserve)?;
    b.reserve_pages(&plan.reserve)?;
    let mut live = Current {
        request: &c.request,
        base: &c.base,
        b,
    };
    let (accounting, captured) =
        accounted::measure(store, &plan.reserve, &plan.inner.pages, mutation, &mut live)?;
    live.current()?;
    let mut next = c.next.clone();
    next.totals.write_bytes = c
        .base
        .totals
        .write_bytes
        .checked_add(accounting.actual_storage_bytes)
        .ok_or("actual statistics cumulative debit overflow")?;
    let value = AccountedStatisticsCommitment {
        semantic: c.clone(),
        next,
        accounting,
    };
    value.canonical_bytes()?;
    b.observe_pages(&value.accounting, &captured)?;
    accounted::mutation_check(b, &plan.reserve)?;
    Current {
        request: &c.request,
        base: &c.base,
        b,
    }
    .current()?;
    Ok(PreparedAccountedStatistics {
        value,
        release_started: Cell::new(false),
    })
}
pub fn verify_accounted_statistics_data<B: StatisticsBoundary + PageAccountingBoundary>(
    store: &dyn IndexReadStore,
    value: &AccountedStatisticsCommitment,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let c = &value.semantic;
    let rebuilt = account_statistics_plan(plan_statistics_window(
        store,
        &c.request,
        &c.base,
        c.window_read_bytes,
        c.window_write_bytes,
        b,
    )?)?;
    if rebuilt.inner.commitment != *c || rebuilt.reserve != value.accounting.reserve {
        return Err("actual statistics differs from independent exact semantic replay".into());
    }
    let mut live = Current {
        request: &c.request,
        base: &c.base,
        b,
    };
    accounted::verify_pages(store, &rebuilt.inner.pages, &mut live)?;
    live.current()?;
    b.verify_pages(&value.accounting)?;
    Current {
        request: &c.request,
        base: &c.base,
        b,
    }
    .current()
}
