//! The job chain behind one publication. Each C event that selected a job for
//! an owner names the record it consumed, and that record derives the job
//! again from the one before it. The direct publisher walks the chain from the
//! audited job back to the job's Start, so a generation's provenance is the C
//! history itself and not a supplied hash, receipt or flag.
use super::job::{JobReservation, JobSelection};
use super::job_advance::{AdvanceSelection, JobAdvance};
use super::phase_selection::PhaseSelection;
use super::verification::checked_record;
use super::*;
use crate::content_index::state::Job;
use luma_content_store::corpus_index::BuilderIdentity;

enum Derivation {
    Start(JobReservation),
    Window {
        preparation: Preparation,
        candidate: BlobReference,
    },
    Advance(JobAdvance),
}

/// One job-selecting event of the walked owner, read from the current C
/// history. It is DATA, never writer Go, a revived grant or a selection.
pub(in crate::content_checkpoint::custody::v2_publication) struct ChainLink {
    job: BlobReference,
    derivation: Derivation,
}
impl ChainLink {
    /// A job selection and the Start reservation it consumed.
    pub(in crate::content_checkpoint::custody::v2_publication) fn start(
        view: &mut impl PreparationView,
        binding: &OwnerBinding,
        selection: &RecordRef,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Self> {
        let record = JobSelection::parse(&checked_record(
            view,
            selection,
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        let reservation = JobReservation::parse(&checked_record(
            view,
            record.reservation(),
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        record.validate_against(&reservation, record.reservation())?;
        if record.base().binding != *binding || reservation.input().binding != *binding {
            return Err("index provenance Start names a different owner".into());
        }
        Ok(Self {
            job: record.job().clone(),
            derivation: Derivation::Start(reservation),
        })
    }
    /// A phase selection and the window preparation it resolved.
    pub(in crate::content_checkpoint::custody::v2_publication) fn window(
        view: &mut impl PreparationView,
        binding: &OwnerBinding,
        selection: &RecordRef,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Self> {
        let record = PhaseSelection::parse(&checked_record(
            view,
            selection,
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        let preparation = Preparation::parse(&checked_record(
            view,
            record.preparation(),
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        if record.base().binding != *binding || preparation.input.binding != *binding {
            return Err("index provenance window names a different owner".into());
        }
        Ok(Self {
            job: record.next_job().clone(),
            derivation: Derivation::Window {
                preparation,
                candidate: record.candidate().clone(),
            },
        })
    }
    /// An advance selection and the advance reservation it consumed.
    pub(in crate::content_checkpoint::custody::v2_publication) fn advance(
        view: &mut impl PreparationView,
        binding: &OwnerBinding,
        selection: &RecordRef,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Self> {
        let record = AdvanceSelection::parse(&checked_record(
            view,
            selection,
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        let reservation = JobAdvance::parse(&checked_record(
            view,
            record.reservation(),
            PREPARATION_BYTES as usize,
            original,
        )?)?;
        if record.base().binding != *binding || reservation.input().binding != *binding {
            return Err("index provenance advance names a different owner".into());
        }
        Ok(Self {
            job: record.next_job().clone(),
            derivation: Derivation::Advance(reservation),
        })
    }
    /// The job this event selected.
    pub(in crate::content_checkpoint::custody::v2_publication) fn job(&self) -> &BlobReference {
        &self.job
    }
    /// The commitment a window derives its job from; other events have none.
    pub(in crate::content_checkpoint::custody::v2_publication) fn candidate(
        &self,
    ) -> Option<&BlobReference> {
        match &self.derivation {
            Derivation::Window { candidate, .. } => Some(candidate),
            _ => None,
        }
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn starts(&self) -> bool {
        matches!(self.derivation, Derivation::Start(_))
    }
    /// The first job's bytes, rebuilt from the owner head its Start reserved.
    pub(in crate::content_checkpoint::custody::v2_publication) fn first(
        &self,
        owner: &OwnerHeadV2,
        builder: &BuilderIdentity,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let Derivation::Start(reservation) = &self.derivation else {
            return Err("index provenance begins only at a job Start".into());
        };
        if reservation.builder() != builder {
            return Err("index provenance Start reserved a different builder".into());
        }
        reservation.job_bytes(owner, check)
    }
    /// This event's job bytes, rebuilt from the job before it and, for a
    /// window, the commitment it selected.
    pub(in crate::content_checkpoint::custody::v2_publication) fn next(
        &self,
        base: &Job,
        candidate: Option<&[u8]>,
        builder: &BuilderIdentity,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        match (&self.derivation, candidate) {
            (Derivation::Window { preparation, .. }, Some(bytes)) => {
                let commitment = phase::Commitment::parse(bytes)?;
                if preparation.review.builder != *builder
                    || preparation.review.base_sha256 != base.sha256()?
                    || commitment.review_sha256()? != preparation.review.core_review_sha256
                {
                    return Err("index provenance window differs from its prepared review".into());
                }
                let bytes = commitment
                    .next_data(base, &preparation.input)?
                    .canonical_bytes()?;
                check()?;
                Ok(bytes)
            }
            (Derivation::Advance(advance), None) => {
                if advance.builder() != builder {
                    return Err("index provenance advance reserved a different builder".into());
                }
                advance.job_bytes(base, check)
            }
            _ => Err("index provenance derives a job only from a window or an advance".into()),
        }
    }
}
