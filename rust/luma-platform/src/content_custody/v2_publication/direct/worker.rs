//! Closed worker-original direct publication. Semantic constructors are private
//! and reconstruct actual current C points before producing an ephemeral token.
//! No decoder, arbitrary new roots or caller-approved replay flag is accepted.
use super::*;
#[path = "worker/cold.rs"]
mod cold;
#[path = "worker/index.rs"]
mod index_preparation;
#[path = "worker/storage.rs"]
mod storage;
#[path = "worker/v1.rs"]
mod v1;
pub(super) use cold::verify_selected as verify_cold_v1;

const MEMORY_BYTES: usize = 4 * 1024 * 1024;
const MEMORY_PAGES: usize = 256;

struct VerifiedTransition {
    base: Selector,
    base_frame_sha256: String,
    source_sha256: String,
    request_sha256: String,
    review_sha256: String,
    roots: Roots,
    edits: BTreeMap<map::Kind, Vec<map::Edit>>,
    pages: BTreeMap<String, Vec<u8>>,
    records: BTreeMap<String, Vec<u8>>,
    operation: OperationData,
    read_cas: Vec<ReadCas>,
    outcome: Completed,
}
enum Outcome {
    Selected(VerifiedState),
    Prepared(VerifiedTransition),
}
struct ReadCas {
    role: map::Kind,
    literal: Vec<u8>,
    value: Vec<u8>,
}
enum Completed {
    V1(VerifiedState),
    IndexPreparation(RecordRef),
    IndexJobReservation(RecordRef),
}
impl<A: Checkpoint> Backend<A> {
    pub(in crate::content_checkpoint::custody::v2_publication) fn publish_v1_direct(
        mut self,
        commitment: &[u8],
        record: &[u8],
        original: &mut OriginalCOperation<'_>,
    ) -> Result<VerifiedState> {
        match v1::prepare(&mut self, commitment, record, original)? {
            Outcome::Selected(state) => {
                self.live(&mut || original.check())?;
                Ok(state)
            }
            Outcome::Prepared(token) => match storage::publish(self, token, original)? {
                Completed::V1(state) => Ok(state),
                Completed::IndexPreparation(_) | Completed::IndexJobReservation(_) => {
                    Err("closed V1 consumer received a different semantic completion class".into())
                }
            },
        }
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn prepare_index_direct(
        mut self,
        input: &crate::content_index::request::Input,
        plan: &crate::content_index::phase::Plan,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        let token = index_preparation::prepare(&mut self, input, plan, original)?;
        match storage::publish(self, token, original)? {
            Completed::IndexPreparation(reference) => Ok(reference),
            Completed::V1(_) | Completed::IndexJobReservation(_) => Err(
                "closed index-preparation consumer received a different semantic completion class"
                    .into(),
            ),
        }
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn reserve_index_start_direct(
        mut self,
        input: &crate::content_index::request::Input,
        builder: &impl crate::content_checkpoint::custody::v2_publication::index::effects::CurrentBuilder,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        let token = index_preparation::start(&mut self, input, builder, original)?;
        match storage::publish(self, token, original)? {
            Completed::IndexJobReservation(reference) => Ok(reference),
            Completed::V1(_) | Completed::IndexPreparation(_) => Err(
                "closed index-Start consumer received a different semantic completion class".into(),
            ),
        }
    }
}

/// This cache writes memory-only deterministic DATA. It is never a hash-file
/// fallback, selected owner or resource reservation. All old reads use the
/// current direct location tree and the actual original worker at each bound.
struct Memory<'a, 'b, 'c, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    original: &'b mut OriginalCOperation<'c>,
    context: map::Context,
    generated: BTreeMap<String, Vec<u8>>,
    bytes: usize,
    readonly: bool,
}
impl<A: Checkpoint> map::CustodyIo for Memory<'_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if self.readonly && (budget.write_bytes != 0 || budget.new_files != 0)
            || budget.write_bytes > MEMORY_BYTES as u64
            || budget.new_files > MEMORY_PAGES as u32
        {
            return Err(
                "direct semantic reconstruction exceeds bounded memory-only admission".into(),
            );
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        self.original.check()?;
        if context != &self.context {
            return Err("direct semantic reconstruction changed current C/source context".into());
        }
        self.backend.live(&mut || self.original.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("direct semantic reconstruction changed fixed page bound".into());
        }
        let bytes = match self.generated.get(sha) {
            Some(bytes) => bytes.clone(),
            None => self.backend.read_immutable(
                sha,
                slots::Kind::Page,
                &mut COperation::Worker(self.original),
            )?,
        };
        if bytes.is_empty() || bytes.len() > maximum || hash(&bytes) != sha {
            return Err(
                "direct semantic reconstruction received incomplete/substituted page".into(),
            );
        }
        self.check_current(context)?;
        Ok(bytes)
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        if self.readonly || bytes.is_empty() || bytes.len() > PAGE_BYTES {
            return Err("direct semantic replay cannot write or exceed a fixed page".into());
        }
        let sha = hash(bytes);
        if let Some(before) = self.generated.get(&sha) {
            if before != bytes {
                return Err("direct semantic memory cache digest collision".into());
            }
            return self.check_current(context);
        }
        if self.generated.len() >= MEMORY_PAGES
            || self
                .bytes
                .checked_add(bytes.len())
                .map_or(true, |n| n > MEMORY_BYTES)
        {
            return Err("direct semantic cache exhausted before copying input".into());
        }
        self.bytes += bytes.len();
        self.generated.insert(sha, bytes.to_vec());
        self.check_current(context)
    }
}
