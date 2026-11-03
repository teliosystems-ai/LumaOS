//! A published generation read only through `ObservedIndexStore`, in the order
//! of the native IndexRead Query arm: the selected manifest blob, open, query.
//! The reader and boundary are shaped like the native `Reader` and `Gate`
//! (owner-bound 16 KiB pages, one aggregate original read reservation, read-only
//! Inspect of one owner). Current C, ACL, observer and TPM callbacks here are
//! synthetic; this is not installed C, observer, TPM or latency evidence.
use super::*;
use crate::corpus_index::storage::{IndexReadStore, ObservedIndexStore};
use crate::corpus_index::MAX_INDEX_PAGE_BYTES;
use crate::v2::readonly::ObservedPageReader;
use crate::v2::BlobReference;
use luma_content::OwnerBinding;
use std::cell::Cell;

/// Native `SOURCE_READ`: the original IndexRead reservation and admit ceiling.
pub(super) const ORIGINAL_READ: u64 = 128 * 1024 * 1024;

/// One request's aggregate original read reservation, debited before I/O.
pub(super) struct Tally {
    reservation: u64,
    remaining: Cell<u64>,
    pages: Cell<u64>,
    bytes: Cell<u64>,
}
impl Tally {
    pub(super) fn new(reservation: u64) -> Self {
        Self {
            reservation,
            remaining: Cell::new(reservation),
            pages: Cell::new(0),
            bytes: Cell::new(0),
        }
    }
    pub(super) fn pages(&self) -> u64 {
        self.pages.get()
    }
    pub(super) fn bytes(&self) -> u64 {
        self.bytes.get()
    }
    pub(super) fn debited(&self) -> u64 {
        self.reservation - self.remaining.get()
    }
}

struct Checked<'a> {
    binding: &'a OwnerBinding,
    check: &'a mut dyn FnMut() -> Result<()>,
}
impl Boundary for Checked<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if *binding != *self.binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("fixture observed read refuses another owner or writes".into());
        }
        (self.check)()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if !matches!(access, Access::Inspect { binding } if binding == self.binding) {
            return Err("fixture observer is read-only".into());
        }
        (self.check)()
    }
}

/// Mirrors the native `Reader`: owner and page bound, then a reservation debit
/// of `maximum + 1` before any private read, then a post-read check.
struct Envelope<'a> {
    store: &'a ObjectStore,
    owner: OwnerBinding,
    tally: &'a Tally,
}
impl ObservedPageReader for Envelope<'_> {
    fn read_observed_page(
        &mut self,
        binding: &OwnerBinding,
        sha256: &str,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        if *binding != self.owner || maximum == 0 || maximum > MAX_INDEX_PAGE_BYTES {
            return Err("index observer read changes selected owner or finite page bound".into());
        }
        let remaining = self
            .tally
            .remaining
            .get()
            .checked_sub(maximum as u64 + 1)
            .ok_or("aggregate original index read reservation exhausted before private IO")?;
        self.tally.remaining.set(remaining);
        let bytes = self.store.read_page(
            sha256,
            IoBudget {
                read_bytes: 32 * 1024,
                write_bytes: 0,
                new_files: 0,
            },
            &mut Checked { binding, check },
        )?;
        if bytes.len() > maximum {
            return Err("fixture observed page exceeds its bound".into());
        }
        check()?;
        self.tally.pages.set(self.tally.pages.get() + 1);
        self.tally
            .bytes
            .set(self.tally.bytes.get() + bytes.len() as u64);
        Ok(bytes)
    }
}

/// Boundary calls one request made, by kind.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Calls {
    pub(super) admit: u64,
    pub(super) check: u64,
    pub(super) corpus: u64,
    pub(super) builder: u64,
    pub(super) index_generation: u64,
    pub(super) generation: u64,
    pub(super) candidate: u64,
}
impl Calls {
    pub(super) fn total(&self) -> u64 {
        self.admit
            + self.check
            + self.corpus
            + self.builder
            + self.index_generation
            + self.generation
            + self.candidate
    }
    /// A lower bound on native `Current::check` calls for these boundary calls
    /// and observed pages. Each native `Gate` method wraps one closure in two
    /// checks; `current_generation` makes three such calls; `current_candidate`
    /// makes two plus the proof's head and initial checks, excluding the proof's
    /// own page reads; each `Reader` page adds `spend` (two) and a post-read
    /// check. Every `Current::check` runs `selected_index`, whose three `live`
    /// calls each read the TPM NV anchor.
    pub(super) fn native_checks(&self, pages: u64) -> u64 {
        2 * (self.admit + self.check + self.corpus + self.builder + self.index_generation)
            + 6 * self.generation
            + 6 * self.candidate
            + 3 * pages
    }
}

/// The selected owner's IndexRead boundary: native `Gate` refusals, then the
/// synthetic current-C fixture.
pub(super) struct Counted<'a> {
    inner: &'a mut Guard,
    owner: OwnerBinding,
    calls: Calls,
    deny_artifact: Option<String>,
    /// Wall time spent inside the synthetic fixture callbacks. The fixture
    /// never calls back into this boundary, so the spans do not nest.
    nanos: u64,
}
impl Counted<'_> {
    fn timed<T>(&mut self, call: impl FnOnce(&mut Guard) -> Result<T>) -> Result<T> {
        let started = std::time::Instant::now();
        let result = call(&mut *self.inner);
        let spent = started.elapsed().as_nanos();
        self.nanos += u64::try_from(spent).unwrap_or(u64::MAX);
        result
    }
}
impl Boundary for Counted<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.calls.admit += 1;
        if *binding != self.owner
            || budget.tasks != 1
            || budget.memory_bytes > 192 * 1024 * 1024
            || budget.read_bytes > ORIGINAL_READ
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("index read exceeds original finite readonly resources".into());
        }
        self.timed(|inner| inner.admit(binding, budget))
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.calls.check += 1;
        if !matches!(access, Access::Inspect { binding } if *binding == self.owner) {
            return Err("IndexRead cannot mutate/recover or substitute owner".into());
        }
        self.timed(|inner| inner.check(access))
    }
}
impl CorpusIndexBoundary for Counted<'_> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        self.calls.corpus += 1;
        self.timed(|inner| inner.current_corpus(root))
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        self.calls.builder += 1;
        self.timed(|inner| inner.current_builder(root, builder))
    }
    fn current_index_generation(&mut self, root: &MapRoot, selected: &str) -> Result<()> {
        self.calls.index_generation += 1;
        self.timed(|inner| inner.current_index_generation(root, selected))
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.calls.candidate += 1;
        if self.deny_artifact.as_deref() == Some(record.reference.artifact_id.as_str()) {
            return Err("fixture fresh owner-local source/lifecycle proof refuses this hit".into());
        }
        self.timed(|inner| inner.current_candidate(root, record))
    }
}
impl CurrentGenerationBoundary for Counted<'_> {
    fn current_generation(&mut self, manifest: &GenerationManifest) -> Result<()> {
        self.calls.generation += 1;
        self.timed(|inner| inner.current_generation(manifest))
    }
}

/// The selected generation as C records it: the manifest stored as a blob.
pub(super) fn select_manifest(
    store: &ObjectStore,
    value: &GenerationCommitment,
    b: &mut Guard,
) -> BlobReference {
    let bytes = value.manifest.canonical_bytes().unwrap();
    let mutation = mutation(value.review.sha256().unwrap(), b);
    let reference = store
        .prepare_blob(
            &bytes,
            IoBudget {
                read_bytes: 4 * 1024 * 1024,
                write_bytes: 4 * 1024 * 1024,
                new_files: 128,
            },
            &mutation,
            b,
        )
        .unwrap();
    assert_eq!(reference.sha256, value.manifest.sha256().unwrap());
    reference
}

pub(super) struct Request<'a> {
    pub(super) store: &'a ObjectStore,
    pub(super) selected: &'a BlobReference,
    /// The owner the observed store is bound to; the Gate owner is the
    /// generation's corpus owner.
    pub(super) reader_owner: &'a OwnerBinding,
    pub(super) reservation: u64,
    /// The caller-supplied query limits the native request validates.
    pub(super) limits: CorpusIndexLimits,
    pub(super) deny_artifact: Option<String>,
}
pub(super) struct Outcome {
    pub(super) result: Result<CorpusQueryResults>,
    pub(super) calls: Calls,
    pub(super) pages: u64,
    pub(super) bytes: u64,
    pub(super) debited: u64,
    /// Wall time inside the synthetic fixture boundary callbacks.
    pub(super) boundary_nanos: u64,
}

/// One IndexRead query: a fresh reservation, observed store and boundary.
pub(super) fn request(
    r: &Request<'_>,
    b: &mut Guard,
    generation_sha256: &str,
    kind: CorpusQueryKind,
    query: &str,
    limit: usize,
) -> Outcome {
    let tally = Tally::new(r.reservation);
    let owner = b.job.corpus().binding.clone();
    let mut gate = Counted {
        inner: b,
        owner: owner.clone(),
        calls: Calls::default(),
        deny_artifact: r.deny_artifact.clone(),
        nanos: 0,
    };
    let result = (|| -> Result<CorpusQueryResults> {
        let remote = ObservedIndexStore::new(
            r.reader_owner,
            Envelope {
                store: r.store,
                owner,
                tally: &tally,
            },
        )?;
        if r.selected.sha256 != generation_sha256 {
            return Err("query chooses a stale/foreign generation".into());
        }
        let credit = r
            .selected
            .bytes
            .checked_mul(2)
            .and_then(|v| v.checked_add(1024 * 1024))
            .filter(|v| *v <= ORIGINAL_READ)
            .ok_or("selected index blob exceeds closed original read envelope")?;
        let bytes = remote.read_blob(
            r.selected,
            IoBudget {
                read_bytes: credit,
                write_bytes: 0,
                new_files: 0,
            },
            &mut gate,
        )?;
        let verified = query::VerifiedGeneration::open(
            &remote,
            &bytes,
            generation_sha256,
            r.limits,
            &mut gate,
        )?;
        verified.query(&remote, kind, query, limit, r.limits, &mut gate)
    })();
    Outcome {
        result,
        calls: gate.calls,
        pages: tally.pages(),
        bytes: tally.bytes(),
        debited: tally.debited(),
        boundary_nanos: gate.nanos,
    }
}

fn allow() -> Result<()> {
    Ok(())
}

#[test]
fn observed_native_envelope_generation_queries_match_local_store_and_withhold_on_refusal() {
    let texts = [
        "alpha alpha beta",
        "beta gamma",
        "alpha delta",
        "delta gamma",
        "alpha beta gamma delta",
    ];
    let (_fixture, store, mut b) = setup(&texts);
    let value = publish(&store, &mut b);
    let selected = select_manifest(&store, &value, &mut b);
    let sha = value.manifest.sha256().unwrap();
    let owner = value.manifest.corpus.binding.clone();
    let page = b.job.progress.coordinates.root.clone().unwrap().sha256;
    let local = open(&store, &value, &mut b);
    let native = |deny: Option<&str>, reservation: u64| Request {
        store: &store,
        selected: &selected,
        reader_owner: &owner,
        reservation,
        limits: limits(),
        deny_artifact: deny.map(Into::into),
    };
    for (kind, query, limit) in [
        (CorpusQueryKind::LexicalAnd, "alpha beta", 2),
        (CorpusQueryKind::LexicalAnd, "alpha beta", 1),
        (CorpusQueryKind::FeatureLsa, "alpha", 2),
        (CorpusQueryKind::FeatureLsa, "delta gamma", 64),
    ] {
        let expected = local
            .query(&store, kind, query, limit, limits(), &mut b)
            .unwrap();
        let outcome = request(
            &native(None, ORIGINAL_READ),
            &mut b,
            &sha,
            kind,
            query,
            limit,
        );
        let result = outcome.result.unwrap();
        assert_eq!(result, expected);
        assert!(outcome.pages > 0 && outcome.bytes > 0);
        assert_eq!(
            outcome.debited,
            outcome.pages * (MAX_INDEX_PAGE_BYTES as u64 + 1)
        );
        assert!(outcome.debited <= ORIGINAL_READ);
        // Every returned hit is re-proven four times (twice reading its record
        // window, twice against the current corpus map); nothing else is.
        assert_eq!(outcome.calls.candidate, 4 * result.matches.len() as u64);
        assert!(outcome.calls.native_checks(outcome.pages) > outcome.calls.total());
        eprintln!(
            "nf08-observed {kind:?} {query:?} limit {limit} hits {} pages {} bytes {} debit {} calls {} native-checks>= {}",
            result.matches.len(),
            outcome.pages,
            outcome.bytes,
            outcome.debited,
            outcome.calls.total(),
            outcome.calls.native_checks(outcome.pages)
        );
    }
    // "alpha beta": document-0 (score 3), then document-4 (score 2).
    let lexical = |deny, limit, b: &mut Guard| {
        request(
            &native(deny, ORIGINAL_READ),
            b,
            &sha,
            CorpusQueryKind::LexicalAnd,
            "alpha beta",
            limit,
        )
    };
    // A refused returned hit withholds the whole output, including counts.
    let refused = lexical(Some("document-0"), 2, &mut b);
    assert!(refused.result.is_err());
    assert!(lexical(Some("document-4"), 2, &mut b).result.is_err());
    // Proof covers returned hits; counts are bound to the exact current corpus
    // root, which C changes in the same transition as any lifecycle change.
    let unreturned = lexical(Some("document-4"), 1, &mut b).result.unwrap();
    assert_eq!(unreturned.matches.len(), 1);
    assert_eq!(unreturned.total_matches, 2);
    assert!(lexical(Some("document-3"), 2, &mut b).result.is_ok());
    // A stale or foreign generation, and a descriptor that is not the selected
    // manifest, refuse before any query.
    let stale = request(
        &native(None, ORIGINAL_READ),
        &mut b,
        &"0".repeat(64),
        CorpusQueryKind::LexicalAnd,
        "alpha",
        2,
    );
    assert!(stale.result.is_err());
    assert_eq!(stale.pages, 0);
    let mut other = owner.clone();
    other.owner_generation += 1;
    let mut gate = Counted {
        inner: &mut b,
        owner: owner.clone(),
        calls: Calls::default(),
        deny_artifact: None,
        nanos: 0,
    };
    assert!(query::VerifiedGeneration::open(
        &store,
        &value.manifest.canonical_bytes().unwrap(),
        &"0".repeat(64),
        limits(),
        &mut gate
    )
    .is_err());
    // The Gate refuses another owner's Inspect and admission.
    assert!(gate.check(Access::Inspect { binding: &other }).is_err());
    let budget = ResourceBudget {
        memory_bytes: 1024 * 1024,
        tasks: 1,
        read_bytes: 1024 * 1024,
        write_bytes: 0,
        additional_storage_bytes: 0,
    };
    assert!(gate.admit(&other, budget).is_err());
    assert!(gate
        .admit(
            &owner,
            ResourceBudget {
                read_bytes: ORIGINAL_READ + 1,
                ..budget
            }
        )
        .is_err());
    assert!(gate
        .admit(&owner, ResourceBudget { tasks: 2, ..budget })
        .is_err());
    // An observed store bound to a borrowed owner reads nothing.
    let borrowed = request(
        &Request {
            reader_owner: &other,
            ..native(None, ORIGINAL_READ)
        },
        &mut b,
        &sha,
        CorpusQueryKind::LexicalAnd,
        "alpha",
        2,
    );
    assert!(borrowed.result.is_err());
    assert_eq!(borrowed.pages, 0);
    // The reader reads one real page, then refuses another owner, an unbounded
    // page and an exhausted reservation before private I/O.
    let tally = Tally::new(ORIGINAL_READ);
    let mut reader = Envelope {
        store: &store,
        owner: owner.clone(),
        tally: &tally,
    };
    reader
        .read_observed_page(&owner, &page, MAX_INDEX_PAGE_BYTES, &mut allow)
        .unwrap();
    let one = (1, MAX_INDEX_PAGE_BYTES as u64 + 1);
    assert_eq!((tally.pages(), tally.debited()), one);
    for (binding, maximum) in [
        (&other, MAX_INDEX_PAGE_BYTES),
        (&owner, MAX_INDEX_PAGE_BYTES + 1),
        (&owner, 0),
    ] {
        assert!(reader
            .read_observed_page(binding, &page, maximum, &mut allow)
            .is_err());
    }
    assert_eq!((tally.pages(), tally.debited()), one);
    let short = Tally::new(MAX_INDEX_PAGE_BYTES as u64);
    let mut reader = Envelope {
        store: &store,
        owner: owner.clone(),
        tally: &short,
    };
    assert!(reader
        .read_observed_page(&owner, &page, MAX_INDEX_PAGE_BYTES, &mut allow)
        .is_err());
    assert_eq!((short.pages(), short.debited()), (0, 0));
    // A reservation exhausted mid-query withholds the whole output.
    let exhausted = request(
        &native(None, 4 * (MAX_INDEX_PAGE_BYTES as u64 + 1)),
        &mut b,
        &sha,
        CorpusQueryKind::FeatureLsa,
        "alpha",
        2,
    );
    assert!(exhausted.result.is_err());
    assert_eq!(exhausted.pages, 4);
    // Revocation and a withdrawn C selection refuse the whole output.
    b.inner.inner.inner.set_revoked(true);
    assert!(request(
        &native(None, ORIGINAL_READ),
        &mut b,
        &sha,
        CorpusQueryKind::FeatureLsa,
        "alpha",
        2
    )
    .result
    .is_err());
    b.inner.inner.inner.set_revoked(false);
    b.generation = None;
    assert!(request(
        &native(None, ORIGINAL_READ),
        &mut b,
        &sha,
        CorpusQueryKind::LexicalAnd,
        "alpha beta",
        2
    )
    .result
    .is_err());
}
