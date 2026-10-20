# ADR-0014: Segmented content and index generations

- Status: **Partially implemented data foundations; native integration and qualification remain open**
- Date: 2026-10-20
- Owners: storage, security/custody, platform, desktop and QA
- Extends: ADR-0003, ADR-0004, ADR-0010 and the existing independent content custody contract
- Scope: native G3 NF08, with inherited artifact, lifecycle, backup and recovery guarantees

## Requirement and present limitation

The pinned feasibility specification, `word/document.xml` table 15 row 9,
requires: “P95 first results at most 500 ms on 100,000 indexed objects”. Its
acceptance covers ACL-filtered text and semantic queries, excluding model
synthesis. The development plan assigns NF08 to G3; it is not deferred.

Current owner-generation content storage permits 256 committed outcomes and
64 MiB, separately from 16 pending preparations. All published versions,
conflicts and no-change outcomes consume that committed history. Reads rebuild
and verify the whole history under an exclusive repository lock. Owner-local
semantic search selects at most 64 versions and constructs an N-by-N Gram
matrix. These are real bounded implementations, not the required 100,000-object
path. Multiple owner namespaces do not supply one authorized 100,000-object query.

Independent content custody currently replays a 4 MiB/1,024-event journal for
each request, with a 32-entry/24 MiB physical namespace. Backup and restore also
have single-repository/256-step bounds. Changing a search constant would not
remove these coupled constraints safely.

This decision defines a new format and implementation direction. Public,
unselected v2 storage/custody and corpus-index data APIs now implement the
bounded format foundations; their verification is recorded separately from
native integration. They do not select a product head, perform a migration,
authenticate a builder or create a deployed native endpoint. This decision
reports neither NF08 completion nor a measured 500 ms result. Existing v1
bytes, limits, receipts, parsers, grants and recovery paths remain independently
supported.

## Authority and format boundary

Use a distinct `luma-editable-content-store-v2` owner-generation domain and
closed, versioned native protocols. The existing content custody authority C,
its independently provisioned sealed credentials and TPM/NV anchor remain the
only authority selecting protected content state. No ownership reset, new NV
allocation, new signing root, expanded Admin role or longer session is needed.

The v2 authoritative representation is an immutable, custody-bound segmented
history and authenticated map structure. This explicitly refines ADR-0003's
generic-content metadata representation: SQLite may be a derivative, not a
second selectable authoritative head. The existing invoice/catalog SQLite
implementation is unchanged. Hashes, serialized snapshots, map proofs, index
manifests and historical receipts alone never create authorization.

A migration marker or damaged v2 state cannot authorize a fresh empty store,
v1 downgrade, alternate root or laboratory fallback. Dispatch, current account,
finite grant, protected UTC, resource generation and output fences remain
mandatory. The initial visibility model remains current owner-generation access;
this decision creates no cross-owner sharing or caller-defined ACL authority.

## Segmented authoritative content

Each immutable segment has bounded canonical records and bounded bytes. A
candidate sizing basis is 256 outcomes/64 MiB per segment, with a separately
declared finite owner quota and segment-count ceiling sufficient for 100,000
current objects and retained history. These are design parameters, not raised
v1 constants or a claim that every nominal segment fits available storage.
The support matrix must fix actual quotas, inode reserves and resource budgets
before the format is admitted. Full storage refuses safely; no automatic purge
or history truncation is introduced.

Use fixed-depth, hash-prefixed directories and hashed pages of at most 16 KiB,
not unbounded directory enumeration or a monolithic 100,000-entry JSON file.
Authenticated maps identify:

- current artifact versions and immutable blob locations;
- exact historical versions and globally unique request outcomes;
- collection membership, logical lifecycle and retained/quarantine inventory;
- segment inventory, byte/inode accounting and pending preparations.

Page types bind schema, owner, generation, key ranges, counts and child hashes.
Global u64 history ordinals and request uniqueness span segment boundaries;
artifact versions and logical lifecycle revisions never reset. Existing
`VersionReference` fields retain their meaning. A v2 blob descriptor additionally
commits bounded content chunks, allowing verified small snippet/offset reads
without hashing an entire large artifact for each search hit. Whole-source
Read/export still checks the original complete content commitment.

Readers retain a shared immutable selected root and verify page paths against
it. Writers retain a short per-owner compare-and-publish lock. Derivative index
construction does not hold the authoritative exclusive lock for its duration.
A stale expected version or lifecycle reference remains a retained conflict;
index generation cannot choose a new target or silently merge it.

## C continuation and publication

Versioned C state consists of a bounded current descriptor/active journal and
immutable archived event segments. The descriptor commits the exact preceding
selected NV head and extension event, global ordinal, archived-event root,
owner-state map, recipient/signer generations, unavailable owners and all
outstanding restore publication/terminal reservations. A descriptor becomes
usable only through the same provisioned NV selection and independently
validated transition, never by adopting a caller's root hash.

Closed delta verification checks exact held source/record bytes, previous
selected roots, current original authority and the resulting map changes.
Preserve every historical segment; continuation is not deletion or reset.
Reconstructed immutable pages can be reused as data, but every operation still
obtains fresh current NV, principal, grant, UTC and lease observations. There is
no cached authorization across queries or effects.

Before any NV dispatch, allocate, synchronize and read back all new content,
map pages, C descriptor, prepared transition and publication files. Account for
physical allocated blocks, inodes, incomplete files and every admitted restore
tail, not just logical file lengths. Do not perform allocation after dispatch.
An uncertain NV or rename outcome poisons that attempt and preserves evidence;
only exact original-context reconciliation can resolve it. It cannot authorize
automatic redispatch or resource release.

## Migration and concurrency

Migration uses the existing authenticated finite review/effect boundaries and
must start from a fully reconstructed, C-selected v1 owner state. Build v2
side by side, preserving exact artifact references, source bytes, request IDs,
global ordering, collections, lifecycle and quarantine history. Retain the v1
namespace and its authenticated history. A reviewed C migration event binds
both old and new state commitments; it does not infer authority from an export.

Before selection advances, v1 remains the selected format; incomplete custody
preparations may require explicit reconciliation before further access. After
selection advances, only the exact v2 cut may serve that owner. Neither branch
silently adopts a partial tree or treats absence as initial installation.

Independent current reads continue during ordinary index rebuild and backup.
Custody uncertainty remains fail-closed and is not hidden by a stale snapshot.
Each writer checks the selected base immediately before publication. A page
cursor binds owner generation, corpus root, query, algorithm and position;
it is data, not a resumable grant. Corpus or policy changes refuse continuation
rather than replacing the user's selection with “latest”.

## Derived text and semantic indexes

Keep exact-selection lexical/LSA-v1 queries unchanged. A new owner-corpus profile
uses immutable paged postings and a separately versioned deterministic TF-IDF/LSA
implementation. It must not build the present N-by-N document Gram matrix:
100,000 squared float64 entries alone would require roughly 80 GB.

The candidate scalable algorithm streams document frequencies and a bounded
feature vocabulary, accumulates a 512-by-512 feature-space matrix, and computes
an explicitly bounded top-eight projection with convergence/refusal rules.
Stored 100,000-by-eight float32 vectors require approximately 3.2 MB before
references/metadata; a query requires approximately 800,000 dot-product terms.
These are arithmetic sizing estimates, not timing or quality evidence. The
profile remains declared statistical ASCII retrieval, not multilingual neural
embeddings or pixel understanding. No model pack, GPU or Infer grant is added.

The index manifest binds the complete authoritative visible-corpus root,
coverage count, source/runtime algorithm and page hashes. Only the fixed,
confined, resource-leased builder can publish an observed complete derivative.
Validate all referenced pages, missing-key proofs and full required vector
coverage. A corrupt, missing, stale or incomplete index produces an explicit
not-ready/rebuild state; it cannot silently omit part of the certified corpus.
Small immutable delta indexes may cover newly committed corpus roots; merging
them never rewrites authoritative history.

Rebuild is a bounded, explicitly admitted job. Progress is inert data; resuming
after expiry obtains new original authorization and a new lease, not automatic
renewal. Ordinary exact Read remains available. Cached index material never
permits another owner, a revoked principal or a trashed artifact to be returned.
Every candidate is resolved to the current authorized immutable reference and
lifecycle before snippets/content, with fresh checks at delivery fences.
Public result count/byte bounds stay finite; 100,000 objects are a searchable
corpus, not 100,000 references serialized into one grant or response.

## Segmented backup and fresh-owner restore

Do not enlarge the existing single-capsule parser to materialize the corpus in
memory. A new whole-snapshot manifest commits the exact frozen authoritative
root and every ordered bounded part, including source, metadata, histories,
lifecycle and map coverage. Parts reuse the existing CMS/recipient protection;
their ordered hashes and origin are bound by the independently authenticated
whole-manifest receipt. Ciphertext alone, a part receipt or a model assertion
cannot authenticate the original installation or a complete backup.

Restore streams bounded chronological windows, remaps artifact/collection and
lifecycle references into the independently provisioned fresh owner, and keeps
an exact C-selected target prefix and all outstanding capacity reservations.
Each new window uses a newly authenticated original Admin, the existing
standard thirty-second purpose and fresh grants. Source preparation, secret
entry where required, work, drainage and delivery must fit that original
deadline; a long worker timeout is not a longer authentication purpose. A
separate thirty-minute restore-only purpose remains an unapproved optional
policy change. Export, model import/activation, QA, repair and five-minute
inference approvals cannot authorize it. Windowing does not renew an earlier
session or import source credentials, grants or TPM state. Completion requires every declared
part and final target commitment; partial prefixes and encrypted original
evidence remain retained. Existing v1/v2 small-archive restore stays unchanged.

## Mandatory fault and adversarial matrix

| Boundary | Required outcome |
| --- | --- |
| Revoked owner/grant, stale lease or unavailable UTC/C before work | No private result or new effect; no cached-authority fallback |
| Partial object, segment or map page before C preparation | Old selected cut unchanged; incomplete bytes retained and charged |
| Prepared C files, before NV | Exact old selection or explicit reconciliation; no inferred commit |
| NV dispatch lost or advanced before rename | Poison attempt; preserve exact old/new files; no automatic second dispatch |
| Published root with missing/tampered page or changed mount/inode | Refuse; never skip a damaged branch or initialize empty |
| Concurrent publication, trash or external edit | Exact CAS conflict or fresh current result; no silently overwritten version |
| Index deletion, corruption, stale watermark or interrupted merge | Rebuild/not-ready; original file Read remains independent |
| Revocation/trash during query or blocked output | No subsequent protected hit/snippet; already delivered bytes reported honestly |
| Stale cursor or historical replay after later restoration | Refuse cursor or label historical fact separately from actual current state |
| Missing/substituted backup part or interrupted restore window | No whole-restore success; preserve authenticated prefix/reservations/evidence |
| v1 rollback, wrong owner/domain or invented migration descriptor | Fail closed against exact C/NV selection; no downgrade/adoption |

## Ownership and measured acceptance

Storage owns new `luma-content-store/v2` format, tree, segment/history,
migration, query and streaming backup/restore modules with fault tests.
Security/platform owns versioned C continuation, physical admission, recovery,
native profile/grant/resource routing and bounded protocol integration. Indexing
owns lexical/LSA builder/query modules and integrity/performance fixtures.
Desktop owns status, explicit rebuild, paged selection and migration/recovery
journeys after native contracts freeze. One integrator owns shared wire enums
and public dispatch changes; no separate ungated search is an intermediate
product feature.

Implement and join storage/C migration first, then streaming backup/restore,
then index/native/desktop paths and full fault testing. Decisions about new
format details, quotas and measured budgets are reviewed implementation work
within the approved scope, not an assumed missing user approval. Cross-owner
sharing, new trust roots/NV allocation, automatic recovery/purge or longer
authentication purposes would be separate authority changes and are excluded.

Acceptance must exercise the actual native 100,000-current-object owner corpus,
with separate unauthorized-owner fixtures, common/rare text and semantic
queries, current ACL/lifecycle filtering, and cold/warm distinctions. Measure
nearest-rank P95 through actual admission, C/TPM/UTC/lease fencing, dispatch,
lookup, candidate validation and first result delivery—not just the dot-product
loop. Publish the exact timing boundary, dataset bytes/objects, resource peak,
failures and limitations. Verify concurrent rebuild does not remove ordinary
Read, then exercise revocation, crash, damaged-index and clean-machine restore.
If the 500 ms bound is not met, optimize bounded proof/IPC/data work without
removing current checks or marking a partial index successful. Component
software fixtures, WSL and algorithm estimates do not qualify NF08 or G3.
