# G3 and GWIN0 implementation plan

Current delivery work targets [complete native G3 and Windows deployments](G3_GWIN0_DELIVERY.md).
The latest produced image is the [sequence-16 native Ubuntu candidate](../native/evidence/G2_NATIVE_DESKTOP_CANDIDATE_16_2026-10-19.md),
not a Windows image or a complete G3 release. Dated checkpoints below retain
their original source and execution scope.

G3 functional-beta development and the GWIN0 Windows foundation start on
`feature/g3-gwin0-beta`, authorized on 2026-10-15. G2 remains open for native
and production qualification. The delivered sequence-14 laboratory image and
its evidence are frozen; subsequent branch changes need separately identified
images and evidence. Native G2 defects take priority over beta features.

The controlling scopes remain [G3](DEVELOPMENT_PLAN.md#g3-functional-beta) and
[GWIN0](DEVELOPMENT_PLAN.md#gwin0-windows-hosted-platform-proof), with the pinned
governing requirements. Development overlap does not waive inherited gates,
close Requirement 1 or declare Requirement 2 complete. The owner explicitly
authorized these named new tracks separately.

## Existing implementation and gaps

| Area | Existing implementation to retain | Work for the new tracks |
| --- | --- | --- |
| Shared control | Native account lifecycle, finite grants, protected UTC, resource generations, workflow journal and recovery | Integrate each new effect through those boundaries; no Python MVP or UI success flag substitutes for native enforcement |
| Artifacts | Native ext4/WAL catalogs, held immutable publication, independent C custody, owner-local typed collections, reviewed quarantine, encrypted backup and fresh-owner restore integration | Custody lifecycle and installed recovery qualification; general per-result access policy and semantic collections/indexes |
| User interface | Model-independent reference workspace and candidate native GNOME/Wayland edition | Accessible conversational/manual shell, progress/cancellation, grounded references and qualified capture/input |
| Content and adapters | Deterministic content engines, C-backed workflow commitments, scoped LibreOffice export and ephemeral browser adapter source; fixed generated KVM runtime | Installed adapter/UI qualification, complete accessible journeys and exact external build/test receipts |
| Windows development | Populated compute-only package, separate hosted TPM/CNG custody source, signed trust/runtime lifecycle, original Admin pipe, held NTFS input leases, ephemeral reads and persistent first-Admin exact-file enrollment | Authenticated complete product distribution, ordinary-user content/grant bridge, broader scoped ingestion, authority-key migration and installed WSL confinement/inference |
| Windows desktop | No qualified complete VM product proof | Hyper-V Gen2 image/template, identity, storage, resource limits and recovery proof; no acceleration claim from display availability |

## Initial implementation checkpoint

The native `artifact-catalog-search QUERY LIMIT` command rebuilds a bounded
in-memory lexical index from verified current catalog versions. It normalizes
case, intersects all query terms, returns deterministic artifact/version/hash
references and never persists an index or modifies artifact metadata/content.
Query size, result count, term size and total postings are bounded. It is an
installed-root **laboratory-only** command over the legacy lab catalog, refuses
production images and becomes unavailable after product Admin bootstrap.
It does not enumerate private principal domains or claim semantic/ACL-filtered
product search. Governed discovery is a subsequent slice, not a hidden fallback.

`packaging/windows/preflight.ps1` collects native Windows/CIM and bounded WSL
inventory observations and reports blockers for the proposed separate
`LumaOS-Dev` distribution. It rejects WSL1-only observations, name collisions,
unsupported architecture/baseline and insufficient observed free memory for
the proposed guest plus an 8-GiB Windows planning reserve. A passing observation
does not reserve memory or authorize installation. Unknown encryption,
enterprise policy, calculated storage, effective guest limits, confinement and
release qualification remain explicit prerequisites. No distribution, global
WSL setting, default distribution, host policy, firewall or boot setting is
changed. No service or executable skill is enabled.

The PowerShell parser accepts observed version columns without interpreting
localized state labels; ambiguous, duplicate or failed inventories stay
unknown. The collector uses the fixed system WSL executable, not a PATH-selected
companion. It only queries `--version` and `--list --verbose`, with a five-second
deadline. These are read-only commands described in
[Microsoft's WSL command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).
Architecture/virtualization observations use the
[Win32 Processor properties](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor).
Neither inventory establishes a qualified WSL or Hyper-V configuration.

The approved QA-only extension is implemented independently in native source.
It does not alter the frozen sequence-14 image or broaden another session's
purpose. See [the approval](gates/g2/qa_session_approval_2026-10-15.json).

## Principal discovery and shared content integration

The next checkpoint adds `granted-run artifact-owned-search LOGIN READ-GRANT
QUERY LIMIT`. It uses the existing independent `catalog-inspect` Read scope
returned by `granted-run artifact-gc-inspection-review LOGIN`. Current human
account, principal generation and grant checks span owner-domain admission,
verified 32-KiB private reads, bounded index work and result delivery. Only the
current generation's latest versions are returned, in deterministic order.
Revocation checks occur at bounded delivery boundaries; already-delivered
partial bytes cannot be recalled. This is owner-domain lexical discovery,
not semantic search, a cross-user corpus or a replacement for export grants.

The cross-platform `luma-content` Rust library adds immutable, owner/generation
and provenance-bound contracts for UTF-8 text, JSON and rectangular CSV.
Exact original and canonical byte digests remain distinct. Canonical reopen
checks content and metadata; optimistic external-edit comparison returns
no-change, a proposed next version or a retained conflict candidate. A stale
base never overwrites current content or automatically merges. Blank text and
delete-all text edits are supported. JSON duplicate keys, oversized structures,
overflowing integers and unsupported controls are refused. Floating-point JSON
uses the pinned parser's round-trip feature, not exact-decimal arithmetic or
RFC8785.

The real `luma-platform content-contract-capture`, `content-contract-reopen`
and `content-contract-compare` commands accept bounded schema-1 JSON on stdin
without root. They return inert data, explicitly without authenticated
ownership, grants, committed storage or certification. They are separate from
the laboratory governed publication commands described below. These commands do not open
files, launch Office adapters or execute CSV formulas.

Windows planning now accepts a closed seven-component storage budget: active
and candidate images, model packs, migration copies, user quota, backup staging
and recovery reserve. Checked UInt64 arithmetic and exact selected-drive binding
compare the total with observed free capacity, without a fixed 80-GiB pass
floor. A separate exact Windows edition/build/WSL runtime tuple comparison
checks supplied review data. Bounded strict JSON refuses duplicate, escaped,
unknown or invalid fields and excessive nesting. Matching supplied data is not
authenticated release qualification or an installation permit. Host encryption,
enterprise policy, effective guest limits and actual confinement remain separate
prerequisites. See [Windows planning commands](../packaging/windows/README.md).

The sequence-14 G2 image remains frozen. These source additions need a later,
separately identified image before native acceptance.

## Editable tables and durable content storage

`content-contract-table-edit` accepts an exact current envelope and a typed
batch of cell, row and column edits. Positions are zero-based, sequential and
include the first row; there is no inferred header. A valid batch proposes one
immutable CSV version, while a no-op keeps the original reference. Stale bases
return a conflict before interpreting positions against changed content. The
response includes the canonical edit request and its digest so a storage caller
can preserve the actual conflict intent. The command itself does not retain
the request or publish content.

All intermediate tables must remain within the existing content, field, row
and column bounds. Unknown operations, ragged insertions, unsupported controls,
exhausted versions and batches over 256 operations are refused. Cell values are
strings: formula-like text is never evaluated. This is an editable table-data
engine, not a spreadsheet calculation engine or an Office adapter.

The Linux `luma-content-store` library provides a separate versioned ext4
namespace for generic content, without changing invoice catalog validation.
Each installation, owner and account generation gets its own locked domain.
Publication retains the canonical version and exact original source together;
conflict and no-change outcomes retain their source without advancing the
artifact. Immutable transaction directories are synchronized before a
no-replace rename. Exact retries acknowledge a matching outcome, resume complete
matching preparations, or refuse and preserve mismatching partial bytes.

The storage API requires an explicit caller-supplied authorization and resource
boundary before private I/O and between bounded reads, writes and commit steps.
It supplies no default authority implementation. The native laboratory adapter
now joins finite Read/effect grants, current principal, protected UTC and broker
resource leases. Production admission still requires catalog head/rollback and
recovery integration; this library's journal is not TPM rollback protection.

## Governed laboratory publication and managed edit retention

The next native slice adds three commands through the existing `granted-run`
launcher: `content-owned-inspection-review LOGIN REQUEST`,
`content-owned-review LOGIN READ-GRANT REQUEST`, and
`content-owned-apply LOGIN READ-GRANT EFFECT-GRANT APPROVAL REQUEST`.
`REQUEST` is an exact canonical schema-1 JSON file, prepared without authority
by `content-contract-native-request`. The first command returns the exact Read
scope without opening private content. Review uses that grant to inspect the
current owner-generation store and returns the exact Read/effect pair and
`write:SHA256` or `retain:SHA256` approval. Apply rechecks the same proposal under
both independently admitted grants; approval text is never authority by itself.

Capture, external replacement and typed managed table edits use the actual
original PAM client's principal/generation, protected UTC, finite grants and
broker acquisition lease. Both grants remain checked together. Every content
renewal/checkpoint requires a fresh broker challenge rather than the model
controller's 500-ms sampling cache. The resource worker has no capabilities,
network or TPM access. The confined client cannot read the private store; sealed
request/output memfds and a fixed staged request path cross the worker boundary.
These commands require an installed **laboratory** image, including after Admin
bootstrap. Production images refuse this beta path.

Managed edits retain the exact canonical intent as `source.bin` in schema-2
outcomes and independently bind the resulting canonical CSV version. History
replays the typed engine against its recorded base; stale positions are never
interpreted against changed content. Conflicts and no-ops retain intent without
advancing versions. Existing schema-1 source records remain byte-compatible.
An exact old request can be acknowledged without republishing or rolling the
current head back; its entire operation metadata and source must match.

This is a governed laboratory storage adapter, not verified workflow execution.
Caller-supplied workflow provenance is descriptive (`workflow_executed:false`,
`provenance_authority:false`). Production catalog-head/rollback protection,
workflow completion linkage, semantic collections, retention/export and recovery journeys
remain development work. Actual installed PAM/broker/AppArmor/cgroup behavior
also needs separately identified image qualification.

### Governed reads and owner local search

Schema-1 native requests now support `current`, `historical`, `page` and `search`
operations through `content-owned-inspection-review` and `content-owned-review`.
They use a dedicated `native-content-query-v1` finite Read scope. `current` and
`historical` return immutable version metadata; `historical` requires every field
of an exact published reference, never a retained conflict candidate. `page`
requires that reference, a byte offset and a count from 1 through 16,384. It
returns a hex slice with the complete envelope's byte count and SHA256, next
offset and explicit EOF. Clients must assemble and hash the complete envelope
before reopening it. Each page requires independently current authorization;
a prior reference, hash or cursor is not permission.

Search reconstructs all verified outcomes, then scans only the current owner's
latest published versions. It matches every query term as an ASCII alphanumeric
word, with case/order/ASCII-whitespace normalization and deterministic artifact-ID
ordering. Byte offsets refer to canonical content, not the imported original.
Queries are bounded to 256 bytes and eight terms; the native path returns at most
32 hits within its finite 64-KiB response. No index is persisted or trusted, no
other owner's domain is enumerated, and these are not semantic results.

Query workers mount the store read-only; a missing or damaged repository is
refused rather than initialized or repaired. Delivery preflights its destination
before private reads/effects, uses nonblocking pipes/sockets/terminals, and
rechecks the original principal, grants, protected UTC and exact broker output
generation at every bounded write and retry. Direct regular-file/device output
is refused; authorized export is a separate unfinished workflow. Already
delivered bytes cannot be recalled. Laboratory and production fences are
unchanged.

Delivery never changes the caller's inherited open-file-description flags.
Pipes use private nonblocking staging pipes and per-call nonblocking transfer;
sockets use per-call nonblocking sends. A terminal needs a separately opened,
identity-verified descriptor, and insufficient DAC/AppArmor access refuses before
private reads or effects without adding privileges. This avoids relying on
cleanup after forced process termination. See the Linux documentation for
[shared descriptor flags](https://man7.org/linux/man-pages/man2/dup.2.html),
[nonblocking socket sends](https://man7.org/linux/man-pages/man2/send.2.html) and
[pipe transfer semantics](https://man7.org/linux/man-pages/man2/splice.2.html).

### Typed spreadsheet source and recalculation

`content-contract-spreadsheet` accepts a bounded schema-1 JSON source with 1 to
64 rectangular rows and 1 to 32 columns. Cells are explicitly blank, text,
decimal numbers or typed expression trees. Supported expressions are numeric
literals, cell references, negation, addition, subtraction, multiplication,
division and rectangular sum/minimum/maximum/average. References are zero-based.
The engine has no functions for network access, files, scripts, clocks or random
values, and never interprets text beginning with `=` as an expression.

Decimal inputs have at most six fractional places and magnitude at most 10^24.
Arithmetic is checked and exact: cycles, zero divisors, overflow and results
requiring rounding are refused. Blank numeric references mean zero; aggregate
functions skip blanks and refuse text. Sum of an all-blank range is zero; its
minimum, maximum and average are undefined and refused. Wider checked range
accumulators allow valid cancellation and averaging at the magnitude bound.
Expression depth, total nodes, uncached reference recursion and evaluation work
are bounded independently.

The result binds canonical editable JSON source and canonical CSV by separate
SHA256 digests and includes typed computed values. Source reopened as a generic
JSON artifact recalculates to the same output. This is a data engine, not a
workflow completion receipt. The laboratory managed-render path below supplies
native publication independently of the pure calculation command. CSV formula-looking
text remains inert inside Luma but is not sanitized for automatic interpretation
by external spreadsheet applications; qualified Office adapters/export remain
separate work.

### Editable document diagram and animation engines

`content-contract-document` renders a closed editable JSON document into escaped
standalone HTML. The source supports headings, styled inline text, paragraphs,
ordered/unordered lists, rectangular tables, code blocks and rules. Source and
output are independently bounded to 1 MiB; block, run, list, table-cell, text and
work limits apply before a complete result is returned. Empty documents and
empty text support delete-all edits. Source text cannot introduce active markup,
links, scripts, styles or embedded resources.

`content-contract-diagram` renders explicit integer canvas geometry into SVG.
It supports rectangles, rounded rectangles, ellipses, a fixed palette, bounded
multiline labels and straight edges with explicit cardinal ports and arrowheads.
Node identities and edge references are checked; missing endpoints, duplicate
identifiers, overlapping node bounds and out-of-canvas geometry are refused.
An empty diagram is a real blank canvas. Escaped labels never become markup or
external references. Automatic layout and cross-viewer pixel equivalence are
not part of this engine.

`content-contract-animation` returns ordered sampled SVG frames, not executable
animation or automatic playback. A closed source names a canvas, frame rate,
frame count, background and rectangular/circular sprites with position keyframes.
Limits are 120 frames, 32 sprites, 64 keyframes per sprite, 4,096 canvas units per
dimension and 1 MiB of serialized frame records. Keyframes cover the exact
timeline in strictly increasing order. Integer linear interpolation rounds down
for both signs; source order defines layering. Colors and identifiers use closed
grammars, so frames contain no scripts, external resources or dynamic CSS.

Each command returns canonical editable JSON, its SHA256 digest, deterministic
rendered bytes and output digests. Reopening the retained source reproduces the
same bytes. These pure stdin/stdout commands do not launch a browser, write a
file, authenticate an owner or publish a version. Actual CLI tests parse returned
SVG as XML and check exact frame positions; pixel rendering and accessibility in
the installed viewer remain qualification work.

### Managed render publication and reconstruction

Native schema-1 requests add `operation.kind:render` with a closed request:
`binding`, `artifact_id`, nullable `expected`, descriptive `metadata`, `engine`
and exact submitted JSON `source`. Engine is one of `spreadsheet`, `document`,
`diagram` or `animation`. Initial capture uses `expected:null`; subsequent edits
require the complete current immutable reference. The ordinary
`content-owned-inspection-review`, `content-owned-review` and
`content-owned-apply` path supplies the existing current principal/generation,
finite Read/effect pair, protected UTC and resource-generation checks. Production
images continue to refuse this laboratory path.

Schema-3 storage outcomes atomically retain the full canonical request, including
the exact submitted source text, and an immutable JSON artifact containing the
engine discriminator and canonical editable source. The plan/review separately
binds the versioned engine implementation, canonical-source digest, derived-output
digest, byte count and media type. Spreadsheet output is CSV, document output is
HTML, diagram output is SVG and animation output is the ordered JSON frame records.
Review/apply responses include that derivation; it is not workflow authority.
For a conflict, the derivation describes the submitted candidate, while
`resulting` identifies the unchanged current artifact, not that candidate.

History reconstruction reruns the engine from retained intent against the exact
prior artifact and compares the complete plan, payload and review. A modified
output digest cannot pass merely by recomputing a record hash. Source or formula
changes create a new version even if rendered bytes stay identical. Canonically
unchanged source retains a no-op intent; a stale reference retains a conflict
without overwriting the current head. Engine substitution is refused. Exact old
retries acknowledge their original outcome without rolling a newer head back.
Existing schema-1 and schema-2 records retain their serialization.

Authorized envelope pages reopen the editable wrapper; its `source` value is
input to the corresponding pure engine. The derived output is reproducible, not
a second independently mutable file. UI recalculation, generated-output export,
production rollback/recovery authority and authenticated workflow completion
remain separate development work.

### Exact owner local collections

`content-contract-collection` prepares a closed schema-1 collection source without
opening private storage. A collection has a stable `collection.ID` artifact,
a name and at most 64 exact immutable member references, sorted by artifact ID.
Canonical source is bounded to 32 KiB. Membership is neither a grant nor an
automatic, transitive or semantic classification.

Native `collection` requests publish schema-4 `CollectionIntent` transactions
through the existing laboratory Read/effect pair. Reconstruction and precommit
validation require genuine earlier published members and an exact collection
base. A first empty collection may initialize a repository; nonempty membership
requires verified existing history. Emptying membership retains the collection
identity and earlier versions. Stale edits retain conflicts instead of changing
the current head. Ordinary JSON with a similar artifact ID cannot forge typed
membership or overwrite an existing typed collection through a generic edit.

`collection-current`, `collection-page` and `collections-for-member` use the
read-only query profile. Pages contain at most 32 references. Reverse membership
is reconstructed from verified current collections rather than a trusted mutable
index. Exact historical member references remain historical; publishing a newer
member version does not silently update a collection. All operations remain
owner-generation-local and continuously checked; per-result cross-user policy
and semantic indexing are separate work.

### Reviewed preparation quarantine

The read-only `preparation` query reviews one exact pending request hash together
with committed history and every pending/quarantined directory, file identity,
byte length and digest. It does not interpret incomplete bytes as a valid plan.
The review is bounded to 32 KiB and is descriptive, not authorization.

A `recovery` request carrying that review first receives a `recover:SHA256`
proposal. Apply requires independent current Read and Retain grants, with the
Retain scope fixed to `native-content-recovery-v1`. Ordinary write/retention
grants cannot substitute for it. The worker rechecks the complete pair, owner,
generation, protected time and lease throughout inspection, rename, fsync and
delivery. Standard authentication sessions remain 30 seconds.

Recovery moves the exact reviewed directory into an optional pinned quarantine
with a no-replace rename. It publishes no content, deletes no evidence and never
changes a committed version. At most 16 quarantined preparations are retained;
the separate pending namespace also holds at most 16. All retained bytes
remain charged against repository capacity. There is no automatic eviction.
The retired request ID cannot publish again; a new operation needs a fresh ID.
Immediate interruption retries recognize the exact retired directory without
restoring an old grant. An unrelated committed-head or inventory change refuses
the old review rather than acknowledging it against changed state. Unknown
members, substitution or damaged committed history also refuse with state
preserved. This is partial-preparation retirement, not committed-authority repair,
backup restore or TPM rollback protection.

## Windows detached signature primitive

`verify-package-signature.ps1` joins the normalized package inspector to a
purpose-separated Ed25519 detached signature over the exact manifest. It requires
an independently supplied, SHA256-pinned laboratory public anchor and an exact
operator-selected, SHA256-pinned OpenSSL executable. No PATH lookup, production
anchor provisioning or signer private key is part of verification. Anchor bounds
are structurally checked, not compared with untrusted host wall time.

Successful output establishes only `cryptographic_signature_valid:true`.
Custody, verifier dependency authentication, protected UTC, current validity,
revocation, package authentication and installation/production admission all
remain false. In particular, pinning the executable does not qualify its DLLs
or the host runtime. See the [Windows commands](../packaging/windows/README.md)
for the signature format and separate compiler/security scratch roots.

Windows signature scratch is atomically private, handle-verified and pinned
against directory rename/delete. Volumes without persistent ACLs are refused
before scratch creation. This host's D volume is exFAT: bulk archives, compiler
scratch, Linux ext4 build storage and evidence stay on D, while these security
tests use only tiny ephemeral metadata in the repository's NTFS `.luma` directory.
No existing directory ACL is changed and cleanup never recursively deletes an
unverified path. These primitives do not import or update a WSL distribution.

### Signed laboratory release policy evaluation

`packaging/windows/verify-release-policy.ps1` joins the real detached package
signature verifier to an independently pinned laboratory authority, a signed
release policy and a separately signed clock interval. `Luma.Trust.psm1`
implements evaluation; `TrustInputs.cs` holds bounded final-file handles during
capture and verification. This evaluates signed data at its attested interval,
not current production admission. The `production` mode refuses explicitly.

The authority is a closed schema-1 laboratory record with purpose
`luma-wsl-trust-policy-v1`, an Ed25519 SPKI key and a finite lifetime of at most
366 days. Its exact bytes need the independently supplied `AuthoritySha256` pin.
That pin is a selection constraint, not authenticated deployed custody.

The signed policy has purpose `luma-wsl-release-policy-v1`. It binds a positive
sequence, exact previous-policy digest, validity of at most seven days, package
anchor digest, verifier executable digest, independent clock SPKI key and exact
authorized release ID/manifest/rootfs digests. Separate revocation arrays name
anchor, manifest and rootfs digests; each is sorted, unique and limited to 64
entries. The caller supplies the exact predecessor and minimum sequence. The
public command accepts only canonical positive decimal sequence text up to
9,007,199,254,740,991; decimals, exponents, signs, whitespace and leading zeros
are refused before coercion.

The clock record has purpose `luma-wsl-clock-interval-v1` and binds the exact
policy digest/sequence, manifest digest, independently supplied nonzero 32-byte
challenge nonce and lower/upper millisecond bounds. The entire closed interval
must lie inside the policy and package anchor's half-open lifetimes; uncertainty
is at most 60 seconds. Package, policy and clock signing keys must be mutually
distinct. Policy and clock signatures are raw 64-byte Ed25519 signatures over
their respective purpose followed by `\nlab\namd64\nW\n` and the exact input
JSON bytes. Unknown/duplicate fields, substitutions and revoked releases refuse.

Each trust input is at most 65,536 bytes. Final-file handles request no-reparse
and no-recall behavior, verify exact local path/identity, refuse hardlinks,
offline files and observed placeholder attributes, and retain read-only sharing.
They check metadata before reading bytes and after capture/final verification.
This is not the scoped reader's metadata-only double-open design and does not
qualify cloud-provider no-hydration behavior or a hard kernel-call deadline.
Private signature scratch uses tiny owned NTFS fixtures; compiler/package
scratch stays on D. The command imports no distribution and changes no host
policy or account.

The output separately reports valid cryptographic signatures, exact policy
binding and validity at the attested interval. Custody, dependency authentication,
fresh protected UTC, current revocation state, durable rollback protection and
installation/production admission remain false. A caller-supplied nonce, floor
or predecessor is not a durable or fresh authority. Deployment of those genuine
authorities, an authenticated complete product root filesystem and safe lifecycle integration remain
GWIN0 development work.

### Explicit Windows scoped file reads

`inspect-enrolled-file.ps1` accepts an explicit unsigned enrollment naming the
actual ordinary interactive Windows SID, an exact local NTFS directory and
relative file, a byte cap up to 1 MiB and the expected source SHA256. A review
hash binds all fields; reading requires its exact `read-exact-file:HASH`
confirmation. This input is not saved enrollment, authenticated custody or a
product grant. No folder is enumerated and no Linux identity is inferred.

The reader checks the actual non-elevated primary token, refuses impersonation
and enabled bypass privileges, pins ancestor/file handles, repeatedly checks
ordinary-caller ACL access, and verifies stable identity and complete bytes
twice before returning hex data. Traversal/device/alternate-stream paths,
reparse points, hard links, offline and observed cloud-placeholder attributes
are refused. The same handle discipline captures the bounded enrollment input.
The implementation follows [Windows handle sharing and open flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [file attribute definitions](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants).

Its five-second observation window is checked between operations and bounds
asynchronous reads; synchronous kernel opens, filters and disposal are not a
hard wall-clock guarantee. Cloud-provider no-hydration behavior still needs
provider-specific qualification. Token/ACL checks qualify this standalone local
read, not an authenticated guest bridge, persistent enrollment or automatic
background ingestion. No existing ACL, account, distribution or host policy is
changed.

## Windows package content validation (structural foundation)

`packaging/windows/validate-package.ps1` inspects a separate manifest and
uncompressed POSIX USTAR root filesystem without extraction or distribution
import. It binds the archive and required files to exact hashes and byte counts,
checks declared amd64/profile-W identity and rejects native disk images presented
as WSL archives. The normalized format excludes links, special files, archive
extensions, ambiguous paths and unsafe ownership or permissions. It requires
explicit parent directories and the exact development configuration disabling
WSL interoperation, Windows PATH inheritance and automatic drive mounts.

This restricted format is not an arbitrary Ubuntu tar importer. Its ELF-header
and embedded identity checks establish content consistency, not a runnable
Windows product. Genuine package authentication, a populated bootable userland,
hosted custody, safe import/update and actual confinement still need integration
and qualification. A passing result never admits installation or executable
skills.

### Populated Windows development package

`native/image/windows_stage.py` captures a fixed minimal Ubuntu 24.04 development
userland from an independently pinned offline tools image. It copies genuine
shell/systemd binaries, selected helpers, units, loader configuration, CA bundle
and their checked ELF dependencies, plus the caller's actual compiled Luma CLI.
It does not execute those inputs. Source accounts, passwords, host keys, machine
identity and resolver configuration are never copied. Generated development root
is locked and is not an enrolled Luma Admin.

`native/image/windows_package.py` builds the existing normalized profile-W USTAR
format from that staged source. Its closed plan lists exact exclusions and an
explicit privileged-mode normalization choice; neither is an implicit repair.
Pinned root-relative resolution, exact byte/identity checks, finite input bounds,
case/path collision refusal and new-output-only construction preserve source
and prior packages. The builder never downloads dependencies or imports a guest.
It checks real ELF load segments and the bounded dependency closure, including
Ubuntu systemd's private RUNPATH and already-loaded sibling libraries. Loaded
bindings remain separate for each executable; differing soname candidates refuse.
Optional dynamically loaded modules are not covered by this static closure.

The dated lab package is `D:\LumaOS-builds\gwin0-candidate-20261016-a`, containing
exactly `manifest.json` and `rootfs.tar`. The archive is unsigned and has no model
runtime, admitted product installation or configured Luma services. Real shell,
systemd-version and pure Luma-contract execution are userland smoke checks, not
a systemd boot or WSL confinement result. Package custody, complete service/unit
and dynamically loaded dependency configuration, first-user/Admin enrollment,
protected time, authenticated host bridge and safe import/update/rollback remain
development and qualification work.

Rebuild only inside the declared offline tools container, with the source
snapshot mounted read-only at `/repo`, the compiled binary cache read-only at
`/cache`, and an explicitly verified D-backed work mount at `/work`:

```sh
python3 -B /repo/native/image/windows_stage.py --root / --platform /cache/target/debug/luma-platform --work-root /work --output-name gwin0-populated-NEW
python3 -B /repo/native/image/windows_package.py --root /work/gwin0-populated-NEW/rootfs --platform /cache/target/debug/luma-platform --plan /work/gwin0-populated-NEW/plan.json --output /work/gwin0-candidate-NEW --release-id luma-wsl-dev-NEW
```

Both names must be unused. Verify the source image pin independently; the
stager does not attest its own container or mount backing. Keep compiler scratch
on D when running the existing Windows `validate-package.ps1` command under
process-only RemoteSigned. Structural success never authorizes `wsl --import`.

## Next integrated work

Requirement mapping remains partial:

| Requirement | Development contribution | Still required for acceptance |
| --- | --- | --- |
| A063, T33 | Held generic-content publication, independent C-protected head, managed render reconstruction, typed collections, quarantine and encrypted fresh-owner restore integration | Custody lifecycle, installed head/rollback and recovery/rebuild tests, and complete application journeys |
| A060, T20 | Current owner-generation/Read grants for verified invoice and generic-content search, exact historical pages and generation-fenced delivery | General per-result access policy, semantic collections/search and installed revocation qualification |
| W005, V01 | Read-only platform observations, calculated storage and exact supplied release-tuple comparison | Authenticated release policy, encryption and enterprise policy checks |
| W006, V01/V03 | Collision refusal, compute archive validation, separate TPM/CNG custody source, protected UTC protocol, durable signed deployment/trust/runtime histories and original Admin ceremonies | Installed custody/dependency and recovery qualification; authenticated complete product root filesystem, SID-owned content/effect integration and real inference |
| W009, V04/T13 | Observed free-memory planning check with an explicit Windows reserve | Effective guest limits, other guest workloads, measured host coexistence and installed worker cgroups |

No requirement in this table is marked complete by these development slices.

1. Complete custody lifecycle and installed recovery acceptance for the
   integrated C-backed content, workflow, encrypted export and restore paths.
   Extend explicit owner-local collections and discovery
   with per-result access policy before embeddings or automatic
   organization; pure data inspection is not storage publication.
2. Build the shared accessible manual/conversational shell on the deterministic
   content contracts. Join the four managed-render engines to authenticated
   workflow completion, UI rendering and recalculation.
   Add adapters and capture only
   with explicit permissions and real completion receipts.
3. Extend the purpose-separated Windows hosted compute deployment into a complete
   authenticated product distribution. Complete authority-key migration and
   the authenticated SID/principal content bridge. Preserve existing
   distributions/defaults. Extend the first-Admin ephemeral exact-file read into
   persistent scoped user enrollment before any host-file write capability.
4. Qualify WSL confinement, effective budgets and host reserve, lifecycle,
   manual/model-disabled controls and actual compact inference. Implement the
   complete Hyper-V desktop proof as a separate profile; do not assume nested
   virtualization or GPU compute is available.
5. Run inherited regression and adversarial tests, then the actual G3 user
   journeys/held-out quality corpus and GWIN0 V-series proof on declared tuples.
   Keep GWIN1/GWIN2 dependencies and native G2 acceptance separate.

### Exact collection search and bounded read journeys

The native `collection-search` operation takes one exact published collection
reference, a lexical query and a result limit. The store verifies membership
and member bytes from the same complete snapshot and searches the collection's
exact historical versions, not newer versions or unrelated artifacts. Generic
JSON, conflict candidates and forged references cannot become collections.
The original owner's current finite Read grant and resource generation remain
necessary throughout reconstruction, scanning and delivery. Membership is not
authority. Results contain exact references and term offsets, not snippets or
content. This is bounded lexical search, not semantic retrieval or a general
cross-owner access policy.

The manual workspace adds an exact-reference native terminal paging journey.
Every 16-KiB page exposes its own native inspection scope and requires an
explicit finite Read grant through the original PAM ceremony. Private pages
remain outside WebKit. The terminal checks the full envelope digest, owner and
immutable reference, then reopens the complete envelope through the native
content engine before displaying escaped content. Stopping discards partial
assembly; it cannot recall bytes already delivered. The browser's ephemeral
preview has keyboard cancellation, explicit errors, focus restoration and
grounded source metadata; none of these UI observations grants publication.

Windows adds a single-use, first-Admin-owned exact-file read over the original
client pipe. A separately reviewed `host-file-read` UTC source intent binds the
commissioned installation, genuine SID, canonical path, exact byte count and
complete hash. That source approval does not start a session or grant a read.
A fresh 30-second original-client session observes the actual token, NTFS
object identity and ACLs before and during bounded byte delivery. The service
opens source data under the original token; it does not use System access to
bypass file permission checks. Exact-prefix acknowledgements and a complete
hash distinguish partial transfer from completed delivery. This path neither
persists enrollment nor creates a Linux principal, content publication or
finite grant. Ordinary-user mapping and persistent ingestion remain development
work.

Existing Admin custody inspection also reports journal capacity bound to the
original genesis, exact journal hash and actual protected checkpoint. It does
not reserve capacity, truncate history, change keys or activate rollover. Safe
continuation still requires authenticated paged state and enforced physical
storage bounds, including bytes retained after interrupted attempts.

The [integrated software verification record](gates/g3/bounded_read_integration_2026-10-19.json)
pins 593 passing native-source tests, 126 focused Rust tests, three disposable-TPM
scenarios, 30 actual CLI tests, 260 Windows assertions and 31 production-JavaScript
assertions. All current source records match the final snapshot; the Windows
input bytes are identical across the composed verification cuts. No new native
image, installed-service qualification or gate closure is claimed.

### Integrated workflow and enrollment development

The native terminal journey now connects actual deterministic-engine preflight,
private workflow review, independently selected Read/effect grants, exact human
approval and C-backed apply. It distinguishes publication, retained conflict and
retained no-change. Interruptions after dispatch report an uncertain outcome;
they never claim rollback or automatically retry. A subsequent read requires
fresh authorization, reopens the exact complete envelope and can recalculate its
editable source. Every additional edit uses a new request ID and new review and
grant selections. Private bytes, passwords and grant IDs stay outside WebKit.

A separate `native-content-envelope-v1` selector admits one bounded whole-envelope
Read under the existing 30-second Standard session. It does not extend ordinary
64-KiB query output, borrow an Export session or authorize publication. Both the
controller and worker require activated production C custody. After the worker
exits, a new proof phase binds the still-live original controller, immutable
request, exact owner, original grants and physical output receipt. Delivery
rechecks current C availability and resource generations at every 4-KiB write
and flush boundary, so retirement stops buffered output even when the completed
worker's receipt remains valid. Only the immutable body hash is reused; live
authorization is not cached. Loaded confinement and performance within the
unchanged session bound remain installed qualification.

Fresh-owner restores now reserve capacity durably in the protected C start:
64 KiB per remaining publication plus 8 KiB for one terminal disposition. Every
new mutation must preserve outstanding promises. Actual publication and terminal
event sizes are checked before preparation or NV extension. Completion preserves
the terminal reservation until reviewed retirement. Historical starts retain
their original canonical bytes. Capacity-deficient histories remain readable,
but new publications and unrelated writes refuse; fitting reviewed retirement
can release a tail, and known committed recovery still finalizes without another
NV extension. These fixed reservations do not raise journal
limits or guarantee that the nominal 256-step maximum fits. Authenticated paged
journal succession remains development work.

Windows adds persistent exact-file enrollment, explicit supersession, revocation
and generation-selected reads through the existing signed W journal and NV
recovery lifecycle. Reviewed control intents pin the genuine first Admin,
installation, exact source, prior entry, registry source and current journal
head. The independent U source purpose is `host-file-enrollment`. Enrollment
lifetime is at most 30 days; each read still requires a fresh 30-second original
session and current UTC, token, NTFS object, owner and ACL checks. Revocation can
complete without opening a missing or expired source. The 64-ID, 256-control and
64-generation limits reserve revocation capacity; generation 64 is revoke-only.
Ephemeral reads remain a separate protocol. This is not an ordinary-user/Linux
principal bridge or background folder ingestion. Deploy the enrollment-capable
runtime before committing new journal kinds: an older binary intentionally
refuses those histories instead of adopting or resetting custody.

Shared-journal admission preserves logical space for active enrollments to be
revoked, including a finite recovery-spare budget reconstructed from committed
history. A prepared revocation does not release that reservation. The admission
check covers ordinary appends, dispatch preparation and abort replacements;
already committed recovery still finalizes without another NV extension.
Exhausting the spare budget does not block a fitting healthy final revocation,
but an additional uncertain previous-head write may have to remain fenced when
an abort cannot fit. No finite journal promises unlimited interrupted attempts.
The reservation covers signed-journal slots and encoded bytes, not NTFS free
space or the separate 4,096-file private-state namespace. Physical allocation,
namespace-safe continuation and complete journal succession remain open.

The [workflow and enrollment verification record](gates/g3/workflow_enrollment_integration_2026-10-19.json)
pins 610 passing native-source tests, 142 focused Rust tests, three actual
disposable-TPM scenarios, 30 unprivileged CLI tests, four actual engine/reopen/
recalculation journeys, 337 Windows assertions and 31 production-JavaScript
assertions. All 596 final source records match the verified native and Windows
inputs. The actual native workflow UI mechanism tests use inert authority
fixtures; the four-engine CLI lane does not authenticate an owner or publish.
No new bootable image, installed confinement qualification or gate closure is
claimed.

Repository metadata, all 288 pinned source requirements and the explicit release
inventory also validate. The source-release manifest lists all 259 tracked files in
its existing scope, including 83 previously omitted entries; its developer-MVP
boundary is unchanged. The legacy suite passes on Linux with its existing one
Windows-only junction case skipped, and that unchanged case passes separately on
genuine Windows/NTFS without a skip. D is exFAT, so this small disposable junction
fixture uses the C workspace; bulk build outputs and evidence remain on D.

### Remaining development and qualification

The [native candidate preparation record](gates/g3/image_candidate_preparation_2026-10-19.json)
adds the primary native desktop entry, original-Admin terminal restore/resume and
reviewed damaged-generation retirement. New lab images select genuine TPM-backed
C through a verity-protected policy; both normal content and backup workers
enforce it independently of release-signing classification. Private authority
and results stay outside WebKit. Missing custody is a refusal, not a file-backend
fallback.

C now admits its closed physical namespace and allocates both transaction data
files before TPM advancement. Exact reviewed partial-publication retirement is
available only at the unchanged pre-dispatch cut with canonical preparation.
Damaged preparation or authoritative history still remains fenced. The frozen
547-file source passes 118 focused Rust tests, all 620 native-source tests,
26 public-input cases, three disposable-TPM scenarios, 30 actual CLI cases and
four each of workflow/reopen and recovery-data compatibility cases. This is
software verification for a new candidate, not installed or native acceptance.

The [subsequent candidate-16 preparation](../native/evidence/workspace_launch_preparation_2026-10-19.json)
replaces the direct Python desktop
entry with a fixed nonprivileged ELF launcher and its own narrowly attached
AppArmor user-namespace compatibility profile. Ubuntu's packaged WebKit 4.1
does not supply that attachment for a custom Python shell. The launcher checks
the exact loaded named profile, unswitched ordinary-user identities and the
actual owner Wayland/session-bus sockets, closes inherited descriptors and
starts only the fixed isolated Python entry with a closed environment. A
mandatory schema-2 browser manifest pins the actual WebKit library, launcher
and profile bytes. The named `unconfined` profile grants compatibility for
WebKit's independently enabled sandbox; it is not whole-application confinement
or product authority. Installed startup, original PAM transitions and the
loaded policy still need image-specific qualification. Candidate 15 was paused
before assembly when this packaging gap was identified; its source and logs
remain retained, not reported as a produced or accepted image.
Its corrected executable/test sources pass 118 focused Rust and all 625
native-source tests, 26 public-input cases, the disposable-TPM and actual CLI
fixtures. The final cut changes only the packaged README, with an exact
byte-equality proof and a fresh 625-test/public-input rerun. The quiet Linux
repository sweep passes 319 cases with one Windows-only skip; that junction
case passes on Windows. Earlier loaded-I/O deadline failures and harness setup
failures remain retained rather than overwritten or counted as passes.
The final image cut additionally disables the packaged QEMU helper's automatic
global KSM policy, retaining QEMU for explicit use. Its 553-file snapshot passes
all 633 native-source and 26 public-input tests plus offline policy parsing.
The exact source comparison retains unchanged Rust and prior native test bytes;
these image-configuration tests do not claim a loaded kernel state or native
boot. The production JavaScript also passes 31 actual DOM assertions, not a
graphical WebKit acceptance test.

The current integrated sources still leave the following development work:

- Content custody lifecycle, bounded-journal succession/compaction and forensic
  recovery of damaged preparation/history beyond the implemented exact-chain
  recovery and application journeys.
- Semantic collections/indexes and per-result access policy beyond the current
  owner's lexical search, including its exact historical collection selector;
  graphical read/edit/recalculation journeys beyond the implemented private
  terminal workflow bridge.
- Accessible manual/conversational shell, progress/cancellation, grounded references,
  explicit speech/image/screen/video capture and visible capture controls.
- Installed viewer integration and authenticated completion for the deterministic
  engines, named/versioned LibreOffice/browser and allowlisted hardware adapters
  with actual external completion receipts.
- Windows authority-key succession, SID/principal content and finite-grant bridge,
  broader scoped ingestion beyond first-Admin exact-file enrollment and a
  complete authenticated product distribution beyond the compute-only package
  and hosted service implementation.
- Complete Windows inference/lifecycle integration and manual/model-disabled
  controls, plus the separate Hyper-V desktop implementation. Effective resources,
  confinement and recovery then require installed qualification.

Installed/native and declared Windows-tuple qualification remain separate from
that development: loaded confinement, revocation and recovery journeys;
two-user/ACL and cloud-provider tests; real inference, accessibility and capture;
host coexistence and Hyper-V behavior; the held-out quality corpus; and final
image/native acceptance. A software or structural test alone closes none of
  those qualification gates.

## Verification and host safety

Rust compilation/tests and native-source regressions use bounded, offline
containers and D-backed ext4 work/cache/evidence. Windows prerequisite tests
use deterministic observations plus a separate read-only native invocation.
PowerShell syntax parsing does not execute scripts. Where local execution
policy blocks scripts, execution is deferred until approved; no policy bypass
is built into the tools.

No host partitioning, existing TPM ownership change, firmware enrollment,
distribution import/replacement, Hyper-V provisioning, firewall change,
global WSL shutdown or memory configuration change is included in this first
slice. Production signing uses genuine external custody; these tools never
manufacture qualification evidence.

The initial read-only host probe on 2026-10-15 observed Windows 11 Home, amd64 and WSL2
with `Ubuntu` still the default distribution. The proposed `LumaOS-Dev` name was
unoccupied. The 12-GiB guest plus 8-GiB host planning reserve was refused on the
approximately 16-GiB host; no allocation or configuration change followed.
Initial Windows development tests passed 26 assertions under the approved process-only
RemoteSigned setting, with saved policy unchanged. See
[the exact Windows evidence](gates/gwin0/preflight_2026-10-15.json).

The initial immutable native snapshot passes warnings-denied all-target checks and
985 Rust tests; 42 existing fixture-only entries remain excluded. A follow-up
using the same snapshot and the retained UTC source/archive passes all 458
native-source tests without skips, thirteen OS and thirteen model
public-authentication cases, eight UTC-authentication cases and nineteen policy
parses. Focused catalog/authentication/QA/Admin regressions were rerun too.
These are software checks, not an installed-image or complete fixture/hardware
qualification. The failed no-exec test invocation and the initial two
unavailable-fixture skips are retained in
[the checkpoint record](gates/g3/development_2026-10-15.json).

### Integrated checkpoint verification

The next immutable 429-file native/Rust snapshot passes warnings-denied
all-target checks and 1,027 Rust tests, with the same 42 existing fixture-only
entries excluded from the unit suite. All 462 native-source tests and nine
actual CLI cases pass without skips. The CLI cases run as UID/GID 65534 with
supplementary groups removed, and cover real capture/reopen/conflict behavior,
blank and maximum-size documents, malformed input and numeric round trips.
Crashes are not counted as valid input refusal.

Thirteen OS and thirteen model public-authentication cases, eight UTC source
authentication cases, nineteen policy parses, six disposable PAM cases and
four resource software-TPM cases pass in the same serialized offline sweep.
This is not the complete final fixture matrix or installed/native qualification.
The [integration record](gates/g3/integration_2026-10-15.json) retains exact
snapshot/results hashes, cross-review findings, the numeric reproducer and
the corrected provenance-fixture failure. No production assertion or test was
weakened to obtain a pass.

The expanded Windows stage passes 154 actual PowerShell assertions and is
committed as `dc07f18`. The [current planning record](gates/gwin0/planning_2026-10-15.json)
binds its source hashes and read-only host observation. It still refuses the
proposed 12-GiB guest plus 8-GiB host reserve, and missing reviewed plan/policy
inputs do not become product installation authority. No host settings or
existing distributions changed.

### Table storage and package checkpoint

The next offline sweep passes 1,067 Rust checks, including 24 new table tests,
15 content-store tests and an exclusive-mutation compile-fail check. The 42
existing fixture-only exclusions are unchanged. All 465 native-source tests
and 13 actual unprivileged CLI cases pass without skips. Public OS/model trust,
UTC authentication, nineteen policy parses, six disposable PAM cases and four
resource software-TPM cases also pass. Storage tests cover interrupted
preparation/rename/acknowledgement, exact replay, stale conflicts, namespace
capacity/concurrency, source substitution and revocation at every observed
private-read and mutation checkpoint.

The final Windows package suite passes 105 assertions, including real wrapper
execution and explicit junction refusal; the existing preflight suite passes
154. A new failing reproducer exposed newline-suffixed release identifiers;
absolute string-end validation now refuses them. The final source snapshot
differs from the native-tested snapshot only in that Windows validator, its
tests and README. Every native/Rust input remains byte-identical, so the native
sweep is retained without repeating it for a Windows-only correction.

The [content/storage record](gates/g3/content_storage_2026-10-15.json) and
[Windows package record](gates/gwin0/package_content_2026-10-15.json) bind the
two immutable snapshots and exact results. These checks qualify development
primitives, not installed product enforcement, a Windows installation image,
the complete final fixture matrix or native/production acceptance. G3 and
GWIN0 remain open for the integration and user journeys listed above.

### Governed publication and detached-signature checkpoint

The final 453-file frozen snapshot passes warnings-denied all-target checks,
1,094 Rust tests, 467 native-source tests and 15 actual unprivileged CLI cases.
The 42 existing fixture-only exclusions remain unchanged. OS/model public trust
(13 cases each), UTC authentication (8), policy parses (19), disposable PAM (6)
and resource software-TPM (4) also pass. A first 1,093-test sweep passed before
cross-review found a false refusal of valid external JSON containing CR
whitespace. The correction and new regression received a fresh complete sweep;
the earlier snapshots/results remain retained, not relabelled.

The Windows package/signature suite passes 162 assertions and the preflight
suite passes 154. Actual signature CLI, substitution, junction, timeout/output
bounds and NTFS rename/delete tests run, including refusal of non-ACL scratch
storage. No package is imported and no runtime/custody qualification is inferred.

The [governed-content record](gates/g3/governed_content_2026-10-15.json) and
[signature record](gates/gwin0/package_signature_2026-10-15.json) bind exact
source/result hashes, execution limits and remaining development. These are
laboratory development checkpoints, not complete G3/GWIN0 acceptance. No new
image is claimed and the delivered G2 sequence-14 image remains unchanged.

### Governed queries and spreadsheet verification

The full offline workspace sweep passes 1,134 Rust tests, with the same 42
existing fixture-only exclusions. A subsequent delivery review replaced shared
descriptor-flag changes with per-call socket flags, private pipe staging and
an independently opened terminal descriptor. The final source passes
warnings-denied all-target compilation and all 45 affected Rust tests,
including real backpressure, authorization revocation, forced termination and
delivery through an inherited root-owned pipe as UID 65534. All other Rust
inputs are byte-identical to the full-sweep snapshot. This is composed
verification, not a claim that the complete workspace suite ran on the final
snapshot; the two Rust totals are not additive.

The final snapshot also passes 19 actual unprivileged CLI cases, all 469
native-source tests without skips, OS/model public authentication (13 each),
UTC authentication (8), policy parses (19), disposable PAM (6) and resource
software-TPM cases (4). The initial failed search-response fixture is retained:
it incorrectly expected truncation below the response budget. The corrected
fixture proves its complete serialized response exceeds the unchanged budget
before checking truncation. No production bound or assertion was weakened.

The ordinary-user Windows scoped-read suite passes 85 assertions, including
actual ACL revocation while a file remains pinned and successful read after
restoring the owned fixture ACL. Package and preflight regressions pass 162
and 154 assertions respectively. The standalone read is not yet an
authenticated Windows/Linux product bridge.

The [query and spreadsheet record](gates/g3/query_spreadsheet_2026-10-15.json)
and [Windows scoped-read record](gates/gwin0/scoped_read_2026-10-15.json) bind
the exact snapshots, results and remaining work. G3/GWIN0 remain open for the
development and qualification listed above; the frozen G2 image remains unchanged.

### Managed render and signed policy verification

The final frozen 473-file snapshot passes warnings-denied all-target compilation
and the complete 1,179-test Rust suite, including 97 shared-content tests, 50
storage tests, 1,031 platform tests and one compile-fail documentation test. The
same 42 existing fixture-only entries remain excluded from the broad unit run;
no new test is ignored. All 26 actual unprivileged CLI cases and 470 native-source
tests pass without skips. The complete pinned UTC source fixture is supplied,
so the two initially unavailable source cases execute. OS/model authentication
(13 each), UTC authentication (8), policy parses (19), disposable PAM (6) and
resource software-TPM cases (4) also pass.

The initial integrated attempt failed a new test that incorrectly required
automatic retry success after every cancelled write. The corrected test verifies
the exact separate-recovery refusal and byte-identical preservation of partial
preparations, or exact replay of a complete outcome. Production recovery behavior
is unchanged. Independent review also found and corrected forbidden XML
characters in diagram text, added exact animation work accounting, and expanded
concurrency, schema-downgrade and durable-phase coverage. The final snapshot
receives a fresh full sweep rather than inheriting the failed attempt's result.

The Windows signed-policy suite passes 94 actual assertions in both its agent
run and independent parent rerun, with no skips. Real signatures, revocations,
bindings, malformed public-command sequence floors and production refusal run
on the ordinary host-user process. The verified Windows stage is pushed as
`0e49cd9`. Its inputs remain byte-identical in the final integrated snapshot.

The [managed-render record](gates/g3/render_engines_2026-10-15.json) and
[signed-policy record](gates/gwin0/release_policy_2026-10-15.json) retain exact
hashes, the earlier failure and qualification boundaries. These complete the
named deterministic engine and laboratory policy components, not all G3/GWIN0
development or installed acceptance. The frozen G2 image remains unchanged.

### Collections recovery and populated package verification

The next immutable snapshot passes warnings-denied all-target compilation and
the full 1,215-test Rust workspace suite: 97 shared-content, 80 storage, 1,037
platform and one compile-fail documentation test. The same 42 existing
fixture-only entries remain excluded from the broad unit run; no new test is
ignored. All 30 actual unprivileged CLI cases pass. OS/model public authentication
(13 each), UTC authentication (8), nineteen policy parses and four independent
resource software-TPM cases pass too.

The original combined invocation failed only its PAM fixture: global
`TMPDIR=/evidence` conflicted with the fixture's required `/tmp/luma-tpm-*`
namespace. A separate setup attempt also omitted the D-backed Cargo target and
correctly refused writes to the read-only source tree. A fresh container with
canonical private `/tmp` and explicit `/cache/target` passes all six real PAM
cases. No product or safety assertion changes. The original failed result and
both setup logs remain retained.

The final 481-file snapshot differs only in strengthened Windows builder tests;
all 132 Rust inputs and all production/CLI inputs remain byte-identical. Its
complete native-source rerun passes 506 tests without skips. This is composed
verification, not a passing full-sweep invocation on the final snapshot or a
claim that the complete final fixture matrix ran. The new coverage includes
exact historical collection membership, generic-source forgery refusal,
preparation identity/byte substitution, every recovery authorization checkpoint,
durable interruption phases and the exact independent recovery grant pair.

The genuine populated Windows lab package passes the unchanged native Windows
validator and three isolated actual-archive userland checks as UID/GID 65534:
shell/id/uname, systemd version and the real Luma collection contract. The
packaged CLI matches the full-sweep rebuilt CLI byte for byte. The archive is
100,579,840 bytes with 166 members and 37 required runtime files, retained on D.
It is unsigned, not imported or booted, and is not an admitted installer.
The verified Windows stage is pushed as `13ca3df`.

The [collections and recovery record](gates/g3/collections_recovery_2026-10-16.json)
and [populated package record](gates/gwin0/populated_package_2026-10-16.json) bind
exact snapshots, result/log hashes, scope and remaining work. Production content
authority/workflow/backup integration, semantic/per-result policy, UI/capture/
adapters and complete secure Windows deployment remain development work.
Installed/native and declared Windows-tuple acceptance remain separate. G3 and
GWIN0 are open; the frozen G2 image is unchanged.

### Approved custody and recovery design

The owner approved the [content, backup and Windows custody design](gates/g3/custody_recovery_approval_2026-10-16.json)
on 2026-10-16. The independent C implementation commits the exact content head
through a fixed-scope coordinator, reconciles interrupted publication and refuses
rollback. It does not append every content event to the shared Admin journal,
reuse resource custody or grant TPM access to ordinary content workers. Custody
lifecycle and installed acceptance remain open.

Backups use per-owner encryption with an offline Admin recovery recipient.
Clean-machine recovery must explicitly bind restored data to a fresh installation
and principal; archived credentials, grants, sessions and TPM blobs cannot become
authority. The new backup-data library supplies exact Read reviews and independently
authorized Export capture. Native encryption, recipient custody, acknowledged
delivery and restored publication are now integrated in source; installed
acceptance remains separate.

Windows deployment uses a distinct TPM2/CNG-backed hosted authority, explicit
SID and first-Admin enrollment, and private NTFS live state. D remains the bulk
build/archive destination; its current exFAT filesystem is not the protected live
authority store. The new in-process signature primitive passes 98 actual Windows
assertions at its initial checkpoint, including child-CLI and NTFS link checks; the
[component record](gates/gwin0/platform_signature_2026-10-16.json) pins those inputs.
That primitive result is distinct from the later hosted authority implementation
and does not itself supply custody or installation permission.

The [backup-data and native-preview record](gates/g3/backup_preview_2026-10-16.json)
binds a passing immutable-source run: 103 storage tests, one documentation test,
warnings-denied checks for all Rust targets, 16 GI-free host tests, nine snapshot
tests and thirteen desktop-policy tests. The real CLI exercises eight engines,
three exact envelope reopens and two malformed-source refusals as UID/GID 65534,
with all capabilities dropped and no new privileges. The initial invocations
exposed test-helper shadowing, omitted fixture-root configuration and Cargo's
multiply linked executable; the corrected run preserves the product checks.

The manual native preview has a separate GTK/WebKit launcher. The cached desktop
image lacks the required WebKit2 introspection binding; the updated package
inputs need a fresh build and actual graphical testing. Integrated workflow,
encrypted backup/restore and named adapter sources require installed testing;
complete accessible journeys remain development work.

Physical TPM provisioning, native boot, power-loss recovery, offline recipient
custody and declared Windows-environment acceptance belong to the final test
phase after those enforcement paths are implemented. The approval itself is
not implementation or qualification evidence. The frozen G2 image is unchanged.

### Held publication and fresh owner restore planning

The shared content store now holds an exact synchronized preparation until its
caller explicitly publishes it. Reads and mutations compare the selected state
inside the same verified snapshot. Replaced inodes, changed quarantine evidence
and failed checks fence the held preparation without deleting its bytes.

Fresh-owner restore planning validates the complete archive and rebuilds every
published historical version under new installation and owner identifiers.
It reruns table edits and render engines, remaps exact historical collection
members, and commits the ordered new proposal hashes in a bounded review.
Archived conflicts, no-change outcomes and forensic bytes remain inert evidence;
accounts, grants, sessions and TPM authority are not restored.

The [component verification record](gates/g3/content_publication_restore_2026-10-18.json)
binds 121 passing storage tests, three compile-fail checks and the later two-test
restore-review regression run. This verifies storage and pure planning. The
native integration below adds original-Admin decryption, restore publication and
damaged-batch disposition; that component record is not retroactively treated as
an installed restore test. No native qualification is claimed.

### Windows hosted authority and service lifecycle

The hosted compute deployment now has a separate TPM/CNG authority, an original
interactive Admin ceremony, protected NTFS history and an authenticated local
pipe. Import and activation retain the actual owned controller identity and
require observed exit and drainage. An uncertain TPM write preserves its signed
intent instead of retrying dispatch. Reviewed abandonment requires a real TPM
reset and a different kernel boot generation.

Publisher and UTC changes replay from the protected history. UTC rotation uses
an explicit prepare and finalize handoff; prepared state fences new effects.
Runtime updates stage a complete signed executable and DLL bundle in a new
immutable slot. Finalization requires the service to run the exact new bundle
after an explicit restart. Installed input leases hold file identity, bytes and
ACLs while allowing legitimate child-directory generation changes.

The service now reports an unexpected worker exit as failure. Stop closes its
owned endpoint and waits for drainage; unsuccessful drainage terminates the
service process instead of reporting an orphan as stopped.

The [Windows component record](gates/gwin0/hosted_authority_2026-10-18.json)
binds 215 passing actual Windows software assertions, current-user NTFS identity
and ACL fixtures, threaded lifecycle tests, a warnings-as-errors executable
build and an installer review-only run. All 42 Windows input pins match the
immutable source snapshot. No service was installed, TPM changed or WSL
distribution imported.

This remains compute-only deployment. TPM authority-key migration, governed
Windows content and effects, and the complete Hyper-V desktop remain development
work. Installed LocalSystem, actual TPM, SCM and durability acceptance remain
separate qualification. GWIN0 is open and the frozen G2 image is unchanged.

### Native custody UTC and encrypted recovery

The native integration separates Admin, resource, content and Windows UTC
checkpoint domains. C and U enrollment retain the original genesis descriptor
whose digest is protected by their own TPM checkpoint. Coordinated changes to
mutable installation headers cannot replace that original proof. Ordinary
content workers have no TPM access; their exact held publication is committed
through C before its filesystem rename and reopened against the protected head.

Encrypted backup requires the current separately enrolled owner and offline
Admin recipient certificates, independent public-key pins, finite Read and
Export grants, and the original purpose-separated Export session. Delivery is
acknowledged ciphertext framing with a signed receipt over the measured output.
Neither encryption nor a supplied receipt key authenticates an origin by itself.

Restore verifies an independently selected origin pin, decrypts through a locked
private-key descriptor and rebuilds the complete archive under a fresh
installation and owner. The original live Admin, account generation, protected
UTC, finite grants and resource generation remain checked throughout. Restore
does not create accounts or reactivate archived credentials, grants, sessions or
TPM authority. Its current Standard session remains thirty seconds; a separate
thirty-minute Restore purpose awaits owner approval and is not borrowed from
Export.

The approved batch anchors each exact chronological publication in C. A fresh
authorized session can resume its verified prefix without repeating a TPM
extend. For a damaged or abandoned batch, separate Read inspection and reviewed
Admin recovery can retire only the exact owner-generation. Retirement preserves
committed records, damaged pending bytes and the original encrypted evidence;
it does not heal data or provision a successor. The rootless
`content-restore-retire-request` command only canonicalizes public phase/scope
data. A supplied review digest never becomes authority.

The U publisher signs exact installation, purpose, source, nonce and protected
time bounds. Its HTTPS frontend is a separately confined transport, not time
authority, and does not listen automatically. Explicit transport configuration,
certificates and key commissioning are required. The resource reserve accounts
for the separate C, U and HTTPS processes before acquisition admission.

Secret-bearing client and helper profiles now override inherited same-label and
unconfined process-inspection permissions across execution. Offline policy
compilation does not qualify the loaded kernel policy; native negative tests
must exercise those boundaries on the actual image.

The [native integration record](gates/g3/native_custody_recovery_2026-10-18.json)
binds the source, exact software results and retained failures. C journal
compaction/custody succession, complete application journeys and installed
acceptance remain open. This is not a claim that all G3/GWIN0 development or
qualification is complete.

The [compute package record](gates/gwin0/hosted_compute_package_2026-10-18.json)
identifies the real Windows-validated archive on D. It is an unsigned,
compute-only development package, not a new native boot image or authenticated
Windows product installer. The G2 sequence-14 image remains unchanged.

### Sequence-16 assembly retry preparation

The first sequence-16 desktop assembly reached the optimized release compiler
but its 4-GiB container was killed by its own memory cgroup. No image or signing
outputs were produced. The build now accepts an explicit 5-GiB assembly-only
limit after checking actual available physical RAM with a 1-GiB build-host
reserve. This observation is not a reservation. It changes neither WSL memory
configuration nor compiler optimization, runtime security, other container
limits or native VM admission.

The [assembly preparation record](../native/evidence/assembly_memory_preparation_2026-10-19.json)
binds the final frozen source and its 638 passing native-source tests, 26
passing public-trust/model-input tests and offline policy parse. The prior
Rust, disposable-TPM and CLI results are joined only through verified identical
code. Actual assembly, image verification and boot results must be recorded
separately; these source results are not a produced or qualified image.

### Sequence-16 image produced and live Secure Boot smoke passed

Build `20261019T135331Z-desktop` now provides the laboratory-signed standalone
Ubuntu 24.04 amd64 UEFI desktop image at
`D:/LumaOS-builds/native/20261019T135331Z-desktop`. This is new sequence-16 media;
the earlier sequence-14 image and its historical evidence remain unchanged.
All thirteen offline image checks passed, including the actual optimized
packaged CLI and exact source/payload/signature/verity checks. A fresh
software-emulated Secure Boot VM then passed live-system startup, reference
AppArmor enforcement, verity and final storage teardown. Its `install` stage
name does not imply installation: the invocation was explicitly smoke-only.

Use the [operator handoff](../native/evidence/G2_NATIVE_DESKTOP_CANDIDATE_16_2026-10-19.md)
for transfer, independently pinned checksums, disposable USB/target selection,
public lab-certificate enrollment, model staging and native acceptance. The
[execution record](../native/evidence/candidate16_execution_2026-10-19.json)
identifies the source, exact artifacts, actual test logs, retained failed
attempts and remaining boundaries. Native installed/graphical, physical TPM,
security/recovery and production custody acceptance remain open. Bounded C
journal continuation/succession and broader G3/GWIN0 development are not
reclassified as testing or closed by producing this laboratory candidate.

### Integrated G3 and Windows delivery development, 2026-10-19

The owner requested complete native G3 and Windows deployments. The
[delivery register](G3_GWIN0_DELIVERY.md) separates the native image/ISO,
authenticated WSL product and Hyper-V desktop/ISO, including remaining
implementation work rather than treating it as final testing.

This batch adds exact selected-version lexical search under the existing
finite Read authorization. A canonical selection binds at most 64 unique
artifacts to genuine published immutable references; forged, absent and
unpublished conflict candidates refuse without broadening the search. All
selected references are resolved from one verified snapshot. This is not a
semantic index or a general per-result ACL implementation.

The accessible spreadsheet grid emits the native typed expression format;
only the actual native engine calculates and validates results. Keyboard
navigation, explicit draft handling, safe resizing, observed progress and
cancellation remain independent of model availability. This does not bring
private content, passwords or grants into the graphical WebKit boundary or
qualify installed graphical accessibility.

Windows storage now accounts for bounded retained files and physically
allocates new authority files before publication. Signed history derives
finite terminal revocation/abort capacity; grouped dispatch writes cannot
borrow another operation's allowance. Actual allocation preserves an empty
logical file until data is written. Available future tail space is an
observation, not a volume reservation against other trusted Windows writers.
Installed SYSTEM/service ACLs, hardware custody and power-loss durability
remain separate acceptance work.

The offline converter holds independently pinned raw-image and tool handles,
compares actual guest bytes and creates new VHDX output only inside protected
D-backed ext4 staging. Descriptor-relative output construction rejects public
directories and substitution races. The Windows planner validates bounded,
pinned data in a fresh process without invoking VM or TPM operations. Neither
component creates an installed desktop, supplies optical boot, establishes
firmware trust or reconciles VM checkpoint/clone rollback. Full-sized
conversion and a safe Windows-readable export remain unexecuted/open.

The [execution record](gates/g3/integrated_delivery_2026-10-19.json) binds all
613 final source files and exact logs: warnings-denied workspace checking,
four selected-search tests, 120 focused Rust tests, 668 native-source tests,
26 public-trust/model-input tests, three disposable-TPM scenarios and the real
CLI checks. Windows passed 89 capacity, 337 authority and 53 planner assertions;
the production JavaScript harness passed 93 assertions. Python regression passed
315 tests with five reported skips. These groups overlap and are not a summed
unique-test total.

The record preserves the earlier full-store run's 127 passes and one corrected
test-fixture failure; unchanged Rust production bytes join that run to the
final successful selected-search rerun, not to an invented fresh full-suite
pass. It also retains wrapper failures and the explicit NTFS fixture correction.
No new full G3 image, Windows bootable product, installed GUI qualification or
production acceptance is claimed by this development checkpoint.

### Semantic retrieval content composers and authenticated Windows compute

Native semantic queries now rebuild a TF-IDF latent semantic index from one
verified owner-local snapshot. `search-semantic-selected` accepts exact sorted
`references`, `query`, `limit` and `dimensions`; `collection-search-semantic`
uses one exact `expected` typed collection reference with the same query
parameters. Dimensions are 1 through 8, with at most 64 versions, 4,096
vocabulary terms and 512 learned features. Actual latent projection can match
an associated document without a literal query term. The same original finite
Read, protected custody, resource generation and continuous revocation checks
cover reconstruction, computation and delivery.

The index is rebuilt in memory, not trusted from a mutable cache. Its descriptor
hash commits the owner-generation, exact references and algorithm parameters;
it is not a signature over learned floats. Scores are rounded cosine similarity,
not confidence, truth or authorization. Tokenization uses ASCII alphanumeric
words in canonical content, including structured-format keys, and excludes
partial Unicode words and identifiers. Contextual/neural or multilingual
relevance is not supplied by this statistical implementation. General
per-result sharing policy and relevance acceptance remain open.

The native workspace now composes every supported document, diagram and
animation source variant with explicit atomic apply/discard, structural edits,
source copy and reload from host-verified canonical results. Structural actions
preserve keyboard focus and reject pending draft loss; invalid imports leave
the prior draft intact. Actual native engines remain the only rendering and
calculation authority. These manual editors do not complete conversational
inference, permissioned capture, private graphical publication or installed
adapter qualification.

On an explicitly commissioned Windows deployment, the original interactive
first Admin can invoke `Luma.HostedAuthority.exe compute ACTIVE_RELEASE_SHA256
OPERATION PAYLOAD_FILE`. The seven allowlisted inert operations are capture,
reopen, spreadsheet, document, diagram, animation and collection. Each request
has a fresh nonce, at most 4,096 UTF-8 payload bytes and 8,192 canonical request
bytes; output is bounded to 16 MiB. Original review, protected UTC, controller
execution, cancellation and acknowledged result delivery share one 30-second
purpose. Complete results are hash-verified and printed as inert base64, not
saved as a content publication or treated as workflow success.

Signed/NV history commits the exact resource generation before execution and
the actual controller identity before resume. Completion requires original
controller exit and confined guest drainage. `compute-recover
ACTIVE_RELEASE_SHA256 REQUEST_GENERATION` requires a separate exact review and
closes interrupted execution without replay or recovered-result success.
Current authenticated service/WSL pins now govern guest execution after runtime
migration; original commissioning, CNG/TPM and journal identities remain
unchanged. This path does not authenticate an ordinary Linux/product principal,
issue finite grants or run compact-model inference. Managed-memory clearing on
every exceptional transfer path is not qualified.

Private VHDX conversion can now be exported with `hyperv_image.py export` using
independent conversion-record, raw-image and VHDX pins. The exporter exclusively
creates new public D files through held directory descriptors, reads back the
complete destination, rechecks source/output witnesses and preserves partial
failures. Public export receipts are descriptive data. The Windows planner
independently holds and rehashes media; receipt validation cannot authorize a
VM, convert an installer into an installed desktop or establish firmware trust.
Actual tiny cross-OS export is distinct from full-sized desktop conversion.

Optical ISO delivery still needs implementation: a distinct signed optical
UKI/initrd path, bounded read-only optical discovery, correctly ordered
verity-backed root and payload mounts, EFI El Torito assembly, and production
signature/checker integration. The existing GPT partition-label UKI is not an
optical boot implementation. Installed native/Windows journeys, real compact
inference, production custody and hardware/profile qualification remain open
alongside the other development work in the delivery register.

The [execution record](gates/g3/semantic_compute_media_2026-10-19.json) binds
615 exact final source files to the retained logs. The final native sweep passed
680 source tests, 121 focused custody/workflow tests, seven semantic-store
cases, four selected-search regressions, 26 trust/catalog tests, three
disposable-TPM scenarios and the actual CLI/editor corpora. Windows evidence
joins 424 authority assertions to 89 capacity and 76 planner assertions through
unchanged tested-source hashes. Production JavaScript passed 118 assertions;
Python regression passed 315 tests with five reported skips. These groups
overlap and are not a summed unique-test total. The full Rust workspace/store
unit suites were not rerun.

The earlier native run's failed assertion is preserved: it mistakenly treated
an inert profile-description constructor as the effect-admission gate. The
test-only correction exercises the actual command/worker mode predicate;
all production bytes are unchanged between those two snapshots. The complete
selected integration sweep then passed on the corrected snapshot. No complete
G3/Windows image, actual installed compute execution or production readiness is
claimed by these software results.

### Native discovery and optical installer development 20 October 2026

The native workspace now has a trusted GTK discovery control for one exact
sorted historical selection or one exact typed collection. The original native
terminal obtains the query's finite Read scope, validates the complete native
response and displays only bounded references and rounded local TF-IDF/LSA
similarities. An explicitly selected hit starts a new exact-envelope ceremony;
the query grant is never passed to that read. Cancellation, an invalid response,
an empty result or missing permission cannot widen the selection or trigger an
automatic fallback. Passwords, grants and private results stay outside WebKit.

The discovery request retains the native limits: 256 ASCII query bytes, at most
eight alphanumeric terms, 1–32 returned hits, 1–8 latent dimensions and at most
64 exact selected versions. Python preserves full unsigned-64-bit versions and
owner generations. The browser's typed collection composer explicitly rejects
integers beyond its exact safe range and directs those references to native
JSON controls. Membership sorting is explicit; duplicate IDs, missing digests
and substituted versions are not silently repaired. Actual native collection
preview and canonical-source reload remain separate from publication through
the existing native owner review/apply controls.

`native/image/optical_media.py` implements a distinct optical installer build
path. Its `slot-optical.efi` must be separately signed and select
`luma.media=optical`, read-only loop-backed root/hash devices and the same signed
verity root, without installed Admin PCR approval. The dracut service is
configured to refuse ambiguous
inserted CDs, unbounded device enumeration, writable media and unsupported
root/hash geometry. The normal live generator is configured to bind the retained optical
payload at `/media/luma`; existing disk partition-label boot remains distinct.

The ISO constructor writes through one exclusively created held output
descriptor. Its independent verifier closes the ISO9660 namespace, root/path
tables, member inventory, extent order, multi-extent framing and complete file
hashes. Alternate Rock Ridge/Joliet namespaces, hybrid boot paths, overlapping
extents, extra catalog entries and substituted EFI extents refuse. EFI load
geometry uses the full partition size or its defined large-image sentinel,
not the legacy four-sector BIOS convention. The firmware interpretation is
specified in [UEFI 2.10 section 13.3.2.1](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#iso-9660-and-el-torito).

Assembly, production signing/finalization, checksums and public artifact export
are wired to carry the optical ISO and its observational report. The production
custody request/checker requires four UKIs plus the bootloader; only installed A/B slots receive PCR
approvals. The signed installed release's six-artifact schema is unchanged.
ISO construction precedes intentional payload staging hardlinks. After complete
payload-image readback, a held-descriptor cleanup removes only the known fresh
staging aliases, verifies that every original survives with one link, and
preserves unknown/substituted evidence. No old assembly or image was removed.

Laboratory resume retains its historical fixed source pin and exact 314-file
repair inventory by default. New builds explicitly select
`--source-approval independent-build` and supply all four nonzero independent
SHA256 pins for the source lock, release public key, Secure Boot certificate
and PCR public key. The source inventory is bounded to 1–4096 files, 32 MiB per
file and 256 MiB total. Exact source-tree/archive reconstruction and joins to
both the retained and actual immutable-root source locks remain mandatory,
alongside release/UKI signatures, verity, kernel/initrd and public-custody checks.
This mode packages already sealed lab inputs; it does not rebuild a product,
create keys, replace product custody or manufacture an optical UKI for an old
three-UKI source.

The [discovery and optical execution record](gates/g3/discovery_optical_2026-10-20.json)
identifies the final 621-file immutable snapshot, actual tool fixtures,
integrated test logs and retained failed attempts. All 717 native source tests
passed without skips, alongside 26 trust/catalog cases, three disposable-TPM
scenarios and 30 actual CLI contracts. Actual native workflow/recovery/discovery
canonicalizers and JavaScript-generated editor corpora passed independently.
The complete content-engine and content-store suites passed 97 and 135 tests,
plus three compile-fail authority-contract doctests; 126 focused Rust cases and
the offline warnings-denied workspace/all-targets check also passed. These
Rust results join through unchanged source to the final snapshot: its sole
change was correcting the real dracut test fixture to include both optical
and PCR modules. The failed earlier fixture transcript remains retained.

Production JavaScript passed 128 assertions and five UI contracts. Python
regression passed 315 tests with five platform skips. Previously executed
Windows results join 589 assertions through 59 exact unchanged source records;
they were not rerun in this second batch. Component checks overlap the full
native suite and are not an additional unique-test total. The tiny ISO fixtures deliberately
contain nonbootable test data: extent/catalog success is not firmware boot or
a produced OS image. Full optical assembly, installed journeys and final
profile acceptance remain separate from this source implementation.

### Earlier Windows inference planning 20 October 2026 (superseded below)

GWIN0 still needs its actual compact-inference, authenticated scoped host-file,
enforced-confinement and complete-VM-desktop proof, including the W008 lifetime/
restart/manual controls, resource coexistence and W022 two-user boundary.
General enrollment/automation, adapters, updates and product migration belong
to GWIN1; W033 checkpoint/clone reconciliation and all-profile release evidence
belong to GWIN2. Those later tasks do not add criteria to the GWIN0 gate. The current
Windows compute guest has a 512-MiB ceiling, one task and a thirty-second
purpose, and calls only deterministic content engines. Adding an operation
name cannot turn it into a Qwen3-4B inference implementation.

The next inference slice needs a distinct signed lab package/profile and an
actual executable worker. It must stream the verified 2,497,280,256-byte Qwen
GGUF, pin the CPU runtime and its complete ELF/dlopen closure, use fixed
context/output/resource bounds, and preserve original-Admin review,
prepare-before-dispatch, continuous protected UTC/cancellation checks and exact
uncertain-dispatch recovery. RPC and arbitrary loader paths stay excluded.
The cached b11100 archive contains `llama-cli`; its CLI implementation also
needs the server implementation library, even when the server executable is
excluded. Static inspection does not establish supported flags, CPU backend
loading or actual inference. A genuine cached model weight has not been
proven available. A separately reviewed five-minute inference purpose versus
retaining the existing thirty-second bound awaits the owner's choice; no
deadline extension is enabled by this batch.

The current WSL kernel, `6.18.33.2-microsoft-standard-WSL2`, reports AppArmor
disabled and no `/sys/kernel/security/lsm` interface. The enforced worker must
refuse on this tuple. A supported enforcing kernel/runtime must be qualified;
no kernel, LSM or WSL setting was changed. Native-source fixtures and offline
AppArmor parsing do not establish installed WSL confinement.

True Windows custody-root replacement remains a later production design
decision, not a GWIN0 prerequisite while the commissioned root is retained
within its admitted bounds. The
current NV policy binds the original key. A separately commissioned epoch
authority requires a reviewed new key/NV identity, exact inherited state and
an irreversible old-root forward commitment before new-root activation.
Retired histories and uncertain writes must remain fenced and recoverable;
normal migration cannot recover an already lost or compromised old root.
Retaining the original hardware root and rotating delegated signing keys is a
different, narrower contract. Neither design has been enabled without the
owner's choice, and neither replaces genuine product-principal/finite-grant
integration with caller-supplied SID metadata.

### Integrated conversation, capture and compact inference 20 October 2026

The owner approved the distinct five-minute inference purpose and deferred
Hyper-V deployment to later development. This supersedes the earlier pending
session decision, not the original profile-V requirements. The current target
is native G3 and profile-W GWIN0; neither stage is declared complete by this
checkpoint. Exact source joins, executed tests, retained failed attempts and
artifact hashes are recorded in
[the execution record](gates/g3/conversation_capture_inference_2026-10-20.json).

Native GTK conversation performs a fresh finite Infer ceremony for every turn.
The model/worker/input commitment is checked inside native admission before
opening effect authority. Manual operation remains available when inference is
unavailable; uncertain submitted work is not retried automatically. Model text
is untrusted data, with no automatic workflow or OS effect.

Explicit image/screenshot, bounded PCM audio and sampled portal-video controls
now have visible indicators, stop/session revocation, dedicated portal
connections and separate audio/video confinement profiles. Private D-Bus and
real synthetic GStreamer fixtures do not establish installed portal permission
or hardware enforcement. PCM capture is not speech transcription; captured
images/video are not automatically submitted to a multimodal model or published
to native content storage.

The Windows inference profile streams the complete pinned Qwen3-4B Q4_K_M
weight and an eighteen-file private completion runtime plus its required ELF
closure. Actual token tests exposed the interactive CLI's banners/prompt echo
and the completion logger's empty-output behavior; both earlier attempts are
retained. The final path uses noninteractive `llama-completion`, output-only
logging, disabled prompt echo/backslash conversion and a sealed prompt memfd.
Its fixed ChatML user/assistant framing and empty thinking prefill match the
[Qwen tokenizer's non-thinking template](https://huggingface.co/Qwen/Qwen3-4B/blob/main/tokenizer_config.json).
There are no hidden system instructions. Completion stdout is retained
verbatim, including its possible end-of-generation marker; no heuristic
stripping or model-text command execution is used.

An authenticated thirty-second enrolled-file Read must complete and close its
pipe before an explicit snapshot-forward choice. The complete, hash-verified
UTF-8 file of at most 4096 bytes then becomes user text in a fresh independently
authenticated five-minute inference session. The snapshot is not a current
file-access claim, portable grant or reusable Read authority. The joined flow
uses one-use in-memory transfer and explicit cancellation/clearing.

The companion command is `infer-enrolled-file`. It takes the current release
and installation identities, enrolled root/relative path, exact whole-file
length and SHA256, publisher-bound runtime/profile hashes and output token
limit. It is interactive and refuses redirected input/output. Direct `infer`
uses an independently reviewed request file; `infer-recover` reconciles the
exact interrupted generation without rerunning the model. These commands do
not provision Windows custody, enroll arbitrary paths, import a distribution
or commission an enforcing kernel automatically.

Original-purpose expiry, protected UTC continuity, exact request hashes,
publisher-bound model/runtime bytes and observed Windows/guest memory headroom
remain mandatory. A durable request-specific cancellation barrier prevents a
late systemd start from executing a drained request. Unknown legacy dispatch
bindings and exhausted cancellation inventory refuse; retained evidence is not
reset to manufacture recovery or capacity. The existing thirty-second
deterministic-compute purpose is unchanged.

The current WSL kernel still lacks the required enforcing AppArmor context.
Offline parsing, actual CPU token generation, package inspection and foreign
label refusal do not qualify an installed Windows-hosted guest. No service,
distribution, kernel setting or physical TPM was changed. The new package is
an unsigned development artifact, not authenticated installation admission,
firmware-bootable Windows media or a complete G3 native image. The sequence-16
native candidate remains unchanged. Remaining code and qualification are kept
separate in the [delivery register](G3_GWIN0_DELIVERY.md).

### Capture revocation follow-through, 20 October 2026

Capture cleanup now attempts portal disconnect and descriptor release even if
worker drainage fails. Uncertain handles remain available for cleanup retry;
new capture admission closes. The production worker also binds its lifetime
to its exact UI owner before opening input, with checks around setup. Actual
owned-process and private D-Bus regressions passed: 28 control/policy tests
and six transport tests, with no skips. The
[source-bound execution record](gates/g3/capture_revocation_2026-10-20.json)
retains exact hashes and earlier attempts. These checks do not qualify physical
devices, installed portal consent or the final enforcing image.

### Reviewed native document handoff, 20 October 2026

An already delivered exact historical envelope can now be explicitly selected
for a new inference ceremony. Its complete bounded source, owner/reference and
digest remain data; the Read grant is not reused. A validated observed model
reply can enter a protected terminal document editor, with literal-text editing,
actual deterministic rendering and exact draft selection. Publication still
requires human-selected target/base/request and the existing independent native
Read/effect grants and approval. Nothing is applied automatically or delivered
to WebKit. Other engine sources retain their existing manual reviewed controls.

The [execution record](gates/g3/reviewed_draft_2026-10-20.json) joins 150
workspace/desktop tests, including 18 new draft cases, and six actual native
document render cases, with no skips. It preserves the failed runner and
empty-title attempts. These software checks do not establish installed PAM,
inference, publication, graphical accessibility or final-image qualification.

### Windows host-protection admission, 20 October 2026

The shared preflight/service observer now checks the actual held private NTFS
backing volume and live BitLocker state, including suspended protection. It
combines caller-context AAD, machine domain/MDM and typed WSL policy signals;
unknown or managed policy cannot supply enterprise approval. Installation,
commission, import/activation and new work fail closed. Read-only inspection and
explicit drainage remain accessible. Sampled observations are bounded checks,
not atomic reservations or a guarantee against an administrator changing host
protection between observations.

A pinned original-user child now observes WSL configuration under a single
bounded lifetime. Native failed/oversized allocation outputs cannot be walked
by the long-lived service. The [execution record](gates/gwin0/host_protection_2026-10-20.json)
joins all 67 Windows sources, 915 authority assertions, 166 preflight assertions,
162 package assertions, full compilation and review-only installer validation.
The actual read-only provider query timed out and policy remained unknown;
admission refused correctly. This is not host protection qualification or an
installed service/guest pass. First-launch identity and workspace/manual
controls remain implementation work; no host setting was changed.

### Genuine bounded source build and test, 20 October 2026

The new initial source profile compiles a declared freestanding C99 subset
inside KVM, then runs one or two explicit tests in fresh strict ELF microVMs.
It retains the existing PAM, finite ExecuteGenerated grant, resource generation,
revocation and drainage boundaries. Original compiler bytes and separately
hardened runnable bytes have distinct digests; receipts do not grant execution.
Source, dependencies, diagnostics and observed tests remain bounded. Compilation
failure, timeout or buffered output overflow cannot be reported as passing tests.

The [execution record](gates/g3/generated_build_2026-10-20.json) joins a coherent
published-base source cut, warnings-denied workspace/all-targets check, 12 generated
and 15 gateway Rust tests, 18 Python tests, six genuine build/test KVM cases,
14 existing raw-ELF KVM regressions and three inert installed request-helper cases.
There were no skipped cases. The appliance includes pinned compiler binaries,
corresponding source, notices and a relink kit; legal redistribution clearance
is not inferred. Offline AppArmor parsing is not enforcement. Installed authority,
full image, hardware-policy adapters and complete G3 acceptance remain open.

### Windows complete-snapshot manual save, 20 October 2026

The original interactive client can now explicitly save a fully verified
completed Read snapshot, up to one MiB, to a new private NTFS file. The Read
pipe closes first. A fresh 30-second manual action binds the source, current
Windows token/logon/session, fresh nonce and held target to an independent
human confirmation. It checks actual target protection, refuses overwrites and
ambiguous objects, then flushes and verifies the whole-file readback. The
client opens the output, not SYSTEM. Read receipts remain data rather than
product Export authority; inference, publication and Linux grants are not implied.
Failure can leave a named partial file for manual inspection, never automatic
retry or deletion. Synchronous kernel hard deadlines are not claimed.

The [execution record](gates/gwin0/manual_snapshot_save_2026-10-20.json) joins
973 authority assertions, including 57 new actual NTFS/manual-save mechanism
checks, 162 package assertions and full executable compilation. It retains the
failed full-file/wire-hash attempt and exact source pins. Installed first-Admin,
UTC, host protection and manual-workspace journeys remain qualification or
separate implementation work; no service, account or host protection was changed.
