# G3 and GWIN0 implementation plan

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
| Artifacts | Native ext4/WAL catalogs, immutable versions, owner-local typed collections, reviewed partial-preparation quarantine and governed lexical discovery | Production generic-content authority, semantic collections/indexes, retention/export and complete backup/restore journeys |
| User interface | Model-independent reference workspace and candidate native GNOME/Wayland edition | Accessible conversational/manual shell, progress/cancellation, grounded references and qualified capture/input |
| Content and adapters | Deterministic invoice, spreadsheet, document, diagram and sampled-animation engines; editable JSON sources with laboratory governed publication and reconstructed result commitments; fixed generated KVM runtime | Named LibreOffice/browser adapters, authenticated workflow completion, UI rendering and exact external output/build/test receipts |
| Windows development | Source-run launchers, populated minimal Ubuntu package builder, real userland smoke, signed laboratory policy/revocation evaluation and ordinary-user scoped-file reads | Separate signed complete product distribution, authenticated companion/file bridge, SID mapping, ACL-aware broker, WSL-specific lifecycle and confinement |
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
| A063, T33 | Immutable generic content/storage, laboratory governed publication, managed render reconstruction, exact typed collections and reviewed partial-preparation quarantine | Production head/rollback and damaged-authority recovery, retention/backup/restore and installed recovery/rebuild tests |
| A060, T20 | Current owner-generation/Read grants for verified invoice and generic-content search, exact historical pages and generation-fenced delivery | General per-result access policy, semantic collections/search and installed revocation qualification |
| W005, V01 | Read-only platform observations, calculated storage and exact supplied release-tuple comparison | Authenticated release policy, encryption and enterprise policy checks |
| W006, V01/V03 | Collision refusal, unchanged distributions, normalized package validation, package signatures and signed laboratory release-policy/revocation evaluation | Qualified custody/dependencies, fresh protected time/current revocation, durable rollback protection, authenticated populated root filesystem, safe import/rollback and first-user/Admin setup |
| W009, V04/T13 | Observed free-memory planning check with an explicit Windows reserve | Effective guest limits, other guest workloads, measured host coexistence and installed worker cgroups |

No requirement in this table is marked complete by these development slices.

1. Finish production catalog head/rollback, recovery, retention/export and
   workflow linkage for the laboratory governed content adapter described above.
   Extend explicit owner-local collections and discovery
   with per-result access policy before embeddings or automatic
   organization; pure data inspection is not storage publication.
2. Build the shared accessible manual/conversational shell on the deterministic
   content contracts. Join the four managed-render engines to authenticated
   workflow completion, UI rendering and recalculation.
   Add adapters and capture only
   with explicit permissions and real completion receipts.
3. Join purpose-separated Windows package/policy/clock verification to authenticated
   custody, protected time/revocation and a populated uniquely named WSL root
   filesystem. Preserve existing
   distributions/defaults. Introduce the authenticated SID/principal bridge
   and a read-only enrolled-file path before
   any host-file write capability.
4. Qualify WSL confinement, effective budgets and host reserve, lifecycle,
   manual/model-disabled controls and actual compact inference. Implement the
   complete Hyper-V desktop proof as a separate profile; do not assume nested
   virtualization or GPU compute is available.
5. Run inherited regression and adversarial tests, then the actual G3 user
   journeys/held-out quality corpus and GWIN0 V-series proof on declared tuples.
   Keep GWIN1/GWIN2 dependencies and native G2 acceptance separate.

### Remaining development and qualification

The checkpoints above do not complete the following implementation work:

- Production generic-content head/rollback authority, damaged-authority recovery,
  governed workflow execution linkage, retention/export and clean-machine backup/restore.
- Semantic collections/indexes and per-result access policy beyond the current
  owner's lexical search; usable UI integration for paged reads and recalculation.
- Accessible manual/conversational shell, progress/cancellation, grounded references,
  explicit speech/image/screen/video capture and visible capture controls.
- Installed viewer integration and authenticated completion for the deterministic
  engines, named/versioned LibreOffice/browser and allowlisted hardware adapters
  with actual external completion receipts.
- Authenticated Windows companion, trusted dependency/custody/time/revocation
  delivery, populated runnable WSL package, SID/principal bridge and persistent
  scoped ingestion with product grants.
- Windows import/update/rollback, effective resources/confinement, manual/model-disabled
  controls, real compact inference and the complete separate Hyper-V desktop proof.

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
on 2026-10-16. Production content authority remains development work: a separate
Admin-provisioned TPM2 checkpoint authority must commit the exact content head
through a fixed-scope coordinator, reconcile interrupted publication, and refuse
rollback. It must not append every content event to the shared Admin journal,
reuse resource custody, or grant TPM access to ordinary content workers.

Backups will use per-owner encryption with an offline Admin recovery recipient.
Clean-machine recovery must explicitly bind restored data to a fresh installation
and principal; archived credentials, grants, sessions and TPM blobs cannot become
authority. The new backup-data library supplies exact Read reviews and independently
authorized Export capture, but encryption, recipient custody, delivery and restored
publication still require integration.

Windows deployment will use a distinct TPM2/CNG-backed hosted authority, explicit
SID and first-Admin enrollment, and private NTFS live state. D remains the bulk
build/archive destination; its current exFAT filesystem is not the protected live
authority store. The new in-process signature primitive passes 98 actual Windows
assertions, including child-CLI and NTFS link checks; the
[component record](gates/gwin0/platform_signature_2026-10-16.json) pins those inputs.
That result does not supply
custody, current time/revocation, rollback resistance or installation permission.

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
inputs need a fresh build and actual graphical testing. Authenticated workflows,
encrypted backup/restore and named external adapters remain development work.

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
original-Admin decrypt/restore journey, damaged-batch disposition and broader
deployment integration remain separate development work. No new image or
native qualification is claimed.
