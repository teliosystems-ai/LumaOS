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
| Artifacts | Native ext4/WAL catalogs, immutable invoice versions, per-principal domains, retention/export and recovery | General content types, governed discovery, semantic collections/indexes, external-edit conflicts and complete backup/restore journeys |
| User interface | Model-independent reference workspace and candidate native GNOME/Wayland edition | Accessible conversational/manual shell, progress/cancellation, grounded references and qualified capture/input |
| Content and adapters | Deterministic invoice calculation and fixed generated KVM runtime | Editable spreadsheet/document/diagram/animation engines, named LibreOffice/browser adapters, exact output/build/test receipts |
| Windows development | Source-run WSL launchers, native Windows/WSL model smoke and platform observations | Separate signed product distribution, authenticated companion/file bridge, SID mapping, ACL-aware broker, WSL-specific lifecycle and confinement |
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
workflow completion linkage, discovery, retention/export and recovery journeys
remain development work. Actual installed PAM/broker/AppArmor/cgroup behavior
also needs separately identified image qualification.

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

## Next integrated work

Requirement mapping remains partial:

| Requirement | Development contribution | Still required for acceptance |
| --- | --- | --- |
| A063, T33 | Immutable generic content/storage, laboratory governed publication and managed-intent retention, plus lexical invoice index rebuild | Production head/rollback and recovery integration, generic discovery, collections and installed recovery/rebuild tests |
| A060, T20 | Current owner-generation and Read-grant checks during verified invoice indexing and bounded result delivery | General per-result access policy, semantic search and installed revocation qualification |
| W005, V01 | Read-only platform observations, calculated storage and exact supplied release-tuple comparison | Authenticated release policy, encryption and enterprise policy checks |
| W006, V01/V03 | Collision refusal, unchanged distributions, normalized package validation and a lab detached-signature primitive | Qualified custody/dependencies/time/revocation, authenticated populated root filesystem, safe import/rollback and first-user/Admin setup |
| W009, V04/T13 | Observed free-memory planning check with an explicit Windows reserve | Effective guest limits, other guest workloads, measured host coexistence and installed worker cgroups |

No requirement in this table is marked complete by these development slices.

1. Finish production catalog head/rollback, recovery, retention/export and
   workflow linkage for the laboratory governed content adapter described above.
   Extend owner-domain discovery
   with collections and per-result access policy before embeddings or automatic
   organization; pure data inspection is not storage publication.
2. Build the shared accessible manual/conversational shell and deterministic
   editable-content engines on those contracts. Add adapters and capture only
   with explicit permissions and real completion receipts.
3. Join the purpose-separated Windows signature primitive to authenticated
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
