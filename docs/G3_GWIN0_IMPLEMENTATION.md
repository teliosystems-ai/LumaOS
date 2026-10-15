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
ownership, grants, committed storage or certification. Generic content
publication into the protected catalog still needs finite write authority,
resource leases and transactional integration. These commands do not open
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

## Next integrated work

Requirement mapping for this first slice is deliberately partial:

| Requirement | Development contribution | Still required for acceptance |
| --- | --- | --- |
| A063, T33 | Disposable index rebuild from verified authoritative current versions, stable IDs and deterministic results | General content types, governed principal access and installed recovery/rebuild tests |
| A060, T20 | Laboratory discovery cannot enter private product domains | Current per-result authorization and revocation during indexing/delivery; lexical lookup is not semantic search |
| W005, V01 | Read-only edition/build/architecture/virtualization/WSL observations | Exact supported-release policy, calculated storage, encryption and enterprise policy checks |
| W006, V01/V03 | Collision refusal and preservation of current distributions/defaults | Signed independent root filesystem, safe import/rollback and explicit first-user/Admin setup |
| W009, V04/T13 | Observed free-memory planning check with an explicit Windows reserve | Effective guest limits, other guest workloads, measured host coexistence and installed worker cgroups |

No requirement in this table is marked complete by the first slice.

1. Publish the shared immutable content/version contracts through governed
   catalog transactions, with finite write grants, resource admission and
   durable external-edit conflict retention. Extend owner-domain discovery
   with collections and per-result access policy before embeddings or automatic
   organization; pure data inspection is not storage publication.
2. Build the shared accessible manual/conversational shell and deterministic
   editable-content engines on those contracts. Add adapters and capture only
   with explicit permissions and real completion receipts.
3. Build purpose-separated signed Windows packaging and a uniquely named WSL
   root filesystem. Preserve existing distributions/defaults. Introduce the
   authenticated SID/principal bridge and a read-only enrolled-file path before
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
