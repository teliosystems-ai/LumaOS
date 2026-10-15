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

## First implemented slices

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

1. Define reviewed artifact-discovery grants and effect-time access checks, then
   integrate rebuildable search with principal domains before exposing product
   search. Add generic immutable content/version contracts and external-edit
   conflict handling before embeddings or automatic organization.
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

The read-only host probe on 2026-10-15 observed Windows 11 Home, amd64 and WSL2
with `Ubuntu` still the default distribution. The proposed `LumaOS-Dev` name was
unoccupied. The 12-GiB guest plus 8-GiB host planning reserve was refused on the
approximately 16-GiB host; no allocation or configuration change followed.
Windows development tests passed 26 assertions under the approved process-only
RemoteSigned setting, with saved policy unchanged. See
[the exact Windows evidence](gates/gwin0/preflight_2026-10-15.json).

The immutable native snapshot passes warnings-denied all-target checks and
985 Rust tests; 42 existing fixture-only entries remain excluded. A follow-up
using the same snapshot and the retained UTC source/archive passes all 458
native-source tests without skips, thirteen OS and thirteen model
public-authentication cases, eight UTC-authentication cases and nineteen policy
parses. Focused catalog/authentication/QA/Admin regressions were rerun too.
These are software checks, not an installed-image or complete fixture/hardware
qualification. The failed no-exec test invocation and the initial two
unavailable-fixture skips are retained in
[the checkpoint record](gates/g3/development_2026-10-15.json).
