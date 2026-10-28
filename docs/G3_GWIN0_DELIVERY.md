# G3 and Windows image delivery

The development target is a feature-complete Ubuntu G3 candidate and the
Windows-hosted Luma deployments defined by the governing requirements. The
native [sequence-19 disk image and ISO](../native/evidence/G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md)
are the current G2/native test media, and sequences 16 to 18 remain available.
Subsequent source changes do not alter any of these images' bytes or qualify a
new release.

On 20 October 2026 the owner approved a separate five-minute compact-inference
session and deferred Hyper-V deployment to later development. The current
implementation target is native G3 plus profile-W GWIN0. Profile V remains a
recorded delivery obligation, not an implemented or tested component.

## Deliverables

| Deployment | Target deliverable | Required distinction |
| --- | --- | --- |
| Native Ubuntu, profile N | Standalone Ubuntu desktop installation/recovery disk image and independently installable native ISO with complete G3 integration | Installs its own OS; not an application in an existing Ubuntu Server |
| Windows WSL2, profile W | Authenticated Windows companion and separately named product distribution, with a supported package and documented tar fallback | Does not replace the existing Ubuntu distribution or change its default; a WSL package is not bootable firmware media |
| Windows Hyper-V, profile V, deferred by owner | Later development: complete Generation 2 desktop deployment, explicit resource limits, verified guest boot, encrypted data and recovery, plus the required ISO | Retain W030–W032 and the full VM proof in the deferred backlog; existing VHDX work is a foundation, not a complete desktop |

The native ISO is explicitly required by `W003` and `W025`. Its distinct optical
UKI, read-only discovery, ISO assembly and verification paths are implemented,
and sequence 17 built and offline-verified a full ISO. That ISO failed its
software-emulated Secure Boot boot: initrd discovery sourced dracut's library
under `set -u` and aborted, so the verity root was never assembled. The script
is fixed in source with a regression test. A software-only diagnostic boot of
the fixed script then reached a verified root and found a second defect: the
udev rule naming the optical loops existed only in the initrd, so the real
root's verity unit failed after a 90 s wait. The rule now ships in the root
overlay and is copied into the initrd from there.

Sequence 18 carries both fixes. Its signed ISO boots under software-emulated
Secure Boot to a root shell on the verified root and passes all ten required
optical checks, with no boot ordering cycle. Its smoke still failed four gated
checks. The UTC recovery keeper exited `226/NAMESPACE` because
`/run/luma-governance` existed only in installed mode, which also left its bound
recovery producer path inactive. Signed media verification refused because live
`/var` is a RAM-backed tmpfs holding at most half of RAM, and a 6-GiB guest
cannot stage the 3,462,000,640-byte desktop payload. Commit `e29187b` creates the
`/run` namespace paths at every boot, adds a regression test over every unit,
and names the RAM that live staging needs; at least 8 GiB is required.

Sequence 19, built from `6528ea1`, carries those fixes. Its signed ISO booted
under software-emulated Secure Boot in an 8-GiB guest and passed all ten
required and all five gated optical checks. No unit failed, and the recovery
keeper and producer path were active. Signed media verification staged the
3,462,041,600-byte payload, which needs more than 6732 MiB of RAM, and exited
zero. Its disk image passed the same live smoke as before. Physical optical boot
from DVD+R DL or a virtual CD, installation from either medium and installed
acceptance remain to be tested on another host; see the
[sequence-19 handoff](../native/evidence/G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md).

These are Linux-based Luma guests under Windows, not replacement Microsoft
Windows installation media. The current Windows deliverable is profile W;
profile-V bootable desktop media is explicitly deferred. Native profile-N
media remains a distinct, independently identified deliverable.

`W030`, extracted from governing Windows paragraph 205, requires the complete
Hyper-V Generation 2 desktop and an ISO. `W031` requires fixed initial guest
memory, Windows headroom and explicit limits, with sharing opt-in and no public
service by default. `W032` requires guest verified-boot, LUKS2 and recovery
testing. A VHDX file, working display or source test cannot substitute for those
behaviors. Microsoft/firmware trust and independently commissioned virtual TPM
custody remain necessary; Secure Boot will not be silently disabled.

## Integrated implementation workstreams

This register retains both the current gates and the later production-delivery
backlog. Later GWIN1/GWIN2 work does not add exit criteria to GWIN0. The
native G3 gate runs concurrently and does not itself gate GWIN0; GWIN1 depends
on both. The [development plan](DEVELOPMENT_PLAN.md#gwin0-windows-hosted-platform-proof)
controls ownership: GWIN0 requires real compact inference, an authenticated
scoped host-file path, W008 lifetime/restart and manual model-disabled controls,
resource coexistence, qualified confinement, W022 two-user separation and a
complete VM desktop proof. The owner deferred that last profile-V component;
this scope decision does not supply its missing implementation or evidence.

| Workstream | Scope | Remaining implementation or qualification |
| --- | --- | --- |
| Durable content and custody | G3 capacity and later production durability | The deployed v1 owner-generation path still accepts at most 256 committed outcomes and 64 MiB. Real v2 owner planning/publication preparation, side-by-side migration, retained recovery and chronological restore replay now pass scoped software tests; the [21 October checkpoint](gates/g3/nf08_owner_snapshot_2026-10-21.json) records 127 tests. The [22 October checkpoint](gates/g3/nf08_direct_custody_observer_2026-10-22.json) adds direct-addressed paged C locations, worker direct publication, a query-only data observer and Admin-governed paged review in component tests. Native C activation, physical tails/accounting, authenticated snapshot delivery and installed restore integration remain development. Unlimited history, root succession and additional forensics are separate later obligations |
| Discovery and result policy | G3 | Existing native owner-local TF-IDF/LSA is bounded ASCII retrieval over at most 64 selected versions. A separate complete-corpus data core now implements bounded streamed postings and feature-space LSA, with explicit source/runtime builder identity and fresh non-default boundary callbacks. It is not a native-selected endpoint, resumable admitted job or measured 100,000-object path. NF08's ACL-filtered text/semantic corpus and P95 first results at most 500 ms still require native integration and optimization; this is not merely missing timing evidence or an approved deferral |
| Accessible workspace | G3 | Exact historical Read, fresh inference, human-edited document and collection handoff, model-disabled manual controls, and human-described visual-reference clarification are implemented. The native editor now retains a real bounded worker lease between literal edits, drains on explicit Freeze, and supports separately authorized durable checkpoints and exact-version resume. Frozen data is not Saved or a renewable session; installed keyboard/screen-reader, cancellation and read/edit/recalculation acceptance remain open |
| Live-content lifecycle | G3, FR30/A061 | Versioned trash/restore, exact lifecycle revisions, separate Read/Delete or Read/Write grants, independent C joins and trash-preserving restore pass scoped software regressions, including all 147 store tests. The subsequent short-response transport and installed authority/GTK journeys remain separately verified. No physical purge, expiry, space reclamation or irreversible erasure is implied |
| Capture and references | G3 | Explicit PNG/PCM/sampled-video controls now include latched lock/bus-loss revocation. Auxiliary Whisper ASR and separately rendered/consented offline readback are implemented; signed ASR model admission and actual installed device/authority qualification remain mandatory. Visual clarification uses human descriptions and exact artifact versions; the current text-only model performs no pixel understanding or OCR |
| Engines and adapters | G3 | Actual bounded C99 build/test receipts, query-only hardware image mediation, typed adapters, original-Admin console, protected dispatch/recovery and active CPU/I/O guards are software-verified: strict all-target check plus 75 hardware and 10 speech tests pass. Installed authority, external application receipts, real hardware effects/recovery and image qualification remain open |
| Windows hosted proof | Current profile-W GWIN0 | Host-protection/policy gates and a distinct opt-in first-account/PAM bootstrap, exact interruption repair, authenticated health and model-disabled original-Windows-user manual console are implemented and software-verified. Installed first-launch/TTY/PAM/health, protection/provider, inference, scoped ingestion, lifecycle/resource coexistence, confinement and two-user proof remain qualification; no native product-grant bridge or GTK desktop is inferred |
| Hyper-V deployment | Deferred development | Complete desktop, explicit identity/resources, verified boot, encrypted data and recovery under W030–W032; installer/template, commissioned vTPM and complete VM proof remain unimplemented/unqualified |
| Windows product integration | GWIN1 | General ordinary-user SID/product-principal and finite-grant integration, enrollment/automation/event queue, adapters, updates, recovery, migration and opt-in background lifecycle beyond the inherited GWIN0 controls |
| Windows release hardening | GWIN2 and production custody | W033 checkpoint/clone rollback reconciliation, all-profile final evidence and custody-root succession. Retaining the commissioned root does not make epoch migration a GWIN0 prerequisite |
| Delivery and evidence | Current G3/GWIN0 and later profile gates | Integrated regressions, exact release inventories and distinct images/packages. G3 installed journeys/held-out quality and GWIN0 inference, scoped ingestion, two-user, confinement and VM proof are current acceptance; later all-profile release acceptance remains separately owned |

Implement and review these as coordinated workstreams against shared identity,
protected UTC, finite grants, resource generations and independent custody.
Neither an editor nor the model receives authority to bypass those controls.
Image assembly follows integration; producing another partial image does not
mark these workstreams complete.

The [latest bounded-job checkpoint](gates/g3/nf08_windows_and_jobs_2026-10-21.json)
adds terminal restore completion, independently verified resumable ingestion
and actual CMS stage tests, with 157 scoped passes and strict production/core
checks. It does not close the native C/physical-allocation joins, remaining
index phases, current-authority search routing or authenticated package
delivery, and does not change the existing disk or Windows package bytes.

The [native desktop package prerequisite](gates/g3/native_package_root_2026-10-20.json)
has now built from the pinned canonical recipe. Its read-only offline check
confirmed 28 installed package states, nine retained input hashes and actual
GTK/WebKit/GStreamer typelib imports. This is a cached build prerequisite,
not the final Luma disk or optical image. The [versioned NF08 design](adr/0014-segmented-content-and-index-generations.md)
documents the required segmented storage, custody continuation and derived
index migration. The [data-foundation record](gates/g3/nf08_foundations_2026-10-20.json)
joins the new bounded formats and index core to scoped software results, and
lists the remaining native producer/consumer contracts. It is explicitly not
an implemented or qualified 100,000-object product path.

## Current development checkpoint

The integration commit `4b5d23d` is pushed. Its current runtime and tests join
the frozen native cut that passed 888 native Python and 39 image tests. A
separate corrected invocation passed all eight UTC release-authentication
checks; the original misconfigured UTC attempt remains retained as failed.
All 219 Rust and literal-include inputs match both the strict hardware/speech
cut and the broader Rust cut. The latter passed 97 content and 135
content-store tests before its overall timeout during platform tests. The
separate platform run then passed 1,279 tests and correctly refused one
fixture configured with a non-private storage root. That same-source test
passed after the runner supplied a mode-0700 disposable storage directory;
the original failed command remains failed in the retained evidence. The
[integration record](gates/g3/integration_regression_2026-10-20.json) retains
the exact evidence joins and limitations.

The wider requirement audit found the NF08 storage/indexing gap above.
Neither this integration checkpoint nor another image closes G3 while that
development is missing. The [held-out quality tool](../scripts/g3_quality.py)
now validates a pinned 500-task external corpus and independently supplied
complete observations, compares retained artifacts against data oracles,
joins explicit human rubric adjudications and reports every attempt, repair,
false refusal, latency, memory and energy measurement. Its 31 regression cases
are synthetic protocol fixtures, not the actual held-out corpus or a product
quality result. The [protocol](gates/g3/QUALITY_PROTOCOL.md) and
[software record](gates/g3/quality_protocol_2026-10-20.json) state its limits:
digest joins do not authenticate native execution, human identity, measurement
origin or release qualification. Persistent editor sessions and the in-progress
live-content lifecycle were not covered by that earlier source cut. The
[subsequent lifecycle record](gates/g3/content_lifecycle_2026-10-20.json) joins
the tested versioned trash/restore implementation, complete 147-test store
suite and scoped native/workspace checks to its exact frozen sources. The
editor and private-response transport are a further integration stage, recorded
in the [editor checkpoint](gates/g3/editor_sessions_2026-10-20.json). Its actual
executable and software tests do not supply installed authority or native-image
qualification.

The integrated source includes typed spreadsheet, document, diagram, animation
and collection editors, exact-version lexical and latent semantic retrieval,
native terminal discovery with independently granted exact-hit reads,
independently pinned raw-to-VHDX conversion and public export, and read-only
Windows deployment planning. Windows authority supports physically admitted
storage and a separately reviewed first-Admin compute request against its
authenticated active distribution, including interrupted-controller recovery
and current authenticated runtime pins. That thirty-second deterministic path
remains separate from the new five-minute compact-inference path. The latter
has an exact publisher-bound Qwen3-4B model/runtime profile, noninteractive
completion worker, continuous authorization/UTC checks and exact-request
cancellation barriers. A completed thirty-second enrolled-file Read can be
explicitly forwarded as user text into a fresh independently reviewed inference
session; no Read receipt becomes inference authority. These are first-Admin
GWIN0 controls, not general ordinary-user product grants. Use the dated
execution records linked from the [implementation register](G3_GWIN0_IMPLEMENTATION.md)
for exact software results and remaining limitations.

The separate schema3 workspace profile now provides original-Admin reviewed
nonroot Linux account creation with real local yescrypt/PAM implementation,
exact interruption repair, protected ninety-day aging and independently
challenged health. The Windows-user manual console offers fresh scoped Read,
independent private whole-snapshot Save, diagnostics, repair and cancel without
requiring a model. It does not launch native GTK or create a general Linux
principal/grant bridge. Its separate setup purpose remains the standard thirty
seconds unless a distinct longer setup approval is granted; the five-minute
model-inference approval is not reused. The [workspace record](gates/gwin0/workspace_bootstrap_2026-10-20.json)
joins 1,191 Windows authority assertions, 162 package assertions, 13 strict
native workspace tests, 60 Python regressions and a real-built-worker/PAM
closure tar validated on both platforms. That unsigned 127.8-MB workspace-only
artifact is not the final combined image, an imported distribution, tested
installed account or production qualification. All gates remain open.

The subsequent [combined package record](gates/gwin0/combined_workspace_inference_2026-10-20.json)
now joins a real 2,710,491,136-byte workspace/inference rootfs, the full pinned
Qwen3-4B model, both runtime dependency manifests and the actual compiled
platform worker. Public archive and all 741 captured source files passed
read-back hash verification; the Windows inspector validated all 225 archive
members and 91 publisher pins. Its 21 Python tests and 170 Windows package
assertions pass. The retained package is under
`D:/LumaOS-builds/gwin-integrated-package-20261020-2fZO16wr-public/package`.
It is unsigned and uninstalled, not qualified or bootable Windows firmware
media. Its executable joins the retained `4b5d23d` source cut, not subsequent
native lifecycle/editor changes. The current WSL AppArmor parameter is `N`;
package inspection cannot substitute for installed enforcing confinement.

The [2026-10-27 refresh record](gates/gwin0/combined_workspace_inference_2026-10-27.json)
recomposes the same profile-W package from the `453ca2e` cut that the
sequence-17 native candidate also froze (954 captured sources, all 396 Rust
files identical to the compiled cut). The exported sequence-17 image was then
built from a re-frozen `55da2e2` cut; that cut changes only
`native/image/Dockerfile.root` and `native/tests/test_speech_input.py`, so no
Rust source differs from the package's compiled cut. The sequence-18 cut at
`4d7fa7c` changes no Rust file either. Source at `e29187b` changes one Rust
file, `rust/luma-platform/src/staging.rs` (its refusal message), so a package
built from that or later source needs its own refresh record. Sequence 19 was
built from `6528ea1`, which includes that change; no GWIN0 refresh from that
cut exists yet. The 2026-10-27
refresh's platform worker uses the workspace
release profile under the approved 8 GiB / 2 CPU assembly bound: 22,120,944
stripped bytes. A debug-profile worker from the same cut measured 75,700,080
bytes, over the unchanged 64 MiB executable cap; that unit is retained as
failed evidence. The 2,636,566,528-byte rootfs passed full public read-back,
21 Python tests, 170 Windows package assertions and production inspection of
225 members and 91 publisher pins. It is under
`D:/LumaOS-builds/gwin-integrated-package-20261027-xD2dTQpC-public/package`.
The 2026-10-20 package remains retained. The refresh is likewise unsigned,
uninstalled and unqualified, and WSL AppArmor is still `N`.

The native workspace has explicit per-turn review and a fresh finite Infer
grant. Native admission checks the reviewed worker/model/input commitment.
Capture remains local data: separately admitted ASR may transcribe a selected
bounded PCM envelope, after which a human reviews/edits the text before any
fresh text Infer. An explicit visual-reference journey selects an exact sample
and human description plus a complete immutable artifact version; actual Read
and later Infer are independent. No pixels, OCR, automatic publication or
machine-verified visual relationship are inferred. The
[collection/workspace checkpoint](gates/g3/collection_workspace_integration_2026-10-20.json)
records 176 workspace, 14 desktop-policy and five actual native structural
checks; ordered authority fixtures are not installed PAM/TPM qualification.

The build contract retains disk UKIs and named partitions. Its optical path
defines a separately signed UKI, bounded read-only CD discovery, verity-backed
root and EFI El Torito assembly with independent namespace, extent and hash
checks. Production-custody requests/checkers require four UKIs and the
bootloader; only installed slots A/B receive Admin PCR approvals. Explicit independent-build resume joins four
external source/public-key pins to the signed root and retained source archive;
the historical pinned repair mode remains the default.

Private converter construction requires protected D-backed ext4 staging;
public Windows-readable export is a separate implemented step, not an exFAT custody
boundary. A real small cross-OS export exercises that mechanism; full desktop
conversion and complete media assembly remain open. The converter/planner does not install or start Hyper-V, commission a TPM,
enroll firmware keys, create a distribution or deliver an installed desktop.
All bulk builds and generated media stay on D; source remains on C. Existing
images and failed-attempt evidence are preserved unless separately retired
under the approved cleanup workflow.

## Decisions and platform dependencies

The owner approved a distinct reviewed five-minute inference purpose on
20 October 2026. Its original deadline includes review, protected UTC,
execution, drainage and result delivery, with no automatic renewal. The
existing thirty-second deterministic-compute purpose is unchanged.

The inference-only resource policy observes at least 5.5 GiB available before
dispatch (4.5 GiB maximum plus a 1-GiB reserve), independently on Windows and
inside the guest. Ongoing supervision requires a 1-GiB low-water reserve on
each side. These observations are not atomic reservations or a guarantee that
other applications cannot change memory use; pressure refuses or interrupts
inference and preserves uncertain-generation recovery. No automatic WSL memory
increase, host reconfiguration, model restart or reduced-security fallback is
performed.

For later production custody, the owner also needs to choose separately
commissioned TPM/NV epoch migration for true root replacement or retention of
the original root with delegated signing-key rotation. This is not a GWIN0
prerequisite while the commissioned root is retained within its admitted bounds.

Compact inference uses a separate lab profile, streamed verified model/runtime
packaging and an executable confined worker. The existing 512-MiB
deterministic-compute purpose is unchanged. The genuine 2,497,280,256-byte
Qwen3-4B Q4_K_M weight is now cached on D and fully verified against the pinned
model-catalog hash. Its completion-only runtime excludes the interactive CLI,
server implementation/program, RPC and GPU plugins. The fixed ChatML user and
assistant framing includes an empty thinking prefill; no system instruction is
inserted, backslash escaping is disabled and raw user bytes retain their exact
request hash. Runtime output is retained verbatim, including its possible
end-of-generation marker; it is never interpreted as commands or authority. On
2026-10-20 the current WSL kernel reports AppArmor disabled; protected guest
execution must refuse until an enforcing platform is qualified. No kernel or
WSL configuration was changed. GWIN0 proof remains open for its current gates
listed above, and G3 user journeys remain open; later production work is not
silently reassigned to either stage.
