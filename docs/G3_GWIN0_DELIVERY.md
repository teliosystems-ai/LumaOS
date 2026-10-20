# G3 and Windows image delivery

The development target is a feature-complete Ubuntu G3 candidate and the
Windows-hosted Luma deployments defined by the governing requirements. The
existing native sequence-16 image remains available for G2/native testing;
subsequent source changes do not alter its bytes or qualify a new release.

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
UKI, read-only discovery, ISO assembly and verification paths are implemented;
full media construction and optical boot acceptance remain unperformed.

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
| Durable content and custody | G3 capacity and later production durability | The deployed owner-generation path still accepts at most 256 committed outcomes and 64 MiB. New unselected v2 map/blob/segment and legacy C-continuation data foundations pass scoped software tests; actual owner-head/C selection, semantic publication, migration and segmented backup/restore integration remain development. Unlimited history, root succession and additional forensics are separate later obligations |
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
