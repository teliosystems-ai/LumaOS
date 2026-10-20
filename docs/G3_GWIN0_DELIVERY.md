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
| Durable content and custody | Supported G3 capacity and later production durability | Preserve explicit finite-capacity refusals, interrupted evidence and outstanding restore reservations; continuation/compaction, key succession and forensics beyond the supported exact chain remain recorded production work, not an implied unlimited-history G3 gate |
| Discovery and result policy | G3 | General per-result access policy, private/conversational collection workflows and relevance qualification. Bounded owner-local TF-IDF/LSA indexes rebuild on demand; native GTK and original-terminal discovery support exact selections and genuine typed collections, with a fresh Read ceremony for every selected hit |
| Accessible workspace | G3 | Exact private-read/capture handoff into fresh inference, model-outcome-to-reviewed-editable-draft and independently granted workflow integration; installed read/edit/recalculation, cancellation and keyboard/screen-reader journeys. Native conversation and human-authored workflows already exist |
| Capture and references | G3 | Bounded PNG, PCM audio and sampled portal video capture now have explicit controls, indicators and revocation; installed device/portal enforcement, speech transcription, model consumption and grounded-reference ambiguity handling remain open |
| Engines and adapters | G3 | Installed LibreOffice/browser journey and receipt qualification; source-to-sandboxed-build/test receipts and allowlisted hardware-policy adapter integration. Existing Office export and WebKit presentation are implementations, not absent components |
| Windows hosted proof | Current profile-W GWIN0 | Actual host-encryption/suspended-protection and managed-policy observation, explicit first-launch nonroot user/Admin setup and authenticated health-to-workspace/manual-model-disabled launcher; installed inference, scoped ingestion, lifecycle/resource coexistence, confinement and two-user proof |
| Hyper-V deployment | Deferred development | Complete desktop, explicit identity/resources, verified boot, encrypted data and recovery under W030–W032; installer/template, commissioned vTPM and complete VM proof remain unimplemented/unqualified |
| Windows product integration | GWIN1 | General ordinary-user SID/product-principal and finite-grant integration, enrollment/automation/event queue, adapters, updates, recovery, migration and opt-in background lifecycle beyond the inherited GWIN0 controls |
| Windows release hardening | GWIN2 and production custody | W033 checkpoint/clone rollback reconciliation, all-profile final evidence and custody-root succession. Retaining the commissioned root does not make epoch migration a GWIN0 prerequisite |
| Delivery and evidence | Current G3/GWIN0 and later profile gates | Integrated regressions, exact release inventories and distinct images/packages. G3 installed journeys/held-out quality and GWIN0 inference, scoped ingestion, two-user, confinement and VM proof are current acceptance; later all-profile release acceptance remains separately owned |

Implement and review these as coordinated workstreams against shared identity,
protected UTC, finite grants, resource generations and independent custody.
Neither an editor nor the model receives authority to bypass those controls.
Image assembly follows integration; producing another partial image does not
mark these workstreams complete.

## Current development checkpoint

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

The native workspace now has explicit per-turn conversation review and a fresh
finite Infer grant. The reviewed worker/model/input commitment is checked
inside native admission before effect dispatch. Captured PCM/images/video
remain local data, not transcripts, automatic model input or published content.

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
