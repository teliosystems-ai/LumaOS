# G3 and Windows image delivery

The development target is a feature-complete Ubuntu G3 candidate and the
Windows-hosted Luma deployments defined by the governing requirements. The
existing native sequence-16 image remains available for G2/native testing;
subsequent source changes do not alter its bytes or qualify a new release.

## Deliverables

| Deployment | Target deliverable | Required distinction |
| --- | --- | --- |
| Native Ubuntu, profile N | Standalone Ubuntu desktop installation/recovery disk image and independently installable native ISO with complete G3 integration | Installs its own OS; not an application in an existing Ubuntu Server |
| Windows WSL2, profile W | Authenticated Windows companion and separately named product distribution, with a supported package and documented tar fallback | Does not replace the existing Ubuntu distribution or change its default; a WSL package is not bootable firmware media |
| Windows Hyper-V, profile V | Complete Generation 2 desktop deployment, explicit resource limits, verified guest boot, encrypted data and recovery, plus the required ISO | A converted live-installer VHDX is not an installed desktop template or its Windows installer |

The native ISO is explicitly required by `W003` and `W025`. Its distinct optical
UKI, read-only discovery, ISO assembly and verification paths are implemented;
full media construction and optical boot acceptance remain unperformed.

These are Linux-based Luma guests under Windows, not replacement Microsoft
Windows installation media. The question about the intended meaning of
"Windows bootable image" remains open with the owner; shared G3 work and the
governed profile-V foundation can proceed without changing the host.

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
complete VM desktop proof.

| Workstream | Scope | Remaining implementation or qualification |
| --- | --- | --- |
| Durable content and custody | G3 and production durability | Authenticated bounded-journal continuation/compaction, custody/key succession and reviewed forensic recovery beyond the current exact-chain recovery; preserve retained interrupted evidence and outstanding restore reservations |
| Discovery and result policy | G3 | General per-result access policy, private/conversational collection workflows and relevance qualification. Bounded owner-local TF-IDF/LSA indexes rebuild on demand; native GTK and original-terminal discovery support exact selections and genuine typed collections, with a fresh Read ceremony for every selected hit |
| Accessible workspace | G3 | Manual/conversational actions joined to real inference and native workflow authority; private read/edit/recalculation journeys, observed progress/cancellation and keyboard/screen-reader semantics. Typed editors are components, not the whole shell |
| Capture and references | G3 | Explicit speech/image/screen/video input with real permission, visible active indicators, bounded capture and stop/revocation; grounded-reference ambiguity handling |
| Engines and adapters | G3 | Complete application journeys, installed viewers, and authenticated receipts for named LibreOffice/browser, generated-code build/test and allowlisted hardware adapters |
| Windows hosted proof | GWIN0 | Authenticated inference-capable WSL distribution, one scoped host-file ingestion path, lifetime/restart/manual controls, resource coexistence, confinement and two-user isolation; complete Hyper-V desktop with explicit identity/resources, verified boot, encrypted data and recovery |
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
and current authenticated runtime pins. This is inert deterministic compute,
not compact-model inference or ordinary-user product grants. Use the dated
execution records linked from the [implementation register](G3_GWIN0_IMPLEMENTATION.md)
for exact software results and remaining limitations.

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

A distinct reviewed five-minute inference purpose versus the current
thirty-second compute purpose awaits the owner's choice for the actual compact
inference slice. No deadline extension is silently enabled.

For later production custody, the owner also needs to choose separately
commissioned TPM/NV epoch migration for true root replacement or retention of
the original root with delegated signing-key rotation. This is not a GWIN0
prerequisite while the commissioned root is retained within its admitted bounds.

Real compact inference needs a separate signed lab profile, streamed verified
model/runtime packaging and an executable confined worker. The current 512-MiB
deterministic-compute guest is not that implementation. The pinned runtime is
cached, but a genuine cached Qwen3-4B weight has not been established. On
2026-10-20 the current WSL kernel reports AppArmor disabled; protected guest
execution must refuse until an enforcing platform is qualified. No kernel or
WSL configuration was changed. GWIN0 proof remains open for its current gates
listed above, and G3 user journeys remain open; later production work is not
silently reassigned to either stage.
