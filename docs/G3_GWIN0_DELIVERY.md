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

The native ISO is explicitly required by `W003` and `W025`; optical boot support
remains development work for both native and Hyper-V ISO delivery.

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

| Workstream | Implementation to complete before final candidate assembly |
| --- | --- |
| Durable content and custody | Authenticated bounded-journal continuation/compaction, custody/key succession and reviewed forensic recovery beyond the current exact-chain recovery; preserve retained interrupted evidence and outstanding restore reservations |
| Discovery and result policy | General per-result access policy, complete user-facing semantic collection workflows and relevance qualification. Bounded owner-local TF-IDF/LSA indexes now rebuild on demand for exact selections and genuine typed collections; this does not implement cross-owner sharing policy |
| Accessible workspace | Manual/conversational actions joined to real inference and native workflow authority; private read/edit/recalculation journeys, observed progress/cancellation and keyboard/screen-reader semantics. The typed spreadsheet editor is one component, not the whole shell |
| Capture and references | Explicit speech/image/screen/video input with real permission, visible active indicators, bounded capture and stop/revocation; grounded-reference ambiguity handling |
| Engines and adapters | Complete document/table/diagram/animation application journeys, installed viewers, and authenticated receipts for named LibreOffice/browser, generated-code build/test and allowlisted hardware adapters |
| Windows product authority | Authority-key continuation, genuine SID/product-principal and finite-grant integration, ordinary-user scoped ingestion, and complete authenticated product distribution rather than a compute-only guest |
| Windows runtime and desktop | Real WSL inference/manual/lifecycle controls and qualified confinement; Hyper-V creation/identity/storage/recovery workflow, supported verified-boot chain, checkpoint/clone rollback reconciliation against independent host custody, and actual optical-media boot support for the ISO |
| Delivery and evidence | Integrated regressions and adversarial tests, exact release inventories, final distinct images/packages and retained build pins. Actual installed journeys, two-user isolation, held-out quality, hardware and profile acceptance remain the confirmation phase |

Implement and review these as coordinated workstreams against shared identity,
protected UTC, finite grants, resource generations and independent custody.
Neither an editor nor the model receives authority to bypass those controls.
Image assembly follows integration; producing another partial image does not
mark these workstreams complete.

## Current development checkpoint

The integrated source includes typed spreadsheet, document, diagram and
animation editors, exact-version lexical and latent semantic retrieval,
independently pinned raw-to-VHDX conversion and public export, and read-only
Windows deployment planning. Windows authority supports physically admitted
storage and a separately reviewed first-Admin compute request against its
authenticated active distribution, including interrupted-controller recovery
and current authenticated runtime pins. This is inert deterministic compute,
not compact-model inference or ordinary-user product grants. Use the dated
execution records linked from the [implementation register](G3_GWIN0_IMPLEMENTATION.md)
for exact software results and remaining limitations.

The current native boot path uses signed UKIs and named disk partitions; it
does not supply optical-media discovery merely by wrapping a disk image in an
ISO. Private converter construction requires protected D-backed ext4 staging;
public Windows-readable export is a separate implemented step, not an exFAT custody
boundary. A real small cross-OS export exercises that mechanism; full desktop
conversion and optical media remain open. The converter/planner does not install or start Hyper-V, commission a TPM,
enroll firmware keys, create a distribution or deliver an installed desktop.
All bulk builds and generated media stay on D; source remains on C. Existing
images and failed-attempt evidence are preserved unless separately retired
under the approved cleanup workflow.
