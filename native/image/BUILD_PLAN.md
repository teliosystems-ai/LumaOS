# Native Ubuntu image implementation

This work implements the G2 native platform test image requested on 2026-09-27.
The existing Python source release and its detached evidence remain historical
development results. No native image or hardware acceptance is claimed until
the corresponding build and execution records exist.

## Build and execution boundaries

- Ubuntu 24.04 amd64, UEFI, Rust trusted platform code (ADR-0001).
- Separate bootable installation/recovery media and signed installed A/B UKIs.
- Read-only ext4 roots measured with dm-verity; encrypted mutable data with
  independently usable LUKS2 recovery credentials.
- Dedicated laboratory signing material stays in a separate Docker volume and is
  never a production custody claim. Secure Boot enrollment is an operator step.
- Development executes only against newly created virtual disk files. Physical
  installation always needs an exact disk selection and destructive confirmation.
- No firmware enrollment, host service activation, physical disk writes, or
  production key ceremony is part of this build task.

## Implementation sequence and required evidence

1. Isolated, pinned Ubuntu build environment and Rust platform executable.
2. Signed artifact inventory, bounded verification, explicit disk admission and
   executable installer with encryption and unique account creation.
3. UKI/verity boot, inactive-slot update, three-attempt fallback and essential
   health acknowledgement independent of model availability.
4. Linux peer-authenticated service, systemd resource/device restrictions,
   mandatory AppArmor/seccomp policy and denial of unsupported generated code.
5. Offline recovery, encrypted data unlock/export, inactive-slot repair and
   model disablement, without inference.
6. Bootable media assembly, checksums, package/source lock, VM integration and
   negative tests, native Ubuntu operator handoff.

Physical firmware, TPM, accelerator, power-cut, suspend/resume and two-board
qualification stay open. Missing implementations stay open as well; simulated
results cannot change either category to complete.

## Model-enabled continuation

The native installer now contains image-owned Qwen3-4B and Qwen3-1.7B CPU
profiles, explicit manual-only selection, resource admission, pinned HTTPS
acquisition, exact size/hash verification, and activation of an isolated local
runtime. Each produced image still needs its own executed evaluation. The model
runner must pass before a build is described as model-tested. The 1.7B profile
is a development fallback, not fulfillment of the governed 4–6B model tier.

Remaining implementation/acceptance work must not be converted into hardware
deferrals:

- Native Rust policy and finite Admin delegation integrated with durable
  authorization/effect receipts and the complete local-file-to-artifact workflow.
- Protected production writer identity, clock, checkpoint/rollback anchors,
  signing custody, revocation/rotation/recovery, and operational reconciliation.
  Select the deployment design before claiming a production integration. A TPM
  anchor is not a substitute for the approved Ed25519 signing-custody ceremony.
- Full governed model-pack/catalog schemas and lifecycle: atomic leases,
  generation fencing, pressure handling, cleanup evidence and the required
  lifecycle/performance matrix, including qualified larger/GPU profiles.
- Complete boot/update/migration interruption matrix, damaged-media recovery,
  account lifecycle and a qualified model-independent desktop.

Production custody needs owner decisions in
`docs/PRODUCTION_SIGNING_CUSTODY.md`; destructive physical evaluation needs the
exact target/firmware approvals in `docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md`.
Laboratory signing and root/sudo operation do not satisfy those requirements.
