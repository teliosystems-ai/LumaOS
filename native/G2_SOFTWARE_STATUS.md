# G2 software completion register

Updated 2026-09-28. **G2 software is not complete.** This register separates
work that can be executed in the current Windows/Ubuntu WSL/VM environment
from production deployment decisions and physical qualification. It does not
change the frozen reference release, governing requirements, or exit criteria.

Authority: `docs/DEVELOPMENT_PLAN.md`, G2 Ubuntu platform alpha; inherited G1
contracts; the pinned sources in `docs/governing_sources.json`. The full G2
gate still requires the specified E1/E2 executions. A lab signature, source
unit test, default-deny placeholder, or smaller model cannot close a different
requirement.

## Current software inventory and work still required

| Component | Implemented/evaluated scope | Remaining work before software completion |
| --- | --- | --- |
| Installer and media | Real laboratory-signed Ubuntu 24.04 image; explicit disk consent, LUKS2, independent credentials, install-time manual/4B/1.7B choice, pinned model download, byte verification; sequence-4 VM tests passed | Governed production catalog/pack and offline distribution integration, full rejection/interruption matrix; rebuild and re-evaluate subsequent source changes |
| Boot, update, recovery | Signed UKI, A/B verity roots, essential-health acknowledgement, three-attempt fallback, independent export/repair/disable; selected VM faults passed | Complete interruption and migration matrix, including pre-userspace failures; protected production rollback anchors; storage-pressure and recovery-retention cases |
| Temporary storage | New locked, bounded snapshot/download reconciliation; sparse-aware admission and exact-file cleanup; Linux boundary tests in `native/tests` | New-image boot/service and repeated guest-interruption evaluation; operator-reviewed disposition of legacy snapshots, which cannot safely be assumed inactive |
| Model lifecycle and resources | Two pinned CPU profiles; hardware admission, isolated UID, authenticated loopback runtime, systemd memory/device/process restrictions; actual inference and offline reboot passed | Full governed model-pack/catalog lifecycle; atomic resource leases and generations, stale-worker fencing, pressure/quarantine/restart policy; 1,000 **real compact-model** cycles with measured resource return and performance distributions |
| Admin, policy, and effects | Frozen Python contracts and negative tests; native broker verifies kernel peer identity and allows only fixed laboratory operations | Native finite Admin assignment/revocation, authenticated product principals, effect-time grants, integrity-protected durable receipts and reconciliation; current root/sudo operation is not the product Admin service |
| Skills and vertical workflow | Isolated reference worker and manual reference interface | Signed skill registry, native typed-DAG validation/supervision, descriptor-scoped file-read and artifact-write skills, deterministic calculation, cancellation/checkpoint/restart semantics; distributed-image file-to-artifact journey through those interfaces |
| Generated-code isolation | General model-generated shell/native execution is denied | Required microVM or separately qualified constrained runtime and adversarial tests before this capability can be available; a deny-only path is not an implemented execution sandbox |
| Desktop and account lifecycle | Headless console/manual recovery and installer-created distinct accounts | Required model-independent Wayland desktop, credential/account lifecycle and migration tests; current optional Xfce/X11 packaging is neither a qualified desktop nor fulfillment of the Wayland baseline |
| Trust and custody integration | Lab release key, signed image bytes, image-owned lab model catalog, reference trust/checkpoint contracts | Selected protected Admin/checkpoint deployment, authenticated writer identity, trusted time, isolated secrets, key rotation/revocation/recovery and reviewed reconciliation; production signatures require approved real custody |
| Acceptance automation | Reference suites, native source tests, six selected image-specific VM runners | Traceable coverage of every applicable G2 test, fault and performance requirement, not only the existing happy paths and selected negative cases |

The snapshot 1,000-cycle test is **not** the compact-model lifecycle test.
Successful download/inference is **not** signed production pack admission.
Container mount/ENOSPC tests are **not** image boot or physical power-loss tests.

## Execution order

1. Close native storage crash-safety defects and retain executable negative
   tests; integrate startup maintenance without making model availability a
   boot-health dependency. Rebuild/retest before distributing changed binaries.
2. Integrate finite Admin/policy and durable effects with the closed native
   service surface, then the signed skills and local-file-to-artifact journey.
   Reuse the frozen contracts as test oracles, not as a claim that an injected
   Python adapter is already the production Rust implementation.
3. Integrate the complete model lifecycle/resource service and execute actual
   compact-model restart/cancellation/pressure/cleanup measurements. Keep GPU
   and larger configurations unavailable until their checks and evidence exist.
4. Implement and test the Wayland/manual desktop and account lifecycle, then
   complete the boot/update/migration/security fault matrix against rebuilt
   distributed images on virtual disks.
5. Integrate the selected production trust/checkpoint design and public custody
   inputs. Never put production private keys, HMAC secrets, or recovery secrets
   in source, images, chat, logs, or test fixtures.

This is a work inventory, not an authorization to erase a physical disk, enroll
firmware, issue production signatures, or silently change the architecture.

## Owner decision and external inputs

Choose a local TPM2-backed Admin/checkpoint deployment or an external protected
Admin/checkpoint service. Define identity enrollment/recovery, trusted time,
deployment/service namespaces, checkpoint reconciliation and custody operators
for that choice. TPM-backed anchoring does not replace the required production
signing custody or distinct approval roles. Development fixtures can exercise
failure semantics but must remain explicitly non-production.

Separately provide the approved production public catalog/trust inputs,
redistribution approval, independently recoverable signing process and named
approvers/custodian. These are not "physical verification only" blockers.

## Physical qualification retained separately

The two named boards, firmware trust/enrollment, TPM-loss behavior, real GPU
and larger-model tuples, actual power cuts, damaged-media recovery and device/
suspend/resume behavior require approved native hardware. Exact destructive
targets and recovery/firmware approvals are still required. See
`docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md` and
`native/evidence/TEST_IMAGE_2026-09-28.md`.

The previously exported sequence-4 image remains unchanged. Its evidence
cannot be reused as acceptance evidence for subsequent source-only fixes.
The new storage implementation's executed scope and outstanding image tests
are recorded in [the storage checkpoint](evidence/NATIVE_STORAGE_STATUS_2026-09-28.md).
