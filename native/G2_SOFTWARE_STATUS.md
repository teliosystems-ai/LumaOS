# G2 software completion register

Updated 2026-10-01. **G2 software is not complete.** This register separates
work that can be executed in the current Windows/Ubuntu WSL/VM environment
from production deployment decisions and physical qualification. It does not
change the frozen reference release, governing requirements, or exit criteria.

Authority: `docs/DEVELOPMENT_PLAN.md`, G2 Ubuntu platform alpha; inherited G1
contracts; the pinned sources in `docs/governing_sources.json`. The full G2
gate still requires the specified E1/E2 executions. A lab signature, source
unit test, default-deny placeholder, or smaller model cannot close a different
requirement.

## Current software inventory and work still required

The [installed-desktop acceptance checkpoint](evidence/G2_DESKTOP_ACCEPTANCE_2026-10-01.md)
adds exact-image verification, a three-stage installed Wayland/GDM-greeter
fixture, software-only virtual display and bounded screenshot evidence.
All 106 native Python tests and a real QMP transport probe passed; that probe
did not boot an OS. The tools build has succeeded and desktop root packaging
is progressing on D:. The frozen greeter evaluation is queued only after
successful export/checksums. It is not yet an installed-desktop pass and does
not cover graphical password login, locking or the full manual workflow.

The [2026-10-01 acceptance checkpoint](evidence/G2_ACCEPTANCE_RESUME_2026-10-01.md)
adds a whole-request inference deadline, explicit bounded emulation options,
failure diagnostics and real poweroff requirements for the remaining follow-up
VM suites. All 93 native Python tests and 55 ordinary Rust tests passed; the
seven specialized Rust functions also passed in separate PAM/software-TPM and
real disk-full export fixtures. Sequence-10 image regression subsequently
**passed all 14 stages**, including eight strict normal shutdowns, atomic
recovery export and installed slow-frame IPC probes, on a fresh D: virtual
disk. Its public evidence is exported beside the image. The first candidate
desktop build failed before assembly due to moving bootstrap OpenSSL packages
conflicting with the pinned snapshot. Both builders now isolate and pin the
CA bootstrap; a real package-install probe passed and a fresh D: desktop build
is running. See [the build/evaluation checkpoint](evidence/G2_BUILD_SNAPSHOT_2026-10-01.md).
The earlier inference failure is not resolved merely by changing its budget.

Earlier image-specific result: sequence 9 passed its four-stage manual install,
installed PAM, measured-credential, cold-reboot, signed A/B continuity and
unapproved-PCR refusal fixture under TCG/Secure Boot/software TPM. Evidence is
exported with the image; see [the sequence-9 checkpoint](evidence/TEST_IMAGE_SEQUENCE9_2026-09-30.md).
Its fresh retry also passed verified late filesystem/DM teardown in every
stage. The initial `/var` unmount warning remains before the initrd completes
cleanup; this is not warning-free or physical shutdown qualification. The
broader 14-stage recovery regression also passed, with eight strict normal
poweroff stages. The resumed model fixture installed the model but subsequently
failed its inference request with a timeout; it is not a model-suite pass.
Full Admin enrollment and
the other software components below remain open.
The [shutdown checkpoint](evidence/NATIVE_SHUTDOWN_2026-09-30.md) records the
repair, source tests and queued strict/broader VM suites; pending tests are not
passes and neither suite closes all G2 requirements.

The native recovery exporter now publishes a completed archive only after
successful tar output and synchronization, retaining failures under `.partial`
without overwriting existing data. Actual Linux producer/ENOSPC tests passed;
this later source repair is **not in sequence 9**. It is in sequence 10, whose
image-level recovery evaluation now passed. See [the export checkpoint](evidence/NATIVE_RECOVERY_EXPORT_2026-09-30.md)
for the earlier source work and the current build/evaluation checkpoint above.

Sequence 10 finished assembly with that exporter and a tested monotonic
whole-frame broker I/O deadline. Its shell driver failed before export after
an in-flight source edit; the retained artifacts passed all checksum checks
and verified export completed without rebuilding. Its test queue stopped when
sequence-9 model inference failed, before sequence-10 guest acceptance started.
That initial queue stop was superseded by the fresh passing regression above;
it does not resolve the model inference failure. See the historical
[build-resumption checkpoint](evidence/NATIVE_BUILD_RESUME_2026-09-30.md).

The candidate desktop now packages GNOME/Wayland, with password-required GDM
restricted to installed boots and no model-service login dependency. A real
isolated software-rendered compositor and Files, Text Editor and Console
passed an unprivileged window/surface smoke test; all 60 native Python tests
passed. This is not installed-image/GDM/session-lifecycle acceptance. The new
desktop is not in the exported sequence-10 headless image. See
[the desktop checkpoint](evidence/NATIVE_WAYLAND_2026-09-30.md).

The C:-backed build-storage limitation is now addressed by a verified dedicated
D:-backed Docker/containerd profile. The code checkout stays on C:, while the
new host profile places bulk build storage and client temporary files on D:
and retains D: image/installer output. A real Docker build, filesystem semantics,
stop/unmount/remount persistence, missing-store refusal and all 75 native Python
tests passed. This is host-storage acceptance, not a new G2 OS-image pass. See
[the setup evidence](evidence/NATIVE_D_BUILD_HOST_2026-09-30.md) and
[operation instructions](host/README.md).

| Component | Implemented/evaluated scope | Remaining work before software completion |
| --- | --- | --- |
| Installer and media | Real laboratory-signed Ubuntu 24.04 image; explicit disk consent, LUKS2, independent credentials, install-time manual/4B/1.7B choice, pinned download; sequence 8 passed pre-write TPM admission, pending enrollment intent and manual installation on a fresh virtual disk | Sealed Admin enrollment and authenticated bootstrap, governed production catalog/pack and offline distribution, full rejection/interruption matrix; rerun actual model acquisition on the new image |
| Boot, update, recovery | Signed UKI, A/B verity roots, essential-health acknowledgement, three-attempt fallback, independent export/repair/disable; sequence 9 passed measured phases, public credential continuity through reboot/signed B, unapproved-PCR refusal and verified late shutdown teardown; sequence 10 passed the 14-stage regression including atomic export and bounded IPC | Complete confined service credential delivery and lifecycle; broaden shutdown/recovery faults; complete interruption and migration matrix, including pre-userspace failures; protected production rollback anchors; storage-pressure and recovery-retention cases |
| Temporary storage | Locked, bounded snapshot/download reconciliation; sparse-aware admission and exact-file cleanup; Linux boundary tests in `native/tests`; sequence 8 verified successful startup maintenance service execution | Repeated guest-interruption/pressure evaluation; operator-reviewed disposition of legacy snapshots, which cannot safely be assumed inactive |
| Model lifecycle and resources | Two pinned CPU profiles; hardware admission, isolated UID, authenticated loopback runtime, systemd memory/device/process restrictions; actual inference and offline reboot passed | Full governed model-pack/catalog lifecycle; atomic resource leases and generations, stale-worker fencing, pressure/quarantine/restart policy; 1,000 **real compact-model** cycles with measured resource return and performance distributions |
| Admin, policy, and effects | Frozen Python contracts and negative tests; native broker verifies kernel peer identity; local TPM2 checkpoint/journal and signed-PCR sealing; native PAM account authentication with real isolated-account tests | Integrate authenticated enrollment/sealed credential delivery, finite Admin assignment/revocation, product principal binding and lifecycle, effect-time grants, durable effect receipts and reconciliation; account authentication and root/sudo operations are not the product Admin service |
| Skills and vertical workflow | Isolated reference worker and manual reference interface | Signed skill registry, native typed-DAG validation/supervision, descriptor-scoped file-read and artifact-write skills, deterministic calculation, cancellation/checkpoint/restart semantics; distributed-image file-to-artifact journey through those interfaces |
| Generated-code isolation | General model-generated shell/native execution is denied | Required microVM or separately qualified constrained runtime and adversarial tests before this capability can be available; a deny-only path is not an implemented execution sandbox |
| Desktop and account lifecycle | Headless console/manual recovery and installer-created distinct accounts; candidate GNOME/Wayland packaging and signed boot-target selection; isolated real compositor/Files/editor/terminal surface smoke passed without a model | Build and boot the desktop image; actual GDM authentication, complete manual file workflow, locking, credential/account lifecycle, migration and model-failure tests; container surface tests do not qualify the installed desktop |
| Trust and custody integration | Lab release key, signed image bytes, image-owned lab model catalog, reference trust/checkpoint contracts; owner selected local TPM2-backed Admin for current installer | Integrate local TPM2 enrollment, authenticated writer identity, trusted UTC, isolated secrets, key rotation/revocation/recovery and reviewed reconciliation; production signatures require approved real custody; external deployment is a future installer variant |
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

## Closed deployment decision and remaining external inputs

The owner selected **local TPM2-backed Admin/checkpoints** for the current
installer. An external protected service is deferred to a **future installer
variant**, not a fallback. See [the local TPM2 implementation note](LOCAL_TPM2_ADMIN.md)
for implemented boundaries and outstanding software integration. Define and
implement identity enrollment/recovery, trusted time, deployment namespaces,
checkpoint reconciliation and custody operators for that choice. TPM-backed
anchoring does not replace the required production
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

## Build history (superseded states retained for traceability)

The paragraphs below describe checkpoints at the time they were recorded.
Use the latest result and inventory at the top for current status: the C: space
blocker and sequence-6/7 failures were subsequently addressed, and sequence 8
completed its scoped fixture. Historical pending text is not a current pass.

The sequence-5 image was built and exported on 2026-09-29 after the owner
reported D: repaired. It includes the later TPM admission, signed-PCR and PAM
changes, but installation evaluation failed; see the
[image checkpoint](evidence/TEST_IMAGE_2026-09-29.md). The initial KVM attempt
failed in QEMU before reaching the live console. TCG boot passed Secure Boot,
verity and AppArmor checks, then exposed a three-second live-payload device
timeout before installation. A live-only, bounded mount fix passed targeted
Linux tests and a sequence-6 rebuild was started. Installed PAM/PCR acceptance
remains unexecuted. Neither image is the final all-components G2 image.

Sequence 6 subsequently completed verified export and passed the live mount
checks. Installation was refused by the native root-owned TPM-device check:
the packaged udev rules instead assign devices to `tss`. An image/initrd
root-only rule and more specific VM assertions passed the full native regression
suite (42 ordinary Rust tests, 20 TPM/6 PAM invocations and 27 Linux Python
tests). Rebuilding is blocked by C: free space below the 8 GiB build minimum;
see the
[sequence-6 checkpoint](evidence/TEST_IMAGE_SEQUENCE6_2026-09-29.md). No
installed-image PAM, credential continuity or all-components G2 pass is claimed.

The owner subsequently freed C: space; sequence 7 (`20260929T194815Z-headless`)
passed the space preflight and is rebuilding with the tested TPM ownership
repair. Export and boot-test results are pending. No prior-image acceptance
is inherited and no G2 requirement is closed merely by starting this build.

Sequence 7 was subsequently rejected by its initrd guard: the rule-copy helper
looked on the build host instead of the target sysroot. The corrected module
passed a read-only retained-root regression. Sequence 8 is building and has
passed the full-kernel initrd guard; a fresh VM run is gated on successful
export. See [the sysroot checkpoint](evidence/NATIVE_INITRD_SYSROOT_2026-09-29.md).

The previously exported sequence-4 image remains unchanged. Its evidence
cannot be reused as acceptance evidence for subsequent source-only fixes.
The new storage implementation's executed scope and outstanding image tests
are recorded in [the storage checkpoint](evidence/NATIVE_STORAGE_STATUS_2026-09-28.md).
The new TPM adapter/journal is likewise source-level software-TPM evidence,
not an installed Admin service or physical qualification; see
[the TPM checkpoint](evidence/NATIVE_TPM_STATUS_2026-09-28.md).
The subsequent [TPM admission checkpoint](evidence/NATIVE_TPM_ADMISSION_2026-09-28.md)
adds read-only installer checks and a persistent QEMU software-TPM fixture.
Its source tests do not establish installed/enrolled Admin or image acceptance.
The [sealed credential checkpoint](evidence/NATIVE_TPM_SEALING_2026-09-29.md)
adds tested fixed-PCR7/signed-PCR11 secret handling, including approved measured
updates without resealing and rejection of replacement TPMs. Authenticated
enrollment, signer lifecycle, service confinement and image integration remain
software work; this primitive does not activate product Admin.
The subsequent [UKI policy checkpoint](evidence/NATIVE_UKI_POLICY_2026-09-29.md)
adds installed A/B PCR signatures to the image builder and verifies artifact
measurements against software-TPM event replay, including A/B credential
continuity. It is not firmware/guest-boot evidence or complete enrollment.
The [account authentication checkpoint](evidence/NATIVE_ADMIN_AUTH_2026-09-29.md)
adds a root-invoked, non-setuid PAM helper and controlling-terminal diagnostic.
It authenticates an account but neither enrolls it nor assigns the product Admin
role. No all-components final image or G2 pass is established by these tests.
