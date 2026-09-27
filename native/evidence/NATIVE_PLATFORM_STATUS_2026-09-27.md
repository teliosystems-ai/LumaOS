# Native platform implementation checkpoint — 2026-09-27

Status: development in progress; G2 has not passed. This is an additive native
platform checkpoint, not a replacement for the historical Python `0.1.0` source
release or its `-004` detached attestations. Statements about absent native
implementations in those earlier records describe that earlier tranche.

The native implementation and its build/operator instructions are in
[`native/image/README.md`](../image/README.md), with Rust
source under `rust/luma-platform`. The image is Ubuntu 24.04 amd64, UEFI,
headless, laboratory-signed and manual-only. It is not an ISO, production
release, qualified desktop, or completed G2 product.

## Implemented paths under evaluation

| Area | Native implementation | Acceptance still required |
| --- | --- | --- |
| Installer | Signed artifact snapshots, exact by-id disk confirmation, GPT, A/B root/hash writes with read-back, LUKS2, independent recovery credential and distinct accounts; VM suite passed | Physical installation and complete governed model/policy admission |
| Boot/update | Signed UKIs/systemd-boot, dm-verity, read-only roots, encrypted state, counted trials, essential health acknowledgement; both VM fallback paths and higher-sequence update passed | Physical firmware, interruption and lifecycle matrix |
| Security | Rust local broker, kernel peer credentials, fixed operations, AppArmor, systemd seccomp/device restrictions, cgroup memory/process limits | Native contract integration, protected production authority/anchors and the complete adversarial/hardware matrix |
| Recovery | Independent unlock, read-only export, automatic ext4 repair, root/hash/UKI slot repair, worker disablement; VM data-preservation and repaired-boot checks passed | Physical recovery and damaged-media/TPM-loss qualification |

Only image-specific execution records can mark individual checks passed.
Building a binary or providing a test script is not a passing evaluation.
Failed runs remain diagnostic evidence and do not count as accepted tests.

## Defects found by actual VM execution

Superseded candidates are not approved images. Their failures drove the
following corrections; only a subsequent complete run can accept the fixes.

- Installation: explicit tree-shaped disk inventory; partition-parent lookup
  through sysfs; separate operation locks which do not deadlock udev; bounded
  `BLKRRPART` retries on the retained target descriptor after udev settlement.
- Boot: boot-mode-specific systemd dependency generation; verity status parsing;
  uncounted-boot health handling; a trial-default pattern excluding exhausted
  entries; exact healthy-entry selection after acknowledgement.
- Integrity failure: corrupted root metadata was refused but initially left
  initramfs waiting. The signed command line now requests a kernel panic and
  bounded reboot on dm-verity corruption.
- Recovery and durability: preserved template ownership, independent data
  repair/journal replay, private staging outside small `/run`, and cleanup of
  failed atomic-write temporary files.
- Test harness: continuous console draining during shutdown, bounded complete
  error capture, persistent virtual NVRAM, and retained image-specific logs.

The corrected boot-default pattern was separately exercised against an overlay
of a failed installation: exactly three failed trials selected slot B and the
saved user file remained readable. That diagnostic then exposed the separate
uncounted-boot health error; it is not recorded as a complete suite pass.

## Remaining software work — not hardware deferrals

- Connect the frozen policy, finite Admin delegation, authenticated durable
  authorization/effect contracts, and model supervision to the trusted Rust
  paths. The current local root/sudo operator is not that production service.
- Connect installation-time model selection and resource admission to the
  native installer; package approved signed offline model/runtime assets.
  This image deliberately installs no weights and advertises manual-only mode.
- Implement protected production rollback/checkpoint and signing-key lifecycle
  integrations, trusted-time/custody operations and operational reconciliation.
  Laboratory keys and a data-volume sequence comparison do not provide these.
- Complete boot/update interruption, migration, lifecycle and adversarial
  coverage, including failures before userspace health evaluation. Three
  counted health-failure reboots are not all possible boot-failure cases.
- Qualify account/credential lifecycle, desktop, accelerator/model execution,
  and the full authorized local-file-to-artifact workflow. None is implied by
  passing the headless platform tests.

## Native-machine handoff

The first physical run needs an amd64 UEFI machine, a separate disposable target
disk, a separate installer USB and protected evidence/recovery storage. Start
with a VM on the native Ubuntu host. Physical erasure, firmware key enrollment
and deliberate power interruption require the owner's exact target approval.
No physical disk or firmware was modified during development.

Follow the native operator guide for image verification and execution. The
existing [`PHYSICAL_QUALIFICATION_RUNBOOK.md`](../../docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md)
still governs E1/E2 designation, approval, security review, physical evidence
and final sign-off. Its historical implementation-absence statements must not
be used as the current native-component inventory.

## Delivery and executed evaluation

Implementation commit: `8201727c51931b9e5a227af9a5073d4b5e0bfed4`.

Artifact folder: `dist/native/20260927T131227Z-headless/`.
Image: `luma-native-lab-20260927-headless-1.img.zst` — 2,125,682,095 bytes
(about 1.98 GiB), decompressing to 11,895,046,144 bytes (about 11.1 GiB).

- Compressed SHA-256: `ef21ab09a4fafacf0c4c10220048e37d2fc2a70ec34265dfdeb3ae90c16e4125`.
- Raw image SHA-256: `b4e6b304a51444b6ac56ade16977cf0c24a735e088d355a30fd8a26f42d4c5e4`.
- Kernel: `6.8.0-142-generic`; Ubuntu 24.04 amd64 headless.
- All 93 captured build-input files matched the source bytes before component
  relocation; the image is bound to implementation commit `8201727` and its
  included source archive. Subsequent tooling relocation does not rebuild or
  change the delivered image.

The [machine-readable execution record](native_platform_2026-09-27.json)
binds results and exported log inventories to this exact image. The artifact
folder includes the checksums, public certificate, signed release metadata,
source archive, package/source locks and the following evidence folders:

| Evidence | Executed result | Boundary |
| --- | --- | --- |
| `evidence-full` | Passed all 14 stages: installation, encrypted boot, negative broker/AppArmor checks, three health-failure trials, fallback, independent recovery/export/disable/repair, three corrupted-root trials, good-slot fallback, corrupted-slot repair and repaired boot | QEMU/KVM virtual hardware, Secure Boot disabled |
| `evidence-secure-boot` | Signed live boot passed; firmware Secure Boot flag was 1; verity, AppArmor and services active | QEMU/TCG virtual firmware; live-boot smoke only, not installation |
| `evidence-unsigned-refusal` | Virtual firmware rejected an unsigned bootloader copy | QEMU/TCG; original image unchanged |
| `evidence-update` | Signed sequence-2 update staged to the inactive slot, booted and was acknowledged; user data and worker-disable state survived; older sequence refused | QEMU/KVM; overlay of the passed installed fixture, not power-cut or protected anti-rollback qualification |

The separately exported update fixture is
`dist/native/20260927T151628Z-headless/luma-native-lab-20260927-headless-2.img.zst`
(2,125,121,134 bytes), compressed SHA-256
`102883e2e805a2cd665a4973c9217f347ef32d815c0ac73371ff884642508afc`.
It passed as an update from the primary image, not as a separately qualified
fresh installation. Transfer both complete artifact folders if repeating the
update test; private signing keys are neither needed nor included.

The Secure Boot smoke runner retains the internal stage name `install`, but
its record explicitly says `installation_tested: false`. No Secure Boot
installation pass is inferred from that stage label. The immutable `build.json`
reports the build-time state; subsequent evaluation is in the separate records.

The 320-test reference suite passed on Windows (five skips) and Ubuntu WSL
(one skip); all 12 native Rust tests passed. Remote CI has not been run here.

This image is suitable for supervised **laboratory evaluation**, starting with
the transferred-image VM instructions. It is not a claim that all requested G2
software is complete. The remaining software work above and the physical-board
acceptance matrix remain open; destructive physical testing still requires
the owner's exact disk and firmware approvals.

## Repository component boundary

The native image tooling and its evidence now live under `native/`, alongside
`rust/`, outside the historical Python release inventory. This fixes the
post-commit repository packaging check without changing that 170-file release
or its detached `-004` records. The image's source archive preserves the original
`packaging/native/` paths from implementation commit `8201727`; current operator
commands use `native/image/`. Runtime Rust/overlay bytes and VM test logic are
unchanged by this relocation. Dedicated native CI covers the new component;
passing the historical Python suite alone does not validate the native image.
