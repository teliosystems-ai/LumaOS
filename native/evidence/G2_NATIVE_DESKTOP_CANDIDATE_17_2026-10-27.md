# Native desktop candidate 17: operator handoff

## Status and exact artifacts

The laboratory-signed Ubuntu desktop disk image and its separate optical
live/installer ISO were assembled and exported on 2026-10-27.
All 14 offline image checks passed, and a software-emulated UEFI Secure Boot
live smoke of the disk image passed, including verified storage teardown at
power-off. **The sequence-17 ISO does not boot**: in its software-emulated
Secure Boot optical smoke the initrd discovery unit failed, so the verity root
was never assembled (see [the ISO section](#optical-liveinstaller-iso)).
For sequence 17, test the `.img` from USB only.
Installation, graphical/installed acceptance and physical/native
qualification remain pending. This record does not close G2, G3 or GWIN0, or
claim production certification. The
[execution record](candidate17_execution_2026-10-27.json) binds the actual
results, logs, source and artifact hashes; the
[executed offline verifier](candidate17_image_verify_2026_10_27.py) and its
[adapter audit](candidate17_verifier_adapter_audit_2026_10_27.py) are retained
unchanged, as are the [optical smoke harness](candidate17_optical_smoke_2026_10_27.py)
and the [diagnostic harness](candidate17_optical_diagnostic_2026_10_27.py) with
its [run wrapper](candidate17_optical_diagnostic_run_2026_10_27.sh). Do not substitute an earlier failed build or verifier attempt for
this candidate's results.

Export directory: `D:/LumaOS-builds/native/20261027T132536Z-desktop`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `luma-native-lab-20260927-desktop-17.img.zst` | 3,690,945,062 | `201f66662307e8373f75f9a50be742bbd92123600ef1a57f9b93c2ba4eb9070d` |
| `luma-native-lab-20260927-desktop-17.img` after decompression | 16,190,013,440 | `24b8ef41eda9932b6d43914b7ea7671e8977595f4c6f79cde1c08adf14f27774` |
| `luma-native-lab-20260927-desktop-17.iso` | 7,225,755,648 | `58bf1cb3b518ad2f9dfeb8cd881c85bf48a4768d0baca1ef5204bc618e07b760` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |

The build uses commit `55da2e2`, source cut b: 877 captured files, manifest
SHA-256 `f4198f999a3cf75a51b753b02c22a2324bc85001a17c53f4ceec0db7b6f4b756`.
The 727-file product source lock is
`eae1b551205ab149bf134e742869c4e21994ee33c94ab3a67861f95421e3a143`.
The signed verity root hash is
`e02c9495eb837a4f65823c32415e43f69aee49659677183c68c91ee4c5b3329f` with
kernel `6.8.0-142-generic`. These identify inputs, not native acceptance or
independently commissioned trust.

Compared with sequence 16, this image carries the G3/GWIN0 source integrated
through `4acc3a0` (direct paged custody, data observer, index review and the
bounded workbook model), query-only hardware writer mediation, explicit
audio/video input capture, the Whisper tiny ASR runtime and pinned weight, and
the optical ISO. `build.json` records each as present but unqualified: device
permissions, ASR model authority and language accuracy, installed hardware
effects and optical boot are not qualified by this candidate.

**The D: USB disk that holds this export reports bad blocks and "Full Repair
Needed".** Copy the export to sound storage promptly and treat only a copy whose
`SHA256SUMS` check passes as the artifact.

## Prepare the Ubuntu test machine

The disk image is a **standalone Ubuntu 24.04 amd64 UEFI operating-system disk
image**, not an application installed into an existing Ubuntu server, a
Windows image, or a dual-boot installer. Installing it erases the selected
target disk. Use a separate disposable machine/disk; preserve the existing
Ubuntu system and unrelated disks by disconnecting them where practical.

Have:

- A 32 GB or larger USB stick for the disk-image installer, distinct from the
  target; or the optical media described below.
- A disposable target of at least 32 GiB; 64 GiB or larger is recommended.
- At least 8 GiB RAM; 16 GiB is practical for desktop installation and model tests.
  Admission rechecks actual available RAM, CPUs and storage; nominal RAM alone
  does not guarantee acceptance.
- At least 32 GiB free working-copy space on the Ubuntu host, in addition to the
  USB and target capacities. Keep the original compressed export intact.
- Local TPM2 support with its existing owner/custodian available, recovery
  material stored separately, and wired networking or another working network
  for model downloads and the commissioned protected-time dependencies.

Transfer **all files in the export directory**, including `SHA256SUMS`, the ISO,
public certificate, source archive and release records, into a new private
Ubuntu working directory named `~/luma-native-desktop-17-test`. Do not transfer
the private Docker volume `luma-native-lab-keys` or any private signing key.

From that working copy:

```sh
(
set -eu
cd "$HOME/luma-native-desktop-17-test"
printf '%s  %s\n' \
  201f66662307e8373f75f9a50be742bbd92123600ef1a57f9b93c2ba4eb9070d \
  luma-native-lab-20260927-desktop-17.img.zst \
  58bf1cb3b518ad2f9dfeb8cd881c85bf48a4768d0baca1ef5204bc618e07b760 \
  luma-native-lab-20260927-desktop-17.iso \
  2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8 \
  secureboot.cer | sha256sum --check -
zstd -d -- luma-native-lab-20260927-desktop-17.img.zst
sha256sum --check SHA256SUMS
)
```

Stop on any error. Decompression does not overwrite an existing raw image.
The complete checksum check is deliberately after decompression because the
inventory includes both compressed and raw images.

In Ubuntu Disks, select the USB by its actual model, serial and capacity, then
use **Restore Disk Image** with the verified `.img`. Manually confirm that this
is the disposable installer USB, not the Ubuntu host disk or installation
target. This erases the USB; no raw-device write command is supplied here.

## Optical live/installer ISO

> **Do not burn or boot the sequence-17 ISO.** It fails in the initrd; the
> known defect is described at the end of this section. Use the `.img`.

The ISO is a separate, independently identified boot medium for the same
signed root. It is ISO9660 with a single EFI El Torito entry: UEFI only, no
legacy BIOS entry and **no hybrid USB boot path**. Writing the ISO to a USB
stick is not a supported boot method; use the `.img` for USB.

At 7,225,755,648 bytes it does not fit single-layer DVD. Use one of:

- A **DVD+R DL** (dual-layer, about 8.5 GB) disc written with the burning
  tool's verify-after-write option, in a UEFI-bootable optical drive; or
- **Virtual CD media**: a virtual machine's CD-ROM device on the Ubuntu test
  host, or a server BMC's virtual-media CD.

Its firmware-authenticated optical UKI
(`e7d98226aa16365a2d667af7680abf028b646f8776e0f8ffa59845143400f10c`) mounts the
disc read-only and exposes `root.ext4` and `root.verity` through read-only loop
devices to the normal verity root; the signed root hash, not the disc label, is
root authority. **Exactly one CD-ROM-class device must be present.** A second
optical drive, including an empty or virtual one, makes the initrd refuse to
boot rather than guess. The optical slot receives no installed Admin PCR
approval. Enroll `secureboot.cer` exactly as for the disk image below.

**Known defect: the sequence-17 ISO does not boot.** In the disposable
software-emulated Secure Boot optical smoke, the firmware verified and started
the optical UKI and the kernel detected the CD, but `luma-optical.service`
failed: its script sourced dracut's shell library under `set -u`, which aborts
on an unset dracut variable outside dracut's own hooks. Verity setup was
therefore skipped, the initrd waited for `/dev/mapper/root` until its timeout
and the VM halted at about 325 seconds without reaching a shell. The disk image
is unaffected: this unit runs only on the optical command line. The script is
fixed in source. A later software-only diagnostic booted the same kernel with
the fixed script and this ISO by direct kernel boot, without Secure Boot; it is
diagnostic evidence, not evidence for this image. Discovery then reached a
verified root and a shell. It also found a second optical-only defect, now fixed
in source: the udev rule that names the two read-only loop devices was installed
only into the initrd, so after switch-root `systemd-veritysetup@root.service`
waited 90 seconds for `/dev/luma-optical-hash` and was marked failed, although
the verified root kept running. **Do not use this ISO.** A bootable ISO still
requires a new signed build and a passing signed optical smoke. Verifying the
signed media from inside a live optical session needs the 6-GiB evaluation
memory: in the 4-GiB diagnostic guest, `luma-platform verify /media/luma`
refused, as designed, for lack of RAM-backed staging.

## Firmware and existing TPM ownership

For Secure Boot testing, enroll only the identified public laboratory
`secureboot.cer` into the test firmware's UEFI `db` using the machine vendor's
supported procedure and owner approval. Back up its existing key configuration;
preserve vendor PK/KEK/db keys. MOK enrollment is not a substitute for trusting
this directly booted systemd-boot image. Do not clear firmware keys, silently
disable Secure Boot, clear the TPM, change its ownership, or overwrite occupied
NV indexes. If the certificate cannot be enrolled, record Secure Boot as
untested and obtain explicit approval for a separate non-Secure-Boot test.

Boot the USB (or the optical medium) through the UEFI boot menu. Its
live/recovery console, not a live graphical desktop, is the installer
interface. Read-only preliminary checks are:

```sh
luma-platform inventory
luma-platform tpm-probe
luma-platform admin-install-check
luma-platform verify /media/luma
```

Missing TPM support, occupied allocations or failed admission must be
investigated, not bypassed. These commands do not enroll product Admin.

## Install with verified, inert model staging

Select the actual whole-disk stable ID from inventory. In the command below,
`EXACT-TARGET-DISK-ID` must be replaced with that reviewed disposable disk's
real `/dev/disk/by-id/` name; it is not a literal disk name or an assumed
`/dev/sdX` ordering:

```sh
luma-platform install /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma --stage-model qwen3-4b-q4-k-m
```

Inspect the displayed serial, WWN and size before entering the exact requested
`ERASE <identity>` confirmation. The installer refuses mounted/unstably
identified targets. Do not run competing privileged disk tools during the test.
Installation from the optical medium uses the same command against its
read-only `/media/luma` binding; it has not been exercised and is part of the
test, not an established path.

The smaller supported choice is `--stage-model qwen3-1-7b-q4-k-m`; omit weights
with `--stage-model manual-only`. Staging downloads pinned GGUF bytes, verifies
their exact length/digest, and keeps normal model serving disabled. It does not
automatically activate, qualify or authorize inference.

| CPU profile | Download bytes | Total RAM floor | Available RAM needed for serving |
| --- | ---: | ---: | ---: |
| Qwen3-4B Q4_K_M | 2,497,280,256 | 6,100,000,000 bytes | 4.5 GiB |
| Qwen3-1.7B Q4_K_M | 1,107,408,544 | 4,000,000,000 bytes | 2.5 GiB |

Both require two CPUs and model download size plus 2 GiB free encrypted storage.
Inert staging separately requires at least 1 GiB available for its bounded
worker; live installer bundle staging has additional RAM overhead. The packaged
runtime is CPU-only. This candidate does not claim GPU inference, Gemma support,
large-model readiness, or that the 1.7B profile meets the governed 4–6B tier.

Create the separate Unix user/administrator accounts and four new credentials
requested by installation: user password, administrator password, data
passphrase and independent disk-recovery passphrase, each at least 16
characters. Keep recovery material off-device; do not put it in logs or chat.
After successful installation, remove the installer medium and boot the target
through UEFI.

## First installed boot and governed setup

Unlock data, log in, and retain these observations before enabling optional
workloads:

```sh
sudo luma-platform boot-health
sudo systemctl --failed
sudo systemctl status luma-broker luma-reference luma-boot-health
sudo veritysetup status root
sudo cryptsetup status luma-data
```

Model availability is not a boot-health prerequisite. Check the actual GNOME
Wayland login, manual workspace, logout/login, screen lock, reboot and shutdown.
The main workspace uses a fixed ELF launcher and its named AppArmor userns
compatibility profile; packaged files do not prove a loaded profile, successful
WebKit sandbox startup or complete application confinement.

A Unix sudo account is **not automatically product Admin**. Follow the reviewed
ceremonies in [local TPM2 Admin](../LOCAL_TPM2_ADMIN.md),
[independent resource checkpoint custody](../RESOURCE_CHECKPOINT_CUSTODY.md),
[protected UTC design](../TRUSTED_UTC_DESIGN.md),
[pinned UTC runtime](../image/utc/README.md), and the current
[native custody/recovery integration](../../docs/G3_GWIN0_IMPLEMENTATION.md#native-custody-utc-and-encrypted-recovery).
Commission the original product Admin, separate R/resource and C/content
authorities, required U/UTC publisher custody, authenticated seed/history and
protected-time delivery, and the exact finite grants for each intended action.
No installation flag, catalog ID, OS synchronization indicator or copied receipt
substitutes for those authorities. Preserve the distinct Admin recovery
credential and offline recipient material; they are not the disk passphrase.

This image requires genuine C checkpoint authority even though its release is
lab-signed. Missing custody, protected UTC, grants or current resource admission
must refuse governed operations; there is no laboratory-file authority fallback.
Audio/video capture and speech transcription additionally need explicit device
permission and separately provisioned ASR model authority; their presence in
the image grants neither. Test explicit model QA/activation only through the
separately reviewed flows in the [image guide](../image/README.md), after their
actual prerequisites pass. Do not run `apt upgrade` against the immutable root
or weaken checks to make a test succeed.

## Test record and remaining boundaries

Retain image/source pins, machine and firmware inventory, target identity and
consent, serial/console logs, boot/slot counters, actual loaded confinement and
resource observations, and success/refusal/recovery outcomes. Exercise Secure
Boot and verity rejection, account/session revocation, manual/model-disabled
operation, model admission/cancellation, A/B fallback and offline recovery using
the [physical test and recovery instructions](../image/README.md#physical-test-machine-preparation).
Use disposable data and separate export storage; the low-level offline disk
recovery export is unencrypted and must not be confused with governed encrypted
content backup. Do not publish passwords, recovery keys or user-data archives.

Physical testing is not the only remaining development boundary. The NF08
100,000-object/500-ms discovery path, native C activation with physical
tails/accounting, authenticated snapshot delivery and installed restore remain
development, as do broader G3 application, adapter/capture journeys and GWIN0
principal/grant/inference integration. See the
[development plan](../../docs/DEVELOPMENT_PLAN.md) and
[G3/GWIN0 implementation record](../../docs/G3_GWIN0_IMPLEMENTATION.md#remaining-development-and-qualification).

The disk-image VM test used the unchanged sequence-16 fixture with a fresh
virtual firmware store, software TPM and disposable disk; it accessed no
physical disk, firmware or TPM, and the read-only image hash was rechecked
afterwards. It checked the live broker and reference services, verity root,
reference AppArmor enforcement, actual guest Secure Boot state, media mount and
TPM probe. Its stage is named `install`, but `--smoke-only` performed no
installation. During poweroff, as in sequence 16, systemd first reported that
`/var` could not be unmounted; the later dracut teardown unmounted the old root
and emitted the required `LUMA_SHUTDOWN_STORAGE_CLEAN` marker before QEMU
exited successfully. This is not evidence that every service shut down without
warnings or that encrypted installed-data recovery passed.

**Known issue in this image: a boot ordering cycle.** The sequence-16 and
sequence-17 disk smokes and the sequence-17 optical diagnostic each print
`Ordering cycle found, skipping …` on the console.
Each UTC producer path unit is ordered after its keeper service, which by
default waits for `basic.target`; as a default path unit it is also ordered
before `paths.target`, which `basic.target` waits for. systemd breaks the loop
by dropping one start job, and which one varies: `paths.target` in this disk
smoke, `luma-utc-recovery-producer.path` in the optical diagnostic and
`luma-utc-producer.path` in sequence 16. When a producer path is dropped,
authenticated network time does not start in that boot. The cause is fixed in
source for the next build. Testers should record which unit the line names. In
the optical diagnostic, `luma-utc-recovery-keeper.service` was also listed as
failed; its cause was not captured and remains open.

Final native machine acceptance must be recorded with its actual results before
any stronger readiness claim. The immutable exported `build.json` retains its
assembly-time `built-not-yet-boot-tested` status; the separate execution record
records the later limited VM tests without rewriting signed/exported evidence.
