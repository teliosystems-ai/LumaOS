# Native desktop candidate 19: operator handoff

## Status and exact artifacts

The laboratory-signed Ubuntu desktop disk image and its separate optical
live/installer ISO were assembled and exported on 2026-10-28.
All 14 offline image checks passed. Software-emulated UEFI Secure Boot live
smokes of **both** media passed, each including verified storage teardown at
power-off. Sequence 19 is the first sequence in which both the disk image and
the ISO passed their smokes: in the 8 GiB optical smoke all ten required and
all five gated checks passed, including no failed units, an active recovery
keeper and producer path, and a complete `luma-platform verify /media/luma` of
the signed media (see [the ISO section](#optical-liveinstaller-iso)).
Installation, graphical/installed acceptance and physical/native
qualification remain pending. This record does not close G2, G3 or GWIN0, or
claim production certification. The
[execution record](candidate19_execution_2026-10-28.json) binds the actual
results, logs, source and artifact hashes; the
[executed offline verifier](candidate19_image_verify_2026_10_28.py), its
[adapter audit](candidate17_verifier_adapter_audit_2026_10_27.py), the
[optical smoke harness](candidate19_optical_smoke_2026_10_28.py) and the
[staging payload measurement](candidate19_payload_measure_2026_10_28.py) are
retained unchanged. Do not substitute an earlier failed build or verifier
attempt for this candidate's results.

Export directory: `D:/LumaOS-builds/native/20261028T162354Z-desktop`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `luma-native-lab-20260927-desktop-19.img.zst` | 3,690,965,526 | `bc74f083a7b5a22a5106da8b79dcd906197daf77a9a17a8a3c926a37fc249276` |
| `luma-native-lab-20260927-desktop-19.img` after decompression | 16,190,013,440 | `082337e4d206f1edd31bdfb44912f93e1b10726d02b5d60a150267674a101756` |
| `luma-native-lab-20260927-desktop-19.iso` | 7,225,784,320 | `a4fbfec8eb760ffae246eb85567c15e47314e89e300836cc0c7422fedef11ca5` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |

The build uses commit `6528ea1`, source cut `candidate19-source-20261028-a`:
880 captured files, build-inputs SHA-256
`7d05afd79e9e26ed689c3d5c4ed6764da037f6aa21bab1a94546ca8087252be8`.
The 729-file product source lock is
`f452c120e3a883dbaf563d2894fb0d7df431a5bfe7a0248946393f3c04256578`.
The signed verity root hash is
`fd483804050457bcb6a1f183f4c333a636b2bac5b0573ac03064fd11b79b83fb` with
kernel `6.8.0-142-generic`. These identify inputs, not native acceptance or
independently commissioned trust.

Compared with sequence 18's product source, sequence 19 adds two tmpfiles
rules that create the masked `/run` namespace paths at every boot
(`luma-governance.conf`, `luma-runtime-masks.conf`), changes
`luma-admin.service` so it no longer owns `/run/luma-governance` as a runtime
directory, and changes the live-staging refusal in
`rust/luma-platform/src/staging.rs` to state the RAM the payload needs. The VM
fixtures and image guide changed for the 8 GiB desktop evaluation memory.
Staging admission itself is unchanged. The packaged platform binary is
therefore new
(`7b05289eeddd900813ede087ab78c2ed379697acb38b39cd433dcbe32f318708`). The
feature content is otherwise that of sequences 17 and 18: the G3/GWIN0 source
integrated through `4acc3a0`, query-only hardware writer mediation, explicit
audio/video input capture, the Whisper tiny ASR runtime and pinned weight, and
the optical ISO. `build.json` records each as present but unqualified.

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
  target.
- A disposable target of at least 32 GiB; 64 GiB or larger is recommended.
- **At least 8 GiB RAM.** The live session keeps `/var` in RAM, sized at half of
  physical memory, and verifying or installing from the live medium stages the
  signed payload there plus a 64 MiB reserve. Sequence 19's payload stages
  3,462,041,600 bytes, so it needs more than 6,732 MiB of RAM; an 8 GiB VM
  staged and verified it. Staging also requires the payload plus 2 GiB of
  available memory. 16 GiB is practical for desktop installation and model
  tests. Admission rechecks actual
  available RAM, CPUs and storage; nominal RAM alone does not guarantee
  acceptance.
- At least 32 GiB free working-copy space on the Ubuntu host, in addition to the
  USB and target capacities. Keep the original compressed export intact.
- Local TPM2 support with its existing owner/custodian available, recovery
  material stored separately, and wired networking or another working network
  for model downloads and the commissioned protected-time dependencies.

Transfer **all files in the export directory**, including `SHA256SUMS`, the ISO,
public certificate, source archive and release records, into a new private
Ubuntu working directory named `~/luma-native-desktop-19-test`. Do not transfer
the private Docker volume `luma-native-lab-keys` or any private signing key.

From that working copy:

```sh
(
set -eu
cd "$HOME/luma-native-desktop-19-test"
printf '%s  %s\n' \
  bc74f083a7b5a22a5106da8b79dcd906197daf77a9a17a8a3c926a37fc249276 \
  luma-native-lab-20260927-desktop-19.img.zst \
  a4fbfec8eb760ffae246eb85567c15e47314e89e300836cc0c7422fedef11ca5 \
  luma-native-lab-20260927-desktop-19.iso \
  2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8 \
  secureboot.cer | sha256sum --check -
zstd -d -- luma-native-lab-20260927-desktop-19.img.zst
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

> **The sequence-19 ISO passed its signed optical smoke.** Use it for live boot
> and signed-media verification testing. Installation from the ISO has not been
> exercised; like installation from the `.img`, it is part of the test.

The ISO is a separate, independently identified boot medium for the same
signed root. It is ISO9660 with a single EFI El Torito entry: UEFI only, no
legacy BIOS entry and **no hybrid USB boot path**. Writing the ISO to a USB
stick is not a supported boot method; use the `.img` for USB.

At 7,225,784,320 bytes it does not fit single-layer DVD. Use one of:

- A **DVD+R DL** (dual-layer, about 8.5 GB) disc written with the burning
  tool's verify-after-write option, in a UEFI-bootable optical drive; or
- **Virtual CD media**: a virtual machine's CD-ROM device on the Ubuntu test
  host, or a server BMC's virtual-media CD.

Its firmware-authenticated optical UKI
(`caf482470478365a7c6321b5f37d8e9e15ebea66f7bc1489c22a1a6e5e1cd727`) mounts the
disc read-only and exposes `root.ext4` and `root.verity` through read-only loop
devices to the normal verity root; the signed root hash, not the disc label, is
root authority. **Exactly one CD-ROM-class device must be present.** A second
optical drive, including an empty or virtual one, makes the initrd refuse to
boot rather than guess. The optical slot receives no installed Admin PCR
approval. Enroll `secureboot.cer` exactly as for the disk image below. A
machine or VM booting the ISO needs at least 8 GiB of RAM for live
verification and installation.

**What the signed optical smoke showed.** It ran in a disposable software
emulator (QEMU TCG, q35, two vCPUs, 8 GiB guest, fresh OVMF Secure Boot
variables, software TPM, one read-only CD, no network). Guest Secure Boot was
enabled and the guest reached a root shell. All ten required checks passed: the
optical command line, only the optical loop and device-mapper block devices,
the verity root, the read-only `/dev/sr0` mount at `/media/luma`, inventory,
status, the broker and reference services, reference AppArmor enforcement,
guest Secure Boot and the TPM probe. All five gated checks passed, including
the four that failed in sequence 18:

- `systemctl --failed` listed no unit.
- `luma-utc-recovery-keeper.service` was active (running) and
  `luma-utc-recovery-producer.path` active (waiting); their journal shows both
  starting and neither failing.
- Neither the console nor the journal showed an ordering cycle.
- `luma-platform verify /media/luma` exited 0 after 381.9 seconds under
  software emulation. It reported release `luma-native-lab-20260927-desktop-19`,
  the signed root hash and the size and hash of all six payload members. Before
  it ran, the guest had 7,903 MiB of RAM, 7,469 MiB available.

Power-off reached `LUMA_SHUTDOWN_STORAGE_CLEAN` after the same `/var` unmount
warning as the disk smoke, and the ISO's hash was unchanged afterwards. Both
sequence-18 optical causes are therefore fixed on a booted image: the masked
`/run` directories now exist in the live session, and 8 GiB of RAM is enough to
stage the payload. The smoke did not install, start a graphical session, or use
a physical optical drive or machine.

## Firmware and existing TPM ownership

For Secure Boot testing, enroll only the identified public laboratory
`secureboot.cer` into the test firmware's UEFI `db` using the machine vendor's
supported procedure and owner approval. Back up its existing key configuration;
preserve vendor PK/KEK/db keys. MOK enrollment is not a substitute for trusting
this directly booted systemd-boot image. Do not clear firmware keys, silently
disable Secure Boot, clear the TPM, change its ownership, or overwrite occupied
NV indexes. If the certificate cannot be enrolled, record Secure Boot as
untested and obtain explicit approval for a separate non-Secure-Boot test.

Boot the USB (or the ISO) through the UEFI boot menu. Its live/recovery console,
not a live graphical desktop, is the installer interface. Read-only preliminary
checks are:

```sh
luma-platform inventory
luma-platform tpm-probe
luma-platform admin-install-check
luma-platform verify /media/luma
sudo systemctl --failed
```

Missing TPM support, occupied allocations or failed admission must be
investigated, not bypassed. A `verify` refusal for "insufficient snapshot
storage" means the machine has too little RAM for live staging; the refusal
states the RAM the payload needs. These commands do not enroll product Admin.
Record any failed unit with `journalctl -b -u <unit>`.

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
Installation has not been exercised for this candidate and is part of the test,
not an established path.

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
worker; live installer payload staging needs the RAM described above. The
packaged runtime is CPU-only. This candidate does not claim GPU inference,
Gemma support, large-model readiness, or that the 1.7B profile meets the
governed 4–6B tier.

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

Record any failed unit with its journal (`sudo journalctl -b -u <unit>`).
Installed-mode services that hide or bind paths under `/var/lib/luma-os` depend
on installation having created them; their start on an installed boot has not
been observed yet. Model availability is not a boot-health prerequisite. Check
the actual GNOME Wayland login, manual workspace, logout/login, screen lock,
reboot and shutdown. The main workspace uses a fixed ELF launcher and its named
AppArmor userns compatibility profile; packaged files do not prove a loaded
profile, successful WebKit sandbox startup or complete application confinement.

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

The disk-image VM test used the sequence-16 smoke-only procedure with a fresh
virtual firmware store, software TPM and disposable disk in a 4 GiB guest;
`vm_test.py` now also admits an 8192 MiB fixture, which this run did not use. It
accessed no physical disk, firmware or TPM, and the read-only image hash was
rechecked afterwards. It checked the live broker and reference services, verity
root, reference AppArmor enforcement, actual guest Secure Boot state, media
mount and TPM probe. Its stage is named `install`, but `--smoke-only` performed
no installation. Its console shows the recovery keeper and producer path
starting during boot and stopping only at power-off; it does not list failed
units. During power-off, as in sequences 16 to 18, systemd first reported that
`/var` could not be unmounted; the later dracut teardown unmounted the old root
and emitted the required `LUMA_SHUTDOWN_STORAGE_CLEAN` marker before QEMU exited
successfully. This is not evidence that every service shut down without
warnings or that encrypted installed-data recovery passed.

**Correction to the sequence-18 record.** Its disk smoke was described as showing
only the recovery keeper's console start line. Its console also shows the
producer path starting and then stopping during boot, and the keeper never
stopping at power-off. That fits the keeper failing with `226/NAMESPACE`, as the
sequence-18 optical smoke observed directly. The sequence-18 record is retained
unchanged; this note and the sequence-19
[execution record](candidate19_execution_2026-10-28.json) carry the correction.

Final native machine acceptance must be recorded with its actual results before
any stronger readiness claim. The immutable exported `build.json` retains its
assembly-time `built-not-yet-boot-tested` status; the separate execution record
records the later limited VM tests without rewriting signed/exported evidence.
