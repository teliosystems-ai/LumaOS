# Native desktop candidate 16: operator handoff

## Status and exact artifact

The laboratory-signed Ubuntu desktop image was assembled and exported on
2026-10-19. **All 13 offline image checks passed, followed by a successful
software-emulated UEFI Secure Boot live-system smoke test and verified final
storage teardown.** Installation, graphical/installed acceptance and
physical/native qualification remain pending. This record does not close G2,
G3 or GWIN0, or claim production certification. The
[execution record](candidate16_execution_2026-10-19.json) binds the actual results,
logs, source and artifact hashes; the
[executed offline verifier](candidate16_image_verify_2026_10_19.py) is retained
unchanged. Do not substitute an earlier failed build or verifier attempt for
this candidate's results.

Export directory: `D:/LumaOS-builds/native/20261019T135331Z-desktop`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `luma-native-lab-20260927-desktop-16.img.zst` | 3,265,429,446 | `4884d0e2910c0520723f0f7ea7a1963466ed48b8f098c3227cb9dc08d8923008` |
| `luma-native-lab-20260927-desktop-16.img` after decompression | 16,190,013,440 | `4e844b54036f549b61dc80d315012000e8a20707f006b4592d0faa0a47d45502` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |

The build uses commit `bc14e7c`, source cut F: 553 captured files, manifest
SHA-256 `6937771ed5da87cfb811300bd745c0081fb879258bf0e2a6430d013e7437277b`.
The 438-file product source lock is
`cfb596caa33c29c15124d70a2e0bd799b772c5f43fdb76d83e3eee3112cd5740`.
These identify inputs, not native acceptance or independently commissioned trust.

## Prepare the Ubuntu test machine

This is a **standalone Ubuntu 24.04 amd64 UEFI operating-system disk image**,
not an ISO, an application installed into an existing Ubuntu server, a Windows
image, or a dual-boot installer. Installing it erases the selected target disk.
Use a separate disposable machine/disk; preserve the existing Ubuntu system and
unrelated disks by disconnecting them where practical.

Have:

- A 32 GB or larger USB stick for the desktop installer, distinct from the target.
- A disposable target of at least 32 GiB; 64 GiB or larger is recommended.
- At least 8 GiB RAM; 16 GiB is practical for desktop installation and model tests.
  Admission rechecks actual available RAM, CPUs and storage; nominal RAM alone
  does not guarantee acceptance.
- At least 25 GiB free working-copy space on the Ubuntu host, in addition to the
  USB and target capacities. Keep the original compressed export intact.
- Local TPM2 support with its existing owner/custodian available, recovery
  material stored separately, and wired networking or another working network
  for model downloads and the commissioned protected-time dependencies.

Transfer **all files in the export directory**, including `SHA256SUMS`, public
certificate, source archive and release records, into a new private Ubuntu
working directory named `~/luma-native-desktop-16-test`. Do not transfer the
private Docker volume `luma-native-lab-keys` or any private signing key.

From that working copy:

```sh
(
set -eu
cd "$HOME/luma-native-desktop-16-test"
printf '%s  %s\n' \
  4884d0e2910c0520723f0f7ea7a1963466ed48b8f098c3227cb9dc08d8923008 \
  luma-native-lab-20260927-desktop-16.img.zst \
  2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8 \
  secureboot.cer | sha256sum --check -
zstd -d -- luma-native-lab-20260927-desktop-16.img.zst
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

## Firmware and existing TPM ownership

For Secure Boot testing, enroll only the identified public laboratory
`secureboot.cer` into the test firmware's UEFI `db` using the machine vendor's
supported procedure and owner approval. Back up its existing key configuration;
preserve vendor PK/KEK/db keys. MOK enrollment is not a substitute for trusting
this directly booted systemd-boot image. Do not clear firmware keys, silently
disable Secure Boot, clear the TPM, change its ownership, or overwrite occupied
NV indexes. If the certificate cannot be enrolled, record Secure Boot as
untested and obtain explicit approval for a separate non-Secure-Boot test.

Boot the USB through the UEFI boot menu. Its live/recovery console, not a live
graphical desktop, is the installer interface. Read-only preliminary checks are:

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
After successful installation, remove the USB and boot the target through UEFI.

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
Test explicit model QA/activation only through the separately reviewed flows in
the [image guide](../image/README.md), after their actual prerequisites pass.
Do not run `apt upgrade` against the immutable root or weaken checks to make a
test succeed.

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

Physical testing is not the only remaining development boundary. C's logical
journal is bounded to 4 MiB and 1,024 events; exhaustion refuses further work.
Paged continuation/compaction and custody/key succession are not supplied by
this candidate. Recovery handles the implemented exact canonical preparation
and publication cases; damaged or noncanonical preparation/authoritative history
remains fail-closed for forensic handling, not automatic repair/reset.
Broader G3 application, adapter/capture
journeys and GWIN0 principal/grant/inference integration remain open as recorded
in the [development plan](../../docs/DEVELOPMENT_PLAN.md) and
[G3/GWIN0 implementation record](../../docs/G3_GWIN0_IMPLEMENTATION.md#remaining-development-and-qualification).

The VM used a fresh virtual firmware store, software TPM and disposable disk;
it accessed no physical disk, firmware or TPM. It checked the live broker and
reference services, verity root, reference AppArmor enforcement, actual guest
Secure Boot state, media mount and TPM probe. Its stage is named `install`, but
`--smoke-only` performed no installation. During poweroff, systemd first reported
that `/var` could not be unmounted; the later dracut teardown unmounted the old
root and emitted the required `LUMA_SHUTDOWN_STORAGE_CLEAN` marker before QEMU
exited successfully. This is not evidence that every service shut down without
warnings or that encrypted installed-data recovery passed.

Final native machine acceptance must be recorded with its actual results before
any stronger readiness claim. The immutable exported `build.json` retains its
assembly-time `built-not-yet-boot-tested` status; the separate execution record
records the later limited VM test without rewriting signed/exported evidence.
