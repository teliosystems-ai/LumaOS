# Native desktop candidate 18: operator handoff

## Status and exact artifacts

The laboratory-signed Ubuntu desktop disk image and its separate optical
live/installer ISO were assembled and exported on 2026-10-28.
All 14 offline image checks passed, and a software-emulated UEFI Secure Boot
live smoke of the disk image passed, including verified storage teardown at
power-off. **The sequence-18 ISO boots**: in its software-emulated Secure Boot
optical smoke the firmware started the signed optical UKI and the guest reached
a root shell on the verified root, with no ordering cycle. That smoke still
**failed**: four gated checks failed (see [the ISO section](#optical-liveinstaller-iso)).
For sequence 18, use the `.img` from USB for installation testing; the ISO is
for boot observation only.
Installation, graphical/installed acceptance and physical/native
qualification remain pending. This record does not close G2, G3 or GWIN0, or
claim production certification. The
[execution record](candidate18_execution_2026-10-28.json) binds the actual
results, logs, source and artifact hashes; the
[executed offline verifier](candidate18_image_verify_2026_10_28.py), its
[adapter audit](candidate17_verifier_adapter_audit_2026_10_27.py) and the
[optical smoke harness](candidate18_optical_smoke_2026_10_28.py) are retained
unchanged. Do not substitute an earlier failed build or verifier attempt for
this candidate's results.

Export directory: `D:/LumaOS-builds/native/20261028T114956Z-desktop`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `luma-native-lab-20260927-desktop-18.img.zst` | 3,690,870,697 | `c7bf36c7f4c33e47e664967aab727962759abc127c2f31af8562d6fc966564a3` |
| `luma-native-lab-20260927-desktop-18.img` after decompression | 16,190,013,440 | `364875ffe9bb49f91e445eb473b90fcea36ba98813a6d8c3fa7497e5e5ffa54e` |
| `luma-native-lab-20260927-desktop-18.iso` | 7,225,747,456 | `cf817cdf1b32d9056c8e914e2ccac7049e3c022d09ae29a3276d4bea3ba44a3e` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |

The build uses commit `4d7fa7c`, source cut c: 877 captured files, manifest
SHA-256 `66b0f07c0f253caae8de05a830c90795eda4c4914f55df85c9c010b7129da6f1`.
The 727-file product source lock is
`72131f0c691c2338644e579ab828ec06597832ae182db281f37f74ffc9abe9ad`.
The signed verity root hash is
`87c6d287c2aa12a343320df2a41b637590fc2be3d18b81625d7041051b49e5b7` with
kernel `6.8.0-142-generic`. These identify inputs, not native acceptance or
independently commissioned trust.

Compared with sequence 17's source cut, the product changes are the boot
policy, the optical initrd discovery script, its dracut module setup and the
relocated optical udev rule, and the two UTC producer path units. No Rust source
changed, and the packaged platform binary is byte-identical. The
feature content is that of sequence 17: the G3/GWIN0 source integrated through
`4acc3a0`, query-only hardware writer mediation, explicit audio/video input
capture, the Whisper tiny ASR runtime and pinned weight, and the optical ISO.
`build.json` records each as present but unqualified.

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
  3,462,000,640-byte signed payload there plus a 64 MiB reserve. That needs more
  than 6,732 MiB of RAM; a 6 GiB machine is refused before copying. 16 GiB is
  practical for desktop installation and model tests. Admission rechecks actual
  available RAM, CPUs and storage; nominal RAM alone does not guarantee
  acceptance.
- At least 32 GiB free working-copy space on the Ubuntu host, in addition to the
  USB and target capacities. Keep the original compressed export intact.
- Local TPM2 support with its existing owner/custodian available, recovery
  material stored separately, and wired networking or another working network
  for model downloads and the commissioned protected-time dependencies.

Transfer **all files in the export directory**, including `SHA256SUMS`, the ISO,
public certificate, source archive and release records, into a new private
Ubuntu working directory named `~/luma-native-desktop-18-test`. Do not transfer
the private Docker volume `luma-native-lab-keys` or any private signing key.

From that working copy:

```sh
(
set -eu
cd "$HOME/luma-native-desktop-18-test"
printf '%s  %s\n' \
  c7bf36c7f4c33e47e664967aab727962759abc127c2f31af8562d6fc966564a3 \
  luma-native-lab-20260927-desktop-18.img.zst \
  cf817cdf1b32d9056c8e914e2ccac7049e3c022d09ae29a3276d4bea3ba44a3e \
  luma-native-lab-20260927-desktop-18.iso \
  2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8 \
  secureboot.cer | sha256sum --check -
zstd -d -- luma-native-lab-20260927-desktop-18.img.zst
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

> **The sequence-18 ISO boots but failed its signed smoke.** Use it only to
> repeat the boot observation. Do not use it for installation acceptance; wait
> for a later sequence whose optical smoke passes.

The ISO is a separate, independently identified boot medium for the same
signed root. It is ISO9660 with a single EFI El Torito entry: UEFI only, no
legacy BIOS entry and **no hybrid USB boot path**. Writing the ISO to a USB
stick is not a supported boot method; use the `.img` for USB.

At 7,225,747,456 bytes it does not fit single-layer DVD. Use one of:

- A **DVD+R DL** (dual-layer, about 8.5 GB) disc written with the burning
  tool's verify-after-write option, in a UEFI-bootable optical drive; or
- **Virtual CD media**: a virtual machine's CD-ROM device on the Ubuntu test
  host, or a server BMC's virtual-media CD.

Its firmware-authenticated optical UKI
(`0bd19126cd7eb51a02b12ba7f88929c80b2e4728968221136e537e2b5dd6e0b4`) mounts the
disc read-only and exposes `root.ext4` and `root.verity` through read-only loop
devices to the normal verity root; the signed root hash, not the disc label, is
root authority. **Exactly one CD-ROM-class device must be present.** A second
optical drive, including an empty or virtual one, makes the initrd refuse to
boot rather than guess. The optical slot receives no installed Admin PCR
approval. Enroll `secureboot.cer` exactly as for the disk image below.

**What the signed optical smoke showed.** It ran in a disposable software
emulator (QEMU TCG, q35, two vCPUs, 6 GiB guest, fresh OVMF Secure Boot
variables, software TPM, one read-only CD, no network). Guest Secure Boot was
enabled. The guest reached a root shell. Inventory, status, TPM probe, the
broker and reference services, reference AppArmor enforcement, the optical
command line, the read-only `/dev/sr0` mount at `/media/luma`, the two read-only
loop devices and the verity root all passed. Neither the console nor the
journal showed an ordering cycle, and power-off reached
`LUMA_SHUTDOWN_STORAGE_CLEAN`. The ISO's hash was unchanged afterwards. The two
sequence-17 optical defects (the dracut-library abort and the loop-device names
missing after switch-root) are fixed in this image.

Four gated checks failed, from two causes:

- **`recovery-keeper-active`, `recovery-producer-path-active` and
  `no-failed-units`.** `luma-utc-recovery-keeper.service` failed with
  `226/NAMESPACE`: "Failed to set up mount namespacing: /run/luma-governance: No
  such file or directory". The keeper hides that directory, which only the
  installed-mode Admin service created, so it never existed in a live session.
  The bound `luma-utc-recovery-producer.path` then stopped, so recovery-mode
  authenticated time does not start from a live session of this image. The
  keeper was the only failed unit. The same unit runs in the USB live session
  and is expected, though not observed, to fail there too: the disk smoke does
  not list failed units. **`systemctl --failed` naming only this unit is a known
  issue of sequence 18, not a new finding.**
- **`signed-media-verify`.** `luma-platform verify /media/luma` refused before
  copying, as designed: the 6 GiB guest had 3,038,302,208 bytes of RAM-backed
  staging for a 3,462,000,640-byte payload plus its 67,108,864-byte reserve.
  The refusal's closing "desktop installation evaluation uses 6 GiB RAM"
  guidance is stale; use at least 8 GiB.

Both causes are fixed in source (`e29187b`) for the next build: the masked
`/run` directories are created at every boot, and the staging refusal states
the RAM the payload needs. A passing optical smoke on a new signed build at
8 GiB is still required.

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
graphical desktop, is the installer interface. Read-only preliminary checks
are:

```sh
luma-platform inventory
luma-platform tpm-probe
luma-platform admin-install-check
luma-platform verify /media/luma
```

Missing TPM support, occupied allocations or failed admission must be
investigated, not bypassed. A `verify` refusal for "insufficient snapshot
storage" means the machine has too little RAM for live staging (see above).
These commands do not enroll product Admin.

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

The disk-image VM test used the unchanged sequence-16 fixture with a fresh
virtual firmware store, software TPM and disposable disk in a 4 GiB guest; it
accessed no physical disk, firmware or TPM, and the read-only image hash was
rechecked afterwards. It checked the live broker and reference services, verity
root, reference AppArmor enforcement, actual guest Secure Boot state, media
mount and TPM probe. Its stage is named `install`, but `--smoke-only` performed
no installation. It shows the recovery keeper's console start line only; it does
not observe the keeper's later state or list failed units. During poweroff, as
in sequences 16 and 17, systemd first reported that `/var` could not be
unmounted; the later dracut teardown unmounted the old root and emitted the
required `LUMA_SHUTDOWN_STORAGE_CLEAN` marker before QEMU exited successfully.
The optical smoke showed the same warning. This is not evidence that every
service shut down without warnings or that encrypted installed-data recovery
passed.

**Fixed in this image: the boot ordering cycle.** Sequences 16 and 17 printed
`Ordering cycle found, skipping …` because each UTC producer path unit was
ordered after its keeper and before `paths.target`. Neither sequence-18 boot
printed it, and the optical smoke's journal check found none.

Final native machine acceptance must be recorded with its actual results before
any stronger readiness claim. The immutable exported `build.json` retains its
assembly-time `built-not-yet-boot-tested` status; the separate execution record
records the later limited VM tests without rewriting signed/exported evidence.
