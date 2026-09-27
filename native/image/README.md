# Native Ubuntu laboratory image

This is a separate native-platform build, not the Python `0.1.0` source archive.
The source archive's historical G2 records do **not** attest this image. G2
remains in progress until native implementation and its acceptance matrix pass.
Read the execution record accompanying the particular image before testing it.

## What the image implements

- Ubuntu 24.04 amd64, generic kernel, UEFI installation/recovery media.
- A Rust platform executable for signed-bundle admission, exact whole-disk
  confirmation, GPT creation, read-back verification, A/B roots, LUKS2 data,
  separate user/administrator identities, updates and offline recovery.
- Ed25519 release metadata; laboratory-signed UKIs containing the kernel,
  initramfs, command line and dm-verity root hash; signed systemd-boot.
- Read-only verified root, encrypted `/var`, independent recovery passphrase,
  three-count trial entries and model-independent boot acknowledgement.
- Kernel-authenticated Unix socket peers, a restricted native broker, an
  unprivileged reference workflow service, enforcing AppArmor and systemd
  seccomp/device/cgroup restrictions. No generated native-code execution.
- Recovery unlock, data export, system-slot repair and worker disablement.

The first image is **headless and manual-only**. It does not include weights,
a native model supervisor, production Admin/custody/anti-rollback anchoring,
TPM auto-unlock, a graphical installer, dual boot, or qualification for arbitrary
hardware. The existing Python multi-model admission contracts are not yet
connected to this Rust installer. These are implementation gaps, not hardware
test deferrals. `desktop` is a build option, not a tested desktop claim.

The local administrator has normal root/sudo authority. The Rust console path
is not a production implementation of finite Admin delegation. Do not expose
the recovery console remotely, deploy this image as a multi-tenant service, or
use production data or production signing keys.

## Build on Ubuntu or Ubuntu WSL

Requires Docker, internet access to Ubuntu repositories on the first build,
and substantial free build space (allow 40 GiB for one build plus VM tests).
Run from this repository:

```sh
bash native/image/build.sh headless
```

The builder uses an exact Ubuntu base digest and an Ubuntu archive snapshot.
`packages.lock`, `toolchain-packages.lock`, `source-lock.json`, signed release
metadata and SHA-256 checksums accompany the image. These identify the inputs;
random filesystem identifiers and laboratory keys mean byte-for-byte
reproducibility is not claimed. The initial CA bootstrap uses authenticated
Ubuntu APT. No host block device or firmware is opened by the builder.

Output is under `dist/native/<build-time>-headless/`. The `.img.zst` decompresses
to a GPT disk image of about 11.1 GiB; it is **not an ISO**. Private keys remain
only in Docker volume `luma-native-lab-keys`. Never publish or copy that volume
to a test machine. Public `secureboot.cer` may be transferred with the image.

Build volumes are retained for diagnosis and VM testing. They are not silently
deleted. Repeated builds consume additional storage.

## First test from an existing native Ubuntu host

Start in a VM with a newly created virtual disk, not your Ubuntu system disk.
The test harness is `vm_test.py`. It creates its own 32 GiB qcow2 target and
rejects image paths outside the generated build-artifact directory. The build
script prints the retained Docker volume name. Replace `BUILD_VOLUME` below
with that exact name:

```sh
docker run --rm --network none --device=/dev/kvm \
  --mount type=volume,src=BUILD_VOLUME,dst=/work \
  --mount type=bind,src="$PWD",dst=/repo,readonly \
  luma-native-tools:20260927 \
  python3 /repo/native/image/vm_test.py \
  --image /work/artifacts/luma-native-lab-20260927-headless-1.img \
  --work /work/vm-new-run
```

Use a new `vm-...` directory each time. Add `--secure-boot` for virtual firmware
enrollment, which never touches physical firmware. On this WSL host, nested
KVM SMM fails with `KVM: entry failed` during Secure Boot; use `--accel tcg`
and initially `--smoke-only` for that separate check. VM fixture passwords in
the harness are public, disposable test data and never image defaults.

Serial and QEMU logs and successful `result.json` are retained under the VM
directory. A build record saying `built-not-yet-boot-tested` is not a test pass.

### Testing a transferred image without rebuilding it

On the separate native Ubuntu host, copy the complete exported artifact folder
and this repository. Verify the compressed checksum, decompress, and verify the
raw image checksum. Build only the test-tools container (no OS image rebuild):

```sh
docker build \
  --build-arg UBUNTU_BASE=ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 \
  -f native/image/Dockerfile.tools -t luma-native-tools:20260927 native/image
docker volume create luma-native-evaluation
docker run --rm --network none --device=/dev/kvm \
  --mount type=volume,src=luma-native-evaluation,dst=/work \
  --mount type=bind,src=/ABSOLUTE/PATH/TO/VERIFIED-ARTIFACTS,dst=/work/artifacts,readonly \
  --mount type=bind,src="$PWD",dst=/repo,readonly \
  luma-native-tools:20260927 \
  python3 /repo/native/image/vm_test.py \
  --image /work/artifacts/luma-native-lab-20260927-headless-1.img \
  --work /work/vm-native-ubuntu-01
```

The bind-mounted artifacts remain read-only. The fresh volume holds only virtual
disks and evidence. No physical target disk or host firmware is used by this
command. Keep `secureboot.cer` alongside the image for Secure Boot tests. The
same layout works for the negative tests below, using different work directories.

`secure_boot_negative.py` removes the bootloader signature in a private copy
of the EFI filesystem and requires firmware rejection. `verity_negative.py`
corrupts root metadata in a qcow2 overlay and requires a real dm-verity error
and bounded panic/reboot. Both take the same `--image` and new `--work` arguments;
neither changes the distributed image. The Secure Boot negative test uses TCG.
The full VM sequence additionally exercises three corrupted-slot boots, good-slot
fallback, offline repair of the corrupted root, and a successful repaired boot.
The signed command line uses systemd 255's
[`panic-on-corruption`](https://github.com/systemd/systemd/blob/v255/man/systemd-veritysetup-generator.xml)
verity option plus a ten-second kernel panic reboot delay.
Trial selection uses an explicit nonzero-counter pattern. On systemd-boot 255,
an overly broad explicit default can keep selecting an exhausted entry despite
the normal assessment ordering. Healthy acknowledgement selects the exact
counter-free entry; a normal uncounted boot does not call the trial-only bless
operation. These behaviors are covered by the VM fallback sequence and a Rust
glob regression test; see the pinned
[`loader.conf` contract](https://github.com/systemd/systemd/blob/v255/man/loader.conf.xml).

For update evaluation, build a higher-sequence candidate with
`bash native/image/build.sh headless 2`. Mount its retained volume read-only
at `/candidate`, keep the original build volume at `/work`, and run
`update_test.py --image /work/artifacts/ORIGINAL.img
--candidate /candidate/artifacts/CANDIDATE.img --base-run /work/vm-PASSED
--work /work/vm-update-new`. The base run must have passed the complete recovery
sequence. The update test uses a fresh overlay of that installed disk and checks
inactive-slot staging, healthy promotion, data preservation and older-sequence
refusal. It is not a power-cut or protected anti-rollback-anchor qualification.
Both releases must come from the same laboratory signing authority. Building on
a different Docker host creates different lab keys unless that host already has
the approved signing setup; such a candidate must be rejected by the old image.
For a transferred-image evaluation, obtain the signed higher-sequence candidate
from the original controlled builder. Do not copy private keys to a test machine.

Export passing logs with `collect_evidence.py --run /work/vm-PASSED
--output /out/evidence-new`, mounting the chosen export folder at `/out`.
The exporter includes a hash inventory, not VM disks or firmware variables.
`native-source.tar.zst` captures the build inputs; test records separately hash
the test scripts actually present when the runner starts. Failed runs retain
their diagnostic logs but are never exported as passing evidence.

## Physical test machine preparation

Use an amd64 UEFI machine, at least 8 GiB RAM, a separate 16 GiB-or-larger USB
stick, and a **disposable target disk** of at least 32 GiB (64 GiB recommended
for tests and future model assets). Back up all existing data and recovery keys.
Disconnect unrelated disks where possible. Legacy BIOS and dual boot are not
supported by this installer.

On native Ubuntu, verify the transferred compressed artifact against
`SHA256SUMS`, decompress with `zstd -d`, then verify the uncompressed hash too.
Use Ubuntu Disks' **Restore Disk Image** action on the explicitly identified
USB stick. This erases that USB. Do not restore the image onto the Ubuntu
system disk. Keep the installer USB and target disk distinct.

Secure Boot requires explicit laboratory-certificate enrollment into the test
machine's UEFI `db`, using its firmware-supported procedure and owner approval.
Back up the current key configuration first. Do not clear production PK/KEK/db,
disable Secure Boot silently, or treat MOK enrollment as equivalent to trusting
this directly booted systemd-boot image. If enrollment is unavailable, record
Secure Boot as untested and perform only the separately approved non-Secure-
Boot test. No image script enrolls physical firmware keys.

Boot the USB via the firmware boot menu. At the recovery console:

```sh
luma-platform inventory
luma-platform verify /media/luma
luma-platform install /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma
```

The last command erases the selected whole disk after displaying its serial,
WWN and size and receiving exact `ERASE <identity>` confirmation. Never select
a disk by an assumed `/dev/sdX` ordering. The installer rejects mounted disks
and disks without a hardware-reported stable identity. Do not run competing
root disk-management tools during installation; the operation lock serializes
Luma operations, not every privileged third-party utility.

Create separate user and administrator accounts and four new credentials:
user password, administrator password, data passphrase, independent recovery
passphrase (each at least 16 characters). Store recovery material off-device.
No default account password is supplied. Remove the USB only after completion,
then boot the target disk. Enter the data passphrase, log in as administrator,
and inspect:

```sh
sudo luma-platform boot-health
sudo systemctl --failed
sudo systemctl status luma-broker luma-reference luma-boot-health
sudo veritysetup status root
sudo cryptsetup status luma-data
```

Do not run `apt upgrade` against the read-only system. Updates must be complete
signed bundles with a higher sequence from the same accepted laboratory trust.
The administrator stages one with `sudo luma-platform update /path/to/bundle`.
Model availability is not a boot-health prerequisite.

## Recovery exercises

Boot the original USB with the installed disk unmounted. Use its exact by-id:

```sh
luma-platform recover unlock /dev/disk/by-id/EXACT-TARGET-DISK-ID
luma-platform recover repair-data /dev/disk/by-id/EXACT-TARGET-DISK-ID
luma-platform recover export /dev/disk/by-id/EXACT-TARGET-DISK-ID /path/to/empty/export-directory
luma-platform recover disable-model /dev/disk/by-id/EXACT-TARGET-DISK-ID
luma-platform recover repair-b /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma
```

Use the independent recovery credential, not just the normal data passphrase.
After an unclean shutdown, `repair-data` can replay the filesystem journal and
perform automatic ext4 repairs before a read-only unlock/export. It requires
separate `REPAIR-DATA <identity>` confirmation and writes filesystem metadata;
it does not format the volume. Back up damaged media before repair. Serious
corruption that automatic repair cannot resolve stops with an error.
Export to separate mounted storage. The resulting archive is **unencrypted**
and contains account/state material; protect it accordingly. `unlock` validates
access and unmounts again. Slot repair rewrites only the selected root/hash/UKI,
not the data volume. `disable-model` currently disables the entire reference
workflow worker, while the local console and recovery remain available.

Retain the image hashes, machine/firmware inventory, consented target identity,
serial/console logs, boot entries/counters, service/kernel-control observations,
data-preservation hashes, and results of negative/recovery tests. Do not publish
passwords, recovery secrets, exported user data, or private firmware keys.

## Completion boundary

Actual VM execution demonstrates implemented paths on virtual hardware. It
does not close physical firmware, TPM, accelerator, power-cut, suspend/resume,
two-board, model-performance, production custody, or full G2 requirements.
Failed or unexecuted matrix entries remain open. See `BUILD_PLAN.md` and the
image-specific evidence; do not infer acceptance from this feature list.
