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

The original sequence-1 image was **headless and manual-only**. New model-enabled
builds include a pinned CPU runtime and an image-owned model catalog. Their
installer downloads and verifies selected weights; weights are not embedded in
the image or Git. Production Admin/custody/anti-rollback anchoring, TPM auto-unlock,
a graphical installer, dual boot, and arbitrary-hardware qualification are still
absent. Native model admission currently covers the catalog below, not the full
governed multi-model contract/lifecycle matrix. `desktop` remains an untested
build option. Consult the execution record for the particular image: the old
image's passing tests do not automatically attest a new build.

## Model selection and installation

Run `luma-platform models` for this image's exact options. The installer prompts
for a model ID unless `--model` is supplied:

| Profile | CPU admission floor | Download | Context |
| --- | --- | --- | --- |
| `qwen3-4b-q4-k-m` | 6,000,000,000 bytes total RAM, 4,000,000,000 available, two CPUs | 2,497,280,256 bytes | 2,048 tokens |
| `qwen3-1-7b-q4-k-m` | 3,000,000,000 bytes total RAM, 2,000,000,000 available, two CPUs | 1,107,408,544 bytes | 2,048 tokens |
| `manual-only` | OS requirements only | None | None |

Both model profiles require their download size plus 2 GiB of free encrypted
storage. These are conservative development admission limits, not performance
certification. The 1.7B option does not meet the governed 4–6B compact-model tier.
GPU support and larger parameter tiers cannot be selected without a supported,
pinned runtime/profile and passing admission/evaluation. Unknown IDs are denied.

Connect Ethernet or configure networking with `nmtui`/`nmcli` on the live image.
After verifying the image and approving the exact disposable disk:

```sh
luma-platform install /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma --model qwen3-4b-q4-k-m
```

The model choice is admitted before disk erasure; resources are checked again
before acquisition. Downloads use immutable publisher URLs, validated HTTPS
redirects, exact byte counts and SHA-256. The downloader runs as a dedicated
unprivileged identity, has a kernel output-size limit, and cannot activate a
partial download. Credentials are newly generated locally; the inference server
binds only to authenticated loopback and has separate AppArmor/seccomp/cgroup
restrictions. No remote inference fallback or model-generated OS execution is
enabled. The lab catalog is signed by the image's lab authority, not production
custody; Qwen's upstream [model card](https://huggingface.co/Qwen/Qwen3-4B-GGUF)
identifies Apache-2.0 licensing.

If acquisition fails after the OS installation, the command exits nonzero and
explicitly reports the missing model. The installed OS remains bootable in
manual mode. After fixing networking, retry on the installed OS:

```sh
sudo luma-platform model-install qwen3-4b-q4-k-m
sudo systemctl status luma-model.service
printf 'Reply with a short greeting.' | sudo luma-platform model-chat
```

`model-chat` is a bounded local operator test, not an autonomous action agent.
Do not paste secrets into test prompts or publish inference logs containing
private data. Model failure does not prevent OS health acknowledgement or manual
workflow operation. Recovery's model-disable marker stops inference without
disabling the reference workflow service in model-enabled images.

After recovery disablement, investigate the original fault and repair/reinstall
the selected profile first. If the administrator explicitly decides to re-enable
inference on this lab image, with no concurrent installation/update/recovery:

```sh
sudo test -f /var/lib/luma-os/model-disabled
sudo rm -- /var/lib/luma-os/model-disabled
sudo systemctl start luma-model.service
sudo systemctl status luma-model.service
```

The marker removal is an intentional local-root maintenance action, not a
production Admin delegation workflow. Do not clear it automatically on boot or
as part of a download retry. The runtime still checks the configured model's
bytes/hash and enforces its sandbox and resource limits when it starts.

The local administrator has normal root/sudo authority. The Rust console path
is not a production implementation of finite Admin delegation. Do not expose
the recovery console remotely, deploy this image as a multi-tenant service, or
use production data or production signing keys.

## Build on Ubuntu or Ubuntu WSL

Requires Docker, internet access to Ubuntu repositories on the first build,
and substantial free build space (allow 40 GiB for one build plus VM tests).
The builder refuses to start below 16 GiB free on the repository filesystem.
Also check Docker's data drive separately; this is not an aggregate reservation
and does not guarantee space for subsequent VM runs.
Run from this repository:

```sh
bash native/image/build.sh headless NEXT_SEQUENCE
```

The builder downloads the pinned llama.cpp CPU archive and verifies its official
digest. An existing archive can be supplied with
`LUMA_RUNTIME_ARCHIVE=/absolute/path/llama-b11100-bin-ubuntu-x64.tar.gz`;
the identical size/checksum checks still apply. Runtime build inputs are retained
under `dist/native-inputs`, outside Git. No arbitrary local binary is accepted.

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

### External build drive (including Windows D: / exFAT)

Create a dedicated directory on the selected drive and ensure WSL can access it.
For this environment it is `D:\LumaOS-builds`, exposed as `/mnt/d/LumaOS-builds`.
If WSL has not mounted D:, an authorized operator can mount it with
`sudo mkdir -p /mnt/d` and `sudo mount -t drvfs D: /mnt/d`; do not format the drive.

```sh
LUMA_BUILD_ROOT=/mnt/d/LumaOS-builds \
LUMA_RUNTIME_ARCHIVE=/absolute/path/to/verified-runtime-cache.tar.gz \
bash native/image/build.sh headless NEXT_SEQUENCE
```

The runtime cache is optional and is still size/digest checked. With an external
root, `native-inputs/`, `work/BUILD-ID/artifacts/`, and exported `native/BUILD-ID/`
are created there. A fresh Docker volume retains the smaller Unix root/source/
compiler/payload workspace; lab private keys remain in their separate existing
Docker volume. No Docker-wide storage relocation occurs. Preflight requires
40 GiB free on the selected output filesystem and 8 GiB on the repository drive;
also check Docker's actual backing drive. Do not unplug the drive during work.

For VM evaluation bind `D:/LumaOS-builds/work/BUILD-ID` (WSL path
`/mnt/d/LumaOS-builds/work/BUILD-ID`) at `/work` in place of the build-volume
mount in the commands below. Disk files and evidence then stay on D:. Unix
control sockets are temporary and remain inside the container's `/tmp`.
An exFAT drive is not a Unix root filesystem or a production secret store.
Generated test disks contain only disposable fixtures; never use production
credentials/data in them. `storage_probe.py` can first check regular-file fsync,
locking and qcow2 I/O in a newly created empty directory mounted at `/probe`.

`NEXT_SEQUENCE` must be a positive integer greater than the installed release
for update tests. A fresh build is not an evaluated release. Use the exact image
filename and build volume printed by that build, not a historical example's ID.

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
  --image /work/artifacts/EXACT-IMAGE-FROM-BUILD.img \
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
  --image /work/artifacts/EXACT-IMAGE-FROM-BUILD.img \
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
`bash native/image/build.sh headless NEXT_SEQUENCE`. Mount its retained volume read-only
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

### Model acquisition and recovery evaluation

The model-specific runner uses a fresh 32 GiB virtual disk, 6 GiB guest memory,
two virtual CPUs, and outbound NAT only during installation. Run it separately
from other VMs on a memory-constrained host. It downloads Qwen3-4B from the pinned
publisher URL; no weights are pre-seeded. It requires approximately 2.5 GB of
network transfer as well as room for the virtual disk and retained logs.

```sh
docker run --rm --device=/dev/kvm \
  --mount type=volume,src=BUILD_VOLUME,dst=/work \
  --mount type=bind,src="$PWD",dst=/repo,readonly \
  luma-native-tools:20260927 \
  python3 /repo/native/image/model_vm_test.py \
  --image /work/artifacts/EXACT-IMAGE-FROM-BUILD.img \
  --work /work/vm-model-new
```

Unlike the offline platform suite, this command deliberately omits
`--network none`. It opens no guest port forwards. The runner checks real
completion-token output, unauthorized API refusal, kernel restrictions,
wrong-length and same-length corrupt weights, cached inference after an offline
reboot, independent-credential recovery disablement, and manual boot afterward.
Only a completed `result.json` is a pass; the existence of this script is not
evidence that these checks have executed on a particular image.

`model_reconfigure_test.py --image /work/artifacts/EXACT-IMAGE.img --base-run
/work/vm-full-PASSED --work /work/vm-small-new` uses a fresh overlay of a passed
full platform fixture. It downloads Qwen3-1.7B through the installed model
command, checks that recovery disablement is retained until explicitly cleared,
and exercises real inference, the smaller memory limit and offline reboot in
a 4 GiB VM. It is not a fresh OS installation test or a 4–6B-tier qualification.

For an already passed model run, `model_recovery_test.py --image
/work/artifacts/EXACT-IMAGE.img --base-run /work/vm-model-PASSED --work
/work/vm-model-recovery-new` checks independent recovery disablement, manual
boot, equal-size corruption refusal and restored health on a new overlay.
Use the same volume/repository mounts and `--network none`; it retains and
references the original acquisition evidence rather than claiming a new download.

`update_powercut_test.py` provides a separate, destructive **virtual-disk-only**
interruption test. Mount the passed original image/run volume read-only at
`/baseline`, the higher-sequence candidate volume at `/work`, and this repository
read-only at `/repo`. Pass `--base-image /baseline/artifacts/ORIGINAL.img`,
`--base-run /baseline/vm-PASSED`, `--candidate /work/artifacts/CANDIDATE.img`,
and a fresh `--work /work/vm-powercut-new`. The runner cuts QEMU power after
observed target writes, then checks old-slot recovery, pending-update
reconciliation, successful retry, and retained user data. It never changes the
baseline disk and is not physical power-loss qualification.

For the selected laboratory regression set, mount the current work directory at
`/work`, the prior passing image/run volume read-only at `/baseline`, this
repository read-only at `/repo`, and the current export folder at `/out`.
Run inside the tools container with `/dev/kvm` and outbound network available:

```sh
bash /repo/native/image/evaluate.sh \
  /work/artifacts/CURRENT.img /baseline/artifacts/ORIGINAL.img \
  /baseline/vm-full-PASSED new-label
```

This runs one VM at a time: full platform regression, 4B download/recovery,
1.7B post-install configuration, update power-cut/retry/older-release refusal,
virtual Secure Boot smoke and unsigned-loader refusal. Each successful runner
exports its own hashed evidence. The first failed runner stops the sequence;
retain its diagnostics and use fresh run names when retrying. Do not treat this
selected set as the complete governed G2 acceptance matrix.

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
not the data volume. `disable-model` stops inference in model-enabled images,
while manual workflow, console and recovery remain available. The original
sequence-1 image instead disabled the entire reference worker; its historical
evidence retains that scope.

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
