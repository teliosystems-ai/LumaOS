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
governed multi-model contract/lifecycle matrix. `desktop` now selects a candidate
GNOME/Wayland profile; it is not yet an installed-image qualification. Consult
the execution record for the particular image: the old
image's passing tests do not automatically attest a new build.

## Candidate Wayland desktop edition

The `desktop` build uses pinned Ubuntu GNOME/GDM packages, Files, Console,
Text Editor, Settings and a browser launcher for the local reference workspace.
The installed signed UKI selects `graphical.target`; live installation/recovery
and the headless edition explicitly select `multi-user.target`. GDM is limited
to installed boots and requires the installer-created account password. There
is no graphical autologin, remote GDM login or dependency on the model service.

The Luma session wrapper refuses X11 and root/service identities. Packaged X11
session entries are preserved under disabled filenames, not presented as the
Wayland baseline. Files and desktop controls are independent of the local
reference web workspace. Console login and the existing offline CLI recovery
remain the fallback; this change does not implement a graphical installer.

Desktop roots are 6 GiB each, with an 8 GiB offline payload partition on the
live media. Use a **32 GB or larger USB** for this edition (the existing
headless media fits a 16 GB device). External-artifact desktop builds require
60 GiB free on D:/the output filesystem and the unchanged 8 GiB minimum on the
repository/WSL backing drive; a wholly local desktop build requires 24 GiB.
These are build thresholds, not certification of arbitrary desktop hardware.

Desktop **installation** evaluation uses 6 GiB RAM; installed greeter checks
use 4 GiB separately. The live installer keeps a private verified bundle in
RAM-backed `/var`. Sequence 11 needs about 2.25 GiB plus staging headroom and
failed before disk confirmation in a 4 GiB installation VM. Model admission
does not cover this separate installer requirement. Do not enlarge tmpfs or
skip snapshot verification to bypass a refusal. See the
[measured failure and retry](../evidence/G2_DESKTOP_MEMORY_2026-10-01.md).

After a desktop image has been built and its checksums verified, native Ubuntu
testing must cover actual GDM password login to the Luma Wayland session,
`loginctl show-session "$XDG_SESSION_ID" -p Type`, Files/editor/terminal use
with inference stopped, logout/login, password changes, screen locking, reboot,
clean shutdown and a missing/broken model. A packaged compositor smoke test
does not establish those properties. Existing sequence-9/10 **headless** images
do not contain this new desktop implementation.

## Source-only laboratory invoice artifacts

Source after the [artifact checkpoint](../evidence/G2_NATIVE_ARTIFACTS_2026-10-03.md)
includes an installed-root artifact prototype. It is not present in previously
exported images; rebuild and test the consolidated candidate before using it
as installed-image evidence. Fresh installation creates private state under
encrypted `/var/lib/luma-os/artifacts`, bound to the installation identity.
For an older installation updated to this binary, `sudo luma-platform
artifact-store-init` explicitly creates missing state. It refuses existing
or incomplete state rather than resetting it.

On an installed candidate containing this implementation:

```sh
sudo luma-platform artifact-store-status
sudo luma-platform artifact-publish-invoice invoice-001 < invoices.csv
sudo luma-platform artifact-read invoice-001
```

The invoking shell supplies CSV bytes; this is not an enrolled folder grant.
Publication verifies the fixed lab-signed skill registry, calculates bounded
monthly totals and binds the receipt to the input/report digests, installation,
workflow, root UID and request ID. Reusing the exact request returns the
verified receipt; changed inputs are refused. State is bounded to 1,024
committed/retained records, 64 MiB of report/receipt bytes and one outstanding
preparation, with a 16 MiB observed filesystem reserve. This is not a disk-space
reservation. Files are private and reads verify receipt/content integrity.

If publication reports failure, inspect `artifact-store-status` before another
attempt. A complete `pending` pair reports a `review_sha256`; after reviewing
its receipt, `sudo luma-platform artifact-reconcile REQUEST-ID REVIEW-SHA256`
publishes it with current signed-workflow revalidation. An incomplete pair
cannot be published. A safe, inspectable preparation reports a separate
`abort_review_sha256`; `sudo luma-platform artifact-abort REQUEST-ID
ABORT-REVIEW-SHA256` moves its existing bytes intact to `retained`, never deletes
them, and permanently refuses reuse of that request ID. A new request can then
proceed. Either recovery command refuses stale reviews; repeating the same
completed recovery verifies/resynchronizes its existing outcome rather than
creating another effect. Unsafe/unknown members remain fenced for investigation.

The existing recovery archive includes `lib/luma-os`, so it includes this state
alongside other sensitive installation data. Retained preparations count
toward capacity and have no automatic garbage collection. Preserve and protect
them; do not delete them to bypass a fence. Directory/file synchronization
errors are uncertain outcomes, not successful receipts.

This lab prototype has no product Admin or principal-bound effect authorization,
TPM rollback anchor, logical artifact/version lifecycle or native DAG supervisor.
It does not supersede [ADR-0003](../../docs/adr/0003-artifact-storage.md), which
requires production SQLite WAL metadata and immutable content-addressed objects.
Its root-only report/receipt pairs exercise native publication/recovery
boundaries, not completion of the production artifact-write skill or G2.

## Native artifact catalog

Current source also includes the separate ADR-0003 catalog at
`/var/lib/luma-os/artifact-catalog`. It uses the pinned Ubuntu SQLite runtime,
WAL with full synchronization, immutable SHA-256 objects, logical artifact IDs
and sequential versions. Fresh installation initializes it; an updated older
installation requires explicit `sudo luma-platform artifact-catalog-init`.
Existing state is never reset, and the earlier laboratory pair store is not
automatically migrated. Previously exported images do not contain this backend.

On an installed candidate containing it:

```sh
sudo luma-platform artifact-catalog-status
sudo luma-platform artifact-catalog-publish-invoice request-001 monthly-invoices 0 < invoices.csv
sudo luma-platform artifact-catalog-read monthly-invoices 1
sudo luma-platform artifact-catalog-publish-invoice request-002 monthly-invoices 1 < updated-invoices.csv
```

Expected version `0` creates version `1`; an update must match the current
version. Each successful publication atomically commits the version, current
version pointer and append-only receipt after synchronizing the object file
and directories. Exact retries return the earlier verified outcome, including
after a lost acknowledgement. Changed requests or stale expected versions are
refused. Objects deduplicate only within the current `local-root` domain.
Historical versions remain readable; this interface has no deletion or export.

Status validates the schema, version chain, receipts and every managed object.
It lists unreferenced objects rather than deleting them. An exact, complete
temporary object can be resumed after current authorization/version checks;
partial bytes require inspection. A pending entry exposes
`retain_review_sha256`; `sudo luma-platform artifact-catalog-retain REQUEST-ID
RETAIN-REVIEW-SHA256` retains the reviewed bytes unchanged and blocks reuse of
that request. Use a new request afterward. Other requests are not globally
blocked by safe pending bytes, but every object/preparation consumes capacity.

The catalog requires private local ext4 storage and canonical protected paths.
It bounds object/preparation bytes to 64 MiB, files to 2,048 and committed
versions to 1,024. Metadata is separately limited to 4,096 4 KiB SQLite pages;
WAL/shared-memory admission is also bounded. Full inventory validation favors
safety over scale at these development limits. Unknown formats, links,
corruption and unsupported filesystems are refused without reset. No automatic
garbage collection, legacy migration or format downgrade is implemented.

The catalog owns its SQLite connection under an exclusive directory lock,
including reads, recovery and connection close. Do not open a competing SQL
writer or checkpoint tool. Copying a live database file alone is unsafe; the
existing offline recovery archive includes all `lib/luma-os` state. A source
copy test is not installed-image backup/restore qualification.

This storage backend follows the approved object/metadata ordering, but the
commands remain installed-root laboratory interfaces. Product Admin and
principal-bound grants, native DAG integration, generic artifact/public-schema
compatibility, trusted UTC, migration, receipted garbage collection and TPM
rollback protection are still required. See the
[catalog checkpoint](../evidence/G2_ARTIFACT_CATALOG_2026-10-03.md) for executed
scope and dependency qualification limits.

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
New images built with the 2026-10-01 helper accept `--timeout-seconds 1..1800`
and `--max-tokens 1..128`. Defaults remain 180 seconds/128 tokens. One deadline
covers prompt input, HTTP headers, response bytes, parsing and output; slow
individual reads cannot extend it indefinitely. Credentials remain local and
neither a timeout nor model text dispatches an OS effect.
The smoke request explicitly disables reasoning through the pinned runtime's
`chat_template_kwargs.enable_thinking=false` and `reasoning_effort=none`
controls, as documented by [llama.cpp at the pinned commit](https://github.com/ggml-org/llama.cpp/blob/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/tools/server/README.md#post-v1chatcompletions).
This keeps a short greeting test's token budget for its visible answer; it is
not evidence that reasoning was the cause of a previous timeout.

For a short functional check under software CPU emulation:

```sh
printf 'Reply with a short greeting.' | sudo luma-platform model-chat \
  --timeout-seconds 1800 --max-tokens 16
```

This larger explicit emulation budget is not native performance acceptance.
Sequence 10 and earlier do not support these options; rebuild first.
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

### Pending model-runtime integration (2026-10-02 source)

New source uses a root-owned, zero-length `model-runtime.lock` beside the model
selection. Provisioning holds it throughout acquisition/activation; the worker
acquires it before reading the selection and retains it across runtime launch.
Concurrent workers or an unmanaged worker racing activation are refused. The
normal installer/reconfiguration path creates the lock; startup never creates
or replaces it. Do not delete a lock file to bypass a refusal: an old descriptor
could remain active on the unlinked inode. Investigate/stop the owning worker.

The worker now retains the descriptor used to verify the selected weights and
passes `/proc/self/fd/N` to the pinned runtime. A replacement filename cannot
silently change the verified inode at launch. Weights and selection must be
root-owned, singly linked and not writable by group/other users. This does not
defend against hostile root modifying the same inode in place.

These changes are not in previously exported images. Existing installations
missing the lock refuse activation after a binary-only upgrade; no silent
startup migration is provided. The controlled `model-install MODEL-ID` path
creates it while holding the model-operation lock, after stopping the managed
service. Full update/migration and installed AppArmor/llama.cpp descriptor
qualification remain deferred to the consolidated image suite.

The exclusion lock is **not** the full resource-manager lease/generation system,
an atomic multi-file activation transaction, or a security boundary against a
compromised worker deliberately releasing its own descriptors. Cgroup limits
and runtime confinement remain necessary; pressure/quarantine, stale-worker
fencing and real model lifecycle evaluation are still open.

New source also writes `model-activation.pending` before changing the model
credential, reference environment or selection. The worker refuses to start
while it is present. For an interrupted activation on a controlled lab system,
run `sudo luma-platform model-activation-reconcile` to inspect the phase and
review digest. After investigating the cause, use `--abort-unchanged DIGEST`
only for `unchanged_prior_state`, or `--publish-committed DIGEST` only for
`consistent_candidate_committed`. For `partial_or_conflicting_state`, preserve
diagnostics and decide explicitly whether to roll forward to the named
candidate. Only after that review, `--complete-candidate DIGEST` verifies its
catalog-pinned weights and writes consistent candidate settings under the
fence before clearing it. Invalid weights, credentials or file state leave
the fence in place. None of these options starts or proves readiness of the
worker; restarting and checking it is a separate operator action. Never
delete the marker to bypass a refusal. This root-only laboratory diagnostic
is not a product Admin approval or signed production custody.

For installed reconfiguration, `model-install` now acquires and verifies the
candidate weights before stopping the managed worker. A failed download or
hash check leaves the current selection and worker untouched. A verified
cached model needs the 2 GiB free-space reserve, not another full download
allocation; `model-install-check` verifies the cache before applying that
threshold. Before stopping the worker, installation also requires an exact
loaded `active/running` or `inactive/dead` unit state; failed, transitioning,
missing or unavailable status refuses the operation. Admission and bytes are
rechecked after the stop, so this is not a resource reservation or a guarantee
that activation and restart will succeed. After reconfiguration, the command
waits up to 300 seconds for the fixed local model `/health` endpoint, then
checks the selected worker and reference service state before returning
success. A failed health check returns nonzero but does not silently roll back
the candidate; preserve diagnostics and use the reviewed activation procedure
if a fence remains. Listener health does not prove real inference or that the
endpoint is cryptographically bound to the model unit.

If the stop request fails or activation then fails, a restart of a previously
running worker is requested only when
its selection, service settings, credential and pinned weights are unchanged,
the runtime lock is free, and neither an activation fence nor recovery
disablement is present. The command still fails; check service health
separately. A stop failure while the old worker still holds its runtime lock
cannot trigger a duplicate restart. Partial activation remains fenced for
reviewed handling.

The reference service's model environment now lives in root-owned
`/var/lib/luma-os/model-reference.env`, outside its writable state directory.
Binary-only upgrades from an older image do not automatically migrate the
former `reference/model.env`. On a controlled installed lab system, an
operator can run `sudo luma-platform model-migrate-legacy` after preserving
recovery access. It verifies the old selection, credential, environment and
pinned weights before stopping the model, then creates the missing runtime
lock, publishes the new root-owned environment under the activation fence,
and requests a model/reference restart. It retains the old file for
older-image rollback. If it refuses, preserve state and investigate; never
remove the lock or activation marker to force startup. This path has passed
targeted source checks only, not an installed upgrade or rollback test. The
fence, new service wiring and policy also await installed-image qualification.
See the
[activation checkpoint](../evidence/G2_MODEL_ACTIVATION_FENCE_2026-10-02.md).

## Build on Ubuntu or Ubuntu WSL

Requires Docker, internet access to Ubuntu repositories on the first build,
and substantial free build space (allow 40 GiB for one build plus VM tests).
Without an external build directory, the builder requires 16 GiB free on the
repository filesystem for headless builds and 24 GiB for desktop builds.
With external artifacts, it requires 8 GiB there plus 40 GiB (headless) or
60 GiB (desktop) on the output filesystem.
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

Before downloads or package builds, the builder captures bounded source inputs
under `dist/native-sources/<build-time>-<edition>/`. Runtime pins, both
Dockerfiles and assembly/export use that captured tree, mounted read-only in
containers. Links, special files, oversized inputs and changes detected during
capture are rejected. Failed snapshots remain diagnostic artifacts, not reusable
build inputs. The shell driver is parsed before its long-running steps, so an
edit to the original script cannot change its remaining commands mid-build.

The builder uses an exact Ubuntu base digest and an Ubuntu archive snapshot.
`packages.lock`, `toolchain-packages.lock`, `source-lock.json`, signed release
metadata and SHA-256 checksums accompany the image. These identify the inputs;
random filesystem identifiers and laboratory keys mean byte-for-byte
reproducibility is not claimed. The initial CA bootstrap uses exact package
versions from the authenticated, release-only `noble main` archive, with all
other source lists excluded for that step. The base already supplies Ubuntu's
archive signing keyring. This avoids upgrading bootstrap dependencies from
moving update repositories before selecting the snapshot. Subsequent package
operations select the pinned HTTPS snapshot; no package-signature or TLS
verification is disabled. See [Ubuntu's snapshot documentation](https://ubuntu.com/server/docs/how-to/software/snapshot-service/)
and [archive verification model](https://documentation.ubuntu.com/security/software-integrity/archive-verification/).
No host block device or firmware is opened by the builder.

Output is under `dist/native/<build-time>-headless/`. The `.img.zst` decompresses
to a GPT disk image of about 11.1 GiB; it is **not an ISO**. Private keys remain
only in Docker volume `luma-native-lab-keys`. Never publish or copy that volume
to a test machine. Public `secureboot.cer` may be transferred with the image.

Build volumes are retained for diagnosis and VM testing. They are not silently
deleted. Repeated builds consume additional storage.

### External build drive (including Windows D: / exFAT)

For this machine's dedicated all-build-storage-on-D: setup, see the
[host profile](../host/README.md). Once installed and verified, `build.sh`
automatically selects its isolated D-backed Docker daemon and checks the
actual Linux store and D: capacity instead of reserving 8 GiB on C:. The
explicit entry point is `bash native/image/build-on-d.sh desktop NEXT_SEQUENCE`.
The source checkout stays on C:. Missing D: storage is an error, not a fallback.
The generic external-artifact instructions below describe the older profile,
which leaves Docker's Linux workspace on its existing backing drive.

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
root, `native-inputs/`, `native-sources/`, `work/BUILD-ID/artifacts/`, and exported `native/BUILD-ID/`
are created there. A fresh Docker volume retains the smaller Unix root/source/
compiler/payload workspace; lab private keys remain in their separate existing
Docker volume. No Docker-wide storage relocation occurs. Preflight requires
40 GiB (headless) or 60 GiB (desktop) free on the selected output filesystem,
and 8 GiB on the repository drive;
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

For current images, add `--require-clean-shutdown`: every normal stage must
power off from inside the guest and emit the verified late filesystem/DM
teardown marker. Deliberately failed trial stages instead require their
expected guest reboot/panic; they are not clean-shutdown passes. Without the
flag, normal stages still require guest poweroff, but do not assert storage
teardown. Host termination is used only for cleanup, never as a successful
normal-stage transition. The result lists `poweroff_stages` explicitly.

On TCG with external-drive storage, use `--timeout 5400` for the bounded
whole-stage budget. Manual installation allows up to 2,700 seconds under TCG
(900 under KVM); model acquisition allows 3,900 seconds. The whole-stage
deadline still applies. Preserve timed-out runs and retry in a fresh directory;
increasing a deadline is not evidence of a successful installation.

Images rebuilt with the transactional recovery-export change can also be tested
with `--require-atomic-export` (full sequence only). That adds acknowledged user
content, a real 1 MiB guest tmpfs exhaustion, preservation of the failed partial,
retry refusal and a complete exported-content hash check. Sequence 9 predates
this export change; do not claim its tests cover it or use that flag on it.

The same full sequence accepts `--require-bounded-ipc` for images rebuilt with
the whole-frame broker deadline. It runs as UID 990 (`luma-control`), drips both
header and body bytes, requires bounded denial, then checks that a fresh
authenticated status request succeeds. This does not test full policy/Admin
authorization, flood fairness or systemctl effect deadlines. Sequence 9 does
not contain the IPC repair. Both checks passed in the fresh sequence-10
14-stage regression; see [its checkpoint](../evidence/G2_BUILD_SNAPSHOT_2026-10-01.md).

### Installed desktop greeter evaluation

`desktop_vm_test.py` is a separate three-stage desktop-only fixture: fresh
manual installation, installed greeter, and cold-boot greeter. Use a new work
directory with the same read-only artifact/source mounts as the VM tests:

```sh
python3 /repo/native/image/desktop_vm_test.py \
  --image /work/artifacts/EXACT-DESKTOP-IMAGE.img \
  --work /work/vm-desktop-new --secure-boot --accel tcg \
  --timeout 5400 --require-clean-shutdown
```

It uses a software-only virtio VGA device, 4 GiB guest RAM, no guest network
and no host display/GPU/input access. Existing non-graphical VM runners retain
their original device configuration. On installed boots it checks the signed
graphical target, active GDM and an actual local seat-0 **Wayland greeter** in
logind. It repeats that observation after stopping the guest model, broker and
reference services, then restores them before clean poweroff. No automatic
login, GDM reconfiguration, PAM bypass or synthetic session is used.

Bounded [QMP screenshot requests](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-screendump)
retain fixed-name PNG evidence. The collector can include those greeter images;
it still excludes VM disks, NVRAM, software TPM state and arbitrary screenshots.
Failed runs retain `failure.json`, bounded journal diagnostics and an optional
failure screenshot, not a passing result.

This fixture does **not** authenticate a graphical user, test screen locking,
run the complete manual graphical workflow, or qualify physical GPUs. Its
result explicitly keeps those acceptance claims false. A passing QMP transport
unit/integration test alone is not a passing greeter or boot evaluation.

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

The model-specific runner uses a fresh 32 GiB virtual disk, two virtual CPUs,
and outbound NAT only during installation. Run it separately from other VMs
on a memory-constrained host. Its default remains Qwen3-4B with 6 GiB guest
RAM and approximately 2.5 GB of download. Explicitly select
`--model qwen3-1-7b-q4-k-m` to test fresh installation of the existing smaller
profile, with 4 GiB guest RAM and approximately 1.1 GB of download. This does
not replace 4B-tier qualification. Both download from their pinned publisher
URLs; no weights are pre-seeded. Unknown profile names are refused before
guest execution, and the image's catalog/selected identity, corruption target,
memory cap and inference result must agree with the selected fixture.

```sh
docker run --rm --device=/dev/kvm \
  --mount type=volume,src=BUILD_VOLUME,dst=/work \
  --mount type=bind,src="$PWD",dst=/repo,readonly \
  luma-native-tools:20260927 \
  python3 /repo/native/image/model_vm_test.py \
  --image /work/artifacts/EXACT-IMAGE-FROM-BUILD.img \
  --work /work/vm-model-new
```

Use `--secure-boot --accel tcg --require-clean-shutdown` for the software-TPM,
TCG fixture on images containing the late-shutdown integration. Omit
`--device=/dev/kvm` when selecting TCG. This enables Secure Boot in the private
VM firmware, checks it during every stage, and requires positive filesystem/DM
teardown after each stage. The result records these options; earlier model
results are not upgraded. Even without the stricter option, the runner now
requests guest power-off and requires a successful exit instead of treating
host termination as clean shutdown.

Unlike the offline platform suite, this command deliberately omits
`--network none`. It opens no guest port forwards. The runner checks real
completion-token output, unauthorized API refusal, kernel restrictions,
wrong-length and same-length corrupt weights, cached inference after an offline
reboot, independent-credential recovery disablement, and manual boot afterward.
Only a completed `result.json` is a pass; the existence of this script is not
evidence that these checks have executed on a particular image.

Corruption checks now require a fresh, exact native refusal from the model
unit after a captured journal cursor; they cannot pass merely because a prior
boot or earlier corruption trial logged the same error. Each observation
records both cursors. The helper follows the packaged
[systemd 255 journal cursor interface](https://www.freedesktop.org/software/systemd/man/255/journalctl.html#--after-cursor=).
Historical runs do not inherit this stronger evidence requirement.

For images containing the 2026-10-01 bounded helper, add `--bounded-model-chat`.
It selects 1,800 seconds/16 output tokens under TCG and 180 seconds/128 tokens
under KVM, verifies the returned budget/elapsed-time observations, and records
the choice. Without this flag, historical image commands remain unchanged.
The stage deadline still caps the complete stage. Inference failures retain a
separate `failure.json` and bounded runtime journal/cgroup diagnostics when the
guest remains reachable; these are not accepted results. Do not relabel a
source test, adjusted deadline or modified-guest diagnostic as an image pass.

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
The follow-up binds its memory fixture, selected identity and corruption path
to the model in the passing base result, supporting either of the two closed
profiles without silently substituting the default 4B model.

The reconfiguration, model-recovery and update-power-cut follow-up runners now
accept `--secure-boot --accel tcg --timeout 5400 --require-clean-shutdown`.
Every normal stage requires guest-initiated poweroff, even without the strict
flag. Strict mode additionally requires the fresh late teardown marker and
records the completed `poweroff_stages`. Only the explicitly injected
`cut-during-write` stage is killed by the host. Historical results that merely
synced then terminated QEMU do not inherit these assertions; rerun them.
The reconfiguration runner also accepts `--bounded-model-chat` for new images.

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
stick (32 GB or larger for the desktop edition), and a **disposable target disk** of at least 32 GiB (64 GiB recommended
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
and contains account/state material; protect it accordingly. Source builds after
sequence 9 require an existing empty directory owned by the invoking operator
(root in recovery), not writable by other users, with no symlink components.
The destination filesystem must support private file permissions, directory
locking/synchronization and no-overwrite rename. Unsupported filesystems are
refused; no weaker publication fallback is used.

The exporter writes `luma-user-data.tar.partial`, synchronizes completed output,
then publishes `luma-user-data.tar` without replacing any existing file and
synchronizes the directory. Failures retain partials and refuse reuse of that
directory. Retain them separately for inspection and select a new empty
directory for a new attempt. A final directory-sync error is an uncertain
durability outcome, not a success even if the final name is visible. No automatic
deletion or resumption occurs. This source repair is not in sequence 9.

`unlock` validates
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

### Pending-image maintenance implementation

The current source adds `luma-platform staging-clean` and `model-clean`, plus
the installed-boot `luma-staging-clean.service`. These changes are **not in the
previously exported sequence-4 image**. A new image and its VM results are
required before using these commands as part of that image's operator handoff.

Verified snapshots use the root-private `staging/verified-v1` namespace. A
nonblocking exclusive lock lasts through all consumption of the verified
bytes; acquisition first reconciles inactive snapshots. Cleanup validates a
bounded, closed inventory before unlinking exact files, rejects links,
mountpoints and unknown entries, and never traverses recovery mount trees.
Sparse-copy storage is measured against signed hashes before payload copying;
the copy is rehashed before it can be consumed. Concurrent external allocation
can still cause a write failure, which must fail closed and reclaim temporary
data. This is not a disk-space reservation service.

Model cleanup runs under the model-operation lock and preserves cataloged
GGUF files. Temporary downloads retain an inode lock inherited by the fetch
process, so an exited parent does not make a still-running downloader's file
eligible for cleanup. Unknown filenames, catalog-obsolete temporaries, unsafe
entries and oversized inventories require investigation rather than deletion.

Legacy `staging/bundle-*` directories are intentionally retained: an older
binary did not participate in the new locking protocol. Inspect them during
an approved offline maintenance window; do not remove them based only on age,
PID guesses, or a blanket recursive cleanup command. Maintenance failures are
visible in the service journal and do not disable manual recovery or gate
essential boot health on model availability.

The repeatable source-level Linux storage suite is
`native/tests/run_storage_boundaries.sh`. Run only in a fresh disposable tools
container with private mount namespaces, no host devices/network, read-only
repository input and a dedicated evidence output mount. It snapshots source
inputs and requires `CAP_SYS_ADMIN` solely for container-local tmpfs/bind tests.
It must not be run directly on an installed test OS. See the native CI job for
the exact invocation and the current evidence checkpoint for executed scope.

### Selected Admin variant and pending TPM integration

The owner selected **local TPM2-backed Admin** for the current installer target.
An external protected Admin service is a future installer variant, never an
automatic fallback. The exported sequence-4 image still has separate local
Unix accounts/sudo, **not enrolled product Admin**. Do not interpret that older
installer as already meeting the TPM requirement.

Current source adds `luma-platform tpm-probe`, `admin-install-check` and
`luma-platform admin-checkpoint-status`, all root-only read-only diagnostics.
The first reads `/dev/tpmrm0` clock/PCR data without enrollment; installation
admission additionally refuses an occupied checkpoint index. Checkpoint status
requires existing protected state and credentials and otherwise refuses.
None clears/provisions a TPM or grants a role. Installation now requires local
TPM admission before disk access and a second check immediately before disk
mutation. It records only pending enrollment intent, not active product Admin.
The native adapter/journal and admission have disposable software-TPM tests,
but the newly integrated sealed enrollment still needs image-level testing and
the full Admin service remains software work. These
installer changes are not in the previously exported sequence-4 image. See
[the implementation note](../LOCAL_TPM2_ADMIN.md).

`native/tests/run_tpm_boundaries.sh` runs in a fresh tools container with a
read-only repository mount and dedicated output mount, no network, no host TPM
devices, no Docker socket and no additional capabilities. Its repeatable
invocation is in `.github/workflows/native-platform.yml`. Evidence exports
logs/results/source hashes only, never the emulator state or NV secret.

The VM harness now attaches a persistent software TPM to each VM stage. Its
small private state must live on a filesystem enforcing Linux ownership/modes;
NTFS/DrvFS artifact and virtual-disk storage is not a substitute. By default it
uses the run's `tpm/` directory. When `/work` is an external-drive bind mount,
create a dedicated Docker volume and add these arguments to the VM container:

```sh
docker volume create luma-native-vm-tpm-state
# Additional docker run arguments (retain the existing disks/artifacts mounts):
# --mount type=volume,src=luma-native-vm-tpm-state,dst=/tpm-state
# --env LUMA_VM_TPM_ROOT=/tpm-state
```

An exact resolved run path selects a stable isolated namespace within that
volume. A held lock rejects competing harnesses, and shutdown retains state
while cleaning only transient sockets. Do not delete/copy TPM state to repair a
failed enrolled VM. Disk-overlay tests currently select a fresh run namespace;
authenticated migration/clone behavior must be implemented before using those
tests as enrolled-Admin continuity evidence. `collect_evidence.py` does not
export software-TPM state. The fixture requires a disposable tools container
without physical TPM devices; its transport is never a product fallback.

### Booted account-authentication and PCR fixture

`admin_vm_test.py` adds a separate installed-image check for the native PAM
diagnostic and signed-PCR credential policy. Use the same disposable VM mounts,
private `LUMA_VM_TPM_ROOT` volume and KVM device described above, with a fresh
`/work/vm-*` directory:

```sh
python3 /repo/native/image/admin_vm_test.py \
  --image /work/artifacts/EXACT-IMAGE-FROM-BUILD.img \
  --work /work/vm-admin-new --secure-boot --accel kvm
```

KVM availability alone does not establish that nested virtualization works.
If QEMU fails in that backend, retain its logs and use `--accel tcg` with a
different fresh work directory for software-emulated evaluation. Do not report
that run as KVM qualification. This occurred on the current WSL host during
the sequence-5 evaluation.

It installs manual mode, authenticates the public fixture administrator from
the controlling console, checks wrong-password/non-root rejection, and confirms
that authentication does not report product Admin authority. A public test
credential is sealed with PCR7 plus signed PCR11, recovered after a full guest
shutdown/reboot and a switch to signed slot B, and then refused after an
unapproved software-TPM PCR extend.
The image-owned public key must match the boot-provided key. A passing result
records the exact image and fixture-source hashes; no success is inferred merely
from adding this runner. This exercises the installed systemd credential path,
not completed native enrollment or a production Admin service. Never attach a
physical TPM or an existing installation disk to this fixture.

For images containing the late-shutdown integration, add
`--require-clean-shutdown`. Each stage must have the restore service armed and
the immutable initrd alias available, then emit `LUMA_SHUTDOWN_STORAGE_CLEAN`
after the old-root mounts and device-mapper devices are absent. Merely exiting
QEMU successfully is insufficient. Earlier sequence-8 results did not execute
this stricter check and retain their shutdown warnings as unresolved evidence.

### Gate boundary

Actual VM execution demonstrates implemented paths on virtual hardware. It
does not close physical firmware, TPM, accelerator, power-cut, suspend/resume,
two-board, model-performance, production custody, or full G2 requirements.
Failed or unexecuted matrix entries remain open. See `BUILD_PLAN.md` and the
image-specific evidence; do not infer acceptance from this feature list.
