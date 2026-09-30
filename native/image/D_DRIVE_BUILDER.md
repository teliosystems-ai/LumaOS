# D: build storage and recovery record

Current checkpoint, 2026-09-30: sequence 9 passed its four-stage Secure Boot/TCG
PAM/PCR fixture including verified late storage teardown; broader regression
is running. Sequence 10 (`20260930T073705Z-headless`) is building on D: with
the transactional recovery exporter and bounded IPC changes. Its image tests
are queued after verified export and the current VM pipeline. See the
[IPC/rebuild checkpoint](../evidence/NATIVE_IPC_2026-09-30.md). Neither image is
the final all-components G2 release. The older observations below are history.

## Resumed external-artifact build

After the owner reported completing repairs on 2026-09-29, a new read-only
check reported **Healthy / OK**, with no CHKDSK process running. D: remains
**exFAT**. This is a filesystem-health observation, not a surface-test or
artifact-integrity certificate; the owner's repair transcript was not imported.

The separate sparse/ACL-backed Docker-daemon proposal below remains unavailable
on this filesystem. Instead, the existing external-artifact build mode was
resumed: cached Docker layers, the small Linux workspace and private signing
keys stay in Ubuntu's C:-backed storage; large public image artifacts and fresh
VM disks use D:. No drive reformat, Docker migration or private-key transfer
was performed. The unused 256 GiB backing file is unchanged.

Before launch, the cached root filesystem measured 1,251,774,464 bytes. The
build preflight recorded 11,964,891,136 free bytes on C: (8 GiB minimum) and
439,318,478,848 on D: (40 GiB minimum). The cached runtime archive from D:
was revalidated against its pinned size and SHA-256 before reuse. Old VM disks
are not reused as qualification evidence.

The fresh sequence-5 build uses `D:\LumaOS-builds\work\20260929T170514Z-headless`
for artifacts, with export target `D:\LumaOS-builds\native\20260929T170514Z-headless`.
Build/VM results must be checked before calling this image test-ready. G2's
remaining implementation and acceptance requirements remain open.

Sequence 5 completed verified export, but its TCG installation test exposed a
live-payload device timeout. The corrected sequence-6 build uses
`D:\LumaOS-builds\work\20260929T175214Z-headless` and export target
`D:\LumaOS-builds\native\20260929T175214Z-headless`. Its verified export completed,
and live-media mounting passed, but installation was refused because the
packaged TPM device ownership conflicts with the native admission check. See
the [sequence-6 checkpoint](../evidence/TEST_IMAGE_SEQUENCE6_2026-09-29.md).

Before another build, C: was observed with 6,105,718,784 free bytes (about
5.7 GiB), below the builder's 8 GiB minimum; D: had 382,445,289,472 free bytes.
The TPM ownership repair needs another image, but no rebuild was started and
no capacity threshold was bypassed. Free space on C: is required (preferably
12-16 GiB headroom), or a separately approved supported storage relocation.
No old build volumes, evidence, keys or unrelated data were deleted. Removing
Linux files alone does not guarantee the Windows-backed virtual disk shrinks.

The owner subsequently freed C: space. Read-only checks reported
20,226,060,288 free bytes on C: and 372,726,038,528 on D:. The sequence-7
preflight passed and build `20260929T194815Z-headless` started with the tested
TPM ownership repair. Its work/export directories follow the same layout on
D:. Completion, exported digests and boot acceptance are pending; the earlier
capacity blocker is no longer active for this build.

Sequence 7 then failed its initrd content guard before disk-image generation.
A separate-root dracut inclusion fix passed a retained-root regression, and
sequence 8 (`20260929T195529Z-headless`) passed that full-build guard and entered
filesystem assembly. A bounded local pipeline will run the fresh VM fixture
only after successful verified export. See the
[sysroot integration checkpoint](../evidence/NATIVE_INITRD_SYSROOT_2026-09-29.md).

Sequence 8 completed export and its four-stage Admin/PCR VM suite. Shutdown
storage warnings remained and led to a further source repair. Sequence 9
(`20260929T221048Z-headless`) is building with that repair; its gated pipeline
will run strict shutdown/Admin/PCR checks followed by the broader 14-stage VM
regression. Results are pending; see the
[shutdown checkpoint](../evidence/NATIVE_SHUTDOWN_2026-09-30.md).

## Earlier isolated-daemon proposal and storage incident

The build client in this environment uses Docker Engine inside Ubuntu WSL,
not the separate Docker Desktop engine. Its existing `/var/lib/docker` and
containerd data reside in Ubuntu's C:-backed virtual disk. Changing Docker
Desktop's disk location would not move this engine's build data.

The selected approach is a separate, host-local build daemon backed by
`D:\LumaOS-builds\docker\build-store.ext4`, mounted at
`/mnt/luma-docker-build`. Existing Docker services, images, volumes and keys
are not migrated, deleted or reconfigured. The earlier attempted owner/SYSTEM
ACL is **not a protection boundary**: the drive was subsequently identified
as exFAT, which does not support ACLs or sparse files. No private key transfer
has occurred. The proposed sparse-file setup requires healthy NTFS storage;
changing the existing drive's filesystem is not authorized.

## Historical state before recovery, 2026-09-29

- Created the dedicated directory and a new empty backing file.
- Added `docker-d-drive.json` and `start_d_drive_docker.sh`; the shell scripts
  passed syntax checks, but the daemon has **not** been started or tested.
- Added optional `LUMA_BUILD_NETWORK=host` support to the image build script;
  its default remains unchanged. Container assembly still uses no networking.
- The first attempt to grow the backing file to 256 GiB stalled in WSL's
  DrvFS/9p I/O. Cancellation was requested for that exact `truncate` process,
  but remained pending in uninterruptible disk sleep at this checkpoint.
  Formatting and Docker startup have not been confirmed or evaluated.
- No image build has started on this store. Do not treat it as ready.

The owner subsequently approved stopping/restarting Ubuntu WSL. The command
`wsl.exe --terminate Ubuntu` reported success, but the following Ubuntu startup
and WSL status checks remained pending. Windows Docker Desktop was still
responsive and reported an additional running `registry` container on port
5000. A full shared-WSL restart would interrupt that separate workload too;
approval was requested before expanding recovery to that backend. No full WSL
shutdown, service force-kill, host reboot or additional file formatting has
been performed at that earlier checkpoint.

## Recovery update

The owner then approved the full shared-WSL restart. `wsl.exe --shutdown`
succeeded and both distributions reported stopped. Ubuntu restarted with its
existing Docker containers. Docker Desktop's initial restart timed out while
stopping, but its old processes subsequently exited; relaunch restored its
running status and the original registry container on port 5000.

Read-only storage checks reported:

- D: filesystem: **exFAT**, health **Warning**, status **Full Repair Needed**.
- The new backing file is 274,877,906,944 bytes (256 GiB), fully allocated,
  not sparse. Setting the sparse flag failed with `Incorrect function`.
- `chkdsk D:` (no repair options) reported corruption attributed to bad
  sectors in `LumaOS-builds\work\20260928T124255Z-headless\vm-seq4-01-small`,
  affecting directory entries 896 through 1023. It also emitted `Access is
  denied`. The scan was stopped after that finding; it was **not** a complete
  surface test or definitive hardware diagnosis. No `/f`, `/r` or `/x` was run.
- No image format/mount, new Docker daemon, image build, private-key transfer,
  file deletion, volume repair or Windows reboot was performed.

Build writes are suspended. Preserve important data to a healthy destination
before making a separately approved repair/recovery decision. Existing D:
artifacts require renewed integrity verification; their old hashes alone do
not establish current readability. The unused 256 GiB backing file remains
untouched pending recovery. Do not reclaim it by deleting or truncating files
on a suspect filesystem as part of an automatic build retry.

The startup script now calls a read-only Windows preflight before touching the
backing file: it refuses unhealthy/non-NTFS storage, a nonsparse/reparse backing
file and insufficient physical capacity. The D: daemon remains untested and
unavailable, not ready for resumed builds.

References: [Microsoft filesystem feature comparison](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison)
and [read-only versus repair CHKDSK modes](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk).

## Owner-approved repair started

On 2026-09-29 the owner explicitly requested disk repairs. The unelevated
session could not repair the volume, so the repair wrapper was launched through
Windows UAC, with administrator consent. It verifies D:'s exact volume GUID,
exFAT filesystem and 1,000,184,217,600-byte capacity before invoking CHKDSK on
the stable volume GUID (not an unverified/reassigned drive letter).

`CHKDSK /r /x` started at approximately 09:09 UTC, dismounted the volume and
reported a media error followed by bad-sector checking. `/r` includes filesystem
repair; `/x` invalidates open handles. No formatting, filesystem conversion,
orphan-discard option or automatic reboot was requested. Backup verification
was not established and is recorded as false, not presumed from authorization.

The local wrapper and logs are excluded from Git under `.luma/`. Current run:
`C:\Users\hakim\LumaOS\.luma\repair-d-20260929T090911Z`, with `status.json`,
`chkdsk.stdout.log` and `chkdsk.stderr.log`. Read those files on C: to monitor;
do not access the dismounted D: volume during repair. The wrapper records the
exit code and post-run volume health for review. **Repair start is not repair
success**, artifact-integrity evidence, hardware qualification or build readiness.
Even if repairs succeed, exFAT still does not support the proposed NTFS sparse/
ACL-backed builder. No new image build has been started.

At the owner's subsequent explicit request, the exact CHKDSK process was stopped
at 11:49:47 UTC on 2026-09-29. Its exit and the wrapper's exit were verified.
`stop-result.json` records `stopped-at-owner-request`; this is **cancellation,
not a successful repair**. The wrapper observed `Warning / Full Repair Needed`
after cancellation and did not retain a numeric exit code. The last observed
free-space scan progress was 48%. No replacement repair was launched; the owner
is taking over execution. Build writes remain suspended.

## Recovery and completion requirements

First resolve the pending allocation and check the resulting file and free
space. Do not rerun formatting, delete the file while it is in use, or assume
that `truncate` on DrvFS creates an NTFS sparse file. Explicitly set and verify
the NTFS sparse flag **before** extending a newly created backing file.
[Microsoft's sparse-file commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-sparse)
describe `fsutil sparse setflag` and `queryflag`. The allocation must be verified
on Windows as well as inside Linux. A WSL shutdown interrupts other Ubuntu
processes and requires a coordinated maintenance decision.

After recovery, prepare and verify ext4 only inside this newly created regular
file, then run the start script as WSL root. The script never formats storage,
refuses a wrong backing device, and refuses to hide a nonempty mount directory.
It starts a transient service, not an automatic boot service. After a WSL
restart, remount and start explicitly; never fall back to the default daemon.

The proposed daemon has its own socket, PID, execution and storage directories.
It uses the classic overlay2 store and its own managed containerd, with no
bridge, forwarding or firewall manipulation. This is development infrastructure,
not an OS runtime isolation claim. Docker documents
[multiple daemons as experimental](https://docs.docker.com/reference/cli/dockerd/#run-multiple-daemons);
verify the resulting data paths and a disposable container before a full build.

Before building, transfer only the required cached images and the private lab
key volume with explicit source/destination daemon endpoints and private
streaming transfer; verify identities without exporting private key bytes to
logs, Git or public artifact directories. This transfer has not occurred.

The intended build environment is:

```sh
export DOCKER_HOST=unix:///run/luma-docker-build/docker.sock
export LUMA_BUILD_ROOT=/mnt/d/LumaOS-builds
export LUMA_BUILD_NETWORK=host
# Verify DockerRootDir is /mnt/luma-docker-build/docker and check both filesystem
# and Windows physical-drive headroom before invoking native/image/build.sh.
```

Host networking is only for the pinned dependency-fetching build steps and
provides no host-network isolation. Product/fixture execution keeps its existing
network restrictions. A successful image build still does not close the
software and acceptance gaps in `native/G2_SOFTWARE_STATUS.md`.
