# Dedicated D-backed Luma build host

This is host setup for the current Windows/Ubuntu WSL development machine,
not configuration installed into the Luma OS image. The source repository
remains at `C:\Users\hakim\LumaOS`. Public images/installers, inputs, logs and
VM disks remain under `D:\LumaOS-builds`.

Current execution direction: **implementation first**, then a consolidated
image-test sweep and separate native Ubuntu testing. Do not apply the proposed
WSL memory increase or restart old VM queues during implementation. Small
targeted checks remain permitted; see [the agreed sequence](../G2_IMPLEMENTATION_FIRST.md).

The dedicated profile uses:

| Purpose | Location |
| --- | --- |
| New 96 GiB ext4 backing file | `D:\LumaOS-builds\docker\luma-build-v1.ext4` |
| Linux mount | `/mnt/luma-build` |
| Docker images, layers and volumes | `/mnt/luma-build/docker` |
| Dedicated containerd persistent state | `/mnt/luma-build/containerd` |
| Daemon temporary files | `/mnt/luma-build/tmp/daemon` |
| Client configuration and temporary files | `/mnt/luma-build/client/hakim` and `/mnt/luma-build/client/root` |
| Dedicated socket | `/run/luma-build-docker.sock` |
| Host configuration | `/etc/luma-build` |

The old `build-store.ext4` is preserved; it was not recognized as an ext4
filesystem during read-only inspection. No physical partition is formatted.
Existing `/var/lib/docker`, `/var/lib/containerd`, default Docker settings,
unrelated workloads and historical build/TPM volumes are not moved or deleted.
Only selected public Luma images and the lab-key volume are copied. The keys
travel directly between local containers and are checked without printing key
bytes or creating a public archive. The original key volume stays intact.

The backing file contains private laboratory keys once that copy completes.
Linux permissions protect the mounted key volume, but the exFAT backing file
is **not encrypted** and can be copied by someone with Windows/drive access.
Do not publish the backing file or use it for production signing custody.

## Operation after host setup has passed validation

For current VM acceptance, use a fresh named volume on this dedicated daemon
for both media and virtual disks. The sequence-11 6 GiB installer run encountered
media-read and target-write I/O errors with QEMU files directly on `/mnt/d`.
An ext4-workspace retry isolates that file path; the exact cause is not yet
established. See the [I/O checkpoint](../evidence/G2_VM_LINUX_WORKSPACE_2026-10-01.md).
This still uses the D: backing file, not C: or a newly formatted drive.

After activating and verifying the dedicated profile, create a new empty named
volume and stage media with `native/image/vm_workspace.py` in the tools container:
mount the volume at `/work`, the original artifact directory read-only at
`/input`, and frozen source read-only at `/repo`. Pass
`--expected-image-sha256 EXACT_RECORDED_IMAGE_SHA256`. The helper requires ext4,
checks capacity for the image plus 36 GiB, and refuses reused workspaces. It
copies only raw media, build metadata and the public firmware certificate;
it is not a complete update-artifact export. Mount staged `/work/artifacts`
read-only for VM execution. Recheck capacity before another fresh VM disk.
Retain failed workspaces for diagnosis; do not reuse or silently repair them.

The shared VM harness now checks Linux `/proc/meminfo` before creating stage
state, provisioning the software TPM or starting QEMU. It requires the full
configured guest RAM **plus 2 GiB host headroom** in `MemAvailable`; swap and
total installed RAM do not substitute for available RAM. A 6 GiB installation
or 4B guest therefore needs at least 8 GiB **available**, not merely an 8 GiB
WSL limit. A 4 GiB guest needs 6 GiB available. The prior 6 GiB desktop run drove
this 8 GiB WSL host to about 20 MiB available and was stopped without a pass.
See [the memory checkpoint](../evidence/G2_HOST_MEMORY_2026-10-01.md).

This check is a conservative observation, not a reservation or cgroup-limit
validator; competing allocations and tighter container/ancestor limits still
matter. Serialize large jobs and use an adequately provisioned host. Do not
silently shrink the required guest, count swap as RAM, stop unrelated services,
or change global WSL settings to bypass refusal. A possible 10 GiB WSL limit
needs operator approval, Windows-memory review and a planned restart, followed
by fresh admission; it is not an automatic guarantee. Existing frozen queues
do not inherit new source safeguards and must not be resumed unchanged.

Increasing the WSL memory ceiling is not impact-free. It permits WSL to compete
for more host RAM, and applying configuration requires a WSL VM restart; a
global shutdown interrupts all running WSL distributions and their processes.
On 2026-10-01 the read-only impact check found about 2.2 GiB free Windows RAM
and six unrelated running containers. No `.wslconfig` existed, and none was
created. Do not interpret approval conditional on "no effect on other
processes" as approval to interrupt those workloads. Coordinate saving work,
gracefully stopping affected applications and cleanly stopping the dedicated
D-backed store before an approved restart; then recheck both Windows and WSL
headroom. See [Microsoft's WSL configuration documentation](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)
and the [impact checkpoint](../evidence/G2_MODEL_REPLY_2026-10-01.md).

From Ubuntu WSL in the repository:

```sh
bash native/image/build-on-d.sh desktop NEXT_SEQUENCE
```

For diagnostics or native tests:

```sh
source /etc/luma-build/environment.sh
docker info --format '{{.DockerRootDir}} {{.Driver}}'
python3 native/image/build_storage.py preflight \
  --repository "$PWD" --external "$LUMA_BUILD_ROOT" --edition desktop
```

The expected Docker root is `/mnt/luma-build/docker`, using `overlay2`.
The builder verifies the exact D: backing file, writable ext4 loop mount,
identity marker, dedicated daemon, client temp/config paths and free space.
It requires 32 GiB free inside the Linux store and 60 GiB on D: for desktop
builds (24/40 GiB for headless), instead of reserving build space on C:.
Once the host profile is installed, the ordinary `build.sh` command also
selects it automatically. On other hosts without that profile, the original
portable behavior remains. `LUMA_BUILD_PROFILE=standard` is an explicit legacy
opt-out with the older C:/repository guard; do not use it for this D-only setup.
An unavailable D: drive or wrong daemon fails closed, never falling back to C:.

The dedicated Docker service depends on the verified store mount. To start it
after WSL startup if necessary, use Windows PowerShell:

```powershell
wsl.exe -d Ubuntu -u root -- systemctl start luma-build-docker.service
```

The daemon has its own socket, execution root, dedicated containerd service
and data root. Admission rejects the default containerd socket/namespaces too;
moving only Docker's data root is insufficient on this packaged Docker version.
It does not alter shared bridge/firewall rules. Package downloads use explicit
host networking; assembly and ordinary tests continue to use `--network none`.
A model acquisition test on this daemon must explicitly choose `--network host`
instead of the disabled bridge; that gives the **container** host networking,
while QEMU still controls guest networking. Do not expose guest ports or run
untrusted code with host networking. Existing old-daemon runner scripts are
not automatically redirected; select this profile explicitly for new work.

Docker considers multiple daemons on one host experimental. This dedicated
instance separates their state and disables its bridge/firewall management;
local execution and persistence checks are required, not assumed from config.
See [Docker's multiple-daemon instructions](https://docs.docker.com/reference/cli/dockerd/#run-multiple-daemons).

Build containers and this daemon use `luma-build.slice` with `MemorySwapMax=0`.
This prevents their Linux memory from spilling into the existing WSL swap file;
it does not promise zero Windows pagefile, system-log or IDE writes on C:.
No global WSL shutdown, default distribution move or Windows paging change is
part of this setup.

Do not unplug D: while mounted. Before safe removal, finish/stop only Luma's
dedicated jobs, then stop `luma-build-docker.service` followed by
`luma-build-store.service` as WSL root. Never force unmount a busy store. Both
the outer exFAT filesystem and inner ext4 filesystem need clean shutdown; this
laboratory setup is not damaged-media or power-loss certification.
