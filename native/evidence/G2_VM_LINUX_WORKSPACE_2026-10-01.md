# Desktop virtual-disk I/O and Linux workspace - 2026-10-01

G2 remains **incomplete**. The checkout was clean at the start of this
continuation; preceding changes were already committed through `7f0e94f`.

## Second desktop attempt failed

The 6 GiB installation fixture passed snapshot admission and reached slot
copying, but failed with `Input/output error (os error 5)`. Its guest log also
contains media reads failing on `vdb` and target writes failing on `vda2`.
This was not the earlier tmpfs-capacity refusal. No installation completion
was reported; the queue exited 1 before starting a model VM.

Retained failure:
`D:\LumaOS-builds\work\20261001T090338Z-desktop\vm-desktop-greeter-20261001-02`.
The virtual disk is not repaired, resumed or reused. Live diagnostics show
3,048,304,640 bytes free in `/var` after failed snapshot cleanup and no guest
swap; those post-failure observations do not measure peak memory.

Read-only checks found D: Healthy/OK with about 112 GiB free, about 82 GiB free
in the dedicated ext4 store, and no qcow2 metadata errors from `qemu-img check`
on the failed target. The bounded Windows event query returned no relevant
storage event. These do **not** establish physical disk health or the exact
cause. Historical WSL shutdown/9p warnings were not reliably correlated with
this failure and are not causal proof. No disk repair, WSL shutdown, filesystem
migration, destructive cleanup or host service change was performed.

## Test-path isolation, not an OS patch

The next run puts media and VM disks in a new named volume on the **existing
D-backed ext4 store**, instead of exposing each QEMU file directly through
`/mnt/d` and its 9p file layer. The backing file still lives on D:; this does
not isolate the physical device or every WSL storage dependency. Source stays
on C:, public images on D:, and all failed runs remain intact.

`native/image/vm_workspace.py` stages the pinned raw candidate, `build.json`
and public Secure Boot certificate into an empty `/work` ext4 volume. It rejects
links/special inputs, unsafe image names, duplicate metadata/checksum entries,
digest disagreement, insufficient capacity and reused destinations. Copies
preserve zero regions, synchronize output, verify source and destination hashes,
and publish without replacing existing names. Failures retain partials without
a ready record. **Prepared** is not booted, signed production or accepted.
Operator-owned input/output trees are assumed; this is not protection against
a hostile root changing mounts. The inventory supports the desktop/model
runners, not every update runner or a complete build export.

The image digest is unchanged:
`96f0083cf64e7d968992256da96f3ed9f1a24d1696ed6c5d8be7a72ca66e264b`.
No patch is injected into the signed guest. Later broker and snapshot RAM
source repairs still need a future image rebuild and evaluation.

## Executed verification

All **121 native Linux Python tests passed**, warnings treated as errors,
including six new staging-contract tests. Rust is unchanged and was not
retested this turn. `git diff --check` passed.

Evidence: `D:\LumaOS-builds\g2-vm-workspace-tests-20261001-01`.

- Input manifest SHA-256:
  `10e8efd98cac2471fc6d47bec3d5b8ca7653c7cd7a9c8430ce6f1793bf8e9494`.
- Completed `test.log` SHA-256:
  `356b3ecb7d09a3c802239c9b3fbd6fdaa7ed2bb909644c0b9fa0dd6bc5bd98bb`.

Native tests were copied separately into the frozen source tree. Later docs
changes do not change the tested helper or queued harness.

A separate fresh ext4 volume passed actual file synchronization/exclusive-lock
checks, QEMU patterned writes and read-back, flush, 16 MiB extents at 1, 2 and
4 GiB offsets, discard/zero-read with neighboring extent preservation, and
qcow2 metadata checks. This bounded probe is not a full-image workload
reproduction or physical qualification. The format operations are documented
in [QEMU's block-driver reference](https://www.qemu.org/docs/master/system/qemu-block-drivers.html);
the pass here is from actual local execution.

## Current serialized execution

Queue log: `D:\LumaOS-builds\g2-desktop-linux-queue-20261001-01\run.log`.
Host/storage preflights and the ext4 probe passed. Candidate copy and read-back
verification are running; neither desktop nor model evaluation has passed.

- Workspace volume: `luma-g2-desktop-linux-work-20261001-01`.
- Probe volume: `luma-g2-desktop-linux-probe-20261001-01`.
- Desktop directory inside workspace: `/work/vm-desktop-linux-20261001-01`.
- Later model directory: `/work/vm-model-linux-20261001-01`.
- Private TPM volumes: `luma-g2-desktop-linux-tpm-20261001-01` and, only after
  desktop success/export, `luma-g2-model-linux-tpm-20261001-01`.

The desktop fixture retains 6 GiB for installation, 4 GiB for installed greeter,
TCG, virtual Secure Boot, software TPM, no guest network and strict shutdown.
Fresh 4B installation/inference follows only after desktop success/export and
another space check; only publisher acquisition enables guest networking, with
no port forwarding. Any error stops the chain. Public passing evidence will
be exported beside the original image. Never publish private volumes, VM disks,
NVRAM or the backing store. Full G2 implementation and qualification remain open.
