# Native storage crash-safety checkpoint - 2026-09-28

G2 remains in progress. This is **source-level implementation and executed
Linux boundary evidence**, not a rebuilt image, product acceptance, or physical
qualification. The previous sequence-4 image and its hashes are unchanged.

## Implemented

- Verified-bundle snapshots have a dedicated root-private versioned namespace
  and an exclusive operation lock retained until all verified bytes have been
  consumed. New operations and installed-boot maintenance reconcile inactive
  snapshots; active operations are refused, not evicted.
- Cleanup validates a bounded closed inventory before deleting exact files.
  Unknown entries, symlinks, hardlinks, other mounts (including same-filesystem
  bind mounts), unsafe ownership/permissions and excess inventory fail closed.
  It never recursively traverses recovery mount directories.
- Storage admission measures sparse-copy allocation from signed artifact
  bytes, retains source descriptors and rehashes during copying. A sparse root
  image does not need its entire logical size reserved in live-media tmpfs.
  Source changes cannot become verified output. Competing allocations can
  still cause ENOSPC: this preflight is not an atomic resource reservation.
- Model download temporaries are reconciled under the existing model-operation
  lock. The fetch output descriptor now carries a lock inherited by the child,
  preventing cleanup while that descriptor remains active. Completed cataloged
  GGUF files are not cleanup targets. Unknown/catalog-obsolete files are retained.
- Root-only `staging-clean` and `model-clean` commands and a confined installed-
  boot maintenance unit are included in the source. Unit syntax was verified;
  the new unit's actual systemd execution in a rebuilt image is still pending.
- Bundle member opens reject FIFOs without blocking. The long-running test
  harness and its source inputs are snapshotted before execution.

The lab root/host administrator remains trusted. These locks do not prevent a
compromised root from replacing state or running an incompatible older binary.
Legacy unversioned `staging/bundle-*` directories are deliberately preserved:
older processes did not participate in this locking protocol. They need
operator-reviewed offline disposition, not deletion based on filename age.

## Executed evidence

Final successful run: `D:\LumaOS-builds\native-tests-20260928-g2-storage-05`.
Its five evidence files were rehashed, and every listed source digest was
compared with the current workspace after execution. Identities are retained
in [the machine-readable record](native_storage_2026-09-28.json).

- 30 native Rust tests passed with warnings denied, including 1,000 snapshot
  create/use/drop cycles, eight actual process-SIGKILL/reconciliation cycles,
  active-operation refusal, retained child-descriptor locks, source mutation,
  bounds and hostile filesystem entries.
- Nine real Linux integration cases passed: directory/file bind-mount refusal,
  legacy/recovery preservation, real Ed25519-signed bundle verification,
  bad-signature cleanup, FIFO refusal, constrained tmpfs admission, sparse
  payload larger than its staging filesystem, and actual mid-copy ENOSPC
  cleanup followed by successful verification after releasing pressure.
- Nine native Python tests passed on Ubuntu userspace and Windows.
- `systemd-analyze verify` passed for the new maintenance unit with the actual
  compiled executable installed in the disposable container. This checks unit
  configuration, not runtime confinement enforcement.
- The 320-test Windows reference suite passed with five skips; governing
  source checks (288 entries), the frozen 170-file release inventory, Python
  syntax, shell syntax and `git diff --check` passed.

The Linux environment was the pinned Ubuntu tools image on WSL2 kernel
`6.18.33.2-microsoft-standard-WSL2`, with network disabled and no host devices.
CAP_SYS_ADMIN was supplied only for test mounts in the disposable container's
mount namespace. Private test signing material remained inside that container;
no production signing, host installation, firmware change or model deletion
was performed. D: stores the output evidence, not the pressured test filesystem.

Intermediate runs remain diagnostic records, not final acceptance. In
particular, run 01 stopped on a warnings-denied compiler error; run 04 passed
its Linux cases but its still-running checkout-backed shell script was edited
before final reporting, causing an EOF error. Run 05 executes the snapshotted
harness and completed the entire suite with exit status zero. Remote CI was
updated but not executed here.

## Not closed by this checkpoint

These are **snapshot** lifecycle tests, not 1,000 compact-model load/unload
cycles. The inherited-descriptor test uses a real child process, not an
interrupted HTTPS download/inference qualification. tmpfs ENOSPC and SIGKILL
are not physical disk-power-loss evidence. The signed test bundle has real
verified bytes but is not a bootable release fixture.

A new image build, installed maintenance execution, actual model-acquisition
interruption, repeated guest update interruptions and broader storage/recovery
matrix remain required. The native policy/Admin/durable-effect/skills vertical
workflow, full model/resource lifecycle, Wayland desktop, production trust
integration and remaining G2 matrix are also still open, as enumerated in
[the software register](../G2_SOFTWARE_STATUS.md). They have not been relabeled
as hardware deferrals.
