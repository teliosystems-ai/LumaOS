# Desktop installer memory admission - 2026-10-01

G2 is **incomplete**. The worktree was clean at the start of this continuation;
all preceding changes were already committed through `5182cb3`.

## Actual image failure and cause

The first sequence-11 desktop fixture failed during manual installation with
`insufficient snapshot storage; no payload copied`, before destructive disk
confirmation. It did not complete installation or qualify a desktop. The
failed virtual disk, TPM state, serial log and `failure.json` remain intact at
`D:\LumaOS-builds\work\20261001T090338Z-desktop\vm-desktop-greeter-20261001-01`.
No model VM followed that failure.

The signed artifacts were then read, SHA-256 checked and measured in a
read-only container. The existing 1 MiB sparse-copy algorithm needs
**2,413,654,016 bytes**, plus its 64 MiB reserve: **2,480,762,880 bytes** total.
This cannot fit in the default live `/var` tmpfs of the 4 GiB guest. A finer
4 KiB zero-page measurement was also taken: 2,402,242,560 bytes, still too
large. Changing sparse granularity alone would not resolve this failure.

The default tmpfs limit is half physical RAM, as documented by the
[Linux kernel tmpfs documentation](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html).
This is a **guest RAM-backed staging limit**, not a shortage of space on D:.
No drive repair, tmpfs remount, swap expansion or disk cleanup was performed.

Measurement log:
`D:\LumaOS-builds\g2-desktop-storage-measure-20261001-01\measurement.log`.
SHA-256: `e6b46e7e98081ae6c7fef3713c620c59624dc232ac68cc9942a948630cfd9a34`.

## Implementation and fixture changes

The native snapshot admission error now reports requested bytes, reserve and
available filesystem capacity. It also identifies tmpfs through `fstatfs()`
on the already-open staging directory descriptor and requires measured
`MemAvailable` to cover the payload plus a **2 GiB RAM reserve** for the OS and
memory-hard key derivation. Invalid observations, arithmetic overflow or an
unreadable filesystem/memory observation refuse admission. Persistent ext4
staging retains its filesystem/inode checks. The default live tmpfs size,
cryptsetup policy, signed inventory, private-copy verification, source mutation
checks and pre-confirmation refusal ordering are unchanged.

This is a conservative admission observation, **not** an atomic resource lease,
cgroup-aware global resource allocator or a guarantee against concurrent memory
pressure/OOM. Those resource-service and fault-injection requirements remain
open. This source change needs a later rebuilt image before image-level testing.

The desktop runner now uses **6 GiB during installation** and **4 GiB for both
installed greeter boots**, recording the per-stage values in its result and the
current stage's memory in failures. This is not a 4 GiB installation claim.
The 4B rejection probe runs only in the existing 4 GiB manual fixture; it is
not expected to fail for lack of RAM in a 6 GiB fixture. The desktop result
explicitly records that this model-memory rejection was not tested there.
Tampered-bundle rejection remains required. Failure diagnostics now attempt
live filesystem and RAM observations as well as desktop journals.

## Verification and retry

Frozen source verification completed successfully under
`D:\LumaOS-builds\g2-desktop-admission-tests-20261001-01` with offline locked
Rust tests/build and formatting/warnings checks. All **62 ordinary Rust tests**
and **115 native Linux Python tests** passed. Seven specialized Rust tests were
ignored in this ordinary run, not rerun. All **13 desktop-fixture tests** also
passed on native Windows. `git diff --check` passed. The full Linux process
exited zero; completed `test.log` SHA-256 is
`867c034f736e9470bd930527dd3e230c5828a1b0593811d9def76356f36f200f`.
Its input-manifest SHA-256 is
`d5b4607b9ba812dcd8942a49b0ade207cc1a6300496fc7c39c89e27dce09e356`.
Native tests were copied separately into that frozen tree. The new Rust tests
exercise memory/space arithmetic and invalid observations; they are not a
booted-image or OOM-pressure qualification.

A fresh serialized queue observed the passing source checks and passed the
D-backed storage preflight. It has advanced to exact-image verification for the
same immutable sequence-11 media with a fresh virtual target and private TPM
volume. It performs exact raw-image verification before starting the guest.
No source patch is injected into the signed guest. Only after all three desktop
stages and evidence export pass does it run the fresh 4B installer/inference
suite. An error stops the chain. Neither the retry nor model evaluation is a
pass at this checkpoint.

- Queue: `D:\LumaOS-builds\g2-desktop-acceptance-20261001-02\run.log`.
- Desktop work: `...\work\20261001T090338Z-desktop\vm-desktop-greeter-20261001-02`.
- Model work: `...\work\20261001T090338Z-desktop\vm-desktop-model-4b-20261001-02`.
- Private volumes: `luma-g2-desktop-tpm-20261001-02` and, only if needed,
  `luma-g2-desktop-model-tpm-20261001-02`; never publish them.

Sequence 11 does **not** contain the later broker client fixes or this new RAM
admission check. The retry evaluates its unchanged image on a correctly sized
installation fixture. Full graphical authentication/workflow, Admin/policy/
effects, skills, model lifecycle, remaining fault matrices, production custody
and physical qualification remain open.
