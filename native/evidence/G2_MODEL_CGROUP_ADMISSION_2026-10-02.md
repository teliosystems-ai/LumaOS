# G2 model cgroup memory admission checkpoint

Date: 2026-10-02. This targeted source increment makes model installation and
worker startup refuse a selected profile when the process's effective cgroup-v2
memory limit is smaller than that profile's configured worker `MemoryMax`.
Previously these paths checked host `/proc/meminfo` but could miss a tighter
cgroup ancestor. The check reads the unified process cgroup path and the
bounded `memory.max` value at each ancestor, taking the smallest finite limit.
Missing, malformed or substituted observations fail closed; `max` is treated
as unlimited. The existing host RAM and free-storage checks remain in place.

The final offline test ran in the D-backed builder at
`D:\LumaOS-builds\g2-model-cgroup-targeted-20261002-02`. Its frozen source
manifest `source/build-inputs.json` has SHA-256
`e5783a4323f10d56b275587385d092c4bc1f45ad2c2ab666b7cd3224f8e2bd4f`.
The `test.log` SHA-256 is
`c7557c832df1a29fd7d9bce10b78d5cba79892d766ac431f80623cd18057a4e4`.
The run used network-disabled Docker, 768 MiB/no extra swap, one CPU and one
Cargo job, with the repository on C: and the snapshot/cache on D:.

Seventeen Rust model tests passed, including nested-limit selection, exact
profile threshold, malformed/symlink refusal and a live read of the test
container's unified cgroup. Two existing model policy checks and fifteen
model-VM harness unit tests passed, as did formatting and a warning-clean
offline native build. An earlier `-01` snapshot passed sixteen Rust model
tests; `-02` adds the live cgroup regression and is the final tested source.
Neither run loaded GGUF weights, booted an image/VM or changed WSL memory.

This is only a pre-start capacity check. It is not a reservation, a measurement
of reclaimable pages or current pressure, an atomic activation transaction,
a generation lease, or stale-worker fencing. Installed Ubuntu/systemd cgroup
layout, actual model activation, memory pressure and real compact-model cycles
remain for the consolidated image and separate-machine evaluation. Manual
operation remains available when model admission fails. G2 is not complete.
