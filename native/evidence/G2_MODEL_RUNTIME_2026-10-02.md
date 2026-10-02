# G2 model-runtime exclusion and descriptor handoff — 2026-10-02

Status: **targeted implementation checks passed; G2 remains incomplete**.
Previous source increments were committed first as `07ce289`. This checkpoint
describes the subsequent model-runtime increment, not a new distributed image.

## Implemented boundary

`rust/luma-platform/src/model.rs` now shares an exclusive kernel file lock
between activation and the worker. Provisioning creates the zero-length,
root-owned 0644 `model-runtime.lock` under the protected model state directory.
It holds the lock across acquisition, credentials and selection writes. Worker
startup never creates or replaces the inode: it acquires the existing lock
before reading selection, checking weights or launching the runtime. The lock
descriptor survives exec, excluding a duplicate cooperating worker or a
concurrent activation until the last inherited descriptor closes.

The existing operation lock still serializes administrative operations. Managed
reconfiguration stops the systemd worker before provisioning and releases the
runtime lock before restarting it. A separate unmanaged worker holding the
runtime lock makes activation fail. Cleanup does not unlink/reset that lock.

Weight verification now returns the descriptor it actually hashed, rewound to
the start. It requires root ownership, one link, no group/other write access,
the expected size/digest, and stable metadata during verification. The pinned
runtime receives `/proc/self/fd/N`, not the mutable model pathname. Replacing
that pathname after verification cannot substitute the opened inode. Existing
byte-count and digest failure messages remain compatible with the image harness.
Selection likewise rejects non-root ownership, multiple links and writable
metadata, while retaining closed bounded JSON/catalog validation.

The AppArmor source profile grants `rk` on the fixed lock path, not write access.
The existing process-descriptor read rule and weight mapping rules are retained.

## Final executed checks

Evidence directory:
`D:\LumaOS-builds\g2-model-runtime-targeted-20261002-04`.

SHA-256 identities:

- Frozen source `build-inputs.json`:
  `c4cd08ced5206fd5db4f559977b86a91daa65199c3bb593781cc2b50e31fd733`.
- Completed `test.log`:
  `8b7c8b30a06787dd34a012f8f4eb89edbe0f1bcf8c0c3d8b508f5833aed6bee7`.
- Separately copied `test_model_runtime_policy.py`:
  `79105a81d4f3d07cba894fb29aeb9581607c0071542937fe4b165b62889f4a50`.
- Separately copied `test_model_vm.py`:
  `b9779bd5f0796b19f26076d39715fa21d16f6fe9cbc10f3a02f235082056b83e`.

The dedicated D-backed Docker daemon ran the pinned tools image with network
disabled, 768 MiB/no extra swap, one CPU, 128 PIDs and one Cargo job. The retained
D-backed compiler cache was reused. No model weights were loaded, no host
accounts/devices were changed, no VM was launched, and WSL limits were unchanged.

Passed:

- All fourteen selected model Rust tests, including seven new tests for lock
  exclusion/lifetime, process-death release, descriptor handoff after path
  replacement, unsafe lock/model metadata and selection validation.
- The isolated UID-989 child acquired the root-owned read-only lock but could
  neither write nor unlink it. This occurs only inside the disposable container.
- Two Python wiring checks and fifteen existing model-VM harness unit tests.
  These test harness logic, not a booted VM.
- Formatting, offline locked native build with warnings treated as errors, and
  a real compiled CLI help invocation.

Earlier attempts remain on D: for traceability. Attempt `-01` passed thirteen
Rust/two wiring checks, then stopped because `apparmor_parser` is absent from
the lightweight tools image; no parser pass is claimed. Attempt `-02` exposed
incorrect privilege-drop ordering in the new test child. The fixture was fixed
to clear groups before dropping GID/UID. Attempt `-03` passed the expanded tests
and build. Final `-04` also preserves/asserts the existing corruption diagnostic
and runs the related harness tests. The source snapshots were not edited in
place and failed evidence was retained.

## Explicit limits and deferred qualification

This is cooperative single-worker exclusion, **not** an atomic resource lease
manager, generation fencing, memory reservation, protected model-pack authority,
or a transaction across all activation files. A compromised worker can close or
unlock its own descriptor; cgroups and confinement remain necessary. Host root
can mutate a verified inode in place and is outside this application boundary.

The exec tests use small ordinary executables, not the pinned llama.cpp loader.
Actual GGUF loading through the retained descriptor, AppArmor compilation and
installed enforcement, systemd stop/restart behavior, migration, pressure and
1,000 real compact-model cycles remain part of consolidated candidate testing.
The AppArmor static wiring check is not a substitute for those tests.

Previously exported images lack this increment. A binary-only upgrade without
the new lock refuses startup; there is no silent runtime migration. Controlled
model reconfiguration can create the lock after stopping the managed service,
but full update/migration behavior still needs evaluation. Authenticated Admin
enrollment/delivery, finite policy/skills, governed catalog/pack lifecycle,
resource leases, generated-code isolation and remaining recovery/desktop work
are still open in `G2_SOFTWARE_STATUS.md`. No G2 closure or new final image is
claimed.
