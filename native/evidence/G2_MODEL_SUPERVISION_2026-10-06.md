# G2 owned model child supervision

On 2026-10-06, the native source gained polling supervision of the one owned
model-runtime child, including live trial-controller failure and independent
runtime fences. This advances the model lifecycle implementation; it is not
installed-image qualification, complete crash/pressure supervision, a resource
lease/generation, product Admin authorization or G2 completion.

## Runtime and controller boundary

`model-serve` now keeps the isolated native supervisor as the service main
process rather than replacing it with llama-server. Its one fixed runtime
child inherits the verified weight inode and persistent runtime-lock descriptors.
The parent also holds those descriptors until supervision returns. Startup
requires the selected canonical profile, a valid existing API key, ordinary
admission and all existing activation/quarantine/trial checks. The child still
cannot read the private reference environment.

Before spawn, immediately after spawn and on a 500-ms polling interval, the
supervisor checks recovery disablement, pending activation/orphan backup,
quarantine, runtime-input hashes and the bound live trial controller. It binds
the exact original trial bytes: substitution or an unexpected new trial refuses,
even if the new record could otherwise admit a fresh worker. Root completion
may remove the original trial with unchanged inputs; supervision then continues
watching ordinary fences. Absence is not a protected completion receipt, and
hostile root deletion remains outside this boundary.

A failed observation kills and reaps only the owned direct child, then returns
a nonzero result without printing the callback's opaque input/error bytes.
Normal child exit succeeds; nonzero/signal exit fails. Supervision never writes
private recovery records, clears fences, downloads models, starts/restarts
services or claims readiness/resource return. A stopped worker's pending trial
and independent quarantine/disablement remain available for reviewed recovery.

## Kernel ownership and teardown

Before spawn, default waitable-child SIGCHLD handling is mandatory. The native
production caller is single-threaded and has no competing child reaper. The
supervisor captures a kernel PID handle before waiting and uses handle-bound
signaling and `waitid(P_PIDFD)` for termination/reaping, without numeric-PID or
process-group fallback. Missing/denied kernel APIs and uncertain observations
are failures, not cleanup claims. If handle acquisition fails after spawn, the
production caller returns to main and exits; parent-death/unit teardown is
required rather than reporting successful cleanup. See the
[PID handle contract](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) and
[handle-bound signal contract](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).

The child registers parent-death SIGKILL before exec, then rechecks the parent
to close the already-dead-parent registration case. This fixed non-setid,
capability-free runtime makes no subsequent credential changes. The kernel
setting does not cover arbitrary forked descendants; installed control-group
teardown remains necessary. See the
[Linux parent-death contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html) and
[systemd 255 kill policy](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.kill.xml).
The existing unit retains `KillMode=control-group`, stop timeout, restart limits,
memory/process/device restrictions and isolated identity. The explicit profile
addition permits same-profile kill signaling and disablement lookup, not
cross-profile sends or private archive/reference-environment reads. The required
process syscalls are in systemd 255's source `@process`/`@system-service` sets;
that source audit is not installed seccomp enforcement. See the
[systemd syscall sets](https://raw.githubusercontent.com/systemd/systemd/v255/src/shared/seccomp-util.c).

Poll checks have observation/scheduling gaps. Kill/reap can block on kernel I/O;
there is no guaranteed wall-clock cleanup deadline, memory-return measurement
or atomic observation-to-spawn boundary. Old already-running direct-exec images
are not upgraded by changing source. Consolidated image/service qualification
must cover actual signals, confinement, descendants, interruption and inference.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-supervision-targeted-20261006-03`.
All 190 captured source entries and seven supplementary inputs matched current
repository raw-byte hashes. Passing scope:

- 106 ordinary Rust model tests, including ten new parent checks for normal/
  failed runtime exit and verified descriptor inheritance; initial unsafe,
  disabled, missing/invalid credential and wrong-profile refusal; refusal of
  non-waitable child policy before spawn; direct-child termination on independent
  fences/runtime-input changes; live worker termination after real controller
  exit/SIGKILL; successful trial completion with continued fence watching;
  substitution/unexpected new trial refusal; supervisor SIGKILL followed by
  owned descendant adoption/reap; unwind cleanup with inherited-lock exclusion;
  and completed-handle/wait-ownership loss without signaling/reaping another
  owned fixture process. Both otherwise ignored helpers are explicitly executed
  by their passing parents, not separate unchecked acceptance claims.
- Twenty-five model-policy, four health-helper and fifteen VM-harness Python
  checks: 44 total without skips. These are wiring, local fixtures and oracles,
  not a launched VM or installed service.
- Formatting, warnings-denied locked offline native build, compiled CLI help,
  C-leaf compilation with warnings denied, three boundary-runner shell syntax
  checks, and no-load/no-cache AppArmor syntax parsing.

Actual Linux kernel PID handles/signals/waits, parent-death delivery, process
exit/kill, disposable subreaper adoption and numeric UID/GID 989 with no
supplementary groups were exercised. The supervisor's death probe ran as UID
989, not a privileged signaling helper. Fake weights and materialized failure
states were used. Kernel process reap and release of the inherited exclusion
lock were observed; neither proves model/cgroup memory return or arbitrary
descendant containment. No installed systemd job, AppArmor/seccomp enforcement,
real LLM inference, physical interruption or full image/VM sweep ran. The parser's
missing cache/interface warning does not turn syntax success into enforcement.

The existing D-backed tools/cache used one CPU/Cargo job, a 768-MiB
memory/memory-plus-swap ceiling, 128-pid limit, no network/host devices/Docker
socket, and all capabilities dropped except CHOWN, DAC_OVERRIDE, FOWNER,
SETUID and SETGID for disposable identity fixtures. The verified tools image ID
was `sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account/service, TPM, clock or WSL memory setting changed.

Earlier failed runs remain retained on D:. Trial 01 exposed a test-harness
thread mismatch in the parent-death observation. A static C leaf now checks the
exec thread directly, matching the kernel's per-task setting rather than a
new Rust test thread; see [Linux task creation](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/fork.c).
Trial 02 exposed the root fixture driver's lack of permission to signal its
UID-989 child with the reduced capability set. The death probe now uses UID 989
and signals only its owned same-UID supervisor, without adding capabilities.
Trial 03 passed the corrected fixture and is the final checkpoint.
The three runner syntax checks were also recorded individually against the
same captured inputs in `runner-syntax.log`; a single `bash -n` invocation with
multiple filenames checks only its first script, so it is not three results.

The C leaf is compiled from captured static test input in each fresh disposable
root and is used only under Rust test configuration. It verifies isolated
identity/groups, parent-death registration, inherited descriptor flags, tiny
weight bytes and the runtime-lock inode before publishing complete readiness.
It is not a real LLM or a production executable override. The storage/export/TPM
runners now hash both nested model modules and this fixture; source-wiring and
syntax checks do not imply execution of those complete runners or remote CI.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `80b75d2666f24ec5ee4ca96eecf078ddd31e877847194bad64b38f7bfb71e34b` |
| `test-inputs.sha256` | `2f983cb28491076792a1e656a5ce99d84e5894e7d93f0fa23cd8de2419e9d113` |
| `test.log` | `24220dfc34406776a0cf86eb72e0f9dbfe5e53eb8aeb7967919e467e6a90ace7` |
| `runner-syntax.log` | `8ae394c0d6ecf3ff5038dd1ec815a271fc64e22625f2e3085d9db554c5e8bb0c` |

## Remaining implementation and qualification

Complete protected resource leases/generations and lifecycle receipts, stale or
hostile descendant containment, pressure/OOM and broader boot/migration/restart
policy, governed model packs/catalog custody, production Admin/effect grants
and receipted retention/recovery. The polling wrapper is not the complete
production lifecycle service. Evaluate the changed binary/profile on the
consolidated image and separate native Ubuntu machine, including real inference,
service teardown and measured resource return. The final image build, heavy
sweep and WSL-memory changes remain deferred by owner direction.

See the [completion register](../G2_SOFTWARE_STATUS.md),
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md),
[operator instructions](../image/README.md),
[controller trial checkpoint](G2_MODEL_VALIDATION_2026-10-05.md) and
[incomplete-trial recovery](G2_MODEL_VALIDATION_INCOMPLETE_2026-10-05.md).
