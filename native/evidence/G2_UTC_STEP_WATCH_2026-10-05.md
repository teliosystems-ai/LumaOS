# G2 kernel clock step watch checkpoint

On 2026-10-05, the UTC source composition gained a kernel clock-step observer
and passed bounded checks on D-backed storage. This closes the observer source
increment, **not trusted UTC, Admin, workflows or G2**. No host clock, account,
TPM ownership, WSL setting or device was changed. No time service was activated,
product listener enabled, final image built or heavyweight VM/model sweep run.

## Implemented boundary

`utc_step_watch.rs` owns a nonblocking, close-on-exec `CLOCK_REALTIME` timer
armed with absolute cancel-on-set flags. The stream arms it before its initial
clock read, then checks it before and after candidate work. Only an exact
would-block read remains live. Cancellation, expiration, interrupted/failed
syscalls, short/zero reads and malformed outcomes fence. Consuming a notification
does not clear the application fence, rearm the timer or reacquire UTC.

Linux's cancel-on-set interface reports discontinuous realtime changes through
`ECANCELED`. Its timer configuration changes only this observer, not the system
clock. [Linux timerfd interface](https://man7.org/linux/man-pages/man2/timerfd_create.2.html).
The kernel implementation retains cancellation state until read; the application
must retain its own fence after that read.
[Linux v6.8 timerfd source](https://github.com/torvalds/linux/blob/v6.8/fs/timerfd.c).
These references explain the mechanism, not qualification of the installed
Ubuntu/WSL kernel tuple or every clock-change/resume race.

The fixed deadline is the protocol's existing 2100 coordinate limit. An expired
observer refuses rather than resetting. The timer is not an alarm timer and
requires no clock-setting or wake-alarm privilege. There is no configuration,
IPC, environment or serialized-authority path for replacing the observer.
Numeric clock checks, bounded heartbeat freshness and existing process/queue
checks remain active; this guard does not approve a producer or authenticate
its supplied history floor.

## Executed checks and retained evidence

Final run: `D:\LumaOS-builds\g2-utc-step-targeted-20261005-02`.
All 187 captured source files and five supplementary test inputs matched current
repository bytes after completion. Passing scope:

- 147 selected ordinary Rust tests, including five new observer tests, across
  UTC, Admin, authentication/principal and workflow modules.
- Four explicitly selected fixtures: 14 datagram cases, ten receiver/keeper
  cases, one final-queue check and unchanged C-frame interoperability. There
  were 151 passing Rust test invocations, including 25 explicit kernel cases.
- 23 Python checks without skips, including pinned-source guards; formatting,
  warnings-denied locked offline native build and runner shell syntax checks.

The observer tests inspect actual kernel timer flags, nonblocking/close-on-exec
descriptor flags, a one-shot active timer and real expiration of an owned timer.
They also classify injected `ECANCELED` and other read outcomes. The composition
fixture verifies expiration refusal both during initial acquisition and on a
quiet poll after a candidate was already bounded; later fresh measurements
cannot silently recover that fenced session.

**No actual host clock step was performed.** Injecting a cancellation read
outcome is not executed kernel cancellation delivery, a step-and-restore attack,
suspend/resume testing or installed confinement evidence. Expiration changes
only the fixture's timer. The existing kernel fixtures own/reap their children
and do not stop unrelated workloads.

The cached tools image was
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
The runner used one CPU, a 768-MiB memory and memory-plus-swap ceiling, pids limit
128, no network, all capabilities dropped, no host devices/Docker socket and
D-backed cache/evidence. Docker root was `/mnt/luma-build/docker`. The pinned
chrony source and unchanged C frame were reused from the
[publisher checkpoint](G2_UTC_PUBLISHER_2026-10-05.md); this batch did not rebuild
upstream chronyd/C or execute live provider traffic.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `b8fa3db3cb91e584f4da0a79562f56388bfaaea85d8fa2bfec7ff509d50f2eb4` |
| `test-inputs.sha256` | `eba57ab1ee1e23f7b4d0bf5999b6ba135ed925bd54d9b32a9f84ba685b79ba16` |
| `test.log` | `7e38933c7e1d6705062987dd5aaedf49c5bb992afb379ce3056b0c1db76c8774` |
| Reused `c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |

The passing earlier trial `01` is retained. Final trial `02` adds the
post-candidate expiration case and strengthens descriptor-flag assertions.
Only its unchanged captured inputs support the final checkpoint. Hashes bind
evidence, not production signatures, reproducibility or certification.

The five observer tests run with:

```sh
cargo test --offline --locked utc_step_watch:: -- --test-threads=1
```

The composition fixture is already selected by the isolated TPM runner. That
complete runner, remote/full CI, other ignored PAM/TPM tests and the full workflow
fault matrix were not executed in this batch.

## Remaining software and qualification

Complete the approved protected supervisor/runtime, lifecycle/resume delivery,
authenticated time history, reviewed certificate bootstrap/recovery and final
authority composition. The observer neither proves the absolute clock-rate
envelope nor provides UTC. Transport review/adaptation remains required before
deploying the experimental telemetry endpoint. Admin finite assignment/revocation
and current effect grants, production workflow/supervisor interfaces and
installer/boot/update/recovery composition remain open.

Actual delivered clock steps, forward/backward and step-and-restore races,
suspend/resume, kernel namespace/confinement behavior and service restart must
be qualified against the consolidated image on approved native test targets.
No new clock-setting privilege or host mutation is authorized by these source
tests. See the [completion register](../G2_SOFTWARE_STATUS.md) and
[implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md).
