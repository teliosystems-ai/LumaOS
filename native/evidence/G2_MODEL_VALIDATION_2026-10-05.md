# G2 model reconfiguration controller lifetime fence

On 2026-10-05, the native source gained a durable validation trial published
before installed model reconfiguration clears its activation fence. A trial
worker requires a freshly observed bound live controller; controller return,
exit or kill leaves a record that refuses subsequent startup until explicit
review. Targeted D-backed checks passed. This is **source startup/recovery
evidence, not continuous supervision, installed-image qualification, proven
resource return, product Admin authorization or G2 completion**.

## Publication and controller binding

`model-install` uses `activate_cached_with` to publish the trial while the
activation marker and runtime lock still protect candidate writes. Durable
publication/readback precedes activation-marker clearance and managed restart.
Earlier provisioning and older-image migration do not silently acquire this
new reconfiguration behavior.

The bounded canonical root-owned mode-0644 `model-validation.pending` contains
a random 128-bit incident ID, kernel boot/PID/start identity, persistent lease
inode/device, fixed catalog/candidate pins and three configuration hashes.
It contains neither API credentials nor exception text. Unknown/partial state
is not overwritten. A private controller guard holds a root-only whole-file
POSIX write lock on the persistent root-owned mode-0644 zero-length
`model-validation.lock`. The lock is not a memory reservation or resource lease.

The controller retains its descriptor through daemon reload, managed restart,
bounded listener health, exact worker state and reference-service activity
checks. The guard verifies unchanged settings, record, inode and controller
context before clearing the trial. Completion failure is reported as the
`validation` failure stage and uses quarantine-before-stop handling, just like
earlier observed restart/check failures. There is no automatic trial cleanup
on error or process death.

POSIX process-lock semantics matter: subprocesses do not inherit the controller's
lock, and closing any descriptor for that inode in the owning process releases
it. The guard's controller-side checks never reopen/clone that inode. Worker
queries open it read-only in their separate process. Ordinary new activation
refuses any trial, even while its controller is live.

## Isolated worker startup

The worker checks existing pending activation/orphan backup and quarantine
fences, then admits a trial only for the exact selected catalog profile and
runtime-input hashes. Kernel `F_GETLK` must report the whole-file write lock
held by the recorded PID; boot and process-start observations must match, and
the checked lock inode must remain bound to the record. Unlocked, substituted,
uncertain or changed state refuses. Stored PID/path existence is not a fallback.

These observations are checked before potentially blocking weight/RAM admission
and again near exec, with fresh inner checks around process/configuration reads.
The verified weight descriptor and existing single-worker runtime flock still
cross exec. The worker reads only selection/its API key for runtime-input hashes;
the root controller and recovery review verify the full selection/environment/
credential tuple. No reference-environment permission was added. The profile
adds read-only controller `/proc` stat observations and trial/lock read/lock
rules, not archive or credential write access. Missing process/boot observations
fail closed and require installed-platform evaluation.

Controller death does not stop an already-running worker, prove memory/process
cleanup or make the final observation-to-exec interval atomic. Continuous
supervision and hostile/stale-worker containment remain separate implementation
work. Boot/PID/start/inode observations are not protected incident history or
a production supervisor/finite Admin authorization service.

## Explicit abandoned trial recovery

Investigate the failure, stop the managed worker and first reconcile pending
activation/orphan backup state. Existing reviewed rollback/restoration can
change settings while preserving the trial. A separate installed-root process
then uses:

```sh
sudo luma-platform model-validation-reconcile
sudo luma-platform model-validation-reconcile --retain-abandoned REVIEW-SHA256
```

Operation and idle-runtime locks are required. Typed inspection requires the
original canonical record/current catalog binding, the exact persistent lease
inode and no live/uncertain holder. Inspection in the recorded owning PID
refuses rather than opening/closing its possible POSIX lock. Current settings
must be consistent with verified current weights, or all absent for manual-only
operation. Fresh checks after potentially blocking verification bind the exact
original trial and current configuration into the review.

Approved clearance first retains exact bytes privately as
`model-validation.retained.CONTENT-SHA256`. Exclusive creation, file/directory
sync, safe readback and fresh review precede trial unlink and directory sync.
An exact private archive permits retry and is synced again. Conflicting, public,
linked or otherwise unsafe archives, stale review, malformed/partial/unknown
trial records, changed catalogs, substituted locks, inconsistent settings and
bad weights refuse. No archives are overwritten or deleted by this procedure.

Settings, weights, independent quarantine and `model-disabled` are preserved.
Quarantine requires its own new review. No service starts or readiness/resource
claims occur. Retention errors before unlink leave the trial; a crash or sync
failure after unlink has an uncertain clearance outcome and requires fresh
inspection of retained evidence. Generic repair of partial/unknown trials or
archives, automatic expiry/quotas and receipted retention lifecycle remain open.
Do not unlink/replace the persistent lease inode as cleanup.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-validation-targeted-20261005-03`.
All 189 captured source entries and three supplementary test inputs matched
current repository raw-byte hashes. Passing scope:

- 88 top-level Rust model tests, including eight new parent checks covering
  live controller/bound isolated-worker admission, ordinary activation/recovery
  refusal, real controller exit and SIGKILL, unchanged successful completion,
  failure quarantine before stop, changed boot/PID/start/pin/runtime inputs and
  substituted lease, stale review/bad weights/pending state after blocking
  resolution, manual-only restoration/exact-archive retry, and unsafe trial/
  conflicting archive preservation without byte disclosure. Both otherwise
  ignored helpers are explicitly executed in owned child processes by their
  passing parents; they are not independent unchecked acceptance claims.
- Eighteen model-policy, four health-helper and fifteen VM-harness Python
  checks: 37 total without skips. These validate source wiring, bounded local
  fixtures and oracles, not a launched VM or installed service.
- Formatting, warnings-denied locked offline native build, compiled CLI help
  and syntax-only AppArmor parsing with kernel loading/cache use disabled.

Actual Linux kernel locks, process exit/kill and isolated UID/GID 989 with no
supplementary groups were exercised in a disposable container. The worker
could neither read the private reference environment nor open a writable lease
descriptor. Tiny fake weight pins and materialized interrupted/configuration
states were used; no real LLM or physical power cut was exercised. No installed
systemd job, AppArmor/seccomp enforcement or resource-return measurement passed
by implication. The AppArmor parser's missing cache/interface warning does not
turn no-load syntax parsing into kernel enforcement.

The existing D-backed tools/cache ran with one CPU/Cargo job, a 768-MiB
memory/memory-plus-swap ceiling, 128-pid limit, no network/host devices/Docker
socket, and all capabilities dropped except CHOWN, DAC_OVERRIDE, FOWNER, SETUID
and SETGID for disposable identity fixtures. The tools image ID was verified as
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account/service, TPM, clock or WSL memory setting changed; no full image,
VM or real model was built/run. Trial 01 retains a corrected Rust cast-inference
compile failure. Trial 02 passed before the final identity recheck, completion
failure test and operator notes; trial 03 is the final checkpoint. All remain D-backed.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `2dcc02097c7708029ab4886f7537466e4806f2299554d55a0a5402736ca22ef5` |
| `test-inputs.sha256` | `b3b8a0ebe48789e598007c083e73186c0baf7dd56a701c73cf265c369c0cc2a1` |
| `test.log` | `3ecf859799e1c6696589e55cb95ead24de5f352ad2219afad2f1ed09261671bb` |

## Remaining implementation and qualification

Qualify the changed binary/profile on one consolidated image and the separate
native Ubuntu machine, including real reconfiguration, controller interruption,
service control, recovery review, manual operation, inference and measured
resource return. Continuous crash/boot/migration/pressure/OOM supervision,
atomic RAM leases/generations, stale-worker fencing, trusted lifecycle delivery,
broader unsupported-state/retention recovery and production Admin/pack custody
remain open. See the [completion register](../G2_SOFTWARE_STATUS.md),
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md) and
[observed quarantine checkpoint](G2_MODEL_QUARANTINE_2026-10-05.md).
