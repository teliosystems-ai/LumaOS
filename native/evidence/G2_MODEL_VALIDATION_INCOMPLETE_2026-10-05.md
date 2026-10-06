# G2 incomplete model validation-trial recovery

On 2026-10-05, the native source gained a separate reviewed recovery path for
empty/truncated validation-trial JSON and exclusive locking across recovery.
This is source recovery, not continuous supervision, product Admin/effect
authorization, a resource reservation or installed-image qualification.

## Operator boundary

Investigate the interruption, stop the managed worker, and reconcile pending
activation/orphan backup state first. Reviewed rollback/restoration may restore
settings without deleting the trial or independent quarantine. In a separate
installed-root maintenance process, use:

```sh
sudo luma-platform model-validation-reconcile --inspect-incomplete
sudo luma-platform model-validation-reconcile --retain-incomplete REVIEW-SHA256
```

Both commands require the operation and idle-runtime locks. The persistent
validation lock must already exist and be safe; recovery never creates or
rebinds it. The record must be root-owned, single-link, regular, mode 0644 and
at most 8192 bytes. JSON parsing must fail only at end of input. Empty input is
included; complete JSON, including unknown/future versions, other malformed
input and unsafe records refuse. EOF classification does not prove a crash or
authorize automatic repair. Opaque bytes and parse details are not printed.

The review binds exact original bytes, the record's device/inode/change identity,
the held persistent lock's device/inode, current catalog and all three runtime
configuration hashes. Current settings must describe a consistent current
profile with verified weights, or all be absent for manual-only operation.
Replacing the trial with identical bytes invalidates the review. Missing,
substituted or uncertain state is preserved for investigation.

## Exclusive recovery and private retention

The controller guard now holds a companion exclusive nonblocking flock alongside
its existing PID-bound POSIX write lock. Worker admission still requires the
bound live POSIX owner and process/boot observations; flock does not replace
that proof. Controller checks still never reopen/clone their own POSIX inode.

Typed abandoned-trial and incomplete-trial recovery both hold an exclusive
flock through potentially blocking configuration/weight verification, private
retention, fresh review, clearance and directory synchronization. POSIX lock
queries additionally reject live legacy controllers without the companion
flock. Unknown OFD/other lock shapes refuse rather than treating an uncertain
holder as dead. Same-PID typed inspection refuses before opening the possible
owning POSIX inode. Maintenance remains a separate operation-locked process.

Clearance first retains exact bytes as root-private mode-0600
`model-validation.retained.CONTENT-SHA256`, using exclusive creation, file and
directory sync, safe readback and fresh review. Exact private archives permit
retry and are synced again; conflicting, public, linked, oversized or otherwise
unsafe copies refuse without overwrite. Fresh identity/configuration and lock
checks precede removal of only `model-validation.pending` and directory sync.

Settings, weights, quarantine, recovery disablement and the persistent lease
remain untouched. No service starts, download, archive deletion, readiness or
resource-return claim occurs. An error before unlink preserves the trial; a
crash or sync failure after unlink has an uncertain clearance outcome requiring
fresh inspection of retained evidence. This does not repair arbitrary malformed
records, reset unknown versions or implement governed retention quotas/expiry.

## Executed checks

Final evidence: `D:\LumaOS-builds\g2-model-validation-incomplete-targeted-20261005-02`.
All 189 captured source entries and three supplementary test inputs matched
current repository raw-byte hashes. Passing scope:

- 96 ordinary Rust model tests, including eight new parent checks for selected/
  manual-only/empty-record private retention; preserved settings, weights,
  quarantine, disablement and lease identity; isolated-worker archive denial;
  complete/malformed/unsafe/missing input refusal; unsafe/missing lease refusal;
  live-controller, legacy POSIX and unknown OFD holder refusal; changed settings,
  weights and same-byte record/lease replacement; exact archive retry and unsafe
  archive preservation; fresh post-retention identity/pending-state refusal; and
  real exclusive-flock exclusion during both typed and incomplete blocking
  review/retention. Both otherwise ignored helper tests are explicitly executed
  by their passing parents in owned child processes.
- Twenty model-policy, four health-helper and fifteen VM-harness Python checks:
  39 total without skips. These are source wiring, local fixtures and oracle
  checks, not a launched VM or installed service.
- Formatting, warnings-denied locked offline native build, compiled CLI help,
  and syntax-only AppArmor parsing with kernel loading/cache use disabled.

Linux kernel flock/POSIX/OFD behavior, owned process exit/kill and isolated
UID/GID 989 with no supplementary groups were exercised in a disposable
container. The isolated worker could neither read nor remove retained opaque
bytes. Tiny fake weight pins and materialized interrupted/configuration states
were used, not real inference or physical power cuts. AppArmor's missing
cache/interface warning does not turn no-load syntax success into enforcement.

The existing D-backed tools/cache used one CPU/Cargo job, a 768-MiB
memory/memory-plus-swap ceiling, a 128-pid limit, no network/host devices/Docker
socket, and all capabilities dropped except CHOWN, DAC_OVERRIDE, FOWNER,
SETUID and SETGID for disposable identity fixtures. The verified tools image ID
was `sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account/service, TPM, clock or WSL memory setting changed; no image,
VM or real model was built/run. Trial 01 passed all 96 Rust checks and the
offline build but failed one whitespace-sensitive Python source assertion after
Rust formatting. Trial 02 passed the corrected guard and is the final evidence.
Both runs remain retained on D:.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `a41ad70d46b19c94929c21fa75495bb49e2758d81526b4d00722aceaf86d8279` |
| `test-inputs.sha256` | `2f383ed45c556f384df8463783988e3378e7cc2a083a7e1cc0200874c4a46600` |
| `test.log` | `0713589335a73ea3f67f0f723e362f1b110a6c7a87c523999c1c2c21c4a17365` |

## Remaining implementation and qualification

The incomplete-record path closes a narrow source recovery gap. Continuous
worker death/boot/migration/pressure/OOM supervision, atomic resource
leases/generations, stale-worker fencing, governed model-pack/catalog custody,
broader unsupported-state/retention recovery and finite product Admin/effect
integration remain open. Initial provisioning/boot and older-image migration
are not silently upgraded to the installed reconfiguration trial.

Evaluate the changed binary on the consolidated image and separate native
Ubuntu machine: actual installation/reconfiguration/interruption, systemd and
AppArmor/seccomp enforcement, recovery review, manual operation, real inference
and measured resource return. Targeted fixtures do not qualify those outcomes
or complete G2. See the [completion register](../G2_SOFTWARE_STATUS.md),
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md),
[controller fence checkpoint](G2_MODEL_VALIDATION_2026-10-05.md) and
[operator instructions](../image/README.md).
