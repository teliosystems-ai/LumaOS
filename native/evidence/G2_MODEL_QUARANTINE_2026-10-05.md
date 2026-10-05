# G2 observed model reconfiguration quarantine

On 2026-10-05, the native source gained a durable quarantine for errors returned
by the installed model reconfiguration restart/check sequence. It fences new
worker startup and normal activation until explicit installed-root review.
The final targeted D-backed checks passed. This is **source implementation
evidence, not installed service enforcement, proven worker/resource cleanup,
production Admin authorization or G2 completion**.

## Failure containment

After activation completes, the closed restart sequence checks daemon reload,
model/reference restart, bounded local listener health, selected-worker state
and reference-service activity. It stops at the first failed stage.
`finish_reconfiguration` then publishes an exclusive root-private
`model-quarantine.json` before requesting the managed model worker stop.
The command always returns failure; it does not silently roll back or report
readiness. A publication failure still attempts stop, and a stop failure leaves
any published fence intact. Neither outcome proves the worker stopped or that
its memory/processes were released.

The canonical bounded record contains a fresh 128-bit incident ID, failed stage,
candidate model pin and exact image-catalog digest. It contains neither API
credentials nor exception text. Existing, partial or unknown state is not
overwritten. File and directory sync precede a successful publication result;
publication errors are reported without claiming a durable validated record.

Normal preflight, activation and the worker's startup check refuse any retained
quarantine, including malformed or linked state. The packaged systemd unit also
has a negative quarantine-path condition. The AppArmor profile adds only its
read/lookup rule; root-private DAC denies the worker content access and unlink.
Those packaged controls remain subject to installed-image qualification.
The failure handler does not stop the reference service, which does not by
itself prove that the manual UI is healthy.

## Explicit recovery and clearance

Investigate the failure, preserve diagnostics without copying credentials, and
stop the managed worker through the installed maintenance procedure. Inspect:

```sh
sudo luma-platform model-quarantine-reconcile
```

The installed-root wrapper holds operation and idle-runtime locks. Inspection
requires pending activation/orphan backup state to be reconciled first. Status
reports the incident, failed stage, candidate/current model or manual-only
state, phase, clearability and review digest without private settings.

Reviewed [completed-activation rollback](G2_MODEL_COMPLETED_ROLLBACK_2026-10-05.md)
can run while quarantined. Its new activation record still protects interrupted
writes, and restoration preserves both quarantine and independent
`model-disabled` recovery state. An interrupted rollback must first use the
existing activation reconciliation: its backup restores the pre-rollback
candidate, not the desired completed-rollback target.

After any restoration, reinspect. To approve clearing this exact incident for
a consistent current configuration with verified current catalog weights,
or the all-absent manual-only state, use the current digest:

```sh
sudo luma-platform model-quarantine-reconcile --clear-consistent REVIEW-SHA256
```

Fresh checks around potentially blocking weight verification bind the quarantine
bytes, catalog/pin, configuration hashes and current phase. Stale review,
inconsistent settings, unavailable weights, unsafe metadata or an intervening
pending activation refuse. Only the exact quarantine file is removed and the
directory synced. A new incident requires a new review even if its candidate,
configuration and failed stage are identical to an earlier incident.

Clearance does not start services, reserve RAM, prove readiness, delete weights
or remove recovery disablement. Reload generated unit limits, refresh the
reference environment and evaluate runtime admission/health/inference separately
before returning a model to use. Root custody and kernel exclusion are not
product finite Admin/effect authorization or a TPM-protected incident ledger.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-quarantine-targeted-20261005-02`.
All 188 captured source entries and three supplementary test inputs matched
current repository raw-byte hashes. Passing scope:

- 71 top-level Rust model tests, including 13 new checks for the five-stage
  failure boundary, publication-before-stop ordering, preserved unknown state,
  publication/stop failure, live runtime exclusion, stale configuration review,
  incident identity, bad weights/inconsistent settings, manual-only clearance,
  completed rollback and interrupted restoration under quarantine, unsafe/
  substituted records, fresh post-verification checks and actual isolated-UID
  read/unlink denial. The existing restrictive-umask parent executes its
  otherwise ignored helper in an owned child process.
- Fourteen model-policy, four health-helper and fifteen VM-harness Python checks:
  33 total without skips. These validate source/oracles and local fixtures, not
  a launched VM, installed service or real model inference.
- Formatting, a warnings-denied locked offline native build, compiled CLI help
  and syntax-only AppArmor parsing with kernel loading/cache use disabled.

Service restart/stop callbacks and weight pins use small fixtures; no systemd
jobs or real model were run. Linux DAC and kernel locks are real, but do not
qualify installed confinement or resource return. Interruption states are
materialized fixtures, not physical power cuts. AppArmor's parser emitted its
cache/interface warning; successful no-load parsing is not kernel enforcement.

The existing D-backed Docker cache/tools were used with one CPU/Cargo job,
768-MiB memory/memory-plus-swap ceiling, 128-pid limit, no network, host devices
or Docker socket. All capabilities were dropped except CHOWN, DAC_OVERRIDE,
FOWNER, SETUID and SETGID for disposable ownership/identity fixtures. The tools
image ID was checked against
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account, service, TPM, clock or WSL memory setting changed; no full image,
VM or real model was built/loaded. Both passing trials remain on D:; the final
trial includes the updated operator instructions and record-writing comment.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `e8032eee44f199bb5fe974c8a08ae161924ff9d7aba7c8e19ebd81a299571a48` |
| `test-inputs.sha256` | `26bf1a0fffb3047e5c419f8d13ef7695c8d1807932b47e9002ce40a9bfcfc63b` |
| `test.log` | `7165ca9cffa112b8c611812ffbb57e3d87ad398cac0759ada6d78890d8450e17` |

## Remaining implementation and qualification

This handler covers errors actually returned by `model-install` after completed
activation. Controller death or power loss before the handler, later boot/
migration failures, worker OOM/pressure supervision and trusted lifecycle/event
delivery still require implementation and evaluation. Complete atomic resource
leases/generations, stale-worker fencing, wider quarantine/restart policy,
unsupported-state recovery/migration and crash-partial retention/cleanup.

Production Admin/effect grants and governed model-pack/catalog custody remain
separate dependencies. Qualify this changed binary and its unit/profile on the
consolidated image and separate native Ubuntu target, including actual stop,
restart, configuration refresh, admission, inference, manual operation and
interruption/resource-return measurements. See the
[completion register](../G2_SOFTWARE_STATUS.md) and
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md).
