# G2 completed model activation rollback

On 2026-10-05, the native source gained a root-private, one-step configuration
rollback record for completed model activation. This extends the earlier
[interrupted activation restoration](G2_MODEL_PRIOR_RESTORE_2026-10-05.md):
prior settings no longer become unavailable merely because normal activation
cleared its pending marker. The final targeted D-backed checks passed.
This is **source implementation evidence, not a running-worker rollback,
production Admin authorization, installed-image qualification or G2 closure**.

## Retention and validation

Before normal activation or reviewed candidate publication clears its pending
state, `retain_completed_prior` atomically writes `model-rollback.json`.
The closed canonical record contains exact prior selection, environment and
local API credential, plus the completed configuration hashes, activation marker
digest, completed model pin and exact image-catalog digest. Root-private,
single-link, no-follow, metadata-stable and bounded reads protect this local
maintenance data. An older marker without saved prior bytes cannot invent it.

One inspected safe slot is replaced at the next completed activation. It is
not a multi-version archive or a signed/TPM-protected release rollback anchor.
Unknown, malformed, public, linked or oversized slot data is preserved and
refuses preflight/new activation. A publication failure after the activation
marker exists leaves that marker and its saved bytes intact. Publication before
pending clearance can be explicitly reviewed and retried.

The archive is credential-bearing. No worker AppArmor permission was added for
it. Its content is not projected in CLI status, and private recovery decode
errors deliberately suppress supplied values. Treat the archive and any
interrupted atomic-write partials as plaintext credentials. Offline export
includes the model-state directory; protect exports and retained partials and
never publish them in Git, release artifacts or public evidence.

## Installed root maintenance procedure

Investigate the failure, preserve diagnostics without copying credentials, and
stop the managed model worker through the installed maintenance procedure.
The command requires installed root, the operation lock and an idle runtime
lock; it does not stop or start services itself. Inspect with:

```sh
sudo luma-platform model-rollback-reconcile
```

Status reports the candidate, prior model or manual-only target, phase,
restorability and exact review digest, without private settings. Changed current
configuration, a different catalog/pin, unsupported saved settings or missing/
invalid prior weights prevent restoration. A corrupt current candidate does
not prevent restoring an otherwise verified prior model. No missing weights
are downloaded and no prior pin is substituted.

After approving the reported target and current digest, use:

```sh
sudo luma-platform model-rollback-reconcile --restore-prior REVIEW-SHA256
```

Fresh checks surround prior-weight verification. Creating the new activation
fence saves the pre-rollback candidate bytes and rechecks that they still match
the completed configuration under review. Restoration writes exact saved
settings with the required service groups/modes, or removes only the three
configuration files for an all-absent manual-only target. It preserves model
weights and recovery disablement. Exact restored hashes, prior weights,
retained archive bytes and marker identity are checked again before the one-step
record is consumed and the activation fence cleared.

An interrupted rollback remains fenced. Inspect it with
`model-activation-reconcile`; its `--restore-prior` restores the **pre-rollback
candidate**, not the desired completed-rollback target. If consumption already
removed `model-rollback.json`, that target is no longer available from the
slot. The saved pre-rollback bytes remain available while the pending backup
exists; interrupted backup/marker cleanup has the same explicitly documented
limitations as ordinary activation. Do not delete fences or force replay.

Successful restoration does not reserve RAM, reload generated unit limits,
refresh the reference service environment, start a worker or prove health/
inference. Those are separate installed maintenance and qualification steps.
The worker still applies its ordinary runtime admission checks. This path uses
root custody and kernel locks, not the unfinished finite Admin/effect policy.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-completed-rollback-targeted-20261005-03`.
All 188 captured source entries and three supplementary test inputs matched
current repository raw-byte hashes. The final run passed:

- 58 top-level Rust model tests, including 16 new checks covering retention,
  actual isolated-UID read/unlink denial, different-model and manual-only
  restoration, exact service groups/modes, stale review, invalid prior weights,
  corrupt current weights, unsafe/substituted records, publication and
  restoration interruptions, record consumption, bounded replacement, catalog
  pin changes, fence-creation revalidation, old markers, preflight refusal and
  credential-error redaction. The existing restrictive-umask parent executes
  its otherwise ignored helper in an owned child process.
- Eleven model policy, four health-helper and fifteen VM-harness Python checks:
  30 total without skips. These use source/oracle checks and local fixtures,
  not an installed rollback, launched VM or real inference.
- Formatting, a warnings-denied locked offline native build and compiled CLI
  help checks.

The Docker run used the existing D-backed tools/cache, one CPU/Cargo job,
768-MiB memory/memory-plus-swap ceiling, 128-pid limit, no network, host devices
or Docker socket. All capabilities were dropped except CHOWN, DAC_OVERRIDE,
FOWNER, SETUID and SETGID for disposable ownership/identity fixtures. The tools
image ID was checked against
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account, service, TPM, clock or WSL memory setting changed. No image,
VM or real model was built/loaded; small weight pins use private test seams.
Interruption tests materialize file states at boundaries, not physical power
cuts. Real Linux DAC/locks do not qualify installed AppArmor enforcement.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `dc2dda692898b349ee324ff493bc2c5cecee32b6ba03a5bd50ec9cb92e9ac9a3` |
| `test-inputs.sha256` | `46bd676744d9993d195e7958bf9bfbea2986e0fe372eb9de6cf0b8219cd3ed23` |
| `test.log` | `fc3d44e2cd53b4c396c1a5ad84515b8255c954a6687c7f79d5a7fc7285d8db7b` |

Trial `01` failed compilation on an API unsupported by the existing toolchain.
The implementation was corrected without changing that toolchain. Trial `02`
passed 57 Rust and 30 Python tests plus the build. Trial `03` additionally
verifies private-error redaction, exact catalog binding and the final operator
instructions. All trials remain on D: for traceability.

## Remaining implementation and qualification

Complete the broader post-stop/restart/readiness failure policy, unsupported/
malformed-state recovery and migration, atomic resource leases/generations,
stale-worker fencing, pressure/quarantine/restart and crash-partial retention
policy. Governed model packs/catalog custody and product Admin/effect grants
remain separate implementation dependencies. This single root-private undo
slot does not close them or provide protected OS/release rollback.

Evaluate restoration, service configuration refresh, admission, real inference
and interruption/recovery on the consolidated image and separate native Ubuntu
target. See the [completion register](../G2_SOFTWARE_STATUS.md) and
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md).
