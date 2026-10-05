# G2 model prior configuration restoration

On 2026-10-05, the native source gained private preservation of prior model
settings and an explicit reviewed restoration path for interrupted activation.
The final D-backed source checks passed. This addresses restoration while a
pending activation retains its saved bytes, **not full model rollback, atomic
activation, product Admin authorization or G2 completion**. No real model,
VM, image, host account, service, TPM or memory setting was changed or tested.

## Durable saved configuration

Before publishing a new schema-version-2 activation marker or changing
worker-visible settings, `begin_activation` exclusively creates and syncs
`model-activation.prior`. It contains the exact prior selection, reference
environment and local model API credential. The root-private file has bounded
canonical data, no-follow reads, single-link checks and restrictive permissions.
The pending marker binds its SHA-256 as well as the individual prior hashes.
Neither the backup nor its credential is returned in CLI status or review output.

The worker, preflight and new activation refuse when either the pending marker
or an orphaned saved file exists. A failure before marker publication therefore
does not permit silent overwrite or bypass. Unknown, substituted, linked,
publicly readable or oversized retained files refuse and are preserved.

Existing schema-version-1 markers remain readable with their original review
semantics, but cannot restore bytes they never saved. Normal or explicitly
reviewed clearance checks the current marker, configuration hashes and saved
file again. It removes the saved file before removing the marker. An
interruption between those removals leaves a reviewable marker with restoration
unavailable; existing safe unchanged/candidate clearance can still apply.

## Reviewed restoration and orphan handling

On a controlled installed laboratory system, inspect with:

```sh
sudo luma-platform model-activation-reconcile
```

Investigate the failure and preserve diagnostics without copying credential
bytes into logs. If restoring the saved prior configuration is approved, use
the exact current digest:

```sh
sudo luma-platform model-activation-reconcile --restore-prior REVIEW-SHA256
```

Restoration validates the saved bytes against the marker and current review.
It accepts only an exact consistent prior configuration in the current image
catalog, or the prior all-absent manual-only state. It verifies the prior
catalog-pinned weights before writes and again before clearance. It never
downloads missing weights or substitutes the candidate for an unavailable prior.
Legacy/mixed or already inconsistent saved settings remain fenced rather than
being presented as a usable model.

Writes occur under the existing operation/runtime locks and pending marker.
The credential, environment and selection are restored with their required
service groups/modes, explicitly independent of a restrictive maintenance
`umask`. Restoration to all-absent state removes only the three corresponding
configuration files, not weights or directories. Interrupted writes retain the
marker and saved bytes. Inspect again and obtain a new digest before retrying;
the old digest cannot authorize changed intermediate state. Exact restored
hashes must agree before clearance.

No service starts, readiness assertion, resource reservation, recovery-disablement
clearance or product Admin grant follows restoration. Restart and health checking
are separate operator decisions. This maintenance path is guarded by installed
root and the existing locks, not the unfinished finite Admin/effect policy.

An `orphan_prior_backup` without a marker has only one supported cleanup:

```sh
sudo luma-platform model-activation-reconcile --discard-orphan-backup REVIEW-SHA256
```

The exact saved bytes and current configuration must remain unchanged through
fresh review. This removes only that saved copy and changes no configuration.
Malformed or conflicting orphan state is preserved for investigation, not
automatically repaired. Never delete either fence by hand to force startup.

The saved copy is removed on successful activation or reviewed clearance. It
is **not a long-term archive for rollback after activation has completed**.
Offline recovery exports currently include the entire model state, including
this credential-bearing file. Protect their plaintext archives and retained
partials; do not place them in Git, release artifacts or public evidence.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-prior-restore-targeted-20261005-04`.
All 188 captured source entries and three supplementary test inputs matched
current repository raw-byte hashes. Passing scope:

- 42 top-level Rust model tests, including eleven new tests for private/bound
  preservation, actual isolated-UID read/unlink denial, exact prior and
  manual-only restoration, a different prior profile, stale review, bad weights,
  missing/substituted/symlink/hardlink/oversized backup, intermediate restoration
  states, orphan review, cleanup interruption, old-marker compatibility,
  invalid/legacy saved settings and restrictive-umask service modes. The umask
  parent launches its otherwise ignored helper in an owned child process.
- Nine model policy, four health-helper and fifteen VM-harness Python checks:
  28 total without skips. The health tests use local fixtures; the VM tests
  validate oracles and do not launch a VM or perform inference.
- Formatting, warnings-denied locked offline native build, compiled CLI help
  and syntax-only AppArmor parsing with kernel loading and cache use disabled.

Model bytes and prior-profile resolution use small fixtures, not real Qwen
weights or production catalog admission. Interruption tests materialize the
file states at write boundaries, not physical power cuts. The isolated UID/GID,
filesystem permissions and locks are real Linux behavior; installed service
confinement, restart, model readiness and physical durability remain unqualified.

The Docker test container used one CPU, a 768-MiB memory/memory-plus-swap
ceiling, 128-pid limit, no network, no host devices/Docker socket and D-backed
cache/evidence. All capabilities were dropped except CHOWN, DAC_OVERRIDE,
FOWNER, SETUID and SETGID for disposable ownership/identity fixtures. The tools
image ID was checked against
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
The WSL AppArmor parser was `5.0.0~beta1`; successful syntax parsing and its
cache/interface warning are not enforcement evidence for the target image.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `5aab8fe1536ca53a75f2174a9ae43b32ef3aac2272ac8d04c758b329b55beecb` |
| `test-inputs.sha256` | `ede603c3183ada013317abf36fc76136833d4498030837b340a8427d0f705e96` |
| `test.log` | `2e73733f12500190a3485f282828478aa78d9152210df26c082c1512a0ee404c` |

Failed trials remain on D:. Trial `01` lacked the container identity-drop
capabilities required by an existing test. Trial `02` passed Rust/Python/build
but used an unsupported parser flag. Trial `03` exposed a hardlink-fixture
verification error: the snapshot reader correctly refused its aliased key.
The fixture was corrected without weakening validation. Trial `04` verifies
the final source, including explicit service modes and the owned umask check.

## Remaining model implementation

Complete post-completion rollback and broader post-stop/readiness failure
policy, unsupported/malformed-state recovery, installed migration and
reconfiguration, governed pack/catalog admission, resource leases/generations,
stale-worker fencing, pressure/quarantine/restart and retention policy. This
does not replace those dependencies with hardware deferrals. Evaluate the
changed code on the consolidated image with real compact-model cycles and on
the separate native Ubuntu target. See the [completion register](../G2_SOFTWARE_STATUS.md)
and [implementation sequence](../G2_IMPLEMENTATION_FIRST.md).
