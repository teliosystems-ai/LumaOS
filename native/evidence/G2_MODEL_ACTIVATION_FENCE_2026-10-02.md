# G2 model activation interruption checkpoint

Date: 2026-10-02. This source increment adds a durable pending marker before
the installer changes the model credential, reference-service environment or
selection. The model worker and model reconfiguration preflight refuse to run
while that marker exists. Normal activation removes it only after the selected
model and reference settings agree; reinstalling the already selected model
also completes when that state is consistent. The reference environment moved
to a root-owned file outside the reference service's writable state directory.

The installed-root laboratory command `luma-platform model-activation-reconcile`
inspects an interrupted activation and returns a review SHA-256. It permits an
explicit `--abort-unchanged REVIEW-SHA256` only when the previous selection,
environment and credential bytes are unchanged, or `--publish-committed
REVIEW-SHA256` only when the candidate selection, environment, credential and
catalog-pinned weight bytes are consistent. The review is recomputed before
clearing the marker. At this initial checkpoint a partial or conflicting state
stayed fenced; the later reviewed completion path is described below. Neither
clearance starts a worker, grants product Admin authority or replaces signing
custody. The digest binds a reviewed observation, not an authorization.

For an interrupted installation on a controlled laboratory system, first
preserve the state and inspect with `sudo luma-platform
model-activation-reconcile`. Use only the matching explicit command and exact
reported review digest after investigating the cause. Do not remove
`/var/lib/luma-os/model-activation.pending` by hand. If the phase is
`partial_or_conflicting_state`, preserve it for forensic review; neither of
these two clearance options is available. The later `--complete-candidate`
path applies only after an explicit decision to roll forward to the verified
candidate. Any service restart after clearance is a separate operator decision
and must be checked against the selected model.

The final bounded offline test snapshot is
`D:\LumaOS-builds\g2-model-activation-targeted-20261002-04`. Its frozen
`source/build-inputs.json` SHA-256 is
`5d89991be36beee44f404d959ab3997902bcf1c1a43305b877526f10309ce290`;
`test.log` SHA-256 is
`19008fa11df55e7ffd64653a8c857a84af67c0db99af909a14b0084c32961d43`.
The D-backed Docker run used no network, VM, TPM or real LLM weights, and limited
the build to one CPU/Cargo job, 768 MiB, no extra swap and 128 PIDs. Twenty-four
Rust model tests, three model-runtime policy tests, fifteen existing VM-harness
unit tests, formatting, a warning-clean offline build and compiled CLI help
passed. Ubuntu WSL's AppArmor parser accepted both changed profiles with
kernel loading and cache writes disabled. The earlier `-03` snapshot retained
a failing test expectation for same-model reinstall; `-04` corrected the test
and passed.

This is an interruption fence and narrow reviewed clearance, not a multi-file
atomic transaction, generation lease, memory reservation, full model lifecycle
or production Admin workflow. This initial checkpoint had no partial-state
repair; a narrow reviewed roll-forward was added later, as recorded below.
Binary-only upgrades of older installations still need an explicit migration:
the old reference environment file is not automatically copied to its new
root-owned location, and older installations may lack the persistent runtime
lock. The changed service and policy have not been exercised on a newly built
image, with a real LLM, or on the separate native Ubuntu machine. G2 remains
open.

## Controlled legacy model migration

A subsequent source increment adds `luma-platform model-migrate-legacy` for an
installed-root operator. Before stopping the managed model, it requires an
unfenced, canonical selection, a safe root-owned credential, an exact legacy
environment under the service-owned directory, and catalog-pinned weight
bytes. It rejects conflicting new settings. After stopping the model, it
creates or acquires the persistent runtime lock, rechecks the legacy state,
uses the activation fence to publish the root-owned environment, reloads the
units, resets a possible model start-limit failure, and requests restart of
the model and reference services. The old environment file is retained for
older-image rollback; the command never runs automatically at boot.

The final migration source snapshot is
`D:\LumaOS-builds\g2-model-activation-targeted-20261002-07`. Its
`source/build-inputs.json` SHA-256 is
`3ee585793dbb41554842c680f295e9beae665b30908b58de31c96269f3aa0910`;
`test.log` SHA-256 is
`0796417be1ab4082ee0145cb8020d2b3c59c868bdad3d339c8f7b32a68240fdf`.
The same bounded, offline D-backed test setup passed 26 Rust model tests, four
policy checks, fifteen VM-harness unit tests, formatting, a warning-clean
build and compiled CLI help. Tests covered wrong legacy content, conflicting
new settings, symlink rejection, repeated migration and a retained pending
fence. No installed service restart, image upgrade, real model, TPM or
physical machine was exercised. A failed restart after a successful file
migration still needs operator diagnosis; the command reports a restart
request, not proven model readiness.

## Verified acquisition before worker stop

Another source increment separates model acquisition from activation.
`model-install` now downloads and verifies the candidate while the selected
worker may remain active. A network, size or hash refusal therefore occurs
before the managed stop request. After acquisition, it checks the remaining
2 GiB storage reserve; activation rechecks capacity and the cached bytes after
stopping the worker. The read-only `model-install-check` now verifies an
existing cataloged cache file and applies the reserve-only disk threshold
when that file is valid. An invalid existing file is refused before stop,
including a symlink. Fresh downloads still require their full size plus the
reserve. The installer also uses the split path, but has no prior worker to
preserve.

The final targeted snapshot is
`D:\LumaOS-builds\g2-model-activation-targeted-20261002-10`. Its
`source/build-inputs.json` SHA-256 is
`40918d7f576e462221ec05091c4f46db07cc673ec7d88e529b083eeca0ee8d3d`;
`test.log` SHA-256 is
`eb3c7a34406f28ef38c98aa495fc7ff46cde157ae51d12883ea725960ec119b8`.
The bounded offline run passed 26 Rust model tests, five policy checks,
fifteen VM-harness unit tests, formatting, a warning-clean build and compiled
CLI help. Unit tests cover pre-stop refusal ordering, cached-file integrity
and the separate disk thresholds. No real download, running model, installed
service transition or image qualification was exercised. Activation failures
after the stop can still leave the previous worker stopped or fenced; resource
reservation, generation fencing and pressure management remain open.
The earlier `-09` snapshot passed its tests but retained a cached-model
preparation check that still demanded space for a second download; `-10`
aligns preparation with its read-only preflight and passed the same checks.

## Unchanged prior worker restart after failed activation

If a selected model was running before the managed stop, `model-install` now
records its exact selection, reference environment and credential digests.
When activation fails, it requests restart of that prior worker only if no
activation marker exists, the three configuration files are still unchanged,
the prior catalog-pinned weights verify, and recovery disablement is absent.
It also requires the runtime lock to be free. A pending marker, changed state,
invalid weights, conflicting worker or explicit recovery disablement prevents
automatic restart. The command still returns an error after requesting a
prior-worker restart; it does not claim service readiness or hide the failed
candidate activation. If there was no running prior model, no fallback starts.

The final bounded offline source snapshot is
`D:\LumaOS-builds\g2-model-activation-targeted-20261002-12`. Its
`source/build-inputs.json` SHA-256 is
`c41d0ce01ced84d9b153d3f1f32abcd5c416c00603ef2b9569553776c8c4456a`;
`test.log` SHA-256 is
`39f12f9904ba4adee4dd03a2b6dcaf8c0f38bf6be15ffc281a7655f981d2d543`.
Twenty-seven Rust model tests, five policy checks and fifteen VM-harness unit
tests passed, along with formatting, the warning-clean offline build and
compiled CLI help. Tests cover the transition order and refusals for a pending
marker, changed environment and recovery disablement. No installed systemd
transition, real LLM, image upgrade or physical failure was exercised.
Partial/conflicting activation still has no automatic repair, and a successful
systemd restart request is not evidence of a healthy inference service.

## Reviewed partial candidate completion

A further source-only increment adds an explicit `--complete-candidate
REVIEW-SHA256` path for a pending `partial_or_conflicting_state`. It verifies
the catalog-pinned candidate weight, rechecks the exact reviewed marker and
file-state digest, then writes a consistent candidate credential, reference
environment and selection under the existing fence. It clears the marker only
after those files agree. Invalid weights, malformed credentials, unsafe files,
or changed review state leave the fence in place. The command does not restart
or prove readiness of any service and is an installed-root laboratory
maintenance command, not product Admin approval or signed production custody.

On a controlled test installation, preserve the marker and diagnostics first.
Inspect with `sudo luma-platform model-activation-reconcile` and investigate
the cause. Only if rolling forward to the named candidate is approved, run
`sudo luma-platform model-activation-reconcile --complete-candidate DIGEST`
with the exact reported digest. Check the resulting selection and service
configuration before separately deciding whether to restart the worker;
verify readiness afterward. Do not delete the marker by hand. This path does
not roll back to the prior model, resolve arbitrary inconsistent state, or
qualify a post-stop service failure.

The final bounded offline source snapshot is
`D:\LumaOS-builds\g2-model-activation-targeted-20261002-14`. Its frozen
`source/build-inputs.json` SHA-256 is
`c9e8b31220ca77e2a485abe77ac2eff95309004d5a087e5ff3694767dc6d6b84`;
`test.log` SHA-256 is
`5b315ddad9e9a9c82c8ef2d4ffe2afefd87349f401afb6280069878f18e4d29c`.
The D-backed Docker run used no network, VM, host TPM or real LLM load, with
one CPU/Cargo job, 768 MiB, no extra swap and 128 PIDs. Twenty-nine Rust
model tests, six model-runtime policy tests, fifteen VM-harness unit tests,
formatting, a warning-clean offline build and compiled CLI help passed. No
installed transition, native Ubuntu qualification or full image test was run.
