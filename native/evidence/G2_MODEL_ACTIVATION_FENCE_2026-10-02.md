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
clearing the marker. A partial or conflicting state stays fenced; the command
does not repair files, start a worker, grant product Admin authority or replace
signing custody. The digest binds a reviewed observation, not an authorization.

For an interrupted installation on a controlled laboratory system, first
preserve the state and inspect with `sudo luma-platform
model-activation-reconcile`. Use only the matching explicit command and exact
reported review digest after investigating the cause. Do not remove
`/var/lib/luma-os/model-activation.pending` by hand. If the phase is
`partial_or_conflicting_state`, leave the system fenced for forensic review;
neither clearance option is available. Any service restart after clearance is
a separate operator decision and must be checked against the selected model.

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
or production Admin workflow. Partial states need a designed repair path.
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
