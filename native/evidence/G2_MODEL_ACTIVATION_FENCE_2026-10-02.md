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
Binary-only upgrades of older installations still need controlled migration:
the old reference environment file is not automatically copied to its new
root-owned location, and older installations may lack the persistent runtime
lock. The changed service and policy have not been exercised on a newly built
image, with a real LLM, or on the separate native Ubuntu machine. G2 remains
open.
