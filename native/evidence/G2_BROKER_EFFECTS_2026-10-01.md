# Native broker effect replay fence - 2026-10-01

G2 remains **incomplete**. Per the owner's updated direction, implementation
continues without WSL memory changes, large VM runs or repeated image builds.
The full integrated sweep is deferred until a consolidated candidate exists,
followed by tests of that distributed image on the separate Ubuntu machine.

## Implemented scope

The native broker's existing laboratory root-only `start-worker` and
`stop-worker` requests now pass through a durable journal before dispatching
the fixed `luma-reference.service` operation. This is native integration, not
an injected Python effect adapter. It deliberately retains the existing
kernel-peer/root authorization boundary: **root is not product Admin**.

Fresh installation initializes `/var/lib/luma-broker/effects.json` inside the
encrypted data filesystem. The installer refuses an existing directory rather
than replacing prior records. Runtime missing/malformed state fails closed;
the broker never silently creates an empty history. The service has private
0700 state, 0600 journal/lock, bounded memory and no swap. A nonblocking sole-
writer lock excludes concurrent cooperative writers. The closed journal is
bounded to 4 MiB/4096 unique requests, with no automatic rotation.

The request identity is bound to the authenticated UID and one of two fixed
actions/targets. Different action bytes under the same request ID are a
conflict. A completed request is reauthorized and its completion synchronized
before replay acknowledgement; no second effect is dispatched. The current
deadline may be renewed for a retry, but grants/principal policy are not
invented by this mechanism. A historical acknowledgement does not assert the
worker is still in that state after other legitimate requests.

Before external dispatch the journal durably records `applying`, then checks
current peer authority/deadline again. A known authorization refusal at that
point is persisted as `not-applied`. Success is synchronized as `completed`.
Effect failure, interrupted dispatch or a lost/failed completion publication
retains an uncertain fence. Any `applying` record denies subsequent worker
effects, including a new request ID; status/manual recovery remain independent.
Neither current service state nor a timeout is treated as proof of completion.

The fixed systemctl invocation has a cleared environment, no interactive
authentication, no shell, no output buffering and a bounded wait (at most ten
seconds, also capped by the admitted request budget). Its child is reaped.
Killing the waiting systemctl **does not cancel its systemd job**; such a case
therefore remains uncertain, with no automatic retry. Filesystem I/O stalls
and kernel-uninterruptible waits are not solved by the userspace timer.

`luma-platform broker-effect-status` reports the installed, root-only journal
and whether reconciliation is required. It provides no clear/reset/retry or
role-assignment command. Broker `status` does not require this ledger, so live
media/manual health remains available. Worker mutations now require installed
mode as well as the existing root peer check.

## Limits and remaining integration

These are laboratory worker-effect records, not signed product receipts or
policy capabilities. They have no TPM anti-rollback anchor and cannot resist
an authorized OS-root adversary rewriting valid state. Account-generation,
finite delegation/revocation, sealed Admin enrollment, trusted time, governed
effect grants and reviewed recovery/reconciliation remain open. No unattended
migration initializes this history on an older installed image: missing state
denies worker mutations until a reviewed migration is implemented. A manual
systemctl invocation is outside this broker's receipt scope.

The installer/unit changes require a rebuilt image. No existing image or
running host service was patched. Integrated root-broker operations, reboot,
power interruption, ENOSPC/fsync faults, service confinement and upgrade
migration are pending for the consolidated sweep. The smaller filesystem
tests are not substitutes for those cases.

## Targeted development checks

Only affected-component checks are selected: eight Rust effect-journal tests,
sixteen Rust broker/transport/helper tests, two Python packaging checks and an
offline native build with warnings denied. The journal tests use real local
files/locks and injected effect callbacks, covering restart replay/conflict,
lost replies, panic boundaries, reauthorization, capacity, unsafe/missing state
and an actual completion-publication rename failure. The helper test executes
only `/bin/true`, `/bin/false` and a bounded `/bin/sleep`, not host systemd jobs.
Packaging tests inspect source/unit wiring; they do not run the installer.

Checks are capped at 768 MiB, one CPU and 128 processes, without networking,
host devices or a Docker socket in the test container. Build output remains
inside the dedicated D-backed daemon. The final snapshot/evidence directory is
`D:\LumaOS-builds\g2-broker-effects-targeted-20261001-02`.
The earlier `-01` snapshot passed but predates the final replay-sync change and
is retained separately. The final `-02` run **passed all 24 selected Rust tests,
both packaging checks, formatting and the offline native build**. The full
Rust/Python regression, specialized TPM/PAM tests and image acceptance were
not run in this implementation batch. `git diff --check` also passed.

- Final input-manifest SHA-256:
  `0f89d182b080b3554d11ccf78204f8c0c3025863efc74cf49f8e9e61dc1350d8`.
- Completed test-log SHA-256:
  `5caa266d9020d19a20537a370c81143b1a69d67fc054f106ebdc669b1aa45edb`.

Tests were copied separately into the frozen source tree. No source-only
result marks the rebuilt installer/service or the full effects requirement
complete; those remain in the consolidated-image acceptance inventory.
