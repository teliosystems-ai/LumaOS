# G2 software completion register

Updated 2026-10-06. **G2 software is not complete.** This register separates
work that can be executed in the current Windows/Ubuntu WSL/VM environment
from production deployment decisions and physical qualification. It does not
change the frozen reference release, governing requirements, or exit criteria.

Authority: `docs/DEVELOPMENT_PLAN.md`, G2 Ubuntu platform alpha; inherited G1
contracts; the pinned sources in `docs/governing_sources.json`. The full G2
gate still requires the specified E1/E2 executions. A lab signature, source
unit test, default-deny placeholder, or smaller model cannot close a different
requirement.

## Current software inventory and work still required

### Admin and workflow closure status

Neither work package is closed, and neither is merely waiting for the final
image/testing. **Both still require software integration.** The source
checkpoints below do not waive the development plan's production-interface,
policy and distributed-media workflow requirements.

Admin has existing-owner checkpoint enrollment, explicit reviewed product
bootstrap, finite activity/role definitions, a local catalog service and genuine
PAM-to-disposable-TPM composition tests. Remaining code includes trusted-time
finite assignment/revocation, effect-time resource grants, principal/account and
bootstrap recovery, reviewed uncertain enrollment states, signing custody
lifecycle and complete installed service/recovery integration. Root privilege
and role definitions remain insufficient to grant effects.

Workflows have signed graph validation, the exact native invoice executor,
SQLite WAL checkpoints, pre-effect cancellation, idempotent artifact publication,
restart/replay and reviewed acknowledgement of proven committed outcomes.
They remain installed-root laboratory interfaces, not the complete production
workflow. Remaining code includes the governed supervisor and service delivery,
principal-bound source-folder/effect grants, effect-time identity/resource/lease
checks, trusted timestamps, broader scheduling/cancellation/reconciliation and
governed public-schema/migration/retention integration. Ordinary node validation
does not implement generic execution or those policy boundaries.

Complete the shared trust/time and grant dependencies, join them to the native
workflow/supervisor, then integrate installer/boot/update/recovery. The final
consolidated image and separate native Ubuntu runs must qualify that integrated
implementation. Production custody and unavailable hardware evidence remain
external requirements, separate from these open software items.

**Execution change requested by the owner:** finish the open G2 implementation
before another memory-heavy VM/model sweep, then evaluate one consolidated
image and perform full testing on the separate native Ubuntu machine. WSL
settings remain unchanged. Only bounded targeted development checks run in
the meantime. See [the implementation-first sequence](G2_IMPLEMENTATION_FIRST.md).
This supersedes the immediate sequence-11 retry plans in older checkpoints.

The [sealed checkpoint delivery checkpoint](evidence/G2_ADMIN_DELIVERY_2026-10-02.md)
replaces the native checkpoint's unused plaintext credential-file dependency
with fixed-path TPM unsealing into locked memory. Schema-v2 configuration binds
the deployment, image PCR key and encrypted blob; missing, unsafe, stale or
legacy inputs refuse without fallback. Ten selected ordinary Rust tests, seven
software-TPM delivery invocations, two wiring checks and the native build passed.
This was a delivery-only checkpoint; subsequent checkpoint-enrollment integration
is described below. Hierarchy custody procedures and the complete confined Admin
service remain open. On 2026-10-02 the owner
selected **existing TPM ownership with custodian-supplied authorization**. Luma
must not take ownership, change hierarchy authorization or clear the TPM.
This closes the selection question, not enrollment or hardware qualification.

The [existing-owner checkpoint](evidence/G2_EXISTING_OWNER_2026-10-02.md) records
the new fixed-index native provisioning boundary. It authenticates the supplied
existing owner, encrypts the independent NV authorization in a salted session,
refuses collisions and exposes no clear, undefine or hierarchy-change operation.
Three ordinary TPM tests, one software-TPM provisioning fixture and the native
build passed. That checkpoint preceded the explicit enrollment transaction below;
the installer still does not provision automatically.

The `admin-checkpoint-enroll LOGIN --existing-owner` source command now joins
principal-bound PAM, masked custodian input, a durable parent-allocation intent,
native signed-PCR sealed-child preparation, a synchronized pending proposal,
one-shot NV provisioning, authenticated readback and no-replace publication.
The fixed-path loader uses that native credential format. A positive
existing-owner enrollment and subsequent credential delivery passed on a
disposable software TPM. The packaged systemd 255 path still refuses nonempty
owner authorization; its refusal remains a compatibility regression, not the
product enrollment path. See [the native enrollment checkpoint](evidence/G2_NATIVE_OWNER_ENROLLMENT_2026-10-02.md),
[the earlier failed integration](evidence/G2_ENROLLMENT_TRANSACTION_2026-10-02.md),
and [the operator instructions](LOCAL_TPM2_ADMIN.md#explicit-checkpoint-enrollment).
Full reviewed interrupted-enrollment recovery, Admin bootstrap/service,
independent credential recovery, production custody and installed-image
evaluation remain open. A [fixed-path inspection command](evidence/G2_ENROLLMENT_INSPECTION_2026-10-02.md)
reports retained intent and TPM handle occupancy. One narrowly reviewed
[bound-parent continuation](evidence/G2_BOUND_PARENT_CONTINUATION_2026-10-02.md)
now passes a disposable-TPM test without repeating parent allocation. An
[exact committed-pending publication](evidence/G2_PENDING_ENROLLMENT_PUBLICATION_2026-10-02.md)
also passed targeted disposable-TPM tests: it authenticates the already-written
genesis head, requires fresh principal authentication in the product command,
and publishes only the unchanged pending proposal without a TPM write. Vacant
NV, wrong head, unbound parent, other uncertain-write and conflict states
remain fenced. Neither increment is full reviewed enrollment recovery or an
installed Admin service; targeted checks do not close those requirements.

The later [retained-record validation checkpoint](evidence/G2_ENROLLMENT_RECORD_2026-10-03.md)
requires intent creation and read-only inspection to validate the canonical,
inert existing-owner enrollment record, not merely its matching deployment
hash. A matching-hash role-grant forgery is rejected before TPM handle
observation. Sixteen ordinary Rust tests, disposable software-TPM enrollment,
continuation and pending-state cases, and the offline native build passed.
Unbound-parent and uncertain-NV recovery, installed operation and product
Admin activation remain open.

The [publication retry and writer authorization checkpoint](evidence/G2_ENROLLMENT_PUBLICATION_RETRY_2026-10-04.md)
adds exact enrollment replay after a lost directory-publication acknowledgement.
Fresh PAM remains mandatory for publication/replay; proof and authority are
rechecked after storage synchronization. The native inert journal now requires
the integrating service's authorization of the exact entry before preparation
and before TPM dispatch, with disk/TPM/epoch checks at that boundary. These
increments do not activate product Admin or complete the service/policy backlog.
Forty-seven focused Rust tests, five pending/publication software-TPM cases,
existing enrollment/continuation/credential and committed-journal recovery,
two wiring checks, formatting and the offline native build passed on D-backed
storage. The CI runner now invokes these fixtures and hashes their C interposer;
syntax passed, but the full updated runner/remote CI were not executed here.
Installed-image and physical qualification remain open.

The [explicit product bootstrap checkpoint](evidence/G2_ADMIN_BOOTSTRAP_2026-10-04.md)
adds a separately authenticated and reviewed `admin-bootstrap` source command.
Its private canonical principal/enrollment payload is bound into one TPM-backed
receipt; restart/replay verifies that semantic payload rather than accepting
root privilege or the inert enrollment record as Admin. Fifty-eight selected
ordinary Rust tests, the disposable existing-owner TPM activation/replay fixture,
four wiring checks, formatting and the offline build passed. This implements
the narrow initial governance-principal bootstrap, not service confinement,
finite delegation, principal recovery/lifecycle, scoped effect grants, trusted
time or signing custody. Installed PAM-to-TPM and candidate-image evaluation
remain open. G2 software remains incomplete.

The [finite activity and role definition checkpoint](evidence/G2_ADMIN_CATALOG_2026-10-04.md)
adds fresh principal-bound registration and compare-exchange role definitions.
Canonical semantic events bind the complete actor, enrollment, predecessor
head, sequence, state version and exact command into the TPM journal. Replay
rebuilds the finite catalog and verifies historical requests without overwriting
later revisions. Unreferenced preparations fence unrelated work; partial or
uncertain state is preserved. Seventy-two ordinary Rust tests, the extended
disposable-TPM definition/restart/replay fixture, five wiring checks, formatting
and the offline build passed. Definitions are not assignments, resource grants
or signing custody. The confined service, trusted-time assignment/revocation,
effect authorization, principal lifecycle/recovery and installed qualification
remain open; this does not complete the Admin/trust work package or G2.

The [local catalog service checkpoint](evidence/G2_ADMIN_SERVICE_2026-10-04.md)
adds a fixed Unix-socket daemon and unprivileged human client for the existing
catalog operations. Kernel peer identity must match the fresh PAM/principal
observation; passwords are separate bounded binary input, never JSON or a
serialized authority token. A packaged systemd/AppArmor boundary and mandatory
enforced-confinement startup checks limit the service. This source increment
does not implement assignments, effect grants, trusted UTC or signing custody.
Targeted checks establish protocol behavior, not installed profile enforcement
or the complete PAM-to-TPM flow; those require the rebuilt consolidated image.
The full Admin lifecycle and the wider G2 implementation backlog remain open.

The [real PAM composition checkpoint](evidence/G2_ADMIN_PAM_COMPOSITION_2026-10-04.md)
closes a freshness gap in the authenticated identity projection and adds a
shared-adapter fixture joining genuine PAM, kernel peer identity, principal
revalidation, sealed reload and the disposable native TPM catalog. Seventeen
socket requests cover reviewed commits/replay and denied password, UID,
principal, review and post-PAM revocation cases. Sixty-five ordinary Rust tests,
ten wiring checks, formatting and the offline build passed. Alternate fixture
paths are test-only; production has no new fallback. This is not an executed
installed systemd/AppArmor service, enrollment/bootstrap acceptance or a
trusted-time provider. Those integrations and the full Admin lifecycle remain
open; no candidate image or final sweep ran.

The [trusted UTC design](TRUSTED_UTC_DESIGN.md) uses NTS-only time from
three independent operators and a protected, uncertainty-bounded Luma keeper.
The source now includes inert quorum/interval arithmetic; it does not implement
or activate that provider. The owner approved the three providers, initial
bounds and offline-refusal policy on 2026-10-05. A fixed policy artifact and
non-authorizing keeper lifecycle now exist in source, with an upstream chrony
measurement/report audit. A pinned good-sample publisher hook and closed C/Rust
measurement codec also exist; they are not an installed or eligible time service.
Protected live reception, bootstrap/recovery,
protected history, service confinement and authorization integration
remain open. Admin still reports no trusted UTC and admits no assignments or
effect grants. See [the bounded arithmetic checkpoint](evidence/G2_UTC_BOUNDS_2026-10-04.md)
and [the policy and keeper checkpoint](evidence/G2_UTC_KEEPER_2026-10-05.md).
The latter passed 101 ordinary Rust tests, ten wiring checks, formatting and
the offline native build on D:. No live NTS or installed-service qualification
was performed; source observations/history remain data rather than authority.

The [publisher checkpoint](evidence/G2_UTC_PUBLISHER_2026-10-05.md) adds exact
source-boundary patch guards, strict operator registration, nonblocking complete
measurement rounds, preserved sample age/identity, clock/leap/loss invalidation
and a bounded frame decoder. The fixture is separate from image packaging;
the exact security-qualified production dependency and controlled NTS attack
journey remain open. Source linkage does not replace live peer verification,
protected history or effect-time checks. No final image/sweep or host time-service
activation is performed by this increment.
Its final targeted run passed the sanitized C fixture, strict hook compilation,
patched `+NTS` build, 107 ordinary Rust tests, one C/Rust interoperability test,
17 Python checks, formatting and the offline native build on D:.

The later [measurement receiver checkpoint](evidence/G2_UTC_RECEIVER_2026-10-05.md)
adds real per-datagram kernel credential checks, pidfd/process observation,
bounded queue draining and source replay/epoch validation. It receives data,
not approved time authority. It does not approve a producer's code/confinement,
restore TPM time history, bind an installed listener or enable assignments.
Complete the protected supervisor/runtime approval, keeper/history and recovery
composition, lifecycle notifications and authorization/package integration.
The subsequent JSON source adaptation removes the binary-format mismatch.
Endpoint/method deployment review under ADR-0002 is still required; no control
transport or logical ownership boundary is superseded.
The final D-backed targeted run passed 131 ordinary Rust tests, two explicitly
selected fixtures (13 real-kernel cases and retained C-frame interoperability),
19 Python checks without skips, formatting and the offline native build.
These are source-boundary checks, not installed-service or production-authority
qualification; Admin and workflow closure remains as described above.

The [receiver and keeper composition checkpoint](evidence/G2_UTC_STREAM_2026-10-05.md)
now preserves every drained round and reduces them in order, so intermediate
quorum loss or disagreement cannot be hidden by later samples. Source-clock and
keeper acquisition generations remain distinct. Quiet polls reproject the
current source inventory at a fresh local-clock boundary only within a bounded
producer-heartbeat deadline; missing operators are not resurrected and lifecycle
notifications/errors fence without automatic recovery. This is source fixture
composition, not an approved runtime, authenticated TPM history or time authority.
Protected supervisor/history/recovery and final effect integration remain open.
The final D-backed run passed 142 ordinary Rust tests and four explicit fixtures
(23 kernel cases plus retained C-frame interoperability), 21 Python checks
without skips, formatting and the offline build. The three kernel fixtures are
now wired into the isolated TPM runner; only their targeted executions and runner
syntax were checked here, not the complete runner or remote CI.

The [kernel clock-step watch checkpoint](evidence/G2_UTC_STEP_WATCH_2026-10-05.md)
adds an owned cancel-on-set timer checked before and after candidate work.
Kernel cancellation, timer expiration and unverifiable reads fence the session,
including quiet polls with a previously bounded candidate. There is no automatic
rearm or weaker observer fallback. This supplements numeric clock comparisons;
it does not qualify actual step delivery, all step-and-restore/suspend races or
the absolute rate envelope. Protected supervisor/history/recovery, complete
lifecycle delivery and authorization integration remain open.
The final D-backed batch passed 147 ordinary Rust tests and four explicit
fixtures (25 kernel cases plus retained C-frame interoperability), 23 Python
checks without skips, formatting and the offline build. Observer checks inspect
real timer configuration and expiration; cancellation-result injection is not
actual clock-step or suspend qualification. No host clock was changed.

The [JSON transport checkpoint](evidence/G2_UTC_JSON_TRANSPORT_2026-10-05.md)
adapts the source publisher and receiver to ADR-0002's four-byte big-endian
length and strict UTF-8 JSON envelope. Caller PID/real UID claims must match
kernel message credentials; fixed request/deadline/epoch fields and the ordered
inventory refuse substitutions. The receive path has no binary fallback.
This removes the serialization mismatch, not endpoint/method deployment review
or protected runtime/history/authority integration. No listener or time service
is enabled. The final D-backed batch passed a newly sanitized C fixture and
patched `+NTS` build, 152 ordinary Rust tests and five explicit fixtures
(27 kernel cases plus binary and JSON C/Rust interoperability), 24 Python checks
without skips, formatting and the offline build. These remain source tests,
not live NTS, installed-service or Admin/workflow completion evidence.

The [UTC history checkpoint](evidence/G2_UTC_HISTORY_2026-10-05.md) adds canonical
monotonic floors and independent history versions to the existing Admin
checkpoint domain. Mixed catalog/history replay checks all payload and prefix
bindings; a private reviewed append adapter retains orphan/pending state and
renews source/principal callbacks through final dispatch. Exact historical
acknowledgement never reacquires time or writes again. No new NV index, history
reset or product writer endpoint is introduced. The new fault tests use fake
anchor/observation adapters, not physical TPM or authenticated live UTC evidence.
The final D-backed batch passed 170 ordinary Rust tests and five explicit
fixtures (27 kernel cases plus retained binary/JSON C interoperability), 26
Python checks without skips, formatting and the offline build. Protected writer
composition, current history binding in keeper/effect checks, certificate
bootstrap/recovery and installed qualification remain open; `trusted_utc_available`
is still false and Admin/workflows/G2 are not complete.

The [current UTC history binding](evidence/G2_UTC_HISTORY_BINDING_2026-10-05.md)
now joins a fresh internal shared-checkpoint semantic reader to the non-authorizing
stream. Explicit bootstrap, all catalog/history payloads and current anchor
checks precede a private floor binding. Shared-head or TPM epoch changes and
failed reads fence; catalog-only changes cannot reuse the older binding. After
blocking replay the stream repeats peer/queue/clock/watch checks and reprojects,
so stale or newly queued telemetry cannot escape on a pre-replay candidate.
Numeric floor construction is test-only outside private assembly, and polling
writes no checkpoint. The final D-backed batch passed 174 ordinary Rust tests
and six explicit fixtures (39 kernel cases plus retained C interoperability),
28 Python checks without skips, formatting and the offline build. New history
cases use fake anchors/observations, not physical TPM or live NTS qualification.
Protected deployed provider/writer, certificate bootstrap/recovery, full lifecycle
delivery and final effect integration remain open. No time authority, assignment
or workflow completion is enabled, and G2 remains incomplete.

The earlier [disposable TPM feasibility experiment](evidence/G2_OWNER_CREDENTIAL_FEASIBILITY_2026-10-02.md)
informed the native backend now integrated above. The targeted native tests
exercise signed PCR 11 renewal, fixed PCR 7 denial, forged-signature refusal,
parent/blob substitution refusal and restart continuity. These are not
installed-image, hardware, service-confinement or production-custody evidence.

The [model-runtime checkpoint](evidence/G2_MODEL_RUNTIME_2026-10-02.md) adds
single-worker exclusion shared with model activation, inherited lock lifetime,
verified-weight descriptor handoff and stricter weight/selection metadata checks.
Fourteen targeted Rust tests, two wiring checks, fifteen existing model-harness
unit tests, formatting and native build passed on D-backed storage. No LLM or
VM was loaded. AppArmor parser/enforcement and actual pinned-runtime descriptor
loading still require image-level evaluation. This is not the full resource
lease/generation, stale-worker fencing, atomic activation or governed-pack
lifecycle implementation; those remain open.

The [cgroup memory admission checkpoint](evidence/G2_MODEL_CGROUP_ADMISSION_2026-10-02.md)
adds a fail-closed capacity check at model selection and worker startup: the
selected worker's configured `MemoryMax` must fit every finite cgroup-v2
ancestor limit. Seventeen targeted Rust model tests, including a live container
cgroup observation, and the existing model policy/harness checks passed. This
does not reserve memory, detect all pressure, or implement resource leases,
generations or stale-worker fencing; no image or LLM was run for this increment.

The [model reconfiguration preflight checkpoint](evidence/G2_MODEL_PREFLIGHT_2026-10-02.md)
adds `model-install-check MODEL-ID`, a read-only, non-reserving hardware,
cgroup and free-space check on the installed system. `model-install` now runs
that check under its operation lock before stopping the existing worker, then
rechecks admission during activation. Predictable capacity refusals therefore
leave the current worker running. Targeted Rust and policy/harness tests passed;
fully atomic activation, generation fencing and actual installed-system
service transitions still need implementation/evaluation. A later source
increment also moves verified candidate acquisition before the stop request,
so download and hash failures no longer require stopping the selected worker.
The read-only preflight distinguishes a verified cached file from a new
download when checking free space. The later targeted run passed 26 Rust model
tests, five policy checks and fifteen VM-harness unit tests; installed
transitions remain untested. A subsequent narrow source-only fallback requests
restart of a previously running worker after failed activation only when its
configuration and pinned weights are unchanged and no activation or recovery
disablement marker exists. The later bounded run passed 27 Rust model tests,
five policy checks and fifteen VM-harness unit tests. A later reviewed
candidate roll-forward can repair a partial activation in source; neither
path proves service readiness. The same guarded prior restart is now requested
after an unsuccessful stop only when the old runtime lock is free and the
prior files and weights still verify. A bounded source run passed 30 Rust
model tests, six policy tests and fifteen VM-harness unit tests; a real
systemd stop failure has not been qualified. A subsequent source guard now
requires an exact loaded `active/running` or `inactive/dead` model unit state
before that stop request; uncertain service status refuses the operation.
The bounded check passed 31 Rust model tests, six policy tests and fifteen
VM-harness unit tests. Installed behavior remains unqualified.

The [model reconfiguration readiness checkpoint](evidence/G2_MODEL_READINESS_2026-10-03.md)
adds a bounded fixed-loopback health probe and post-probe selected-worker and
reference-unit checks before `model-install` reports success. It prevents a
successful systemd restart request alone from being treated as listener
readiness. The D-backed source check passed 31 Rust model tests, seven policy
tests, four health-helper tests and fifteen VM-harness unit tests. This is
not a real inference, installed reconfiguration or full failure-policy pass.

The [model activation interruption checkpoint](evidence/G2_MODEL_ACTIVATION_FENCE_2026-10-02.md)
adds a durable pending fence before model credential, reference environment or
selection writes. The worker and reconfiguration preflight refuse while it is
present; explicit root-only review can clear only an unchanged prior state or
a consistent candidate with verified catalog-pinned weights. The reference
environment is now root-owned outside the service's writable directory.
Twenty-four targeted Rust model tests, three policy checks, fifteen existing
VM-harness unit tests, formatting, offline build and no-load AppArmor parsing
passed. This is not atomic multi-file activation or product Admin approval.
Partial states remained fenced at that checkpoint, and installed service
transitions and real-model cycles remain untested. A later source-only,
digest-reviewed `--complete-candidate` path can roll a partial activation
forward to verified candidate settings without starting the worker. Its
bounded check passed 29 Rust model tests, six policy tests and fifteen
VM-harness unit tests; rollback and installed qualification remain open. The
same checkpoint also records a source-only,
explicit `model-migrate-legacy` path for older model-enabled installations.
It verifies the legacy selection, credential, environment and pinned weights
before stopping the worker, creates the missing runtime lock, and publishes
the root-owned environment under the activation fence. The later bounded run
passed 26 Rust model tests, four policy checks and fifteen VM-harness unit
tests. Installed upgrade and rollback behavior are not yet qualified.

The [prior configuration restoration checkpoint](evidence/G2_MODEL_PRIOR_RESTORE_2026-10-05.md)
now saves exact prior model settings in a root-private, marker-bound file before
new activation writes. Both pending and orphan saved state fence startup and
new activation. Installed-root review can restore a consistent catalog-pinned
prior configuration or its all-absent manual-only state without starting services;
stale review, unsafe/missing saved data, invalid prior settings and bad weights
refuse. Intermediate restore states require fresh review. Required groups/modes
are explicitly restored under restrictive umask; legacy markers cannot invent
missing prior bytes. Exact unchanged orphan cleanup and interrupted cleanup
remain reviewed, not automatic. The final D-backed run passed 42 Rust model
tests, 28 Python checks, formatting, the offline build, CLI help and no-load
AppArmor parsing. Small weights and fault states are fixtures, not real-model
or power-cut qualification. The pending saved copy is removed at activation/clearance;
broader failure/resource policy and installed
qualification remain open. This is not product Admin approval or G2 closure.

The [completed activation rollback checkpoint](evidence/G2_MODEL_COMPLETED_ROLLBACK_2026-10-05.md)
now retains one separate root-private prior-configuration slot before pending
clearance. The exact catalog, completed pin/configuration and current review
bind restoration; unsupported prior state, unsafe records and bad prior weights
refuse. Preflight rejects unknown slot data before stopping the managed worker.
Reviewed restoration saves the pre-rollback candidate under an activation fence,
restores exact settings or manual-only state, consumes the slot and does not
start services or clear recovery disablement. Interrupted writes require explicit
activation reconciliation; consumption/cleanup limitations remain documented.
Private decode errors suppress supplied credential values. The final D-backed
source checks passed 58 Rust model tests, 30 Python checks, formatting, the
offline build and CLI help. This is one-step configuration undo, not running
worker recovery, resource generations, protected release rollback or installed
qualification. Broader failure/resource and governed Admin/pack policy remain open.

The [observed reconfiguration quarantine checkpoint](evidence/G2_MODEL_QUARANTINE_2026-10-05.md)
adds a closed five-stage restart/readiness sequence and an exclusive durable
incident record before requesting worker stop on failure. Publication or stop
failure still returns failure and preserves uncertain state. Normal activation,
preflight and worker startup refuse quarantine; the packaged unit/profile are
wired in source. Reviewed completed rollback can preserve quarantine and recovery
disablement while restoring prior settings. Separate installed-root clearance
requires a fresh incident/configuration review, verified current weights or
manual-only state and idle runtime exclusion; it does not restart services or
prove resource return. Fresh incident IDs prevent reuse of an earlier identical
failure's review. The final D-backed run passed 71 Rust model tests, 33 Python
checks, formatting, the offline build, CLI help and no-load AppArmor parsing.
Source checks cover these observed-error paths. The later trial increment below
adds startup fencing for controller death; continuous cleanup, later
boot/migration/OOM/pressure supervision, resource generations, product
Admin/effect policy and installed qualification remain open.

The [incomplete quarantine recovery checkpoint](evidence/G2_MODEL_INCOMPLETE_QUARANTINE_2026-10-05.md)
adds explicit installed-root review and exact private retention of empty/truncated
JSON before removing the startup fence. Complete/future JSON, other malformed
input and unsafe/conflicting state refuse. Fresh review binds file identity,
current catalog and consistent settings/verified weights or manual-only state;
exact private archives permit retry without deleting evidence. Settings,
weights and recovery disablement are preserved; services are not started.
The final D-backed checks passed 80 Rust model tests, 34 Python checks,
formatting, the offline build and CLI help, including actual isolated-worker
denial of retained bytes. This is not crash supervision or installed-image
qualification. Broader unsupported/archive recovery, retention quotas/lifecycle,
resource generations, production Admin/effect policy and the other model
supervision gaps remain open.

The [controller validation checkpoint](evidence/G2_MODEL_VALIDATION_2026-10-05.md)
adds a durable trial before installed reconfiguration publishes activation.
Bound live kernel process/write-lock observations gate isolated-worker startup
before and after weight/RAM admission; process exit/kill preserves trial bytes
and blocks subsequent startup. Successful restart/health/state checks explicitly
clear the trial; completion errors use quarantine-before-stop handling.
Separate installed-root abandoned-trial review retains exact private evidence
before clearance for consistent verified settings or manual-only state, preserving
independent quarantine and recovery disablement. The final D-backed checks passed
88 Rust model tests, 37 Python checks, formatting, offline build, CLI help and
no-load AppArmor parsing. This closes a source publication-to-validation startup
gap, not continuous worker cleanup, the final observation-to-exec interval,
memory leases/generations, initial-boot/migration policy, unsupported partial-trial
recovery, protected product Admin authority or installed qualification.

The later [incomplete validation recovery checkpoint](evidence/G2_MODEL_VALIDATION_INCOMPLETE_2026-10-05.md)
adds reviewed exact private retention for empty/truncated trial JSON. Fresh
review binds record identity, existing lease inode, catalog and consistent
settings/verified weights or manual-only state; same-byte replacement and stale
review refuse. Both typed and incomplete recovery now hold an exclusive flock
through review, retention and clearance, with POSIX ownership checks that also
refuse live legacy or unknown OFD holders. Recovery does not start services,
clear independent fences or delete archives. The final D-backed checks passed 96 Rust model
tests, 39 Python checks, formatting, offline build, CLI help and no-load AppArmor
parsing; all captured source/test hashes matched. This closes the narrow EOF-only
trial recovery gap, not arbitrary malformed/future-state repair, retention
lifecycle, continuous supervision, resource leases/generations, production
Admin/effect authority or installed qualification. G2 remains incomplete.

The [owned-child supervision checkpoint](evidence/G2_MODEL_SUPERVISION_2026-10-06.md)
keeps the native isolated supervisor as the service main process and the fixed
runtime as its owned child. Poll checks bind trial bytes/controller liveness,
independent activation/quarantine/disablement fences and runtime-input hashes;
failure kills/reaps only that child through a kernel PID handle. Parent-death
registration protects the direct child when the supervisor dies. Successful
trial completion permits continued operation and watching. Recovery state is
not cleared or invented by the worker. The final D-backed checks passed 106 Rust
model tests, 44 Python checks, formatting, offline build, CLI help, runner syntax
and no-load AppArmor parsing; all 190 source and seven supplementary hashes
matched. This closes a narrow running-child/controller-death gap, not installed
descendant containment, complete event/pressure/OOM/boot/migration supervision,
atomic resource leases/generations, protected lifecycle receipts, production
Admin/effect integration or G2 completion. Evaluate the changed binary/profile
and actual service teardown on the consolidated image and separate Ubuntu machine.

The [committed-audit recovery checkpoint](evidence/G2_ADMIN_RECOVERY_2026-10-01.md)
adds explicit, digest-reviewed publication of an interrupted journal commit only
when the authenticated TPM proves the exact one-entry successor. It does not
write the TPM, replay effects, discard uncommitted proposals or grant Admin.
Thirteen targeted Rust tests, one isolated software-TPM lost-reply/recovery test
and the native build passed. The command still requires the outstanding
installed enrollment/service qualification; this is not fresh-image operational
recovery or production effect reconciliation. No heavyweight suite was started.

The subsequent [canonical-byte checkpoint](evidence/G2_ADMIN_JOURNAL_CANONICAL_2026-10-03.md)
requires the current and pending journal bytes to match the native writer's
serialization before they can pass a normal read or reviewed publication.
Twelve targeted Rust tests, one isolated software-TPM recovery invocation and
the offline native build passed. It preserves noncanonical state for review;
the installed Admin service and full recovery qualification remain open.

The [local-principal checkpoint](evidence/G2_LOCAL_PRINCIPALS_2026-10-01.md)
adds fresh-install principal IDs and binds the local PAM observation to the
installation, principal generation, and current account/credential state.
Missing, disabled, substituted or changed identities refuse authentication;
an invalidated observation cannot be revived by unlocking the account. This
is wired into installation and `admin-auth-check`, not a product Admin grant.
The registry is not TPM-anchored, and governed account lifecycle, enrollment,
delegation and recovery remain open. Nine targeted Rust tests, six real-PAM
fixture modes, two packaging checks and the native build passed. Full-image
testing remains deferred.

The first implementation-first increment adds a durable replay fence to the
existing root-only worker start/stop broker path, fresh-install journal
initialization, effect-time rechecks and bounded helper waiting. Uncertain
effects fence further worker mutations and are never automatically replayed.
It does **not** enroll Admin, protect the ledger against rollback, or provide
reviewed reconciliation. Its targeted checks and deferred integrated work are
recorded in [the broker-effects checkpoint](evidence/G2_BROKER_EFFECTS_2026-10-01.md).

The later [broker receipt-boundary checkpoint](evidence/G2_BROKER_RECEIPT_2026-10-03.md)
requires canonical effects-log bytes and replaces the local CLI's recyclable
process-ID request identifier with a fresh random one. Nine effects-log tests,
17 broker/service tests, two packaging checks, an isolated CLI/socket fixture
and the offline native build passed. The public CLI currently exposes only
`status`; other socket callers must still supply unique request IDs. This is
not TPM rollback protection, product Admin authorization or reviewed effect
reconciliation.

The [native workflow validation checkpoint](evidence/G2_NATIVE_WORKFLOW_VALIDATOR_2026-10-03.md)
adds a read-only Rust `workflow-validate` command and an image-overlay
file-to-artifact graph template. Four validator tests, a compiled-CLI template
check and the offline build passed. It admits only the graph's declared shape;
it does not verify signed skills, execute nodes, authorize effects, checkpoint
results or complete the file-to-artifact journey. Those G2 components remain
open for the consolidated candidate.

The [laboratory skill registry checkpoint](evidence/G2_SKILL_REGISTRY_2026-10-03.md)
adds a separate private lab signing key in the image builder, a signed closed
registry bound to the exact packaged workflow, and fixed-path native
`skill-registry-status` verification using sealed in-memory inputs. Three
registry tests, four DAG tests, two builder tests and an offline build passed
on a D-backed source snapshot. No image was rebuilt for this checkpoint.
Admission remains read-only and assumes
the eventual image's verity-protected root; it is not product Admin-governed
production signing, effect authorization or workflow execution.

The [native invoice calculation checkpoint](evidence/G2_NATIVE_INVOICE_CALCULATION_2026-10-03.md)
adds a bounded pure `invoice-calculate` stdin-to-JSON path using exact integer
cents and input-byte hashing. Five calculation tests, three signed-registry
regression tests, compiled-CLI positive and negative checks and an offline
build passed on a D-backed snapshot. The command is not wired into an
authorized DAG supervisor, file grant or artifact effect; no new OS image was
built for this checkpoint.

The [descriptor-scoped read checkpoint](evidence/G2_SCOPED_FILE_READ_2026-10-03.md)
adds a bounded native `openat` reader with no-symlink path traversal and
before/after file checks. Signed registry verification now uses it for the
image-owned workflow template. Two reader tests, three registry regressions,
five calculation regressions and an offline build passed on D-backed inputs.
It is not connected to principal-bound folder enrollment or effect-time
policy, and no new image was built.

The [native laboratory artifact checkpoint](evidence/G2_NATIVE_ARTIFACTS_2026-10-03.md)
adds installed-root invoice publication to a bounded private store, durable
content/receipt pairs, exact replay, integrity-checked reads and explicit
reviewed recovery. Complete preparations can be published; partial ones can
be moved intact into retained state, fencing request-ID reuse while allowing
a new request. Fresh-install setup is wired in source. Seven artifact tests,
14 calculation/registry/principal regressions, two builder checks, a compiled
CLI fixture and the offline native build passed. The fixture simulates the
installed boot marker and interruption states in a disposable container; it
does not boot an image. This laboratory prototype does not replace ADR-0003's
production SQLite/content-addressed storage, provide principal-bound grants,
activate product Admin or protect state against rollback. Those integrations
and the native supervisor remain open.

The later [native artifact catalog checkpoint](evidence/G2_ARTIFACT_CATALOG_2026-10-03.md)
implements ADR-0003 ordering in a separate ext4/SQLite WAL backend: immutable
domain-local content objects, logical artifact IDs, sequential versions,
compare-exchange and one transactional metadata/receipt commit. Exact retries,
orphan inspection and reviewed retention of partial bytes pass native tests.
Fresh-install initialization and the runtime package dependency are wired in
source; the earlier lab pair store is not automatically migrated. All 164
enabled Rust tests, both compiled CLI fixtures, two builder checks and the
offline build passed; 18 fixture-dependent tests were explicitly skipped.
The CLI injects abrupt process exits without destructors, not physical power
loss. The current interface remains installed-root/lab: product principal and
policy integration, generic/public-schema compatibility, trusted timestamps,
migration, receipted garbage collection and installed recovery qualification
are still open. No image was rebuilt for this checkpoint.

The [reviewed legacy import checkpoint](evidence/G2_ARTIFACT_IMPORT_2026-10-03.md)
adds an explicit copy of verified committed lab-pair invoices into the native
catalog. Review binds the complete source receipt; stable mapped IDs make
interrupted retries and lost acknowledgements repeatable without duplicates.
Both stores stay locked, source integrity and current signed-workflow admission
are rechecked, and original data/receipts remain untouched. Pending source
preparations require separate reviewed reconciliation. Import replay preserves
later destination versions. Twenty-three focused Rust tests, compiled CLI
checks, two builder checks, formatting and the offline build passed on D-backed
storage. This is not a schema/principal migration or installed-image evaluation;
the broader integrations above remain open.

The [native workflow checkpoint](evidence/G2_WORKFLOW_RUNS_2026-10-04.md)
adds a durable coordinator for the exact image-owned three-node invoice DAG.
It consumes an operator-stdin snapshot, checkpoints source reading and
calculation in SQLite WAL, commits Applying before catalog publication, then
records the exact artifact receipt. Explicit retry recovers uncertain
publication without duplicates; completed replay refuses missing receipts
after catalog rollback and preserves later artifact versions. Accepted
pre-publication cancellation persists, including after skill withdrawal.
Lost step/cancellation acknowledgements replay without advancing another node.
Forty focused Rust tests, compiled CLI checks with six abrupt-exit boundaries,
two builder checks, formatting and the offline build passed on D-backed storage.
Fresh-install initialization is wired in source; no new OS image was built.
Product Admin and folder/effect grants, generic scheduling, wider reconciliation,
trusted time and installed-image qualification remain open.

The [committed outcome acknowledgement checkpoint](evidence/G2_WORKFLOW_RECONCILIATION_2026-10-04.md)
adds explicit inspection and reviewed acknowledgement of an exact already
committed native catalog receipt. This root-only laboratory audit operation
can complete the saved Applying checkpoint after skill withdrawal without
publishing another artifact or restoring execution authority. Coordinator and
catalog ownership span the acknowledgement transaction; fresh installation
and catalog integrity are rechecked before commit. Missing, conflicting or
corrupt evidence remains uncertain. Forty-four focused Rust tests, compiled
CLI checks including both acknowledgement crash boundaries, two builder checks,
formatting and the offline build passed on D-backed storage. Broader
known-not-applied/conflict resolution, product policy and installed-image
qualification remain open; no new OS image was built.

The [model-response and WSL-impact checkpoint](evidence/G2_MODEL_REPLY_2026-10-01.md)
records a native CLI fix: replies must match the selected model and a single
completed assistant message, with finite integer token accounting within the
requested budget. Duplicate JSON, tool-call replies and malformed observations
are refused without a successful result. All **133 native Linux Python tests**
and six real CLI/HTTP cases passed; the HTTP server used synthetic responses,
not a real model. This guest-source change needs a later image rebuild and
real-model evaluation. Windows had about 2.2 GiB free and six unrelated
containers were active. The owner's conditional no-impact approval does not
authorize their interruption; WSL configuration and running workloads remain
unchanged. All component-level gaps below remain open.

The [host-memory checkpoint](evidence/G2_HOST_MEMORY_2026-10-01.md) records
successful media staging but an unsuccessful third desktop run. WSL had only
about 20 MiB available during the 6 GiB guest evaluation; its installer did not
reach disk confirmation. Only this disposable G2 container was stopped, with
all named volumes preserved. The queue exited 1 and no model VM started.
New shared VM admission requires guest RAM plus 2 GiB of observed host headroom
before stage state, TPM or QEMU startup. All **127 native Linux Python tests
passed**, and a real read-only host probe refused another 6 GiB launch. The
current 8 GiB WSL limit cannot meet this threshold. A larger approved test host
or a separately approved WSL memory/restart change is needed for this fixture.
This is not a desktop/model pass, a physical diagnosis or G2 closure.

The [Linux VM workspace checkpoint](evidence/G2_VM_LINUX_WORKSPACE_2026-10-01.md)
records a second desktop failure: snapshot admission passed at 6 GiB, but media
read/target write I/O errors stopped installation. No model VM followed.
Read-only checks did not identify a definitive cause. All 121 native Python
tests and a bounded QEMU I/O probe on the existing D-backed ext4 store passed.
The next test staged identical media in a fresh Linux workspace, retaining all
failed runs. Image transfer/read-back passed; the subsequent run stopped under
host memory pressure as recorded above. Desktop/model acceptance is not passed.

The [desktop memory-admission checkpoint](evidence/G2_DESKTOP_MEMORY_2026-10-01.md)
records an actual sequence-11 installation failure: the 4 GiB VM's live tmpfs
cannot hold the measured 2.25 GiB private artifact snapshot plus its reserve.
The failed run is preserved. The retry uses 6 GiB for installation and retains
4 GiB for installed greeter checks; the model suite remains conditional on a
passing desktop run. Source now adds explicit tmpfs RAM headroom admission and
capacity diagnostics. All 62 ordinary Rust tests, 115 native Linux Python tests
and 13 native Windows desktop-fixture tests passed. The retry subsequently
failed with I/O errors as recorded above; desktop acceptance is not complete.
This source repair also requires a later image rebuild.

The [bounded broker connection checkpoint](evidence/G2_BROKER_CONNECT_2026-10-01.md)
records commit `c0345fe` and the next client fix: a full Unix listen queue now
refuses admission instead of blocking before the IPC deadline. All 61 ordinary
Rust tests, 15 real CLI cases and 112 native Python tests passed. Sequence-11
artifact checksums and live readiness/refusal probes passed; its first desktop
installation subsequently failed as recorded above. No completed desktop/model
acceptance is claimed.
Both later broker client repairs require a new image build.

The [broker client and desktop export checkpoint](evidence/G2_BROKER_CLIENT_2026-10-01.md)
records the completed sequence-11 desktop image export on D:. The desktop
first acceptance attempt failed; a fresh virtual-installation retry and the
conditional 4B model suite are described above. Neither is yet a
pass. A later native client repair rejects denied, malformed or unrelated
broker replies instead of reporting CLI success; all 59 ordinary Rust tests,
14 real CLI cases and 112 native Python tests passed. Seven specialized Rust
tests were not rerun. That repair is **not in sequence 11** and requires a later
rebuild and image-level evaluation.

The [model-profile acceptance checkpoint](evidence/G2_MODEL_PROFILE_ACCEPTANCE_2026-10-01.md)
adds explicit fresh-install 4B/1.7B evaluation profiles and binds recovery to
the actual selected model. Corruption checks now require fresh journal-cursor
evidence, not old errors. All 112 native Python tests passed. The desktop build
subsequently completed verified export; desktop acceptance and then the bounded
4B installer/inference suite remain serialized as described above.
Neither is yet a pass, and 1.7B does not replace required 4B qualification.

The [installed-desktop acceptance checkpoint](evidence/G2_DESKTOP_ACCEPTANCE_2026-10-01.md)
adds exact-image verification, a three-stage installed Wayland/GDM-greeter
fixture, software-only virtual display and bounded screenshot evidence.
All 106 native Python tests and a real QMP transport probe passed; that probe
did not boot an OS. Desktop packaging/export subsequently completed on D:.
The frozen greeter evaluation requires successful artifact checksums before
starting its VM. It is not yet an installed-desktop pass and does
not cover graphical password login, locking or the full manual workflow.

The [2026-10-01 acceptance checkpoint](evidence/G2_ACCEPTANCE_RESUME_2026-10-01.md)
adds a whole-request inference deadline, explicit bounded emulation options,
failure diagnostics and real poweroff requirements for the remaining follow-up
VM suites. All 93 native Python tests and 55 ordinary Rust tests passed; the
seven specialized Rust functions also passed in separate PAM/software-TPM and
real disk-full export fixtures. Sequence-10 image regression subsequently
**passed all 14 stages**, including eight strict normal shutdowns, atomic
recovery export and installed slow-frame IPC probes, on a fresh D: virtual
disk. Its public evidence is exported beside the image. The first candidate
desktop build failed before assembly due to moving bootstrap OpenSSL packages
conflicting with the pinned snapshot. Both builders now isolate and pin the
CA bootstrap; a real package-install probe passed and a fresh D: desktop build
is running. See [the build/evaluation checkpoint](evidence/G2_BUILD_SNAPSHOT_2026-10-01.md).
The earlier inference failure is not resolved merely by changing its budget.

Earlier image-specific result: sequence 9 passed its four-stage manual install,
installed PAM, measured-credential, cold-reboot, signed A/B continuity and
unapproved-PCR refusal fixture under TCG/Secure Boot/software TPM. Evidence is
exported with the image; see [the sequence-9 checkpoint](evidence/TEST_IMAGE_SEQUENCE9_2026-09-30.md).
Its fresh retry also passed verified late filesystem/DM teardown in every
stage. The initial `/var` unmount warning remains before the initrd completes
cleanup; this is not warning-free or physical shutdown qualification. The
broader 14-stage recovery regression also passed, with eight strict normal
poweroff stages. The resumed model fixture installed the model but subsequently
failed its inference request with a timeout; it is not a model-suite pass.
Full Admin enrollment and
the other software components below remain open.
The [shutdown checkpoint](evidence/NATIVE_SHUTDOWN_2026-09-30.md) records the
repair, source tests and queued strict/broader VM suites; pending tests are not
passes and neither suite closes all G2 requirements.

The native recovery exporter now publishes a completed archive only after
successful tar output and synchronization, retaining failures under `.partial`
without overwriting existing data. Actual Linux producer/ENOSPC tests passed;
this later source repair is **not in sequence 9**. It is in sequence 10, whose
image-level recovery evaluation now passed. See [the export checkpoint](evidence/NATIVE_RECOVERY_EXPORT_2026-09-30.md)
for the earlier source work and the current build/evaluation checkpoint above.

Sequence 10 finished assembly with that exporter and a tested monotonic
whole-frame broker I/O deadline. Its shell driver failed before export after
an in-flight source edit; the retained artifacts passed all checksum checks
and verified export completed without rebuilding. Its test queue stopped when
sequence-9 model inference failed, before sequence-10 guest acceptance started.
That initial queue stop was superseded by the fresh passing regression above;
it does not resolve the model inference failure. See the historical
[build-resumption checkpoint](evidence/NATIVE_BUILD_RESUME_2026-09-30.md).

The candidate desktop now packages GNOME/Wayland, with password-required GDM
restricted to installed boots and no model-service login dependency. A real
isolated software-rendered compositor and Files, Text Editor and Console
passed an unprivileged window/surface smoke test; all 60 native Python tests
passed. This is not installed-image/GDM/session-lifecycle acceptance. The new
desktop is not in the exported sequence-10 headless image. See
[the desktop checkpoint](evidence/NATIVE_WAYLAND_2026-09-30.md).

The C:-backed build-storage limitation is now addressed by a verified dedicated
D:-backed Docker/containerd profile. The code checkout stays on C:, while the
new host profile places bulk build storage and client temporary files on D:
and retains D: image/installer output. A real Docker build, filesystem semantics,
stop/unmount/remount persistence, missing-store refusal and all 75 native Python
tests passed. This is host-storage acceptance, not a new G2 OS-image pass. See
[the setup evidence](evidence/NATIVE_D_BUILD_HOST_2026-09-30.md) and
[operation instructions](host/README.md).

| Component | Implemented/evaluated scope | Remaining work before software completion |
| --- | --- | --- |
| Installer and media | Real laboratory-signed Ubuntu 24.04 image; explicit disk consent, LUKS2, independent credentials, install-time manual/4B/1.7B choice, pinned download; sequence 8 passed pre-write TPM admission, pending enrollment intent and manual installation on a fresh virtual disk | Sealed Admin enrollment and authenticated bootstrap, governed production catalog/pack and offline distribution, full rejection/interruption matrix; rerun actual model acquisition on the new image |
| Boot, update, recovery | Signed UKI, A/B verity roots, essential-health acknowledgement, three-attempt fallback, independent export/repair/disable; sequence 9 passed measured phases, public credential continuity through reboot/signed B, unapproved-PCR refusal and verified late shutdown teardown; sequence 10 passed the 14-stage regression including atomic export and bounded IPC | Complete confined service credential delivery and lifecycle; broaden shutdown/recovery faults; complete interruption and migration matrix, including pre-userspace failures; protected production rollback anchors; storage-pressure and recovery-retention cases |
| Temporary storage | Locked, bounded snapshot/download reconciliation; sparse-aware admission and exact-file cleanup; Linux boundary tests in `native/tests`; sequence 8 verified successful startup maintenance service execution | Repeated guest-interruption/pressure evaluation; operator-reviewed disposition of legacy snapshots, which cannot safely be assumed inactive |
| Model lifecycle and resources | Two pinned CPU profiles; hardware and cgroup-v2 limit admission, isolated UID, authenticated loopback runtime, systemd memory/device/process restrictions; source-only pre-stop verified acquisition and exact service-state guard, guarded unchanged-prior restart after failed stop or activation, interrupted-activation fence, reviewed clearance, narrow reviewed partial-candidate roll-forward, private prior preservation/restoration and one-step reviewed completed-activation configuration undo, bounded listener check and observed restart/check-failure quarantine with explicit clearance and reviewed private retention of incomplete records, packaged quarantine startup refusal, a durable controller-bound validation trial before publication with reviewed abandoned/EOF-incomplete trial retention under exclusive recovery locking, owned-child polling supervision with handle-bound teardown/parent-death registration and explicit older-image migration; actual inference and offline reboot passed on an earlier image | Full governed model-pack/catalog lifecycle; unsupported/malformed-state recovery and broader event/crash/boot/migration/post-stop failure policy, installed reconfiguration/restoration/roll-forward/quarantine/trial-recovery/supervision qualification, atomic resource leases and generations, stale or hostile descendant containment, pressure/OOM policy, broader quarantine/restart and governed retention lifecycle; evaluate the changed binary on a new image and run 1,000 **real compact-model** cycles with measured resource return and performance distributions |
| Admin, policy, and effects | Frozen Python contracts and negative tests; local TPM2 checkpoint/journal and signed-PCR sealing; native PAM with installation-scoped principal/generation and credential revalidation; source-only explicit bootstrap, finite catalog definitions and local kernel-peer-bound catalog service/client with packaged confinement; durable replay fence for two laboratory root-only worker effects | Qualify installed enrollment/bootstrap/service enforcement and complete trusted-time finite assignment/revocation, governed principal/account lifecycle, effect-time grants, protected production effect receipts and reviewed reconciliation; the catalog service is not the complete Admin/policy lifecycle |
| Skills and vertical workflow | Reference/manual interface; native typed-DAG validation, lab admission/calculation/scoped reads; lab pair store; native ADR-0003 WAL/content-object catalog with versions, transactional receipts, replay/retention and reviewed lab-pair import; native WAL coordinator for the exact invoice graph adds snapshot/checkpoints, pre-effect cancellation, explicit catalog-backed restart/replay and reviewed acknowledgement of exact past commits after withdrawal | Product signing/revocation, production coordinator and principal-bound folder/effect grants, generic artifact/public-schema and trusted-time integration, broader schema/reference/principal migration, receipted retention/GC and effect-time policy, wider cancellation/reconciliation and scheduling; distributed-image journey |
| Generated-code isolation | General model-generated shell/native execution is denied | Required microVM or separately qualified constrained runtime and adversarial tests before this capability can be available; a deny-only path is not an implemented execution sandbox |
| Desktop and account lifecycle | Headless console/manual recovery and installer-created distinct accounts; candidate GNOME/Wayland packaging and signed boot-target selection; isolated real compositor/Files/editor/terminal surface smoke passed without a model | Build and boot the desktop image; actual GDM authentication, complete manual file workflow, locking, credential/account lifecycle, migration and model-failure tests; container surface tests do not qualify the installed desktop |
| Trust and custody integration | Lab release key, signed image bytes, image-owned lab model catalog, reference trust/checkpoint contracts; owner selected local TPM2-backed Admin for current installer | Integrate local TPM2 enrollment, authenticated writer identity, trusted UTC, isolated secrets, key rotation/revocation/recovery and reviewed reconciliation; production signatures require approved real custody; external deployment is a future installer variant |
| Acceptance automation | Reference suites, native source tests, six selected image-specific VM runners | Traceable coverage of every applicable G2 test, fault and performance requirement, not only the existing happy paths and selected negative cases |

The snapshot 1,000-cycle test is **not** the compact-model lifecycle test.
Successful download/inference is **not** signed production pack admission.
Container mount/ENOSPC tests are **not** image boot or physical power-loss tests.

## Execution order

1. Close native storage crash-safety defects and retain executable negative
   tests; integrate startup maintenance without making model availability a
   boot-health dependency. Rebuild/retest before distributing changed binaries.
2. Integrate finite Admin/policy and durable effects with the closed native
   service surface, then the signed skills and local-file-to-artifact journey.
   Reuse the frozen contracts as test oracles, not as a claim that an injected
   Python adapter is already the production Rust implementation.
3. Integrate the complete model lifecycle/resource service and execute actual
   compact-model restart/cancellation/pressure/cleanup measurements. Keep GPU
   and larger configurations unavailable until their checks and evidence exist.
4. Implement and test the Wayland/manual desktop and account lifecycle, then
   complete the boot/update/migration/security fault matrix against rebuilt
   distributed images on virtual disks.
5. Integrate the selected production trust/checkpoint design and public custody
   inputs. Never put production private keys, HMAC secrets, or recovery secrets
   in source, images, chat, logs, or test fixtures.

This is a work inventory, not an authorization to erase a physical disk, enroll
firmware, issue production signatures, or silently change the architecture.

## Closed deployment decision and remaining external inputs

The owner selected **local TPM2-backed Admin/checkpoints** for the current
installer. An external protected service is deferred to a **future installer
variant**, not a fallback. See [the local TPM2 implementation note](LOCAL_TPM2_ADMIN.md)
for implemented boundaries and outstanding software integration. Define and
implement identity enrollment/recovery, trusted time, deployment namespaces,
checkpoint reconciliation and custody operators for that choice. TPM-backed
anchoring does not replace the required production
signing custody or distinct approval roles. Development fixtures can exercise
failure semantics but must remain explicitly non-production.

Separately provide the approved production public catalog/trust inputs,
redistribution approval, independently recoverable signing process and named
approvers/custodian. These are not "physical verification only" blockers.

## Physical qualification retained separately

The two named boards, firmware trust/enrollment, TPM-loss behavior, real GPU
and larger-model tuples, actual power cuts, damaged-media recovery and device/
suspend/resume behavior require approved native hardware. Exact destructive
targets and recovery/firmware approvals are still required. See
`docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md` and
`native/evidence/TEST_IMAGE_2026-09-28.md`.

## Build history (superseded states retained for traceability)

The paragraphs below describe checkpoints at the time they were recorded.
Use the latest result and inventory at the top for current status: the C: space
blocker and sequence-6/7 failures were subsequently addressed, and sequence 8
completed its scoped fixture. Historical pending text is not a current pass.

The sequence-5 image was built and exported on 2026-09-29 after the owner
reported D: repaired. It includes the later TPM admission, signed-PCR and PAM
changes, but installation evaluation failed; see the
[image checkpoint](evidence/TEST_IMAGE_2026-09-29.md). The initial KVM attempt
failed in QEMU before reaching the live console. TCG boot passed Secure Boot,
verity and AppArmor checks, then exposed a three-second live-payload device
timeout before installation. A live-only, bounded mount fix passed targeted
Linux tests and a sequence-6 rebuild was started. Installed PAM/PCR acceptance
remains unexecuted. Neither image is the final all-components G2 image.

Sequence 6 subsequently completed verified export and passed the live mount
checks. Installation was refused by the native root-owned TPM-device check:
the packaged udev rules instead assign devices to `tss`. An image/initrd
root-only rule and more specific VM assertions passed the full native regression
suite (42 ordinary Rust tests, 20 TPM/6 PAM invocations and 27 Linux Python
tests). Rebuilding is blocked by C: free space below the 8 GiB build minimum;
see the
[sequence-6 checkpoint](evidence/TEST_IMAGE_SEQUENCE6_2026-09-29.md). No
installed-image PAM, credential continuity or all-components G2 pass is claimed.

The owner subsequently freed C: space; sequence 7 (`20260929T194815Z-headless`)
passed the space preflight and is rebuilding with the tested TPM ownership
repair. Export and boot-test results are pending. No prior-image acceptance
is inherited and no G2 requirement is closed merely by starting this build.

Sequence 7 was subsequently rejected by its initrd guard: the rule-copy helper
looked on the build host instead of the target sysroot. The corrected module
passed a read-only retained-root regression. Sequence 8 is building and has
passed the full-kernel initrd guard; a fresh VM run is gated on successful
export. See [the sysroot checkpoint](evidence/NATIVE_INITRD_SYSROOT_2026-09-29.md).

The previously exported sequence-4 image remains unchanged. Its evidence
cannot be reused as acceptance evidence for subsequent source-only fixes.
The new storage implementation's executed scope and outstanding image tests
are recorded in [the storage checkpoint](evidence/NATIVE_STORAGE_STATUS_2026-09-28.md).
The new TPM adapter/journal is likewise source-level software-TPM evidence,
not an installed Admin service or physical qualification; see
[the TPM checkpoint](evidence/NATIVE_TPM_STATUS_2026-09-28.md).
The subsequent [TPM admission checkpoint](evidence/NATIVE_TPM_ADMISSION_2026-09-28.md)
adds read-only installer checks and a persistent QEMU software-TPM fixture.
Its source tests do not establish installed/enrolled Admin or image acceptance.
The [sealed credential checkpoint](evidence/NATIVE_TPM_SEALING_2026-09-29.md)
adds tested fixed-PCR7/signed-PCR11 secret handling, including approved measured
updates without resealing and rejection of replacement TPMs. Authenticated
enrollment, signer lifecycle, service confinement and image integration remain
software work; this primitive does not activate product Admin.
The subsequent [UKI policy checkpoint](evidence/NATIVE_UKI_POLICY_2026-09-29.md)
adds installed A/B PCR signatures to the image builder and verifies artifact
measurements against software-TPM event replay, including A/B credential
continuity. It is not firmware/guest-boot evidence or complete enrollment.
The [account authentication checkpoint](evidence/NATIVE_ADMIN_AUTH_2026-09-29.md)
adds a root-invoked, non-setuid PAM helper and controlling-terminal diagnostic.
It authenticates an account but neither enrolls it nor assigns the product Admin
role. No all-components final image or G2 pass is established by these tests.
