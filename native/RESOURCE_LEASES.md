# Native resource leases and generations

Updated 2026-10-08. Requirement #1 remains open until its remaining integrations
and the applicable installed-image qualification pass. This implementation is
not a claim that all G2 resources, inference clients or hardware are qualified.
Requirement #2 has not been started by this work.

## Implemented native boundary

The existing root broker owns `/var/lib/luma-broker/resources`. No model or
reference worker reads or writes that private directory. The existing
`/run/luma-broker/control.sock` is the only transport: bounded four-byte
big-endian framed JSON, strict request/response envelopes and kernel peer
credentials. A socket-specific POSIX ACL admits root, UID 989 and UID 990
without adding the model worker to the control database's group. UID 990 gains
only the bounded reference gateway methods described below, not physical
acquisition, renewal, controller or history-maintenance authority. UID 989 gains
acquisition and renewal of its own fixed, selected CPU worker and gateway
dispatch restricted to that exact lease-owning supervisor. Root acquisition is accepted only from the fixed,
enforcing acquisition unit. Both worker kinds now require their exact enforcing
AppArmor label, no-new-privileges, seccomp filter mode and current fixed capability
sets, not merely a matching UID and cgroup. Unsupported ACL or peer-PID-handle support refuses
without a weaker fallback.

Sixteen bounded transport threads have separate UID quotas: eight root,
four model and four reference connections. Their only tasks are framing and
reply delivery. Partial frames and blocked readers do not hold the resource
coordinator. One independent legacy effect helper can wait for systemd without
blocking resource maintenance or renewals; additional effects refuse while it
is busy. The resource ledger and controller still have one coordinator/writer.

The broker pins the connecting process using `SO_PEERPIDFD`, its boot/start
generation and the cgroup device/inode. Requests cannot supply a PID, cgroup,
capacity, allocation credit, arbitrary domain or controller command. Model profiles
come from the root-owned pinned image catalog. The closed invoice calculation
uses the fixed compiled contract described below, not a caller-supplied budget.
Serving must match the installed
selection and lifecycle fences; acquisition can prepare another pinned profile
before a selected worker is stopped. Acquisition additionally binds the physical
IO-controller device resolved from the trusted target's kernel storage topology.

Current real, effective, saved and filesystem UIDs must all equal the authenticated
peer UID. Peer observation binds the PID handle's kernel-reported target to the
connecting PID and rechecks start time, credentials and liveness around reads.
Resource dispatch, history maintenance/export and inference acknowledgements
recheck that proof. A live caller that drops any of those UIDs loses request
authority; periodic request maintenance fences its serving generation just as
for caller death. Observation failure never substitutes another process or
revives a stored PID.

Serving owners require zero permitted, effective, bounding, inheritable and
ambient capabilities. The root acquisition supervisor requires exactly
`CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` in its permitted/effective/bounding
sets, with empty inheritable/ambient sets. Both plans require `NoNewPrivs: 1`,
`Seccomp: 2`, their fixed cgroup and zero soft/hard locked-memory limits across
repeated bounded observations. An absent, changed, malformed or duplicate
security field refuses admission/renewal; ongoing enforcement loss uses the
existing durable revoke and whole-group drain path without returning capacity
early. Filter-mode observation does not attest the exact seccomp program or
replace installed AppArmor/cgroup/filter qualification. These are root laboratory
interfaces, not product Admin authorization or an atomic credential-transition
claim.

The native ledger implements checked unsigned 64-bit accounting, atomic
multi-domain admission, loading/serving peak reservation, exact replay,
monotonically increasing lease generations, manager epochs, expiry/revocation,
pressure hysteresis, whole-lease quarantine and reviewed reconciliation.
All 64-bit contract values are canonical decimal JSON strings; numeric JSON,
overflow and noncanonical strings refuse. Whole-worker peak reservation is
never reduced because a worker reports readiness or exit.

Root preflight, activation, rollback and recovery verification now dispatch to
the same contained acquisition service, using only exact catalog paths under
the installed data mount or the live installer's private target. No unleased
production hashing fallback remains. A successful preflight still does not
reserve future serving capacity or change the selected model; cached hashing
uses a temporary acquisition lease and waits for its observed drainage.

Current native profiles use one CPU worker in `lumamodel.slice`, with a
`luma-model.service` leaf. The broker verifies cgroup-v2 identity, whole-slice
and leaf memory limits, zero swap, CPU/IO/PID ceilings, grouped OOM handling
and zero locked-memory allowance. The runtime has no accelerator access. Its
command explicitly uses CPU-only F16 K/V caches, one non-unified slot,
memory-mapped weights without repacking, 256-token logical and 128-token physical
batches, and two HTTP threads. Prompt cache RAM, idle-slot caching, prompt reuse
and context checkpoints are disabled. These fixed settings eliminate extra
default cache/copy budgets. The verified model-layout inventory described below
now checks the CPU KV allocation. The installed-root operator path has the
request admission described below; other inference consumers remain open.
The host reserve is the larger of one GiB and 20 percent of reported RAM;
physical loading checks supplement, rather than replace, kernel ceilings.
Qwen3-4B now requires at least 6.1 billion RAM bytes and 4,831,838,208 available
bytes; Qwen3-1.7B requires four billion RAM bytes and 2,684,354,560 available
bytes. These are admission policies, not measured performance certificates.

The model obtains a lease before hashing/loading weights. A separate heartbeat
renews every two seconds during loading; supervision also checks the exact
token before and during runtime execution. Leases last ten seconds using
`CLOCK_BOOTTIME`, not civil UTC. Renewal failure or thread failure fences
execution. Conservative local deadlines also fence hashing and download polls
if an RPC stalls; once detected, lease loss stays latched even if an old renewal
eventually returns. Dropping the heartbeat stops renewal but sends no release
claim.

Model acquisition now uses pinned direct-child supervision rather than a raw
`try_wait` loop. Credential dropping to UID/GID 988 and the catalog byte ceiling
precede parent-death `SIGKILL` registration. A checked `CLOCK_BOOTTIME` deadline
and output metadata fence run during download; observation failures terminate
and reap through the owned PID handle. There is no saved-PID fallback. Failure
to obtain a handle remains uncertain, not a cleanup proof. Temporary cleanup
requires the originally created inode, safe metadata and an independent
exclusive lock on the inherited writer description. Busy, substituted or
uncreated paths remain intact for the existing fenced orphan reconciliation.
Production preparation now runs in a separate fixed transient
`luma-acquisition.service` in `lumaacquisition.slice`: 512 MiB memory, no swap,
16 processes, two CPU cores, 64 MiB/s storage IO, zero locked memory and a finite
3,700-second lifetime. The helper obtains a broker lease before download or
hashing. Its AppArmor policy cannot access the private broker database. Targets
are limited to installed `/var` or the live installer's private encrypted data
mount, with trusted ancestors. A live-only oneshot explicitly initializes the
volatile ledger once; a broker restart never initializes or clears it.

Serving and acquisition share physical host-memory accounting and an 80-process
aggregate quota, but have distinct execution slots. An acquisition OOM fences
that slot without automatically quarantining serving; critical host pressure
still fences both. Each group's retained cache is counted once. The controller
waits for broker-observed emptiness, completed generation drainage and bounded
residual charges before and after an acquisition, rather than treating the
systemd controller's exit as an allocation receipt. Idle acquisition cache is
reclaimed from fresh kernel observations before handoff.

Systemd throttles the originating whole disk, not a LUKS mapper or partition.
The broker resolves the supported encrypted ext4/simple-disk chain through
bounded read-only sysfs observations. Missing, cyclic, multi-slave, non-crypt
mapper or otherwise unsupported topology refuses. No device access or weaker
IO limit fallback is introduced. Root activation, preflight and recovery
verification use the contained preparation worker in source; the actual installed
handoff still requires qualification.

The closed installed-root invoice coordinator now shares this helper pool with
model acquisition and verification. Invoice work reserves the same 512-MiB,
16-process peak and single execution slot; it cannot overlap another helper
generation or alter the aggregate inventory. Its transient unit has a
30-second lifetime, a 4-MiB file-output limit, Unix-only address families and
no model-directory write exception. Artifact publication remains in the
trusted coordinator, outside this helper. The current root helper does not
implement product principals, source-folder grants or generic DAG execution.

Invoice admission binds a canonical source digest, the exact compiled graph,
current installation and physical storage device. The helper acquires its
lease before reading a sealed anonymous input descriptor and rejects pipes,
unsealed or changed input. Output is captured in a bounded anonymous descriptor,
sealed after observed drainage, and accepted only after its exact digest and
token match a durable broker receipt. New calculated workflow checkpoints
retain the token. Preparation replay starts no additional worker. Calculation
failure leaves the current checkpoint intact; applying/completed reconciliation
uses the same calculation boundary without a production fallback.

The standalone installed `invoice-calculate` command also uses this boundary.
It requires installed root before reading bounded stdin, launches the confined
helper, and rechecks the result generation before writing any report to stdout.
It has no in-process pure-calculation fallback. The reusable pure function remains
internal to the leased helper and explicitly synthetic unit/store tests. The
disposable CLI fixture obtains comparison reports only from its separate Rust
test executable; native missing-resource and non-root invocations publish no
bytes. This command still grants no source-folder or artifact-write authority.

`resource-output-complete` accepts only the exact confined, lease-owning root
invoice helper, with its token and output digest in the `review` field. It
persists `output_sha256` and `output_domain_epochs` from the broker's current
inventory, not worker-supplied epochs. The complete snapshot names exactly every
reserved domain, uses lossless canonical decimal strings, and is immutable on
exact completion retry. This changes no deadline, reservation or physical state.
`resource-output-receipt` is a read-only root method on the same socket.
It rejects missing, expired, cancelled, quarantined, uncertain-owner or stale
manager results. A persistent `output_fenced` flag prevents drainage or archive
from rehabilitating a rejected result. Only a signalled original process
handle counts as normal owner exit; missing handles and observation errors
fence the result. `physical_release_granted` is always false in result replies.
Only the existing cgroup observations can return physical capacity. Result
retrieval also requires the original domain epochs to match current authority.
The invoice client accepts exactly the three compiled helper-plan domains and
refuses missing, unknown, zero, numeric or noncanonical epoch values.

Revocation and domain quarantine now fence outputs even when physical drainage
has already marked the lease Released. Reviewed quarantine clearing advances
all domain epochs and fences existing results; broker restart and inventory
migration likewise preserve result fences in every physical state. None of
these operations rewrites the output's original epoch snapshot or restores
publication authority. Remaining cache charges, generation floors and physical
cleanup receipts are preserved. Normal owner exit cannot clear an existing
fence. This does not add principal/effect grants or TPM rollback protection.

Absent result/token/epoch fields remain omitted, preserving canonical older ledgers,
archives and workflow checkpoint bytes. Older checkpoints do not acquire
fabricated provenance; current publication/reconciliation revalidates their
reports through the leased helper. Older completed results with no domain
snapshot remain readable/reviewable/archiveable history but cannot authorize
current publication. Completion replay cannot stamp today's epochs onto old
output: a new worker generation must recompute the source. Already committed
artifact acknowledgements remain read-only and do not need a revived worker.
Broker, helper and coordinator require a
coordinated image upgrade: older strict readers cannot consume the new result
fields and must refuse rather than reset state or fall back to unleased work.
Installed service, AppArmor descriptor rules, upgrade and recovery qualification
remain required. The tools fixture now verifies missing-resource refusal;
calculator-injected unit tests do not qualify actual installed containment.

Both direct invoice publisher commands now use that same leased helper, rather
than in-process calculation. Signed workflow/installation authorization and the
current broker output receipt are rechecked before the legacy-pair rename or
catalog WAL commit. The coordinator also checks the calculation generation
before storing a calculated checkpoint, at the artifact boundary and before its
completion checkpoint. A fence after artifact commit leaves Applying intact;
only reviewed proof of the committed outcome can acknowledge it without another
effect. A saved checkpoint token alone cannot authorize publication.

New direct-publisher receipts retain `resource_lease`. Exact retries recompute
under a fresh lease but preserve the original receipt's historical token; the
response's `calculation_lease` describes this invocation, not a mutation of the
original provenance. Old canonical receipts omit the optional field, remain
readable and never acquire fabricated history. Reviewed copy import preserves
any existing source token and does not turn it into live worker authority.

`artifact-reconcile` can acknowledge an already committed pair without a live
calculation grant. Publishing a pending pair requires its recorded token, bound
report digest, installation/storage identity and current unfenced broker receipt.
Missing legacy provenance, an archived/unavailable receipt or a changed manager
epoch refuses publication even with operator review. Inspect
`artifact-store-status`, retain the pair using its exact abort review, and
resubmit the original CSV under a new request with the broker available. The
retained bytes and original receipts are not deleted or rewritten.

The disposable CLI fixture uses the shipped binary to verify absent-resource
refusal, reads, retention and legacy-copy recovery. Successful publication and
abrupt storage-crash tests use an explicitly marked, separate Rust unit-test
executable with synthetic calculation/checks. That fixture is compiled only
under `cfg(test)`; there is no test selector or calculator fallback in the
installed executable. These tests cover storage/effect fencing, not installed
systemd, AppArmor or real broker-to-worker qualification.

Cancellation, expiry, lost owners, broker restart and quarantine leave all
reservations charged until the broker fences the fixed cgroup and observes
empty descendants. Surviving file-cache charges remain explicit. Verified
same-cgroup cache can transfer into a new whole-worker peak once, rather than
being counted twice. A replacement cgroup in the same boot cannot prove old
allocation drainage; the old reservation remains held. A new kernel boot
provides a new epoch for these CPU-only volatile allocations, not for future
device allocations.

Under pressure, admission stops. Only an empty, unleased worker group is
eligible for bounded idle reclaim. A successful `memory.reclaim` write or
`EAGAIN` does not return bytes: a fresh `memory.current` observation controls
the retained charge. Critical host pressure or observed worker OOM quarantines
the domain and drains affected work. Suspend stops the model unit before sleep;
subsequent model execution must obtain a fresh lease.

## Operator inference admission

The installed `sudo luma-platform model-chat` helper uses the existing broker socket for
`resource-inference` inspection, begin, admission, completion and cancellation.
Only a live root peer is accepted. This is a laboratory maintenance path for
untrusted text, not a product Admin grant or permission to execute model output.
The broker pins the caller process generation and the exact active serving
lease. A request cannot select a different worker, enlarge the catalog context,
or report physical cleanup.
The native CLI replaces itself with the fixed helper, preserving that process
generation instead of leaving an unsupervised child after caller cancellation.

The `resource-inference` method now uses wire schema version 2. Its preparing
receipt binds a mandatory lowercase SHA-256 digest of the exact original prompt
bytes, computed as `SHA256(UTF8("luma-native-operator-prompt-v1") || 0x00 || prompt)`.
Whitespace and UTF-8 bytes are not normalized. The fixed template transformation
occurs afterwards. Every subsequent receipt must contain that same input digest,
in addition to the nonce, caller generation, worker, profile, context, maximum
output and deadline. Preparing/admitted replay with changed input refuses before
mutation; the helper cancels on a substituted binding and publishes no result.
The digest does not grant effects or prove semantic correctness of model text.

Upgrade the broker, native command and packaged helper together. Version-1
inference requests/replies refuse; there is no downgrade or implicit unbound
admission. Other resource/transport methods retain their existing version 1.
The durable journal remains version 1 with an optional input-digest field so that
genuine older canonical receipts/archive bytes and their SHA-256 references remain
readable without rewriting. Missing old digests are reported as unavailable,
not fabricated. They cannot resume via begin/admit/finish or be relabeled by
replay. Restart fences outstanding old requests without reconstructing their
caller handles or returning physical capacity. Terminal old receipts can still
be archived, and their retired nonces remain fenced. Request-history status
reports separate bound and legacy-unbound hot inventories.

One logical slot is reserved before template rendering or tokenization. The
helper renders the pinned model template without reasoning, tokenizes that exact
prompt, and checks the actual token count plus the requested maximum output
against the 2,048-token context. The broker accepts a digest of the exact token
array; completion receives that array instead of messages or a re-tokenized
string. Output is limited to 1..128 requested tokens. Counts, result identity,
stop/truncation state and runtime timing counters are validated before the
broker acknowledges completion and the helper publishes text. The whole worker
peak already includes its KV tensors; request admission does not charge those
physical bytes again.

The helper disables prompt reuse, proxy lookup and redirects. Both broker frames
and runtime responses have finite byte and whole-operation time bounds. For
b11100, `tokens_cached` is final slot occupancy, not the reused prompt count;
the helper checks bounded occupancy and `timings.cache_n == 0`. The pinned
runtime can exceed `n_predict` slightly when finishing partial UTF-8: an actual
count above the admitted output budget is refused and cancels the generation,
not certified as successful bounded output. These contracts follow the pinned
[completion serializer](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/tools/server/server-task.cpp),
[slot accounting](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/tools/server/server-context.cpp)
and [runtime API](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/tools/server/README.md).

Preparing, admitted and uncertain requests retain the slot. Cancellation,
expiry or caller death durably revokes the physical worker generation; only
trusted cgroup drainage returns its capacity. A failed cancellation reply is
not cleanup proof. Exact completion releases only the logical request slot,
never the worker lease. Nonce, owner, worker, token and result replay drift
refuse. A lost completion acknowledgement does not publish a success object.

The broker durably retains at most 256 hot request receipts under the same
private resource-store exclusion. Every successful request acknowledgement
follows synchronized publication or an exact synchronized retry. Counts use
canonical decimal strings; history contains identities, phases, counts and
digests, never prompt or response text. Only outstanding requests retain a
caller PID handle. Restart loads the receipts but never reconstructs a live
process handle from a saved PID: an outstanding request stays fenced until its
physical generation is released. Missing, damaged, noncanonical or externally
changed history is not reset. An uncertain publication poisons admission.

Installed-root `resource-request-status` reports an archival review bound to
the current request history and physical manager epoch. With no preparing,
admitted or draining request, `resource-request-archive REVIEW-SHA256` publishes
the exact terminal receipts without replacement, synchronizes the archive,
then durably cuts the hot inventory. It does not stop a serving worker, change
its physical lease, return capacity or delete history. Retired nonces are
reconstructed from the validated archive chain and cannot be admitted again.
There are at most 64 referenced archives, 128 retained archive/stage/incident files,
1 MiB per journal/archive, and 512 entries per directory inspection. Limits
refuse rather than evict. Status reports logical archival eligibility, not a
guarantee that storage inspection or publication will succeed. Complete orphan archives and interrupted private
stages remain retained; neither proves that a hot cut completed.

Installed-root `resource-request-export BATCH SHA256` exports only an exact
referenced immutable request archive. The existing broker socket returns closed
JSON chunks of at most 2,048 ASCII bytes, with lossless offsets, total length and
archive identity. Each chunk requires a live authenticated root peer and a
current deadline. The client limits the complete operation to 30 seconds,
512 chunks and 1 MiB, checks every correlation/offset/length and verifies the
complete SHA-256 before writing any archive bytes to stdout. It never exports
mutable hot history, arbitrary paths or unreferenced publications. Output is
unsigned laboratory evidence; it does not implement production signing custody,
tenant disclosure policy or deletion authority.

After an incomplete archive stage causes refusal, preserve the files and restart
the broker so that it reloads durable authority. Drain and release all physical
generations using their normal trusted controller paths. With both worker groups
empty, run `sudo luma-platform resource-request-recovery-status`. Only if it
reports `recoverable: true`, review the named stage, byte length and digest, then
run `sudo luma-platform resource-request-recover REVIEW-SHA256`. The review binds
the physical ledger, current journal, exact candidate name and stage content,
inode and timestamps. This operation moves only the incomplete stage for the
current archive candidate, without replacement, to a retained incident name in
the same private directory and synchronizes the directory. The live peer,
deadline, empty worker groups and their current cgroup identities are rechecked
immediately before and after preservation. Its inode and bytes,
hot receipts, archive references, nonce fences and physical accounting remain
intact. Complete stages use normal exact archival retry, never this recovery.

Unsafe links/modes, a stale review, changed bytes/inode, outstanding requests or
physical generations, populated worker groups and uncertain publication refuse.
A lost preservation acknowledgement poisons the session: restart and inspect
the durable result rather than deleting or automatically retrying anything.
Retained incidents count against the same finite file inventory and are checked
at startup. Recovery does not reclaim a retention slot, start workers or repair
a damaged hot journal, older unrelated stages or a broken archive chain. Those
broader recovery and product governance integrations remain open.

These are durable laboratory receipts and reviewed archival, not complete
product retention governance, export/deletion custody or a tenant gateway.
The reference service now has an explicit broker transport, described next.
Fresh activation now rotates its private runtime key and provisions the native
gateway, without giving the reference service an HTTP endpoint or key. Explicit
legacy migration and refusal of unsafe rollback are implemented in source;
their installed qualification is still required before Requirement #1 closes.
Real installed model/tokenizer execution and
cancellation/drainage still require image qualification.

### Reference gateway over the existing broker socket

`LUMA_MODEL_TRANSPORT=native-broker` selects the reference client's native
gateway. It requires the selected `LUMA_MODEL_NAME` and refuses an HTTP endpoint
or runtime API key. The installed systemd unit and newly activated model
environment select this transport by default. Standalone developer configuration
still defaults to `openai-http`; it is not an installed admission path.
The fixed installed reference UID cannot select or construct the HTTP client:
configuration and service composition refuse before creating state. Every
direct HTTP request also rechecks the current UID, so an object constructed
before changing to the reference identity cannot bypass native admission.
Binary-only upgrades never silently migrate old environments.
The new `resource-gateway` envelope uses schema version 1 independently of
the root operator's version-2 `resource-inference` envelope. Broker, supervisor
and client must be upgraded together. No listener, writable shared database or
TCP control transport is added.

The broker authenticates UID 990 and pins its current process generation for
submission, fetch, acknowledgement and cancellation. It holds at most one
transient job, with 1..16 role/content messages ending in a user message and
at most 8,192 UTF-8 content bytes. The exact canonical original messages are
bound by a domain-separated SHA-256 before a preparing receipt is persisted.
The eventual claim frame is bounded before reservation; JSON escaping cannot
produce an unrepresentable queued job. A busy queue, changed nonce replay or
another caller's receipt refuses. Prompts and results are not durable journal
content and are not revived after broker restart.

UID 990 alone is insufficient. At each live-peer observation, the broker
requires the exact `/system.slice/luma-reference.service` cgroup and enforcing
`luma-reference` AppArmor label, all four current UIDs, zero capability masks,
no-new-privileges, seccomp filter mode and zero locked-memory limits. Repeated
kernel snapshots bind these checks to the pinned PID/start/boot generation.
Request maintenance uses the same proof; a moved, unconfined, re-privileged or
unobservable caller is fenced without an early physical release. The real
negative test uses a live UID-990 process outside the installed service. Positive
installed confinement and the exact filter rules still need image qualification.

Only the exact UID-989 owner of the current physical serving lease can register
readiness, claim or advance a job. A runtime child sharing the UID and cgroup
cannot borrow the supervisor's owner generation. The existing leased supervisor
calls the pinned runtime at literal loopback port 8081 with its private key;
the broker itself remains restricted to Unix sockets. Template/tokenizer work
follows the preparing reservation. The exact token array and maximum output
must fit the fixed context, and execution follows an exact admitted
acknowledgement. Rendering disables thinking, concurrency remains one, and
sampling is explicitly temperature 0.7 without a seed. Unsupported client
sampling options refuse rather than being ignored.

Runtime requests and responses have fixed authority, byte limits, strict
framing and one boot-time request deadline. Redirects, duplicate headers,
alternate encodings, truncation, excessive context/output and mismatched model
or timing counts refuse. Local lease/fence checks run throughout IO; a pipeline
failure exits through owned-child supervision and trusted whole-group drainage.
Completion releases only the logical slot, never the physical worker peak.
The client checks the exact receipt, output counts and domain-separated result
digest, then acknowledges before publishing text. Exact completed
acknowledgements and client cancellations are repeatable from durable receipts
without clearing a different queued job. Fetch and acknowledgement require a
current active physical token, the live pinned supervisor and matching readiness;
gateway maintenance runs after physical revocation/drainage, and non-cancellation
replies recheck the serving generation after persistence. Retaining a completed
receipt cannot authorize publication from a revoked or expired worker.
Expired publication or lost/mismatched
acknowledgement produces no result and makes no cleanup claim.

This is reference-process resource mediation, not product user/session grants,
Admin authorization, effect authority or signed production custody. Actual
installed enforcement and proof that old keys are rejected remain qualification
work, not consequences of passing the gateway's source/protocol checks.

### Runtime credential rotation and reference migration

Every activation, including reviewed partial-candidate completion, creates a
new random 256-bit runtime credential and refuses a collision with the existing
key. Under the existing operation/runtime exclusions and durable activation
fence, it publishes the key first, the key-free environment second, and canonical
version-2 selection last. Final file ownership/modes and both affected directories are
synchronized before the activation fence can be cleared. A sync failure leaves
the pending records for review. Worker admission and ongoing supervision require the canonical
version-2 selection. Version-1 configurations remain readable for explicit migration, but
cannot serve through the new broker/supervisor. The private key remains readable
only by root and the model group, not UID 990.

The existing `sudo luma-platform model-migrate-legacy` command accepts either
the exact old root-owned environment or the exact former `reference/model.env`.
If both exist they must agree with the selected credential and catalog model.
It verifies weights before stopping the model and reference services, obtains
runtime exclusion, verifies again, then performs the fenced activation and
requests a restart. It does not claim readiness or silently repair conflicting
files. Apply the broker, supervisor, helper, client, unit and policies together;
old binaries are not a supported security downgrade.
Outstanding lifecycle/validation fences are not automatically migrated or
cleared. Preserve them for review; broader damaged/legacy recovery remains open.

Private recovery files retain exact prior bytes for investigation. Interrupted
and completed rollback refuse version-1/direct-runtime configurations before
any restoration write; a legacy migration's undo record is therefore not
restorable. An environment/selection-only migration retaining the prior exposed
key cannot be published through activation reconciliation. Review and complete
that partial candidate to rotate, or preserve state for investigation. Exact
rollback between consistent private version-2 configurations remains available.
The obsolete worker-writable legacy file, if present, is retained with its now
revoked key; it is not a fallback or authority to restart an older image.

### Upgrade of older request history

Fresh resource-state initialization creates the private request journal along
with the physical ledger. For an older image with genuinely absent request
history, first release all physical generations using its matching old broker,
then stop the broker and both worker services. The existing runtime exclusion
inode must be available; if it is genuinely missing, follow its separate
reviewed recovery procedure first. With the new binary and both worker slices
empty, run `sudo luma-platform resource-request-migration-status`, review the
reported historical gap, then `sudo luma-platform resource-request-migrate REVIEW-SHA256`.

The operation holds the model operation/runtime exclusions and the resource
store's lifetime lock, which requires the broker stopped. It refuses any
request journal, retained archive, interrupted request publication, outstanding
physical generation or stale review. It rotates only an initialized physical manager
epoch and exclusively creates the missing journal with explicit legacy
provenance. Physical receipts, generation floors, retained charges and fences
stay intact. Pre-upgrade session receipts were not retained and are reported
as unavailable, not fabricated. An interrupted creation may leave a changed
review or an existing journal: inspect again, never overwrite or reset it.
An older ledger that has never established an inventory stays uninitialized;
this migration does not invent physical capacity or authority for it.
This command does not start services, clear quarantine or grant product Admin.

## Persistence and retention

The root-private canonical ledger has an exclusive lifetime lock. Missing,
malformed, unsafe, future or noncanonical state is never silently initialized
or reset. Authority changes are synchronized atomic publications. A failed
publication or durability acknowledgement poisons the manager session; no
further lease is granted. Ordinary telemetry remains session-local when it
does not change authority. Pressure, retained charges, expiry, tokens and
reviewed transitions remain durable.

The store now pins its private root directory's device/inode and continuously
checks that the held lifetime-lock descriptor still matches the private named
lock. A replaced, missing, linked, aliased or nonprivate lock/directory fences
the existing session. Putting the original path back cannot clear an observed
loss. Reads also require the exact hot-ledger digest loaded or acknowledged by
this writer; a canonical external edit is not an authorized transition or a
capacity credit. A changed publication is acknowledged only after exact durable
readback and renewed exclusion checks. Exact retries and nonpublishing telemetry
also recheck the boundary before returning. No failed check rewrites or resets
state. Preserve the durable outcome and stop the old broker before a fresh
locked load. These are active-writer integrity checks, not TPM anti-rollback,
corrupt-state reconstruction or proof that a copied ledger is safe to deploy.

The request journal now verifies its last loaded or acknowledged digest on
every maintenance cycle, including unchanged nonpublishing cycles. A bounded
streaming read checks exact private file custody and stable descriptor/path
identity; the shared physical-store exclusion is checked before and after.
Changed request publications require matching durable readback before the
acknowledged digest advances. Status, preservation review and archive export
also verify the current hot authority. Export validates the complete referenced
archive and stable file identity before producing a chunk; damaged archive
custody fences the request session, while an invalid client reference or offset
does not. Archive publication is verified before the hot cut.

Observed request-authority loss is sticky even on read-only paths. Restoring
the original bytes, modes or lock cannot revive that session. Preserve evidence
and stop the old authority before a fresh locked load; no failure resets history,
revives retired nonces or frees physical resources. These checks provide active
request-writer integrity, not product export authorization, signed custody,
cross-restart rollback protection or damaged-state reconstruction.

Unsupported outstanding native owners, catalog bindings or reservation plans
refuse before restart/drainage; structurally valid generic ledger data is not
silently skipped as though supported. Startup failure attempts fencing of both
trusted fixed groups without resetting state or claiming allocation return.

The hot ledger holds up to 4,096 lease records and eight MiB. Reviewed archival
requires all leases already released and an observed empty worker domain.
Private, hash-addressed receipts are published with a synchronized preparation
and no-replace rename before the hot-ledger cut. Referenced archives form a
validated predecessor chain. Generation floors and retained charges survive;
the manager epoch changes, and archived owners cannot reacquire using old
requests. Archives are not signatures or TPM anti-rollback anchors.
Retired-owner lookup uses a bounded digest index rebuilt from validated
referenced receipts at broker startup and extended after a durable archive cut;
the admission path does not repeatedly read historical archive files.

There are at most 64 referenced archives and 128 retained archive/preparation/
incident files, each bounded to eight MiB. Directory inspection is limited to
512 entries, including unrelated files. Exhaustion refuses rather than evicting
receipts. Interrupted private preparations and complete unreferenced
publications remain evidence; neither implies a ledger cut or capacity return.
Exact complete publications can be retried. Partial/conflicting preparations
are not overwritten.

`resource-recovery-status` and `resource-recover REVIEW-SHA256` provide reviewed
preservation of interrupted physical-lease archive preparations. After a failed
archive publication, restart the fenced broker and drain both workers normally.
With terminal requests, empty worker groups and Released physical generations,
inspect the reported stage, size and digest before applying its exact review.
The review binds the current hot ledger's authority, exact durable bytes/inode
and the selected stage's canonical name, bytes/inode and timestamps. The broker
rechecks the live root peer, deadline and empty group identities immediately
before and after a synchronized no-replace rename. The retained incident has
the same inode and bytes; no ledger/request record, generation floor, owner
tombstone, result fence or retained charge is changed by preservation.

Candidates may come from an older interrupted archive attempt, including after
broker restart or a later ledger cut. They must name a known nonfuture generation;
checksum-matching complete stages are left for exact archival retry/investigation.
Preservation never infers that any archive cut completed. Selection is stable and
one stage is retained per reviewed command. Unsafe modes/links, future/unknown
stage names, stale review, destination collision or observation failure refuse.
A lost acknowledgement poisons authority; restart and inspect the durable side
of the rename, with no automatic retry. Incidents count toward the unchanged
128-file limit and their name/content digest is verified during broker startup.
Preservation does not reclaim a slot or repair missing/damaged ledger bytes,
referenced archives or request history. Governed export/deletion and broader
damaged-state recovery remain open; do not delete records to bypass a fence.

Request-history preservation now covers older interrupted preparations as well
as the current archive attempt. After draining both worker groups and all
physical generations, inspect `resource-request-recovery-status` and apply its
exact review with `resource-request-recover REVIEW-SHA256`. The broker scans the
bounded private inventory and chooses one stage in stable filename order. The
stage must have a canonical archive filename and name a nonfuture batch within
the existing 64-archive limit. Checksum-matching complete stages remain intact
for exact retry or investigation; they are never treated as evidence of a hot
cut. Unknown, noncanonical or future stage names refuse preservation without
changing state. An older incomplete stage can be retained after journal advance,
restart or a later archive cut, even with no hot receipts or a full archive chain.

The new request-recovery review binds the exact stage, the durable hot request
journal's bytes/inode/timestamps, and both the physical ledger's current review
and durable file identity. A byte-identical replacement of either authority file
invalidates an earlier review. An unpublished request-state change also refuses;
the recovery command cannot overwrite it or manufacture an acknowledgement.
Obtain a fresh review after upgrading; earlier request-recovery review digests
are not reused. Stage hashing uses an 8-KiB buffer within the unchanged one-MiB
file limit. The existing live-peer, deadline, empty-group and no-replace checks
still surround the move. Hot receipts, archive references, retired nonces and
physical charges remain unchanged. Preservation consumes the same retained-file
slot and does not raise a retention limit or authorize deletion/export.

## Installed operator commands

These are installed-root maintenance interfaces, not product Admin role
assignments or an effect authorization service.

```sh
sudo luma-platform resource-status
sudo luma-platform resource-revoke LEASE-ID GENERATION MANAGER-EPOCH
sudo luma-platform resource-reconcile REVIEW-SHA256
sudo luma-platform resource-archive REVIEW-SHA256
sudo luma-platform resource-recovery-status
sudo luma-platform resource-recover REVIEW-SHA256
sudo luma-platform resource-request-status
sudo luma-platform resource-request-archive REVIEW-SHA256
sudo luma-platform resource-request-export BATCH SHA256
sudo luma-platform resource-request-recovery-status
sudo luma-platform resource-request-recover REVIEW-SHA256
```

Use the exact outstanding token and current review returned by status.
Revocation acknowledges a durable fence; `cleanup_complete: false` means
drainage is still pending. Even completed process drainage may leave nonzero
retained memory. Reconciliation requires no outstanding lease and an empty
worker groups; it does not clear model lifecycle quarantine, activate a model,
change TPM ownership or grant roles. Archival requires the model stopped and
drained, preserves receipts and never starts it. Restart it explicitly only
after resolving all independent lifecycle fences.

For an older installation with genuinely absent resource state, install the
matching new binary/unit/image configuration, stop and drain the model, then
run `sudo luma-platform resource-migrate` and restart the broker. Migration
creates only a missing ledger; an existing or uncertain directory refuses.
The broker must load that state before a model is started. Never infer that a
new binary alone upgrades older packaged units, catalog or confinement.

The catalog's added attention-layout fields change profile resource bindings.
Drain outstanding leases using their matching old broker before upgrading the
catalog and binary. The new broker refuses unsupported outstanding bindings;
do not reset the ledger or remove receipts to bypass that refusal. Released
history remains retained rather than rewritten to the new binding.

An existing valid ledger with the older inventory needs an explicit reviewed
inventory migration, not missing-state initialization. First drain/release its
leases under the matching old broker, then stop the broker. With both new slices
empty and the existing model runtime lock available, run
`sudo luma-platform resource-migration-status`, then
`sudo luma-platform resource-migrate REVIEW-SHA256`. The durable migration
preserves retained charges, history, archive references and generation floors,
adds the fixed execution domains and changes the manager epoch. Outstanding
leases, a stale review, removed domains or damaged state refuse. Older manual
installations missing the model runtime lock now have the explicit offline
recovery below. Inventory migration still never manufactures an exclusion proof.

For an older installed system with a genuinely absent runtime lock, first drain
and release any generations using their matching broker. On that installed
system, explicitly stop and runtime-mask `luma-model.service`,
`luma-acquisition.service` and `luma-broker.service`, then reload systemd. Run
`sudo luma-platform resource-runtime-lock-status` and, only if it reports
`recoverable: true`, `sudo luma-platform resource-runtime-lock-recover REVIEW-SHA256`.
Do not execute this procedure on the development host or clear an outstanding
lease to make recovery proceed.

Recovery requires systemd to have loaded all three exact root-owned `/dev/null`
masks, no pending job, inactive/failed units, empty worker slices, and no live
thread carrying UID 989 anywhere in the installed systemd PID namespace. Its
complete proc census is bounded to 32,768 process/thread entries and five seconds;
hidden/subset proc mounts, unreadable credentials or an incomplete census refuse.
The model operation lock and, when present, the validated resource store's lifetime
lock span inspection and creation. Existing damaged state, outstanding generations,
changed boot/cgroup/mask/catalog/ledger review or any existing exclusion inode refuse.
The same proof is collected again immediately before exclusive creation and durable
file/directory synchronization. The procedure neither resets the ledger nor returns
retained memory, removes receipts, clears lifecycle fences or starts a worker.

All three masks stay in place on success and failure. Inspect again after an
uncertain creation acknowledgement; an existing safe idle inode reports
`recoverable: false` and is never replaced or recreated. Then perform the applicable
missing-ledger initialization or reviewed inventory migration, separately verify
all lifecycle fences, and explicitly remove only the three masks after that review.
Start the broker first; start a selected model only after resource authority has
loaded successfully. These are installed-root maintenance commands, not product
Admin authorization, and their combined native-image procedure remains unqualified.

## Still required before Requirement #1 closes

The owner selected the following implementation order. Principal/session and
grant integration is the active subgate; the next starts only after its
implementation and targeted evaluation pass and the owner reviews completion.
Final-image/native-hardware qualification remains separate.

The owner approved the UTC runtime and offline Admin recovery designs in
[ADR-0011](../docs/adr/0011-local-utc-runtime-and-offline-admin-recovery.md)
on 2026-10-08. The installer now enrolls a public recovery verifier for explicit
TPM adoption, and a separate custody transaction rotates Admin/recovery
generations. This is not Unix account/password lifecycle, damaged-authority
recovery, installed UTC authority or integration of grants into lease consumers;
the subgate and the remaining items below are still open.

- Complete principal/session and grant integration, including governed account
  generations, authenticated sessions, trusted-time finite Admin assignments,
  principal-bound folder/effect grants and current authority checks at resource,
  inference and effect boundaries. The initial native per-request PAM session
  lifecycle now has suspend-aware expiry, explicit closure and sticky failure
  fencing. Original registry/account descriptors and directory handles now fence
  file replacement even when replacement bytes are identical; visible metadata
  changes also require fresh authentication. These live continuity checks are
  not durable anti-rollback generations. Admin IPC now pins the original live
  caller and connection through catalog identity checks, without a PID lookup
  fallback. Current human-peer credentials now use a separate read-only,
  zero-capability observer. It checks all four UID/GID fields for every pinned
  thread in a stable task set (maximum 32), with sticky peer fencing. A fixed
  read-only kernel metadata bundle verifies the observer without opening another
  process through Admin's hidden proc view. Native installed observer enforcement
  remains unqualified; governed account, time and grant integrations remain
  required software work. Explicit reviewed principal-registry adoption now has a
  native source path: the existing TPM catalog checkpoints the installed snapshot
  and rejects changed metadata during Admin/UTC semantic replay. Live catalog
  mutations pin the original registry through final authentication. This
  immutable checkpoint is not mutable account lifecycle, credential rollback
  protection or authority enforcement at resource/inference/effect boundaries.
  Reviewed non-Admin disable/re-enable and generation rotation now advance TPM
  catalog state without changing installation account files. A genuine PAM-bound
  governed session double-replays that state and permanently fences on generation,
  shared-head, clock or proof changes. The installed root `principal-check`
  diagnostic exercises this source composition. Original enabled Admin generation
  rotation now uses a separate reviewed command, with journal-prefix writer
  validation for catalog and shared UTC history. It preserves enrollment/baseline
  bytes, closes the request's PAM on commit attempts and never rewrites old
  writers. Admin credential/custody recovery, account creation/credential recovery
  and resource/inference/effect admission integration
  remain open; this does not qualify those boundaries or close the subgate.
  Governed login issuance now brackets a new PAM exchange with the exact pre/post
  TPM-backed state and retained original registry handles. It rejects earlier
  PAM observations, mismatched accounts, registry replacement and authority
  changes during login, without holding writer locks through password entry.
  This source path is exercised by `principal-check` and genuine-PAM/software-TPM
  fixtures; it does not integrate the remaining catalog control, time, grant or
  admission paths.
  Session use now brackets the whole protected projection with semantic authority
  replay and the bounded PAM observation. Its drop guard closes reader, session
  and PAM on refusal or unwinding, including a failure in PAM's final checks.
  Its retained TPM clock/epoch floor also constrains fresh readers from their
  first snapshot. Identity diagnostics use this same path. This primitive does
  not authorize effects, roll back completed operations or integrate the remaining
  admission consumers.
- Finish broader content/workflow worker admission. The closed invoice
  coordinator and both direct publishers use leased calculation and effect-time
  result checks, but remain installed-root paths, not generic governed execution.
  Root model hashing also uses the leased service in source; the real installed
  pipelines still need qualification.
- Extend request-level accepted prompt/output/concurrency accounting to all
  inference consumers and qualify closure of the installed reference bypass.
  Native gateway defaults and fenced key rotation/migration now exist in source;
  real installed reference execution, old-key refusal and upgrade/rollback
  qualification remain open.
- Complete governed request export/deletion, custody and retention lifecycle.
  Durable operator receipts, reviewed archival, bounded root export and
  preservation of current and older interrupted archive preparations exist;
  installed-root maintenance is not product export/deletion authorization.
- Finish broader reviewed damaged-authority recovery, including ledger/journal
  and referenced-archive reconstruction. Manual deletion or an empty fallback
  ledger is not recovery.
- Complete supported multi-worker/tenant and device-domain adapters and
  generation/recovery paths. Current CPU-only, zero-pinned/zero-device profiles
  do not certify GPU, large-model, NUMA or other hardware paths.
- Qualify the real installed broker-to-worker pipeline, descendant drainage,
  pressure/OOM, suspend, storage/crash/restart and migration on the consolidated
  image. Unit arithmetic and source wiring are not kernel-enforcement evidence.

## Verified CPU allocation inventory

The catalog now includes the selected model's actual attention layout in its
resource binding. A bounded GGUF-v3 parser reads the same checksum-verified
descriptor, with lease checks around every metadata read. Metadata is limited
to 64 MiB, 4,096 unique keys, 512-byte keys, 65,536-byte strings and 1,048,576
elements per array. Missing, duplicate, malformed, incompatible and unsupported
sharded or nonstandard attention layouts refuse. These limits are enforced
without allocating tensor storage or retaining tokenizer arrays.

For the pinned CPU runtime, context rounds to 256 cells, each F16 key/value
tensor rounds to 32 bytes, and concurrency remains one. At 2,048 cells the
Qwen3-4B profile reserves 301,989,888 KV tensor bytes; Qwen3-1.7B reserves
234,881,024. Head widths come from the verified metadata and checked runtime
defaults, not an assumption that embedding width divided by attention heads
is the model's actual cache width.

The inventory counts the file mapping and its shared file-cache charge once,
rounded to the pinned amd64 base page size. KV bytes plus the combined remaining
runtime/scratch ceiling sum to the full worker peak. Extra prompt, idle and
checkpoint caches, device memory and locked staging memory remain disabled.
This is a bounded allocation plan, not a measurement of graph scratch or RSS;
installed model loading must qualify the combined ceiling. Download publication,
cached acquisition verification and serving all check the layout before admitting
the verified descriptor to subsequent use. Inventory diagnostics serialize
64-bit values as canonical decimal strings and never reduce the broker lease.

The implementation follows the [GGUF specification](https://raw.githubusercontent.com/ggml-org/ggml/master/docs/gguf.md),
the pinned [KV tensor construction](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/src/llama-kv-cache.cpp)
and [context padding](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/src/llama-context.cpp).
CPU alignment and tensor-size accounting follow its
[backend](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/ggml/src/ggml-backend.cpp),
[allocator](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/ggml/src/ggml-alloc.c)
and [alignment definition](https://raw.githubusercontent.com/ggml-org/llama.cpp/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/ggml/src/ggml-impl.h).

The [reference rotation checkpoint](evidence/G2_RESOURCE_KEY_ROTATION_2026-10-07.md)
records the current selected regressions. The
[earlier gateway checkpoint](evidence/G2_RESOURCE_GATEWAY_2026-10-07.md) and
[earlier resource checkpoint](evidence/G2_RESOURCE_LEASES_2026-10-06.md) retain
the preceding work. These separate source results from open integrations.
The final image and native Ubuntu evaluation remain subsequent work; no WSL memory increase is needed
for the bounded development checks described there.

Kernel controller behavior is specified by the
[cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
Systemd 255 resource controls are specified in its
[versioned resource-control source](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.resource-control.xml).
Credential changes clear the parent-death setting; the final hook ordering
follows the [Linux parent-death interface](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
Whole-disk IO resolution follows the
[systemd 255 controller implementation](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/cgroup.c)
and its [block-device utility](https://raw.githubusercontent.com/systemd/systemd/v255/src/shared/blockdev-util.c).
The explicit runtime settings use the pinned
[llama.cpp b11100 options](https://raw.githubusercontent.com/ggml-org/llama.cpp/b11100/tools/server/README.md).
