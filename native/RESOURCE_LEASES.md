# Native resource leases and generations

Updated 2026-10-06. Requirement #1 remains open until its remaining integrations
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
no resource methods; UID 989 gains only acquisition and renewal of its own
fixed, selected CPU worker. Root acquisition is accepted only from the fixed,
enforcing acquisition unit. Unsupported ACL or peer-PID-handle support refuses
without a weaker fallback.

Sixteen bounded transport threads have separate UID quotas: eight root,
four model and four reference connections. Their only tasks are framing and
reply delivery. Partial frames and blocked readers do not hold the resource
coordinator. One independent legacy effect helper can wait for systemd without
blocking resource maintenance or renewals; additional effects refuse while it
is busy. The resource ledger and controller still have one coordinator/writer.

The broker pins the connecting process using `SO_PEERPIDFD`, its boot/start
generation and the cgroup device/inode. Requests cannot supply a PID, cgroup,
capacity, allocation credit, arbitrary domain or controller command. Profiles
come from the root-owned pinned image catalog. Serving must match the installed
selection and lifecycle fences; acquisition can prepare another pinned profile
before a selected worker is stopped. Acquisition additionally binds the physical
IO-controller device resolved from the trusted target's kernel storage topology.

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
The reference service still has direct runtime credentials and is not covered
by this operator admission path. Its integration and closure of that bypass
remain required before Requirement #1 can close. Real installed model/tokenizer
execution and cancellation/drainage still require image qualification.

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

There are at most 64 referenced archives and 128 retained archive/preparation
files, each bounded to eight MiB. Exhaustion refuses rather than evicting
receipts. Interrupted private preparations and complete unreferenced
publications remain evidence; neither implies a ledger cut or capacity return.
Exact complete publications can be retried. Partial/conflicting preparations
are not overwritten. Governed export/deletion and broader damaged-state
recovery remain separate open work; do not delete records to bypass a fence.

## Installed operator commands

These are installed-root maintenance interfaces, not product Admin role
assignments or an effect authorization service.

```sh
sudo luma-platform resource-status
sudo luma-platform resource-revoke LEASE-ID GENERATION MANAGER-EPOCH
sudo luma-platform resource-reconcile REVIEW-SHA256
sudo luma-platform resource-archive REVIEW-SHA256
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

- Join resource admission to content/workflow workers. Root model hashing is
  routed through the leased service in source; its real installed pipeline
  still needs qualification.
- Extend request-level accepted prompt/output/concurrency accounting to all
  inference consumers, close the reference service's direct-runtime bypass,
  and finish governed request export/deletion, custody and retention recovery.
  Reference integration must also rotate previously exposed runtime keys through
  the reviewed lifecycle; changing an environment file alone leaves a bypass.
  Durable operator receipts, reviewed archival, bounded root export and reviewed
  preservation of a current incomplete archive stage now exist; the operator path
  and verified CPU KV inventory do not close those integrations by themselves.
- Complete supported multi-worker/tenant and device-domain adapters and
  generation/recovery paths. Current CPU-only, zero-pinned/zero-device profiles
  do not certify GPU, large-model, NUMA or other hardware paths.
- Finish broader reviewed damaged-state and governed retention/recovery
  integration; manual deletion or an empty fallback ledger is not recovery.
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

The [development checkpoint](evidence/G2_RESOURCE_LEASES_2026-10-06.md) separates
targeted results from those open integrations. The final image and native
Ubuntu evaluation remain subsequent work; no WSL memory increase is needed
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
