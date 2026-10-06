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
fixed, selected CPU worker. Unsupported ACL or peer-PID-handle support refuses
without a weaker fallback.

The broker pins the connecting process using `SO_PEERPIDFD`, its boot/start
generation and the cgroup device/inode. Requests cannot supply a PID, cgroup,
capacity, allocation credit, arbitrary domain or controller command. Profiles
come from the root-owned pinned image catalog and must match the installation's
selected model and current lifecycle fences.

The native ledger implements checked unsigned 64-bit accounting, atomic
multi-domain admission, loading/serving peak reservation, exact replay,
monotonically increasing lease generations, manager epochs, expiry/revocation,
pressure hysteresis, whole-lease quarantine and reviewed reconciliation.
All 64-bit contract values are canonical decimal JSON strings; numeric JSON,
overflow and noncanonical strings refuse. Whole-worker peak reservation is
never reduced because a worker reports readiness or exit.

Current native profiles use one CPU worker in `lumamodel.slice`, with a
`luma-model.service` leaf. The broker verifies cgroup-v2 identity, whole-slice
and leaf memory limits, zero swap, CPU/IO/PID ceilings, grouped OOM handling
and zero locked-memory allowance. The runtime has no accelerator access.
The host reserve is the larger of one GiB and 20 percent of reported RAM;
physical loading checks supplement, rather than replace, kernel ceilings.
Qwen3-4B now requires at least 6.1 billion RAM bytes and 4,831,838,208 available
bytes; Qwen3-1.7B requires four billion RAM bytes and 2,684,354,560 available
bytes. These are admission policies, not measured performance certificates.

The model obtains a lease before hashing/loading weights. A separate heartbeat
renews every two seconds during loading; supervision also checks the exact
token before and during runtime execution. Leases last ten seconds using
`CLOCK_BOOTTIME`, not civil UTC. Renewal failure or thread failure fences
execution. Dropping the heartbeat stops renewal but sends no release claim.

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

## Persistence and retention

The root-private canonical ledger has an exclusive lifetime lock. Missing,
malformed, unsafe, future or noncanonical state is never silently initialized
or reset. Authority changes are synchronized atomic publications. A failed
publication or durability acknowledgement poisons the manager session; no
further lease is granted. Ordinary telemetry remains session-local when it
does not change authority. Pressure, retained charges, expiry, tokens and
reviewed transitions remain durable.

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
```

Use the exact outstanding token and current review returned by status.
Revocation acknowledges a durable fence; `cleanup_complete: false` means
drainage is still pending. Even completed process drainage may leave nonzero
retained memory. Reconciliation requires no outstanding lease and an empty
worker group; it does not clear model lifecycle quarantine, activate a model,
change TPM ownership or grant roles. Archival requires the model stopped and
drained, preserves receipts and never starts it. Restart it explicitly only
after resolving all independent lifecycle fences.

For an older installation with genuinely absent resource state, install the
matching new binary/unit/image configuration, stop and drain the model, then
run `sudo luma-platform resource-migrate` and restart the broker. Migration
creates only a missing ledger; an existing or uncertain directory refuses.
The broker must load that state before a model is started. Never infer that a
new binary alone upgrades older packaged units, catalog or confinement.

## Still required before Requirement #1 closes

- Join native resource admission to model acquisition/staging and content or
  workflow workers, not just the installed serving worker.
- Implement and integrate request-level accepted prompt/output/concurrency
  accounting and the actual KV/cache layout inventory. A whole-worker ceiling
  does not close those contracts by itself.
- Complete supported multi-worker/tenant and device-domain adapters and
  generation/recovery paths. Current CPU-only, zero-pinned/zero-device profiles
  do not certify GPU, large-model, NUMA or other hardware paths.
- Finish broader reviewed damaged-state and governed retention/recovery
  integration; manual deletion or an empty fallback ledger is not recovery.
- Qualify the real installed broker-to-worker pipeline, descendant drainage,
  pressure/OOM, suspend, storage/crash/restart and migration on the consolidated
  image. Unit arithmetic and source wiring are not kernel-enforcement evidence.

The [development checkpoint](evidence/G2_RESOURCE_LEASES_2026-10-06.md) separates
targeted results from those open integrations. The final image and native
Ubuntu evaluation remain subsequent work; no WSL memory increase is needed
for the bounded development checks described there.

Kernel controller behavior is specified by the
[cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
Systemd 255 resource controls are specified in its
[versioned resource-control source](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.resource-control.xml).
