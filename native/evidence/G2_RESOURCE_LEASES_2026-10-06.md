# G2 native resource lease development checkpoint

Date: 2026-10-06. Scope: Requirement #1, resource leases/generations only.
Status: native CPU-serving and acquisition-generation increments; **Requirement #1 and G2
remain open**. No Requirement #2 implementation, final image build, physical
qualification, production custody change or TPM ownership change is asserted.

## Source changes

`resources.rs` adds the root-private native ledger and checked multi-domain
reservations, durable generations/manager epochs, expiry/revocation,
quarantine/review, immutable receipt archival and retained-memory accounting.
`resource_manager.rs` implements the adapter inside the existing broker,
fixed-cgroup controls, kernel owner binding, physical loading checks, idle
reclaim and worker heartbeats. `service.rs` retains the existing framed Unix
socket and adds strict resource responses, socket-specific service-user ACLs
and peer PID handles. No listener or shared writable database was added.

The model serving path now acquires before weight verification and renews
during loading/execution. Installer initialization, the owned slice, model
unit budgets, narrow broker controller access, AppArmor socket access and
suspend stop ordering are wired in source. The catalog's available-RAM and
minimum-RAM policies account for full worker peaks and the protected reserve.
Changed catalog/unit/binary bytes require a new image and cannot inherit older
image qualification.

The subsequent acquisition increment replaces curl's raw child polling with
the existing pinned-child supervisor. The production UID/GID-988 confinement
hook precedes parent-death registration and retains the kernel byte limit.
Download observation checks an explicit boot-time deadline and output identity;
temporary cleanup requires the created inode and an independent inherited
writer lock. Uncertain, busy or replaced paths remain intact. This is not a
download/staging lease, contained hashing worker or physical allocation-return
receipt; those integrations remain required.

Use [the resource register](../RESOURCE_LEASES.md) for the implemented boundary,
operator instructions, finite limits and remaining software integrations.

## Current bounded execution

Evidence directory:
`D:\LumaOS-builds\g2-resources-targeted-20261006-11`.

- Docker root: `/mnt/luma-build/docker`, backed by D: storage.
- Tool image: `luma-utc-targeted-tools:20261005`, image ID
  `sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
- Cargo cache: `luma-g2-rust-targeted-cache-20261001`, also on D:.
- One CPU, 768 MiB memory with no extra swap, 256 PID ceiling, one Cargo job,
  no network and no `CAP_SYS_ADMIN`, host devices or host-service mutations.
- Source snapshot mounted read-only; test output and temporary/build data on
  D:-backed mounts. WSL memory settings were not changed.
- Warnings denied, debug symbols disabled to reduce compiler memory. This is
  an unoptimized development binary, not a qualified production image.

| Check | Result |
| --- | --- |
| Native resource core | 17 passed, zero failures/ignored |
| Native adapter and heartbeat | 8 passed, zero failures/ignored |
| Existing broker transport plus resource/ACL checks | 20 passed, zero failures/ignored |
| Model lifecycle/supervision and acquisition generation regression | 111 passed; two pre-existing owned child entrypoints excluded from top-level discovery |
| Resource/model/health/VM/broker packaging Python checks | 57 passed |
| Cargo formatting and offline locked build | Passed |
| AppArmor no-load/no-cache syntax parse | Passed; not an enforced profile test |
| Real systemd unit graph verification | Exit 1: tool container lacks `apparmor.service`; installed graph qualification remains pending |

Total: **213 passing selected tests**. The two model entrypoints are invoked by
their parent process-boundary fixtures; they are not counted as extra passes.
Unrelated Admin tests were not selected. No new resource test is ignored and
no unimplemented resource code path is hidden behind a successful placeholder.
The source-level Python checks are wiring guards, not installed enforcement.

Core checks include 100 competing clients, all-or-nothing domains, loading
peaks, shared retained-cache credits, hostile/stale tokens, checked overflow,
precision-preserving serialization, replay conflicts, expiry, restart,
quarantine, lost publication acknowledgement and private-file locking.
Archival checks cover durable generation floors, predecessor chains, owner
tombstones, archive tampering, complete orphan publications and incomplete
private preparations without hot-ledger clearance. Telemetry tests verify no
ordinary polling rewrite while pressure and expiry transitions remain durable.

Adapter checks include real bounded read-only kernel observations, physical
reserve arithmetic, cgroup-generation drainage rules, IO ceiling parsing,
method/peer restrictions and live heartbeat renewal/failure/panic/drop behavior.
Transport tests exercise a real Unix socket and kernel credentials, PID-handle
creation, deadline/framing/correlation and substituted renewal token refusal.
The peer-handle test also verifies a socket created by an already exited
thread still identifies the live process generation used by heartbeats.
The ACL fixture actually drops groups/UID/GID in disposable child processes:
root, 989 and 990 connect; 988 and 1000 receive permission denial. These tests
do not run the installed cgroup controller or a real model loading cycle.

Five additional ordinary Rust tests cover acquisition observation failure,
callback unwind, normal/failed exit and spawn failure before independent
descriptor reuse; temporary cleanup with a live inherited writer; replaced or
uncreated identity preservation; and drained-file removal. The captured C
fixture executes after the exact production confinement function and checks
UID/GID 988, no supplementary groups, `NoNewPrivs`, registered `SIGKILL`, the
finite `RLIMIT_FSIZE` and root-owned locked stdout, then writes tiny fixture
bytes. It checks exec-boundary state, not acquisition crash-delivery, network
downloads, hostile descendant containment or installed AppArmor/cgroup policy.
No production executable/UID/environment override was introduced. Two Python
wiring checks guard hook ordering and descriptor/identity cleanup prerequisites.

## Retained evidence integrity

The captured manifest contains 193 source files. All manifest file digests and
all 52 separately captured native test-input digests were checked against the
current checkout after execution and matched. Documentation outside the native
image/source capture is explanatory, not deployment evidence.

| Retained file | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `b104464ead2918305c187e68e3f6f203c53466d355665472cdc9647886181e52` |
| `test-inputs.sha256` | `a678bccfe8ffea6a446f59ae9573bd29cd7ab85c8f201575ab5f6480ddbe7887` |
| `test.log` | `596fb2a40c77350be918bb4fb47d911819c0e7d98a2f7900ff1a3643291c9210` |
| `checks/unit-verification.txt` | `7759a560b4c9c8194edf5c41c4d4e052cd8741b97c1232bbf355ab2fb99d8504` |
| `checks/unit-verification-exit.txt` | `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` |

Earlier trials remain retained on D:, not silently overwritten. Trial 02 had
a compiler error corrected in later source. Trial 03 stopped at the real unit
graph failure; no fabricated AppArmor dependency was used to make it pass.
Trial 05's compiler was terminated by SIGKILL before tests; this is not a test
pass or a proven root-cause diagnosis. Subsequent runs used `-Cdebuginfo=0` at
the same memory limit and passed. Trials 01/04/06/07/08 cover earlier source and do
not qualify the current additional changes.

The prior 206-test trial 09 qualified the CPU-serving baseline committed as
`b9e8420`; its evidence remains in `g2-resources-targeted-20261006-09` on D:.
Its manifest, test-input and log SHA-256 values were respectively
`6736b6514c663df7387fbe335945389466674d41161b887d6002bde1aa57ec77`,
`634aa936b737120cd487e8aed33610d5fe57cf99629770d625681e7ef9388dbf`
and `0188eebdb888f24e01edcda37b6e396e7c1538737c488ea5d25f7663396d9e1c`.
Trial 10 passed 212 selected tests for the first acquisition increment, before
the final production-confinement exec fixture; it does not qualify trial 11's
additional source bytes. No prior evidence directory was overwritten.

## Required continuation

Implement native acquisition/content-worker leases, request-level accepted
context/concurrency and actual KV/cache accounting, wider tenant/device
adapters, and broader reviewed damaged-state/retention recovery. Then freeze
the consolidated candidate and exercise installed enforcement, hostile
descendants, memory pressure/OOM, cancellation/restart, suspend, migration and
storage crash cases using the actual image. Native Ubuntu and unavailable
hardware qualification remain separately recorded acceptance work.

Do not label this checkpoint 100-percent resource completion, close G2, reuse
older image passes for the new catalog, or advance to Requirement #2.
