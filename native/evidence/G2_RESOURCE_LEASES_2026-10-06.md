# G2 native resource lease development checkpoint

Date: 2026-10-06. Scope: Requirement #1, resource leases/generations only.
Status: native CPU-serving, leased root verification, verified KV layout,
offline exclusion recovery, operator admission, durable request history and transport increments;
**Requirement #1 and G2
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
writer lock. Uncertain, busy or replaced paths remain intact.

Preparation now runs in the fixed AppArmor-confined acquisition service, with
512 MiB memory, 16 processes, no swap/locked memory, finite CPU/IO ceilings and
a 3,700-second lifetime. It acquires a broker lease before download/hashing,
including the live installer's private data mount. Serving and acquisition
share physical memory/process accounting but have independent execution/OOM
domains. Handoff requires broker-observed generation drainage and bounded
residual charges, not a systemd controller's successful exit. Acquisition idle
cache is reclaimed with fresh accounting; reclamation writes never return
capacity by themselves. Local expiry stays latched despite a delayed renewal.

The broker now resolves IO limits to the originating physical whole disk using
bounded trusted sysfs observations. Native outstanding owners/plans/bindings
are checked before interpreting saved allocations; startup failures attempt
fixed-group fencing while preserving the ledger. Reviewed idle inventory
migration preserves history, retained charges, archive references and the
generation floor. No missing/damaged state is reset by broker startup.

The existing listener has finite, UID-partitioned framing/reply workers with
no resource authority. One legacy effect helper can wait for systemd while
the resource coordinator continues maintenance and lease dispatch. A real
socket fixture checks that partial headers and waiting operations cannot
block another complete frame. This is not installed pipeline qualification.

The serving command explicitly disables extra prompt/idle/checkpoint caches,
weight repacking and accelerator work, with fixed F16 KV types and bounded
batching/HTTP threads. Its actual pinned runtime parser accepts all 56 arguments
with only the model identity/descriptor and a private API-key fixture supplied
for this parser check. A negative unknown-option control refuses. No model was
loaded and no runtime listener was started by that check.

Root preflight, activation, rollback and recovery hashing now use the same
fixed acquisition service. Only exact catalog model paths under the supported
native data mounts are accepted. There is no unleased production fallback;
tiny unit fixtures explicitly inject a test-only checksum verifier. Preflight
help and output distinguish the temporary verification lease from future
serving capacity, which is not reserved by preflight.

The image catalog now binds the actual attention shape. Acquisition and serving
parse bounded GGUF-v3 metadata from the same fully checksum-verified descriptor,
with lease checks around every metadata read. Layout mismatch, malformed input,
duplicates, unsupported attention/sharding, bounds violations and cancellation
refuse before download publication or runtime execution. CPU F16 KV tensor
bytes are 301,989,888 for Qwen3-4B and 234,881,024 for Qwen3-1.7B at 2,048 cells.
The mapping/file-cache charge is counted once, and the remaining combined
runtime/scratch ceiling completes the existing worker peak. Inventory output
uses lossless decimal strings. This inventory does not by itself implement
request admission or measure actual model-loading scratch.

`resource_manager/recovery.rs` adds reviewed offline creation of an absent
runtime exclusion inode. It requires loaded idle masks for the model,
acquisition and broker units, no systemd job, empty worker slices, a complete
visible process/thread census and no outstanding ledger generation. Inspection
and publication hold the model operation lock and validated store exclusion;
boot, catalog, mask/cgroup/state identities and ledger review are rechecked
before exclusive creation and file/directory synchronization. A safe existing
inode is inspectable but cannot be recreated. All masks and ledger/receipt bytes
remain intact. The bounded systemd observer uses a kernel output ceiling,
owned PID-handle supervision and a boot-time deadline. These installed-root
commands do not provide product Admin authorization or physical drainage
qualification; the actual combined installed recovery procedure remains pending.

`resource_manager/requests.rs` and the installed operator helper now implement
one preparing/admitted request slot inside the existing worker peak. The slot
precedes template/tokenizer work; exact rendered token IDs and maximum output
are checked against the catalog context before inference. Strict replies bind
caller, serving generation, nonce, token count/digest and result count/digest.
Completion returns the logical slot only. Cancellation, expiry or caller death
durably revokes the serving lease; physical drainage remains controller-owned.
The helper refuses proxying, redirects, malformed identities, cache reuse,
truncation and actual output above the admitted budget, and publishes no text
without an exact completion acknowledgement. The subsequent journal increment
makes request phases durable under the existing private resource-store lock.
Terminal-receipt archival is root-only and reviewed, preserves nonce tombstones,
and never releases a physical lease. Publication uncertainty poisons request
admission; restart never reconstructs live caller handles. Missing older history
requires an explicit offline migration with unchanged physical history and an
acknowledged historical gap. The reference client's direct runtime path and
product export/deletion/custody and retention recovery remain open. No real
model/tokenizer execution is asserted by protocol fixtures.

A separate read-only publisher check retrieved exactly the first 65,536 bytes
of each pinned catalog URL, requiring HTTP 206 and an exact Content-Range.
The observed architecture, layers, embedding, attention/KV heads, K/V widths
and training context match the catalog. The prefix SHA-256 values were
`70560094eeed902a6a3aed2815b72fc7a2a8c18b125d463d8fc4a3abb69cde46`
for Qwen3-4B and
`0a3b30796a4138c37f2e17d004bf51c5195d90b0a731c044be3e57e2fb630f9e`
for Qwen3-1.7B. That observation did not verify either whole file, acquire model
weights or qualify loading. Production still requires the full pinned digest.

Use [the resource register](../RESOURCE_LEASES.md) for the implemented boundary,
operator instructions, finite limits and remaining software integrations.

## Durable request history execution

Latest evidence directory: `D:\LumaOS-builds\g2-resources-targeted-20261006-32`.
It uses the same D:-backed tool image/cache and bounded execution configuration
described below: one CPU, 768 MiB, no extra swap or network, with no WSL settings,
host services or TPM ownership changed. All 203 captured source digests and
53 test-input digests matched the checkout after execution.

| Check | Result |
| --- | --- |
| Resource core | 18 passed |
| Resource manager, recovery, request admission and durable history | 55 passed, including 21 new journal/archival/migration tests |
| Acquisition and storage | 6 passed |
| Broker transport | 23 passed |
| Model lifecycle and supervision | 126 passed; two existing owned fixture entrypoints invoked by their parents, not counted twice |
| Selected Python policy/helper checks | 95 passed |
| Real CLI/Unix/HTTP protocol fixtures | 9 passed with synthetic authorities; no real model or installed controller |
| Formatting, warnings-denied offline locked build, AppArmor syntax and pinned runtime option controls | Passed; syntax/parser checks do not qualify enforcement |
| Real systemd graph verification | Exit 1 because the tool image lacks `apparmor.service`; unchanged installed qualification gap |

Total: **323 passing selected tests**, plus the nine protocol cases and parser
controls. No new Requirement #1 check is skipped. The broader 222-pass Python
regression below belongs to the earlier baseline and was not rerun or added
to this total.

The journal tests cover phase publication and exact durable receipts, lossless
counts, dropping completed caller handles, restart without PID resurrection,
publication failure before/after commit, reviewed archive cuts, nonce retirement,
partial stages and complete orphans, lost cut acknowledgements, stale reviews,
archive-chain corruption, finite inventory/directory/frame bounds and private
file/link/mode checks. Offline migration tests preserve physical receipts and
charges, deny stale reviews/outstanding generations/existing artifacts, retain
interrupted creation outcomes, and keep a never-started ledger uninitialized.
They exercise the core and real filesystem operations in the disposable
container, not the combined installed systemd/locking procedure.

| Retained file | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `3693025cd4d9b274607cc66c6eeb6b02b33781f5ab82b48d20035510535fb1fd` |
| `test-inputs.sha256` | `ec1b2d18aeb4374bb980d93b56ed8b60250396d5d1faca81b369b30f500cc737` |
| `test.log` | `95a4faa5ab4d0773bba82d5756a3b5ff1f2a6bf07137b7039fb6b2364352baf5` |
| `checks/unit-verification.txt` | `cc6d6ba4f56881e50612c693db5577418157f96999327fbac956e538602db498` |
| `checks/unit-verification-exit.txt` | `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` |
| `checks/runtime-options.json` | `d6c5bc021ad939c79d18ba4c18213954e73dee3c4a200d763086f2e0c28c38cb` |

Trial 29 stopped on an internal visibility error. Trial 30 passed its Rust
checks but failed a source-wiring assertion whose test-module boundary had
changed; it is not a passing suite. Trial 31 passed 322 selected checks and
nine protocol cases before the additional virgin-ledger migration case. Trial
32 passed the final 323-check snapshot above. Every earlier directory remains
retained; its evidence does not qualify subsequent changed bytes.

## Operator admission baseline execution

Evidence directory:
`D:\LumaOS-builds\g2-resources-targeted-20261006-28`.

- Docker root: `/mnt/luma-build/docker`, backed by D: storage.
- Tool image: `luma-utc-targeted-tools:20261005`, image ID
  `sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
- Cargo cache: `luma-g2-rust-targeted-cache-20261001`, also on D:.
- One CPU, 768 MiB memory with no extra swap, 256 PID ceiling, one Cargo job,
  no network and no `CAP_SYS_ADMIN`, host devices or host-service mutations.
  `CAP_KILL` permits the production root supervisor to terminate its owned
  UID-988 child inside the disposable container's PID namespace.
- Source snapshot mounted read-only; test output and temporary/build data on
  D:-backed mounts. WSL memory settings were not changed.
- Warnings denied, debug symbols disabled to reduce compiler memory. This is
  an unoptimized development binary, not a qualified production image.

| Check | Result |
| --- | --- |
| Native resource core | 18 passed, zero failures/ignored |
| Native adapter, heartbeat, offline recovery and request admission | 34 passed, zero failures/ignored |
| Acquisition target/launch/handoff/root verification routing | 4 passed, zero failures/ignored |
| Storage topology resolver | 2 passed, zero failures/ignored |
| Existing broker transport plus ingress/resource/ACL checks | 23 passed, zero failures/ignored |
| Model lifecycle/supervision, acquisition generations, verified layout and exclusion creation | 126 passed; two pre-existing owned child entrypoints excluded from top-level discovery |
| Resource/model/health/VM/broker packaging and operator-helper Python checks | 94 passed |
| Real operator CLI, Unix IPC and HTTP protocol cases | 9 passed; synthetic broker/runtime replies, no real model or installed controller |
| Broader native Python regression on D:-backed Linux ext4 storage | 222 passed, zero failures; two existing UTC pinned-source-fixture checks skipped |
| Cargo formatting and offline locked build | Passed |
| AppArmor no-load/no-cache syntax parse | Passed; not an enforced profile test |
| Digest-pinned b11100 runtime option parsing | Positive exit 0; unknown-option control exit 1; no model loaded |
| Real systemd unit graph verification | Exit 1: tool container lacks `apparmor.service`; installed graph qualification remains pending |

Total: **301 passing selected tests**, plus nine CLI/Unix/HTTP cases and the
runtime parser/control checks.
The two model entrypoints are invoked by
their parent process-boundary fixtures; they are not counted as extra passes.
Unrelated Rust Admin tests were not selected. No new resource test is ignored and
no unimplemented resource code path is hidden behind a successful placeholder.
The source-level Python checks are wiring guards, not installed enforcement.
The broader regression includes the 94 selected Python checks, so its 222 passes
are not added to the targeted total. Its two skipped UTC-source tests are not
claimed as passing and no new Requirement #1 test is skipped. The extra run
used 512 MiB with no extra swap, one CPU, an isolated container and the same
read-only snapshot; temporary data used the existing D:-backed Linux volume.

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

The 12 ordinary layout tests cover both exact KV inventories, runtime width
defaults, every required shape mismatch/type, duplicates/missing fields,
unsupported layouts, every truncated fixture prefix, bad header counts,
array/string/type/boolean limits, tokenizer-array scanning, lease cancellation,
checked overflow and peak exhaustion. Actual-file tests verify that digest and
layout validation retain one original inode despite pathname replacement, and
that a matching digest alone does not admit an incompatible attention layout.
No layout test is ignored and no production fixture override was added.

Ten ordinary adapter recovery tests cover canonical real/effective/saved/fs
UIDs, changed reviews and every bound identity, malformed/stale/existing-inode
refusal, observation/publication failure, exact root-owned unit mask paths,
loaded systemd mask/job states, hidden/subset/malformed proc mount refusal and
finite census/deadline bounds. One test launches an actual UID-989 child outside
the model slice in the disposable container: the census refuses until that
owned child is killed and reaped. Another exercises the observer's real kernel
file-size ceiling, failed helper and owned deadline teardown. The model test
creates the actual root-owned lock inode, proves competing flock refusal, and
preserves existing files/symlinks instead of recreating them. The additional
Python source guard checks wiring only. No installed unit was masked or stopped
on the developer machine by these tests.

Twelve ordinary request-admission Rust tests cover atomic preparing-slot
reservation, exact replay, foreign/stale owners, every finite budget and nonce
bound, checked context overflow, exact context-edge admission, prompt/result
drift, logical-only completion, physical charges held through cancellation,
expiry/restart fencing, uncertain observations and finite receipt exhaustion.
The schema test found and fixed internally tagged unit-variant acceptance of
unknown inspection fields; inspection now uses a closed struct variant. Real
PID handles pin caller generations, and an actual owned root child is killed
and reaped to prove request-owner exit yields revocation without capacity return.

The 28 helper Python tests include exact-token ordering, bounded fixed-loopback
transport, non-proxy/redirect behavior, malformed UTF-8/JSON/identities/counts,
over-context prompts, actual output overruns, cache reuse and truncation,
substituted receipts, cancellation at each uncertain step and whole-operation
deadlines. A real Unix socket pair exercises framing and kernel credentials.
Nine separate disposable-container cases run the isolated helper CLI through
the actual fixed broker socket and loopback HTTP path. They cover valid output,
wrong identity, over-budget output, truncation, cache reuse, duplicate/malformed
JSON, denied admission and a socket reply actually lost after fixture completion.
Only the exact successful acknowledgement publishes text. These are protocol
fixtures, not real-model or physical-controller qualification. The native CLI's
fixed `exec` launch preserves the caller PID generation rather than creating an
unsupervised helper child; source wiring and the locked build check that launch.

## Retained evidence integrity

The captured manifest contains 202 source files. All manifest file digests and
all 53 separately captured native test-input digests were checked against the
current checkout after execution and matched. Documentation outside the native
image/source capture is explanatory, not deployment evidence.

| Retained file | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `e239f22b70b22c65a79294811bc44f8d6fd809d54c856a188c2723eb47fc16d3` |
| `test-inputs.sha256` | `446364a72091e308535d3b3f5065895efb13764a8d8f6885455716b827e8c1e1` |
| `test.log` | `5a908668607d55fe9313768d281136ce598cb378a182950828ce2bc9b9b12ffe` |
| `checks/unit-verification.txt` | `cc6d6ba4f56881e50612c693db5577418157f96999327fbac956e538602db498` |
| `checks/unit-verification-exit.txt` | `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` |
| `checks/runtime-options.json` | `d6c5bc021ad939c79d18ba4c18213954e73dee3c4a200d763086f2e0c28c38cb` |
| `native-python-regression-ext4.log` | `0e3454373b4eab543563eea0d56c72afa07e129f668a4aa46ee9cda68b0dc9c9` |
| `native-python-regression.log` (failed Windows bind temporary storage run) | `ff18f984a2d5bd9bab5371a44a03ddee6462e35eb6c0f80ff48e847ed568728b` |

The first broader Python run used a Windows-backed D: bind directory for
temporary files. It finished with 23 errors and two existing skips: custody
mode checks, symlink/hard-link operations and private TPM fixture paths could
not use the required Linux filesystem semantics there. That failed log is
retained and not counted as a pass. Repeating all 224 discovered checks with
the same source/tool image and limits, using the existing D:-backed Linux ext4
Docker volume, yielded 222 passes and only the two existing UTC source-fixture
skips. No production custody check was weakened and no host TPM was accessed.

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

Trial 11 passed the prior 213-test acquisition-generation baseline. Trials
12/14/16 found outdated source-wiring assertions; trial 13 found a wrong profile
ID in a new test. Trial 15 passed 226 selected tests before the transport/cache
changes. Trial 17 passed 233 tests but failed the runtime parser check because
the parser opens its API-key file even with `--help`; it also encountered a
runner-script edit during execution. Trial 18 used an explicit private parser
fixture and pipeline error propagation, passed its 233 selected tests and parser
checks, and had its captured input hashes verified against that checkout. Earlier trials remain
retained and are not evidence for the latest bytes.

Trial 19 passed 234 selected tests for the root verification increment before
layout integration. Trial 20 passed its Rust checks but failed one Python
source-wiring assertion that expected an equivalent call in a different textual
form; it is not a passing suite. Trial 21 includes the corrected assertion and
the additional descriptor/type tests, passed its earlier 248 selected checks,
and had all captured source/test hashes verified against that checkout.
Trial 18 remains the earlier 233-test transport/acquisition checkpoint, not
qualification of this newer catalog or layout implementation.

Trial 22 stopped on the new UID parser's leading-zero rejection test and is not
a passing suite. Trial 23 passed its 259 selected checks before the final proc
parser and observer changes. Trial 24 passed the prior 260 checks and its
201 captured source and 53 test-input digests matched that checkout.
Trial 25 stopped on the new closed inspection-schema test and is not a passing
suite. Trial 26 passed its 298 selected checks; trial 27 passed 301 checks and
nine protocol cases before the final CLI exec and true lost-socket-reply changes.
Trial 28 passed the 301-check operator-admission baseline and nine cases above,
with all 202 source and 53 test-input digests verified against that checkout,
subsequently committed as `a21b5c4`. Earlier
directories remain retained and do not qualify changed bytes.

## Required continuation

Integrate content/workflow leases and all remaining inference consumers, close
the direct-runtime bypass, complete governed request export/deletion/custody and
retention recovery, wider tenant/device
adapters, and broader reviewed damaged-state/retention recovery. Then freeze
the consolidated candidate and exercise installed enforcement, hostile
descendants, memory pressure/OOM, cancellation/restart, suspend, migration and
storage crash cases using the actual image. Native Ubuntu and unavailable
hardware qualification remain separately recorded acceptance work.

Do not label this checkpoint 100-percent resource completion, close G2, reuse
older image passes for the new catalog, or advance to Requirement #2.
