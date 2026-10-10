# G2 UTC runtime admission evidence

On 2026-10-09, the native source gained immutable producer admission and the
fixed UTC measurement endpoint, followed by cold-start acquisition handling.
The runtime admission evaluation passed. **Protected UTC deployment,
Requirement #1 and G2 remain incomplete.** No clock, host service, physical TPM,
ownership, account or WSL setting was changed; no final image was rebuilt.

## Implemented boundary

`utc_runtime.rs` accepts only the fixed read-only release manifest and bounded,
ordered artifact inventory. It retains original file/parent descriptors,
requires exact SHA-256/length and metadata, and refuses links, writable or
special-mode files and ambiguous paths. The compiled approved policy and fixed
NTS-only configuration must match the installed artifacts exactly. Configuration
line endings are pinned to LF in Git because admission compares bytes.

Live producer admission checks the actual executable and library mappings,
namespace-visible artifacts, closed arguments/environment, kernel credentials,
enforcing AppArmor label, unit cgroup, capability bounds, no-new-privileges,
seccomp mode and task inventory. It checks kernel procfs rather than accepting
caller-supplied process metadata. Executable anonymous mappings refuse except
the kernel-reported vDSO and the exact legacy x86 kernel vsyscall mapping.
This is not an audit of the complete kernel, loaded seccomp program or NTS
dependency, nor proof of an absolute physical clock-rate envelope.

The protected supervisor's source path binds only
`/run/luma-utc/measurements.sock`, under a root-owned 0710 directory with producer
GID 987. Descriptor-relative creation sets the socket to root:987 mode 0660,
enables kernel message credentials, and retains its identity. Acquisition derives
the PID/credentials/epoch from the actual bounded datagram and verifies the live
runtime; it takes no caller PID, runtime digest, clock seed or time estimate.
Existing sockets and replacements refuse without deletion. Failed acquisition
does not silently retry an old endpoint or manufacture a clock observation.

Normal receiver construction requires the private runtime admission. Numeric
attachment is compiled only for isolated tests. Every poll/final quiet check
revalidates the live process and retained release objects. The first accepted
round is preserved, not discarded as a handshake, and consumed in queue order.
The initial step-watch and clock capture precede binding and move into the
keeper once. A later startup clock cannot invalidate all first-round samples
merely by being newer than their acquisition boundary.

Zero/one-source startup rounds retain the Acquiring state and return no estimate.
Their epochs, clocks, sequence, sample identity/age and producer heartbeat still
undergo validation. This wait path exists only before the first candidate.
Subsequent quorum loss, malformed state, heartbeat loss or an invalid boundary
fences; a later valid round cannot revive the stream. Shared history still comes
from the existing internal Admin semantic reader, never a saved UTC estimate.

## Runtime admission evaluation

Final evidence directory:
`D:\LumaOS-builds\g2-utc-runtime-20261009-03`.
The frozen runner finished with exit zero and `UTC_RUNTIME_SWEEP_PASSED`.
All 225 captured build inputs and 65 native support inputs matched the checkout
at that checkpoint by raw-byte SHA-256; the retained CI workflow also matched.

- 176 ordinary targeted Rust passes, including eleven new runtime tests, one
  receiver admission test and two cold-start stream tests. The selected binary
  discovered 749 tests; the full ordinary Rust suite was not rerun.
- Six explicitly selected fixture invocations passed: datagram, receiver/keeper,
  final-queue and shared-history composition, plus retained C binary/JSON
  interoperability. The four kernel suites exercised forty cases: sixteen
  datagram, eleven keeper, one queue and twelve shared-history cases.
- All 305 native Python regressions passed with no skips, including the two
  retained pinned-upstream checks and eight new UTC composition checks.
- Formatting and the locked offline production build passed with warnings
  denied. No AppArmor profile was loaded and no time daemon was run.

The new positive socket test executes descriptor-relative binding, permission
and owner setup, actual SCM credentials, nonblocking/CLOEXEC behavior, duplicate
bind refusal and socket preservation after descriptor closure. Other new tests
cover exact inventory/roles, closed wire fields, mutable-file refusal, retained
descriptor replacement and identical-byte rewrite detection, hardlinks, parent
permissions, capability/confinement controls, loader/TLS environment injection,
mapped-code/device/inode/offset substitution and kernel executable-page identity.
No test downgrades the production read-only or confinement admission checks.

The ordinary filtered runs reported eight existing fixture-dependent ignores.
The four UTC parent fixtures and both C fixtures were then explicitly executed;
the sender helper is exercised by its owning parent. The real-PAM/software-TPM
Admin bootstrap fixture was not rerun in this evaluation. Shared-history tests
use fake checkpoint/observation adapters: their kernel sockets and clocks are
real, but they do not qualify TPM transport, live NTS or authenticated UTC truth.

Tests used the cached tools image
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`,
Docker root `/mnt/luma-build/docker`, and the existing D-backed Rust cache.
The main container had one CPU, 1536 MiB memory/memory-plus-swap, 128 PIDs,
no network, no host devices or Docker socket, and only the bounded fixture
capabilities. CAP_SYS_TIME and CAP_SYS_ADMIN were absent. Formatting had a
256-MiB ceiling. No WSL memory increase or heavyweight image/model run occurred.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `edcb3ca2424895ad8615363a76311d55230ef4cd76f0a427415595be8e6c085d` |
| `checks/runner.sh` | `1fd06c991155f674223f2fdbdba2ed26308ec24336ce44dd0d3c01a67a4d4d05` |
| `test.log` | `b0250393e4665c17cd406d147eca655adba53a8c2a6359b0e9cdb5ade822261b` |
| Production executable in D-backed cache | `5e19de5cb9cf8f0f987c912bd0866718024314fcb0dbd405c12eb6b586fe2af4` |

Trials 01 and 02 remain retained. Trial 01 passed the Rust/kernel/C checks but
failed two source assertions after the constructor/test-boundary refactor.
Trial 02 found an owned-fixture borrowing error at compilation. Trial 03 includes
the fixes, positive binding test and final cold-start changes. Earlier ad hoc
compilation also detected unsafe-call annotation and unused-method issues; those
were repaired before the final frozen evaluation. Older passes are not credited
as qualification of the final code.

## Internal history delivery implementation

The subsequent source increment adds `execute_history_live`, which accepts the
actual ephemeral PAM account and admitted bound stream rather than arbitrary
authentication JSON or an observation-producing callback. It borrows the same
exclusive Admin journal Store, replays the current history binding, and requires
that exact binding when obtaining new live evidence. The lower-level callback
transaction remains private; its externally callable arbitrary adapter is
compiled only for fixtures.

`HistoryDelivery` borrows the stream and has no wire form. Observation fields
are private to the stream, with a fixture-only numeric constructor. Production
delivery polls the actual receiver, derives the admitted runtime digest and
producer/keeper context, and checks the proposed floor against the fresh
candidate. Queue, peer, clock and step-watch checks repeat before returning.
It cannot obtain production evidence from a raw fixture receiver or replace the
bound checkpoint with a freshly opened different head.

Source checks now repeat after potentially blocking semantic replay and PAM
checks at each journal authorization boundary, including immediately before
TPM advancement. A successful checkpoint-changing write, or any error including
failed installed-environment admission, invalidates the old stream. Historical
acknowledgement obtains no new live evidence and cannot redispatch the write.
This does not return a time capability or activate grants.

The internal adapter is not connected to an installed human-control endpoint.
No independent seed, producer service, keeper service, system clock change,
production TPM write or native-image qualification was executed by this work.

## History delivery evaluation

The final implementation has passing source evaluation recorded in two frozen
D-backed directories. Trial 05 passed 178 ordinary targeted Rust tests, all six
explicit fixture invocations and the locked offline production build with
warnings denied. The kernel suites exercised 42 cases, including two new
history-delivery cases: a raw receiver cannot supply admitted runtime evidence,
and a reopened different checkpoint cannot refresh the retained stream.
Two new ordinary tests exercise every one of nine source-refusal boundaries and
source loss during the final PAM check without TPM dispatch. The binary
discovered 751 tests; the full ordinary Rust suite and real-PAM/software-TPM
bootstrap fixture were not rerun.

Trial 05 then failed three stale Python source-scope assertions. Their boundaries
were corrected without changing any Rust/runtime build input. Trial 07 proved
its complete 225-file build-input manifest byte-identical to trial 05 and passed
all 307 native Python checks with no skips, plus formatting. Its runner exited
zero with `UTC_HISTORY_PYTHON_RECHECK_PASSED`. All 225 build inputs, 65 native
support files excluding bytecode caches, and the CI workflow matched the final
checkout by SHA-256. Rust/kernel/C/build results are from trial 05; trial 07
does not claim to have rerun them or upgraded them to installed qualification.

The ordinary Rust runs still report eight existing prerequisite-dependent
ignores. The four parent UTC kernel fixtures and both C fixtures were explicitly
executed; their owned sender is exercised by its parent. Shared-history/TPM
semantics use fake checkpoints in these fixtures. No fully admitted installed
NTS-to-PAM-to-TPM positive journey was executed.

The final Python container used one CPU, 512 MiB memory/memory-plus-swap and
128 PIDs, without network, host devices, CAP_SYS_TIME or CAP_SYS_ADMIN.
Its Linux scratch filesystem was inside the verified D-backed Docker root.
No WSL memory setting, host service, clock, account or TPM ownership changed.

| Retained history delivery artifact | SHA-256 |
| --- | --- |
| Trial 05 and 07 `source/build-inputs.json` | `496b94d2c015b22d901788c6dc03f8db4dbcf407259ba632a7dd96221aee73c1` |
| Trial 05 `test.log` | `c20af28c1f45f1bdea13d66accd8ccdf8b6780b860cd87580c341b414893ace2` |
| Trial 07 `checks/runner.sh` | `485e75fb64c565b269c3767840557e12534f1befd8812d8aff34169fedc5d358` |
| Trial 07 `test.log` | `18baf9fa98dd248207cecf93aec1cc50d6880e93a20d40c026a0bba4252038df` |
| Production executable verified in trial 07 | `e10a4f40850f1e4fe27bbf91db9f53f6285f689e3b490035228cfd07edf63f0f` |

Trials 04, 05 and 06 remain retained. Trial 04 exposed the fixture's attempt to
read another writer's new head through its intentionally stale Store; the
corrected case reopens current history but keeps the old stream. Trial 06 used
Windows-filesystem temporary storage, encountered excessive initrd I/O and
Linux fixture filesystem incompatibilities, and was stopped after verifying
the exact owned container source mount. Trial 07 uses Linux scratch on D.
No failed/cancelled trial is counted as a complete passing sweep.

## Required work not closed

The image still needs the qualified producer dependency and provenance,
runtime inventory, producer UID/GID 987, enforcing producer/keeper profiles and
units, and a protected composition able to inspect the admitted process.
No installed command currently activates this endpoint. Authenticated human
acquisition/query control, independently reviewed certificate seed delivery,
installed history delivery and explicit recovery/lifecycle integration remain
software work. Current status still denies trusted UTC and timed authority.

The approved total rate envelope, live certificate/NTS attacks, loaded confinement,
clock steps and suspend/resume, outage/interruption behavior and final-image
journeys require separate qualification. The fixed 25-ppm drift and 25-ppm slew
configuration does not prove the total 100-ppm envelope. See the
[approved design](../TRUSTED_UTC_DESIGN.md) and its primary-source references.

Usable-account activation/password aging, original Admin password/lock recovery,
finite assignments and resource/inference/effect grants, broader workflow and
retention/reconstruction also remain implementation work. Passing this source
increment does not close any of those bundles or authorize Requirement #2.
The [completion register](../G2_SOFTWARE_STATUS.md) records their current scope.
