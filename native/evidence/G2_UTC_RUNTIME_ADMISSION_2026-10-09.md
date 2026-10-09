# G2 UTC runtime admission evidence

On 2026-10-09, the native source gained immutable producer admission and the
fixed UTC measurement endpoint, followed by cold-start acquisition handling.
The final targeted D-backed evaluation passed. **Protected UTC deployment,
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

## Executed evaluation

Final evidence directory:
`D:\LumaOS-builds\g2-utc-runtime-20261009-03`.
The frozen runner finished with exit zero and `UTC_RUNTIME_SWEEP_PASSED`.
All 225 captured build inputs and 65 native support inputs matched the final
checkout by raw-byte SHA-256; the retained CI workflow also matched.

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

## Required work not closed

The image still needs the qualified producer dependency and provenance,
runtime inventory, producer UID/GID 987, enforcing producer/keeper profiles and
units, and a protected composition able to inspect the admitted process.
No installed command currently activates this endpoint. Authenticated human
acquisition/query control, independently reviewed certificate seed delivery,
production history delivery and explicit recovery/lifecycle integration remain
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
