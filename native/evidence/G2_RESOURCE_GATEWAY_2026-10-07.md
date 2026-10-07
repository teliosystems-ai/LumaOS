# Native reference inference gateway development checkpoint

On 2026-10-07, Requirement #1 gained an opt-in reference inference gateway over
the existing broker socket. Source and selected protocol regressions pass.
**Requirement #1 and G2 remain open**: installer credential migration, broader
resource integrations and installed qualification are not complete. Requirement
#2 has not been started.

## Implemented boundary

The broker now mediates one bounded transient job, authenticates the reference
process generation and persists preparing, admitted and completed receipts.
Canonical original messages, exact rendered tokens and the verified result have
distinct digest bindings. Prompts/results are not journal content or recoverable
jobs after restart. UID-990 caller identity is durable; old root receipts retain
their exact canonical representation without an added UID field.

Only the exact lease-owning supervisor can register readiness and dispatch work.
Runtime IO executes in its existing leased unit, not in the broker. Physical
revocation/drainage precedes gateway maintenance; fetch, acknowledgement and
non-cancellation replies require the current active physical generation, live
owner handle and matching readiness. Exact terminal acknowledgement/cancellation
retries preserve caller fences and do not clear another job or return capacity.

`LUMA_MODEL_TRANSPORT=native-broker` selects a client with no runtime credential,
HTTP endpoint or fallback. It verifies the output and exact acknowledgement
before publication. Runtime HTTP has fixed authority, bounded framing, local
lease checks and one boot-time request deadline. Malformed runtime JSON produces
a static error, without private field names or values in supervisor diagnostics.
See [the resource contract](../RESOURCE_LEASES.md) for limits and the deliberately
unchanged legacy installer default.

## Execution and evidence

Evidence: `D:\LumaOS-builds\g2-resources-targeted-20261007-08`.
All **208 source files and 88 test inputs** matched the checkout after execution.
The frozen runner exited zero. Builds, compiler cache, temporary test state and
evidence used D. Execution used the pinned D-backed tool image, one CPU with CPU
affinity, a 1-GiB container ceiling, no extra swap or network, offline locked
Cargo and warnings denied. No WSL configuration, host service, installed
reference credential or TPM ownership changed.

| Selected check | Actual result |
| --- | --- |
| Resource core | 18 passed |
| Native manager, requests, peer proof, history and recovery | 87 passed |
| Acquisition and storage | 6 passed |
| Broker transport | 25 passed |
| Model lifecycle, supervision and gateway driver | 130 passed |
| Python policy, native client and selected reference regressions | 153 passed; one existing Windows-junction-only check skipped on Linux |
| Compiled native history CLI over framed Unix IPC | 24 cases passed against synthetic root authority |
| Compiled native model-chat CLI over Unix and HTTP | 11 cases passed against synthetic authorities |
| Formatting, warnings-denied build, AppArmor syntax and 56 pinned runtime parser options | Passed; no model loaded or installed enforcement qualified |
| Real systemd unit graph verifier | Exit 1: the tool image lacks `apparmor.service`; not a passing installed graph |

Total: **419 passing selected tests plus 35 CLI protocol cases**. Two existing
owned-child entrypoints are ignored at top-level but invoked by their parent
fixtures, not counted twice. No new Requirement #1 check is skipped. The Unix
client fixture authenticates a real root socket peer but asserts a synthetic
client UID; the runtime pipeline uses real TCP with synthetic broker authority.
Neither fixture proves installed UID/cgroup/AppArmor enforcement or real-model
execution. The larger whole-program Python/Windows suite was not rerun.

Earlier attempts remain retained in the same dated directories. Three 768-MiB
compiler attempts ended with SIGKILL. Later attempts exposed a corruption-fixture
construction error, a formatting-sensitive source assertion and a helper return
type mismatch; each was corrected before this final capture. The preceding
successful run remains separate from this finalized privacy-hardening source.

## Evidence digests

These SHA-256 values identify unsigned laboratory evidence, not production
signing custody or reproducibility attestation.

| Artifact relative to the evidence directory | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `3865911c1e36d7cc7c17f0fc10a1646db4745f17073c7469e0c0492b4c4bf888` |
| `test-inputs.sha256` | `2091b2ea1f784d16ffad151aeef9df51bfca12c52cd3bbbf71d312f6cac060a1` |
| `test.log` | `f2cc007c09a58da5a76a2b3b8e257da3e5388abbfbcb18778cd6245e568c16c5` |
| `checks/targeted-runner.sh` | `428024adca5343348dd66217cf9bd1a6164e92224678db08d33d730360964f56` |
| `checks/sweep-exit.txt` | `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` |
| `checks/unit-verification.txt` | `cc6d6ba4f56881e50612c693db5577418157f96999327fbac956e538602db498` |
| `checks/unit-verification-exit.txt` | `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` |
| `checks/resource-history-artifacts.sha256` | `565b8c2bbd1584a073404114a96baa348feb777d2201fe1ee1a482966d4b5b84` |

The compiled native binary digest is
`0484d070f3c6bc15137a57799d66a3392c7f31589777e7db9c8b58ef61d4c9a2`.
The existing test-only command-line preload digest is
`a0e259b7847aebbd3b1eb46970d83b5e7edc35ed1150a06f69b7a768bc71eb73`.
That preload is not installed production code.

## Work still required

The next software work is reviewed key rotation and default reference migration,
including activation, rollback and recovery so old exposed keys cannot return.
Changing only an environment file is insufficient. Content/workflow leases,
product principal/session authorization, broader consumers and tenant/device
generation adapters, and governed retention/export/deletion/recovery remain
open. Their scope is retained in [the completion register](../G2_SOFTWARE_STATUS.md).

The final image, real model/tokenizer execution, installed security enforcement,
descendant drainage, pressure/OOM, suspend and storage/crash/restart/migration
qualification remain subsequent evaluations, including the separate native
Ubuntu machine. This checkpoint does not mark the package production ready or
authorize Requirement #2.
