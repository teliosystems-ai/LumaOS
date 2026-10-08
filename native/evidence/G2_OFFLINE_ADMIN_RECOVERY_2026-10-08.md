# Offline Admin recovery software checkpoint

Date: 2026-10-08. Requirement #1 and G2 remain open. This checkpoint implements
installer recovery-verifier custody and reviewed product-generation rotation;
it does not qualify a final image or complete account/UTC/grant integration.

## Approved decisions and implemented scope

[ADR-0011](../../docs/adr/0011-local-utc-runtime-and-offline-admin-recovery.md)
records the owner's approval of fixed peer-authenticated local UTC endpoints
with a confined keeper, and installer-enrolled offline Admin recovery custody.
No host clock, accounts, services, WSL configuration or physical TPM changed.
UTC runtime implementation/qualification is not claimed by this approval.

The installer generates a separate random 256-bit credential in locked,
nondumpable, wiped storage. It displays the credential only on `/dev/tty` and
requires hidden re-entry before destructive partitioning. The principal registry
persists only its salted, domain-separated verifier, bound to the installation,
original Admin, UID 1001 and recovery credential generation. The digest preimage
also uses locked storage; packaged libcrypto computes SHA256 and
[compares fixed-width credentials without content-dependent comparison time](https://docs.openssl.org/3.0/man3/CRYPTO_memcmp/).
No production secret enters arguments, environment, JSON, files or diagnostics.

Explicit principal adoption anchors the verifier in the existing TPM journal.
Legacy registries without a verifier retain their old canonical serialization
and refuse recovery; no automatic enrollment or root/owner fallback exists.
`admin-custody-recover REQUEST` is a separate installed local-terminal ceremony.
A private, nonserializable offline-credential proof binds the exact command and
checkpoint head, original registry handles, TPM epoch/latest observed clock and
the protected boot/process/root lifetime. The 30-second BOOTTIME deadline starts
after preparation and never renews on use. The operator records/confirms a fresh
replacement credential and reviews the exact transaction before dispatch.

One checkpointed catalog event advances both the Admin principal and recovery
credential generations. Historical writer prefixes and the installer registry
remain unchanged. Ordinary catalog/PAM paths and the general Admin service
cannot supply recovery verifiers or substitute PAM for that proof. A reviewed
write attempt consumes the in-process proof; errors/unwinding fence it. An
uncertain TPM outcome retains pending/event files and cannot be retried or reset.

## Retained evaluation

Final snapshot: `D:\LumaOS-builds\g2-principal-session-20261008-13`.
Runs 11 and 12 remain retained: 11 exposed source-policy extraction failures
from newly placed test-only helpers; 12 passed before the final persistent
recovery clock-floor refinement. Only snapshot 13 represents this checkpoint.

The runner used offline D-backed Docker, one CPU, a 1-GiB memory/no-swap bound
and narrowly enumerated fixture capabilities. No host TPM or Docker socket was
passed into the containers. Formatting, warnings-denied offline Rust build,
167 ordinary targeted Rust tests and 54 selected Python policy checks passed.
The targeted filters cover observer/authentication/principal/recovery/governance/
roles/journal/Admin service/broker code. Actual fixture evaluation also passed
six PAM cases, three kernel human-peer modes, bounded credential/descriptor/
thread/FSUID checks, 49 PAM/kernel-peer/software-TPM catalog requests, seven
governed login issuance cases and twelve guarded projection cases.

Five new recovery markers passed through the same disposable native TPM store:

- Wrong credential and replacement of a credential with itself refuse.
- Genuine PAM cannot substitute for the private recovery proof.
- The checkpoint commits both generation changes.
- The previous governed session and consumed recovery proof close.
- Old credentials refuse after two recoveries; immutable registry bytes remain.

The integration deliberately uses **public test credentials**, with an
independent Python/hashlib verifier encoding. It tests native composition, not
human production custody. Deterministic checkpoint tests cover wrong review,
identical registry replacement, interleaved history, TPM reset/restart/regression,
expired proof, an injected later clock floor and a lost TPM reply. Injected
conditions do not constitute physical TPM, suspend or firmware evidence.

The full native Python regression passed 271 of 273 tests. The two existing
upstream UTC publisher checks skipped because this offline lane lacks their
isolated pinned-source fixture; they are not counted as passes. Both Admin and
credential-observer AppArmor profiles parsed without kernel loading. The 218
build-input files, 58 test-input files and frozen CI workflow matched the current
checkout after evaluation.

SHA256 records:

| Artifact | SHA256 |
| --- | --- |
| Build-input manifest | `feb0ea619bbc4ecf4d61c9ba42354e09eb494db4b5e792901de43585d52e621f` |
| Test-input manifest | `dad724f6f1a5f2dc87a33fa1ad3212059a38b76711e309e0496a36edbd9d11d3` |
| Targeted log | `6e02628294380dc4e8c4bdc1b12920fae76d63088d2ac330e4a2388dee85370e` |
| Frozen targeted runner | `2f721d30b5746fd63ae9d1b20808dfdef51005731fbdf5fa81affc68518767b6` |
| Native executable | `45a420276f4634e9ba3a537d1a69dcf0db7fa36c2f85ed6575b8dc7071c91e07` |
| Full native regression log | `2adacf1e297cc15dad39f0e831e51ac383492b165b4899ae6f5e0ee3e59cd58e` |
| Frozen regression runner | `4d668cb75815a509af2594b78cdcf51f3e2af904d976c399acdeb03c4fd3a14e` |

## Work still required

This does not reset Unix passwords, create/delete accounts, transfer Admin,
recover signing keys, reconstruct damaged authority or grant effects. Existing
maintenance/catalog consumers still need governed session integration. Complete
account/credential transactional lifecycle and interrupted-recovery handling,
the installed protected UTC producer/keeper and history/control delivery,
time-bound assignments and principal-bound folder/effect grants, and current
admission checks at worker/workflow/inference/effect boundaries. The broader
resource completion register remains in [RESOURCE_LEASES](../RESOURCE_LEASES.md).

Installed terminal custody, enforcing confinement, crash/reboot/publication,
physical TPM/security/recovery qualification, the consolidated final image and
the separate native Ubuntu tests remain unexecuted. Source checks and a
software TPM cannot close these gates.
