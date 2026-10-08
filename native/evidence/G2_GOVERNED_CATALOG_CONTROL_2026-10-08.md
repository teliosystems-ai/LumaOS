# Governed Admin catalog control software checkpoint

Date: 2026-10-08. Ordinary native Admin catalog/status control now uses governed
principal sessions. Requirement #1 and G2 remain open: account lifecycle,
installed trusted UTC, grants and admission consumers are not completed by this
checkpoint. No final image or installed/physical qualification is claimed.

## Implemented control boundary

CLI maintenance, explicit principal adoption and the human socket service now
prepare an exact governed login before starting PAM. They release journal/TPM
writer locks during human authentication, retain the original registry handles,
and consume the new authenticated account into the session. Earlier PAM,
different accounts, replaced registry files, intervening checkpoint changes and
TPM clock/epoch discontinuity refuse issuance. IPC retains the original kernel
process/connection and current-credential observer checks.

Catalog authority has a private purpose distinct from a general-principal
session. Only the original enrolled Admin can use it. Explicit bootstrap permits
finite catalog control before principal adoption without manufacturing general
principal or grant authority; after adoption the session binds the current
governed Admin generation. Bootstrap and offline recovery custody remain
separate ceremonies. No root, TPM-owner or raw-PAM ordinary catalog fallback
exists in the production executable.

Status brackets its complete semantic read with the session replay and PAM.
Mutation preparation does the same, then creates a private one-use continuation
bound to the exact command, request, installation and prior checkpoint head.
It retains original registry handles and the latest observed TPM clock floor.
Actual PAM and, for IPC, the live peer bracket execution and final results.
Execution consumes the continuation by value; its drop guard closes the session
after inspection, no-op, replay, commit, refusal or unwinding. It cannot silently
refresh to a new head after its own write. Review and commit require separate
fresh authentication.

The existing append path still rechecks the exact semantic inputs and live
writer before pending preparation and TPM dispatch. A deliberately changing
head is not treated as an ordinary read projection. Uncertain TPM outcomes
retain journal/event evidence and refuse automatic retry or reset. Historical
events preserve the writer generation at their original journal prefix.
Raw callback catalog executors are compiled only for deterministic primitive
tests; ordinary software-TPM service fixtures now use the production control
implementation with owned governed sessions.

## Retained evaluation

Final snapshot: `D:\LumaOS-builds\g2-principal-session-20261008-16`.
Run 14 retains a fixture closure-lifetime compilation failure. Run 15 passed
Rust/build/kernel/PAM checks but stopped on one formatter-sensitive policy
assertion before catalog integration execution. Only snapshot 16 represents
the final evaluated source.

The offline D-backed Docker runner used one CPU, 1 GiB without swap and narrowly
enumerated fixture capabilities. No host TPM or Docker socket was passed into
the containers. No host account, service, clock, WSL setting or physical TPM changed.
Formatting, warnings-denied offline native compilation and 168 ordinary Rust
tests passed, along with 55 selected Python policy checks. The nine ordinary
Rust groups passed 8, 15, 14, 3, 66, 10, 16, 14 and 22 tests respectively.
Ignored disposable-kernel/software-TPM tests are not included in those totals;
the relevant integrations were executed explicitly afterward.

The real PAM/software-TPM composition validated all 49 human kernel-peer
catalog scenarios through the governed control path, including pre-adoption
operation, explicit adoption, principal changes, Admin rotation, historical
replay, invalid review, registry/account changes and peer exit. Seven governed
login issuance cases, twelve protected-projection cases and five existing
offline recovery cases also passed. Nineteen catalog markers additionally
verified:

- Current-generation status, earlier PAM refusal, wrong principal and request
  scope refusal, and identical-byte registry replacement refusal.
- Inspection without writes, invalid review refusal, reviewed commit, stale
  head refusal, and replay/no-op without another TPM extend.
- Exact command/request continuation binding and consumption after inspection.
- Closure without a journal write after invalid review, deliberate unwinding,
  registry replacement, logout, and injected in-process clock-floor/epoch loss.
- Refusal to convert a general-principal session into catalog authority.

The clock-floor/epoch cases inject private fixture state; they do not change a
host or TPM clock and are not physical interruption evidence. Existing actual
PAM modes and explicit kernel credential/thread/descriptor/FSUID checks passed.
Both AppArmor profiles parsed without being loaded into the kernel.

Full native Python discovery passed 272 of 274 tests. Two existing upstream UTC
publisher checks skipped because the offline lane lacks their isolated pinned
source fixture; these are not counted as passes. The 55 selected checks are
included in discovery, not additional distinct tests. All 218 captured build
inputs, 58 test inputs and the CI workflow matched the checkout after evaluation.

SHA256 records:

| Artifact | SHA256 |
| --- | --- |
| Build-input manifest | `d15d52fc5fc06c50863ea9b2372a7d36cc4b1e2714d2af2415f63d3cffe4d289` |
| Test-input manifest | `1345b829a73065165013ec0db9f66b4d5691b01dc9503e3a070b30bc44a22a88` |
| Targeted log | `1a2d3bff10fd4e01fcabaff6ddc007d4ffcc453c52c0ec599a6c49f4d884ed92` |
| Frozen targeted runner | `2f721d30b5746fd63ae9d1b20808dfdef51005731fbdf5fa81affc68518767b6` |
| Native executable | `2e14c81347a8d0f4ac9a1790c50835d6705b73de62792553f80f2232283d2c45` |
| Full native regression log | `3a342d3af1d9d09829d455f0f292515d8d4a55b9f37aaaac175f99ec2ea494e3` |
| Frozen regression runner | `4d668cb75815a509af2594b78cdcf51f3e2af904d976c399acdeb03c4fd3a14e` |

## Work still required

Complete transactional Unix account/password lifecycle and interrupted recovery,
the approved protected UTC producer/keeper and seed/history delivery, finite
time-bound assignments, principal-bound folder/effect/resource/inference grants,
and current authority checks in their admission consumers. Broader workflow
workers, inference consumers, governed export/deletion/retention, damaged-authority
reconciliation and device/multiworker integrations also remain open in the
[Requirement 1 register](../RESOURCE_LEASES.md#still-required-before-requirement-1-closes).

Installed observer/PAM/AppArmor/seccomp enforcement, terminal custody, crash and
reboot behavior, final-image evaluation, physical TPM/security/recovery evidence
and the separate native Ubuntu qualification remain unexecuted. This software
checkpoint does not close those requirements or start Requirement #2.
