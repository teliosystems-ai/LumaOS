# Governed account lock and recovery evidence

Development checkpoint: 2026-10-09. Existing non-Admin account lock/unlock now
has reviewed native preparation, publication and completion paths. This evidence
does not close the account-lifecycle bundle, Requirement #1 or G2. Runner dates
are laboratory timestamps, not protected UTC authority.

## Implemented scope

The local controlling-terminal commands derive the mutation from fixed protected
installation records after preparing governed Admin authentication. They accept
no password/hash input, identity path or caller-supplied commitment. The original
Admin account is excluded. Every phase uses the shared TPM semantic history and
fresh governed Admin PAM, with its exact request and current review digest.

Preparation retains the registry, directory, migration lock and original passwd
and shadow descriptors. It stages only the reviewed exact bytes, retains the
new staging descriptors through writer dispatch, advances the target generation
and disables its principal before replacing an account file. Credential
commitments remain unchanged during preparation and publication permission.

Publication requires its separately committed permission, the owned live
continuation, original account inputs and exact private staging. It rechecks
current checkpoint history and Admin at final dispatch, preserves shadow
ownership/mode, renames through the held directory descriptors and synchronizes
both directories. A stale session, changed source or replacement staging file
cannot dispatch. Replacing shadow intentionally invalidates old account handles.

Completion checks the exact published whole-file digest, target credential
commitment and retained intent through final authentication and TPM dispatch.
Only then does it advance the credential commitment. A locked target remains
disabled; an unlocked target becomes enabled at its new generation.

Uncertain TPM outcomes never trigger filesystem publication or automatic retry.
Exact reviewed journal reconciliation precedes explicit continuation of the
same phase. An already-published continuation verifies the new records without
another rename or TPM extend. Reviewed staging may finish an exact interrupted
prefix; conflicting bytes are preserved, not truncated. Only one unfinished
transition and 128 retained transitions are permitted; exhaustion refuses.

All three mutation commands are rejected by the general socket service,
including serialized valid commands carrying a review. Its read-only identity
mount is unchanged. The local maintenance AppArmor rules are enumerated in
source, but installed enforcement has not been qualified.

## Retained evaluation

Final source and evidence: `D:\LumaOS-builds\g2-account-lock-20261009-05`.
The frozen runner exits zero and records `ACCOUNT_LOCK_SWEEP_PASSED`.
All 219 complete build inputs, 60 native test input files and the CI workflow
matched the final checkout byte-for-byte, with zero mismatches.

Builds and caches remained on D-backed Docker storage. The pinned tools image is
`luma-utc-targeted-tools:20261005`, image SHA-256
`69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
Tests use offline locked Cargo, one CPU, a 1.5-GiB build/test container and a
separate 1-GiB disposable PAM/software-TPM container. Neither has physical TPM
devices, a Docker socket, host account files or network access. No WSL memory
setting, host account, host service, clock or TPM ownership was changed.

| Check | Final result |
| --- | --- |
| Cargo formatting and offline locked production build | Passed with warnings denied. |
| Account file engine | Five passed. |
| Admin catalog reducer | Twelve passed. |
| Account lock filter | Three passed, already included in catalog/governance filters. |
| Credential checkpoint filter | Three passed, already included in catalog/governance filters. |
| Admin governance | Seventy passed; one fixture-dependent test ignored in the ordinary filter. |
| Principal filter | Thirty-seven passed, overlapping other filters. |
| Admin service | Fourteen passed; six fixture-dependent tests ignored in the ordinary filter. |
| Full native Python regression | 284 executed: 282 passed, two existing UTC-fixture skips. |
| Real PAM/kernel-peer/software-TPM fixture | Parent passed; all thirteen new account-lock markers passed. |
| AppArmor | Updated Admin profile parsed without loading or enforcing it. |

These overlapping Rust filters are not summed as distinct tests. The complete
ordinary Rust suite was not rerun in this checkpoint. Ignored tests and Python
skips are not passes. The parent fixture explicitly executes its ignored PAM
entrypoint; it does not execute every other ignored test or qualify an installed
service. The parser emitted the existing WSL interface/cache warning and exited
zero; this is not evidence of enforcing AppArmor.

The thirteen account markers cover both lock and unlock: inspection/wrong review
without staging, generation fencing before publication, early-completion refusal,
real shadow replacement while retaining the fence, already-published recovery
without another rename, completion and fresh governed-login eligibility. The
last marker verifies that restoring the original password does not revive the
old session. The same parent reran ten credential-checkpoint, nineteen governed
catalog, seven session-issuance, twelve session-projection and five offline
custody-recovery markers. These markers describe scenario steps, not independent
test-process counts.

Two new governance unit tests additionally inject lost TPM replies in all three
phases and replace staged shadow after journal preparation. They verify retained
pending fences, no unintended filesystem dispatch and exact reconciliation
without another extend. These are FakeTPM fault injections, not physical power
loss, rollback or TPM fault observations.

## Failed attempts retained

The sibling evidence directories `01` through `04` remain intact:

- `01`: initial file-engine/catalog checks and build passed; native regression
  caught an assertion that still expected the commitment domain inside the old
  method after factoring it into the shared rows helper. The corrected test
  checks both the delegation and the helper's exact domain/identity inputs.
- `02`: Rust test compilation was killed at the 1-GiB container cap. Current WSL
  reported 6,233 MiB available; the build container cap, not WSL configuration,
  was raised to 1.5 GiB for subsequent attempts.
- `03`: targeted Rust checks and build passed; the new policy test expected
  contiguous `events.iter()` across a formatter line break. Its replacement
  requires the same expression with formatting-insensitive whitespace.
- `04`: Rust and native regression passed; the new PAM helper retained a
  diagnostic Store while opening its command Store. The sole-writer guard
  correctly refused it. The helper now explicitly drops that reader first.

No failed run, skip or zero-match filter is credited as completion. The final
snapshot reran the checks after strengthening original staging-handle retention
and explicit wire refusal; earlier results are not substituted for final input
coverage.

## Artifact digests

| Artifact | SHA-256 |
| --- | --- |
| Final build input manifest | `91aefa088ee146fa5ad8b0f06608cd4421a6093141bc385934cf29a1cc29201d` |
| Final test log | `356ba1c168946baa5c623e946b2164573b462862209ea78b7b0405ad049654c6` |
| Frozen runner | `5b731abea019d83adcf2423d62c5407469d6ce0309468ba894c755e77fc48d5f` |
| Production executable observed during build | `85a5383602898b268449a4ae912790901319c11f7db055574c15c191fe1e889c` |

## Remaining completion work

Creation/deletion, password rotation/reset, original Admin password/lock recovery
and recoverable multi-file account publication remain unimplemented. Protected
UTC deployment, reviewed independent seed and authenticated history delivery,
finite grants and all resource/inference/effect consumers, generic workflow and
retention authority, damaged-authority reconstruction and multiworker/device
integration remain open software work. Installed security, native interruption,
physical TPM, final-image build and native-machine qualification are additional
requirements. No final image, model run, live NTS test or physical-machine test
was performed here. Requirement #2 has not started.
