# G2 native software integration results

The compact CPU-profile implementation passes the software verification below.
The owner-approved model-import and model-activation purposes each have a fixed,
nonrenewable thirty-minute lifetime; ordinary sessions retain thirty seconds.
Both model purposes bind their exact reviewed operation before PAM and retain
continuous account, protected UTC, finite-grant and lease checks.

This is software evidence, not installed-image or production certification.
Requirement 1 and G2 remain open for their actual image and native qualification.
The machine-readable [evidence record](G2_NATIVE_INTEGRATION_2026-10-12.json)
contains source identities, transcript hashes and the complete fixture ownership
mapping. Implementation is committed at `bf30ae2`, following checkpoint `f3b4c2d`.

## Verified source and results

The final test snapshot contains 393 files. Its manifest SHA-256 is
`4beb1624283fed4f7c6596673c34d9f23ea9d1d13d9d7e7d08bec19cd0d93fc1`.
An independent post-test recapture matches exactly. All 314 image-build inputs
also match the tested snapshot; the other 79 files are native test inputs.
Code remains on C; caches, temporary storage, evidence and image work are on D.

- All-target Rust compilation passes with warnings denied.
- The full serial baseline passes 962 Rust tests, with zero failures under
  restrictive umask `077`. Its 42 fixture-only entries are accounted separately.
- All 393 native tests pass with zero skips, including fifteen fixture-runner
  regressions. Thirteen OS public-trust and thirteen model-public crypto and
  sidecar cases pass, as do eight UTC source-authentication cases.
- All fourteen AppArmor profiles parse with kernel loading and policy caches
  disabled. This does not establish enforcing installed confinement.
- The authenticated chrony release builds with NTS, privilege drop and seccomp;
  sixteen capability-free upstream crypto/NTS cases pass without a daemon.
- The real PAM/disposable-TPM catalog lane passes account checkpoints, lock,
  password, deletion, creation, continuation and recovery cases. All six scoped
  model-custody cases execute. They verify actual account and purpose binding,
  not a production timed catalog approval, signing ceremony or QA result.
- The compiled inference CLI passes twenty transport cases, including governed
  schema-3 selection. Storage and real ENOSPC fixtures pass their refusal,
  cleanup, private-mount and retained-output assertions.

## Retained failures and targeted reruns

The first complete fixture selection used snapshot M and passed 24 of 26 lanes.
Its PAM lane failed on an artificial cross-filesystem registry rename. Its full
baseline had twelve model-validation fixture failures caused by inherited
permissions rather than the intended published file modes. These failures remain
recorded; neither result is relabeled as passed.

Snapshot N changes exactly two native test files and the test-only portion of
`model/validation.rs`. That file's production prefix is unchanged, with SHA-256
`9277ce0ba6c8afb9caafcf9eb1beb0f8a88b27eeaaf5da01eba108b9e477c4c2`.
The PAM fixture now keeps its disposable `/etc` and `/tmp` on the same D-backed
container layer, preserving the real atomic-rename requirement. Model fixtures
explicitly reproduce public trial and weight permissions; unsafe-mode refusal
tests and private credentials remain unchanged.

Under N, all-target checks, 61 targeted Rust tests, all native source tests,
crypto, policy parsing and the UTC build pass. The PAM lane, complete hardened
baseline/TPM lane and native-source lane also pass. Together with the unchanged
passing M lanes, this supplies passed owners for all 26 selected lanes and all
42 ignored entries: 35 external fixtures and seven owned children. Children are
not double-counted. This is combined evidence, not a full 26-lane N run.

## Generated guest and qualification boundaries

The separate disposable KVM corpus passes thirteen real guest cases for identity,
input, forged output, prohibited syscalls, closed descriptors, memory, output and
wall limits, and abnormal exit. Its guest, runner and fixture sources are unchanged.
It does not test the installed PAM/broker/cgroup/AppArmor journey or qualify the
distributed image's complete runtime dependency closure.

The image scope supports the exact pinned Qwen3 4B and 1.7B CPU tuples, plus
manual operation. Other parameter/back-end configurations require their own
implementation and qualification; catalog capacity does not provide an adapter.
Production public roots, signatures, actual custody and model QA inputs are not
manufactured by the builder. Native installation, login, authorization,
confinement, live NTS/error bounds, interruption/recovery, firmware, encryption,
existing-owner TPM and the required physical boards remain separate evaluation.
