# G2 committed-audit publication recovery — 2026-10-01

Status: **targeted implementation checks passed; G2 remains incomplete**.
No new OS image was built and no guest or physical qualification is claimed.

## Implemented scope

`rust/luma-platform/src/admin_journal.rs` now supports explicit recovery of one
specific interruption: the native journal's pending successor was committed to
the TPM, but disk publication did not finish. Inspection and publication reuse
the existing local authenticated checkpoint adapter and retained writer lock.

- Closed, bounded, private journal files; same deployment, exactly one additional
  entry and the complete unchanged committed prefix are mandatory.
- The authenticated TPM must already contain the successor's exact computed
  head. The path never advances the TPM or invokes a service effect.
- Inspection returns a domain-separated review digest binding both files' exact
  bytes, deployment, request ID, counts and checkpoint heads.
- Explicit `--publish-committed REVIEW-SHA256` rechecks the review, both files,
  TPM head and in-process clock continuity before syncing and publishing.
- Wrong/stale review, foreign deployment, non-successor, rewritten prefix,
  uncommitted proposal, changed TPM, malformed/unsafe files and changed clock
  refuse publication. Pending state is preserved on these refusals.
- Publication synchronizes the pending file, atomically renames it to the
  journal, synchronizes the parent and checks the resulting checkpoint. The
  previous journal's records are retained as the successor's prefix.

`main.rs` exposes only fixed-path installed-system/root maintenance. There is
no automatic repair, force, reset, empty-state initialization, uncommitted
proposal deletion or credential/transport override. A successful report is
explicitly non-gate-closing and grants no product Admin authority. The review
digest is a confirmation guard, not an authentication capability.

## Executed targeted checks

Evidence: `D:\LumaOS-builds\g2-admin-recovery-targeted-20261001-01`.
Frozen source manifest SHA-256:
`45dd2f2515f90e7481134412325512665e5aac4c45411cc48eec63bc31a42952`.
Completed `test.log` SHA-256:
`cabdcede551352a279d123826f5a6ae743dbc6f975ffa089521f7ad0aeb07392`.
Separately copied `native/tests/admin_recovery_integration.py` SHA-256:
`b300d25f6d14aa1ff3a0a1769a6fb2d83287500cd1d6436eb641f61182dbea27`.

The dedicated D-backed Docker daemon ran `luma-native-tools:20260927` with
network disabled, one CPU, 768 MiB memory/no extra swap, 128 PIDs and one Cargo
build job. It reused `luma-g2-rust-targeted-cache-20261001`. The container had
no host TPM devices, host account paths or daemon socket. WSL limits and other
workloads were unchanged. Test-only secrets stayed inside the disposable
container and are not in public evidence.

Passed:

- Formatting and offline locked build with warnings treated as errors.
- Ten `admin_journal` tests, including six new recovery tests. The recovery
  unit-test anchor panics if any TPM advance is attempted.
- Three ordinary `tpm` tests. Five specialized functions were ignored by this
  selection; the new recovery function was explicitly run below, not skipped.
- One actual software-TPM recovery invocation through the native ESAPI adapter:
  append really extends NV, a wrapper drops the successful reply, reopening
  normally refuses the pending boundary, explicit review/publication succeeds,
  the journal reopens with one event and the TPM head is unchanged by recovery.

The software-TPM fixture is `native/tests/admin_recovery_integration.py`; run it
from `rust/` inside a fresh tools container after the targeted build. It refuses
a visible physical TPM or Docker socket and owns only its disposable TPM state.
No complete source, PAM, credential-sealing, image or model sweep was run.

## Remaining integration and qualification

Existing images do not include this source increment. Fresh installations still
lack authenticated Admin enrollment and sealed service credential delivery, so
the fixed-path maintenance command is not yet usable on them. It refuses those
missing inputs rather than manufacturing an enrollment. The fixture provisions
only a disposable emulator; it is not a product provisioning implementation.

This repairs inert audit publication, not an ambiguous external side effect.
Production effect reconciliation, finite roles, governed principal lifecycle,
hierarchy custody, approved recovery authentication and trusted signer/time
lifecycle remain open. The sole-writer lock does not defeat hostile root or
provide a hardware compare-and-swap primitive. The tests do not exercise real
power loss, filesystem directory-sync failure, installed service confinement,
credential delivery or physical TPM replacement. Those must be incorporated
into the consolidated candidate and native Ubuntu qualification matrix.
