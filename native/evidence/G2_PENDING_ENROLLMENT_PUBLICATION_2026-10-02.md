# G2 exact committed-pending enrollment publication checkpoint

Date: 2026-10-02. Scope: native source and disposable software-TPM tests, not
installed-image, native Ubuntu hardware or product Admin acceptance. G2 remains
open. This increment adds
`admin-checkpoint-enrollment-reconcile` inspection and an explicitly reviewed
`--publish-committed LOGIN REVIEW-SHA256` path for one narrowly proven state:
the complete retained proposal is unchanged, the existing parent is bound to
its original Name, and an authenticated fixed NV read equals that proposal's
exact genesis head. The product command requires the original principal and
fresh local PAM before publication. The implementation does not provision,
extend, clear, undefine or retry a TPM write; it uses no-replace publication of
the already committed inert credential directory. Vacant NV, mismatched head,
changed inputs and other uncertain states are denied and retained for review.

## Bound targeted evidence

- D-backed source snapshot: `D:\LumaOS-builds\g2-native-seal-targeted-20261002-11\source`
- Source manifest SHA-256 (`build-inputs.json`):
  `927bbe2b5f46be1778b7dbd739cae6ce90511029ce92947b64060a8046914ebb`
- Test log: `D:\LumaOS-builds\g2-native-seal-targeted-20261002-11\test.log`;
  SHA-256 `9106d72b1cd668b17f6b8bb02a4b0e170cc7a9d1e8ed6d7f1b08e816b78c2542`.
- Offline Docker run, one CPU/Cargo job, 768 MiB and 128-PID limits, D-backed
  cache/snapshot, no host TPM/socket, no image, VM or model load. `cargo fmt
  --check`, selected ordinary TPM/owner-credential/admin-credential/enrollment
  tests, native seal/enrollment/bound-parent integration, policy checks and a
  warning-clean native build passed.
- `admin_enrollment_pending_integration.py` started a fresh disposable TPM per
  case. `committed` recovered the sealed NV authorization, authenticated the
  exact genesis head, published the pending directory and loaded the final
  credential. `vacant` refused with no NV index and retained pending state.
  `wrong-head` refused with a different provisioned head and retained pending
  state. Ordinary unit tests also rejected a wrong review digest, wrong head
  and changed pending files.

The earlier `D:\LumaOS-builds\g2-enrollment-inspection-targeted-20261002-03`
snapshot failed compilation under `-D warnings` because the new fixture was
not yet exercised. It is retained as failed evidence; the later `-11` snapshot
includes the fixture test and passed. These are isolated source/TPM tests, not
proof of real account PAM, installed-system PCR/custody, crash/power-loss
interruption, concurrent hostile root, or physical TPM behavior. The inspected
digest is not a TPM attestation or an authorization token. No end-to-end
installed enrollment recovery or finite product Admin role is claimed.
