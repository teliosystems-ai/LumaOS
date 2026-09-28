# Native local TPM2 checkpoint evaluation — 2026-09-28

Result: **selected source-level boundaries passed; G2 remains incomplete**.
The owner selected local TPM2-backed Admin for the current installer target;
the external service is a future installer variant. See
[the implementation and remaining-work note](../LOCAL_TPM2_ADMIN.md).

This change adds a Rust-owned TPM2-TSS adapter, an inert durable checkpoint
journal, read-only diagnostics, toolchain/runtime dependencies, isolated tests
and CI coverage. It does **not** add a fully enrolled Admin service or convert
root/sudo into product authority. Nothing was provisioned on a physical TPM.

## Executed evidence

Accepted TPM run: `D:\LumaOS-builds\native-tests-20260928-tpm-04`.
Source base: `e2f8f31` plus the source hashes retained with that run.
The tools image is
`sha256:f7c1c6dd2a4352d755e73036629c0c0baa49993441cfd8489b5020c8a37a4bdd`.
Ubuntu 24.04 tools ran on kernel `6.18.33.2-microsoft-standard-WSL2` with
TPM2-TSS 4.0.1, tpm2-tools 5.6, swtpm 0.7.3 and libtpms 0.9.3.

- Rust formatting and warning-denying native compilation passed. The C shim
  compiled with `-Wall -Wextra -Werror`.
- The ordinary Rust suite passed 36 tests. Three emulator-dependent tests were
  deliberately ignored in that ordinary run, then explicitly run in the TPM
  harness: four successful invocations, including the same refusal test against
  both an absent index and a replaced, wrongly attributed index.
- The emulator harness passed all 17 labeled boundaries in its result record.
  These cover HMAC-authorized NV read/extend, exact Name and authorization,
  single-writer locking, stale-head refusal, 16 persisted appends, disk rollback,
  payload tampering, missing/pending journal, persistent NV after restart,
  old-epoch time refusal, unexpected NV advance, absent/replaced NV index and
  product rejection without enrollment or a local TPM device.
- The product CLI rejected an environment-advertised software TPM when no local
  `/dev/tpmrm0` existed. Emulator transports are confined to the test path.
- Windows native Python tooling: 9 tests passed. Windows reference regression:
  320 tests ran successfully, with 5 platform-specific skips. These counts were
  observed from their commands; the TPM transcript is not their transcript.
- Final TPM-linked storage regression:
  `D:\LumaOS-builds\native-tests-20260928-tpm-storage-02` passed the same 36
  ordinary Rust tests, 9 real Linux mount/storage cases and 9 Linux Python
  tooling tests. This includes actual mid-copy ENOSPC cleanup/retry, not an
  injected free-space value. The startup unit passed static verification; it
  was not booted under systemd in a rebuilt image. The 1,000 snapshot cycles
  remain snapshot tests, not compact-model lifecycle qualification.

The fake-anchor unit test separately injects a lost reply **after** an anchor
advance and verifies restart/retry refusal with a persistent pending marker.
That is injected fault evidence, not a real TPM bus-loss or physical power-cut
test. The emulator's restart tests retain NV state, not a physical TPM result.
The suite deliberately destroys only its private software-TPM test state on
exit. No credential or emulator NV state is exported as evidence.

Earlier TPM runs remain in their own D: directories. The first was a narrower
passing run; run 02 exposed warning-denying non-test-build failures at the
not-yet-integrated append/time seams. Those failures were fixed explicitly,
not accepted as passes. Run 03 passed before the final logging hardening;
run 04 is the accepted source identity. Storage run 01 hit the same non-test
build warning and must not be used as a successful integration run.

## Acceptance limits

The previously exported sequence-4 image is unchanged. No new bootable image
was built or evaluated for these changes. In particular, runtime shared-library
packaging, initramfs behavior and service execution still require a rebuilt
image and its own VM evidence.

Still open: install-time TPM admission and enrollment, sealed secret delivery,
approved hierarchy/index custody, authenticated Admin/policy/effect integration,
trusted UTC, signed-update/fallback continuity, rotation, authenticated recovery
and reconciliation. An index Name alone does not prevent same-attributes index
recreation or TPM clear. The test's incorrect-attributes replacement is not
evidence of complete anti-clear protection.

The broader model lifecycle, signed skills/DAG workflow, constrained execution,
Wayland desktop, boot/migration fault matrix, production catalog/custody and
physical acceptance work remain tracked in
[the G2 software register](../G2_SOFTWARE_STATUS.md). No test in this checkpoint
promotes a gate, certifies a physical board, or replaces the required model
lifecycle/performance evaluation.

Machine-readable identities: [native_tpm_2026-09-28.json](native_tpm_2026-09-28.json).
