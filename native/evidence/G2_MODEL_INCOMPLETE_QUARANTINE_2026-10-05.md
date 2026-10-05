# G2 incomplete model quarantine recovery

On 2026-10-05, the native source gained explicit review and private retention
of an empty or truncated JSON model quarantine before clearance. This handles
one state that an interrupted exclusive record write can leave behind. Targeted
D-backed checks passed. It is **source recovery evidence, not installed-image
qualification, proof of an actual crash, production Admin authorization or G2
completion**.

## Accepted state and review

The existing normal worker/preflight refusal remains unchanged. An incomplete
quarantine cannot use ordinary typed incident clearance. Installed-root
maintenance now provides these explicit commands:

```sh
sudo luma-platform model-quarantine-reconcile --inspect-incomplete
sudo luma-platform model-quarantine-reconcile --retain-incomplete REVIEW-SHA256
```

Both hold operation and idle-runtime kernel locks. Inspection is non-starting
and does not change the quarantine, settings or archive. It accepts only a
bounded, single-link root-private regular file whose JSON parser reports
end-of-input, including an empty file. Complete JSON of any schema or shape,
other malformed data, links, unsafe metadata and oversized files refuse. This
syntactic classification cannot establish the failure's cause or the intended
incident/model; it does not reinterpret partial bytes as authority.

Pending activation/orphan backup state must be reconciled first. Current
selection, reference environment and credential must be mutually consistent
with the current image catalog, and current selected weights must verify.
The all-absent configuration permits manual-only recovery without resolving a
model. Mixed/legacy settings and unavailable or corrupt weights refuse.
Checks after potentially blocking verification detect changed configuration,
pending fences and quarantine bytes/identity.

The review digest binds exact incomplete bytes, file device/inode/change
timestamp, current catalog, settings hashes and current model weight pin.
Replacing the file invalidates review even when its bytes match. These file
observations are not a TPM-protected incident ledger, boot epoch, resource
lease or malicious-root rollback defense. Status contains no credential or
opaque input bytes.

## Retention before clearance

An approved fresh review saves the exact bytes under
`model-quarantine.retained.CONTENT-SHA256` in the existing model state directory.
New archives are exclusively created root-private with no-follow flags and
explicit mode 0600. File and parent-directory sync, private bounded readback,
fresh configuration/weight review and final exact checks precede removing the
quarantine fence. Existing exact private bytes permit retry and are synced
again. Partial, conflicting, public, linked, oversized or otherwise unsafe
archives remain untouched and block clearance; they are not overwritten or
silently repaired.

Only the reviewed quarantine is unlinked, followed by directory sync. Current
settings, weights, completed rollback and independent `model-disabled` state
are preserved. The command never starts services, proves readiness or returns
an assertion that resources were reclaimed. Generated unit limits/reference
settings and actual runtime admission/health/inference require separate review
before model use resumes.

Retention errors before unlink keep the fence. Interruption after durable
retention but before unlink permits exact-archive retry. A crash or sync failure
after unlink has an uncertain clearance outcome; the private archive remains
and fresh inspection is required. This procedure never deletes or exports
archives. Treat opaque retained bytes as potentially credential-bearing.
Automatic expiry, a retention quota and recovery of an incomplete/conflicting
archive are not implemented by this narrow path.

## Executed source checks

Final evidence: `D:\LumaOS-builds\g2-model-incomplete-quarantine-targeted-20261005-03`.
All 188 captured source entries and three supplementary test inputs matched
repository raw-byte hashes after the final run. Passing scope:

- 80 top-level Rust model tests, including nine new checks for empty/truncated
  and manual-only retention, exact private copies/configuration preservation,
  complete/future/malformed refusal without byte disclosure, stale review,
  inconsistent settings/corrupt weights, identical-byte file replacement,
  exact-archive retry, conflicting/unsafe archives, fresh checks around
  blocking resolution/retention, pending/unsafe source refusal, and actual
  isolated-UID read/unlink denial of retained opaque bytes. The existing
  restrictive-umask parent executes its otherwise ignored owned child helper.
- Fifteen model-policy, four health-helper and fifteen VM-harness Python checks:
  34 total without skips. These are source/oracle and local fixture checks,
  not a launched VM or installed runtime evaluation.
- Formatting, a warnings-denied locked offline native build and compiled CLI
  help exposing both explicit recovery options.

Small private weight fixtures and materialized interrupted states were used;
no real model, physical power cut or production catalog custody was exercised.
Kernel locks and isolated-worker Linux DAC are real source-test boundaries,
not installed AppArmor/systemd enforcement or measured resource return.
The unit/profile were not changed by this increment.

The existing D-backed tools/cache ran with one CPU/Cargo job, a 768-MiB
memory/memory-plus-swap ceiling, 128-pid limit and no network, host devices or
Docker socket. All capabilities were dropped except CHOWN, DAC_OVERRIDE,
FOWNER, SETUID and SETGID for disposable identity/ownership fixtures. The tools
image ID was verified as
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
No host account/service, TPM, clock or WSL memory setting changed. No full image
or VM was built or run. Trial 01 retains a corrected test-only Rust slice-type
compile failure; trial 02 passed before the final private-archive DAC test and
sync-failure wording; trial 03 is the final checkpoint. All remain on D:.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `e5b7f879efc1745ea89ef5488030bc97be4480e60822ee35980880a381e2bb98` |
| `test-inputs.sha256` | `494ccb3a72c0b208e9252e8ccffa0c4f115c28ab59c691f01e4563ef644726c2` |
| `test.log` | `e593c291d695da27dec6b6fccbd4385f69c93e7bc438a35491cdb4802cc5b1ae` |

## Remaining implementation and qualification

This is one incomplete-record recovery path. Broader unsupported-state/archive
recovery and receipted retention lifecycle, controller death before failure
publication, boot/migration/pressure/OOM supervision, atomic resource leases
and generations, stale-worker fencing and trusted lifecycle delivery remain
open. Governed model-pack/catalog custody and production Admin/effect grants
are separate dependencies. Qualify changed bytes on the consolidated image and
the separate native Ubuntu target, including actual reconfiguration, failure,
retention, manual operation, inference and measured resource return. See the
[earlier observed-failure checkpoint](G2_MODEL_QUARANTINE_2026-10-05.md),
[completion register](../G2_SOFTWARE_STATUS.md) and
[implementation sequence](../G2_IMPLEMENTATION_FIRST.md).
