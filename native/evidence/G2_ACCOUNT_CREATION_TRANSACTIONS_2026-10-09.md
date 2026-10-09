# Governed locked account creation source evaluation

Date: 2026-10-09. The native source now implements reviewed locked-account
creation with a private home and five-file publication. The isolated evaluation
passed, but usable-account activation and Requirement #1 remain open. No final
image, installed confinement or physical-machine qualification is claimed.

## Implemented boundary

Hidden confirmed password entry uses the existing locked, nondumpable secret
buffers and the distribution yescrypt adapter, including verification of the
generated hash. An owned governed Admin session retains exact private proposal
bytes. Later inspection and commit reuse that salt and evidence; passwords and
hashes never appear in arguments, environment variables or returned JSON.

The proposal appends a fresh principal without changing original installation
identities or their recovery verifier. UID/GID selection checks all four account
files and every historical registry identity, including removed accounts.
Preparation anchors the manifest and disables the new governed principal.
Separately reviewed permission does not publish anything. Fresh transaction-scoped
Admin continuations publish home, gshadow, group, shadow, passwd and registry in
that order. Completion requires their exact publication before recording the
approved registry extension and credential commitment. The original installer
snapshot remains unchanged in history.

All source and evidence descriptors, directories and the migration lock remain
pinned at dispatch. Home-marker metadata detects replacement and in-place
rewrite, even if bytes are restored. Exact ordered publication and matching
interrupted dispatch prefixes can resume explicitly; conflicts and unsafe modes
remain untouched. Interrupted group-readable shadow files must have their exact
approved mode and group before any additional bytes are written. This check was
also tightened in the existing deletion path.

The new account remains locked and governed-disabled with password age zero.
Its `needs_password_aging` fence prevents ordinary enable/unlock from bypassing
protected UTC establishment. The socket service rejects every creation phase,
keeps its strict read-only system mount and retains CAP_CHOWN as its sole
capability. Local-maintenance AppArmor source lists the fixed staging, registry
and home paths and allows the DAC override needed to inspect a new user-owned
mode-0700 home. Installed enforcement remains unqualified.

The ceremony is in [the local Admin implementation note](../LOCAL_TPM2_ADMIN.md).
The combined account catalog admits one incomplete transaction and at most 128
retained credential/deletion/creation transactions. Creation proposal and
interrupted staging directories have a separate combined 128-entry ceiling.
Exhaustion refuses without deleting evidence.

## Executed evaluation

The final frozen runner was
`D:\LumaOS-builds\g2-account-creation-20261009-06\checks\runner.sh`.
Its log and exit record are in that evidence directory. The runner exited zero
with `ACCOUNT_CREATION_SWEEP_PASSED`.

| Check | Result |
| --- | --- |
| Account creation Rust suite | 8 passed |
| Account deletion Rust suite | 7 passed |
| Admin roles Rust suite | 13 passed |
| Admin governance Rust suite | 72 passed; 1 fixture-dependent ignore |
| Admin service Rust suite | 11 passed; 4 fixture-dependent ignores |
| Account transition Rust suite | 8 passed |
| Principal Rust suite | 15 passed |
| Targeted Rust total | 134 passed; zero failures; 5 existing fixture-dependent ignores |
| Native Python regression | 297 discovered; 295 passed; 2 existing UTC-fixture skips |
| Real PAM, kernel peer and existing-owner software-TPM parent | Passed in 89.86 seconds |
| New account creation markers | All 14 passed |
| Formatting and offline locked production build | Passed with warnings denied |
| AppArmor source parsing | Passed without kernel load or cache write |

Creation coverage includes original-history preservation, reserved names and
UIDs, malformed names, changed sources/evidence, home-marker replacement and
in-place rewrite, retention exhaustion, ordered publication at every prefix,
exact interrupted writes, conflicting or unsafe dispatch files, final
authorization refusal, and all three uncertain-TPM-reply phases. Those replies
require exact reviewed journal reconciliation without another dispatch or TPM
write.

The real-PAM composition exercises private proposal retention without disclosure,
preparation/permission fences, general-session refusal, closed/clock-floor/epoch/
head changes, six independently authenticated publications and replay without
another rename, exact registry completion, and enable/unlock bypass refusal.
The same parent retained 13 deletion, 13 lock, 9 password, 10 credential-checkpoint,
19 catalog, 7 issuance, 12 projection and 5 offline-custody-recovery markers.
Deliberately caught unwind panics in its refusal fixtures are not failed tests.

All 223 captured build inputs, 64 native source/support test inputs and the copied
CI workflow matched the working tree with zero mismatches. Fourteen pre-existing
bytecode cache files were also copied; they are not counted as source inputs.
The complete ordinary Rust suite was not rerun: this binary discovers 735 tests,
while this record credits only the targeted suites and explicitly executed
disposable fixture.

Build cache and evidence remained on D through Docker root
`/mnt/luma-build/docker` and volume `luma-g2-rust-targeted-cache-20261001`.
The pinned tools image was `luma-utc-targeted-tools:20261005`, image SHA-256
`69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
The source-check container used one CPU and 1536 MiB with no additional swap;
the disposable PAM container used one CPU and 1 GiB with no additional swap.
Both ran without network access and with a 128-process ceiling. No WSL settings,
host accounts, host services, host time or physical TPM ownership were changed.

## Retained digests

| Artifact | SHA-256 |
| --- | --- |
| Source build inputs | `75dce844f44ee7d29ddfe909aa4462b27d674563fbf21f11aa99421ed22f39d3` |
| Frozen runner | `7362c8af412f1eba9745aefcb69b3c7b22f4d0d46e34ae12d5733eb2b45d0436` |
| Final test log | `7d9a64e62f60f25c0c2e5fd8318ec2160a0ee5b83f4b3dd59c08ae0bbac4c383` |
| Production executable | `ade2a9c966e3c8de22fb8da69053c6b6fe5fe06340502fa766e2286814268611` |

## Earlier attempts and remaining work

Attempts 01 and 02 failed compilation because of a test-only missing directory
trait import and a fixture continuation temporary lifetime. Attempt 03 passed
its Rust checks but stopped on two stale native source-composition assertions
after the registry-helper and boundary-check changes. Those assertions were
updated to retain their original security checks. Attempts 04 and 05 passed,
but preceded the final permission/marker hardening. None substitutes for the
final attempt 06 source snapshot.

AppArmor parsing reported the existing WSL interface/cache warning and did not
enforce the profile. Boot, power cuts, installed systemd confinement, production
custody and physical TPM behavior remain unexecuted. Protected UTC password-aging
establishment and governed activation are still required for usable newly created
accounts. Original Admin password/lock recovery, protected UTC deployment and
seed/history delivery, finite grants/admission, governed workflow/retention and
damaged-authority reconstruction remain separate software work. Requirement #1
and G2 are not complete; Requirement #2 has not been started.
