# G2 checkpoint enrollment transaction and credential blocker

The native checkpoint now has an explicit enrollment transaction in source.
Its bounded transaction tests pass, but **operational enrollment has not passed**:
the real integration attempt fails because the packaged systemd 255 credential
backend cannot seal with the selected nonempty existing TPM owner authorization.
This is an implementation dependency, not a reason to change the owner's choice,
waive testing, or mark G2 complete.

## Implemented transaction

`admin-checkpoint-enroll LOGIN --existing-owner` requires installed-root context,
the selected UID 1001 principal and fresh fixed-profile PAM authentication.
Custodian authorization is entered as hidden hex into locked, wiped memory,
separately from the account password. No owner credential is persisted or passed
in arguments. The transaction binds an inert principal/boot record into the
deployment namespace and initial audit checkpoint; it does not grant Admin.

The fixed-path flow includes seal/unseal preflight, a private synchronized
four-file proposal, revalidation before dispatch, one-shot existing-owner NV
provisioning, authenticated Name/head readback and no-replace publication. A
retained runtime lock excludes cooperating writers throughout publication.
Existing or interrupted directories refuse, including partial state and dangling
links. Failures never trigger an NV retry, reset, undefine or proposal removal.
Reviewed recovery of interrupted enrollment remains unimplemented.

The current credential preflight fails before that transaction can allocate NV
on a nonempty-owner TPM. The CLI reports this dependency explicitly. The positive
software-TPM acceptance test remains present and pending; it was not converted
into a passing test by accepting refusal.

## Credential backend finding

The existing helper and signed PCR policy successfully seal and unseal on the
fresh empty-owner control TPM. After the fixture establishes nonempty ownership,
both new sealing and unsealing the previous ciphertext refuse. The index remains
vacant and no enrollment directory is published. Sealing before ownership is
therefore not a viable workaround.

This agrees with the pinned upstream implementation: the
[systemd 255 credential caller](https://github.com/systemd/systemd/blob/v255/src/shared/creds-util.c)
does not request serialized SRK state, selecting the legacy primary-creation
branch in its [TPM helper](https://github.com/systemd/systemd/blob/v255/src/shared/tpm2-util.c).
The required next implementation is a reviewed credential backend compatible with
existing ownership and its runtime unlock requirements. Do not clear/empty owner
authorization, persist the owner password for routine unlock, or weaken the PCR
policy. A backend replacement needs its own positive, negative, restart and
signed-update/recovery evaluation before enrollment can be called operational.

## Executed checks and evidence

Final bounded evidence is at
`D:\LumaOS-builds\g2-enrollment-targeted-20261002-03`.

- Frozen source manifest SHA-256:
  `ce315e2a6326f75295f851495e62396164df241af4966c7598c902601f4968b1`.
- Completed test log SHA-256:
  `ddd3e9cbb146050f5dad7364d6d04795c8d830dc59db80bf24c7053ac1ca852a`.
- Separately copied `admin_credential_integration.py` SHA-256:
  `781fe7da58a4936179be854ea68248036c831322fd481b5c3361a52a8e9adc8d`.
- Separately copied `admin_enrollment_integration.py` SHA-256:
  `3550dc4dc94ed4e298fcd3a9bb9c17b7d4dd679bc1682f096360ace3769d44f7`.
- Separately copied `test_admin_credential_policy.py` SHA-256:
  `7aa0be4981b447c23b29bdc871c18a69346f30ccaab5369627bb7aacb8056fd7`.
- Separately copied `existing_owner_integration.py` SHA-256:
  `d560fa397b560e2e2e09b4176cd15a9e39195200b723ba5cfa5209be55e62183`.
- Separately copied `principal_pam_integration.py` SHA-256:
  `b9a9d9c92202441d65d4c91dc59856d6a776addb8b0dc25b7fd208eeebc0bace`.

Thirty-five selected ordinary Rust tests, six isolated PAM cases, two wiring
checks, formatting and the warning-clean offline locked native build passed.
The seven enrollment transaction unit tests cover successful simulated readback,
authorization refusal, lost reply/wrong head, non-overwrite publication, changed
proposal bytes before/after dispatch, and partial/symlink attempt refusal. These
use a fake checkpoint and are not evidence of real enrollment success.

Three explicitly invoked software-TPM checks passed: the empty-owner sealed
control, the expected nonempty-owner seal/unseal refusal, and the separate native
existing-owner NV provisioning regression. The latter still verifies unchanged
custodian authorization and no leaked transient handles. Other ignored tests
are not claimed as executed. The positive integrated enrollment test failed in
attempt `-02` and is still pending a backend implementation.

Attempt `-01` failed in test-only owner-credential setup before native enrollment;
the tools authorization file was corrected to include its hex-format prefix.
Attempt `-02` exposed the real sealing incompatibility. Both failed snapshots and
logs are retained, alongside the final compatibility/transaction regression run.
The current build inputs were compared with the final snapshot with zero changes.

Execution used the dedicated D-backed Docker daemon and existing compiler cache,
one CPU, one Cargo job, 768 MiB with no extra swap, 128 PIDs and no network, host
TPM or host daemon socket. Only disposable container accounts/TPMs were changed.
No WSL memory change, image/VM/model sweep, production credential operation or
physical TPM enrollment occurred.

## Remaining work

Implement the owner-compatible credential backend and pass the retained positive
enrollment test; then add reviewed interrupted-enrollment recovery and complete
the confined Admin service, finite roles, governed principal lifecycle and
independent credential/custody recovery. Installed CLI/PAM/TPM composition,
reboot/update/fallback and physical interruption tests remain unqualified.
The implementation-first candidate freeze and consolidated image sweep remain
deferred until the open software packages in the completion register are ready.
