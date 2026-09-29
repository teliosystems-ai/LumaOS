# Native account-authentication checkpoint — 2026-09-29

**Selected software checks passed; G2 and its final all-components image remain
incomplete.** This is an authentication prerequisite, not authenticated TPM
enrollment, a finite Admin service, product authority or gate acceptance.

## Implemented

`admin-auth-check LOGIN` is a root-invoked diagnostic on an installed system.
It takes the account password from the controlling terminal, not arguments,
environment, redirected stdin or a plaintext temporary file. Echo is suppressed
before the prompt; bounded input supports backspace and cancellation, and restores
terminal settings on ordinary success/error/cancellation paths. Password input
uses locked, nondumpable memory that is wiped on release. Abrupt process death,
TTY hangup and full service signal handling still need installed qualification.

The separate, non-setuid `luma-auth-helper` uses Ubuntu PAM 1.5.3-5ubuntu5.7 with
the fixed image-owned `luma-admin` profile. It authenticates the supplied account,
checks account validity, requires a password conversation, rejects system/root
and nologin identities, checks the returned PAM username and UID continuity, and
returns only a four-byte UID on success. No PAM session, setcred, password update
or product role assignment is performed. The Rust caller checks profile bytes
and helper ownership/mode, clears the environment, discards helper diagnostics,
limits output size and kills/reaps a helper exceeding its 30-second deadline.

The builder compiles/copies the helper as root-only mode 0700 and ships the PAM
profile. The profile delegates to the image's normal Ubuntu authentication and
account policies; it does not implement custom password hashing or bypass PAM
expiry. PAM's library/module working allocations are **not** claimed fully locked
or swap-qualified. The complete service/process, rate-limit/lockout, memory and
identity-generation boundaries remain integration work. Module authentication
audit records may contain usernames and outcomes, never supplied passwords.

The in-process authentication observation is short-lived and not serializable
or caller-constructible. It is not a bearer token or a role/capability. Account
authentication must be bound to the independently selected product principal,
deployment and protected TPM enrollment, then checked against live revocations
and identity generations at every subsequent authority boundary. A root/sudo
session or a successful diagnostic does not become the product Admin role.

## Executed tests

Only a fresh, no-network/no-host-TPM container was used for real PAM account
creation/password setup/locking/expiry changes. No Windows or Ubuntu WSL host
account was created or modified. The temporary account, credentials and helper
test state disappear with the disposable container; secrets are not exported.

The real PAM fixture verified correct authentication and rejection of wrong or
empty passwords, unknown/root accounts, locked/expired accounts, required
password changes, nologin shells and substituted PAM profile bytes. Pseudo-terminal
tests verified hidden input, editing and cancellation with terminal restoration;
ordinary tests also check account-name syntax and observation expiry. Existing
TPM sealing, journal, UKI event replay and kernel-less initrd tests were rerun.

Final evidence: `D:\LumaOS-builds\native-tests-20260929-admin-auth-02`.
The [machine-readable record](native_admin_auth_2026-09-29.json) pins the tools
image, PAM package and retained evidence hashes. It records **42 ordinary Rust
tests passed**, **20 TPM and 6 PAM explicit invocations passed**, **49 runner
boundary labels**, and **20 Linux Python tests passed**. Six isolated functions
are intentionally ignored in the ordinary Rust suite and explicitly invoked by
the fixture runner. Counts are not all distinct test functions.

A subsequent Windows run of `python -W error -m unittest discover -s native/tests
-v` passed 12 tests and skipped the eight Linux-only cases. This was a terminal
check, not an additional retained transcript in the evidence directory above.

The exact evaluated inputs are in `source-sha256.txt`. Later documentation and
the storage runner's additional PAM-profile inventory entry do not change that
evaluated binary. The image assembly/copy path and installed diagnostic were
not exercised by a full rebuilt-image boot, and are not qualified by these
source/fixture results. No final image has been produced in this checkpoint.

## Work still required for the requested all-components image

1. Complete authenticated TPM enrollment, hierarchy/credential custody,
   collision/interruption handling and recoverable provisioning.
2. Integrate the finite native Admin/policy service, signed skill registry,
   typed workflow supervision, scoped file/calculation/artifact skills and
   durable authorized effects/reconciliation.
3. Complete governed model lifecycle/resource leases, generation fencing,
   quarantine/pressure handling and the actual 1,000 compact-model cycle tests.
4. Provide and test the model-independent Wayland/manual desktop and the
   generated-code isolation runtime; neither the old X11 packaging nor a
   deny-only generated-code path closes those requirements.
5. Rebuild the complete image and execute the remaining installer, measured
   boot, update/fallback, recovery and security matrix from that artifact.

The full inventory remains in [G2 software status](../G2_SOFTWARE_STATUS.md).
Production custody and the named-board tests remain separate acceptance inputs.
Docker's Linux backing store is still on the nearly full C: drive; D: is retained
for artifacts. Storage relocation/downtime was requested but not performed or
assumed approved. No existing volumes, signing keys or retained evidence were
deleted. Free space or approve a supported, preserving relocation before the
large all-components build; this is separate from the unfinished software above.

Primary API reference: [Linux-PAM 1.5.3 application interface](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/include/security/pam_appl.h).
