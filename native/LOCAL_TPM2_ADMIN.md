# Current installer target: local TPM2-backed Admin

Owner decision, 2026-09-28: the current installation variant shall use a local
TPM2-backed Admin/checkpoint service. An external protected Admin/checkpoint
service is a **future, separately implemented installer variant**. It is not an
automatic fallback when a TPM is absent, unavailable, cleared or inconsistent.
This closes the deployment-selection question, not implementation or acceptance.

This native implementation note supplements the frozen reference ADRs 0001,
0002, 0007, 0009 and 0010; it does not rewrite them or the release inventory.

## Implemented boundary

`rust/luma-platform/src/tpm.rs` owns the local transport, exact NV identity and
attribute checks, service lock, authenticated reads/extends, and TPM clock
epoch validation. A small fixed-width C ABI adapter calls the packaged
TPM2-TSS ESAPI. Policy and journal logic remain in Rust. The shim adds native
dependency and unsafe-FFI review obligations; it is not a C policy engine.

The product transport is explicitly `device:/dev/tpmrm0`, a root-owned character
device. Environment-selected TCTIs, TCP transports and external fallback are
not accepted. Root-only `luma-platform tpm-probe` reads the clock and SHA-256
PCRs 7 and 11. It does not provision, attest, clear or claim to enroll the TPM.
`luma-platform admin-install-check` reads the clock/PCRs and checks that the
proposed NV allocation is unoccupied. A missing local TPM, unsupported PCR read,
unsafe clock, occupied index or TPM error refuses admission. No environment
transport fallback, index overwrite or hierarchy mutation is available.
`luma-platform admin-checkpoint-status` validates existing protected checkpoint
configuration, credential and journal. Missing enrollment fails closed.

The proposed index is `0x01804c41`, SHA-256, 32-byte NV_EXTEND with exact
AUTHREAD/AUTHWRITE/NO_DA/WRITTEN attributes and pinned public Name. This is a
development allocation, not permission to overwrite an index on a real machine.
The 32-byte random authorization is used in TPM HMAC sessions, never a password
session in the native adapter. Only public digest parameters are sent; the
adapter does not implement encrypted secret provisioning. An unbound HMAC
session relies on the high-entropy authorization; replacing it with a human
password is not supported.

The native inert audit journal binds a random deployment namespace, ordered
records and their payload digests into the TPM extend chain. It is bounded to
4 MiB and 4,096 records; exhaustion denies further appends, not silent rotation.
Every append first persists a proposed journal, then advances the exact expected
TPM head, then publishes the journal and synchronizes the parent directory.
Uncertain TPM outcomes leave a pending transaction that denies further use.
Missing files, unknown fields, insecure file/directory modes, hard links,
duplicate request IDs, disk rollback, payload tampering, an unexpected TPM head
and any pending marker are rejected. The lock is a sole-writer OS lock, **not a
hardware compare-and-swap primitive** or distributed consensus protocol.

These records are **not capabilities or effect receipts**. The adapter does
not authenticate a human, assign roles, authorize an effect, dispatch a skill,
or make an external side effect atomic with disk and TPM. There is no public
append/enrollment CLI. Integrating services must independently authenticate and
authorize entries; an event containing a UID or role claim grants no authority.
TPM powered-time is not UTC. Epoch changes/regression invalidate boot-bound
timing; catalog expiry still needs a reviewed trusted wall-clock design.

The current installer performs read-only admission before target-disk access,
then rechecks PCRs, clock epoch and index vacancy immediately before disk writes.
It writes `/var/lib/luma-os/admin-install-intent.json` into encrypted mutable
state with the candidate account/UID, `enrollment_status: required` and
`product_admin_active: false`. That record is informational, not authenticated
bootstrap or a role grant. A limitation warning is printed before destructive
confirmation and on successful lab installation. No TPM provisioning occurs.
Recovery/export paths remain independently usable and do not require a vacant
TPM index. Reinstallation over an occupied index is refused; it is not recovery.

Expected future service inputs (not created by the current installer):

- `/var/lib/luma-os/admin/anchor.json`: closed version/profile/index/Name record.
- `/var/lib/luma-os/admin/journal.json`: exact persisted inert audit journal.
- `/run/credentials/luma-admin.service/nv-auth`: private 32-byte authorization.
- `/run/luma-admin/anchor.lock`: exclusive writer lock in a private directory.

No service unit currently supplies that credential. Do not manually turn these
paths into production enrollment. The memory boundary disables core dumps and
clears the Rust credential buffer; installed sealed delivery and the complete
service confinement boundary remain to be implemented and evaluated.

## Sealed credential primitive (not installed enrollment)

`rust/luma-platform/src/sealed_credential.rs` adds bounded TPM-only sealing
through the Ubuntu-packaged systemd 255 credential helper. The fixed profile
requires SHA-256 PCR7 and signed PCR11, an exact independently supplied public
key, and a deployment-bound credential name. Only the explicit
`tpm2-with-public-key` mode is accepted. A bounded header filter rejects host,
TPM-absent, unsigned-PCR, combined host/TPM and unknown credential profiles
before decryption; authenticated decryption remains the helper's responsibility.
There is no public seal/unseal CLI or selectable weaker fallback.

Plaintext input/output use anonymous locked, nondumpable memory mappings, are
not passed in arguments or ordinary temporary files, and are wiped on release.
The helper has a cleared environment, fixed executable/device, discarded
diagnostics, a 30-second deadline and an output-file size limit. These measures
do **not** establish complete secret isolation: the packaged helper's own
working allocations, process inspection, swap/service confinement, inherited
descriptors and physical TPM/bus attacks still need integration and review.

The future trusted service must authenticate the deployment, enrollment record,
public signer and policy signatures independently of the encrypted blob.
Caller-supplied metadata is not authority. The primitive does not establish
approved image admission, signer revocation, trusted UTC, old-image rollback
prevention or finite Admin roles. A signature for a different PCR11 measurement
can authorize that measurement without resealing; this is not evidence of a
working installed A/B enrollment or recovery flow. Changed PCR7 intentionally
denies access until an independently authorized recovery/migration exists.
The deployment-bound helper name must be deliberately integrated with the
future service credential loader; the proposed `nv-auth` path is not wired up.

## Image builder: signed installed boot policies

The builder now creates/retains a separate laboratory RSA PCR signer in the
private key volume (`pcr-policy.key`), distinct from release and Secure Boot
keys. Only its public bytes enter the verity-protected root at
`/usr/share/luma-os/admin-pcr-public.pem`. Installed A/B UKIs embed that same
public key and signed SHA-256 PCR11 policies for
`enter-initrd:leave-initrd:sysinit` and
`enter-initrd:leave-initrd:sysinit:ready`. Live installer/recovery UKIs contain
neither the installed public-key section nor PCR approvals. This keeps live
media from implicitly becoming an installed Admin unlock environment; authorized
recovery/enrollment still requires its own independently authenticated flow.

`native/image/boot_policy.py` verifies the Secure Boot signature, exact slot/mode,
embedded expected public key, closed signature inventory, measured section bytes
and signature cryptography before assembly continues. A correctly PE-signed
artifact whose measured bytes no longer match its PCR approvals is rejected.
Default host ukify configuration is not consumed. The public `boot-policy.json`
report is exported/checksummed as build evidence, not runtime approval authority.

The `luma-pcrphase` dracut module includes the packaged initrd phase unit and
systemd 255's `systemd-pcrextend` helper, with the maintained `tpm2-tss` dependency.
It bridges the packaged dracut module's obsolete `systemd-pcrphase` binary name.
The builder explicitly activates the packaged sysinit/ready phase units and
checks the generated initrd for the helper, unit, activation link and TPM library
before signing. The test suite generates a real **kernel-less** initrd and checks
those contents; it does not prove native driver loading or service execution.

The artifact, initrd and software-TPM replay checks are recorded in the
[UKI policy checkpoint](evidence/NATIVE_UKI_POLICY_2026-09-29.md). These do not
establish that real firmware/stub/boot-phase measurements match on a guest or
that a confined Admin service receives its credential at the correct phase.
The previous exported OS
image is unchanged. Do not enroll against its unsigned-PCR UKIs or assume these
new source changes are already present on installation media.

## Remaining software before the local installer can be complete

The native `admin-auth-check LOGIN` diagnostic now performs masked
controlling-terminal account authentication on an installed system. A separate
non-setuid, root-only helper uses the fixed `luma-admin` PAM service, normal
Ubuntu authentication and account checks, rejects root/system/nologin accounts,
and never opens a session, changes a password or assigns a role. The caller
validates its exact image-owned PAM profile and helper ownership/mode, clears
the helper environment and bounds its execution/output. Password buffers in
the caller and the helper's input are locked and wiped; PAM's own working
allocations still need the complete service isolation/swap review. Standard PAM
authentication auditing can record the account name and outcome, not passwords.

Successful authentication is only a short-lived in-process observation. It is
not a serializable bearer capability, enrollment record, role assignment or
authorization for any effect. Enrollment still must bind it to the selected
principal, deployment and protected TPM state, with identity-generation and
credential-revocation checks at each authority boundary. The diagnostic does
not activate product Admin. Real account/terminal tests and limitations are in
the [authentication checkpoint](evidence/NATIVE_ADMIN_AUTH_2026-09-29.md).

1. Evaluate the implemented pre-write TPM admission/intent path in a rebuilt
   image, and bind the selected product Admin principal through authenticated
   enrollment independently of root/sudo. Admission does not reserve an index
   or prove that provisioning, sealing, hierarchy authorization or NV capacity
   will succeed. It is not complete enrollment preflight.
2. Implement enrollment using an exact approved NV allocation and collision
   refusal, cryptographically random secrets, independently recoverable local
   credentials, and interruption/retry fencing. Never clear the TPM, overwrite
   someone else's index, or silently take ownership of its hierarchies.
3. Integrate the sealed credential primitive into authenticated delivery for
   the approved local platform/boot policy. Handle
   signed A/B updates, fallback and recovery without sealing solely to the live
   installer's PCR values. The builder now emits installed signed PCR policies;
   boot-phase/service execution and signer rotation remain to be qualified.
   Exercise changed PCRs, firmware and signer rotation.
4. Define/protect owner/platform hierarchy custody against undefine/redefine
   and clear. An NV public Name identifies its public attributes, **not its
   physical creation instance**. Same-attributes recreation can have the same
   Name. Attribute pinning alone is not anti-clear protection; protection also
   needs the enrolled secret, provisioning state and approved hierarchy policy.
5. Implement the finite native Admin service, assignment/revocation, authenticated
   product principals, scoped effect-time grants, durable effect receipts,
   idempotency and reviewed reconciliation. OS root/sudo is not that service.
   Preserve the governing distinctions between Admin assignment and production
   signing custody/approval. No role text supplied by a model is authority.
6. Implement authenticated recovery from an interrupted checkpoint, TPM loss,
   replaced hardware, journal capacity exhaustion and key rotation. Never
   auto-reset a mismatching head, silently reconstruct empty state or replay an
   uncertain effect. Preserve manual data recovery independently of inference.
7. Integrate trusted catalog time and signed production trust inputs, then rebuild
   the image and run admission, enrollment, reboot, update/fallback, tamper,
   rollback and recovery tests with persistent isolated VM TPM state. Existing
   image/VM evidence cannot establish these newly introduced properties.

Physical TPM/bus/firmware/power-loss qualification follows that software work;
it does not substitute for it. Production custody requires approved public
trust inputs and operators, not private keys supplied in chat or source.

## Future installer variant: external protected service

Deferred TODO: a separate `external-admin` installation variant with authenticated
service identity, namespace isolation, protected checkpoint API, trusted time,
network failure/partition behavior, explicit enrollment and recovery/custody.
Define migration from local to external as an independently authorized operation
with continuity evidence. Do not expose it as a selectable working profile until
its implementation and full negative matrix exist. Neither network loss nor
TPM loss may trigger implicit migration between variants.

## Repeatable evaluation and references

`native/tests/run_tpm_boundaries.sh` snapshots the source and executes the normal
Rust suite plus explicitly isolated software-TPM tests. It runs only in a fresh
tools container, without host TPM devices, network, host services, privilege
grants or Docker socket. Test-only index provisioning/undefinition uses the
disposable emulator and is not linked into the product. Private emulator state
and random credentials are destroyed on exit, not exported with diagnostics.
See [the evidence checkpoint](evidence/NATIVE_TPM_STATUS_2026-09-28.md).
The subsequent admission/VM-fixture evaluation is recorded in
[the installer admission checkpoint](evidence/NATIVE_TPM_ADMISSION_2026-09-28.md).

Implementation references:

- [TPM2-TSS 4.0.1 ESAPI declarations](https://github.com/tpm2-software/tpm2-tss/blob/4.0.1/include/tss2/tss2_esys.h).
- [NV extend semantics](https://github.com/tpm2-software/tpm2-tools/blob/5.7/man/tpm2_nvextend.1.md)
  and [NV definition](https://github.com/tpm2-software/tpm2-tools/blob/5.7/man/tpm2_nvdefine.1.md).
- [Authorization session behavior](https://github.com/tpm2-software/tpm2-tools/blob/5.7/man/tpm2_startauthsession.1.md).
- [systemd 255 credential design](https://github.com/systemd/systemd/blob/v255/man/systemd-creds.xml),
  [explicit signed-key option parsing](https://github.com/systemd/systemd/blob/v255/src/creds/creds.c)
  and [authenticated credential format](https://github.com/systemd/systemd/blob/v255/src/shared/creds-util.c)
  for the primitive; installed sealed-delivery integration remains pending.

The built Ubuntu toolchain uses TPM2-TSS 4.0.1 and tpm2-tools 5.6; executed
tool behavior, rather than assuming all newer documentation options exist,
is retained in the test transcript.
