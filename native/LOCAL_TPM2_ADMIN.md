# Current installer target: local TPM2-backed Admin

Owner decision, 2026-09-28: the current installation variant shall use a local
TPM2-backed Admin/checkpoint service. An external protected Admin/checkpoint
service is a **future, separately implemented installer variant**. It is not an
automatic fallback when a TPM is absent, unavailable, cleared or inconsistent.
This closes the deployment-selection question, not implementation or acceptance.

Owner decision, 2026-10-02: use **existing TPM ownership**. Enrollment will require
the custodian's existing nonempty owner authorization, supplied locally through
the protected enrollment flow. Luma must not take ownership, change owner,
endorsement or platform credentials, clear the TPM, or delete existing indexes.
Credentials must never be supplied in chat, command arguments, Git or logs.
Custodian availability, hardware access and actual enrollment consent remain
separate from this software-design decision.

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
The 32-byte random NV authorization is used in TPM HMAC sessions, never a
password session in the native adapter. Ordinary reads/extends send only public
digest parameters; their unbound HMAC session relies on the high-entropy NV
authorization, which must not be replaced by a human password.

The new low-level existing-owner provisioning boundary refuses an occupied
index and accepts only the fixed allocation/profile. It uses a temporary NULL
hierarchy RSA key to salt an AES-CFB HMAC session, authenticates the existing
owner, encrypts the new NV authorization parameter, defines the index and
extends its initial digest. It never changes hierarchy credentials, persists
the temporary key, clears the TPM or undefines an index. It flushes only its
own temporary key/sessions. Empty owner authorization is not supported by this
enrollment profile; the custodian must provide an existing nonempty credential.

The explicit checkpoint enrollment source command composes this boundary with
local PAM, native sealed credential preparation and durable publication. Its
positive existing-owner flow passed on a disposable software TPM; it has not
been qualified on an installed image. The installer does not invoke it
automatically. The transaction persists a parent intent **before** allocating
the persistent parent and a sealed proposal **before** the NV write. An error
can follow either applied write, so it never retries, resets or automatically
cleans up TPM state.
TPM ownership is not the product Admin role; supplying owner authorization
does not alone authorize bootstrap, signing, or another product effect.

The native inert audit journal binds an installation-specific deployment namespace, ordered
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
append CLI. Integrating services must independently authenticate and
authorize entries; an event containing a UID or role claim grants no authority.
The native append API requires the trusted integrating service to authorize
the exact entry before preparation and again immediately before TPM dispatch.
The adapter rechecks the original journal, exact prepared bytes, TPM head and
entry epoch at that boundary. Post-preparation refusal retains a fence without
dispatch. This mandatory callback is not a complete product authenticator or
role/grant service; see the
[writer authorization checkpoint](evidence/G2_ENROLLMENT_PUBLICATION_RETRY_2026-10-04.md).
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

Required sealed checkpoint inputs (not created by the current installer):

- `/var/lib/luma-os/admin/anchor.json`: closed schema-v3 profile/index/Names,
  deployment, image PCR-key digest and sealed-credential digest record.
- `/var/lib/luma-os/admin/journal.json`: exact persisted inert audit journal.
- `/var/lib/luma-os/admin/nv-auth.cred`: private TPM-only encrypted credential.
- `/var/lib/luma-os/admin/enrollment.json`: inert principal/boot observation whose
  exact bytes derive the deployment namespace committed by the initial TPM head.
- `/var/lib/luma-os/admin/parent.name`: persistent credential-parent Name.
- `/var/lib/luma-os/admin.parent-intent/`: retained parent allocation record,
  input digests and Name; an interrupted attempt is never silently reused.
- `/usr/share/luma-os/admin-pcr-public.pem`: image-owned approved PCR signing key.
- `/run/systemd/tpm2-pcr-signature.json`: installed boot's signed PCR policy.
- `/run/luma-admin/anchor.lock`: exclusive writer lock in a private directory.

The native checkpoint adapter now unseals directly into locked, nondumpable,
wiped memory and passes the secret to its authenticated TPM connection. It no
longer reads a plaintext `/run/credentials/.../nv-auth` file. Legacy schema-v1
configuration is refused without fallback. The volatile lock directory is
created by a fixed tmpfiles rule; no enrollment/credential is auto-created.

`admin_credentials.rs` bounds and validates the fixed files, requires a private
configuration/ciphertext and root-owned, non-writable public inputs, pins the
image key and ciphertext digests, and rechecks the snapshot after unsealing.
The native TPM backend verifies the ciphertext, deployment, persistent parent
Name and signed PCR policy.
Metadata/digests alone are not authority. No selectable key, transport or
credential path is exposed. Missing enrollment remains a refusal.

Do not manually fabricate these paths. The checkpoint transaction creates them
only after explicit authorization on the selected installed system.
Explicit initial product bootstrap is now available in source as described
below; the confined Admin service, signing/hierarchy custody, rotation and
recovery are still open. The helper/TSS libraries' working copies
still need the full service memory/swap review; locking the Rust secret does
not prove every dependent allocation is locked. Targeted evaluation is recorded
in [the sealed-delivery checkpoint](evidence/G2_ADMIN_DELIVERY_2026-10-02.md).

## Explicit checkpoint enrollment

The native existing-owner backend and positive enrollment passed on a
disposable software TPM. The earlier systemd 255 incompatibility is retained
as a compatibility regression; the product command no longer uses that helper.
See [the current checkpoint](evidence/G2_NATIVE_OWNER_ENROLLMENT_2026-10-02.md)
and [the earlier failed integration](evidence/G2_ENROLLMENT_TRANSACTION_2026-10-02.md).

The source command is intended for a newly installed test system after
operator approval of its TPM allocation. It has not yet been qualified on a
booted candidate image. Do not run it on the Windows/WSL host or treat the
existing-owner design decision as permission to modify a machine's TPM.

```text
sudo luma-platform admin-checkpoint-enroll LOGIN --existing-owner
```

`LOGIN` must be the installer's selected account at UID 1001, enabled in the
local principal registry and accepted by the fixed PAM profile. Root alone,
the installation intent file, or an owner credential alone is insufficient.
The command first verifies the image-owned key and current signed boot policy,
then prompts for the existing owner's authorization
as 2–128 hidden hexadecimal characters (1–64 original bytes), followed by the
account password. These are separate credentials. The hex is the encoding of
the existing authorization, not a replacement authorization; never paste it into
chat, a shell argument, an environment variable, source or logs. Empty ownership
is unsupported. Luma will not change ownership to make enrollment succeed.

After authentication, the transaction retains the sole-writer lock and writes a
private parent-allocation intent to `/var/lib/luma-os/admin.parent-intent`.
It allocates the fixed persistent parent under the existing owner authorization,
records its Name, seals and verifies the new secret, then writes a five-file
proposal to
`/var/lib/luma-os/admin.enrollment-pending`, synchronizing files, directory and
parent before any NV write. Immediately before dispatch it rechecks the
short-lived authenticated principal, credentials, public boot inputs, prepared
bytes, TPM epoch/PCRs and index vacancy. It provisions once, authenticates the
exact NV Name and initial head, then publishes the directory using a no-replace
rename and synchronizes the parent. Success reports `checkpoint_enrolled: true`
but `product_admin_active: false` and `role_grant: false`.

Any existing final, parent-intent or pending enrollment refuses, including a partial directory
or dangling symlink. An error after proposal creation leaves it intact even if
the TPM rejected the write. Do not delete it, rerun with altered credentials,
undefine the index, or fabricate a final directory. Full reviewed recovery of
all interrupted enrollment states remains to be implemented. The read-only
`admin-checkpoint-enrollment-inspect` command reports the fixed parent/NV handle
occupancy, retained intent, recorded parent Name/profile match and presence of
pending/final directories. Its observation digest is not TPM attestation or
authorization by itself. Only if it reports `parent_bound_proposal_absent` and
`bounded_continuation_possible: true` may an operator review that exact state,
then run `sudo luma-platform admin-checkpoint-enrollment-resume LOGIN REVIEW-SHA256`.
This requires fresh account and owner authentication, the original principal
and boot inputs, the same parent Name/profile, and an absent NV index. It does
not repeat parent allocation; it prepares a new sealed proposal before one NV
write. A changed digest, unbound parent, pending proposal, occupied NV index or
any conflict refuses. It has passed a disposable-TPM test, not installed-image
or physical interruption qualification. Do not use this command to remove or
repeat an uncertain write. A separate, narrowly scoped pending-publication
command is described below. If final publication
completed but its acknowledgement was lost, use the read-only
`admin-checkpoint-status` command; that is not permission to repeat provisioning.
The existing audit reconciliation command below does not recover enrollment.

The transaction's intended output is an inert checkpoint, not finite Admin roles, protected principal
lifecycle, independent credential recovery, production signing custody, secure
service confinement or resistance to a hostile OS root. Those remain open.

### Exact committed enrollment publication and replay

If the five-file pending proposal exists and the final credential directory is
absent, run `sudo luma-platform admin-checkpoint-enrollment-reconcile` to inspect
it. This command accepts only the original bound parent, unchanged proposal and
signed current boot inputs, a credential unsealed under that parent, and an
authenticated fixed TPM NV head equal to the exact enrollment genesis. It does
not write the TPM. A report with phase `committed_pending_publication` includes
a `review_sha256` for that exact state; the digest is not human authentication
or TPM attestation. After independently reviewing the retained enrollment and
selected principal, publication requires a fresh password check:

```text
sudo luma-platform admin-checkpoint-enrollment-reconcile --publish-committed LOGIN REVIEW-SHA256
```

The selected account must still be the original installation principal. The
command rechecks the retained files, parent binding, boot inputs and TPM head
after authentication, then no-replace renames the already committed proposal
and opens the inert checkpoint. Authority and proof are rechecked again after
file synchronization, before publication. It never provisions, extends or
resets the TPM; it does not grant product Admin. A vacant NV index, wrong head,
changed files/boot inputs, unbound or different parent, simultaneous pending
and final directories, or uncertain TPM outcome remains fenced. Do not use it to retry a TPM write or
delete retained state. Targeted disposable-TPM tests cover committed, vacant
and wrong-head cases; installed-image, real-hardware and power-loss
qualification remain pending. See the
[pending-publication checkpoint](evidence/G2_PENDING_ENROLLMENT_PUBLICATION_2026-10-02.md).

If publication succeeded but its acknowledgement was lost, inspection can also
verify the sole final directory against the same retained proposal and exact
authenticated TPM genesis. It reports `verified_published_enrollment`. The
same review remains valid across directory publication within the same boot
epoch and unchanged inputs. Explicit retry still requires the original
principal and fresh PAM; it returns `replayed: true` without another rename or
TPM write. It synchronizes the verified files/directories again instead of
reconstructing missing state. The directory's existence alone is not proof.
An advanced journal, changed boot inputs/epoch, partial or conflicting state
does not qualify for this exact enrollment replay. This path does not activate
Admin or implement general checkpoint recovery. See the
[publication retry checkpoint](evidence/G2_ENROLLMENT_PUBLICATION_RETRY_2026-10-04.md).

## Explicit committed-audit publication recovery

The native `admin-checkpoint-reconcile` command now inspects an existing pending
inert audit commit without changing journal bytes. It requires root, an installed
boot, the fixed local TPM/checkpoint paths and existing credential delivery.
It requires a successfully enrolled checkpoint and does not recover a pending
enrollment attempt. Fresh-image enrollment/recovery still needs integrated
qualification. Do not fabricate credentials or enrollment files to enable it.

The only supported publication is an exact one-entry successor, in the same
deployment, whose computed head equals the authenticated TPM head. Inspection
returns the request ID, previous/proposed heads, byte digests and a domain-bound
`review_sha256`. After review, the explicit invocation is:

```text
luma-platform admin-checkpoint-reconcile --publish-committed REVIEW-SHA256
```

It retains the checkpoint writer lock, checks the reviewed bytes and TPM again,
rejects an in-process clock epoch change/regression, synchronizes the pending
file, renames it to the journal and synchronizes the directory. The previous
entries remain as the exact prefix of the published journal. It neither extends
the TPM nor dispatches/replays any effect. No startup auto-repair, reset, force,
caller-selected file/transport, uncommitted-proposal discard or empty-genesis
inference is provided. An absent, malformed, unsafe or inconsistent journal
remains blocked. If publication already finished but its acknowledgement was
lost, inspect `admin-checkpoint-status`; do not invent another pending file.

The review digest is not a capability or proof of human authentication. This is
OS-root maintenance of inert audit data, not product Admin, production effect
reconciliation, or defense against hostile root replacing files outside the
sole-writer lock. Enrollment, protected effect receipts, recovery authorization,
and physical interruption tests still need integration. Targeted unit and real
software-TPM results are in the
[publication-recovery checkpoint](evidence/G2_ADMIN_RECOVERY_2026-10-01.md).

## Sealed credential primitive

`rust/luma-platform/src/owner_credential.rs` and the TPM adapter implement
the product native sealed-child format under the fixed persistent parent.
The policy fixes SHA-256 PCR 7 and authorizes signed PCR 11 with the exact
image-owned public key. The versioned envelope binds deployment, parent Name,
signer fingerprint and bounded TPM public/private blobs. Unknown or legacy
credential formats refuse without fallback. There is no public seal/unseal CLI.
The older `sealed_credential.rs` systemd 255 helper remains for compatibility
regression tests, not product checkpoint delivery.

Plaintext input/output use anonymous locked, nondumpable memory mappings, are
not passed in arguments or ordinary temporary files, and are wiped on release.
The native backend uses the fixed local TPM transport and encrypted sessions
for secret transfer. These measures do **not** establish complete secret
isolation: TPM2-TSS/OpenSSL working allocations, process inspection,
swap/service confinement and physical TPM/bus attacks still need review.

The future trusted service must authenticate the enrollment record,
public signer and policy signatures independently of the encrypted blob.
Caller-supplied metadata is not authority. The primitive does not establish
approved image admission, signer revocation, trusted UTC, old-image rollback
prevention or finite Admin roles. A signature for a different PCR11 measurement
can authorize that measurement without resealing; this is not evidence of a
working installed A/B enrollment or recovery flow. Changed PCR7 intentionally
denies access until an independently authorized recovery/migration exists.
The native checkpoint loader uses the deployment-bound envelope and fixed
image key/installed signature paths directly. This replaces the proposed
plaintext `nv-auth` path. Explicit checkpoint enrollment also uses this primitive;
the complete product Admin bootstrap/service remains unimplemented.

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
Sequence 6 includes these signed policies and successfully booted the live
image, but its installer was refused because Ubuntu's packaged udev rules
assign the TPM device to `tss` while native admission requires root ownership.
The source repair installs final root:root 0600 rules in both the image and
initrd and retains the native root-owned-device check. It is not in sequence 6;
see the [image checkpoint](evidence/TEST_IMAGE_SEQUENCE6_2026-09-29.md).
Do not interpret live boot or source tests as installed Admin enrollment.

## Remaining software before the local installer can be complete

### Local principal binding prerequisite

Fresh installation now creates `/var/lib/luma-os/principals/registry.json`
inside encrypted mutable state, with a random installation namespace and
distinct 256-bit IDs for the two local human accounts. Entries carry their
login/UID, positive generation and enabled state. **Enabled is not Admin or
any role grant.** The private registry refuses duplicate identities, unknown
fields, unsafe metadata and runtime auto-initialization. It is currently
root-controlled metadata, not a TPM-anchored authority/anti-rollback record.

Native PAM authentication captures a principal and bounded local passwd/shadow
observation before invoking the helper. It then binds the returned UID to that
same principal and rechecks the registry/account state, including at each use
of the 30-second in-process observation. Registry replacement, changed
generation, disablement, changed credentials, duplicate UID or account
substitution fail closed. Once a change/error is observed, the observation is
permanently invalid; unlocking does not revive it. Shadow input uses the
existing locked, nondumpable, wiped buffer and is neither serialized nor logged.
The diagnostic's output remains explicitly non-authoritative.

No governed principal create/disable/rekey/recovery API is exposed yet, and
there is no automatic migration of older installations. Do not manually edit
the registry to establish Admin. Full account lifecycle, serialized effect-time
authorization, protected generations and TPM-sealed bootstrap still require
integration. Root rollback/ABA replacement is not prevented by content checks.
See [the local-principal checkpoint](evidence/G2_LOCAL_PRINCIPALS_2026-10-01.md)
for targeted checks and the deferred image-level matrix.

### Authentication and outstanding enrollment

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

Successful authentication is only a short-lived, principal-bound in-process observation. It is
not a serializable bearer capability, enrollment record, role assignment or
authorization for any effect. Checkpoint enrollment now binds the selected
principal to the deployment and initial TPM head, with identity-generation and
credential-revocation checks before dispatch. Finite-role service integration
still needs equivalent checks at every authority boundary. The diagnostic does
not activate product Admin. Real account/terminal tests and limitations are in
the [authentication checkpoint](evidence/NATIVE_ADMIN_AUTH_2026-09-29.md).

1. Evaluate the implemented pre-write TPM admission/intent path in a rebuilt
   image, and bind the selected product Admin principal through authenticated
   enrollment independently of root/sudo. Admission does not reserve an index
   or prove that provisioning, sealing, hierarchy authorization or NV capacity
   will succeed. It is not complete enrollment preflight.
2. Qualify the implemented native existing-owner checkpoint enrollment on an
   installed image and complete independently recoverable local credentials
   and reviewed interrupted-enrollment recovery. Exact allocation, collision refusal, random secrets and durable
   interruption/retry fencing now exist in source. Never clear the TPM, overwrite
   someone else's index, or silently take ownership of its hierarchies.
3. Integrate the checkpoint enrollment/loader with product Admin bootstrap and the
   complete confined service for the approved local platform/boot policy. Handle
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

## Explicit initial product Admin bootstrap

The source command below establishes the initial governance principal only
after checkpoint enrollment. It is intended for an approved newly installed
test system, not the Windows/WSL host, and has not been qualified on a rebuilt
image. The existing distributed image does not automatically contain it.

```text
sudo luma-platform admin-bootstrap LOGIN
sudo luma-platform admin-bootstrap LOGIN --activate REVIEW-SHA256
```

Each invocation prompts for the human account password through the protected
PAM flow. Use the original installer-selected UID 1001 account. The first
invocation is read-only and returns the review digest; independently review its
principal and checkpoint before the explicit activation. The digest binds the
current head, activation state, complete bootstrap payload and TPM boot epoch.
It is not an authenticator. Changed state or a reboot requires fresh inspection.
No owner authorization is requested again; no hierarchy credentials change.

Activation retains a private canonical `bootstrap.json` and appends its digest
and exact actor/activity/request to the authenticated TPM journal. Both pieces
must verify before the source command reports `product_admin_active: true`.
That flag describes the initial governance receipt, not a confined running
Admin service. No finite delegation, resource effect grant or signing capability
is enabled. The command returns no reusable authenticated session.

A partial or altered payload, disk/TPM mismatch, pending journal or unsupported
history refuses. Preserve it for review; do not delete the payload, clear an
index, restore genesis or fabricate role files. If the TPM committed the exact
successor but its publication/reply was lost, the existing reviewed committed
journal publication can make that already authorized receipt readable without
another TPM write. It cannot clear an uncommitted fence. Once readable, rerun
inspection and explicitly replay its current review if confirmation is needed;
replay requires fresh PAM and never repeats activation.

The [bootstrap evidence](evidence/G2_ADMIN_BOOTSTRAP_2026-10-04.md) records the
targeted source and software-TPM checks. Full installed PAM-to-TPM, confinement,
finite role/grant lifecycle, trusted time, independent recovery, production
custody and physical qualification remain required.

## Finite activity registration and role definitions

After explicit bootstrap, the source interfaces below let the original human
Admin inspect or explicitly commit finite catalog mutations. Each invocation
requires fresh protected PAM authentication. These commands are for an approved
installed test system, not the Windows/WSL host, and await inclusion and
qualification in a rebuilt candidate image.

```text
sudo luma-platform admin-governance-status LOGIN
sudo luma-platform admin-activity-register LOGIN register-model model.select
sudo luma-platform admin-activity-register LOGIN register-model model.select --commit REVIEW-SHA256
sudo luma-platform admin-role-define LOGIN define-operator Operator 0 model.select
sudo luma-platform admin-role-define LOGIN define-operator Operator 0 model.select --commit REVIEW-SHA256
```

Use each inspection's own digest after independently reviewing the principal,
request, command and current catalog. The review binds current checkpoint head
and TPM boot epoch; changed state/reboot requires reinspection. Request IDs must
be distinct for different commands. Keep the same ID and exact command when
reviewing a committed retry, even if a role has since advanced. Historical replay
does not replace the current definition or write the TPM again.

Role version zero creates; the exact current version updates. Activities must
already be registered, finite and unique. CLI lists are sorted; duplicate,
wildcard, undeclared and bootstrap activities refuse. `Admin` remains the fixed,
nondelegable bootstrap role. Native identifiers are limited to 64 ASCII
characters; catalogs are bounded to 128 activities and 128 roles, with at most
64 activities per definition. Identical registration/definition is a no-op:
no new payload, receipt or version. The four governance control activity names
are metadata defaults, not proof that assignment/revocation execution exists.

Each private event payload binds the exact actor, enrollment, sequence,
predecessor head, previous state version and command into the TPM journal.
All referenced payloads must verify on every replay. A retained unreferenced
proposal fences ordinary status and unrelated work; only that same request can
review/resume its exact complete proposal at the unchanged head. Partial,
changed, unsupported or uncertain state must be preserved. Never delete event
files, restore an older catalog/journal, reset genesis or repeat an uncertain
TPM write. The existing exact committed-journal publication is the only narrow
repair for an already TPM-proven successor; uncommitted proposals stay fenced.

A role definition grants nothing to a subject and authorizes no resource effect.
Trusted UTC, assignments, expiry/revocation, principal and credential recovery,
signing custody, the complete confined lifecycle and installed PAM-to-TPM
qualification remain open. The [catalog evidence](evidence/G2_ADMIN_CATALOG_2026-10-04.md)
records source and disposable-TPM checks, not G2 completion.

## Local catalog service and human client

The source now packages `luma-admin.service`, its `luma-admin` AppArmor
profile and the required `luma-peer-observer.service` with its separate enforcing
profile. It exposes catalog status, activity registration, role definition,
explicit adoption and reviewed non-Admin principal-generation changes. Adoption checkpoints a
snapshot without changing local accounts. This is not the complete assignment,
principal lifecycle, signing or effect
authorization service. The existing distributed image does not contain this
increment until the consolidated candidate is rebuilt and qualified.

On an approved installed test candidate, first complete the explicit checkpoint
enrollment and separately reviewed product bootstrap above. Then start the
service with the local maintenance authority:

```text
sudo systemctl start luma-admin.service
```

The unit is enabled in source, but missing `bootstrap.json` skips startup.
Presence of that file does not establish authority: every request verifies the
original principal, enrollment and complete TPM-backed semantic history. The
service refuses an unconfined/manual launch, complain-mode profile, unexpected
cgroup, disabled seccomp/no-new-privileges or unsupported memory/swap/task limits.
Do not bypass a refusal by removing confinement or changing the fixed limits.
The service is not a boot-health requirement; manual operation stays independent.
The Admin unit starts its observer dependency automatically. A missing, unconfined
or unverifiable observer denies requests; do not start a substitute process or
relax Admin's proc visibility or capabilities. The observer has no capabilities,
PAM/TPM credential access, model access, network time source or grant authority.
It accepts one bounded process-handle observation per protected local connection.

From the original UID 1001 human account, use the client **without sudo**:

```text
luma-platform admin-client LOGIN status
luma-platform admin-client LOGIN adopt-principals adopt-installed-principals
luma-platform admin-client LOGIN adopt-principals adopt-installed-principals --commit REVIEW-SHA256
luma-platform admin-client LOGIN register register-model model.select
luma-platform admin-client LOGIN register register-model model.select --commit REVIEW-SHA256
luma-platform admin-client LOGIN define define-operator Operator 0 model.select
luma-platform admin-client LOGIN define define-operator Operator 0 model.select --commit REVIEW-SHA256
```

Every invocation prompts through a masked controlling terminal. Independently
review the inspection's principal, request, command and current state before
using its `review_sha256`. The digest is not authentication; the commit requires
fresh PAM again. Preserve the exact request/command on reviewed retry. No
authenticated session or reusable bearer credential is returned.

Principal adoption must be explicitly inspected and approved after product Admin
bootstrap. The service captures only `/var/lib/luma-os/principals/registry.json`;
the request cannot supply registry contents, a path or a generation. Check every
principal's installation namespace, identifier, generation, login, UID and enabled
state in the proposal before approval. The snapshot must include the original
enabled enrolled Admin. A reviewed commit places its canonical semantic bytes in
the existing TPM-backed catalog history. It does not checkpoint passwords,
credential hashes, PAM configuration or the registry file's inode across restarts.
Maintenance can use `sudo luma-platform admin-principals-adopt LOGIN REQUEST`
and the same separately reviewed `--commit REVIEW-SHA256`; genuine local PAM,
installed-mode checks and the existing TPM checkpoint are still required.

After adoption, Admin catalog and shared UTC-history replay require the current
registry to match the adopted snapshot, including other accounts. Missing or
changed metadata fences these semantics without resetting the checkpoint.
Original registry handles are also pinned throughout a live catalog transaction;
even identical-byte file replacement refuses that transaction. An exact historical
request can be replayed without a new TPM write, and an identical new adoption is
a no-op. A different snapshot cannot replace adopted generations. Preserve any
interrupted intent and use reviewed journal publication only when its TPM proof
allows it; never repeat an uncertain write automatically.

The adopted snapshot is an immutable installation baseline. Reviewed changes to
the governed non-Admin principal generation and enabled state, and rotation of
the original enabled Admin's generation, are recorded in
TPM-backed history, not by editing that baseline. Existing pre-adoption history
remains readable and is not silently converted into principal authority. Account
creation, OS credential rotation and principal/custody recovery remain unavailable.
Resource, inference and effect boundaries do not yet consume the governed session;
principal/session and grant integration remains open, as does installed
confinement and native-hardware qualification.

From the original human Admin account, inspect and separately commit a change:

```text
luma-platform admin-client LOGIN principal-advance disable-user PRINCIPAL-ID CURRENT-GENERATION disabled
luma-platform admin-client LOGIN principal-advance disable-user PRINCIPAL-ID CURRENT-GENERATION disabled --commit REVIEW-SHA256
```

The principal ID must already belong to the adopted baseline. The exact current
generation is required. Every newly committed change advances it by one, even
when requesting the same enabled state; use `enabled` for a deliberate rotation
or to re-enable a governed-disabled principal. There is no force, caller-selected
next generation, wildcard or generation reset. An exact historical request replays
its receipt without changing the current state or extending the TPM again. The
bootstrap UID 1001 Admin is refused by this non-Admin command; use the separate
rotation command below. Initially disabled baseline accounts still require
separate account recovery. Maintenance can use
`sudo luma-platform admin-principal-advance LOGIN REQUEST PRINCIPAL-ID CURRENT-GENERATION enabled|disabled`
with the same reviewed commit option. Genuine PAM of the original Admin and the
existing installed TPM checkpoint remain mandatory.

After explicit principal adoption, the original Admin can inspect and separately
commit its own generation rotation:

```text
luma-platform admin-client LOGIN rotate-admin rotate-admin-generation CURRENT-GENERATION
luma-platform admin-client LOGIN rotate-admin rotate-admin-generation CURRENT-GENERATION --commit REVIEW-SHA256
```

Maintenance uses `sudo luma-platform admin-principal-rotate LOGIN REQUEST CURRENT-GENERATION`
with the same optional reviewed commit. This operation advances the original,
enabled UID 1001 principal exactly once. It accepts no target account, disabled
state, force flag, next generation or custody-transfer instruction. Zero, stale
and exhausted generations refuse without preparing a mutation. It does not
rotate passwords or TPM owner credentials, create another Admin, replace the
installation registry, or change the original enrollment/bootstrap payloads.

Each catalog or shared UTC-history event is checked against the Admin generation
that was current immediately before that event. Older events keep their original
writer identity; new writes use the current governed generation. Exact historical
request acknowledgement does not rotate again. Review digests bind the proposal,
current checkpoint and TPM epoch, so inspect again after any intervening change.
Existing governed sessions are fenced by the changed generation/head. A service
rotation commit attempt closes that request's PAM observation even on failure or
a lost reply; use fresh authentication for a subsequent request. Lost TPM replies
still require the existing reviewed publication of a proven committed journal,
never an automatic second write. Credential/custody transfer and account recovery
remain separate open implementations.

These changes do not lock Linux accounts or rewrite registry/passwd/shadow files.
Product disable is enforced by the governed session composition, not by ordinary
PAM alone. `sudo luma-platform principal-check LOGIN` double-replays the adopted
TPM principal history before starting a fresh local PAM exchange, then requires
that same governed state afterward. It reports the current governed identity,
returns no reusable session, role or effect grant and closes
its PAM observation before output. `admin-auth-check` remains only a local-account
authentication diagnostic and must not substitute for this governed check.

Login issuance retains the original registry handles and exact pre-PAM identity,
generation, enrollment, checkpoint head and TPM epoch. A private kernel-clock
boundary requires the PAM exchange to start after that precheck in the same
protected process and boot; an older genuine PAM observation is insufficient.
Journal and TPM writer locks are released while the human enters a password.
Changed authority, registry replacement (even identical bytes), a different PAM
account or clock/proof loss refuses issuance and closes the PAM observation.
Restart the complete login with fresh authentication; neither re-enabling an
account nor automatically rebinding to a newer head repairs an old attempt.
Ordinary catalog/status CLI commands, explicit principal adoption and the human
socket service now use this issuance path. The catalog scope is not convertible
to a general-principal session or an effect grant. After explicit bootstrap, the
original enrolled Admin may inspect/change the finite catalog before adoption;
general-principal sessions still require explicit adoption. After adoption,
catalog sessions bind the current governed Admin generation. Bootstrap and
offline custody recovery retain their separate ceremonies.

Status brackets its complete read with semantic replay and PAM. Mutations consume
a private one-use continuation bound to the exact command, request, installation
and prior head. The original registry handles, latest TPM clock floor, actual PAM
account and original IPC peer are checked through the operation and final result.
The session closes after inspection, no-op, replay, commit, refusal or unwinding;
inspect and commit therefore require separate fresh authentication. Journal
preparation and TPM dispatch retain their exact semantic/live-writer checks.
Interleaved history invalidates the review and old login; uncertain writes remain
pending and require reviewed reconciliation, not automatic retry or re-login.
No production ordinary catalog executor accepts a raw identity callback. This is
not yet the resource/inference/effect admission interface.

### Account credential checkpoint

After explicit bootstrap and principal adoption, use a local controlling
terminal for this separate reviewed maintenance operation:

```text
sudo luma-platform admin-accounts-checkpoint LOGIN REQUEST
sudo luma-platform admin-accounts-checkpoint LOGIN REQUEST --commit REVIEW-SHA256
```

Both calls require fresh governed Admin PAM. Inspection reads only the fixed
installation registry and protected account records; it does not write an event
or TPM state. Commit requires the exact current proposal review. It pins every
enabled installation account's original registry/passwd/shadow handles through
each writer boundary. Commitments are separated by installation, principal and
UID; passwords and password hashes are not exposed in command arguments,
proposals or receipts. This operation has no general socket command accepting
caller-provided hashes, source paths or credential bytes.

After commit, both Admin catalog scope and general governed sessions require the
current account records to match TPM-backed commitments. Replacing an account
file with different rows cannot be legitimized by fresh PAM or a process restart.
Equal historical requests acknowledge the earlier transaction without another
extend; an identical new checkpoint is a no-op. Other snapshots refuse and
require the separate governed lifecycle/recovery implementation, not re-adoption,
manual journal editing or root/TPM-owner override. Principal generation rotation
does not alter credential commitments. Lost TPM replies preserve pending state
and require exact reviewed committed publication, never redispatch.

Legacy records remain byte-compatible and are not automatically migrated.
Status/identity diagnostics explicitly report `account_credentials_checkpointed`;
false is not admission evidence for a future product grant. This command does
not create/delete accounts, rotate/reset passwords, lock/unlock Linux accounts
or repair changed credentials. Those account transactions, protected UTC,
grants/admission and their installed qualification remain open Requirement #1
work. Do not run this development command as host administration.

The [credential checkpoint evidence](evidence/G2_ACCOUNT_CREDENTIAL_CHECKPOINT_2026-10-08.md)
records isolated evaluation and remaining implementation/qualification limits.

### Existing account lock transactions

Use these commands only on a disposable installed Luma test environment with
intact enrolled TPM history, explicit principal adoption and the complete
credential checkpoint. Do not run them as host administration. `LOGIN` is the
original Admin; `TARGET` is an existing non-Admin installation account. Each
inspection and commit authenticates fresh governed Admin PAM. Inspection creates
or takes the operational migration lock but does not stage shadow, publish an
account file or extend TPM history.

```text
sudo luma-platform admin-account-lock LOGIN TARGET TRANSACTION lock
sudo luma-platform admin-account-lock LOGIN TARGET TRANSACTION lock --commit REVIEW-SHA256
sudo luma-platform admin-account-publish LOGIN TRANSACTION PUBLISH-REQUEST
sudo luma-platform admin-account-publish LOGIN TRANSACTION PUBLISH-REQUEST --commit REVIEW-SHA256
sudo luma-platform admin-account-complete LOGIN TRANSACTION COMPLETE-REQUEST
sudo luma-platform admin-account-complete LOGIN TRANSACTION COMPLETE-REQUEST --commit REVIEW-SHA256
```

Use `unlock` instead of `lock` for the inverse transaction. Give publication and
completion distinct request IDs, and use the review digest from that specific
phase's latest inspection. No source paths, password hashes or credential bytes
are accepted. Preparation pins the registry, directory, migration lock, passwd
and shadow. It anchors the exact mutation, advances the target generation and
fences its principal before any account-file replacement. A partial staging file
can only be completed under fresh review if it is an exact prefix of the approved
bytes; conflicting bytes are retained and refused, never truncated.

Publication permission is separately checkpointed. The owned continuation then
rechecks fresh TPM history and live Admin immediately before the descriptor-bound
shadow rename and synchronizes both directories. A committed permission is not
completion: the target stays disabled, with its old credential commitment, until
the third reviewed phase validates the new whole-file digest and target rows.
Completion adopts the approved credential commitment. A locked account remains
disabled; an unlocked account is enabled only at its new generation. Replacing
shadow invalidates all original account descriptors, so later phases need fresh
authentication. Restoring the old password cannot restore an old session.

An uncertain TPM reply must first use the existing exact reviewed journal
reconciliation, without redispatch. Then inspect and commit the same phase/request
again. If publication permission committed but shadow was not replaced, this
explicit continuation checks the old files and exact private staging before
publishing. If shadow already matches the new digest, it verifies publication
without a second rename or TPM extend. Other files, credentials or history refuse;
there is no automatic retry, rollback, journal reset or TPM-owner bypass.

Only one incomplete account transaction may exist at a time. Up to 128 retained
transactions are permitted; exhaustion refuses rather than silently discarding
history. No general Admin socket accepts these operations. Its strict read-only
identity mount is unchanged; local maintenance has narrowly enumerated AppArmor
file rules. Installed confinement, native interruption and physical TPM behavior
are unqualified. This lock source path does not create/delete users, lock the
original Admin, bypass broken authority or close Requirement #1. Existing
non-Admin password replacement has its separate ceremony below.

The [account transaction evidence](evidence/G2_ACCOUNT_LOCK_TRANSACTIONS_2026-10-09.md)
retains the final isolated sweep, all thirteen real PAM/software-TPM account cases,
prior failed attempts and explicit qualification limits.

### Existing account password replacement

This ceremony requires the same intact installed TPM history, adopted registry
and complete credential checkpoint as lock/unlock. Do not execute it as host
account administration. `LOGIN` is the original Admin and `TARGET` is an existing
non-Admin account with a usable crypt credential.

```text
sudo luma-platform admin-account-password LOGIN TARGET TRANSACTION
sudo luma-platform admin-account-password LOGIN TARGET TRANSACTION --commit REVIEW-SHA256
sudo luma-platform admin-account-publish LOGIN TRANSACTION PUBLISH-REQUEST
sudo luma-platform admin-account-publish LOGIN TRANSACTION PUBLISH-REQUEST --commit REVIEW-SHA256
sudo luma-platform admin-account-complete LOGIN TRANSACTION COMPLETE-REQUEST
sudo luma-platform admin-account-complete LOGIN TRANSACTION COMPLETE-REQUEST --commit REVIEW-SHA256
```

On the first inspection, enter and confirm the new password at the controlling
terminal without echo: at least twelve printable characters and no more than
256 UTF-8 bytes. This occurs before preparing and authenticating the Admin, so
secret entry does not consume the short governed PAM operation lifetime. The
proposal cannot be retained until fresh governed Admin authentication succeeds.
Do not put a password or hash in arguments, environment variables or JSON.

Unlike lock inspection, first password inspection deliberately writes a private
proposal, but does not replace shadow or extend TPM history. The distribution
libxcrypt adapter generates a fresh yescrypt salt and verifies its result in
locked external buffers. An atomic no-replacement directory rename publishes the
complete private intent/shadow proposal for later review. Interrupted temporary
directories remain private evidence, never reusable reviewed proposals. Up to
128 proposal/transition directories and 128 interrupted temporary directories
are admitted; exhaustion refuses without deleting anything.

Subsequent inspection and commit reuse the exact retained intent and salt and
require fresh governed Admin authentication. A commit without its retained
inspected proposal refuses. Each publication/completion phase needs its own
latest review digest and distinct request ID. Existing lock and aging fields,
passwd and all unrelated shadow records remain unchanged. This does not use
the host clock to renew password age or expiry. A disabled-but-unlocked governed
principal cannot be enabled by password replacement; use the separate reviewed
lock/unlock transition for an explicit enablement.

Preparation disables and advances the target generation. Publication preserves
the fence until completion adopts the exact new credential commitment. Old
passwords and sessions cannot regain access by restoring earlier bytes or by
changing the password back at a later generation. Uncertain TPM outcomes use
the same explicit exact journal reconciliation and phase continuation as
lock/unlock; already-published continuation does not rename again.

The general socket rejects password intents and cannot write the identity mount.
The image declares libcrypt build/runtime dependencies and narrowly enumerated
local maintenance AppArmor paths; this is not enforced-image qualification.
Original Admin password/lock recovery, usable new-account activation, generic
multi-file registry/group lifecycle, password-aging renewal, governed proposal retirement and damaged
authority reconstruction remain separate implementations. Requirement #1 is
still open. See the [password evidence](evidence/G2_ACCOUNT_PASSWORD_TRANSACTIONS_2026-10-09.md)
for the frozen source, executed checks and limits.

### Existing non Admin account deletion

Use this ceremony only on a disposable installed Luma test environment with
intact enrolled TPM history, explicit principal adoption and checkpointed account
credentials. It is not host account administration. `LOGIN` is the original
Admin. `TARGET` is an existing non-Admin installation account with its own
unshared primary group; shared or ambiguous groups refuse rather than deleting
another account's authority. It accepts no file paths, secret or supplied hash.

```text
sudo luma-platform admin-account-delete LOGIN TARGET TRANSACTION
sudo luma-platform admin-account-delete LOGIN TARGET TRANSACTION --commit REVIEW-SHA256
sudo luma-platform admin-account-delete-permit LOGIN TRANSACTION PERMIT-REQUEST
sudo luma-platform admin-account-delete-permit LOGIN TRANSACTION PERMIT-REQUEST --commit REVIEW-SHA256
sudo luma-platform admin-account-delete-file LOGIN TRANSACTION shadow
sudo luma-platform admin-account-delete-file LOGIN TRANSACTION gshadow
sudo luma-platform admin-account-delete-file LOGIN TRANSACTION group
sudo luma-platform admin-account-delete-file LOGIN TRANSACTION passwd
sudo luma-platform admin-account-delete-complete LOGIN TRANSACTION COMPLETE-REQUEST
sudo luma-platform admin-account-delete-complete LOGIN TRANSACTION COMPLETE-REQUEST --commit REVIEW-SHA256
```

Every invocation needs fresh governed Admin authentication. Use the latest
review digest for each checkpointed phase and distinct permission/completion
request IDs. Preparation reserves a bounded private transaction containing the
exact four before/after files and their ownership/permission commitments, then
anchors its intent and advances/disables the target principal. Permission is a
separate reviewed TPM event and performs no file publication. The explicit file
commands consume fresh process-local Admin continuations bound to that exact
transaction and current history; the committed permission covers only its four
manifest files in shadow-first order. A JSON receipt, root UID or generic PAM
session is not a dispatch capability.

Each file rename preserves its original mode and group and synchronizes both
directories. Unrelated account and group records, including group passwords,
remain unchanged; the target's memberships and private group are removed.
Partial publication keeps the principal disabled. After a restart, continue the
next file explicitly. Repeating an already published file verifies exact state
without another rename. An empty or exact-prefix private dispatch file may be
finished under the new owned continuation. Conflicting or out-of-order bytes
refuse and remain evidence; no implicit rollback or truncation is available.

Uncertain TPM results require exact reviewed journal reconciliation before any
continuation, not another TPM extend or automatic retry. Completion requires all
four published files and leaves the principal disabled permanently. Its original
registry entry and credential commitment remain historical evidence; the governed
tombstone reserves its ID, login and UID against ordinary re-enablement. Home
data is retained and existing Unix processes are not forcibly terminated. This
is neither home-data erasure nor generic worker/resource-drain integration.

Only one incomplete credential/deletion/creation transaction is admitted globally,
with 128 retained catalog transactions across all three types. Deletion staging additionally
counts complete and interrupted proposal directories against a 128-entry ceiling;
exhaustion refuses without removing evidence. The general socket rejects all
deletion phases and retains its read-only identity mount. AppArmor source
enumerates only the fixed local file and staging paths; enforcement is unqualified.
Usable new-account activation, original Admin credential recovery, generic registry mutation,
governed retirement and damaged-authority reconstruction remain open. See the
[deletion evidence](evidence/G2_ACCOUNT_DELETION_TRANSACTIONS_2026-10-09.md).

### New locked account creation

Use this only on a disposable installed Luma environment with intact enrolled
TPM history, principal adoption and checkpointed account credentials. `LOGIN`
is the original Admin. `NAME` is a new non-Admin account name. This path accepts
no caller-supplied UID, registry, home path, password hash or trusted timestamp.

```text
sudo luma-platform admin-account-create LOGIN NAME TRANSACTION
sudo luma-platform admin-account-create LOGIN NAME TRANSACTION --commit REVIEW-SHA256
sudo luma-platform admin-account-create-permit LOGIN TRANSACTION PERMIT-REQUEST
sudo luma-platform admin-account-create-permit LOGIN TRANSACTION PERMIT-REQUEST --commit REVIEW-SHA256
sudo luma-platform admin-account-create-file LOGIN TRANSACTION home
sudo luma-platform admin-account-create-file LOGIN TRANSACTION gshadow
sudo luma-platform admin-account-create-file LOGIN TRANSACTION group
sudo luma-platform admin-account-create-file LOGIN TRANSACTION shadow
sudo luma-platform admin-account-create-file LOGIN TRANSACTION passwd
sudo luma-platform admin-account-create-file LOGIN TRANSACTION registry
sudo luma-platform admin-account-create-complete LOGIN TRANSACTION COMPLETE-REQUEST
sudo luma-platform admin-account-create-complete LOGIN TRANSACTION COMPLETE-REQUEST --commit REVIEW-SHA256
```

First inspection asks for a hidden confirmed password, then authenticates the
governed Admin and retains the exact salt, private before/after evidence and home
marker. It does not create a visible home, publish account files or extend TPM
history. Later review and commit reuse that proposal rather than hashing again.
Passwords and hashes never enter arguments, the environment or returned JSON.

Preparation anchors the intent and fences the new installation principal at
generation one. Permission is separately reviewed and does not publish anything.
Each file command consumes a fresh owned Admin continuation scoped to this
transaction and current history. The empty mode-0700 home is published without
replacement before group/credential files; the registry is published last. The
new account has its own vacant UID/GID and no privileged group memberships.
Existing registry identities and their names/UIDs, including deleted accounts,
cannot be reassigned. Completion advances only the exact approved registry
extension and credential commitment, preserving the original installer snapshot.

All original sources, private evidence, directories and migration-lock handles
remain pinned through dispatch. Exact ordered publication and matching-prefix
dispatch files can resume explicitly after a restart. Conflicting files, replaced
handles, unsafe permissions and out-of-order changes refuse without truncation
or cleanup. An uncertain TPM reply requires exact reviewed journal reconciliation
before continuation. One incomplete transaction and the combined 128-transaction
catalog ceiling cover creation, deletion and existing credential changes.
Creation proposal and interrupted staging directories additionally share their
own 128-entry ceiling; evidence is preserved on exhaustion.

The new shadow credential remains locked with password age zero. Completion
keeps the governed principal disabled and records `needs_password_aging`.
Ordinary principal enablement, password replacement and lock/unlock cannot bypass
this fence. Protected UTC password-aging establishment and explicit governed
activation remain required; this transaction alone does not deliver a usable
account. The host clock is not treated as trusted UTC.

The general socket rejects all creation phases. Its strict read-only system
mount has no writable identity, principal-registry or home exception. AppArmor
source lists fixed local creation paths; enforcing installed-image qualification
is still required. Original Admin password/lock recovery, governed home-data
retirement and damaged-authority reconstruction remain open Requirement #1 work.
The [creation evaluation](evidence/G2_ACCOUNT_CREATION_TRANSACTIONS_2026-10-09.md)
records the frozen-source tests, real PAM/software-TPM cases, retained attempts
and qualification limits.

### Governed session continuity

The process-local governed session combines the original account pins and
30-second suspend-aware PAM lifetime with the current principal generation,
shared checkpoint head and TPM boot epoch. It consumes and owns its non-clonable
PAM observation rather than borrowing reusable authentication. It revalidates the
full semantic history before and after each protected projection, including the
identity diagnostic. The result is released only after both proofs match the
issued binding and PAM's final account-pin and lifetime checks pass. Failed or
unwound projections close the participating reader, session and PAM observation;
even a restored proof cannot reactivate them. Already closed or stale sessions
refuse before invoking the projection. Disable/re-enable, generation advance,
any shared-head change, clock/proof loss and expiry also permanently fence them.
The session retains its last fully verified TPM clock. Both replays must respect
that clock and epoch even when the protected composition uses a fresh reader;
changing readers cannot discard the monotonicity check. Login issuance likewise
checks its retained pre-PAM clock from the first post-PAM replay.
Fresh genuine PAM is required to bind the new state; restoring old metadata or
re-enabling the principal cannot revive
an old session. Installed resource/inference/effect admission still requires the
separate integration and qualification listed in the completion register.

This process-local projection is an identity-continuity primitive, not an effect
transaction. It neither grants authority nor reverses an operation that already
occurred. Actual effects still require their own role, folder, resource and
effect-time checks before dispatch, with governed outcome and recovery handling.

The fixed root-owned socket accepts only the kernel-observed UID 1001; root,
workers and ordinary users are not product Admin peers. PAM must resolve the
same UID and still-valid installation-scoped principal. Caller/role fields and
serialized tokens are refused. Password bytes travel in a separate fixed binary
frame directly into protected buffers, never request JSON, arguments,
environment variables or error replies. This is a local-only interface, not
an external Admin variant or model/browser-controlled endpoint.

The original connected process handle remains live through catalog authority
checks. Current real/effective/saved/filesystem UID and GID must match the
connection credentials in every original thread. The supported task set is
bounded to 32 threads and must stay stable during observation; missing tasks,
credential changes, disconnect, timeout or unverifiable kernel metadata deny
the request and permanently fence that peer object. The normal native client is
single-threaded. Restoring credentials does not revive an already fenced peer.
Each observer reply binds a fresh nonce and six exact, read-only kernel metadata
descriptors: its status, cgroup, AppArmor label and three resource limits. Admin
keeps its existing hidden proc view and CAP_CHOWN-only boundary. These are current
observations, not durable account-generation rollback protection or effect grants.

One request runs in one bounded child process. Timeout or lost reply never
automatically replays a mutation, clears a fence or reconstructs state. Inspect
and explicitly review an exact retry; use only the existing narrow committed
journal publication when its TPM proof permits it. Preserve uncertain proposals.

The [service checkpoint](evidence/G2_ADMIN_SERVICE_2026-10-04.md) separates
source/kernel-peer checks and policy parsing from still-required installed
AppArmor/seccomp enforcement, full PAM-to-TPM execution and interruption tests.
Never treat the protocol fixture as evidence that those installed flows passed.

The subsequent [real PAM composition checkpoint](evidence/G2_ADMIN_PAM_COMPOSITION_2026-10-04.md)
adds 17 socket requests through genuine PAM and the disposable native TPM
catalog adapter. It also bounds the complete authenticated identity projection
before and after its account reads. These checks improve source-level coverage;
they do not start the installed confined service, qualify enrollment/bootstrap
or replace the consolidated image tests above.

## Trusted UTC integration policy

The [UTC source design](TRUSTED_UTC_DESIGN.md) uses three NTS operators and
a protected uncertainty-bounded keeper, with explicit certificate bootstrap,
offline refusal and governed history. The owner approved the providers, initial
bounds and offline refusal on 2026-10-05. Fixed policy and keeper lifecycle code
remain non-authorizing; no time authority, assignment endpoint
or time-service configuration is enabled. Do not set the service's trusted-time
status from an OS synchronization flag or bypass its current refusal.
The [publisher source checkpoint](evidence/G2_UTC_PUBLISHER_2026-10-05.md)
adds a pinned chrony hook and bounded measurement codec, not an installed
trusted-time endpoint. Its producer generations are not keeper recovery
generations, and decoding a frame does not authenticate it or its history.
The [kernel measurement receiver checkpoint](evidence/G2_UTC_RECEIVER_2026-10-05.md)
adds sender/queue/replay checks in source but does not approve runtime custody,
restore protected time history or enable an installed time endpoint. Admin
assignment/revocation and workflow effect grants remain unavailable.

## Offline Admin custody recovery

The owner approved installer-enrolled offline recovery custody on 2026-10-08;
[ADR-0011](../docs/adr/0011-local-utc-runtime-and-offline-admin-recovery.md)
records it alongside the fixed local UTC runtime design. The installer now
generates a separate random 256-bit Admin recovery credential, displays it only
on the controlling terminal and requires hidden re-entry before partitioning.
It is distinct from the account password, disk recovery passphrase and TPM owner
authorization. Store it outside the machine; Luma persists no plaintext copy.

The principal registry contains only a domain-separated, salted verifier bound
to the installation, original Admin principal, UID 1001 and recovery credential
generation one. Explicit TPM checkpoint enrollment, product bootstrap and
principal adoption must commit before that verifier can authorize recovery.
The installer does not silently perform those ceremonies. Existing registries
without a verifier preserve their original serialization and refuse recovery;
neither missing state nor root access creates a replacement credential.

On the installed system, `sudo luma-platform admin-custody-recover REQUEST`
uses a separate local-terminal ceremony. Enter the current offline credential;
record and confirm a newly generated credential; inspect the exact proposal;
and re-enter its review SHA256. The native proof is boot/process/root-bound and
expires after 30 suspend-aware seconds, starting after preparation. It does
not renew on use. No credential, verifier or proof is accepted through the
general Admin service as a recovery command.

The shared TPM transaction advances the original Admin's product generation
and the recovery credential generation together. The replacement verifier is
checkpointed; the immutable installer registry and historical writer prefixes
are not rewritten. Governed `PrincipalSession` objects fence on their next protected observation and
old credentials cannot authorize another recovery after commit. An error,
unwind, changed original registry/head/TPM epoch or expired proof refuses; a
reviewed write attempt consumes the in-process proof even after an uncertain
outcome. Retained pending/event files must be preserved for exact reconciliation.
Do not retry a TPM write, reset history, or substitute TPM-owner authorization.

This is product custody-generation recovery, not Unix password reset, an
Admin-principal transfer, signing-key recovery, reconstruction of damaged
authority, an effect grant, or stage closure. Those account-lifecycle and
integrated installed-image paths remain separate open work. Installed terminal
custody, confinement, crash/reboot publication and physical TPM qualification
still need retained evidence.
The subsequent [stream composition](evidence/G2_UTC_STREAM_2026-10-05.md)
processes all receiver rounds through the keeper and reprojects current samples
at fresh clock boundaries within a bounded heartbeat deadline. It does not
approve runtime/history inputs, deliver protected lifecycle notifications or
change Admin's refusal of assignments and effect grants.
The [kernel step watch](evidence/G2_UTC_STEP_WATCH_2026-10-05.md) adds fail-closed
clock-change notification checks around candidate evaluation, not trusted-time
authority or TPM-backed history. Admin assignments/effects remain unavailable.

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
grants or Docker socket. Legacy test-only provisioning/undefinition commands
use the disposable emulator, not a product command interface. The new native
fixed-index provisioning primitive has its own existing-owner fixture. A separate
enrollment acceptance fixture now passes native sealing, durable parent and NV
preparation, provisioning, readback, publication and credential delivery with
existing ownership. The old systemd 255 refusal is retained as a separate
compatibility check; neither fixture substitutes for installed PAM-to-TPM or
physical testing.
Private emulator state
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
  for the primitive; confined-service/enrollment qualification remains pending.

The built Ubuntu toolchain uses TPM2-TSS 4.0.1 and tpm2-tools 5.6; executed
tool behavior, rather than assuming all newer documentation options exist,
is retained in the test transcript.
