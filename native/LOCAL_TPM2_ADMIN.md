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
profile. It exposes only catalog status, activity registration and role
definition. This is not the complete assignment, principal, signing or effect
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
