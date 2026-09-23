# ADR-0010: Durable Admin events and offline-source revalidation

- Status: Accepted for development; production identity, anchors, and physical evidence remain blocked
- Date: 2026-09-23
- Decision owners: security lead, release engineer, platform lead
- Extends: ADR-0007 and ADR-0009
- Applies to: catalog authorization, offline installation-source descriptors, and installer schema version 3

## Context

Catalog signatures and root-signed public trust do not establish that an
approval or signing assignment was issued by the authenticated Admin service.
Likewise, a parsed offline-source descriptor or a prior validation receipt is
not authority to consume release bytes or mutate a disk. These decisions must
survive process restart, reject rollback and substitution, and remain current
through the last authority boundary.

SQLite, an HMAC, or a Python object cannot independently establish all of
those properties. SQLite and HMAC can protect a local event representation;
writer identity must come from an authenticated external Admin service, and
rollback resistance must come from protected state outside the database. An
offline descriptor can bind expected digests, but only separately governed
pins and verification of the bytes actually consumed can establish release
provenance.

## Decision

### Integrity-protected durable Admin event log

The development reference stores bounded, canonical ASCII events for exact
assignment grants, assignment revocations, catalog approvals, and catalog
signing authorizations. Events have a monotonic sequence, previous-event
SHA-256 link, and HMAC-SHA256 tag made with an injected secret that is never
stored in the database. SQLite uses transactional append, WAL, and full
synchronization. The store rejects unexpected persistent or temporary schema
objects, including triggers and views, and verifies the exact committed row
and reconstructed head before advancing the external checkpoint. The complete
bounded log is also verified on reopen and on each authorization query.

The HMAC proves only that the configured store accepted the bytes and that
the stored representation has not changed under that secret. It does **not**
authenticate a human, service, or caller. Construction therefore requires a
non-optional `AdminEventWriterAuthorizer`. Immediately before each append,
that adapter must authenticate and authorize the exact grant, revoke actor,
approval, or signing statement. A false result or exception denies the append;
clock rollback, malformed transitions, and field or receipt substitution also
fail closed. The log may retain a historical or now-expired event when the
external writer explicitly authorizes that exact append. Assignment expiry and
revocation deny authorization when the log is queried at the requested time;
HMAC persistence must not silently rewrite history into current authority.

Catalog verification uses a read adapter over the authenticated event log. It
matches the exact principal, activity, assignment and decision receipt,
request, catalog, and release at the requested time. A caller-constructible
`RoleAssignment`, approval object, signing statement, or in-memory identity is
not authority.

A complete catalog-authorization batch performs one bounded, fresh,
authenticated event replay for that call rather than replaying the same log
once per approval and signer. It verifies the exact database head and external
checkpoint before and after the transactional snapshot and again as the batch
completes. No verified state is retained as a long-lived authorization cache;
an appended revocation is therefore effective on the next call. This is a
bounded development optimization, not target performance evidence: maximum-
capacity replay time, external-anchor latency, native filesystem behavior,
and SQLite lock contention remain unqualified on the target Ubuntu systems.

The current contract is one centralized logical Admin event log. Its HMAC
domain and anchor namespace are fixed; it is not a safe multi-tenant,
multi-deployment, or independently writable multi-store design. Two stores
must not share the secret or write the same external checkpoint namespace.
Production requires one authoritative service plus a unique deployment/service
identity, checkpoint namespace, and protected secret-custody domain. Adding
multi-host replication or independent stores requires an explicit domain-
separation and consensus/fencing design that is not present here.

### External checkpoint and reconciliation

Every usable non-empty database head must equal the exact checkpoint in an
injected `ExternalDigestAnchor`. Authorization fails closed if that checkpoint
is missing, unavailable, malformed, ahead of the database, or behind it. The
repository's in-memory anchor is a test fake and supplies no production
rollback resistance.

There is no atomic transaction spanning SQLite and an external anchor. The
store commits the event locally, then attempts an exact compare-and-swap of
the checkpoint. If the compare-and-swap is rejected or the process fails in
that interval, the database may be ahead. An anchor-side advance can instead
leave the anchor ahead. Either state is a typed reconciliation-required
condition and authorizes nothing. The implementation must not silently roll
back either side, automatically replay an ambiguous authorization, or claim
distributed atomicity. Production requires a reviewed, operator-controlled
reconciliation procedure and retained evidence.

### Inert offline installation-source validation

The offline-source descriptor is bounded canonical data containing release,
architecture, base-image, payload, release-metadata, package-lock, and SBOM
digests. It does not contain a catalog. Validation starts from the immutable
raw descriptor bytes,
an independently supplied expected descriptor SHA-256, the expected
environment, the exact installer edition, and a current anchored catalog
admission. That validation context and its receipt bind the descriptor to the
release, architecture, edition, catalog sequence and digest, catalog admission,
and trust-bundle digest.

The returned validation record and receipt are inert historical data. They
are deliberately caller-constructible and never confer installer authority.
The expected digest is also caller input: unless a protected release-governance
system supplied it, it is not evidence of approval. Descriptor validation does
not hash or verify the referenced base image, OS payload, metadata, package
lock, SBOM, or signatures, and it does not prove that an installer later
consumed those bytes.

### Installer schema version 3

Schema-version-3 preflight accepts the raw descriptor bytes, expected digest,
expected environment, and anchored catalog admission as separate inputs and
invokes source validation itself. It never accepts a prior
`ValidatedInstallationSource` as authority. The plan binds the actual and
expected environment and descriptor digests, validation-receipt digest,
complete edition digest, catalog digest and sequence, catalog-admission plan
digest, and trust-bundle digest. Confirmation repeats the expected environment, descriptor
digest, and validation-receipt digest.

Execution obtains fresh raw inputs from an `InstallationSourceProvider` and
performs full validation twice:

1. after fresh hardware inventory and before device binding or attempt-journal
   creation; and
2. after journal creation at the effect boundary and before current
   authorization and the injected executor. For a model-bound plan, a fresh
   hardware sample and model selection are revalidated against that source
   admission's catalog after the potentially slow provider. Execution
   authorization follows, then catalog/trust currentness and confirmation/
   inventory freshness are checked before executor entry.

Both passes must reproduce the plan and confirmation bindings. A changed raw
byte, digest, environment, edition, catalog, trust state, or provider result
fails closed. The plan, confirmation, provider result, and validation receipt
remain data rather than disk-effect capability.

### Transitive catalog and trust freshness

A protected composition root supplies the live clock, root policy, public-only
cryptographic provider, Admin authorization reader, and external anchors. The
trust admission retains the exact clock and provider selected there: callers
cannot pass a backdated verification instant or replace the provider when they
later create a leaf verifier. Trust commit and each verifier use re-parse and
re-verify the root signature, policy, lifecycle, and exact checkpoint. Module-
private tokens and Python object identity only guard correct trusted
composition; they do not protect against hostile code in the same process.
Untrusted models, plugins, and IPC peers must submit raw artifacts to an
isolated trusted service rather than receive authority objects.

A catalog admission is usable only while its exact catalog checkpoint and the
exact anchored trust bundle remain current. Catalog, signature, approval,
signer, pack tuple, policy, lifecycle, and trust state are checked with a live
trusted clock at commit and on authoritative access. A newer catalog or trust
bundle, expiry, revocation, anchor outage, malformed checkpoint, or failed
Admin revalidation makes a previously retained catalog admission stale. Lab
trust cannot authorize a production catalog.

Catalog admission retains a bounded immutable snapshot of the supplied
`ModelPackVerification` records and repeats the catalog-to-pack tuple checks
against that same snapshot. This prevents tuple substitution inside the
admitted artifact, but it is not a live re-read of pack files, signatures,
certification/revocation services, runtime binaries, or loadability. The
composition root must create those records from freshly verified evidence and
prepare a new admission whenever pack or certification state changes.

## Consequences

- Restarted processes can reconstruct exact catalog authorization from
  integrity-protected persisted events, but only when the external Admin
  writer boundary and checkpoint also validate.
- HMAC secret custody, database permissions, writer authentication, clock
  trust, and rollback-resistant anchor storage become explicit production
  dependencies rather than properties attributed to SQLite.
- A cached catalog authority fails after relevant catalog/trust change. A
  cached source-validation result remains readable as historical data but is
  never reusable as authority; every authority boundary starts again from
  fresh raw inputs.
- Authority objects are not serialized credentials. After restart, the trusted
  service reconstructs authority from raw signed artifacts, authenticated Admin
  events, the provisioned composition policy/provider/clock, and current external
  checkpoints.
- Schema-v3 narrows time-of-check/time-of-use gaps for descriptor metadata but
  does not convert a Python reference contract into a disk installer.
- Availability failures at the Admin service or external anchors deny
  authorization. This is intentional fail-closed behavior.

## Production blockers

This decision does not close G2. Production still requires:

- an OS-authenticated, process-isolated Admin service implementing the exact
  writer-authorizer contract, plus reviewed bootstrap and recovery;
- protected HMAC-secret custody, a trusted clock, durable rollback-resistant
  compare-and-swap anchors, unique deployment/service domains, and a rehearsed
  reconciliation procedure;
- provisioned production roots, non-exportable HSM keys, named separated
  custodians, a witnessed ceremony, revocation and recovery exercises, and an
  actual signed production catalog and model packs;
- authenticated release governance for the descriptor pin and edition, plus
  signature and digest verification of every artifact byte actually consumed;
- a privileged installer, native device/peer identity, UKI, Secure Boot,
  dm-verity, LUKS2, A/B boot and recovery integration; and
- destructive-install, boot, recovery, power-loss, security, and performance
  qualification on the designated native Ubuntu 24.04 physical systems.

Windows and Ubuntu WSL contract tests remain useful development evidence, but
they share one physical host and cannot satisfy those production blockers.

## Change control

Changing event canonicalization, writer-authorization semantics, HMAC or
checkpoint/deployment domains, reconciliation behavior, descriptor fields, source
revalidation boundaries, authority-token freshness, or schema-v3 bindings
requires a superseding ADR and security review.
