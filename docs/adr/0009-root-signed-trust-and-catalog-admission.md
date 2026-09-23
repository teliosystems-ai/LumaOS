# ADR-0009: Root-signed trust distribution and anchored catalog admission

- Status: Accepted for development; production roots and rollback storage remain blocked
- Date: 2026-09-23
- Decision owners: security lead, release engineer, platform lead
- Extends: ADR-0005 and ADR-0007
- Applies to: public signing trust, model-catalog verification, revocation, and rollback control

## Context

The detached model-catalog contract defines the data that a production
catalog must sign, but a caller-provided key table or rollback floor is not a
production trust decision. A compromised or misconfigured caller could select
the wrong public key, reuse a lab key in production, lower a sequence floor,
or continue using a catalog after a newer trust decision was published.

Private signing material must remain outside Luma OS. The runtime therefore
needs a public-only path from an externally provisioned root key to the exact
leaf key, purpose, environment, lifecycle, catalog digest, and monotonic
checkpoint that authorize an artifact. Verification and publication must be
separate so a successful signature check cannot be mistaken for committed
authority.

## Decision

### External roots and signed trust bundles

Lab and production root public keys are provisioned out of band. A trust
bundle cannot introduce or replace its own root. The root signs canonical,
bounded ASCII JSON containing:

- an environment and trust domain;
- a monotonically increasing bundle sequence and predecessor digest;
- an accepted policy version and validity interval; and
- unique Ed25519 leaf public keys with exact roles, purposes, validity, and
  optional revocation information.

Leaf validity must be contained by bundle validity, and bundle validity must
be contained by the selected root's effective validity. Root and leaf key
reuse across separated environments is rejected when the externally trusted
configuration identifies the other environment's keys. Root keys cannot also
be leaf keys.

Trust admission is two phase. Preparation verifies canonical form, policy,
environment, lifecycle, the root signature, sequence, predecessor, and the
checkpoint read from an external compare-and-swap anchor. Commit succeeds only
against the same anchor and exact checkpoint observed during preparation. Only
the committed result can create a purpose-bound verifier. It rechecks the
root, bundle, leaf, and exact current external checkpoint for every operation,
so a cached verifier fails after expiry, revocation, anchor failure, or a
newer bundle.

The repository's in-memory checkpoint implementation is a deterministic test
fake. It is neither durable nor rollback-resistant and is never production
evidence.

### Public-only cryptographic provider

The concrete provider accepts only an immutable 32-byte Ed25519 public key,
message bytes, and a 64-byte detached signature. It has no signing, key
generation, or private-key interface.

On the Ubuntu path, OpenSSL is invoked by an absolute provenance-checked path
with a fixed argument vector, `shell=False`, a controlled environment and
configuration, private exclusive temporary inputs, bounded output, and a
timeout. Ambiguous provider behavior fails closed. Windows use requires a
separately qualified native executable and ACL provenance adapter; a pathname
alone is not treated as Windows trust evidence.

### Catalog admission

A verified catalog receipt is evidence, not authority. Catalog admission:

- accepts only a committed trust bundle for the same lab or production
  environment;
- obtains the rollback floor from a fixed environment-specific external
  namespace rather than from the caller;
- verifies the exact release, accepted catalog policy, approval set, signer,
  signature purpose, pack tuples, and catalog sequence;
- binds catalog, envelope, trust-bundle, and verification-receipt digests in a
  non-authoritative preparation plan; and
- returns an authority token only after exact compare-and-swap commit and a
  retained-value read.

A same-sequence replay is accepted only when the digest is identical and a
fresh preparation observes that exact checkpoint. A failed compare-and-swap
never returns authority, even if another writer installed the same value. The
committed token rechecks that its exact checkpoint remains current before
exposing authoritative catalog data.

## Consequences

- Callers can no longer choose a catalog rollback floor or construct a
  production catalog verifier from an unanchored key table.
- Lab and production catalog namespaces, signing purposes, and roots remain
  distinct.
- Key rotation and revocation require publishing the next signed trust bundle
  and atomically advancing protected checkpoint storage.
- The OS release and installer can consume an anchored catalog token instead
  of treating a plain parsed catalog or receipt as authority.
- Availability of the external checkpoint service becomes part of the
  fail-closed verification path.

## Certification boundary

These contracts and their Windows/WSL tests do not provide production keys,
protected root provisioning, an HSM, a witnessed signing ceremony, a native
rollback-resistant checkpoint implementation, signed model packs, or a signed
production catalog. They do not authorize disk mutation and do not close G2.
Those assets and physical evidence remain governed by the production-custody
and G2 qualification procedures.

## Change control

Changing the canonical encoding, signature algorithm, root-provisioning rule,
role/purpose mapping, environment separation, lifecycle containment, external
checkpoint semantics, or the prepare/commit authority boundary requires a
superseding ADR and security review.
