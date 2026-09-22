# ADR-0005: Model-pack format, certification, and signing

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: inference lead, security lead, release engineer, license owner
- Applies to: G1 model selection and all later model distribution

## Context

Model weights, tokenizers, templates, runtimes, licenses, and execution evidence vary independently. A filename or successful load is insufficient to establish integrity, compatibility, redistribution rights, or an interactive service claim.

## Decision

### Canonical pack

The canonical model pack is an immutable directory, imported into a private content-addressed store:

```text
model-pack/
|-- manifest.json
|-- manifest.sig
|-- blobs/sha256/<digest>
`-- licenses/<declared-license-files>
```

Symlinks, hard links, device files, absolute paths, `..`, duplicate normalized paths, and undeclared files are rejected. A transport archive is only an input to a bounded safe importer; it is never executed or trusted in place.

`manifest.json` uses a versioned JSON schema and records at least pack ID/version, model and architecture identity, parameter class, quantization, every blob digest and size, tokenizer, chat/template digest, context limits, runtime/backend compatibility, required features, default-deny network behavior, source locator, license identifiers/files, redistribution decision, and signer key ID.

The manifest is serialized with RFC 8785 JSON canonicalization and signed with Ed25519. Every declared blob is verified with SHA-256 before it becomes loadable. Algorithms are versioned fields so migration can be explicit.

### States

- `recognized`: manifest schema and identifiers are understood; this makes no load or execution claim.
- `loadable`: signature and all blob digests pass, license use is approved for the stated context, and the exact runtime tuple satisfies declared compatibility.
- `execution-certified`: signed test evidence binds the pack digest to exact OS, kernel, driver, backend, device, resource limits, context, and required execution tests.
- `interactive-certified`: execution certification plus the required latency, quality, cancellation, recovery, and sustained-load thresholds for that exact tuple.

States only advance. A changed byte, runtime, driver, template, context, or material resource limit creates a different tuple and cannot inherit certification silently.

### Keys and evidence

- Signing private keys and recovery material never enter Git, source archives, model packs, logs, or test fixtures.
- Development/lab keys are distinct from production release keys and are marked non-production in their trust records.
- The trust store contains public keys, roles, allowed purposes, validity bounds, and revocation state. Verification binds a signature to the requested purpose and verification time; unknown, expired, not-yet-valid, revoked, wrong-role, or wrong-purpose keys fail closed.
- Manifest import, execution certification, and interactive certification are distinct signing purposes. A key authorized for one purpose cannot promote a pack to another lifecycle state.
- The Luma OS `Admin` role governs the signing-role catalog and may assign finite signing activities to authenticated custodians as defined by ADR-0007. This product authorization never exposes raw key material or substitutes for protected key storage.
- Each signing operation records the acting principal, assignment and activity, input digest, key identifier, policy version, output digest, and timestamp. A model, model worker, generated program, or ordinary skill cannot be a signing custodian.
- Pack signatures attest integrity and authorized provenance only. They do not prove model safety, task quality, license compliance, or runtime certification.
- Execution certificates are separate signed evidence documents referencing the immutable pack and release tuple.
- Candidate models cannot enter measured comparison until the license register records evaluation and redistribution decisions.

## Consequences

- Model assets remain outside Git and can be independently acquired where licenses permit.
- Unsigned developer assets may be inspected only in an explicit development mode and can never receive a release certification state.
- Import safety, signature/digest tampering, key-role, revocation, tuple drift, and downgrade tests are mandatory.
- The development governance decision is complete: `Admin` governs roles and signing activities. Production custody remains a formal-certification blocker until named human custodians, protected key storage, recovery, rotation/revocation, separated trust roots, and a retained verification exercise exist.

## G1 change control

Changing the canonicalization, signature/hash algorithms, state meanings, mandatory manifest identity, trust roles/purposes/lifecycle checks, or allowing certification to float across tuples requires a superseding ADR and migration/security review.
