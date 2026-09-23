# Production model-catalog signing and custody runbook

## Status and boundary

This runbook defines the decisions, people, protected equipment, artifacts,
ceremony, and evidence required to turn a tested model profile into a
production-selectable Luma OS catalog entry. The repository now provides a
strict detached catalog-signature contract and a no-private-key ceremony
utility, plus development reference contracts for root-signed public trust,
anchored catalog admission, and integrity-protected Admin authorization events.
It does **not** provide production keys, an HSM, an authenticated/process-
isolated Admin identity and writer service, protected HMAC-secret custody,
rollback-resistant production anchors, or a certified model pack.

Completing the development contract on Windows or Ubuntu WSL does not prove
production custody. A production ceremony must run on controlled native Linux
workstations with approved protected key storage. WSL remains useful for
schema, canonicalization, negative, and public verification tests only.

A valid catalog signature proves authorized provenance and integrity of the
catalog statement. It does not by itself prove model safety, license rights,
pack integrity, runtime certification, physical installation, or boot-chain
security. Those claims require their own evidence.

## Decisions and inputs required from the owner

The owner must approve and provide the following before a production ceremony
can be scheduled:

| ID | Owner decision or input | Required record |
| --- | --- | --- |
| SC-01 | Approve this role, quorum, and separation policy, including the rule that a production signer cannot be one of the three catalog approvers | Versioned policy approval and SHA-256 digest |
| SC-02 | Nominate authenticated human principals for Admin, License Approver, Security Approver, Release Approver, Catalog Signing Custodian, Model-pack Custodian, Certification Custodian, Auditor/Witness, and three Recovery Custodians | Private roster with identity proofing date, owner, backup, and revocation contact |
| SC-03 | Approve an Ed25519-capable HSM or hardware-token design, including two independently stored production devices or an equivalent supported high-availability design | Security architecture and vendor capability evidence |
| SC-04 | Approve a two-of-three recovery policy and two geographically or administratively separated secure storage locations | Recovery policy and storage attestations |
| SC-05 | Approve the exact model revision, quantization, tokenizer, prompt template, runtime, license use, redistribution decision, and offline distribution scope | License decision and immutable artifact inventory |
| SC-06 | Assign a release ID, monotonically increasing catalog sequence, catalog policy version, activation time, expiry, and rollback floor | Release request signed or authenticated by the release owner |
| SC-07 | Provide a controlled native Ubuntu ceremony workstation and an independent offline verification workstation | Asset IDs, clean-build or measured-state records, time source, and network-isolation record |
| SC-08 | Approve retention, audit access, incident response, key rotation, revocation, and destruction periods | Operations policy and evidence-retention schedule |
| SC-09 | Approve one authoritative Admin writer/identity service, its deployment identity and process boundary, HMAC-secret custody, and trusted clock | Service design, deployment identity, identity proof, secret-custody record, time-source evidence, and negative-test results |
| SC-10 | Approve a unique deployment/service checkpoint namespace, rollback-resistant compare-and-swap storage, and the non-atomic database/anchor reconciliation procedure | Anchor design, namespace allocation, access policy, backup/recovery rule, and witnessed reconciliation drill |
| SC-11 | Approve the offline-source descriptor pin, exact installer edition, and consumed-artifact verification process | Signed release decision, canonical descriptor digest, edition digest, final-media inventory, and independent hash/signature results |

Names, private facility details, recovery shares, token PINs, and unredacted HSM
logs must remain in the restricted evidence store, not this public repository.

If there are not enough distinct people to meet SC-02, use the `lab`
environment only. A single Admin can govern all activities, but one person or
shared account must not be represented as separated production custody.

## Product roles and exact activities

`Admin` remains the fixed Luma OS governance super-role. It registers the
finite activities below, defines roles, assigns authenticated humans, and
revokes assignments. Admin authorization never exposes a private key and does
not replace the catalog approval quorum, HSM access control, or effect-time
checks.

| Operational role | Exact activity | Production rule |
| --- | --- | --- |
| License Approver | `model-catalog.approve.license` | Confirms evaluation and redistribution decision for every included pack |
| Security Approver | `model-catalog.approve.security` | Confirms threat review, runtime tuple, test evidence, key policy, and known limitations |
| Release Approver | `model-catalog.approve.release` | Confirms release ID, catalog sequence, profile availability, and evidence completeness |
| Catalog Signing Custodian | `model-catalog.sign.production` | Operates only the production catalog key after all three approvals exist |
| Lab Approver | `model-catalog.approve.lab-release` | Authorizes a non-production lab catalog only |
| Lab Catalog Custodian | `model-catalog.sign.lab` | Uses a lab-only key and trust root |
| Model-pack Custodian | `model-pack.sign.production` | Signs canonical model-pack manifests, never catalogs or certificates |
| Execution Certification Custodian | `model-pack.certify.execution` | Signs exact execution tuple evidence |
| Interactive Certification Custodian | `model-pack.certify.interactive` | Signs exact interactive tuple evidence after execution certification |
| Trust/Revocation Custodian | `trust-bundle.publish` | Publishes root-authorized public keys and revocations |
| Recovery Custodian | `signing.recovery.execute` | Participates in the approved two-of-three recovery procedure |

Production catalog approval requires exactly the license, security, and
release activities, held by three distinct current principals. The catalog
signing principal must be a fourth person. The auditor/witness observes the
ceremony and verifies evidence but cannot approve or sign the artifact being
audited. Admin assignments should be time-bounded to the ceremony window and
revoked immediately afterward unless a documented operational need exists.

## Key hierarchy and storage

Use distinct public-key identities and non-exportable Ed25519 private keys:

| Key | Storage and activation | Permitted purpose |
| --- | --- | --- |
| Offline production trust root | Offline HSM; two-person activation; two-of-three recovery; no routine release signing | Authorize and revoke production public trust records only |
| Production model-pack key | Separate production HSM partition/token; custodian plus witness | `model-pack-manifest` |
| Production catalog key | Separate production HSM partition/token; catalog custodian plus witness | `model-profile-catalog-production` |
| Production certification key | Separate production HSM partition/token | Execution and interactive certificates, subject to separate approval policy |
| Lab catalog/model keys | Lab token or development keystore, marked non-production | Lab purposes only |

Do not place production private keys, exportable backups, PINs, recovery
material, or HSM configuration secrets in Git, a source archive, the model
pack, the installation image, CI variables, logs, shell history, tickets, or a
model-accessible process. Prefer vendor-supported HSM cloning or wrapped backup
objects over raw seed export. If the selected device cannot provide controlled
backup, document how loss of the key is handled without bypassing revocation
and rollback protections.

The root-signed public trust bundle must contain key ID, role, allowed purpose,
public key, validity interval, revocation state, environment, policy version,
and monotonically increasing bundle version. The installer must reject an
unknown, expired, not-yet-valid, revoked, wrong-role, wrong-purpose, or
lab-for-production key. The development trust admission contract validates
those conditions and rechecks exact current trust/catalog state. Production
activation still requires provisioned roots, protected rollback-resistant
checkpoint storage, a trusted clock, and independently reviewed platform
adapters; the repository's in-memory anchor is only a test fake.

## Required artifacts

Retain these immutable artifacts by SHA-256:

1. canonical model-pack `manifest.json`, detached `manifest.sig`, every declared
   blob, license files, and complete offline inventory;
2. model-pack verification receipt and exact loadable runtime tuple;
3. signed execution certificate and its evidence; an interactive certificate
   when the catalog claims `interactive-certified`;
4. canonical model-profile catalog conforming to
   `schemas/model-profile.schema.json`;
5. canonical pre-approval release request binding the environment, release,
   catalog ID and digest, sequence, policy, purpose, algorithm, validity,
   signer key and principal, signing activity, assignment, and assignment
   receipt;
6. canonical approval set containing the three production approvals, release
   request digest, Admin assignment-receipt digest, and a distinct authenticated
   approval-decision receipt digest for each decision;
7. canonical catalog signature statement reconstructing and binding that exact
   release request;
8. raw 64-byte Ed25519 statement signature;
9. detached envelope conforming to
   `schemas/model-catalog-signature.schema.json`;
10. root-authorized trust bundle and current revocation list;
11. exact Admin grant, revoke, approval, and signing events; writer-service
    authentication evidence; event-log checkpoint; and any reconciliation
    record;
12. canonical offline installation-source descriptor, separately governed
    descriptor pin and edition approval, plus independent signature and digest
    results for every image, payload, package-lock, metadata, and SBOM byte
    actually placed on media;
13. independent trust/catalog admission receipts and rollback-floor update
    receipts; and
14. independent catalog verification receipt,
    HSM audit event, ceremony log, witness sign-off, and final offline bundle
    inventory.

The verification receipt emitted by `verify_signed_catalog` binds the catalog,
statement, signature, approval set, signer key, policy, sequence, release, and
verification time. It is verification evidence, not proof that the HSM was
operated correctly; retain the separate HSM and witness records.

## Native Ubuntu preparation

Use a controlled native Ubuntu host for the production ceremony. The following
non-destructive checks can also run in Ubuntu WSL during development:

```bash
cd /path/to/LumaOS
python3 --version
openssl version
PYTHONPATH=src python3 -m unittest \
  tests.test_model_catalog_signing tests.test_signing_trust \
  tests.test_catalog_admission tests.test_durable_administration \
  tests.test_installation_source -v
PYTHONPATH=src python3 -m unittest tests.test_model_pack tests.test_model_selection -v
python3 scripts/model_catalog_ceremony.py --help
sha256sum schemas/model-profile.schema.json schemas/model-catalog-signature.schema.json
```

For production, additionally record the native Ubuntu release, kernel, secure
time source, package inventory, host asset ID, console participants, HSM model,
HSM firmware, token/partition serial reference, PKCS#11 provider digest, and
proof that the ceremony networks were disabled or physically disconnected.
Do not copy private-key or recovery material into the workstation.

Untrusted ceremony inputs are rejected before full processing when a catalog
exceeds 4 MiB, an envelope or approval set exceeds 1 MiB, a request or
statement exceeds 64 KiB, a signature file exceeds 65 bytes, or a catalog has
more than 256 profiles. An assembled Ed25519 signature must be exactly 64
bytes. These are security limits, not sizing recommendations.

## Catalog ceremony

### 1. Freeze and verify inputs

- Start from a reviewed, immutable release commit and clean source tree.
- Independently hash the catalog, every model pack, runtime binary, license
  decision, trust bundle, and certification record.
- Verify the catalog is canonical, contains exactly one `manual-only` profile,
  and makes no model profile available unless its exact pack and runtime tuple
  has the claimed certification state.
- Verify that the production trust and lab trust roots have no shared private
  key and no cross-environment purpose.
- Read the current externally protected rollback floor. The new catalog
  sequence must be greater than or equal to that floor and must not reuse an
  existing sequence for a different digest.

### 2. Freeze the pre-approval release request

Create the release request before asking anyone to approve. It is the sole
scope digest for every approval and prevents a valid approval from being moved
to another environment, sequence, policy, validity interval, signer, key, or
assignment:

```bash
PYTHONPATH=src python3 scripts/model_catalog_ceremony.py request \
  --catalog catalog.json \
  --request-out catalog-request.json \
  --environment production \
  --release-id RELEASE-ID \
  --catalog-sequence 1 \
  --policy-version catalog-policy-v1 \
  --signer-key-id PROD-CATALOG-KEY-ID \
  --signing-principal-id CATALOG-CUSTODIAN-ID \
  --signing-assignment-id CATALOG-ASSIGNMENT-ID \
  --signing-assignment-receipt-sha256 REPLACE_WITH_64_LOWERCASE_HEX \
  --not-before 2026-09-23T11:00:00Z \
  --not-after 2026-12-22T11:00:00Z

sha256sum catalog.json catalog-request.json
```

The release owner and witness retain the printed `release_request_sha256`.
Changing any scoped field requires a new request and all-new approvals.

### 3. Create authenticated approvals

Admin assigns each approver only the required activity. Each approval binds the
same release-request digest, release ID, catalog SHA-256, current assignment ID,
assignment-receipt digest, and a distinct authenticated decision-receipt
digest. The decision receipt must prove the exact approval event and request
digest, not merely that an assignment once existed. The approval set has this
canonical outer form:

```json
{"approvals":[{"activity":"model-catalog.approve.license","approved_at":"2026-09-23T10:00:00Z","approval_decision_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","assignment_id":"LICENSE-ASSIGNMENT-ID","assignment_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","catalog_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","decision":"approved","principal_id":"LICENSE-PRINCIPAL-ID","release_id":"RELEASE-ID","release_request_sha256":"REPLACE_WITH_REQUEST_SHA256"},{"activity":"model-catalog.approve.release","approved_at":"2026-09-23T10:01:00Z","approval_decision_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","assignment_id":"RELEASE-ASSIGNMENT-ID","assignment_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","catalog_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","decision":"approved","principal_id":"RELEASE-PRINCIPAL-ID","release_id":"RELEASE-ID","release_request_sha256":"REPLACE_WITH_REQUEST_SHA256"},{"activity":"model-catalog.approve.security","approved_at":"2026-09-23T10:02:00Z","approval_decision_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","assignment_id":"SECURITY-ASSIGNMENT-ID","assignment_receipt_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","catalog_sha256":"REPLACE_WITH_64_LOWERCASE_HEX","decision":"approved","principal_id":"SECURITY-PRINCIPAL-ID","release_id":"RELEASE-ID","release_request_sha256":"REPLACE_WITH_REQUEST_SHA256"}],"schema_version":1}
```

Generate this record from the authenticated Admin/evidence system rather than
editing placeholders for a real release. Its adapter must authenticate the
exact decision receipt and request digest, and validate each assignment both at
the approval timestamp and at verification time. Expired, revoked, replayed,
or metadata-only assignment evidence fails closed.

The development durable store is not that authentication service. It requires
a separate `AdminEventWriterAuthorizer` for every exact append, then protects
the accepted canonical event bytes with a sequence/hash chain, HMAC, and
external checkpoint. The HMAC establishes local at-rest integrity under its
injected secret, not the identity of the writer. Production must retain the
external service's identity/policy decision and protect both the HMAC secret
and checkpoint. A database/anchor mismatch is a reconciliation-required stop;
it must never be auto-replayed or silently rolled back.

The current store is a singleton log with fixed domains. Do not run independent
writers or stores against one secret/namespace. Production needs one
authoritative service and an independently provisioned deployment/service
domain; multi-host/store replication remains unimplemented.

### 4. Prepare the exact bytes for the HSM

The utility refuses noncanonical input and existing output paths. It does not
accept a private key:

```bash
PYTHONPATH=src python3 scripts/model_catalog_ceremony.py prepare \
  --catalog catalog.json \
  --request catalog-request.json \
  --approvals approvals.json \
  --statement-out catalog-statement.json \
  --signed-at 2026-09-23T11:00:00Z

sha256sum catalog.json catalog-request.json approvals.json catalog-statement.json
```

Both the custodian and witness compare the displayed hashes to the approved
request before activating the HSM.

### 5. Sign in the protected device

Sign the exact bytes of `catalog-statement.json` with Ed25519 in raw-message
mode. Use the HSM vendor's reviewed PKCS#11/KMS procedure and capture its audit
event. A typical PKCS#11 command shape is shown only as an integration example;
mechanism names and options must be qualified for the selected HSM:

```bash
pkcs11-tool --module /approved/provider.so \
  --sign --mechanism EDDSA --id APPROVED_KEY_OBJECT_ID \
  --input-file catalog-statement.json --output-file catalog-statement.sig

test "$(wc -c < catalog-statement.sig)" -eq 64
```

Do not substitute a software private key for a production ceremony. An
independent station may perform a public cryptographic check when its OpenSSL
build supports Ed25519 raw-message verification:

```bash
openssl pkeyutl -verify -pubin -inkey catalog-public.pem -rawin \
  -in catalog-statement.json -sigfile catalog-statement.sig
```

### 6. Assemble the detached envelope

```bash
PYTHONPATH=src python3 scripts/model_catalog_ceremony.py assemble \
  --catalog catalog.json \
  --approvals approvals.json \
  --statement catalog-statement.json \
  --signature catalog-statement.sig \
  --envelope-out catalog.sig.json

sha256sum catalog.json catalog.sig.json
```

The production loader first admits the root-signed public trust bundle against
its fixed production checkpoint, then prepares and commits catalog admission
with:

- `expected_environment="production"`;
- the exact expected release ID;
- accepted catalog policy versions and a trusted live clock;
- exact `ModelPackVerification` records for every available profile;
- a public-only crypto provider populated from the anchored production trust
  bundle;
- the authenticated durable Admin authorization adapter; and
- the rollback-resistant production catalog anchor in its fixed environment
  namespace.

The trust composition root owns that live clock, root policy, public provider,
and anchors. The clock is never artifact/request data, and later callers may
not substitute a backdated instant or a different crypto provider. In-process
authority objects must remain inside an isolated trusted service; Python object
identity is not a boundary against a hostile peer in the same process.

The `ModelPackVerification` records are retained tuple snapshots. Rechecking an
admitted catalog proves it still matches those exact records; it does not
re-hash pack files, re-query certification/revocation state, verify a runtime
binary still present, or prove loadability. Generate the records from fresh
independent pack/runtime/certification evidence and prepare a new catalog
admission whenever any of that state changes.

Preparation is non-authoritative. Commit must compare-and-swap the exact
checkpoint read during preparation and then retain that exact value. The
admitted catalog is usable only while the catalog checkpoint, trust bundle,
signature, approvals, signer, pack bindings, policy, and lifecycle remain
current. A newer catalog/trust bundle or any clock, Admin, or anchor failure
invalidates retained authority.

No model process, installer UI, catalog file, or command-line caller may assert
its own trust record, assignment, hardware result, or rollback floor.

### 7. Independent verification and publication

On the second offline workstation, independently verify every hash, public
signature, assignment, certification tuple, validity interval, and catalog
profile. Retain the canonical verification receipt. Only after the independent
review passes may the release owner authorize publication and atomically raise
the protected `(catalog sequence, catalog digest)` rollback floor.

Copy only public artifacts to the offline installation bundle. Re-hash the
final bundle from read-only media. Test that a changed catalog byte, signature,
approval, environment, release, sequence, key role, runtime tuple, or pack
certification is rejected.

Create the canonical offline-source descriptor only after those artifacts are
frozen. The release system, not the descriptor or installer caller, must govern
the descriptor digest and exact edition. Independently hash and verify the
signature of every referenced artifact from the final media. Schema-v3
descriptor validation binds those expected values and repeats current catalog/
trust checks; it does not itself read, authenticate, or authorize the image,
payload, package, metadata, or SBOM bytes.

## Acceptance criteria

The signed production catalog/custody item is acceptable only when all of the
following are retained and independently reviewed:

- four distinct current human principals performed the three approvals and
  catalog signing, with a separate witness;
- the production catalog key is non-exportable, production-only, within its
  validity interval, not revoked, and authorized for
  `model-profile-catalog-production` only;
- the three approval activities and signing activity are current in the Admin
  system; every assignment and decision-receipt digest matches; and each exact
  approval event is valid both at its approval time and verification time;
- the production Admin writer service authenticated every exact stored event;
  the protected HMAC secret and external checkpoint agree with the database;
  and no reconciliation-required state is open;
- every approval and the signed statement bind the same reconstructed
  pre-approval release-request digest;
- the exact canonical catalog and statement digests match the release request;
- every available model profile has an exact signed model pack, loadable
  runtime tuple, approved license decision, and the certification state claimed
  by the catalog;
- offline verification succeeds on a second controlled native Ubuntu station;
- negative tests reject lab keys, wrong-purpose/role keys, expired and revoked
  keys, missing or duplicated approvers, signer/approver reuse, changed bytes,
  wrong release, validity failure, rollback, and pack/runtime drift;
- the final bundle works with networking disabled and contains no private key,
  PIN, recovery material, private roster, or unredacted sensitive HSM log;
- the governed offline-source pin and edition match the canonical descriptor,
  and independent checks prove every referenced artifact byte and signature on
  the distributed media rather than relying on the inert validation receipt;
- a revocation/rotation drill proves a compromised catalog key can be revoked,
  a replacement key/root record published, a higher sequence signed, and the
  old artifact rejected;
- a two-of-three recovery drill is witnessed and restores signing capability
  without exporting raw private material or accepting an old rollback floor.

Any missing item leaves the result at development or lab status. It must not be
listed as a production-selectable catalog or used to close G2.

## WSL versus native Ubuntu evidence

Ubuntu WSL can legitimately provide:

- unit and optimized-Python results for the catalog/signature contracts;
- canonicalization and schema checks;
- public OpenSSL signature verification;
- deterministic hash and envelope assembly evidence; and
- negative tests for tampering, roles, purposes, validity, revocation,
  approvals, pack tuples, and rollback floors.

Ubuntu WSL cannot close:

- protected HSM custody, USB/token reliability, or offline-root operation;
- authenticated production Admin writer identity/process isolation, protected
  HMAC secrets, trusted time, or rollback-resistant external checkpoints;
- native boot, Secure Boot, UKI, TPM, firmware, LUKS2, dm-verity, or A/B slots;
- destructive installation or recovery-media evidence;
- cgroup, device, AppArmor, seccomp, KVM, kernel peer-credential, or physical
  power-loss qualification; or
- two-board hardware independence.

Run the same repository tests in WSL now, then carry the immutable source
commit, test plan, and empty evidence templates to the separate native Ubuntu
environment. Evidence from that environment must record its own exact host,
OS, kernel, firmware, HSM, device, model-pack, runtime, and release identities.

## Remaining repository integration gaps

Before production activation, implement and independently review:

1. provisioned production roots and the platform-qualified public Ed25519/HSM
   verification adapter used by installer and recovery environments;
2. an authenticated, process-isolated Admin writer/identity service satisfying
   the exact writer-authorizer API, with protected HMAC-secret custody and a
   trusted time source; this must be one authoritative log with a unique
   deployment/service identity rather than independent stores sharing state;
3. durable rollback-resistant external compare-and-swap storage for trust,
   catalog, and Admin checkpoints, plus a reviewed database/anchor
   reconciliation procedure;
4. generation of actual signed model-pack, certification, trust-bundle, and
   production-catalog evidence for Qwen3-4B or another approved profile;
5. authenticated release governance for the offline descriptor pin and
   edition, plus independent signature/digest verification of every referenced
   artifact byte actually consumed; and
6. privileged installer/base-image/first-boot integration that preserves the
   schema-v3 revalidation boundary and is qualified on disposable native
   Ubuntu hardware.

These are explicit G2 deliverables, not documentation-only approvals.
See [ADR-0010](adr/0010-durable-admin-and-offline-source-revalidation.md) for
the durable Admin, external-anchor reconciliation, and schema-v3 source-
revalidation decision.
