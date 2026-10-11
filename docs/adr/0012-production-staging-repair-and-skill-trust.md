# ADR 0012 Production staging repair and skill trust

- Status: Accepted for development implementation; production custody and native qualification remain separate
- Date: 2026-10-11
- Extends: ADR-0007, ADR-0009, ADR-0010 and ADR-0011
- Supersedes: The native installation/recovery admission restrictions and native skill-purpose mapping only within the scope below

## Production staging and activation

The owner approved offline immutable signed staging followed by first-boot
activation. Before any installation write, the installer verifies the exact
release artifacts and independently provisioned public root signatures. Offline
verification is not current finite-time authorization. It can stage the exact
approved image and installation-bound bootstrap inputs, but cannot activate
timed grants, workers, workflows or protected effects.

First-boot activation requires the original Admin bootstrap, the existing TPM
owner and hardware-selected journal, current authenticated protected UTC and
the release trust/admission transition. Approximate seeds, wall clocks and
serialized receipts cannot activate authority. Missing or damaged state cannot
silently return an enrolled installation to initial staging. Stable acknowledged
manual operation and exact prior fallback retain their existing offline behavior.

## Separate repair custody session

The owner approved a separately typed repair-only session of at most thirty
minutes. It is nonserializable, nonrenewable and bound to the original process,
root identity, boot and suspend-aware kernel deadline. It is not a PAM account,
role assignment, export session or grant. Existing ordinary/PAM/seed-control
thirty-second limits and export-only limits are unchanged.

The session authorizes no effect by itself. A repair actor must authenticate
the original Admin's current offline custody verifier, retain an exact reviewed
disk/image and private live-image/target-mount context, and reconstruct the same
target's sealed TPM credentials, principal and journal/history state. Target,
TPM epoch/head, current custody, release identity/trust/floor and authenticated
UTC must remain current before and after bounded writes, readback and publication.
Final delivery checks use the provider's exact final kernel coordinate without
blocking work afterward. Timeout, revocation, uncertainty or panic fences the
operation; subsequent use cannot extend or revive its deadline.

There is no new NV allocation, ownership reset, new PCR policy, root/owner bypass,
arbitrary directory/chroot authority, automatic retry or keeper access to target
secrets. Media must satisfy the target's existing approved PCR/signing policy.
Manual unlock/export/model-disable remains independent of online UTC and models.

Installed machine services may query the protected UTC keeper as an exact
kernel-authenticated unconfined root peer. The closed query supplies only a
nonce, never history, a seed, a time value or a control action. Its estimate is
not authorization: the machine client independently reconstructs sealed TPM
history and finite release authority. Control remains restricted to the exact
enforcing Admin profile; recovery queries/control retain their separate exact
recovery profile. Host root remains outside the application threat boundary.

## Native skill registry trust domain

The native closed FileRead/DeterministicCalculate/ArtifactWrite profile gains a
purpose-separated public trust adapter. This extends the native purpose mapping,
not model-catalog approval quorums, OS release purposes or the root Admin role.
The exact signing purpose/domain is `skill-registry`; the leaf role is
`skill-registry-signer`. Original Admin publishes/adopts through finite reviewed
commands in the existing shared TPM journal. A signer designation is not an
effect grant and does not expose a private key.

Root public keys and root-validity policy are independently provisioned inside
the immutable image. Production uses `/usr/share/luma-os/production-skill-root.pub`;
governed laboratory trust uses `/usr/share/luma-os/skill-trust-root.pub`. A bundle
cannot introduce or replace its root. The fixed root policy binds environment,
DER fingerprint, domain/purpose and effective validity. Roots and leaf keys cannot
reuse OS/model/environment-separated signing identities.

Root-signed trust bundles use bounded compact JSON in the declared Rust schema
field order (not the OS-release recursively sorted encoding), increasing version and
exact predecessor digest, a fixed policy/domain/environment, unique leaf
identities and finite validity. Leaf validity fits bundle validity, which fits
the immutable root policy. Revoked identities remain retained and cannot revive.
Registry admissions bind exact signed metadata, registry/graph digests,
environment, purpose, finite validity and increasing sequence/floor. Same-sequence
replay requires identical evidence; changed evidence needs a newer sequence.

Current workflow admission reconstructs committed trust/admission and checks
root/leaf signatures, current protected UTC, current TPM-selected journal,
monotonic floor and exact immutable registry/graph bytes. A trust change fences
old current admission until explicit fresh admission. Historical semantic replay
retains facts without confusing expired past evidence with current authority.
Production has no laboratory fallback. Legacy ungoverned laboratory registries
remain schema-1 laboratory-only and are refused once skill trust has ever been
anchored. Governed laboratory and production registries use schema 2. A damaged
or unavailable journal cannot prove absence of prior trust and enable fallback.
No arbitrary plugins or generated code are introduced.

## Security review and completion

The development review requires private typed recovery contexts, purpose/root
separation, original-custody checks, monotonic journal replay, whole-interval UTC
validity, exact payload identity and uncertainty preservation. Tests must cover
wrong roots/purposes/environments, replacement, duplicate/unknown fields, expiry,
revocation, stale/changed targets, missing anchors and interrupted publication.
These requirements are implementation constraints, not passing test evidence.

The approval covers software and disposable testing. It does not authorize host
TPM/clock/account changes, physical disk writes, firmware changes or production
private-key ceremonies. Native image installation, confinement, NTS/time-error,
power-loss, firmware/TPM and production custody evidence remains mandatory.
