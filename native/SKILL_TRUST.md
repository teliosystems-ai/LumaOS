# Native closed-profile skill trust

This implements the native `file-to-artifact-v1` profile, not arbitrary plugins,
generated code, model catalog custody or populated-schema migration. Public
signatures are inputs to reviewed original-Admin transitions; they are not
principal/resource/effect grants. Native qualification and external production
signing custody remain separate.

## Immutable packaging

The builder optionally accepts `LUMA_NATIVE_PUBLIC_TRUST=/exact/public-directory`.
It mounts that directory read-only for assembly only. The helper refuses private
keys, extra/partial files, links, replacement, malformed/duplicate fields,
unbounded inputs and actual wrong signatures. Provisioning happens before the
verity root is sealed; it does not modify a running machine or publish a journal.

The directory may contain `production-release-root.pub` alone for recovery
media. A governed skill group additionally contains the environment-specific
root and root policy, `skill-trust.json`, `skill-admission.json`, `registry.json`
and `file-to-artifact-v1.json`. Laboratory roots use `skill-trust-root.pub` and
`skill-trust-root-policy.json`; production uses `production-skill-root.pub` and
`production-skill-root-policy.json`. The registry environment must match the
immutable OS image. The current laboratory builder does not manufacture a
production-signed OS image.

The root policy binds environment, `skill-registry` domain/purpose, SHA-256 of
Ed25519 SPKI DER, effective validity and independently declared separated key
fingerprints. Runtime checks additionally reject reuse of known OS/model/opposite
environment roots and OS signing leaves. A bundle cannot select or replace its
root. The leaf role is exactly `skill-registry-signer`; private keys never enter
the helper, runtime image or Admin journal.

Signatures cover compact UTF-8 JSON in declared schema field order, including
nested key declarations; this is distinct from recursively sorted OS-release
trust encoding. The helper's closed schemas and cryptographic validation are
the interoperability contract. Trust and leaf validity are finite, at most 366
days, and contained in the immutable root validity. Admission binds the exact
trust version/digest and exact immutable registry/workflow bytes.

## Reviewed activation and lifecycle

The helper stages inert public proposals at
`/usr/share/luma-os/skills/initial-trust.json` and `initial-admission.json`.
After original-Admin/bootstrap/UTC setup and production OS activation where
applicable, register `admin.skills.trust_publish` and
`admin.skills.registry_admit` through the existing finite activity ceremony.
Then review and explicitly commit these separate commands:

```text
luma-admin-control admin-skill-trust-publish LOGIN REQUEST EXPECTED-VERSION SIGNED-TRUST-FILE
luma-admin-control admin-skill-registry-admit LOGIN REQUEST EXPECTED-FLOOR SIGNED-ADMISSION-FILE
```

Append `--commit REVIEW-SHA256` only after reviewing the returned exact digest.
Initial expected version/floor are zero. Trust versions increase exactly with
an exact predecessor digest; revoked identities cannot disappear or revive.
Registry floors cannot decrease. Same-sequence replay must be byte-identical
evidence; changing the registry, workflow or trust binding requires newer
explicitly signed admission. Trust changes fence previous current admission
until that admission is renewed explicitly.

Every governed workflow admission reconstructs current TPM-selected trust and
finite UTC, verifies root/leaf signatures, rechecks pinned immutable content and
compares fresh authority before delivery. Historical replay retains facts,
not expired current authority. Schema 1 remains legacy laboratory-only and is
refused once skill trust is anchored, including if the journal is damaged or
unavailable. Schema 2 is required for governed laboratory and production work.
There is no production fallback to a laboratory key or stale receipt.

External production roots/signatures, role custody ceremonies, final-image
installation/confinement and interrupted-write/TPM/UTC qualification are still
required before production deployment. Source tests cannot replace them.
