# Windows GWIN0 prerequisite observations

This new product-development lane is separate from the historical
`packaging/wsl` source-MVP launchers. It does not install a WSL distribution,
change the default distribution, edit global WSL settings, enable Hyper-V,
open a listener or enroll host folders.

Run in native Windows PowerShell under an execution policy that permits local
repository scripts:

```powershell
.\packaging\windows\test-preflight.ps1
.\packaging\windows\preflight.ps1 -StorageDrive D -DistributionName LumaOS-Dev -GuestMemoryGiB 12
```

The owner approved process-only RemoteSigned execution for development tests;
that approval does not override managed policy or authorize permanent changes.
The scripts do not alter execution policy themselves.

The probe writes JSON to stdout only. Exit zero means the observation completed,
not that installation is admitted: inspect `development_observations_passed`,
`blockers` and `pending_qualification`. Unknown capabilities remain unqualified.
Read-only inventory cannot prove host encryption, enterprise authorization,
worker confinement, nested virtualization, supported-release qualification or
compute acceleration. Host administrators, Windows and WSL/the hypervisor
remain trusted host components.

The proposed guest-memory check uses observed Windows available RAM plus an
8-GiB host planning reserve; swap is not counted. It neither reserves memory
nor changes WSL limits. A smaller constrained profile needs its own measured
budget and qualification; do not lower the reserve simply to obtain a pass.
Storage free space is observed, but full active/candidate/model/state/backup
and recovery budgets are compared only when an explicit plan is supplied.

## Checked planning inputs

Optional JSON inputs enable two additional read-only checks:

```powershell
.\packaging\windows\preflight.ps1 -StorageDrive D -DistributionName LumaOS-Dev `
    -GuestMemoryGiB 12 -StoragePlanPath D:\LumaOS-builds\windows-storage-plan.json `
    -ReleasePolicyPath D:\LumaOS-builds\windows-release-comparison.json
```

`planning_observations_passed` requires the original development observations,
enough observed free space for every storage component, and an exact release
tuple match. Missing inputs produce planning blockers, while malformed inputs
raise an error. The original observation-only invocation remains available.
Neither result authorizes installation or certifies the host.

The storage schema has exactly these fields; byte counts below are a small
synthetic example, not product sizing recommendations:

```json
{
  "schema_version": 1,
  "storage_drive": "D",
  "active_image_bytes": 1073741824,
  "candidate_image_bytes": 2147483648,
  "model_pack_bytes": 3221225472,
  "state_migration_bytes": 1073741824,
  "user_quota_bytes": 4294967296,
  "backup_staging_bytes": 2147483648,
  "recovery_reserve_bytes": 1073741824
}
```

All seven components are mandatory nonnegative integers, with positive
candidate-image, user-quota and recovery-reserve budgets. Explicit zero means
the corresponding optional allocation is not planned. The checked UInt64 sum
is compared with the selected drive's actual observed free bytes, with no
fixed 80-GiB pass threshold. The plan must name that exact uppercase drive
letter. The calculation conservatively gives no credit for pre-existing
allocations; it cannot replace later verified allocation accounting. Inputs
cannot reserve capacity, prove package size or turn an undersized caller budget
into a product admission. Installation still needs budgets derived from its
authenticated package manifests and an immediate capacity recheck/allocation.

The release comparison schema requires a review reference and a bounded list
of complete, exact edition/build/runtime tuples. For example, the following is
test data, not an approved production policy:

```json
{
  "schema_version": 1,
  "review_reference": "test-fixture-only-not-production",
  "tuples": [
    {
      "windows_edition": "Professional",
      "windows_build": 26100,
      "wsl_runtime_version": "2.6.0.0"
    }
  ]
}
```

Edition identifiers come from the observed Windows `EditionID`, not a fuzzy
caption match. Build and WSL runtime must match exactly; wildcards, ranges,
duplicate tuples and non-runtime version lines are refused. A review reference
is a claim supplied by the caller, not authenticated custody. A matching tuple
sets `tuple_matches_input` only: `policy_authenticated`, `production_qualified`
and `product_installation_admitted` remain false. Genuine signed policy and
per-tuple platform qualification remain separate requirements.

Both schemas are closed: omitted/unknown fields, booleans or strings used as
byte counts, negative/floating-point values and overflowing storage totals are
refused. JSON files are bounded to 64 KiB and 16 object or array nesting levels;
duplicate or escaped property names are refused before accepting a record.
Storage capacity and release tuple comparison are not encryption, enterprise
authorization, effective guest-limit, other-workload or confinement proofs.

## Offline package content validation

`validate-package.ps1 -PackageDirectory D:\path\to\candidate` inspects a
directory containing exactly `manifest.json` and `rootfs.tar`. It does not
extract files, import a distribution, execute package binaries or authenticate
a signer. It accepts only the normalized symlink-free POSIX USTAR development
format, not arbitrary Ubuntu archives or the native G2 disk image.

The closed manifest binds archive bytes/hash, member count, content size and
4 to 64 required-file descriptors. Mandatory members include Ubuntu 24.04
identity, exact WSL configuration, the matching amd64/profile-W release marker
and an executable ELF header. Every member is checked for safe canonical paths,
explicit parents, ownership, modes, archive checksums and padding. Links,
extensions, special files, aliases and trailing archives are refused. The
configuration disables automatic drive mounts, executable interoperation and
Windows PATH inheritance. These are declared bytes, not effective confinement
or bootability evidence.

Run the disposable fixture suite on D with the approved process-only policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\test-package.ps1 -WorkRoot D:\LumaOS-builds
```

Fixture archives include a header-only ELF; they are not runnable product
images. Passing reports keep authentication, runtime qualification and
installation admission false. See the
[package checkpoint](../../docs/gates/gwin0/package_content_2026-10-15.json).

GWIN0 still needs signed independent packaging, authenticated launcher/bridge,
scoped Windows ACL-aware ingestion, actual compact inference and confinement,
resource/lifecycle coexistence and a complete qualified VM desktop proof.
The current Home host can support WSL development; the plan requires a separate
qualified Pro/Enterprise Hyper-V host for the full VM proof. Do not change the
host edition or enable virtualization features automatically.

## Detached package signature verification

`verify-package-signature.ps1` verifies a lab Ed25519 signature over the exact
validated manifest bytes. The signature is a separate 64-byte binary file
outside the two-file candidate directory. The signed input is ASCII
`luma-wsl-package-v1\nlab\namd64\nW\n` (`\n` denotes one LF byte), followed by
the original manifest bytes with no JSON reserialization. The manifest binds the rootfs
archive. Native OS-release signatures and signatures for a different purpose,
environment, architecture or profile cannot substitute for this input.

The separately supplied public anchor is closed JSON with `schema_version: 1`,
`environment: "lab"`, `purpose: "luma-wsl-package-v1"`,
`public_key_spki_hex`, `not_before_ms` and `expires_ms`. The public key must be
exactly the 44-byte Ed25519 SPKI encoding, in lowercase hexadecimal, beginning
`302a300506032b6570032100`. Validity bounds must be positive and at most 366
days apart; verification does not establish whether the anchor is current.
The present development package format refuses production anchors.

Supply independently obtained SHA256 pins for the anchor file and a known
local OpenSSL 3 executable. Do not obtain either pin from the candidate package.
For example, after setting the two pin variables from reviewed inputs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\verify-package-signature.ps1 -PackageDirectory D:\candidate -SignaturePath D:\reviewed\candidate.sig -AnchorPath D:\reviewed\lab-anchor.json -AnchorSha256 $anchorPin -OpenSslPath 'C:\Program Files\Git\usr\bin\openssl.exe' -OpenSslSha256 $verifierPin -WorkRoot C:\Users\hakim\LumaOS\.luma -CompilerWorkRoot D:\LumaOS-builds
```

`WorkRoot` must support persistent Windows ACLs. The verifier atomically creates
a private GUID child for its bounded public signature inputs, checks its owner
and protected DACL through a pinned handle, and removes only its known files
before deleting that same directory through the handle. Input ancestors remain
pinned against rename/delete; reparse points are refused. Existing parent ACLs
are not changed. **This host's D drive is exFAT**, so it remains suitable for
bulk archives and compiler fixtures but is refused for private verifier scratch.
The repository `.luma` directory on NTFS is used only for tiny temporary
security metadata, not builds, images or caches. `CompilerWorkRoot` keeps
PowerShell compiler scratch separate; it defaults to `WorkRoot` if omitted.

The result establishes `cryptographic_signature_valid` and matching input pins,
not managed custody, authenticated revocation, protected UTC freshness or
trusted deployment of the anchor. Pinning `openssl.exe` does not authenticate
its DLLs or other runtime dependencies. Consequently `package_authenticated`,
`product_installation_admitted`, `production_qualified` and `gate_closing`
remain false. The verifier imports no distribution, executes no package code
and makes no saved host-policy changes.

Run the complete signature and storage-safety suite with D-backed bulk fixtures
and the repository's explicit NTFS security-metadata directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\test-package.ps1 -WorkRoot D:\LumaOS-builds -SecurityWorkRoot C:\Users\hakim\LumaOS\.luma
```

Without `SecurityWorkRoot`, the suite reports content and storage-capability
checks only; it does not claim that the complete signature suite ran. Tests use
disposable lab keys, genuine valid/invalid signature CLI calls, real subprocess
timeouts and output bounds, NTFS rename/delete refusal and fixture junctions.

See [the shared implementation plan](../../docs/G3_GWIN0_IMPLEMENTATION.md).
