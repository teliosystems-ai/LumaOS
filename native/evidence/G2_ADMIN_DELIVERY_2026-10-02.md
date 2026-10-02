# G2 direct sealed checkpoint credential delivery — 2026-10-02

Status: **targeted source checks passed; G2 is not code-complete**.
No new OS image, physical TPM enrollment or full acceptance pass is claimed.

## Implemented and integrated

`admin_credentials.rs` now supplies `LocalAnchor::installed` directly from the
existing TPM-only sealing primitive. The old plaintext credential-file read,
pageable Rust authorization vector and manual wipe in `tpm.rs` were removed.
The unsealed authorization stays in the existing locked/nondumpable `Secret`
mapping until passed to the TPM connection, and is wiped on drop. TSS/helper
internal copies still require full confined-service memory/swap qualification.

Product input paths are fixed:

- `/var/lib/luma-os/admin/anchor.json`: closed schema-v2 configuration with
  local profile, exact NV allocation/Name, deployment and lowercase SHA-256
  digests for the image PCR key and encrypted blob.
- `/var/lib/luma-os/admin/nv-auth.cred`: bounded private encrypted credential.
- `/usr/share/luma-os/admin-pcr-public.pem`: independently image-owned PCR key.
- `/run/systemd/tpm2-pcr-signature.json`: installed boot's signed PCR policy.

Only installed Luma boots/root may use the product loader. Unknown/duplicate
configuration fields, schema-v1/plaintext configurations, incorrect Names or
allocations, unsafe files, incorrect digests and missing inputs refuse. The
helper authenticates the sealed profile, deployment name and PCR policy. The
loader checks the exact input snapshot again after the helper returns. There
is no environment-selected transport/key/path, plaintext fallback, automatic
enrollment, secret output or credential-writing CLI.

The native checkpoint takes its exclusive writer lock before unsealing. A new
image tmpfiles rule creates only `/run/luma-admin` with root:root 0700, not
persistent enrollment files. Existing checkpoint status/reconciliation paths
use this loader through `LocalAnchor::installed`; enrollment is still missing,
so a fresh current installation remains unable to activate product Admin.

## Executed evidence

Final output: `D:\LumaOS-builds\g2-admin-delivery-targeted-20261002-02`.

- Frozen source manifest SHA-256:
  `e7b603be7c61fc0b5fc4fcf96b28f5b59c5f7e6cbe66aca686244de0f7210629`.
- Completed `test.log` SHA-256:
  `c5073e88ec29dc62be0b75cd57d54170c72b23dee87aa34b797b74f1939739ae`.
- Separately copied `admin_credential_integration.py` SHA-256:
  `6a3acfbb02691cb653963fe83db486514dc4307ba1166b1085592238f312d88e`.
- Separately copied `test_admin_credential_policy.py` SHA-256:
  `e2b8af2973d15a949b7b5118ab27eac15a4011d0f6169ed16ab0339e40ebd948`.

Checks ran on the dedicated D-backed Docker daemon with the pinned tools image,
no network/devices/host account mounts/socket, 768 MiB/no extra swap, one CPU,
128 PIDs and one Cargo job. Builds reused the retained D-backed target cache.
WSL settings and unrelated workloads were unchanged. No VM/model sweep ran.

Passed:

- Five credential-loader unit tests, two sealing-boundary tests and three TPM
  tests. Missing encrypted inputs, even with a legacy plaintext file present,
  neither initialize state nor invoke the unsealer.
- Two fixed-path/tmpfiles wiring checks, formatting and offline locked native
  build with warnings treated as errors.
- Seven invocations of the new software-TPM integration function: initial
  seal/delivery, repeat delivery, unapproved PCR11 refusal, approval of changed
  PCR11 with the **same** blob, invalid signature refusal, restored signature
  acceptance, then fixed-PCR7 change refusal. Product entrypoints refuse the
  fixture container rather than borrowing its test transport.

The generated credential plaintext is never persisted by this fixture; only a
test digest is retained inside its disposable private directory for comparison.
Private signing/TPM state is not exported. Other specialized tests skipped by
the filtered unit selections were not claimed as executed. Attempt `-01` also
passed but predates the additional missing-input/plaintext-fallback test; both
source snapshots and transcripts remain retained.

## Not yet implemented or qualified

This is credential consumption, not an authenticated enrollment producer. The
installer still does not create schema-v2 enrollment, define an NV index, grant
Admin or silently migrate schema-v1. The software-TPM fixture exercises signed
sealing/delivery; it does not prove a booted installed service, a production
signer, NV provisioning, hierarchy custody or physical anti-clear behavior.

The owner has been asked to choose between existing TPM ownership with supplied
custodian credentials and a managed new ownership setup on a dedicated Luma
machine. Do not choose either by silently clearing or taking ownership of a
host TPM. Authenticated bootstrap, finite roles, effect-time grants/receipts,
native workflow/skill execution, full model resource management, generated-code
isolation, account/desktop lifecycle and update/recovery integration remain in
the completion register. This increment cannot mark those packages complete.
