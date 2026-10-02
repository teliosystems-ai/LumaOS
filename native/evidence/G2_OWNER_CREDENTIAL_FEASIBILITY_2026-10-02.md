# Existing owner TPM credential feasibility

The packaged systemd 255 credential helper still blocks G2 checkpoint enrollment
with a nonempty TPM owner authorization. A disposable software TPM experiment
established a possible replacement protocol. A subsequent native TPM boundary
now allocates and verifies its persistent parent under existing ownership. The
sealing and unsealing backend and its durable transaction remain unimplemented;
this is not an enrollment pass.

## Protocol exercised

The fixture sets a random nonempty owner authorization, creates an RSA storage
parent with that authorization, and persists it at fixed handle `0x81004c41`.
It records the parent's TPM Name. A sealed child holds a random 32-byte secret.
Its TPM policy first authorizes a PCR 11 policy digest through the fixed RSA
signer, then binds PCR 7 to the value at sealing. At unlock, the fixture verifies
the PCR 11 signature in the TPM, satisfies the current PCR 11 policy, applies
`PolicyAuthorize`, checks PCR 7, and unseals through the persistent parent.
Routine unlock supplies no owner authorization.

The sequence follows the [TPM tools PolicyAuthorize example](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policyauthorize.1.md)
and the [persistent object operation](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_evictcontrol.1.md).
The fixture is [admin_owner_backend_feasibility.py](../tests/admin_owner_backend_feasibility.py).

## Result and limits

One bounded, isolated run passed these assertions:

- A credential sealed under the persistent parent unsealed while owner
  authorization was nonempty, without supplying that authorization at unlock.
- A changed PCR 11 refused the old signature. A fresh signature over the new
  PCR 11 policy restored unlock. A changed PCR 7 refused it again.
- A one-bit change to the signature failed TPM verification after a valid
  signature had verified with the same loaded signer.
- After controlled software TPM shutdown and restart, the parent's Name was
  unchanged, owner authorization was still required to create an owner primary,
  and the original sealed child unsealed under the restored measurements.

This test invokes `tpm2-tools` and uses private fixture files for the random
owner authorization and test secret. It clears all transient handles only inside
its disposable TPM. None of those handling choices are approved for the product.
No host TPM, installed OS, physical restart, updated boot image, or production
signature was involved. The current product sealing path still calls
`systemd-creds` and will refuse the selected owner profile. The positive
checkpoint enrollment test remains pending.

## Native persistent parent boundary

`tpm_esys.c` now has a one-shot operation for fixed handle `0x81004c41`.
It refuses a pre-existing handle, authenticates the existing owner through a
salted encrypted HMAC session, creates the RSA storage parent, persists it, reads
back its TPM public profile and Name, and releases only the operation's
temporary handles. It does not change hierarchy authorization, clear the TPM,
evict an existing object, or retry an uncertain write. The Rust entrypoint has
no public command and is not called by enrollment: a durable parent-allocation
record must be implemented before that irreversible operation may be dispatched.

The extended existing-owner integration fixture passed wrong-owner refusal with
the handle vacant, correct-owner allocation, Name readback, collision refusal,
the previously implemented NV provisioning, a check that the custodian's owner
authorization remains valid, and no leaked transient objects. Three ordinary
TPM Rust tests and the warnings-as-errors native build also passed. This is
low-level allocation evidence, not a sealed credential or Admin service test.

Final native evidence is at `D:\LumaOS-builds\g2-parent-targeted-20261002-02`.
Its 146-file source manifest SHA-256 is
`df4b826d19576936cac3a3a8599a99be4c3c081748de7999359c5708e958ed95`;
the separately copied integration fixture SHA-256 is
`a7b4035ee08d8545e25bc2fd69ea37d94928f55369e8efd63c2f23eda081bcbe`;
the completed test log SHA-256 is
`3323fbc0105cc4c5edd0e06639917f1021dc3dd093af848325b3898fe4b1f382`.
An earlier snapshot `-01` also passed before the public-profile readback was
tightened; it is retained, but `-02` is the final result for this increment.

## Protocol experiment evidence and implementation path

The run is retained at `D:\LumaOS-builds\g2-owner-backend-20261002-01`.
Its 146-file source manifest SHA-256 is
`ce315e2a6326f75295f851495e62396164df241af4966c7598c902601f4968b1`;
the separately copied fixture SHA-256 is
`80da47edb698d99134c885dc7a68f2c014ede51455e93c958cbb7b6687d887cd`;
the completed test log SHA-256 is
`369b40362905252ecd9f85fc525634cceaf0eff4da8c2e4eafa101cccdccbd70`.
This first manifest matches the prior product-source snapshot because that
checkpoint changed only the separately copied test fixture and documentation.
The subsequent native boundary was rebuilt and tested as recorded above. No
installer image was rebuilt for either increment.

The next implementation must durably fence parent allocation before calling the
native boundary, then create and unseal a child under its pinned Name. The sealed
blob and configuration need versioned, bounded parsing and binding to the signer
and deployment. Runtime unlock must authenticate signed PCR 11 and fixed PCR 7
without a second password, keep plaintext in protected memory, and refuse
unknown or changed inputs. Tests must include lost replies, malformed blobs,
restart, signed update, recovery, and the positive integrated enrollment path
before installed-image qualification.
