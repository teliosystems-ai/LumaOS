# Existing owner TPM credential feasibility

The packaged systemd 255 credential helper still blocks G2 checkpoint enrollment
with a nonempty TPM owner authorization. A disposable software TPM experiment
established a possible replacement protocol. This result supports a backend
design; it is not a product credential implementation or an enrollment pass.

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
signature was involved. The current product code still calls `systemd-creds` and
will refuse the selected owner profile. The positive checkpoint enrollment test
remains pending.

## Evidence and implementation path

The run is retained at `D:\LumaOS-builds\g2-owner-backend-20261002-01`.
Its 146-file source manifest SHA-256 is
`ce315e2a6326f75295f851495e62396164df241af4966c7598c902601f4968b1`;
the separately copied fixture SHA-256 is
`80da47edb698d99134c885dc7a68f2c014ede51455e93c958cbb7b6687d887cd`;
the completed test log SHA-256 is
`369b40362905252ecd9f85fc525634cceaf0eff4da8c2e4eafa101cccdccbd70`.
The manifest matches the prior product-source snapshot because this checkpoint
changes only the separately copied test fixture and documentation. No native
binary or installer image was rebuilt for this experiment.

The next implementation must use a fixed local TPM transport and a reviewed
native boundary for parent creation and sealed child operations. It must check
handle vacancy and the parent's Name, transmit the existing owner authorization
from locked memory in an encrypted TPM session, never persist that authorization,
and durably fence the parent allocation before dispatch. The sealed blob and
configuration need versioned, bounded parsing and binding to the signer and
deployment. Runtime unlock must authenticate signed PCR 11 and fixed PCR 7
without a second password, keep plaintext in protected memory, and refuse
unknown or changed inputs. Tests must include lost replies, collision, malformed
blobs, owner authorization denial, restart, signed update, recovery, and the
positive integrated enrollment path before installed-image qualification.
