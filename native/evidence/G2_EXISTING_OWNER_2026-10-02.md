# G2 existing owner provisioning

On 2026-10-02 the owner selected existing TPM ownership for local Admin
enrollment. Luma must use custodian-supplied owner authorization, without taking
ownership, changing hierarchy credentials, clearing the TPM or deleting another
allocation. This checkpoint records the low-level implementation and tests;
authenticated enrollment and G2 closure remain incomplete.

## Implemented scope

The native TPM adapter now contains a fixed-allocation provisioning boundary
for index `0x01804c41`, SHA-256, 32-byte NV_EXTEND with the existing approved
attribute profile. It refuses occupancy and empty/oversized owner authorization.
The Rust wrapper accepts owner bytes in the locked credential buffer and an
independently generated NV secret. No credentials appear in command arguments
or diagnostic output, and this boundary has no public CLI.

The adapter creates only a transient NULL-hierarchy RSA salt key, then uses an
AES-CFB salted HMAC session for existing-owner authorization and encrypted NV
authorization delivery. It defines the index and extends the supplied genesis
digest. It closes the NV reference, flushes its own transient/session handles,
clears its cached owner authorization and wipes temporary C auth buffers. It
does not call hierarchy-change, clear, evict-control or NV-undefine operations.

This is a one-shot write boundary, not an atomic enrollment transaction. A
future authenticated caller must durably persist the sealed proposal and
interruption fence before entry. Failure can occur after allocation or extend;
it must never trigger automatic retry, deletion or reconstruction of empty
state. The current installer does not call this boundary and still refuses to
claim operational product Admin enrollment.

The implementation uses the ESAPI interfaces for
[session creation](https://tpm2-tss.readthedocs.io/en/stable/group___esys___start_auth_session.html),
[transient primary creation](https://tpm2-tss.readthedocs.io/en/latest/group___esys___create_primary.html)
and [NV definition](https://tpm2-tss.readthedocs.io/en/latest/group___esys___n_v___define_space.html).
Executed compatibility is with the repository's packaged TPM2-TSS toolchain,
not an assumption that newer documentation proves target behavior.

## Executed checks

Final evidence is retained at
`D:\LumaOS-builds\g2-existing-owner-targeted-20261002-02`.

- Frozen source manifest SHA-256:
  `375ac9746850182b49d8473c70dddccd20e121b132961298c1c1b7d1d80a9186`.
- Completed `test.log` SHA-256:
  `4564c52e2367f5d8350ce7e93f65063a7d21adfb2d46bad74c7910268b428730`.
- Separately copied `existing_owner_integration.py` SHA-256:
  `d560fa397b560e2e2e09b4176cd15a9e39195200b723ba5cfa5209be55e62183`.

The dedicated D-backed Docker daemon ran the pinned tools image with no
network, physical TPM or host daemon socket, 768 MiB/no extra swap, one CPU,
128 PIDs and one Cargo job. The compiler cache and output remained on D:.
No WSL limit, host account, physical device or hierarchy credential was changed.

Three ordinary TPM tests, formatting, warning-clean C/Rust compilation and the
offline locked native build passed. The new ignored Rust integration function
was explicitly executed inside the disposable software-TPM fixture, proving:

- Oversized or empty owner inputs are rejected.
- Wrong owner authorization leaves the fixed index vacant.
- Correct existing owner authorization creates the exact NV profile; the
  independent NV secret authenticates read-back of the expected genesis head.
- A subsequent collision refuses without changing the head.
- The original custodian authorization remains valid after native provisioning.
- No native transient objects remain, and the fixture releases its own final
  verification object using its exact handle rather than a global flush.

The harness establishes ownership only on its newly created emulator before
calling native code. That setup command is not part of the product interface.
Private emulator and owner material remain inside the disposable container,
not exported with evidence. Other ignored tests were not claimed as run.

Attempt `-01` passed the native tests and custodian-auth check but failed its
test-only object-context cleanup. The corrected fixture inventories and flushes
only the exact newly created verification handle. Both evidence directories are
retained; the final run completed successfully.

## Remaining integration

Implement masked local custodian input within authenticated Admin bootstrap,
persist the sealed proposal before NV writes, bind the enrolled product
principal, verify/publish the checkpoint configuration and journal, and handle
interrupted or lost-reply provisioning through explicit recovery. Owner
authorization alone is not product Admin, a signing approval or an effect grant.

Missing custodian credentials must block enrollment rather than prompt Luma to
clear or take ownership of a TPM. Secure service confinement, secret working
copies inside dependent libraries, existing hierarchy recovery procedures and
physical bus/firmware/power-loss qualification remain open. No installed-image
or final-G2 acceptance result is established by this fixture.
