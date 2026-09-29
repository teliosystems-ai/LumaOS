# Native UKI policy and initrd checkpoint — 2026-09-29

**Selected artifact, initrd and software-TPM tests passed. G2 remains open.**
This integrates an enrollment prerequisite into the image builder, not a
completed installer/Admin service or a newly qualified OS image.

## Implementation

Installed A/B UKIs now contain a separate laboratory PCR signer's public key
and SHA-256 PCR11 approvals for post-initrd sysinit and ready phases. Live
installer/recovery UKIs carry neither installed PCR approvals nor the embedded
PCR public-key section. The public key also enters the verity-protected root;
its private key remains in the private laboratory key volume, distinct from
release and firmware signing keys. Existing unsafe/link-based PCR custody paths
are refused, and an existing key is not silently replaced.

The builder ignores default ukify host configuration. It verifies Secure Boot
signatures, exact slot/mode, signer identity, signature inventory and actual
embedded measurements before assembly continues. `boot-policy.json` is an
exported/checksummed evidence report, not runtime approval authority.

The maintained Ubuntu dracut PCR module expects the old `systemd-pcrphase`
executable, whereas packaged systemd 255's unit invokes `systemd-pcrextend`.
The new `luma-pcrphase` compatibility module includes that helper and vendor
initrd unit, using the packaged `tpm2-tss` dependency for TPM libraries/drivers.
The builder checks initrd contents before signing and explicitly activates the
packaged sysinit/ready userspace phase units. These are not product Admin units.

## Executed scope

The fixture uses synthetic **nonbootable** PE payloads, a generated **kernel-less**
initrd, disposable signing keys and an isolated software TPM. No firmware,
physical TPM, disk installation or guest OS boot was performed.

- Built and checked A/B and live signed PE artifacts; A/B approvals differ,
  while live has no installed PCR policy. Wrong slot or signer is refused.
- Altered initrd bytes invalidate the PE signature. Signing that altered PE
  again with the accepted laboratory Secure Boot key still fails the separate
  PCR-policy verification, because its signed measurements no longer match.
- Replayed measured section-name/content and phase events into the TPM using
  actual PCR extends. Observed values match independent UKI predictions; a
  predicted final PCR value is never directly assigned to the emulator.
- Sealed/unsealed a credential under A at sysinit; allowed it at ready and
  refused it after shutdown. Restarted the same TPM and replayed B: initrd
  refused access, sysinit allowed the original A credential without resealing,
  and an additional unapproved measurement refused access.
- Generated an initrd with the real phase helper, vendor unit, activation link
  and TPM library; checked enter-initrd/leave-initrd commands and rejected an
  invalid initrd. This does not evaluate TPM kernel driver loading or unit
  execution during boot.
- Reran the original NV/checkpoint, sealing, admission, source and VM-fixture
  tests without host TPM access or network access.

Final evidence is in
`D:\LumaOS-builds\native-tests-20260929-uki-policy-03`.
The [machine-readable record](native_uki_policy_2026-09-29.json) pins the tools
image, source inventory and hashes of all five retained evidence files.

Results: **39 ordinary Rust tests**, **20 explicit emulator invocations**
covering **39 boundary labels**, and **20 Linux Python tests passed**.
Windows ran 20 Python tests: **12 passed, 8 Linux-only tests skipped**.
Offline locked build with warnings denied and Rust format checks passed.
Labels are not distinct test functions. Earlier policy-01/02 runs passed their
then-current scope but do not cover the final initrd compatibility addition.

## Remaining work

Authenticate bootstrap enrollment and the product Admin principal; implement
NV provisioning/collision refusal, hierarchy custody, durable interruption
fencing and recovery; deliver the sealed credential through a confined service;
then implement finite assignment/revocation and authorized durable effects.
Signing keys/measurements alone confer none of those roles or permissions.

Rebuild and boot actual native UKIs to evaluate firmware/stub/phase measurement,
TPM drivers, unit ordering, credential availability, A/B fallback and recovery.
The old sequence-4 image remains unchanged and cannot inherit this source/test
evidence. Full assembly/export and a complete guest-boot flow were not run here.
Physical and production-custody qualification remain separate requirements.

A full image rebuild was not attempted with C: at 98% usage (10,125,770,752
bytes available), although D: has 714,200,580,096 bytes available. External
artifact output meets its filesystem minimum, but Docker still needs separately
budgeted Linux backing-store workspace. Free/migrate that workspace with
operator-approved disposition of existing volumes before the next large build;
no existing user artifacts, evidence or key volumes were removed.

References: [implementation and limitations](../LOCAL_TPM2_ADMIN.md),
[systemd 255 ukify](https://github.com/systemd/systemd/blob/v255/man/ukify.xml),
and [TPM PolicyPCR calculation](https://github.com/systemd/systemd/blob/v255/src/shared/tpm2-util.c).
