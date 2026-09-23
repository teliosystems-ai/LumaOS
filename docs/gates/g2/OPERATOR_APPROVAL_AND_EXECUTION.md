# G2 operator approvals and execution inputs

This is the consolidated hand-off for the external work needed to close G2.
Repository tests, Windows, and Ubuntu under WSL can prepare and validate the
interfaces, but they cannot certify native boot, destructive storage changes,
firmware trust, physical recovery, or kernel enforcement.

Nothing in this document authorizes a disk write. A destructive run begins
only after the named operator and approver sign an authorization for one exact
host, one exact target disk, one release, and one time window.

## Decisions and material the project owner must provide

Before a physical run can be scheduled, provide or approve all of the
following:

1. **Two independent machines.** Name them `E1` and `E2`. Each must be a
   physical x86-64 Ubuntu candidate, not two guests on one host. Record vendor,
   model, firmware revision, TPM version, CPU, installed RAM, accelerator,
   accelerator firmware/driver, and network adapters.
2. **A disposable disk for each machine.** Supply its vendor, model, serial or
   WWN, capacity, connection type, and stable Linux identity. The disk must not
   contain the only copy of any data. State explicitly that the complete disk
   may be repartitioned, encrypted, overwritten, and rendered temporarily
   unbootable. Never approve `/dev/sdX`, `/dev/nvmeXnY`, a wildcard, or a
   capacity alone.
3. **Recovery access.** Provide physical console access, firmware setup and
   recovery access, the ability to restore Secure Boot trust, a tested recovery
   USB, a separate encrypted export/backup device, and a power interruption
   fixture. Preserve the vendor recovery procedure before changing firmware or
   storage.
4. **Network isolation.** Provide a switchable network path or physical cable
   control so the offline workflow can be demonstrated with networking
   physically unavailable. A software firewall alone is not the T02 oracle.
5. **The retained platform tuple.** Approve Ubuntu 24.04 LTS amd64, the exact
   GA/HWE/OEM kernel, firmware, shim/bootloader, NVIDIA or other accelerator
   driver, inference runtime, and package snapshot. Ubuntu 26.04 WSL remains a
   development lane; promotion of native Ubuntu 26.04 requires the separate E8
   migration matrix.
6. **The model candidates and licenses.** Approve the exact model revision,
   weights, tokenizer, templates, runtime tuple, context, quantization, source,
   and redistribution terms. Qwen3-4B is the current compact development
   recommendation. Gemma 4 E2B/E4B may be retained as alternatives only after
   their exact artifacts, total and active parameter counts, licenses, and
   hardware fit are reviewed. Keep at least two signed 4–6B candidates for the
   required comparison; larger 32B–405B profiles remain selectable only on
   hardware that passes their exact resource checks.
7. **Named people and role assignments.** Name the product `Admin`, release
   approver, security approver, license approver, production catalog signing
   custodian, recovery custodian, installation operator, QA witness, and
   security witness. `Admin` assigns finite product activities; it is not Linux
   `root`, does not expose private keys, and does not let a signer approve their
   own production catalog.
8. **A test window and failure budget.** Approve planned reboots, deliberate
   boot failures, removal/corruption of test model assets, TPM/recovery
   exercises, controlled power interruption, 100 suspend/resume cycles, 1,000
   compact lifecycle cycles, pressure tests, and restoration of both machines.
   State who may stop the run and the maximum acceptable outage.
9. **Evidence handling.** Name the restricted evidence location, retention
   period, redaction reviewer, time source, and evidence signer. Raw serials,
   recovery secrets, private keys, user data, TPM material, and model license
   credentials must not enter Git or a public support bundle.

## Approval 1: production model catalog and signing custody

The source repository contains verification contracts, not production private
keys and not an online signing service. The owner must approve a custody design
and arrange the external key ceremony described in
[`PRODUCTION_SIGNING_CUSTODY.md`](../../PRODUCTION_SIGNING_CUSTODY.md).

Required decisions:

- a new production catalog-signing key and trust root, distinct from all lab,
  model-pack, update, recovery, and certification keys;
- protected offline or HSM-backed key storage and an approved cryptographic
  implementation;
- named custodians, distinct license/release/security approvers, quorum and
  presence rules, backup shares, physical storage locations, access review,
  clock source, validity period, catalog sequence/rollback floor, and incident
  contacts;
- bootstrap, rotation, expiry, revocation, compromise, disaster recovery, and
  verification procedures; and
- a rule that build workers, inference workers, models, generated code, CI,
  and ordinary host administrators cannot read or export private key material.

The production ceremony input set must contain:

- the canonical model-profile catalog and its SHA-256 digest;
- each model-pack manifest, detached signature, complete blob inventory, and
  exact pack verification result;
- exact signed runtime and certification tuples;
- release identifier, catalog identifier, monotonically increasing catalog
  sequence, policy version, validity interval, and minimum accepted sequence;
- license, release, and security approval receipts from distinct principals;
  and
- current Admin assignment receipts for every approver and signer.

The retained output set must contain the canonical catalog, detached catalog
signature envelope, public trust metadata, approval-set digest, ceremony log,
independent verification receipt, and a second-person verification result on
the final offline bundle. A production exercise must also prove rejection of:

- a changed catalog byte, model shard, tokenizer, template, or runtime tuple;
- a lab key, wrong-purpose key, unknown key, expired key, or revoked key;
- a missing, duplicate, self-approved, expired, or wrong-release approval;
- a sequence below the protected rollback floor; and
- a catalog profile whose pack or claimed certification state is incomplete.

Do not provide private keys to this repository or to the Luma runtime. What is
needed from the owner is approval of the custody policy, named personnel,
access to the external protected signer, and the signed public artifacts.

## Approval 2: destructive installation and native boot evidence

First run the read-only preflight and inventory. Review their JSON together
with an independent physical inspection. Stop if the observed disk identity,
host identity, firmware state, release digest, or model bundle digest differs
from the authorization.

The destructive authorization must contain this information with no blanks:

```text
Authorization ID:
Release ID and digest:
Signed catalog ID, sequence, and digest:
Environment: E1 or E2
Pseudonymous host inventory digest:
Physical chassis/asset tag checked by:
Exact target disk vendor/model/serial-or-WWN/capacity/stable-ID:
Target disk inventory digest:
Non-target disks present and protected:
Backup/export location and verification digest:
Recovery-media digest and successful boot date:
Firmware/Secure-Boot recovery procedure location:
Approved operations: repartition / format / encrypt / image / reboot / power-cut
Forbidden targets and operations:
Start and expiry time in UTC:
Installation operator:
Independent witness:
Approver accepting complete target-disk data loss:
Abort contact and recovery owner:
Signatures and timestamps:
```

The operator must verbally and visually re-identify the physical host and
target disk immediately before the first write. Automation must re-open,
exclusively lock, and re-identify that exact device; any mismatch, ambiguous
identity, mounted target, active system disk, unprotected non-target disk,
expired approval, or failed backup check is a hard stop.

Capture at least these artifacts for both E1 and E2:

- signed pre-install host and block-device inventories, photographs or asset
  records sufficient for the witness to bind the physical machine, and hashes
  of all release/media inputs;
- the proposed partition and encryption plan before confirmation, the signed
  authorization, operator/witness identities, and the effect-time inventory;
- installer transcript, exit status, partition/GPT inventory, filesystem and
  LUKS2 metadata, slot identities, mounted-root identity, and proof that every
  non-selected disk is unchanged;
- UEFI/Secure Boot state, bootloader and UKI verification, kernel/initramfs/root
  digest binding, dm-verity state, and boot logs for the selected slot;
- offline first boot and the complete baseline workflow with the network cable
  removed or equivalent physical isolation;
- successful operation without a model plus missing/corrupt-model boot,
  desktop/file access, export, repair, and model-disable recovery;
- update writes to the inactive slot only, interruption at every declared write
  phase, prior-slot bootability, no live-root mutation, at most three failed
  trial boots, essential-health promotion, and automatic fallback;
- tampered bootloader, UKI, kernel, initramfs, verity digest, release bundle,
  model catalog, and model pack rejection results; and
- LUKS2 recovery with the model unavailable, TPM-unseal failure, and the
  approved motherboard/TPM replacement simulation, followed by a verified
  data export and normal recovery.

The normal recovery credential must be tested before any TPM failure exercise.
Never record the credential itself; record only the ceremony identifier,
custodians, successful use, timestamps, and signed result.

## Approval 3: hardware-dependent security and recovery qualification

Security qualification is evidence of enforcement under attack and resource
pressure, not the presence of a kernel feature. For each retained E1/E2 tuple,
provide an independent security reviewer and approve the following run set:

- **cgroup v2:** saturate CPU, memory, process count, and I/O independently;
  prove per-replica/per-tenant ceilings, a responsive control plane, bounded
  failure, no host OOM, and cleanup after cancellation/crash;
- **accelerator and pinned memory:** exhaust device memory and pinned memory
  separately; prove exact admission, one-device binding, exclusive assignment
  where required, lease fencing, bounded reset/recovery, and no stale reuse;
- **AppArmor and seccomp:** show the exact signed/versioned policy loaded in
  enforce mode, then exercise forbidden file, process, syscall, mount, ptrace,
  device, and network operations. Complain/permissive mode is a failure;
- **peer identity and privileged helper:** capture the kernel-derived peer
  identity path; try forged identity, replay, stale/revoked capability,
  argument mutation, wrong device, wrong driver/runtime certificate, crash at
  every journal phase, and effect after cancellation. No arbitrary command or
  shell interface may exist;
- **generated code:** run the escape, filesystem, network, device, resource,
  and persistence corpus inside the qualified KVM microVM. If KVM or the exact
  boundary is unavailable, deny native code; approve a separately qualified
  constrained runtime only through change control;
- **boot/storage recovery:** repeat tamper, LUKS2, slot fallback, power loss,
  recovery-media, export, restore, and idempotent repair cases without relying
  on inference; and
- **hardware lifecycle:** complete suspend/resume, accelerator reset, worker
  crash, thermal/pressure, firmware/driver invalidation, and compact lifecycle
  runs with raw measurements and defect disposition.

Every case needs the case ID, release and host tuple, prerequisites, exact
input, expected oracle, timestamps, raw log hashes, result, deviations,
reviewer, defects, and final disposition. A screenshot or `feature present`
probe alone is not acceptance evidence.

## Safe execution order

1. Approve roles, evidence storage, retained platform tuple, model licenses,
   and the signing-custody design.
2. Build and independently verify the signed offline release/model bundle.
3. On WSL, run only repository checks, development preflight, and read-only
   inventory. Preserve the JSON as non-closing development evidence.
4. On each native candidate, run read-only preflight and inventory. Review and
   sign them before drafting a destructive authorization.
5. Boot and verify recovery media, validate backups, remove or protect every
   non-target disk, and sign the exact time-bounded destructive authorization.
6. Execute T01–T16 and the applicable security/recovery procedures under a
   console recording or equivalent witnessed evidence process.
7. Restore the machine, verify exported data and evidence hashes, revoke any
   temporary lab authorization, and obtain QA/security/release sign-off.
8. Repeat independently on E2. Do not count two installations on one physical
   machine as two boards.

Any unexplained identity change, unreviewed package/firmware update, missing
witness, permissive mandatory control, evidence gap, unexpected write, data
corruption, privilege escape, secret disclosure, unrecoverable boot, host OOM,
or post-cancellation effect stops the run and blocks the affected release.

## What can be done on the current machine

The current Windows host and Ubuntu 26.04 WSL2 guest can run the full repository
suite, the Ubuntu development preflight, the read-only host collector, source
runtime, user install, and optional systemd user service. WSL output must say
that it is WSL and non-closing. Do not use it as evidence for Secure Boot,
native UEFI, physical disk installation, TPM/LUKS recovery, KVM isolation,
physical power interruption, or a second board.

The native-Ubuntu commands and artifact naming rules are in
[`UBUNTU_QUALIFICATION.md`](../../UBUNTU_QUALIFICATION.md), while the witnessed
physical procedure and case matrix are in
[`PHYSICAL_QUALIFICATION_RUNBOOK.md`](PHYSICAL_QUALIFICATION_RUNBOOK.md).
