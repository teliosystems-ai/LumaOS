# Resource checkpoint custody and recovery

The resource ledger and request journal use a separate TPM2 checkpoint authority
on installed systems. The original product Admin provisions it through reviewed
finite grants while the broker, model and acquisition services are masked and
drained. Unix root is an execution prerequisite, not authorization.

The owner approved implementation and disposable software-TPM tests on
2026-10-10. This approval does not cover the host TPM, disk installation or
physical qualification. Automatic commits and pushes of verified development
stages are authorized until the owner withdraws that instruction.

## Independent authority

The resource NV index is `0x01804c52`; its persistent parent is `0x81004c52`.
The Admin journal retains its distinct `0x01804c41` and `0x81004c41` handles.
The resource parent uses a distinct primary template and Name, independently
generated authorization and separately sealed credentials. Sharing an approved
public PCR-policy verifier does not share either secret. Installed access uses
the fixed local TPM transport, PCR7 and signed PCR11 policy.

`/var/lib/luma-os/resource-checkpoint/sealed` holds immutable enrollment inputs.
The sibling `paired` directory holds exact content-addressed backups, immutable
records indexed by their resulting NV head, the confirmed head and any retained
prepared transition. The fixed private runtime lock at
`/run/luma-resource-checkpoint/authority.lock` survives broker stop/start and
excludes competing writers;
the ledger lock separately excludes broker and offline maintenance overlap.

Every durable authority change captures and syncs the complete ledger, request
journal and referenced immutable archives before advancing NV once. Confirmation
requires exact durable readback. Lost replies poison the live authority and
retain the prepared transition; they never authorize automatic retry. Renewed
lease deadlines stay in the live session and cannot extend durable deadlines
across restart. Restart therefore retains charged capacity and fails closed
until drainage is proved.

## Reviewed provisioning

These are candidate interfaces for a qualified native installation. They are
not permission to run the ceremony on the development host. All mutations use
`sudo luma-admin-control`, genuine current Admin authentication, a live protected
UTC observation and the exact finite scope returned by review. Catalog issuance
uses the existing typed Admin catalog interface; no command issues its own grant.

1. Mask and drain the fixed broker/model/acquisition units. Preserve existing
   evidence and confirm the installation identity and resource pair.
2. Run `resource-checkpoint-prepare-review LOGIN`. Issue the returned exact
   `resource.provision` scope, then run
   `resource-checkpoint-prepare LOGIN GRANT REVIEW-SHA256`.
3. Run `resource-checkpoint-enroll-review LOGIN`. Issue its distinct scope, then
   run `resource-checkpoint-enroll LOGIN GRANT REVIEW-SHA256`. The existing owner
   secret is entered through a protected prompt; it is never argv or environment.
   The command refuses occupied handles and never takes ownership or clears TPM.
4. Retain the receipt and readback evidence. Service restart is a separate
   deliberate action after confirmation; enrollment does not restart anything.

Review digests bind exact installation, paired closure, boot policy and protocol
phase. Reviews are not bearer credentials. An expired or changed grant, account,
catalog, boot policy, inode, service mask or drainage proof refuses the ceremony.

## Interrupted enrollment

`resource-checkpoint-parent-review LOGIN` inspects a lost parent-persistence
reply. `resource-checkpoint-parent-continue LOGIN GRANT REVIEW-SHA256` requires
the retained expected Name recorded before dispatch, the exact current parent
profile, unchanged paired genesis and a vacant resource NV index. It does not
repeat parent persistence. It proceeds only from this authenticated phase.

`resource-checkpoint-pending-review LOGIN` and
`resource-checkpoint-finalize LOGIN GRANT REVIEW-SHA256` finalize an exact
authenticated genesis NV result whose sealed publication was interrupted.
Finalization does not replay the NV command. If sealed publication completed but
paired confirmation did not, the installed authority's exact NV-selected repair
path can finish the pair without reenrollment.

A dispatched NV operation whose result cannot be authenticated, missing sealed
custody, corrupt intent or incompatible handles remains quarantined. No reset,
clear, ownership takeover, fabricated success or blind dispatch is provided.
Custody investigation must preserve that evidence and determine a separately
authorized remediation; these commands cannot infer an outcome.

## Damaged ledger recovery

`resource-checkpoint-recovery-review LOGIN` reports the exact current NV-selected
closure and damaged-file inventory. Issue its exact `resource.recover` grant,
then run `resource-checkpoint-recover LOGIN GRANT REVIEW-SHA256` while masks and
drainage remain intact. The repair preserves damaged bytes and interrupted intent
in a private incident directory before restoring exact anchored bytes. Directory
and member identities are rechecked after authentication and TPM reads.

Only the actual current NV value selects a snapshot. A readable backup, checksum,
old mutable head or entire rolled-back filesystem does not grant recovery
authority. Missing current-NV records or damaged required backups refuse repair.
Repair neither releases capacity nor revives fenced leases, restarts services,
rewinds generations or writes NV. Subsequent reviewed drainage/reconciliation is
still necessary before any resource release or new admission.

## Explicit bounded retention

Backups and immutable head records have fixed count/byte ceilings. They are not
automatically purged. `resource-checkpoint-gc-review LOGIN NAME...` returns the
exact sorted inventory and Retain scope;
`resource-checkpoint-gc LOGIN GRANT REVIEW-SHA256 NAME...` deletes only the
reviewed unreferenced members. An object name is its SHA256; a historical record
name is `record-<NV-head>`. The current record and closure are always protected.

Delete obsolete records through reviewed disposition first; an object referenced
by any retained record cannot be removed. Partial cleanup is uncertain evidence,
not implied success or a capacity release. Inspect again before continuation.

## Qualification boundary

Unit tests and fresh disposable TPMs exercise software ordering, independent
handles/secrets, signed sealing, restart, lost-reply reconciliation and refusal.
They do not establish physical TPM endurance, real power-loss behavior, Secure
Boot/PCR acceptance, enforcing native AppArmor/systemd integration or installation
safety. Those remain native-image qualification work. Workflow history epochs
and policy archives are protected filesystem evidence, not separate TPM authority
and never an archive-based authorization or automatic restoration mechanism.
