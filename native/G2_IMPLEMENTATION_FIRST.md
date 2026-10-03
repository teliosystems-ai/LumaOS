# G2 implementation-first delivery sequence

Owner direction, 2026-10-01: finish the open implementation work before another
memory-heavy VM/model sweep; then test one consolidated candidate and perform
full testing of the produced image on the separate native Ubuntu machine.
This supersedes earlier plans to retry sequence-11 desktop/model VMs immediately.

## Resource and evidence rules

- Leave WSL memory settings and unrelated workloads unchanged. Do not launch
  the old frozen acceptance queues or a new full-image build after each patch.
- Keep source on C: and build/cache/image/evidence storage on D:.
- Run small targeted compilation, unit and isolated boundary checks as code is
  changed. They detect implementation defects but are not the full test sweep.
- After the components below are implemented and reviewed, freeze one candidate
  source manifest, build its image, and bind every integrated result to that
  image's digest. Serialize heavyweight tests and retain failed evidence.
- A failed integrated test requires repair and a new candidate/relevant rerun;
  "one sweep" does not allow skipping failures or qualifying changed bytes
  using an older image's passing evidence.
- The separate Ubuntu machine will test the actual distributed image, including
  installation/boot/recovery, not merely a source checkout. Physical destructive
  targets, recovery preparations and firmware changes still require approval.

## Dependency-ordered implementation backlog

Use [G2_SOFTWARE_STATUS.md](G2_SOFTWARE_STATUS.md) for implemented scope and
evidence. Every row here remains open until its complete implementation exists;
targeted source checks alone cannot close G2 acceptance.

| Work package | Required integration before candidate freeze |
| --- | --- |
| Admin and trust | The native sealed-child backend, durable parent intent, fixed-path loader and positive existing-owner checkpoint enrollment now pass targeted disposable-TPM tests. Read-only inspection, reviewed bound-parent/no-NV continuation and exact TPM-committed pending-proposal publication pass targeted tests. Vacant or mismatched NV, unbound-parent and other uncertain states remain fenced. The older systemd 255 path still refuses nonempty owner authorization and is not the product backend. Keep existing ownership; no weaker fallback. Complete the remaining reviewed enrollment recovery, product Admin bootstrap/service, finite roles, governed principal and signer/time/custody lifecycle, and qualify the installed flow. External Admin remains a future variant. |
| Policy and durable effects | Effect-time identity/grant checks, durable request/effect receipts, idempotent replay and reviewed uncertain-outcome reconciliation through native production interfaces. The root-only worker replay fence and explicit publication of TPM-proven pending inert audit records are limited increments, not production effect reconciliation or completion. |
| Signed skills and vertical workflow | A read-only native validator and image-overlay three-node template cover closed file-to-artifact DAG shape, types, bounds and cycles. A separate laboratory skill key signs a closed registry bound to that template; fixed-path native signature and descriptor admission pass bounded source tests. A pure bounded invoice CSV calculation now passes native source tests, but is not called by a supervisor. None of these paths executes an authorized effect. Complete governed production signing custody, rotation/revocation, native supervisor integration, descriptor-scoped file reads, managed artifact writes, cancellation/checkpoints/restart and a manual file-to-artifact journey. |
| Model lifecycle | Single-worker exclusion, verified-descriptor handoff, cgroup-v2 ancestor-limit admission, verified acquisition and exact service-state admission before the managed worker stop, a narrow guarded unchanged-prior restart after failed stop or activation, a durable interrupted-activation fence with reviewed clearance and narrow reviewed candidate roll-forward, bounded post-restart listener readiness, and explicit older-image migration now exist in source. They are not a memory reservation or atomic multi-file activation. Complete rollback/arbitrary partial-state and broader post-stop failure policy, installed migration, reconfiguration and roll-forward qualification, governed catalog/pack admission, resource leases/generations, stale-worker fencing, pressure/quarantine/restart and bounded cleanup; evaluate installation/activation and real cycles on the consolidated image. Preserve manual operation without a model. |
| Generated-code isolation | Implement a supported microVM or separately qualified constrained runtime, with adversarial tests. Keeping execution denied is safe but not completion of the requested capability. |
| Desktop/accounts | Installed GDM authentication, manual application workflow, locking, credential/account lifecycle, migration and model-failure independence. Packaging and compositor smoke are not sufficient. |
| Installer/boot/recovery | Integrate all new services into the installer/image, update/fallback and recovery; interruption/migration/storage-pressure handling and no silent reset of uncertain state. |
| Consolidated acceptance | Add checks for the new components, freeze/build one candidate on D:, execute the applicable integrated suite and real compact-model cycles, then retain the separate Ubuntu/physical results. |

## External evidence remains separate

Production public signing/catalog approvals and actual custody cannot be
manufactured from laboratory keys. Firmware/TPM/GPU/power-loss qualification,
both required A1 boards and unavailable large-model hardware remain explicit
acceptance dependencies. Tests on the separate Ubuntu machine are valuable
but do not automatically satisfy a requirement for two named boards or other
hardware tuples. Implement the software paths first and record those remaining
inputs/qualifications without claiming G2 complete.
