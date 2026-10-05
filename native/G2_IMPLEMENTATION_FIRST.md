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
| Admin and trust | The native sealed-child backend, durable parent intent, fixed-path loader and positive existing-owner checkpoint enrollment now pass targeted disposable-TPM tests. Read-only inspection, reviewed bound-parent/no-NV continuation and exact TPM-committed pending-proposal publication pass targeted tests. A separately authenticated, reviewed product bootstrap anchors the initial governance principal. Fresh principal-bound finite activity registration and versioned role definitions now have TPM-bound semantic receipts and exact restart/replay; neither enables assignment or resource effects. The local catalog service/client, enforced-confinement startup checks and packaged unit/profile now exist in source; kernel-peer/framing checks are not installed PAM-to-TPM qualification. Vacant or mismatched NV, unbound-parent and other uncertain states remain fenced. The older systemd 255 path still refuses nonempty owner authorization and is not the product backend. Keep existing ownership; no weaker fallback. Complete the remaining reviewed enrollment recovery, full confined Admin lifecycle, trusted-time finite assignment/revocation, governed principal/bootstrap recovery and signer/time/custody lifecycle, and qualify the installed flow. External Admin remains a future variant. |
| Policy and durable effects | Effect-time identity/grant checks, durable request/effect receipts, idempotent replay and reviewed uncertain-outcome reconciliation through native production interfaces. The native inert journal requires its integrating service to authorize the exact entry before preparation and again before TPM advancement; this is not the complete product authenticator or policy service. The root-only worker replay fence and explicit publication of TPM-proven pending inert audit records are limited increments, not production effect reconciliation or completion. |
| Signed skills and vertical workflow | Native validation, lab-signed admission, calculation and scoped reading exist. The earlier lab pair store remains separate, with an explicit reviewed copy into the native catalog that preserves source records and retries by stable mapped IDs. A native ADR-0003 backend adds WAL metadata/receipts, immutable domain-local objects, logical IDs, sequential versions, compare-exchange, replay and retained preparations. A separate native WAL coordinator now runs the exact invoice graph from an operator snapshot, with durable checkpoints, cancellation before Applying, explicit catalog-backed recovery/replay and reviewed acknowledgement of an exact already committed receipt after skill withdrawal without redispatch. Fresh-install initialization is wired in source. These interfaces remain installed-root/lab. Complete governed signing custody/rotation/revocation, production supervisor and principal-bound folder/effect grants, generic artifact/public-schema and principal integration, trusted timestamps, broader schema/reference/principal migration, receipted retention lifecycle, wider cancellation/reconciliation and scheduling, and the installed manual journey. |
| Model lifecycle | Single-worker exclusion, verified-descriptor handoff, cgroup-v2 ancestor-limit admission, verified acquisition and exact service-state admission before the managed worker stop, a narrow guarded unchanged-prior restart after failed stop or activation, a durable interrupted-activation fence with reviewed clearance and narrow reviewed candidate roll-forward, bounded post-restart listener readiness, and explicit older-image migration now exist in source. They are not a memory reservation or atomic multi-file activation. Complete rollback/arbitrary partial-state and broader post-stop failure policy, installed migration, reconfiguration and roll-forward qualification, governed catalog/pack admission, resource leases/generations, stale-worker fencing, pressure/quarantine/restart and bounded cleanup; evaluate installation/activation and real cycles on the consolidated image. Preserve manual operation without a model. |
| Generated-code isolation | Implement a supported microVM or separately qualified constrained runtime, with adversarial tests. Keeping execution denied is safe but not completion of the requested capability. |
| Desktop/accounts | Installed GDM authentication, manual application workflow, locking, credential/account lifecycle, migration and model-failure independence. Packaging and compositor smoke are not sufficient. |
| Installer/boot/recovery | Integrate all new services into the installer/image, update/fallback and recovery; interruption/migration/storage-pressure handling and no silent reset of uncertain state. |
| Consolidated acceptance | Add checks for the new components, freeze/build one candidate on D:, execute the applicable integrated suite and real compact-model cycles, then retain the separate Ubuntu/physical results. |

The [UTC design](TRUSTED_UTC_DESIGN.md) records the owner-approved provider set,
initial bounds and offline refusal. Checked interval/quorum arithmetic, fixed
policy, a non-authorizing keeper lifecycle and a pinned chrony good-sample
publisher/closed frame decoder are implemented in source. The publisher fixture
is not deployed. A kernel-bound receiver source increment now handles sender
identity, bounded queues and replay, but protected supervisor/runtime approval,
keeper/clock/history lifecycle and
time-bound authorization integration remain part of the open Admin/trust work
package. See [the publisher checkpoint](evidence/G2_UTC_PUBLISHER_2026-10-05.md).
See also [the receiver checkpoint](evidence/G2_UTC_RECEIVER_2026-10-05.md).
The subsequent [stream composition](evidence/G2_UTC_STREAM_2026-10-05.md) joins
every receiver round to the keeper without hiding queued quorum loss, and adds
fresh projection with bounded heartbeat freshness. It remains non-authorizing;
protected runtime approval, history, lifecycle notification delivery and grant
composition are still required before candidate freeze.
The [clock-step watch](evidence/G2_UTC_STEP_WATCH_2026-10-05.md) now supplements
numeric comparisons with a kernel notification checked around candidate work.
This is not complete suspend/resume delivery or deployed-clock qualification;
the remaining protected runtime/history and grant integrations stay open.
Do not count source linkage or arithmetic as a completed time provider.

## External evidence remains separate

Production public signing/catalog approvals and actual custody cannot be
manufactured from laboratory keys. Firmware/TPM/GPU/power-loss qualification,
both required A1 boards and unavailable large-model hardware remain explicit
acceptance dependencies. Tests on the separate Ubuntu machine are valuable
but do not automatically satisfy a requirement for two named boards or other
hardware tuples. Implement the software paths first and record those remaining
inputs/qualifications without claiming G2 complete.
