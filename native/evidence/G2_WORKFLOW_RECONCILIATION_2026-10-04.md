# G2 Committed Workflow Outcome Acknowledgement

The native invoice coordinator now supports reviewed acknowledgement of an
exact already committed catalog receipt, including after signed-skill
withdrawal. This closes a narrow recovery gap: an artifact may commit while
the coordinator remains Applying because its acknowledgement was lost.
This is installed-root laboratory audit recovery, not product Admin, new
effect authority, general uncertain-outcome resolution or G2 completion.

## Bound observation and acknowledgement

`workflow-invoice-reconcile REQUEST-ID` inspects a validated Applying or
Completed run. It recomputes the report from the immutable source and requires
an exact existing native receipt bound to installation, effect ID, artifact
target, expected/committed version, workflow and source digests, output digest,
size, filename and media type. An object alone, a conflicting receipt or a
missing receipt is not success and does not prove the effect was not applied.

Inspection returns a distinct reconciliation review. Its SHA-256 input is
`luma-native-workflow-acknowledgement-v1`, one NUL byte and canonical JSON
containing the plan digest, Applying checkpoint digest and exact receipt.
The ordinary advance/status review does not authorize acknowledgement.
`workflow-invoice-reconcile REQUEST-ID --publish-committed REVIEW-SHA256`
appends only the existing-format Completed checkpoint with that saved receipt.
The review remains stable after completion so a lost acknowledgement can be
retried without another checkpoint. Later artifact versions remain unchanged.

The fixed-path native observer owns the catalog directory lock and connection;
it exposes only a verified receipt recheck, not artifact publication. The
coordinator acquires its lock first and retains both ownership guards through
the acknowledgement transaction. Catalog metadata/object integrity and fresh
installed installation identity are rechecked before checkpoint commit. A
changed proof rolls back the checkpoint transaction. Root-only admission,
bounded private ext4 storage, native schema validation and immutable history
remain in force. No database schema migration or silent reset is introduced.

Skill withdrawal continues to block ordinary advance and effect replay.
Acknowledgement does not require renewed skill admission because it records
only a proven past commit; it cannot invoke the publication boundary, revive
execution authority, cancel an uncertain effect or grant any capability.
Preparation and pre-effect cancellation cannot be used as past-commit proof.

## Verification scope

Targeted verification passed on 2026-10-04 against a frozen source snapshot in
`D:\LumaOS-builds\g2-workflow-reconciliation-targeted-20261004-01`.

- Source snapshot manifest SHA-256: `f2c2560ebf194d10b410e1df8bd8b1101f21b2cda88654ed5418ab7893813b8b`.
- Completed test log SHA-256: `823f4d6ac449cffbe9ad3a442d39410c29ca16edc71beb90b914bdd8b6fb4a9f`.
- All 165 captured source files matched the current checkout after the run.
- All 44 selected Rust tests passed: ten coordinator, five DAG, 14 catalog,
  three signed-registry, seven lab-pair and five calculation tests. This is a
  targeted regression, not a rerun of every Rust/hardware fixture.
- Formatting, the offline locked native build with warnings denied and two
  skill-registry builder checks passed.
- The compiled CLI fixture exercised three real committed-artifact/lost-workflow
  acknowledgement cases after signature withdrawal, distinct review binding,
  non-root denial and unchanged catalog contents. Ordinary advance remained
  denied after audit acknowledgement; each run retained exactly five checkpoints.
- Abrupt process exits immediately before and after acknowledgement COMMIT
  left Applying and Completed respectively. Explicit retry of the same review
  completed or replayed without another artifact or checkpoint. The earlier
  six workflow publication crash boundaries also passed their regression.
- Missing receipts, a receipt bound to a different target and corruption of
  actual catalog output after review all refused acknowledgement. Restoring
  the test-corrupted bytes allowed the exact reviewed retry. A completed
  acknowledgement also replayed after the artifact advanced to a later version.
- Rust checks additionally covered catalog lock ownership, exact proof binding,
  object-integrity rechecks, proof loss inside the checkpoint transaction and
  refusal before Applying or after cancellation.

The compiled fixture uses test-only boot-marker and abrupt-exit interposers in
a disposable container. They are not packaged into the runtime. Its real
SQLite/ext4 transactions are source/CLI evidence, not installed-image or
physical power-loss qualification. The existing native CI fixture inherits
these checks; remote CI execution was not observed.

The disposable tools container uses one CPU, 768 MiB memory with no extra swap,
128 PIDs, no network and no host devices. Docker storage, cache, snapshot and
logs remain on D:; source remains on C:. No OS image is rebuilt, model loaded,
WSL memory changed, physical TPM touched or unrelated workload stopped.

## Remaining G2 integration

This is a narrow addition to the
[native workflow checkpoint](G2_WORKFLOW_RUNS_2026-10-04.md). Missing or
conflicting receipts remain fenced, not terminally resolved. Broader
known-not-applied/conflict disposition, principal-bound policy and folder/effect
grants, authenticated product Admin/service delivery, trusted time, generic
scheduling and governed schema/migration/retention remain open. The native
catalog's dependency and qualification limits are unchanged.

The [implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md) and
[software completion register](../G2_SOFTWARE_STATUS.md) remain authoritative
for open work. Freeze/build one integrated candidate after implementation,
then run the consolidated sweep and the separate native Ubuntu evaluation.
These targeted checks do not qualify installed boot, physical power-loss
behavior, LUKS/TPM, production signing custody or the distributed image.
