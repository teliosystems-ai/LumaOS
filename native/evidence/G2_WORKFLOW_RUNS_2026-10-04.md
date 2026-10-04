# G2 Native Invoice Workflow Checkpoint

Status: native checkpoint coordinator and focused source/CLI verification
passed on 2026-10-04. The exact image-owned invoice graph now has a durable
installed-root laboratory runner. This is not product Admin/grant integration,
a generic DAG scheduler, the enrolled-folder journey or G2 acceptance.

## Native execution and checkpoint ownership

Preparation binds installation, workflow request, artifact target/expected
version, current signed graph digest and immutable source digest/size. Input
comes from the operator's bounded CSV stdin snapshot; it confers no folder
grant. The first node reads that private snapshot, the second calculates exact
monthly totals, and the third calls the existing typed artifact boundary.
No model, shell, generated-code or ambient source-folder execution is added.
Other valid graph shapes remain validation-only; executor support is checked
separately against the exact normalized three-node image profile.

The separate private ext4 store uses SQLite WAL with full synchronization.
One native owner holds its directory lock until database close. Plans remain
immutable; checkpoints append with a digest-linked predecessor and a
transactional current-stage pointer. Schema triggers reject history deletion,
checkpoint edits, changed plans and skipped or post-cancellation transitions.
Admission validates schema/installation, database integrity, checkpoint chains
and referenced object bytes. It never creates or resets missing runtime state.

Source and report objects use private same-filesystem preparations, file sync,
no-overwrite rename and directory sync before metadata commit. Complete exact
preparations can resume; partial bytes remain fenced without truncation or
deletion. `workflow-store-status` exposes their observed digest and size.
Unreferenced objects remain preserved, not automatically collected. These
consume the 64 MiB/512-file bound; the store admits at most 256 runs, and
metadata has a separate 4,096-page limit. General receipted retention/GC and
storage-pressure qualification remain open.

## Cancellation and publication recovery

Each explicit advance checkpoints the next step. The normal sequence is
`prepared -> source-read -> calculated -> applying -> completed`.
Publication commits Applying before crossing into the catalog. The artifact
service synchronizes its object and commits its own version/receipt transaction;
only then does the coordinator append Completed with that exact receipt.
The two services do not share writable databases or claim a cross-database
atomic commit. Their ownership order is coordinator first, then catalog.

The catalog effect ID is SHA-256 of `luma-native-workflow-invoice-v1`, one NUL
byte and the complete canonical plan. Its target, expected version, source and
workflow digest remain fixed across retries. Signed graph and installation
admission are rechecked on every execution/replay and at checkpoint/effect
commit boundaries. The coordinator also rechecks its current checkpoint before
catalog commit. A stale unrelated review or changed plan is refused.

Repeating a step's original review after a lost acknowledgement returns the
saved outcome without advancing another node. An interrupted publication stays
Applying; status inspection and explicit retry use the catalog's exact
idempotent receipt rather than infer success from an object or process state.
Completed replay requires the original receipt to exist: it cannot recreate a
missing receipt after catalog rollback, and it never resets later versions.
Startup does not automatically resume requests.

Cancellation is accepted only before Applying and appends a durable terminal
checkpoint. Its original review can be retried idempotently. Withdrawal of the
signed workflow blocks advancement but does not block authority-reducing
cancellation of a prepared run. Once publication may have begun, cancellation
is refused instead of claiming to undo an artifact. A competing owner receives
a busy refusal; that is not accepted cancellation. Lost connections do not
imply cancellation or rollback.

Fresh-install initialization is wired into the installer source. Existing
installations require explicit `workflow-store-init` on a candidate containing
the new binary. The existing offline archive includes `lib/luma-os`, including
this store; that inclusion is not restore qualification. Keep SQL writers and
checkpoint tools offline while the native owner is active. See the
[operator instructions](../image/README.md#durable-native-invoice-workflow).

## Verification

Final evidence: `D:\LumaOS-builds\g2-workflow-targeted-20261004-02`.

- Source snapshot manifest SHA-256: `73c69b8cf1dae38732a9bc38c2aeabe4060fb361b2bb47d7eb8e745270588aea`.
- Completed test log SHA-256: `6ec18b8b90f19aaab48ed7e5f7ee37282bf37a3d8f903a7b9a396ffd783bbcab`.
- All 40 selected Rust tests passed: seven coordinator, five DAG, 13 catalog,
  three signed-registry, seven lab-pair and five calculation tests. This is a
  targeted regression, not a rerun of every Rust/hardware fixture.
- Formatting, the offline locked build with warnings denied and two
  skill-registry builder checks passed.
- The compiled CLI fixture passed real workflow/catalog publication, exact
  preparation and step replay, stale-review/changed-target refusal, non-root
  refusal, cancellation at all three pre-effect stages, skill withdrawal,
  preservation of later versions, missing-receipt refusal after a quiescent
  catalog rollback, append-only SQL guards and retained partial preparations.
- Six abrupt exits covered before/after Applying commit, after artifact object
  publication, after artifact receipt commit, before Completed commit and
  after Completed commit. Explicit retries of the original publication review
  yielded one artifact receipt and preserved the expected checkpoint state.
- Rust tests additionally exercised competing ownership, pure-checkpoint
  commit-time revocation, uncertain effect acknowledgement, unbound effect
  replies, source corruption, invalid format and executor-profile refusal.

The earlier `-01` run passed a narrower version of the runner/CLI checks. Its
evidence is retained; the final `-02` manifest binds the completed scope.
Test-only interposers simulate the installed boot marker and abrupt process
exits without destructors. They never enter the OS runtime. Real SQLite/ext4
operations in a disposable container do not prove OS boot, LUKS/TPM behavior,
physical power-loss recovery or the integrated Ubuntu journey. Native CI
inherits the CLI checks through the existing fixture; remote execution was
not observed.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs, no network
and no host devices. D: holds Docker storage, cache, snapshots and logs; C:
holds source. No OS image was rebuilt, WSL memory changed, physical TPM
ownership altered or unrelated workload stopped.

## Remaining product integration

Product Admin and principal-bound folder/effect grants, authenticated service
delivery and effect-time policy must be integrated before this can be the
production workflow. Generic scheduling, deadlines/lease generations, broader
cancellation and known-not-applied/conflict reconciliation, public artifact
schemas, trusted UTC, governed migration/retention and protected rollback
remain open. The SQLite dependency qualification limits from the
[catalog checkpoint](G2_ARTIFACT_CATALOG_2026-10-03.md) are unchanged.

The consolidated image and separate native Ubuntu evaluation must exercise
the integrated implementation before G2 can close.
