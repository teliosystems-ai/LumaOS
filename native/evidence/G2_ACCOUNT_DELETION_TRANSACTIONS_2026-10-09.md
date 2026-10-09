# Governed account deletion transaction evidence

Development checkpoint: 2026-10-09. Existing installed non-Admin account
deletion now has a reviewed native source path with explicit four-file
publication and continuation after interruption. This does not complete the
account-lifecycle bundle, Requirement #1 or G2. Laboratory dates and emulator
clocks are not protected UTC authority.

## Implemented scope

The fixed local ceremony accepts an installed target account and transaction
identifier, not file paths, secrets, hashes or supplied identity commitments.
The original Admin is excluded. The target must have an unshared account-owned
primary group. Duplicate identities, mismatched private groups and other users
sharing that primary group refuse without removing their authority.

Preparation derives exact passwd, shadow, group and gshadow replacements from
original pinned records. It preserves unrelated rows and group passwords and
removes the target's records, memberships and private group. The manifest binds
the installation, principal, current generation, credential checkpoint, whole-file
before/after hashes and each file's mode/group. Private nondumpable buffers hold
credential-bearing records; returned proposals contain commitments, not hashes
from shadow or gshadow.

Reviewed preparation atomically retains the complete private before/after
transaction directory without replacing an existing proposal, then checkpoints
the intent and advances/disables the target principal. Original evidence handles
remain pinned through authentication and TPM dispatch. A separately reviewed
permission event performs no filesystem publication. Each explicit file command
requires a fresh nonserializable Admin continuation, its exact transaction scope,
live PAM and current semantic history. Publication order is shadow, gshadow,
group, then passwd. Generic PAM, root privilege, receipts and general socket
requests cannot substitute for that owning continuation.

Publication holds the original identity directory, migration lock, source and
evidence descriptors. It preserves the target file's original ownership/mode,
renames through directory descriptors, synchronizes both directories, and checks
the published inode, content, metadata and unchanged other files. The deliberate
rename invalidates old whole-file account proofs; the continuation closes on
success, refusal or unwind rather than reusing those proofs.

Retained evidence admits only exact ordered before/after mixtures. Restarted
continuation can publish the next file or verify an already published file
without another rename. A fresh owning continuation may finish an empty or exact
prefix dispatch file without truncation. Conflicting, replaced or out-of-order
state refuses and remains evidence. Uncertain TPM outcomes require explicit exact
journal reconciliation and cannot trigger filesystem dispatch or another extend.

Completion requires every exact published file and its permitted fenced
generation. The principal remains disabled; its installer registry entry and
credential checkpoint remain history, with a governed deletion tombstone.
Ordinary generation advancement, lock/password transitions or another deletion
cannot revive it. Its ID, login and UID remain reserved. Home data is not erased
and existing Unix processes are not forcibly terminated.

One incomplete credential/deletion transaction is admitted globally. Their
combined catalog inventory is bounded at 128; complete/interrupted deletion
proposal directories have an additional combined 128-entry ceiling. Exhaustion
preserves evidence and refuses. General socket requests reject all deletion
phases, and the service identity mount remains read-only. AppArmor source
enumerates the fixed local publication and private staging paths.

## Final retained evaluation

Final evidence is `D:\LumaOS-builds\g2-account-deletion-20261009-04`.
The frozen runner exited zero with `ACCOUNT_DELETION_SWEEP_PASSED`. All 222 build
inputs, 63 native source/support test files and the CI workflow match the checkout
byte-for-byte, with zero mismatches. Fourteen pre-existing Python bytecode files
were also copied; all 77 copied native test-tree files match the checkout.

Build output, Docker storage, cache and evidence remained D-backed. The offline
build/test container used one CPU, a 1.5-GiB memory cap, no swap and 128 PIDs.
The separate PAM/emulator container used one CPU, 1 GiB, no swap and 128 PIDs.
No host accounts/services, host clock, physical TPM, TPM ownership or WSL settings
changed. Account mutation occurred only inside the disposable test container,
against the non-Admin account created by its parent fixture.

- Formatting and the locked offline production build passed with warnings denied.
- Six targeted Rust filters passed: 124 tests, zero failures and five
  fixture-dependent ignores. This was not a rerun of the complete ordinary Rust
  suite. All six new deletion-engine tests ran without skips or ignores.
- Catalog tests covered immediate generation fencing, immutable adoption,
  completed tombstones, non-revival and valid serialized deletion socket refusal.
  The new lost-reply test exercised preparation, permission and completion,
  requiring exact journal reconciliation without redispatch or another extend.
- Full native Python discovery ran 293 tests: 291 passed and two existing
  upstream UTC-fixture checks skipped. Skips and ignores are not passes.
- The real PAM/kernel-peer/existing-owner software-TPM parent passed in 70.27
  seconds. Thirteen new deletion markers covered inspection/wrong-review refusal,
  preparation fencing, permission without publication, generic-session refusal,
  closed/expired/epoch/head-change continuation refusal, all four actual file
  publications with exact replay, and final permanent tombstones.
- The same parent reran thirteen lock, nine password, ten credential-checkpoint,
  nineteen catalog, seven session-issuance, twelve projection and five offline
  custody-recovery markers. These are scenario steps, not independent test-process
  counts or physical qualification results.
- The updated Admin AppArmor profile parsed without kernel loading/enforcement.
  The existing WSL interface/cache warning did not change its zero exit status.

These are isolated fault injections and semantic restart checks, not physical
power-loss, installed confinement or full-image observations. The executable is
not a newly built bootable image; tool/root image definitions were not rebuilt.

## Earlier attempts retained

- `01` stopped at compilation because the new CLI supplied the wrong
  session-issuance argument shape. The call was corrected to the existing owned
  Admin composition.
- `02` passed its earlier targeted Rust filters and production build, then its
  new Python source check incorrectly required an unwrapped reducer expression.
  The assertion now matches formatting whitespace without weakening the required
  tombstone insertion. This run did not execute the PAM integration.
- `03` passed the updated targeted Rust filters, production build and Python
  regression. The new PAM fixture then retained the exclusive TPM-writer handle
  while opening another login. Its handle lifetime was corrected; the head-change
  fault also releases and reacquires that handle around the deliberately separate
  writer. Production authentication and exclusive-writer rules were not relaxed.
  Post-publication inode/metadata validation was additionally tightened for `04`.

Failed or earlier-source runs are not credited as final-source passes. Their
logs and snapshots remain on D; no existing evidence was removed.

## Artifact digests

| Artifact | SHA-256 |
| --- | --- |
| Final build-input manifest | `8ec6b638d24b5ab80e77af951f274ec74c2fa5779a1fd5cd943443dfec502c17` |
| Final test log | `9e84ca7270b801ff1dcfeb2540c435bd709c8e81a11b89e9d570047777569ebc` |
| Frozen runner | `02dca267e3c9cee01a783d0726f8c38477882578a6e70baf04b1dc7355124b0e` |
| Production executable observed during build | `84f56731a4aecef43c646426699b86de6331e3a201dec350df55b41c8fcd3bbd` |
| Cached tools image | `69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0` |

## Remaining completion work

Account creation, original Admin password/lock recovery, general registry and
multi-file identity mutation, protected password-aging renewal, governed proposal
retirement and damaged-authority reconstruction remain open. Protected UTC
deployment and authenticated seed/history delivery, finite grants and
resource/inference/effect admission, and broader workflow/retention integration
remain separate outstanding bundles.

No enforcing installed-service, physical TPM, native interrupted
installation/boot/recovery, final-image or requirements-defined hardware gate
claim is made. The [software completion register](../G2_SOFTWARE_STATUS.md) and
[local Admin ceremony](../LOCAL_TPM2_ADMIN.md) retain the boundaries and remaining
work. Requirement #2 has not been started.
