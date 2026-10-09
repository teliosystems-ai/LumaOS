# Governed non-Admin password transaction evidence

Development checkpoint: 2026-10-09. Existing non-Admin account password
replacement now has a reviewed native source path. This increment does not
complete the account-lifecycle bundle, Requirement #1 or G2. Laboratory dates
and emulator clocks are not protected UTC authority.

## Implemented scope

The fixed local `admin-account-password LOGIN TARGET TRANSACTION` ceremony
accepts no secret, hash, identity-source path or supplied credential commitment.
Initial hidden terminal entry confirms a password with at least twelve printable
characters and at most 256 UTF-8 bytes. Secret entry precedes preparing the Admin
login, avoiding expenditure of the short governed PAM lifetime on human input.
Fresh original-Admin authentication and an owned governed session are required
before retaining any private proposal.

The distribution libxcrypt adapter generates and verifies a fresh yescrypt hash.
The admitted profile is fixed; unavailable or incompatible hashing refuses
without an alternative algorithm or reduced-cost fallback. Plaintext entry,
entropy, external crypt context and result buffers are locked and nondumpable,
with wiping on drop. The crypt context has a separate 64-KiB allocation ceiling;
existing sealed-credential and account-row ceilings remain 16 KiB. Distribution
internal allocations are not separately attested by this evaluation.

The owned session validates the catalog reducer before private staging and
rechecks live Admin, registry and checkpoint authority before an atomic
no-replacement directory rename. The retained proposal fixes its intent, salt
and exact shadow bytes across CLI invocations. Commit requires an inspected
retained proposal and its current review digest. Passwords and hashes do not
appear in returned JSON, command arguments, environment input or diagnostics.

The existing preparation, publication-permission and completion phases anchor
the exact mutation, advance and disable the target generation, publish only
under the owned live Admin continuation, and adopt the new credential commitment
only after exact publication checks. Uncertain TPM replies retain the pending
journal fence without filesystem dispatch or retry. Explicit exact journal
reconciliation precedes continuation. Already-published continuation checks
the records without another rename. Legacy lock intents omit the optional kind
field and preserve their canonical representation.

Lock state, password aging, passwd and unrelated shadow rows remain unchanged.
A password change cannot implicitly enable a disabled-but-unlocked principal.
No host clock is used to renew aging or expiry. Interrupted temporary proposals
are private evidence, never reusable complete proposals. Both temporary and
proposal/transition inventories have 128-entry ceilings; exhaustion preserves
evidence and refuses, rather than evicting it. The general socket rejects valid
password intents and still has a read-only identity mount. Image source declares
libcrypt build/runtime dependencies and the narrow local AppArmor paths.

## Final retained evaluation

Final evidence is `D:\LumaOS-builds\g2-account-password-20261009-04`.
The frozen runner exited zero and recorded `ACCOUNT_PASSWORD_SWEEP_PASSED`.
All 221 build inputs, 62 native test-input files and the CI workflow matched
the checkout byte-for-byte, with zero mismatches.

All compiled artifacts, container storage, cache and evidence stayed on D-backed
storage. The offline build/test container used one CPU, a 1.5-GiB memory cap,
no container swap and 128 PIDs. The separate PAM/emulator container used one CPU,
1 GiB, no container swap and 128 PIDs. No WSL settings, host accounts/services,
clock configuration, physical TPM or TPM ownership changed.

- Formatting and the locked offline production build passed with warnings denied.
- The complete ordinary Rust suite passed: 679 passed, zero failed and 38
  fixture-dependent tests ignored by ordinary discovery, in 594.66 seconds.
- Full native Python discovery ran 289 tests: 287 passed and two existing
  upstream UTC-fixture checks skipped. Skips and ignores are not passes.
- The real PAM/kernel-peer/existing-owner software-TPM parent passed in 61.44
  seconds, explicitly executing its normally ignored integration entrypoint.
- All nine new password scenario markers passed. Both replacement and governed
  restoration checked stable private proposals, wrong-review refusal without
  shadow replacement, generation fencing for both passwords, early-completion
  refusal, actual shadow publication while fenced, replay without a second rename,
  new-password PAM/governed admission and old-password refusal. Restoring a
  password did not revive the original session.
- The same parent reran thirteen lock/unlock, ten credential-checkpoint,
  nineteen catalog, seven session-issuance, twelve projection and five offline
  custody-recovery markers. Markers are scenario steps, not additional independent
  test-process counts.
- The updated Admin AppArmor profile parsed without kernel loading or enforcement.
  Its existing WSL interface/cache warning did not change the zero exit status.

The ordinary suite includes all eight account file-engine tests and both new
secret/crypt tests. Catalog tests cover disabled-principal non-enable semantics
and serialized password-intent socket refusal. The lost-reply test covers all
six lock/password and preparation/permission/completion combinations, preserving
filesystem state and requiring exact reconciliation without another extend.
These are isolated fault injections, not physical power-loss observations.

## Earlier attempts retained

- `01` stopped at compilation on a fixture-only temporary lifetime error.
  Binding the owned continuation before the closure return corrected it.
- `02` passed the earlier targeted checks, production build, native regression
  and all nine PAM password markers. It predates the final retention, fault
  coverage and packaging checks and is not substituted for final-source evidence.
- `03` passed the targeted final-source filters, then its full ordinary suite
  found worker-UID fixture failures because the shared temporary parent was mode
  `0700`. Only its verified isolated container was stopped; its runner recorded
  exit 137 and retains the partial failure log. The corrected runner uses a
  traversable root-owned parent, private per-fixture/storage directories and the
  same product source and assertions. It runs the full suite once without
  redundant overlapping filters. Runs `03` and `04` have identical complete
  build-input manifests. No interrupted or failed full run is credited as a pass.

## Artifact digests

| Artifact | SHA-256 |
| --- | --- |
| Final build-input manifest | `5e947e0fb57b5f684d1c2498c9d457041cffb150dd055080949e68f36f5d6f79` |
| Final test log | `3a267245b4bbb14a63ad75c01244d286fba33b7681d1d8735822da0eb4c49412` |
| Frozen runner | `99528155efd0ed223c8aba3de07ea32b798c179b46e0cd20455d279a1573c822` |
| Production executable observed during build | `0e614c5f6c88ef8dcf47b0984f46a23a5cd72a73fedcefdf55e9e7e244fdca8d` |
| Cached tools image | `69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0` |

The executable is not a newly built bootable image. The cached tools image
contained libcrypt-dev/libcrypt1 `1:4.4.36-4build1`; tool/root image definitions
were not rebuilt during this isolated verification.

## Remaining completion work

Governed account creation/deletion, original Admin password/lock recovery,
multi-file registry/group identity publication and reconciliation, protected
password-aging renewal, governed proposal retirement and damaged-authority
reconstruction remain open. Protected UTC deployment and authenticated
seed/history delivery, finite grants and resource/inference/effect admission,
broader workflows and retention are separate outstanding integration bundles.

No claim is made for an enforcing installed service, physical TPM behavior,
native interrupted installation/boot/recovery, distribution-internal memory
qualification, final-image execution or the requirements-defined hardware gate.
The [software completion register](../G2_SOFTWARE_STATUS.md) retains these limits.
