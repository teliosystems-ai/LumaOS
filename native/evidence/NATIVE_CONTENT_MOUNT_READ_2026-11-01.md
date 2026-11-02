# Content mount read cost - 2026-11-01

The CI `tpm-boundaries` job for `64e71fc` stopped at its 7200-second suite
deadline. This note records the cause, a change to a production check and the
local check of that change. It is development test evidence, not G3 or GWIN0
image, TPM, PAM or installed qualification.

Unlike the recent test-only changes, this one changes production code:
`PersistentDirectory::check` in `independent_checkpoint.rs`.

## Failure

CI run 41275178599 (`64e71fc`):

| Job | Result |
| --- | --- |
| `storage-boundaries` | passed |
| `rust-boundaries` | tests passed, then stopped at the known `artifact-read` blocker |
| `tpm-boundaries` | failed both attempts at the 7200-second deadline, runners 1000001904 and 1000001907 |

The TPM suite stopped at about test 501 of 1624. Up to there, test order matches
the passing run on `acdc0d5`.

## Cause

This was not a regression from `bd0d65b`. That commit extended two existing
tests, and the rust and storage suites grew by about 175 seconds. The suite was
already near the limit on slower runners, and the TPM pass on `acdc0d5` had a
fast one.

Serial suite seconds on CI:

| Commit | rust | storage | tpm |
| --- | --- | --- | --- |
| `efb045a` | 3238 | 3244 | |
| `676c2d5` | 4616 | 5117 | |
| `6890988` | 4347 | 5130 | |
| `bd8a655` | 5997 | 5506 | |
| `acdc0d5` | 7340 | 6729 | 2941 |
| `64e71fc` | 7516 | 6903 | over 7200 at test 501 |

All compared runs used runner image 20261025.353.1. No log records which CPU a
job received, so "slower runner" is an inference from these times. On `64e71fc`
the rust job took 153 minutes and the storage job 140 minutes of their 180.
Raising the 7200 seconds alone would therefore have bought only a few more
slices.

One migration test was profiled on `64e71fc`. Its 386 seconds were 317 seconds
of kernel time and 47 of user time.

| Directory | What it holds | `SHA256SUMS` sha256 |
| --- | --- | --- |
| `D:\LumaOS-builds\g3-migration-profile-20261101-a` | wall, user, system and off-CPU time | `d7a001e49b4d4615bcadd42353f33ce23999ca6f95304dbcc3e184239a342dd0` |
| `D:\LumaOS-builds\g3-read-count-20261101-a` | call counts from a preload shim | `3a1f4a2ac0c63789db11007c3ed710fb5f2fa9347db9a353eea62e802b6f92ab` |
| `D:\LumaOS-builds\g3-mountinfo-bench-20261101-a` | cost of one mount table parse | `4b68b30d02d3636fb449a8aabbd21cbfcb9d2f1d013c73673db664b1e631ca77` |

Under the counter the test opened `/proc/self/mountinfo` 4,709,800 times, which
took about 285 of its 395 seconds. A parse costs about 58 microseconds, and the
number of reads per parse barely changes that, so the number of parses is what
matters.

`PersistentDirectory::check` parsed the table once for each of four descriptors:
the held directory, its current reopen, the held parent and its current reopen.
The directory walks capture every directory, and `capture` calls `check`.

The CI logs behind the table above and the TPM transcripts are retained in
`D:\LumaOS-builds\g3-ci-time-budget-20261101-a`; its `SHA256SUMS` (sha256
`b36967fc9a96f8059d75bec077644f3ad87d09306d635131358e163556f06db2`)
verifies. `joblogs/64e71fc-tpm-boundaries.log` is attempt 2. Attempt 1's job log
could not be fetched, but its transcript is in `tpm-artifact-13074702418`.

## Change

`check` now parses the mount table once, after all four descriptors pass.

Each descriptor still proves, on every check, its directory type, owner, mode,
device and inode identity, kernel mount id and ext4 filesystem. Those checks
give all four the same device and mount id, so they name one kernel mount entry.
`capture` also refuses a file and parent on different devices. The single parse
runs after the loop, so it is at least as late as the old fourth parse.

`installed_mount` also lost its repeated `ext4` and mount id checks, because the
loop now makes them for every descriptor. The text `persistent content mount
identity changed` therefore no longer exists; the loop's refusal text covers
that case.

What does change:

- a mount table entry that goes bad and recovers between the old parses within
  one `check` is no longer seen. Every parse is a moment-in-time read, so no
  version could rule out such a change between reads;
- a refusal can now come from a later point in `check`. It still refuses before
  `check` returns.

The parse itself moved unchanged into a pure function, `mount_evidence`. A grep
found none of its refusal texts in any test, so the new test
`content_authority_mount_evidence_is_one_exact_writable_ext4_entry` now covers
the accepted forms and 13 refused ones: an empty table, no entry, a duplicate
entry, wrong device, wrong filesystem, read-only, no `rw` option, `rw,ro`,
three malformed entries and two over-limit tables.

## Local check

Retained logs: `D:\LumaOS-builds\g3-mount-read-check-20261101-a`; its
`SHA256SUMS` (sha256
`b5aeb8e53388b3f40fbda859cefdf25e5195d6e41f091fa995d5e676d98f0df0`)
verifies.

The check ran on an exact `git archive` of unreferenced snapshot
`4a08d79997fb44366bb5f62e3a79a267bab5df06` over `64e71fc`, whose `rust` tree is
`0ca16eec3b9faf704532fe3759be4d1d715073c4`. It ran offline in the pinned tools
image (`--network none`, 8 GiB, 6 CPUs, one build job, `RUSTFLAGS=-Dwarnings`)
with the committed lightly optimized dev/test profile, as `profile.txt`
confirms. Platform tests ran serially.

| Step | Result | Log sha256 |
| --- | --- | --- |
| rustfmt on a disposable copy | exit 0, empty diff | `469df7a8aea106e495a2b01bfd0a8896d7382ac6c1f38f509330daf03f135c7a` |
| warning-denied test build | `Finished test [optimized] target(s) in 21m 30s`, exit 0 | `b4f9ecd0db3b44d92825dfeaf9361e13f1ebcba835fbd631b2c408fe3ddd8a05` |
| measured migration test, plain | 1 passed, 134.99 s | `6f523f6c3d2081fafe0e7ac97f6f5cde9a66ae8dc08cccdc0d1f58c6ed67fd4f` |
| measured migration test, counted | 1 passed, 141.40 s | `ebf1d9901ce7e4174754363f72cade09e99e11ce992fca9ffeee9ab7061aa991` |
| index tests | 5 passed, 0 failed | `26f9929dc0d6f2d2bf0c3ac31b008eb36d3a6e427034f5b26dfa5215cf2535fc` |
| `luma-content`, `luma-content-store` | 102, 356 and 3 doc-tests passed | `a2fd7f8aaceec7839877cbcdce379e9b70b7e7f1af2d5bd8a2df49248c838954` |
| other `custody::v2_publication` tests | 107 passed, 0 failed | `ed18a50266565456daa267ba8146bd7a96f5a1abc347fc30c1c654d7b9a4fc8f` |
| remaining platform tests | 1471 passed, 0 failed, 42 ignored | `b1b7f9c6d12c6910577fc27b7b11bb1d87960e721135f5783ca88a41ba0c5538` |

The three platform filters are disjoint and cover each of the 1625 tests once
(5 + 107 + 1513). The new test passed. `kernel_task_inventory_limit` is one of
the 42 ignored tests and was not stressed here.

## Measured effect

The same migration test under the same counter, before (`g3-read-count`) and
after (`counts.14`):

| Measure | Before | After |
| --- | --- | --- |
| test seconds | 395.23 | 141.40 |
| mountinfo opens | 4,709,800 | 1,177,450 |
| mountinfo seconds, open to close | 284.6 | 73.5 |
| `statx` calls | 27,276,254 | 19,034,104 |
| `fstatfs` calls | 9,508,073 | 5,975,723 |
| `paged-v3` directory opens | 1,167,959 | 1,167,959 |
| `fsync` calls | 837 | 837 |
| `realpath` calls | 414,735 | 414,735 |

Opens fell to exactly one quarter. The unchanged directory, `fsync` and
`realpath` counts show the test did the same work.

Filter times against the `bd0d65b` check, whose Rust sources equal `64e71fc`'s:

| Filter | Before, s | After, s | Change |
| --- | --- | --- | --- |
| index tests | 3946.34 | 1326.78 | -66.4% |
| other `custody::v2_publication` tests | 1915.77 | 752.90 | -60.7% |
| remaining platform tests | 801.70 | 844.51 | +5.3% |
| all platform tests | 6663.81 | 2924.19 | -56.1% |
| `luma-content-store`, control | 863.99 | 908.61 | +5.2% |

The control does not use this check, so about 5% is ordinary variation between
runs on this host. The remaining platform tests moved by the same amount, so
this check was no visible part of their time.

## CI budget

The 7200-second deadline and the 180-minute job limits stay unchanged. If CI
scales as these filters did, the 7516-second rust suite would take about 3300
seconds. That is an estimate. CI has not run this change, and the
`tpm-boundaries` result on a pushed commit is the acceptance evidence.

The mount table parse is still the largest single cost: 73.5 of the test's
141.40 seconds. Reducing it further would need a change notification on an open
mount table or fewer checks per item. Both change the production check more, and
this budget does not need them now.
