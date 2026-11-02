# Content store check cost - 2026-11-02

The prepared phase run slice raised platform test time from 2924 to 4805 seconds
and its checkpoint recorded no cause. This note records the cause, a change to
two production checks and the local check of that change. It is development test
evidence, not G3 or GWIN0 image, TPM, PAM or installed qualification.

Like the mount read change, this one changes production code:
`PersistentDirectory::check` in `independent_checkpoint.rs`, and
`PageStore::check` and `PageStore::absent` in `paged.rs`. The third changed
source, `backend.rs`, is test-only.

## Cost

Scaled the way the [mount read note](NATIVE_CONTENT_MOUNT_READ_2026-11-01.md)
scales it, 4805 platform seconds is an estimated 5420 seconds of CI suite time
against the 7200-second deadline. One more slice of this size would pass it. This
was a local measurement, not a CI failure. CI has run neither the slice nor this
change.

## Cause

The one test
`actual_index_phase_run_refuses_substitutes_before_nv_then_one_dispatch_resolves_the_preparation`
took 929.45 seconds on the slice's snapshot `4213feb`: 2m22s of user time and
12m31s of system time. Reading `/proc/self/mountinfo` took about 492.5 of those
seconds, across 8,906,264 opens.

The mount read change left one table read in each `PersistentDirectory::check`.
Two things multiplied that read:

- `PageStore::check` ran a full directory check on its root and five children, so
  one store check read the table six times;
- `Backend::live` ran `check` and then two `absent` calls, each with its own store
  check, so one `live` ran three store checks and 18 table reads.

The object boundary then multiplies `live`. `Guard::check` reaches
`ObservedObjectWriter::check`, whose writer check reaches `Guard::check` again,
and `Checked` in `index_writer.rs` checks the writer on both sides of every
`admit` and `check`. The slice's run goes through this boundary, as the fixture's
preparation does. This recursion is deliberate and is unchanged.

## Change

`PersistentDirectory::check` is now two parts: `held`, the old descriptor checks,
then `installed`, the one mount table read. `check` calls both, as before.

`PageStore::check` now runs `held` on the root, then `held` on each child, then
`installed` once on the root. The loop already refused a child on another device
or mount id with `paged C namespace crossed installed mount`. `mount_evidence`
matches one table entry by those two values, so all six directories name one
entry, and the single read runs after all of them.

`absent` is now `all_absent` of one name. `all_absent` runs one store check, then
looks up each name in turn. `Backend::live` calls it with `selected.json` and
`pending.json` and no longer runs a store check of its own, so one `live` is one
store check and one table read.

Every descriptor still proves, on every check, what it proved before. No refusal
condition was dropped.

What does change:

- a mount table entry that goes bad and recovers between the old reads within one
  check is no longer seen. Every read is a moment-in-time read, so no version could
  rule out such a change between reads;
- a store fault that appears between the two name lookups in one `live` now waits
  for the next check. The old code left the same gap after its last check;
- a refusal can now come from a later point in the check, or with a different text
  when two faults coincide. It still refuses before the check returns.

A cached table held open and polled for changes was rejected. A descriptor on
`/proc/self/mountinfo` keeps the old namespace after `unshare` or `setns`, so it
could keep reporting a table the process no longer lives in. `Backend::open`
keeps its two `absent` calls, because it runs once per handle.

Two tests cover the new form:

- `absent_names_take_one_store_check_first_and_any_present_name_counts` is new. A
  present name counts in either position, an invalid name is refused, and a store
  fault is refused even with an empty name list;
- `direct_backend_poison_is_monotone_after_actual_nv_or_original_control_changes`
  now places each conflicting name in turn. The running backend refuses it, and
  removing the name does not revive the fenced handle.

The `crossed installed mount` refusal has no test, because reaching it needs a
second mount. That was already so before this change.

## Local check

Retained logs: `D:\LumaOS-builds\g3-test-cost-check-20261102-c`; its `SHA256SUMS`
(sha256 `06853d23a45be8b37e1370e1be67f94bf3c81b287dbdaae733a5ef827ab4e15c`)
verifies.

The check ran on an exact `git archive` of unreferenced snapshot
`57960452af5a90760eabbe50717a08dfc53e1d91` over `64e71fc`, whose tree is
`f4745844e1a58e98196aa74a1c2d34687f6487f7` and whose `rust` tree is
`5e582510deb10951de07fa03665b938ae7332373`. It ran offline in the pinned tools
image (`--network none`, 8 GiB, 6 CPUs, one build job, `RUSTFLAGS=-Dwarnings`)
with the committed lightly optimized dev/test profile, as `profile.txt` confirms.
Sources were stamped before the build, `build-tests.log` shows `luma-platform`
compiled, and no log has a `FORGED` line. Platform tests ran serially.

| Step | Result | Log sha256 |
| --- | --- | --- |
| rustfmt on a disposable copy | exit 0, empty diff | `c7dbba9974e15cba040701900d411e90bf41d3a9770306f4f04e65ed3e5af543` |
| warning-denied plain build | `Finished dev [optimized] target(s) in 55.54s`, exit 0 | `e007e763985b1a1a99b42eaa2afad5c53376ee8771d121fb3152236b0ab9c4fe` |
| warning-denied test build | `Finished test [optimized] target(s) in 21m 27s`, exit 0 | `6cadbcf5e1b6529b1585eb9d83930ff7ec9b68b9559fbe7103eaf0266fe5f01f` |
| index tests | 6 passed, 0 failed | `f9fc1220d86aa1bec72f6ae1c92cbf6ca4372a9416c5f39f258c608d5092f657` |
| `luma-content`, `luma-content-store` | 102, 356 and 3 doc-tests passed | `c589296a73fdac933b21740067224500ca2e5626886059182c1816188daf0729` |
| other `custody::v2_publication` tests | 107 passed, 0 failed | `406555ffff62878633bdf4935c5dbae6798caab1228a88e19d591a4f89cd9074` |
| remaining platform tests | 1472 passed, 0 failed, 42 ignored | `41f6f01ef6898a98e6529766c21e5bac70ea97c2fe4cb8b4a04561812b9ab754` |

The three platform filters are disjoint and cover each of the 1627 tests once
(6 + 107 + 1514). Both tests named above passed.

Two earlier checks are retained and are not the evidence for this snapshot:

| Directory | Snapshot | Result | `SHA256SUMS` sha256 |
| --- | --- | --- | --- |
| `g3-test-cost-check-20261102-a` | `3cd4b0b`, before the two tests | `failures=0` | `b943a1ab4678fffb3dc4fde9daa7d1a348d88c94b5806ba346d4e3e5aa5f4ef3` |
| `g3-test-cost-check-20261102-b` | `c8e3431`, with the two tests | `failures=1`: all tests passed, the rustfmt diff guard refused 23 diff lines in one new test | `371d8a9d60aac9e6a883ce32751d222cdab984cfe95f974c49c0f1a8496a2d87` |

## Measured effect

The phase run test under the same counter. Run `b` is before, on `4213feb`. Runs
`c`, `d` and `e` are one binary, on `3cd4b0b`. The final snapshot differs from
`3cd4b0b` only by the two tests and their formatting, so the profiles were not
repeated on it.

| Measure | b | c | d | e |
| --- | --- | --- | --- | --- |
| test seconds | 929.45 | 254.97 | 249.85 | 249.42 |
| mountinfo opens | 8,906,264 | 733,938 | 745,977 | 744,730 |
| `pages` directory opens | 1,466,210 | 624,619 | 637,203 | 634,748 |
| `statx` calls | 146,486,011 | 92,579,854 | 95,136,916 | 94,354,120 |
| `fstatfs` calls | 45,597,612 | 17,188,660 | 17,533,971 | 17,467,212 |
| `realpath` calls | 3,158,079 | 1,470,503 | 1,499,189 | 1,493,849 |
| `fsync` calls | 1217 | 1230 | 1211 | 1231 |
| `write` calls | 1094 | 1098 | 1087 | 1095 |

Before these runs I predicted that `fsync` and `write` would stay at exactly 1217
and 1094, as the migration test's 837 did in the mount read note. That prediction
was wrong: three runs of one binary differ from each other. The differences come
only from `slots::Directory::fill`, from `allocate_window`, `create_instance` and
`physical::allocate` under `publish`, and from `ObjectStore::leaf`'s `mkdir`.
Slot windows are allocated once per up to 16 page specifications, so these counts
follow the specification count of a run. Fixture content varying per run is the
likely cause, which was inferred and not traced. Run `b` lies inside the range of
the other three on both counts, so these counts show no change in the work done,
but they do not prove it as exact equality would.

Run `c`'s stack profile has 23,341 samples, none lost and 4 at the depth limit.
Inclusive seconds of 255.0:

| Frame | Seconds |
| --- | --- |
| `Guard::check` | 144.0 |
| `Backend::live` | 140.3 |
| `PageStore::check` | 119.5 |
| `index_run` | 112.9 |
| `ObservedObjectWriter::check` | 108.7 |
| `check_existing_writer_inner` | 94.7 |
| fixture `migrated` | 89.1 |
| `prepare_index_observed` | 79.3 |
| `all_absent` | 76.8 |
| `held` | 58.9 |
| `installed` | 55.7 |
| `publish` | 49.8 |
| `read_to_string` | 44.3 |
| `File::sync_all` | 33.9 |

Nothing further was changed. No single cause dominates, and what remains is the
boundary recursion, which is deliberate. Reading the mount table now takes 42.8 of
the test's 254.97 seconds, not counting its opens and closes.

| Directory | What it holds | `SHA256SUMS` sha256 |
| --- | --- | --- |
| `D:\LumaOS-builds\g3-test-cost-20261102-b` | before, counts and stacks | `2b7136ae85b341547fa4da36d2d58093bfcd6e8c9945fc26cd356b8ccd545b43` |
| `D:\LumaOS-builds\g3-test-cost-20261102-c` | after, counts and stacks | `d00fad906d17a609f0db483f95b707f0f23f54f9741a43102466bb82d58b2874` |
| `D:\LumaOS-builds\g3-test-cost-20261102-d` | after, repeat | `b9ccb4e63c2f4fa23a2313111948bc0d38b5cca70e6b1fc75e3dbae16893bf02` |
| `D:\LumaOS-builds\g3-test-cost-20261102-e` | after, repeat | `f42e48f4705013f0f133b09ca2c2427e6f9312a33d98091bed400fde005b1705` |

Attempt `a` in the same series is retained as failed. Its stack shim did not
compile (`unknown type name 'u32'`, exit 90), the test never started and it has no
`SHA256SUMS`. `profile.log` has sha256
`5c3f34ed7acb9c2e0716afe8b8fdb482f826e080499a1d29e8e4e32ebcaa309c`.

Filter times against the phase run check
(`D:\LumaOS-builds\g3-phase-run-check-20261101-b`, `SHA256SUMS` sha256
`5515e2942be1518fc5213b95a2299ddee5bded6bc20c09887bf749c60a381bbe`):

| Filter | Before, s | After, s | Change |
| --- | --- | --- | --- |
| index tests | 3214.56 | 895.23 | -72.2% |
| other `custody::v2_publication` tests | 749.92 | 402.20 | -46.4% |
| remaining platform tests | 840.85 | 887.68 | +5.6% |
| all platform tests | 4805.33 | 2185.11 | -54.5% |
| `luma-content-store`, control | 923.66 | 911.82 | -1.3% |

The remaining platform tests took 882.76, 904.02 and 887.68 seconds across the
three checks, 5.0% to 7.5% above the before figure, while the control did not
rise. Nothing measured here explains that. The first of the three predates the new
test that this filter gained, so that test is not the reason.

## CI budget

The 7200-second deadline and the 180-minute job limits stay unchanged. Scaled the
same way, the estimate falls from 5420 to about 2465 seconds. That is an estimate.
CI has not run the mount read change, the prepared phase slice or this change, and
the `tpm-boundaries` result on a pushed commit is the acceptance evidence.

The mount read note stays as dated history, but its closing paragraph no longer
holds. It said that further reduction would need a change notification or fewer
checks per item, and that the budget did not need either. The prepared phase slice
then raised the cost enough that the budget did need one, and this change took a
route that note did not list: fewer table reads per store check, keeping every
per-item check.
