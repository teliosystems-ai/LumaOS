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

An earlier version of this note said the `crossed installed mount` refusal has no
test because reaching it needs a second mount. The refusal had no test, but the
reason was wrong. A second mount alone reaches earlier refusals: a bind in place is
refused when the child is captured, and one added later is refused by the held pin
of what it covers. The crossing refusal needs the root's mount to change between
the root's `held` and a child's `held` within one check.

`actual_binds_and_a_mount_moved_during_one_check_are_refused` in
`paged/mount_tests.rs` now covers all three. A second thread keeps moving one
mount over the root while the check repeats. The test is ignored by default and
needs a disposable container with a private mount namespace. It passed on
unreferenced snapshot `fcaa032`, refused on check 79, in
`D:\LumaOS-builds\g3-validate-b\mount.log` (`SHA256SUMS` sha256
`5c4eb7efe21b4cd4efe1e65a8a4da67fa70a7e431a8f57d9470586d698db0515`). The check
number depends on timing. `run_storage_boundaries.sh` now runs this test, and CI
has not run that step yet. The G2 fixture sweep gained the lane `custody-mounts`,
which is unit-tested and has not been executed by the sweep itself.

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
was wrong: three runs of one binary differ from each other, and no exact figure can
be predicted for this test. An earlier version of this note called fixture content
varying per run the likely cause, which was inferred. A later trace found the real
cause.

Fixing the random seed does not stop the variation. With `getrandom` seeded by an
`LD_PRELOAD` shim, two runs of one seed gave 1227 and 1240 `fsync` calls. The test
read no other randomness: `/dev/urandom` reads were 0, `getrandom` returned exactly
32 bytes per call, and neither `content_custody` nor `luma-content-store` uses a
`HashMap` or `HashSet`. Three runs of one seed, with every call in sequence, show
where the counts move:

| Count | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `fsync` | 1222 | 1223 | 1210 |
| `write` | 1095 | 1094 | 1090 |
| slots created, each one `getrandom` | 132 | 132 | 130 |
| of those, in `reserve_index_start_direct` | 12 | 11 | 8 |
| of those, in `migrate_owner_direct` | 73 | 72 | 72 |
| of those, in the other four callers | 47 | 49 | 50 |
| `fsync` sealing location tree nodes | 90 | 90 | 84 |
| `write` sealing location tree nodes | 55 | 55 | 52 |
| object shard `mkdir` `fsync` | 37 | 38 | 37 |

The chain runs from the records to the counts:

- slot references and other records hold values of the run: inode, ctime, device,
  mount id and instance id. Their bytes, and so their content hashes, differ even
  with a fixed random seed;
- object keys are those hashes, so they land differently in the location tree,
  whose fanout is 16. `direct/worker/storage.rs` sizes each publication's exact slot
  set from that tree's new nodes, so a batch that touches more leaves needs more
  slots;
- each slot costs one `getrandom`, six `fsync` calls and about two `write` calls, and
  each sealed node adds its own;
- the same hashes decide which `objects/xx/yy` shard directories already exist, and
  a new one costs `mkdir` `fsync` calls.

This follows from a hash-keyed tree over records that name their own inodes. It is
not a fault, and no production code changes for it. Across every run measured,
`fsync` stayed within 1207 to 1240 and `write` within 1087 to 1098. Run `b` lies
inside both ranges, so these counts show no change in the work done, but they do
not prove it as exact equality would.

| Directory | What it holds | `SHA256SUMS` sha256 |
| --- | --- | --- |
| `D:\LumaOS-builds\g3-fsync-seeded-b` | seeded and unseeded counts | `44d86b830ada6a77bb24317fa997365f4ad97181bac70e603ebb65c43479dfb1` |
| `D:\LumaOS-builds\g3-fsync-sequence-a` | three seeded call sequences | `bf61a4f1e5981dab76fbc656e77d03a69f0fa1521a8d15bff19f825223667ced` |
| `D:\LumaOS-builds\g3-fsync-sequence-a-resolved-b` | the same with resolved stacks | `e39d06ce08654acb62cf3c292c5d82c159c6fd76ff3c0b644aca79360ceb12bb` |

All three ran one test binary, sha256
`7d825cf9f1575416b7f7196dc80b93d0f0d4e6d4b3b0cef3af871e102a4e7cd8`. Attempt
`g3-fsync-seeded-a` is retained as failed: its shim did not compile
(`stringop-truncation`) and no count came from it. The first resolver filtered
frames after tidying their names and dropped the custody frames, so only the
filtered-first output above is used.

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
rise. The first of the three predates the new test that this filter gained, so
that test is not the reason.

An A/B run then measured this filter on both commits in one session. Old is
`4213feb`, the commit behind the before figure. New is `8aedc0b`. The order was
old, new, new, old, so that steady drift falls on both sides. Evidence is
`D:\LumaOS-builds\g3-rise-ab-b` (`SHA256SUMS` sha256
`d0fe04d2a8d51d0513bc34133933911c38bc29c2cf0f46e73fa119325fb437be`).

| Run | Commit | `finished in`, s |
| --- | --- | --- |
| 1 | old | 794.63 |
| 2 | new | 851.09 |
| 3 | new | 883.72 |
| 4 | old | 883.52 |

The old commit moved 88.89 seconds, 11.2%, with no code change, which is more than
the whole rise. Both new runs sit inside the old range. The rise is therefore not
attributed to the code. The means differ by 28.33 seconds, 3.4%, and with two runs
a side and this spread, that does not show the code costs nothing either.

These totals are not comparable with the table above. All four runs used a test
binary copied out of the target, so 40 tests failed for lack of the helpers and of
a path uid 989 can reach. The same 40 failed on all four runs. In the three checks
those tests carried about 5% of this filter's time and about 2.3 seconds of the
mean rise.

The drift itself is not traced. Between run 1 and run 4 the largest rises are in
account creation, the request journal and admin governance tests, while the slowest
test, `staging::tests::thousand_snapshot_cycles_leave_no_payloads`, fell from 170 to
165 seconds. Inside WSL, `MemAvailable` stayed between 11310252 and 11329852 kB, the
store had 60.95 GiB free and the five other containers each stayed under 0.2% CPU,
so neither memory nor store space accounts for it. Nothing was measured on the
Windows side.

## CI budget

The 7200-second deadline and the 180-minute job limits stay unchanged. Scaled the
same way, the estimate fell from 5420 to about 2465 seconds.

CI has since run this change. On `d38aa7f`, run 41398711108, `tpm-boundaries`
passed. Its full platform suite took 1475.90 seconds, 1585 passed and 42 ignored,
in `results/transcript.txt` of the `native-tpm-boundaries` artifact (sha256
`965014837d8057045197b18e58d98f19b8981596d7c3d5e2fbd2db4aa2d05274`, the value its
`result.json` records). That is the acceptance evidence, and it leaves 5724 seconds
of the deadline.

The estimate was 989 seconds high. CI ran the suite at 0.675 of the local time,
where the scale used until now was 1.128. The two ratios differ by a factor of 1.67
and the reason is not traced, so a ratio from one commit does not predict another.
Later slices should state the local figure, the scaled figure on both ratios and
the next measured CI figure.

The direct Advance slice is the first to do so. On snapshot `2c635e0` the platform
suite took 2523.34 seconds locally, up from 2185.11, and its one new test took 314 of
them. That scales to about 1704 seconds on the 0.675 ratio and 2846 on the 1.128
one, leaving 5496 or 4354 seconds of the deadline. CI has not run that snapshot, so
there is no measured figure yet.

The direct Publish slice follows it. On snapshot `b9d06bc` the platform suite took
5347.88 seconds locally, and its one new chain test took 2749 of them (3116 in an
earlier aid run of the same commit). That scales to about 3612 seconds on the 0.675
ratio and 6032 on the 1.128 one, leaving 3588 or 1168 seconds of the deadline. The
slice added about 2825 local seconds, more than the smaller margin, so on the older
ratio another slice of this size would miss the deadline unless the chain test's
cost comes down first. CI has not run this snapshot either.

The mount read note stays as dated history, but its closing paragraph no longer
holds. It said that further reduction would need a change notification or fewer
checks per item, and that the budget did not need either. The prepared phase slice
then raised the cost enough that the budget did need one, and this change took a
route that note did not list: fewer table reads per store check, keeping every
per-item check.
