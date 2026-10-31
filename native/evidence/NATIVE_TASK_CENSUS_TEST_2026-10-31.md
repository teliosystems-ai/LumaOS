# Task census test - 2026-10-31

The CI `tpm-boundaries` job for `bd8a655` failed one ignored credential
observer test. This note records the failure, its cause and the local check of
the test-only fix in `17b4293`. It is development test evidence, not G3 or
GWIN0 image, TPM, PAM or installed qualification.

## Failure

CI run 41224112063 (`bd8a655`), job 124604553049, `tpm-boundaries`:

```
thread 'credential_observer::tests::kernel_task_inventory_limit' panicked at luma-platform/src/credential_observer.rs:1020:38:
called `Result::unwrap()` on an `Err` value: Os { code: 2, kind: NotFound, message: "No such file or directory" }
test credential_observer::tests::kernel_task_inventory_limit ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1622 filtered out; finished in 0.00s
```

`native/tests/run_tpm_boundaries.sh` runs this test alone, so no other test
shared its process. The same run passed `storage-boundaries`. Its
`rust-boundaries` job passed the content suites and 1581 platform tests (42
ignored), then stopped at the native `artifact-read` step, which needs an
installed Admin anchor and TPM.

## Cause

The test spawns `MAX_THREADS` threads, checks that `kernel_check` refuses the
over-limit process, joins the threads and requires `kernel_check` to pass
again. Line 1020 is that final check.

`kernel_check` lists `/proc/PID/task`, opens each thread directory and reads
its status twice, and it refuses if the thread set changes during that census.
A join returns when the kernel clears the thread's id, before the task is
released and unlisted. A joined thread can therefore still be listed, and the
later open then fails with `NotFound`. That refusal is the intended fail-closed
behaviour; the race is in the test.

## Baseline

Retained logs: `D:\LumaOS-builds\g3-task-inventory-baseline-20261031-a`; its
`SHA256SUMS` (sha256
`f4c29b3cdbd85cb04708471b4c7038490f4202f9c92df4611d25ebd4df713628`) verifies.
This run was a diagnosis, not a gate check.

It ran the unfixed test alone, offline in the pinned tools image (4 GiB, 6
CPUs), from a binary whose `credential_observer.rs` equals `bd8a655`'s, as
`source.txt` confirms. The binary's sha256 is
`ac2e8ea4e925a6857198e98cf7728410c361a1d0efbb2b72111f96b942156daa`.

| Runs | Failures |
| --- | --- |
| 1000 serial | 0 |
| 6 x 1000 in parallel | 4 (2, 0, 1, 1, 0 and 0) |

All 4 failures panicked at `credential_observer.rs:1020:38`, the CI location.

## Fix

`17b4293` changes only the test. It records its own task set before spawning.
After the joins it waits for exactly that set before the final census, polling
every millisecond and failing the test after 10 seconds.

What did not change:

- `kernel_check`, its bounds and every production path;
- the assertion that the over-limit process is refused, and the final
  `kernel_check` after the threads are gone;
- the test's run in the TPM boundaries job, its `--ignored` attribute and its
  60-second limit;
- every other test, filter and CI job limit.

## Local check

Retained logs: `D:\LumaOS-builds\g3-slice8-check-20261031-a`; its
`SHA256SUMS` (sha256
`f93571cd53d3118937703d3bedc93461bb6dc367f4e4ab777cc35a242972143d`)
verifies.

The check ran on an exact `git archive` of `17b4293`, offline in the pinned
tools image (`--network none`, 8 GiB, 6 CPUs, one build job,
`RUSTFLAGS=-Dwarnings`). It used the committed lightly optimized dev/test
profile, as `profile.txt` confirms. The stress ran the fixed test alone from
the built binary, sha256
`12c53120d525e1bdecc158d7d37a33adbfc4cc4a137b8d02ef7a60ddb0106f45`.

| Step | Result | Log sha256 |
| --- | --- | --- |
| rustfmt on a disposable copy | exit 0, empty diff | `b35dab8e17e451052ebe6f2e9dc73c62bf84ee3f1a2d40dcfb9bac0305100b5d` |
| warning-denied test build | `Finished test [optimized] target(s) in 21m 09s`, exit 0 | `58a785a367f20852fa833eadd3d304dbf6e62bf7e410c247f1d68db29e470a1d` |
| fixed test, 1000 serial and 6 x 10000 in parallel | `total_runs=61000 total_failures=0` | `a07e455bd49d1240e2a50e584b1714ba614d5d42693594433e53c2b43e9d879c` |

The same check's full test results are in the
[index phase preparation checkpoint](../../docs/gates/g3/nf08_direct_index_preparation_2026-10-31.json).

At the baseline's parallel failure rate, 60000 parallel runs would have shown
about 40 failures. The two runs are not identical: the baseline had 4 GiB and
the stress 8 GiB, and CI timing can differ from this host. The CI
`tpm-boundaries` result for the pushed branch is the acceptance evidence for
this change.
