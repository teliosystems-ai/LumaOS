# Credential observer real kernel handle test - 2026-10-31

The CI `rust-boundaries` job for `6890988` failed one credential observer
unit test. This note records the failure, its cause and the local check of the
test-only fix in `11a7283`. It is development test evidence, not G3 or GWIN0
image, TPM, PAM or installed qualification.

## Failure

CI run 41205654555 (`6890988`), job 124550088922, `rust-boundaries`:

```
test credential_observer::tests::real_kernel_handle_and_received_cloexec_descriptor_are_observed ... FAILED
thread 'credential_observer::tests::real_kernel_handle_and_received_cloexec_descriptor_are_observed' panicked at luma-platform/src/credential_observer.rs:807:10:
called `Result::unwrap()` on an `Err` value: Os { code: 2, kind: NotFound, message: "No such file or directory" }
test result: FAILED. 1579 passed; 1 failed; 42 ignored; 0 measured; 0 filtered out; finished in 4347.02s
```

The job exited with code 101, so it did not reach the native `artifact-read`
step. The same run passed `storage-boundaries` and `tpm-boundaries`. The same
test passed in the four earlier `rust-boundaries` jobs (124542020027,
124493372668, 124471787095 and 124398114476), each of which then stopped at
`artifact-read`.

## Cause

The test pinned the running libtest process with `pidfd_open` and ran
`kernel_check` on the received handle. `kernel_check` lists
`/proc/PID/task`, opens each thread directory and reads its status twice, and
it refuses if the thread set changes during that census. libtest starts and
retires a thread per test even with `--test-threads=1`. A test thread that
left `/proc/PID/task` between the listing and its open made the census fail
with `NotFound`. That refusal is the intended fail-closed behaviour; the
admin peer fixture already retries its own binding for the same reason (29
October).

## Fix

`11a7283` changes only the test. It now observes a single-threaded
`/bin/sleep` child through `pidfd_open`, so the observed thread set is stable
by construction. It still sends the handle over `SCM_RIGHTS`, requires the
received descriptor to be close-on-exec, observes the exact current
credentials and refuses other ids. It now also refuses the handle once the
child is reaped.

What did not change:

- `kernel_check` and every production path;
- the ignored container tests, which still observe the test process;
- every other test, filter and CI job limit.

## Local check

Retained logs: `D:\LumaOS-builds\g3-credential-observer-check-20261031-a`;
its `SHA256SUMS` (sha256
`4b62a033d1fbd06e7f05a2b9aabd4d8014799dd85ec6c04cba8724ca79c12350`)
verifies.

The check ran on an exact `git archive` of `11a7283`, offline in the pinned
tools image (`--network none`, 8 GiB, 6 CPUs, one build job,
`RUSTFLAGS=-Dwarnings`). It used the committed lightly optimized dev/test
profile, as `profile.txt` confirms.

| Step | Result | Log sha256 |
| --- | --- | --- |
| rustfmt on a disposable copy | exit 0, empty diff | `2b8b93d39bc818f0d9749a206e563fdea8e6e6eba5804f1df40cde0fcdeb577a` |
| warning-denied `luma-platform` test build | `Finished test [optimized] target(s) in 17m 47s`, exit 0 | `2c22ee04b37ac8b97518bed4fe9f8942ddd2cc86289fce501cf7407bd222759a` |
| `credential_observer::` serially | 8 passed, 0 failed, 4 ignored by their own attributes | `dd7f8b70bc77ec0ce74f6659dd99f2fc1fc59d0da0f54c115390a4941d007e0c` |
| same module 200 times with 8 test threads | `iterations=200 failures=0 ok_lines=1600`; the changed test passed in every iteration | `33d284070fcbeddf526b3dd2cd5ed297744c65c28ec77b2dd9fcc2b8b48ffe87` |

The stress loop starts and retires test threads in parallel with the changed
test. It does not resolve the parallel interference of the full platform
suite, which CI still runs serially. The CI `rust-boundaries` result for the
pushed branch is the acceptance evidence for this change; its native
`artifact-read` step needs an installed Admin anchor and TPM and is not
passed.
