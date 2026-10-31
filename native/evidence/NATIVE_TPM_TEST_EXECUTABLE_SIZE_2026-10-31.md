# TPM suite test executable size - 2026-10-31

After commit `efb045a` set `opt-level = 1` for dev and test builds, the CI
`tpm-boundaries` job failed. This note records the cause and the measurement
behind the dev/test-only fix. It is development build evidence, not G3 or
GWIN0 image, TPM or installed qualification.

## Failure

CI run 41186151549 (`efb045a`), job 124493372614, `tpm-boundaries`:

```
thread 'admin_service::tests::pam_catalog_connection' panicked at luma-platform/src/admin_service.rs:1504:73:
called `Result::unwrap()` on an `Err` value: "unsafe disposable public test executable source"
```

The test-only `PublicTestExecutable::stage` in `admin_service.rs` refuses to
stage the running luma-platform test executable as a disposable public test
executable if it is over 512 MiB, among other checks. The same job passed
for `0f5db4c` and `41292fc`, which were built without optimization.

## Measurement

Retained logs: `D:\LumaOS-builds\g3-tpm-exe-size-20261031-a`; its
`SHA256SUMS` verifies.

Both builds ran on an exact `git archive` of `676c2d5`, the same way
`native/tests/run_tpm_boundaries.sh` builds: workspace
`cargo test --offline --locked --no-run`, `RUSTFLAGS=-Dwarnings`. They ran
offline in the pinned tools image, each into its own new target directory.
Nothing was executed.

| Build | Debug info | `luma_platform-*` test executable bytes | Under the 536870912-byte cap |
| --- | --- | --- | --- |
| `[profile.dev]` as committed in `676c2d5` | full (default) | 599169880 | no |
| same, with only `CARGO_PROFILE_DEV_DEBUG`/`CARGO_PROFILE_TEST_DEBUG=line-tables-only` | line tables | 222472792 | yes |

Code sections are nearly the same in both builds: `.text` is 50791053 and
50790413 bytes. The difference is almost all DWARF type and location data:

| Section | Full | Line tables |
| --- | --- | --- |
| `.debug_info` | 147548208 | 53012497 |
| `.debug_loc` | 107918813 | 4591464 |
| `.debug_str` | 83376402 | 41269040 |
| `.debug_pubnames` | 63527872 | 1912399 |
| `.debug_pubtypes` | 56501040 | 1733795 |
| `.debug_line` | 29507951 | 27196339 |

## Fix

`[profile.dev]` in `rust/Cargo.toml` now sets `debug = "line-tables-only"`.
Panics and backtraces still report file and line.

What did not change:

- the 512 MiB staging cap and every other staging check;
- `opt-level = 1`, debug assertions, overflow checks and the sha2 override;
- every test, filter and job limit;
- the release profile that builds the image executables.

Local check scripts that already set `CARGO_PROFILE_*_DEBUG=0` keep their
explicit choice. The CI `tpm-boundaries` result for the fixing commit is the
acceptance evidence for this change.
