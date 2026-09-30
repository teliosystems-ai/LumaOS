# Late-shutdown integration checkpoint - 2026-09-30

**Source and initrd checks passed; rebuilt-image evaluation is pending.**
The sequence-8 installed Admin/PCR fixture passed its intended checks but
reported `/var` unmount and remaining device-mapper warnings at power-off.
Those warnings are retained in its logs and are not treated as clean-shutdown
acceptance. See [the sequence-8 record](TEST_IMAGE_SEQUENCE8_2026-09-30.md).

## Implemented repair

- The custom initrd data-mount hook explicitly requests dracut shutdown
  restoration after successful live/installed data initialization.
- The builder enables the packaged `dracut-shutdown.service` and supplies its
  conventional kernel-version initrd alias pointing to `boot/luma-initrd` inside
  the immutable root. Existing conflicting files/links are refused, not replaced.
- Required restore inputs and late teardown executables/hooks are checked
  before the root filesystem is assembled and signed.
- After dracut's unmount/device-mapper hooks, a separate observation hook emits
  `LUMA_SHUTDOWN_STORAGE_CLEAN` only when the old-root mounts and all DM devices
  are absent. Missing/empty mount inventories and remaining/dangling DM entries
  fail the check. It does not remove devices or grant authority itself.
- `admin_vm_test.py --require-clean-shutdown` requires restore preparation and
  that positive teardown marker for every guest stage. The result records
  whether that stricter mode was used. Earlier evidence is not retroactively
  upgraded by this new option.

## Executed source-level evidence

`D:\LumaOS-builds\native-tests-20260930-shutdown-01` passed 42 ordinary Rust
tests, 20 explicit TPM and 6 PAM invocations, and 32 Linux Python tests. Six
isolated functions are ignored in the ordinary Rust suite and invoked by the
runner; counts are not all distinct functions. The source inventory includes
the new hooks, verifier and regression tests.

`D:\LumaOS-builds\initrd-shutdown-20260930-01.json` records a passing kernel-less
initrd build against a real retained root mounted read-only, with candidate
modules overlaid read-only. It verifies the existing TPM rule and the new
late-shutdown inventory. This is not an OS shutdown test.

## Rebuilt-image execution

Update: sequence 9 completed export. Its first manual-install test timed out;
a fresh TCG retry with a bounded longer allowance is running. No strict
shutdown pass is established yet. See [the current image checkpoint](TEST_IMAGE_SEQUENCE9_2026-09-30.md).
The original queued-run description below is retained as history.

Sequence 9: `20260929T221048Z-headless`.
Work: `D:\LumaOS-builds\work\20260929T221048Z-headless`.
Expected export: `D:\LumaOS-builds\native\20260929T221048Z-headless`.

The environment-local pipeline waits for this exact successful verified export,
then runs two suites sequentially on separate fresh virtual disks and software-
TPM namespaces: the four-stage Admin/PCR fixture with strict shutdown checks,
then the existing 14-stage install/trial-fallback/recovery/verity-corruption
regression. The pipeline was subsequently extended with the five-stage real
Qwen3-4B acquisition/inference/offline-reboot/recovery-disable fixture, using
Secure Boot, TCG and strict shutdown. Only that suite's installation guest has
outbound NAT for the pinned publisher download; it opens no forwarded ports.
Any failure stops the pipeline. Passing evidence is exported only
after the corresponding suite completes. No physical disk/TPM, production key,
Docker cleanup or unrelated workload is involved.

The full G2 software inventory and physical/production acceptance requirements
remain open. Neither source tests nor the queued suites imply complete Admin
enrollment, model lifecycle, workflow, desktop or generated-code isolation.

The shared VM power-off assertion additionally excludes pre-existing or echoed
markers. Four fixture-only unit tests cover fresh positive markers, missing/
partial/echoed/old markers, nonzero QEMU exit and legacy power-off behavior.
The model runner now accepts explicit Secure Boot/TCG/strict shutdown options
and powers off each stage. A subsequent WSL Python run passed 28 tests with
8 isolated-container tests skipped (36 discovered); it is not an image or
model-runtime result. The same 36 Python tests subsequently all passed with
no skips in `luma-native-tools:20260929-auth` (network disabled, repository
read-only, no host TPM). Four further inference-oracle tests brought this to
40 passing Linux Python tests: missing/duplicate results, wrong model, empty
content, invalid token counts and effect/certification claims are rejected.
The 4B offline-reboot stage now requests and records a new actual completion,
not merely a healthy listener. The smaller-profile fixture also requires each
stage's new response instead of retaining a previous result. These source
changes do not strengthen historical image results retroactively. The earlier
full Rust/TPM/PAM container results above remain separate.
