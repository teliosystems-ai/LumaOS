# Local TPM2 installer admission and VM fixture — 2026-09-28

Result: **selected source and emulator boundaries passed; G2 remains open**.
Base commit: `2ef734c`, plus the exact source hashes in this run's inventory.
Accepted evidence: `D:\LumaOS-builds\native-tests-20260928-tpm-admission-05`.

## Implemented continuation

- Installer admission now requires the local `/dev/tpmrm0` transport, a safe
  TPM clock, readable SHA-256 PCRs 7/11 and an unoccupied proposed NV index.
  The check runs before target-disk access. A second check immediately before
  partition mutation refuses an occupied index, changed PCRs, changed boot
  epoch or regressed time. Read errors are never treated as vacancy.
- `admin-install-check` exposes the read-only admission diagnostic. Neither it
  nor installation provisions, clears or undefines a TPM index. Admission is
  not attestation, reservation, hierarchy authorization or successful sealing.
- Installation persists a candidate account/UID and pending enrollment intent
  in encrypted mutable storage. It explicitly records inactive product Admin
  and warns before disk consent that sealed enrollment is not implemented.
  The separate Unix administrator remains distinct from product Admin.
- The VM harness now attaches a locked persistent software TPM, retains its
  state across stages, refuses unsafe state files/links and cleans temporary
  sockets on shutdown/startup errors. Large disks may remain on D: while
  `LUMA_VM_TPM_ROOT` selects a dedicated Linux volume for private TPM state.
  No physical TPM device is passed through and no TPM state is exported.

## Executed evaluation

Toolchain image:
`sha256:f7c1c6dd2a4352d755e73036629c0c0baa49993441cfd8489b5020c8a37a4bdd`.
Kernel: `6.18.33.2-microsoft-standard-WSL2`. No host disks, firmware or TPMs
were modified by these tests.

- Rust formatting, warning-denying compilation and 37 ordinary tests passed.
- Four emulator-only test functions were excluded from the ordinary run, then
  executed in six explicit invocations: admission free/occupied, journal and
  rollback, restart, missing index, replaced index. All passed.
- The TPM harness passed 21 labeled boundary cases, including binary
  authorization containing NUL/CR/LF and no fallback when a local TPM is absent.
- Fourteen Linux Python tests passed, including actual QEMU QMP verification
  of an emulator-backed `tpm-tis`, retained software-TPM state on restart,
  writer exclusion, unsafe-state refusal and failed-start resource cleanup.
  QEMU was paused: this is transport/fixture evidence, not a guest OS boot or
  enrolled Admin continuity test.
- Windows Python tooling ran 14 tests: 10 passed and 4 explicitly skipped
  because they require the isolated Linux tools container. Python image/test
  scripts also passed bytecode compilation. Windows counts were observed
  separately; `native-tests.txt` is the Linux run transcript.

The 1,000 snapshot-cycle test now runs in an isolated child process. Parallel
test processes can transiently inherit unrelated flock descriptors between
fork and exec, which caused a false immediate-release expectation in run 04.
The actual product lock/refusal behavior is unchanged. This remains snapshot
cleanup evidence, not model lifecycle testing.

## Failures retained and corrected

The run-02 random credential exposed the tools' text-based `file:` password
parser: NUL bytes truncate a string and CR/LF suffixes are trimmed. The native
adapter takes binary authorization. The fixture now supplies a private
`hex:`-encoded tools file separately from the raw native credential, and forces
NUL/CR/LF in its test bytes. No secret is put on a command line or in evidence.
See the [installed tools-version parser](https://github.com/tpm2-software/tpm2-tools/blob/5.6/lib/tpm2_auth_util.c).

Run 03 passed the TPM cases but exposed swtpm's explicit default 0640 state-file
mode when the strengthened private-state checks refused restart. The fixture
now requests `--tpmstate ...mode=0600`, verified against installed swtpm help
and the executed restart test. Run 04 then exposed the separate parallel test
descriptor issue above. Only run 05 passed the complete final wrapper and
produced its source inventory. Earlier logs remain diagnostic evidence, not
acceptance for the final source.

## Still open

No new image build or guest installation was executed. C: had approximately
9.4 GiB free during the build-capacity check, versus approximately 666 GiB on
D:. A fresh image build was not started with that limited system-drive
headroom. Free/relocate Linux/Docker build storage through an approved operation
before rebuilding; do not delete prior evidence, volumes or user data blindly.

The sequence-4 exported image remains unchanged. Its VM results cannot validate
the new admission checks, TPM shared libraries, staging startup service or
new harness. The new harness requires private Linux TPM storage even when
virtual disks/artifacts use NTFS/DrvFS.

Next software work: sealed enrollment and collision-safe interrupted-provisioning
handling; authenticated product Admin bootstrap; finite policy/effect service;
approved hierarchy custody; key rotation and TPM-loss recovery; trusted UTC;
then rebuilt-image admission/enrollment/update/fallback/recovery evaluation.
Disk-overlay tests currently create fresh TPM namespaces, so they cannot be
used as enrolled-Admin continuity evidence without additional integration.

The other G2 implementation work and physical acceptance remain listed in
[the software register](../G2_SOFTWARE_STATUS.md). The external-service installer
variant remains a future TODO, never an automatic fallback.

Machine-readable identities:
[native_tpm_admission_2026-09-28.json](native_tpm_admission_2026-09-28.json).
