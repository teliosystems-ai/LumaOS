# Native build and acceptance resumption - 2026-09-30

G2 is incomplete. This checkpoint repairs build/test orchestration; it does not
complete product Admin, policy/effects, model lifecycle, skills or the desktop.

## Observed failures and source repairs

Sequence 10 assembled successfully, but the shell resumed after its long
Docker call at an invalid offset in the edited `build.sh`, reporting
`mage/assemble.py: No such file or directory`. The build record and artifacts
were complete; export had not started. The previous queue correctly did not
accept this as a successful export. No corrupt or partial export was promoted.

The driver now parses its complete main function before execution. A Linux
regression pauses stub assembly, replaces only a temporary copy of the driver,
resumes it and requires the original export/completion commands to execute.
Docker is stubbed in this test: it is orchestration evidence, not image boot.

A second repair captures the selected source trees **before** runtime/package
construction. Both Dockerfiles, runtime pins and assembly/export now consume
that capture rather than a checkout that can change between stages. Capture
requires new output, regular files, bounded size/count and stable inventories;
it rejects links, special files and observed concurrent modifications. Failed
captures are retained without a completion manifest. Exact hashes are recorded
in `build-inputs.json`; the assembler still emits its existing source lock.
This is neither a production signature nor byte-for-byte reproducibility.

The sequence-9 model launcher also supplied an unsupported `--timeout` option.
Its parser exited before creating a VM. The checkout now supports explicit
60..21,600-second stage deadlines (default 5,400), records the selected deadline
and tests invalid values. Retained older harnesses are run without this option;
they keep their original 5,400-second default and source identity.

## Executed scope

All 68 native Linux Python tests passed with warnings treated as errors, no
skips. The source capture also succeeded against the real checkout and a D:
destination, retaining 135 bounded source files. The shell syntax check passed.
The shell regression additionally checks that package construction and both
assembly/export mounts use the captured tree. No new full image has yet been
built with these driver changes.

Final evidence: `D:\LumaOS-builds\native-build-driver-tests-20260930-02`.
`test.log` SHA-256:
`4d1b926c9ef31f4af7b6c935d6274e942f3ea5abf4c15c607e12f314989b1a25`.
Captured `build-inputs.json` SHA-256:
`18f1db10257c5889e4eb8a38ffea5c886ed4537afcc2f2327dba869c6dc05cd9`.
The source fixture and earlier attempt are retained on D:.

The sequence-9 14-stage recovery regression passed and its public evidence is
exported; see [its checkpoint](TEST_IMAGE_SEQUENCE9_2026-09-30.md). Its model
suite has resumed on a fresh disposable virtual disk. Secure Boot and TPM are
virtual fixtures; only model acquisition permits guest networking.

## Retained sequence-10 image

Work: `D:\LumaOS-builds\work\20260930T073705Z-headless`.
Output: `D:\LumaOS-builds\native\20260930T073705Z-headless`.
Linux source volume: `luma-native-build-20260930T073705Z-headless`.

- Release: `luma-native-lab-20260927-headless-10`.
- Kernel: `6.8.0-142-generic`.
- Raw image SHA-256: `7470551731871555f04764353dde7aafb62700e76e0fb7f2dfd5f7a088cac096`.
- Compressed SHA-256: `4379b98ae8ee7d17aea0e424b65d4d3c4cb32a8578c5d4910a22cc12192dd939`.
- Source lock SHA-256: `e9c5c0ca66536ee13bed9fa5732734982b831e3ffae8277f5fea1545f05fe795`.

All ten entries in the retained `SHA256SUMS` passed before resuming export into
a new output directory. The exporter is the build's captured source, not the
subsequently edited checkout. **Verified export completed successfully**, with
all eleven public output files exported. Exported `build.json` SHA-256:
`e6602d896e001986e87f6962eb4751b17552c35140431565ff0b428286da8250`.
The original failure log is preserved separately from the resumed
export log; no earlier failure is rewritten as a successful build-driver run.

After sequence-9 model testing, the serialized pipeline
runs fresh sequence-10 regression (including atomic export and bounded IPC),
PAM/PCR and Qwen3-4B fixtures. These are queued tests, not acceptance passes.
Neither sequence includes the new GNOME desktop or these later source fixes.

C: had 4,435,492,864 free bytes at resumption, below the 8 GiB threshold for a
new image build. D: had 276,814,626,816. No threshold was bypassed, storage
reformatted, old evidence removed or private laboratory key exported.
