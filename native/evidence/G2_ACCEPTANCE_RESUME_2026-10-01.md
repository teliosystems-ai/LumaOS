# G2 acceptance repairs and resumption — 2026-10-01

Follow-up: the exact sequence-10 regression described as running below has
since **passed all 14 stages** and its public evidence has been exported.
The first queued desktop build failed in package bootstrap, before assembly;
the repair and fresh build are tracked in
[the subsequent checkpoint](G2_BUILD_SNAPSHOT_2026-10-01.md). The text below
retains the observations and pending state at the original checkpoint.

G2 is **not complete**. These are source-level fixes and an active image
evaluation, not complete Admin/policy, workflow, model lifecycle or desktop
acceptance. The formal two-board and production-custody gate remains open.

## Inference boundary

The retained sequence-9 console proves that the runtime became healthy and
refused an unauthenticated request, but its operator inference then timed out
while waiting for HTTP response headers. The old helper used a 180-second
socket timeout and requested up to 128 tokens. That does not by itself prove
whether the underlying cause was emulation speed, resource pressure or a
runtime defect. No successful retry is claimed here.

The new helper retains those defaults and adds explicit, finite numeric
options: 1–1,800 seconds and 1–128 output tokens. A process-owned deadline now
covers prompt input, headers, body, parsing and output, including a slow
trickling response. No ambient proxy, redirect, configurable endpoint, model
effect dispatch or automatic retry is added. Transport failures produce a
nonzero result without printing credentials or an apparent success object.

The short smoke request also explicitly disables reasoning through the
`chat_template_kwargs.enable_thinking=false` and `reasoning_effort=none`
controls supported by [the pinned llama.cpp commit](https://github.com/ggml-org/llama.cpp/blob/7ab4ee7baad2d920464cbacfad4f4b07cf111fd2/tools/server/README.md#post-v1chatcompletions).
This avoids relying only on a text suffix; it does not establish the cause of
the prior timeout or a successful model run.

The new `--bounded-model-chat` VM option selects 1,800 seconds/16 tokens for
TCG, records and validates the reported limits and elapsed time, and retains
the ordinary 180/128 budget for KVM. Historical images keep their original
command unless the new option is explicitly selected. Sequence 10 and earlier
do **not** contain the helper changes. A larger budget is not a performance
pass; a new image and successful actual inference remain required.

The model runner now retains a failed-stage record and bounded runtime
journal/cgroup diagnostics when the guest remains reachable. A failed run has
`failure.json`, not a passing `result.json`.

## Follow-up acceptance correction

The smaller-model reconfiguration, model recovery, and update-power-cut
runners previously synced then ended normal stages through host QEMU
termination. They now require guest-requested poweroff. Optional strict
teardown and Secure Boot observations are supported and recorded. Only the
intentional mid-write fault-injection stage kills QEMU. Historical results do
not inherit these stronger checks; these follow-up suites need rerunning.

## Executed source tests

- All **93 native Linux Python tests passed**, warnings treated as errors,
  no skips, in the dedicated D-backed tools container.
- Ordinary Rust tests: **55 passed, 7 ignored, 0 failed**. The seven cases
  require their separate PAM, TPM or mount-namespace fixtures; they were not
  executed by that command. They subsequently passed in their specialized
  fixtures below. The 1,000 snapshot cycles passed, which is not the
  required 1,000 real model lifecycle cycles.
- `cargo fmt --check` and `git diff --check` passed.
- Native Windows execution of the four changed oracle modules: **25 passed,
  5 Linux-only signal tests skipped**, no failures. This is not Linux runtime
  or VM acceptance. The signal tests passed in the Linux run above.

Final Python/format/source-capture evidence:
`D:\LumaOS-builds\g2-source-tests-20261001-04`.

- `test.log` SHA-256:
  `e3b7826c50e5a86784c7e449442d36fd9ce72603ac40497e3cefc0e5748b4e2b`.
- Captured `source/build-inputs.json` SHA-256:
  `0e0629910a93910d63d9549660049cbb764f2c5537cec8b574428e1fc05c82dd`.
- Rust transcript: `g2-source-tests-20261001-01/test.log`, SHA-256
  `e0b0a173a5485223f340a0819ded913b88ff8a04d69f650568850b343323ec17`.

## Image execution — pending, not passed

The exact sequence-10 headless image is running a fresh full 14-stage
Secure Boot/software-TPM/TCG regression with strict shutdown, atomic recovery
export and bounded broker IPC enabled. Image SHA-256:
`7470551731871555f04764353dde7aafb62700e76e0fb7f2dfd5f7a088cac096`.

- Public work/logs:
  `D:\LumaOS-builds\work\20260930T073705Z-headless\vm-regression-seq10-20261001-01`.
- Frozen harness and run log: `D:\LumaOS-builds\g2-seq10-20261001-01`.
- Isolated software TPM state: dedicated D-backed volume
  `luma-g2-tpm-20261001-01`; never publish that volume.

At this checkpoint the guest had passed live boot/confinement observations,
refused a tampered bundle and an inadmissible 4B selection without changing
the target prefix, completed manual installation, and powered off with a fresh
`LUMA_SHUTDOWN_STORAGE_CLEAN` marker. The installed stage then passed the real
UID-990 slow-header and slow-body IPC probes: denial took approximately 2.005
and 2.008 seconds, respectively, and a fresh status request succeeded after
each. That stage also emitted verified clean teardown. The failed-trial and
recovery regression remains in progress. The install console also recorded a TPM operation timeout; its
cause and impact are not yet qualified. This is not a warning-free run.

The specialized real-PAM and software-TPM suite **passed** in a
512 MiB/one-CPU-limited, no-network container with no host TPM, disk devices or
account access. It exercised the six corresponding ignored Rust functions,
including authenticated/incorrect-secret refusals, journal rollback fencing,
signed-PCR credential continuity and real PAM account refusal cases. These
are primitives, not enrollment or production Admin authorization. Its 49
boundary labels are not 49 distinct Rust test functions. Evidence:
`D:\LumaOS-builds\g2-tpm-pam-20261001-01\result`.

- `result.json` SHA-256:
  `f9300d101172130f49203470e1b4b1777a1354e2824de3c179825208eb80bae2`.
- `source-sha256.txt` SHA-256:
  `e2de3c8b22315245184698db0786286f157ff01703700060f499952392c6692a`.

The remaining specialized Rust recovery-export case **passed** against a real
1 MiB tmpfs in an isolated container/private mount namespace. It retained the
partial archive without publishing a final file after disk exhaustion. The
ordinary 55 Rust tests and all 93 Python tests also passed in that run, including
the latest portable test guards. This remains source/runtime evidence, not the
pending guest recovery-export evaluation. Evidence:
`D:\LumaOS-builds\g2-export-tests-20261001-01`.

- `run.log` SHA-256:
  `20df8893cbb75ac03b2508d0a7ea94f1961088af608e70c4db81dba9fb3cf039`.
- `result/source-sha256.txt` SHA-256:
  `98c3ee1042a109c251cfaa61cf8d91a10adf9931fe783f29a67f7544699373f4`.

A candidate **desktop sequence 11** build is queued behind successful
completion of that exact regression. It will use the D-backed build profile,
the pinned runtime archive and a fresh source capture. Its log is
`D:\LumaOS-builds\g2-desktop-build-20261001-01\build.log`. A queued build is not
an exported or accepted image, and this candidate is not an all-components
final G2 release.

WSL currently exposes approximately 8 GiB RAM. The Windows host has about
16 GiB total and had less than 1 GiB free during evaluation. Large builds and
VMs are therefore serialized. No WSL memory configuration, unrelated service,
physical disk, physical firmware or production signing key was changed.
