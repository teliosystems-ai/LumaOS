# Model profile acceptance and current image work — 2026-10-01

G2 remains **incomplete**. Commit `8adbbc2` saved all preceding desktop
acceptance changes before this work began. No push was performed.

## Fresh-install profile coverage

The fresh-disk model runner now accepts exactly two existing image-catalog
profiles. The default remains `qwen3-4b-q4-k-m`, with a 6 GiB VM and
4,831,838,208-byte model cgroup ceiling. An explicit
`--model qwen3-1-7b-q4-k-m` selects the smaller fresh-install fixture, with a
4 GiB VM and 2,684,354,560-byte ceiling. This does not add a new model to the
image or qualify the smaller profile as a replacement for required 4B testing.

Unknown names and arbitrary paths are rejected. The installed catalog digest,
exact selected identity, resource ceiling, weight corruption target and online/
offline inference identity must match the chosen profile. Results and failures
record the chosen model and fixture. The offline recovery follow-up also binds
its resource fixture and corruption target to the passing base run's model,
instead of assuming every passing base contains 4B weights.

## Fresh integrity-refusal evidence

The prior corruption helper searched the entire model-service journal. An old
identical error could therefore satisfy a later check, particularly when using
an overlay of a previous run. Both wrong-length and same-length checks now
capture a journal cursor before starting the corrupted model, then require an
exact native refusal from the model unit after that cursor. They retain both
the starting and observed cursors in the result. Missing cursors, old logs,
wrong units/messages and ambiguous response records fail rather than count as
acceptance. The guest's commands and polling have finite deadlines.

This uses the packaged [systemd 255 cursor interface](https://www.freedesktop.org/software/systemd/man/255/journalctl.html#--after-cursor=).
Source tests demonstrate the oracle's boundary; a new image run is still needed
to demonstrate its actual runtime behavior. Earlier tests are not retroactively
upgraded to the stronger requirement. No production runtime/budget, model
catalog, security policy or approved model identity was relaxed.

## Executed checks

All **112 native Linux Python tests passed**, warnings treated as errors,
no skips, using the frozen source in a 512 MiB/one-CPU D-backed container.
All **15 model-oracle tests passed on native Windows**. `git diff --check`
passed. These tests do not execute a real model or close image acceptance.

Evidence: `D:\LumaOS-builds\g2-model-profile-tests-20261001-01`.

- `test.log` SHA-256:
  `e05bdd1c1b3e4af3bd909c8961162ace02178481f5ba3f5fd829b652f66de986`.
- `source/build-inputs.json` SHA-256:
  `61e1e40e09adb3bd3221d25c72fc2e1fef8c15f06a5d97608cd78e631499656b`.

The source manifest captures the image/test harness; native tests were also
copied into that frozen tree before execution. The later documentation update
does not change that tested harness or the queued inputs.

## Build and queued execution

Desktop build `20261001T090338Z-desktop` completed both package builds, native
compilation, initrd generation, the 6 GiB root filesystem/verity checks and
laboratory UKI signing/policy verification. It has reached payload assembly.
At the read-only progress check, the assembler had advanced from artifact reads
to allocating `/work/artifacts/payload.ext4` (8 GiB). The public `build.json`,
complete disk image and verified export are not yet available.

D: reports healthy/OK and approximately 144 GiB free; a sampled read rate was
about 40 MB/s. The assembler's kernel wait showed WSL filesystem I/O, not a
request for interactive input. The exFAT-backed artifact allocation/copy/checks
are slow. No disk repair, formatting, filesystem migration, source mutation
inside the active build, or host service changes were performed.

The existing desktop-greeter queue remains first, after successful image export
and artifact checksum verification. A second, serialized queue now waits for
that exact desktop result and exported evidence before attempting a fresh 4B
installer download/inference suite with Secure Boot, software TPM, strict
shutdown and bounded model requests. It explicitly stops if desktop acceptance
fails; its wait is bounded to six hours. It opens no guest port forwards and
enables guest networking only during publisher acquisition. All large storage
remains on D:; no physical target disk is used.

Second queue log:
`D:\LumaOS-builds\g2-model-after-desktop-20261001-01\run.log`.
Planned model work:
`D:\LumaOS-builds\work\20261001T090338Z-desktop\vm-desktop-model-4b-20261001-01`.
Private software TPM volume:
`luma-g2-desktop-model-tpm-20261001-01` (never publish).

Neither queued evaluation is a pass. The 1.7B fresh-install option is ready
for its own separate run but is not queued as a substitute for 4B acceptance.
Full Admin enrollment/policy/effects, signed skills/workflow, model lifecycle,
desktop login/locking/manual workflow, remaining fault matrices, production
custody and physical qualification remain open in the software register.
