# Installed desktop acceptance harness — 2026-10-01

G2 is **not complete**. This checkpoint adds a real installed-image greeter
fixture; its source/transport tests are not a passed OS-image evaluation.

## Implemented evaluation

`native/image/desktop_vm_test.py` accepts only the declared desktop image
whose bytes match `build.json` before starting a VM. It checks the identity
again before publishing success. It creates a new 32 GiB virtual target and
uses the existing public installer credentials, no physical target devices,
no guest network and no host display/GPU/input access. Its three stages are
fresh manual installation, installed greeter and cold-boot greeter.

Installed checks require the desktop profile and signed graphical target,
successful boot health, active GDM, and exactly one active, local, seat-0
Wayland session with class `greeter`, user `gdm` and service
`gdm-launch-environment`. They repeat the observation after stopping the
guest model/broker/reference services, then restore those services. Strict
Secure Boot observations and fresh verified late-shutdown markers are enabled
for the queued run. Live media must not start GDM.

The shared VM wrapper's explicit graphical option adds software-only
`virtio-vga`; existing headless runners retain their prior device options.
The QMP screenshot helper has a whole-operation deadline, message/byte bounds,
exact reply IDs, failure checks and fixed non-overwriting output names. The
collector includes only the fixed public greeter PNG names, never arbitrary
screenshots, VM disks, NVRAM or TPM state. Failure diagnostics and screenshots
are retained separately without publishing a passing `result.json`.

This does **not** authenticate a graphical user, evaluate screen locking or
the full manual graphical workflow, or qualify physical graphics hardware.
Those result flags remain false. No automatic login, session injection or
authentication bypass is introduced.

## Executed source and transport checks

The final frozen harness passed **106 native Linux Python tests**, with
warnings treated as errors and no skips, in a 512 MiB/one-CPU disposable
D-backed tools container. The ten portable desktop oracle tests also passed
under native Windows Python. `git diff --check` passed.

A separate real QEMU process exercised the PNG/QMP helper and produced a
640×480 image. That QEMU was deliberately paused without an OS or guest disk;
the result explicitly says OS boot, desktop, physical hardware and gate
closure were not tested. The process was terminated only after transport
evaluation, not represented as a guest shutdown.

Final evidence:
`D:\LumaOS-builds\g2-desktop-fixture-tests-20261001-03`.

- `test.log` SHA-256:
  `f91d59f0f13ffe71d4eaee9f31c3e063383c13962cef022f6b1e31b179f57019`.
- `source/build-inputs.json` SHA-256:
  `5a2d063728a2dee064dc473af4f57aa58d08d87bdcf1c403e902b3722fb44119`.
- `qmp/result.json` SHA-256:
  `f81f775b701d240d48465e5196e6eed3bd5d488e9a48eeeff0fcdc854dc8f485`.

The standard build-input manifest covers the harness under `native/image`;
the native tests were additionally copied into that frozen source tree for
execution. No later checkout edit changes the queued harness.

The first restricted source run exposed a cleanup race in the earlier HTTP
trickle test: the deadline could fire before the server accepted a connection,
leaving its request thread waiting indefinitely. The fixture now bounds accept
and starts the body deadline after real response headers arrive. Its slow-body
refusal assertion remains; the production helper/budget is unchanged. The
failed run was retained as attempt 01. Only its identified disposable test
container was stopped. Attempt 02 passed 105 tests and the QMP probe; final
attempt 03 adds image-identity binding and passed all 106 tests.

## Image build and acceptance queue

The repaired D-backed desktop build `20261001T090338Z-desktop` has completed
the tools container and advanced through desktop package installation. Its
log remains `D:\LumaOS-builds\g2-desktop-build-20261001-02\build.log`.
It is not yet an exported/accepted image at this checkpoint.

The frozen desktop evaluation is queued with a bounded two-hour wait for both
the final source/QMP pass and that exact build's completed export. It rechecks
the D-backed profile and all artifact checksums before starting, so a partial
image is never accepted as build completion. Large build and VM jobs are
serialized. Queue log:

`D:\LumaOS-builds\g2-desktop-acceptance-20261001-01\run.log`

Planned work directory:
`D:\LumaOS-builds\work\20261001T090338Z-desktop\vm-desktop-greeter-20261001-01`.
Private software TPM state uses the separate D-backed volume
`luma-g2-desktop-tpm-20261001-01`; do not publish it. Only after a full fixture
pass will the collector export public evidence beside the image as
`desktop-greeter-evidence-20261001-01`.

Still open: actual GDM password login, locking and session/account lifecycle;
full manual graphical workflow; fresh bounded model inference and follow-up
model tests; product Admin enrollment/policy, skills/workflow and model
lifecycle; remaining security/recovery matrices and physical qualification.
