# Candidate native Wayland desktop checkpoint - 2026-09-30

G2 remains incomplete. This checkpoint implements and tests a candidate
desktop profile, not the remaining product Admin, model lifecycle, signed
skills or generated-code services. No desktop image has been boot-qualified.

## Implemented source

The optional desktop root now uses pinned Ubuntu GNOME/GDM packages instead
of Xfce/LightDM. It includes Files, Text Editor, Console, Settings and a local
reference-workspace browser launcher. The new assembly policy:

- Requires packaged executables and the GNOME session/GDM unit.
- Installs a Wayland-only, non-root interactive-account session wrapper.
- Disables automatic/timed login and XDMCP; preserves packaged X11 session
  bytes under disabled filenames rather than offering them as the baseline.
- Requires installed boot mode for GDM without a model or broker dependency.
- Selects and checks the signed UKI's `graphical.target` only for installed
  desktop boots; live/recovery and headless boots use `multi-user.target`.
- Preserves Ubuntu's exact packaged locale and GDM aliases, rejecting
  substituted aliases. Account creation remains the existing native installer.
- Uses a 6 GiB root and 8 GiB payload for desktop media; headless geometry is
  unchanged. Desktop media needs a 32 GB or larger USB, not a nominal 16 GB one.

The image still uses the independent console installer/recovery path. This
does not implement a graphical installer, finite product Admin enrollment,
account migration or a completed credential lifecycle.

## Executed evidence

The root-package build succeeded using the pinned Ubuntu base
`ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3`
and archive snapshot `20260927T000000Z`.

Root image: `luma-native-root:20260930-wayland`.
Docker image ID:
`sha256:e22727d650f782cf970c6614dc6b29405733d1d671362ad2cc32fc1fe731927f`.
This is a container package layer, **not a bootable OS image**.

Final smoke evidence: `D:\LumaOS-builds\desktop-smoke-20260930-06`.
The runner applies the real assembly policy in a fresh disposable container,
starts private real D-Bus/logind services, then runs GNOME Shell and applications
as UID 1000. It observes a software-only Wayland compositor and configured,
committed application surfaces for Text Editor, Files and Console. No model,
host display/GPU/input device, host system bus, TPM or production key is used.
The fixture file remained unchanged. The container has no network, a 1536 MiB
memory limit, two-CPU quota and 256-process limit. The final invocation exited 0.

The installed package tuple includes:

- GDM `46.2-1ubuntu1~24.04.9`, GNOME Session `46.0-1ubuntu4`.
- GNOME Shell `46.0-0ubuntu6~24.04.15`.
- Files `1:46.4-0ubuntu0.2`, Text Editor `46.3-0ubuntu2`, Console `46.0-1build1`.

SHA-256 evidence identities:

| File | SHA-256 |
| --- | --- |
| `result.json` | `e7875e17cba8f2a4b0a32e2109c3b8bedc33ea5fff64d404ff7e26ce1ca50722` |
| `packages.lock` | `bad8aeb0b09a0bc3a688bacc530649c61c12a27423aebf93ee7267c88c5f80ba` |
| `sources.json` | `b14f49dcf38ae29e8b0788659d3206efe37d5f81095ac57908cf8ca264aa3442` |

All 60 native Linux Python unit tests passed with warnings treated as errors,
no skips, in `luma-native-tools:20260929-auth`. Ten desktop tests cover boot
targets/geometry, login independence, required packages, symlink rejection,
exact packaged aliases, X11 preservation and wrapper refusals. These tests
use synthetic roots; the real packaged-root smoke is separate evidence.
The final source verification also passed `bash -n native/image/build.sh`.
Its transcript (including source hashes) is
`D:\LumaOS-builds\desktop-source-tests-20260930-01\test.log`, SHA-256
`e2573bbf01ea8035f5b86e576610aa6d44f74f8ccc3fc93ab7a1c719e4af9fb3`.

Earlier attempts are preserved on D:, not relabeled as passes: attempts 01/02
identified the packaged locale/GDM aliases; 03/04 exposed the missing private
system bus/logind setup. Attempt 05 passed editor/Files surfaces; final 06 adds
Console and captures auxiliary session logs. Portal/FUSE/accessibility/session
warnings in the container remain visible in those logs. No host repair or
service reconfiguration was performed.

## Still required

Sequence 9 and the currently building sequence 10 are headless; neither
contains this desktop change or its new explicit signed boot-target policy.
At the latest read-only capacity check, C: had 4,623,585,280 free bytes and D:
had 276,915,027,968. Another complete image build is below the unchanged 8 GiB
repository-drive minimum. Do not bypass the guard or prune retained evidence,
build volumes, private key volumes or unrelated Docker data to force a build.
Free additional C: capacity before assembling the desktop image; D: continues
to hold exported images, public logs and disposable VM disks.

After building a fresh desktop image, evaluate actual GDM password login,
Wayland session identity, file open/edit/save/export, terminal and Settings,
logout/login, screen locking, password/account changes, reboot and clean
shutdown, and missing/broken/stopped-model operation. The container smoke
does not test GDM, a complete `gnome-session`, locking, accessibility, input,
account migration, installed-image persistence or physical GPU behavior.
The result explicitly marks GDM, installed image, physical hardware and
gate closure as false. Physical-device and two-board qualification remain
separate from these executable software checks.

Implementation references: the packaged shell's `--help` and
[Ubuntu GNOME Shell manual](https://manpages.ubuntu.com/manpages/noble/man1/gnome-shell.1.html),
and GNOME's [headless testing guidance](https://gnome.pages.gitlab.gnome.org/pygobject/guide/testing.html).
