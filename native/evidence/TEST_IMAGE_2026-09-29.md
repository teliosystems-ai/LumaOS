# Sequence-5 laboratory image - 2026-09-29

**Build and verified export passed; live boot passed selected checks but
installation evaluation failed. G2 is not complete.** This is a headless laboratory image, not the requested final
all-components release or production qualification.

## Exact artifact

Export directory: `D:\LumaOS-builds\native\20260929T170514Z-headless`.

- Compressed image: `luma-native-lab-20260927-headless-5.img.zst`.
- Compressed SHA-256: `397f06c0208232682cd41d2bd4b8a079ab102b850adb2084c9bdf671150da120`.
- Raw image SHA-256: `6d81f2afb30d75cbcb538b8c4a5007b0fa45c59d67f94a552ac136ddb4a96018`.
- Source-lock SHA-256: `08995a3e73f3da3ecaf91fd54d76f0d92ac10472c6b8de945dc8effe799bed7b`.
- Source archive SHA-256: `96e0065507024a04a0ce005c4881d1c14cbf6ac307ea1f02715640f93efab592`.
- Boot-policy SHA-256: `dee8144615a6ccaf725304cf9517293e2a405144d6582d513d9429cc8f555041`.
- Kernel: `6.8.0-142-generic`; image base: Ubuntu 24.04 amd64.

The image contains the native implementation through commit `07d76bb`, including
installer TPM admission and pending enrollment intent, signed installed A/B
PCR policies, initrd phase measurement, storage maintenance, and the PAM
authentication diagnostic. It does not implement authenticated Admin enrollment.
The manifest pins the exact source bytes; the later boot-test runner is separate
evaluation tooling, not a claim about the archived image source.

The builder verified dm-verity, UKI signatures/PCR policy sections, initrd
contents and GPT structure. Export checked each copied artifact's digest before
renaming it out of its temporary filename. The original `build.json` correctly
records `built-not-yet-boot-tested`; separate boot evidence must establish any
later acceptance and must not retroactively alter the build record.

## Storage and test boundaries

D: was reported repaired by the owner and subsequently observed Healthy / OK.
It remains exFAT. Large artifacts and disposable VM disks are on D:; cached
Docker layers, the Linux build workspace and private lab signing keys remain in
Ubuntu's C:-backed storage. No private keys were copied to D:, no physical disk
was installed, and no host TPM was enrolled. See the
[storage record](../image/D_DRIVE_BUILDER.md).

The isolated TPM/PAM runner passed in
`D:\LumaOS-builds\native-tests-20260929-resume-01`: 42 ordinary Rust tests,
20 explicit TPM and 6 PAM invocations, and 24 Linux Python tests. Six isolated
functions are intentionally ignored in the ordinary Rust suite and invoked by
the runner; these counts are not all distinct test functions. The retained
source inventory predates the new fixture's final A/B orchestration edit.
A subsequent Windows run passed 16 Python tests and skipped eight Linux-only
tests. Neither run qualifies installed-image behavior.

## Boot evaluation

The separate `admin_vm_test.py` fixture installs on a fresh 32 GiB virtual disk
with Secure Boot and a private software-TPM namespace. It checks PAM success and
refusals without product-authority claims, measured phases, staging maintenance,
signed-PCR credential delivery, reboot/A-B continuity and unapproved-PCR refusal.
Its result and serial logs are required before these checks can be marked passed.

The initial KVM run (`vm-admin-seq5-01`) failed before the live console was ready:
QEMU aborted with `cpu_asidx_from_attrs` / `ret < cpu->num_ases && ret >= 0`.
The generated disk, firmware state and serial/QEMU logs were retained, without
claiming a successful boot or a product defect. A fresh software-emulated (TCG)
run used `vm-admin-seq5-tcg-01`; it does not qualify KVM operation.

The TCG run reached the live root console and passed the explicit Secure Boot,
dm-verity, AppArmor and native service checks. Installation then failed before
any disk erase: `/media/luma/release.json` and `release.sig` were absent. The
serial log records the payload device timing out after the unconditional fstab
entry's three-second wait, with `media-luma.mount` failing its dependency.
Installed authentication and credential recovery were therefore **not run**.

Source now removes the unconditional fstab entry, generates a live-only mount
dependency and 90-second device timeout, and orders both live consoles after
the mount attempt. A failed mount still permits recovery-console access rather
than requiring successful installation media. The VM readiness check now
explicitly requires the mounted release files. Three targeted Linux regression
tests passed, including actual generator execution for live/installed/unknown
boot modes. These edits are not in sequence 5. A fresh sequence-6 rebuild was
started; its image and boot results must be recorded separately.
Its run ID is `20260929T175214Z-headless`, using D: work/export directories as
recorded in the storage note. At this checkpoint it has compiled, built the
initrd and reached filesystem-image assembly; no completed sequence-6 export
or VM pass is claimed.

The complete isolated runner was then rerun against the corrected source in
`D:\LumaOS-builds\native-tests-20260929-live-media-01`: 42 ordinary Rust tests,
20 explicit TPM and 6 PAM invocations, and **27 Linux Python tests passed**.
The source inventory includes the new mount, console units and boot generator.
`systemd-analyze verify` accepted the mount/console units; warnings about the
Windows checkout's permission bits do not describe the image permissions, which
the builder explicitly normalizes (0644 for units, 0755 for generators).

The full installer/update/recovery matrix and real model inference have not been
rerun against sequence 5. Sequence-4 evidence is not acceptance evidence for this
image. The full remaining implementation and qualification inventory is in
[G2 software status](../G2_SOFTWARE_STATUS.md).
