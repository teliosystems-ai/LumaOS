# Sequence-6 laboratory image - 2026-09-29

**Build and verified export passed; live-media checks passed, but installation
evaluation failed at TPM admission. G2 remains
incomplete.** This is a headless Ubuntu 24.04 amd64 laboratory image, not a
production-signed or all-components G2 release.

## Artifact identity

Export: `D:\LumaOS-builds\native\20260929T175214Z-headless`.
Work/VM files: `D:\LumaOS-builds\work\20260929T175214Z-headless`.

| File | SHA-256 |
| --- | --- |
| `luma-native-lab-20260927-headless-6.img.zst` | `733dc7371cf0d83faf990ee67e5682e2dd5336b025002c68ed9ab38a669aa3ee` |
| Uncompressed `.img` | `6228c6756a41a911ea545152d503eb4082545e32cf23fab958f97e548905388f` |
| `source-lock.json` | `09bdd6861770afc6ecf8a1f7b5e64943e5320445a6da4f7f6cec4a4f9cdfedef` |
| `native-source.tar.zst` | `78c8e848d839193c8a2a28edbfd4366da12b79d32a1651a80665f79764e7ea80` |
| `boot-policy.json` | `5333eca0bd205718f4570f0f6a0e217571136d27d3d9cb1d9c23803f6fd61955` |

Kernel: `6.8.0-142-generic`. Tools image:
`sha256:40d9d50237189a8880580e16edcaf1a3ff81ac996be9b4f180d397c7140b1bce`.
The builder verified verity, UKI signatures/PCR policies, initrd contents and GPT,
then exported each artifact using a verified temporary-file transfer. The
unaltered `build.json` records `built-not-yet-boot-tested`; later test results
are separate evidence, not edits to that build record.

This image includes the live-only payload mount, bounded 90-second device wait
and ordered recovery consoles from commit `66a9a3f`. The build started before
that commit and subsequent documentation edits; its source-lock/archive, not
the current checkout's documentation, define its exact contents. Sequence 5
and its failure logs remain unchanged; see the [prior checkpoint](TEST_IMAGE_2026-09-29.md).

## Evaluation boundaries

`vm-admin-seq6-tcg-01` uses Secure Boot, software CPU emulation, a fresh 32 GiB
virtual disk and an isolated persistent software TPM. No physical TPM or target
disk is attached. TCG is deliberate after the sequence-5 KVM backend failure;
this does not qualify nested KVM.

The fixture checks live-media readiness, installation rejection paths and the
manual-mode installation, then installed PAM and measured-boot credential
behavior across reboot and A/B slots. A pass is not inferred until all stages
finish and `result.json` is exported with its logs and exact source/image hashes.
No completed authenticated Admin enrollment is claimed by this fixture.

## Observed failure and source repair

The live boot passed Secure Boot, verity, AppArmor, service and payload-file
checks. `media-luma.mount` completed, confirming the sequence-5 mount fix.
Installer attempts were rejected before disk writes with `local TPM2
resource-manager character device required`. The disk-prefix comparison
remained unchanged. The apparent tampered-bundle refusal was actually the
earlier TPM check, so it is **not** counted as signature-rejection evidence.
The subsequent model-admission assertion exposed the wrong rejection cause.

The kernel log reports a TPM2 TIS device and successful TPM phase services.
Inspection of the exact built root found Ubuntu's `60-tpm-udev.rules` assigns
both TPM devices to `tss`, conflicting with native `Context::local()` requiring
a root-owned character device. This is an image integration defect, not proof
that hardware or the virtual TPM was absent.

Source now supplies final root:root 0600 udev assignments for raw and resource-
manager TPM devices, includes them through the measured-phase dracut module,
and verifies exact rule bytes in the generated initrd. Native device admission
is not weakened. `udevadm verify` passed. The VM readiness check now reports
device metadata and runs `tpm-probe`; the tampered-bundle test must observe the
specific signature-verification error, not any failure code. These repairs
are **not** present in sequence 6 and require a new image and VM run.

The first regression run (`native-tests-20260929-tpm-ownership-01`) caught
the missing rule in the generic initrd: dracut only searches `/etc` rules by
filename in host-only mode. The module now installs the absolute rule path.
The fresh rerun in `D:\LumaOS-builds\native-tests-20260929-tpm-ownership-02`
passed 42 ordinary Rust tests, 20 explicit TPM and 6 PAM invocations, and all
27 Linux Python tests, including exact initrd rule bytes. Six isolated Rust
functions are intentionally ignored in the ordinary suite and explicitly
invoked by the runner; invocation counts are not all distinct functions.
The original failed evidence was retained and is not reported as a pass.

## Rebuild blocker

C: was observed with 6,105,718,784 bytes free, below the builder's 8 GiB
minimum; D: had 382,445,289,472 bytes free. Docker's Linux workspace still
resides on C:. No new image build was started, no minimum was lowered, and no
retained builds, keys or user data were removed. Free C: to at least 8 GiB
(preferably 12-16 GiB) or approve a supported preserving storage relocation
before rebuilding and rerunning installed authentication/PCR evaluation.

The full installer/update/recovery matrix and actual model inference have not
been rerun against sequence 6. Model/resource lifecycle, finite Admin/policy,
skills/workflow, Wayland desktop, generated-code isolation and production trust
integration remain open as listed in [G2 software status](../G2_SOFTWARE_STATUS.md).
Physical qualification and production custody remain separate requirements.
