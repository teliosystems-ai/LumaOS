# G2 native Ubuntu test image

The desktop sequence-13 laboratory image is built, exported and checksum
verified. It is ready to transfer to the separate native Ubuntu test machine.
It has not been boot-tested in this delivery; production signing, native
qualification and the G2 exit gate remain open.

## Image and verified scope

The Windows export directory is
`D:\LumaOS-builds\native\20261013-resumed-desktop-13`.
Copy all eleven files together, not just the image. The compressed image is
`luma-native-lab-20260927-desktop-13.img.zst`, 2,927,978,781 bytes
(about 2.73 GiB). Decompression produces a 16,190,013,440-byte raw UEFI image
(about 15.08 GiB). This is a disk image, not an ISO or an in-place Ubuntu upgrade.

- Compressed SHA256: `30591427894edd407996936d9608016abaafbb0d105de76f05db05a40ed6bb0b`.
- Raw SHA256: `09ba55b4ab66831b42c5243ac8ac7ccb4b666a71b009f7fc23efe44b5554c88a`.
- Source lock SHA256: `58be10695ba8165541d4f4caa0f1853190fcf62cb8177230d886e9234e509885`.

The resumed assembler exited successfully. It verified the signed sealed
artifacts, public custody fingerprints, root verity, embedded source/release
identity, all three UKIs and their PCR policies, exact payload and ESP contents,
primary/backup GPT and copied partition bytes. Compression integrity and exact
decompressed-image equality passed. Export verified destination bytes for each
file; an independent Windows checksum pass verified all nine exported members
listed in `SHA256SUMS`. The tenth row identifies the raw image retained in
D-backed Linux working storage, not an accidentally missing exported file.

The build record says `built-not-yet-boot-tested`, `production_signed: false`
and `gate_closing: false`. The source is the original 314-file sealed build
snapshot. Its Rust code has the retained 962-test baseline; packaging-only
changes pass 407 native regressions with zero failures or skips. These results
do not certify installed confinement, login, real model admission or hardware.

The compact candidate includes the implemented account lifecycle, finite
grants/resource generations, protected UTC delivery, governed workflow and
recovery paths, trust/update lifecycle, native model governance and fixed
generated-code KVM runtime. Use the [software register](../G2_SOFTWARE_STATUS.md)
for exact scope and qualification boundaries. The [assembly checkpoint](G2_IMAGE_RESUME_2026-10-13.md)
records the explicit source-archive correction and preserved failed attempts;
OS filesystems, boot artifacts and signatures were not rebuilt or re-signed.

## Prepare the native test media

Use an amd64 UEFI test machine. A 32 GB or larger USB device fits the raw image;
a disposable 64 GB or larger installation disk and 16 GiB or more RAM are
practical starting points for the desktop/4B model tests. The installer performs
its own actual hardware and capacity checks; these starting points are not a
qualification result. Allow at least 18 GiB free where the image is decompressed.

On Ubuntu, with `zstd` available, run these commands from the copied export
directory:

```sh
sha256sum --check --ignore-missing SHA256SUMS
zstd --decompress --keep luma-native-lab-20260927-desktop-13.img.zst
sha256sum --check SHA256SUMS
```

The first check intentionally omits only the uncompressed raw file. The second
checksum pass checks that file too. Do not force decompression over an existing
image. Preserve all sidecars and the successful checksum output with the test
evidence.

Use Ubuntu Disks to restore the decompressed image to an explicitly selected
test USB device. Restoring erases that device. Do not select the machine's
existing system disk. Boot the USB in UEFI mode. This delivery does not modify
firmware trust: Secure Boot testing requires an owner-approved laboratory
certificate enrollment that preserves existing platform keys. Disabling Secure
Boot is not a passing security qualification. Do not clear or reset the TPM.

At the live console, first inspect the actual machine and verify the bundle:

```sh
luma-platform --help
luma-platform inventory
luma-platform verify /media/luma
```

Select the actual disposable installation disk from its stable by-id identity,
then follow the built-in installer help and explicit erase confirmation. Use
the local TPM2-backed Admin path with existing TPM ownership. No installation
or physical-disk write has been executed on the development host.

For the model selection, use `--model qwen3-4b-q4-k-m`, or the smaller supported
`--model qwen3-1-7b-q4-k-m` when its hardware checks pass. The installer contains
the pinned model download and installation path; weights are not embedded in
the image. Network access is needed for an uncached model. This candidate does
not qualify Gemma, GPU inference or a 400–450B model. Governed production model
operation separately needs genuine signed public catalog/custody/qualification
inputs for the exact installation, image, runtime and hardware tuple; none are
fabricated by this build.

## Native acceptance work

Retain the exact raw/compressed hashes above with every test run. Cover:

- Destructive installation, download interruption/retry, slot A/B boot,
  acknowledged health, graphical login and operation independent of inference.
- Existing-owner TPM2 Admin provisioning, Secure Boot/PCR enforcement, encrypted
  persistent state, account activation/aging and password/lock recovery.
- Authenticated UTC acquisition, signed seed/control/history delivery, bounds,
  expired or offline refusal, and explicit recovery without host-clock shortcuts.
- Finite principal-bound grants, resource pressure/generation fencing, continuous
  authorization, and separate nonrenewable 30-minute model-import/activation
  sessions that cannot become inference, signing, workflow, export or repair.
- Actual model download/admission/inference, installed AppArmor/seccomp/cgroup
  enforcement, generated KVM confinement, cancellation and output provenance.
- Governed workflows, retained artifacts/history, interrupted updates/fallback,
  storage pressure, damaged-authority repair and independent recovery.
- The required E1/E2 physical executions and larger-model/GPU qualification when
  their hardware and genuine production inputs are available.

Image availability does not close G2 or Requirement 1, and does not advance
Requirement 2. Native and production qualification evidence must satisfy the
governing exit criteria separately.
