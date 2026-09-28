# Sequence-4 native Ubuntu test image

This is a headless Ubuntu 24.04 amd64 **laboratory installation/recovery image**.
It is not a package to install over an existing Ubuntu system, a desktop release,
or a certified production OS. Consult the
[current checkpoint](NATIVE_EXTERNAL_STATUS_2026-09-28.md) for executed evaluation
status; this guide alone does not assert a test pass.

## Transfer and verify

Copy the complete export directory to the native Ubuntu test machine:

`D:\LumaOS-builds\native\20260928T124255Z-headless`

Keep `SHA256SUMS`, the public certificate, release manifest/signature, source
archive/lock, package locks and exported evidence with the compressed image.
Do not copy the private Docker key volume or the disposable VM disks.

On Ubuntu, in the transferred directory (requires `zstd`):

```sh
printf '%s  %s\n' \
  b7f98803ee732525124f27b594cc87b4f2f8b71eb1d833f6da568e386a50514e \
  luma-native-lab-20260927-headless-4.img.zst | sha256sum --check -
zstd --decompress --keep luma-native-lab-20260927-headless-4.img.zst
printf '%s  %s\n' \
  5408c3d8430dc085c52b0d816abfcdd3fe68f9b079925a2e469aa7643a5f5197 \
  luma-native-lab-20260927-headless-4.img | sha256sum --check -
sha256sum --check SHA256SUMS
```

Stop if verification fails. Retain both the compressed image and its metadata.
The raw image needs about 12 GB of free space in addition to the compressed file.
The filename's September-27 date is a fixed release label; the build ran on
September 28 and has sequence 4.

## Prepare an explicitly approved test target

Use an amd64 UEFI machine with at least 8 GiB RAM for the 4B CPU profile,
a separate USB stick of at least 16 GiB, and a disposable target disk of at
least 32 GiB (64 GiB recommended). Back up all data and existing recovery keys.
Disconnect unrelated disks where practical. This installer does not implement
dual boot or legacy BIOS installation.

In Ubuntu Disks, use **Restore Disk Image** on the explicitly identified USB
stick. Restoring erases that USB. Keep it distinct from both the Ubuntu host's
system disk and the approved installation target. No host disk is selected by
this guide. Boot the prepared USB through the machine's firmware menu.

Secure Boot requires separate owner-approved enrollment of `secureboot.cer`
into the test firmware's `db`. Do not clear existing production keys, treat MOK
enrollment as equivalent, or silently disable Secure Boot. If enrollment is
unavailable, record Secure Boot as untested and obtain approval for a separately
scoped non-Secure-Boot test. No script enrolls physical firmware automatically.

## Install with automatic model acquisition

Connect Ethernet or configure networking interactively with `nmtui`. At the live
console, inspect the disk inventory and verify the bundle before selecting the
exact approved target:

```sh
luma-platform inventory
luma-platform verify /media/luma
luma-platform models
luma-platform install /dev/disk/by-id/REPLACE-WITH-APPROVED-TARGET /media/luma --model qwen3-4b-q4-k-m
```

The last command **erases the selected whole disk** after resource admission,
display of its identity, and exact `ERASE <identity>` confirmation. Do not use an
assumed `/dev/sdX` ordering or choose the existing Ubuntu disk by default.
Create distinct user/administrator accounts and new passwords, data-unlock and
independent recovery passphrases. Keep the recovery credential off-device.

The installer downloads the pinned Qwen3-4B Q4_K_M weight file (2,497,280,256
bytes), checks its exact length and SHA-256, and configures the isolated local
CPU runtime. Weights are not embedded in the image. There is no cloud-inference
fallback. The smaller `qwen3-1-7b-q4-k-m` profile is also selectable after its
hardware checks, but is not a substitute for the governed 4-6B tier.

If acquisition fails, keep the diagnostic and use the manual operating mode.
After fixing networking on the installed system, retry with:

```sh
sudo luma-platform model-install qwen3-4b-q4-k-m
```

Recovery disablement is intentionally not automatically cleared by a model
reinstallation. Investigate the fault and repair/reinstall the selected profile
first, then follow the full operator guide's explicit local-administrator
re-enablement steps. Do not automatically clear the disable marker on boot.

## Boot and retain evidence

After the installer reports completion, remove the USB, boot the target, unlock
the encrypted data and log in. Check:

```sh
sudo luma-platform boot-health
sudo systemctl --failed
sudo systemctl status luma-broker luma-reference luma-model
printf 'Reply with a short greeting.' | sudo luma-platform model-chat
```

Repeat boot with the network disconnected to exercise the cached model. Retain
machine/firmware inventory, image hashes, approved target identity, boot/service
results, inference output and timings, and the independent-recovery evidence.
Do not publish credentials, private keys or exported user data. Follow the
[full operator guide](../image/README.md) for independent unlock/export, model
disablement, slot repair and signed updates. Physical power-cut/damaged-media
tests need a separately approved plan; VM results do not qualify them.
