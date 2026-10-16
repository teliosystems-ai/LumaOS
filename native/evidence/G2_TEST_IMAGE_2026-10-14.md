# G2 native Ubuntu test image, sequence 14

The newly rebuilt desktop laboratory candidate is exported on D. It includes
the isolated model QA and inert installer-staging changes committed in
`3b6ed0457b18c585144092bb6b93051f8e5a2b3c`. This is standalone Ubuntu 24.04
amd64 installation/recovery media, not an application installer, ISO or
in-place upgrade of an existing Ubuntu Server installation. It has not yet
been booted or installed on the native test machine. G2 is not closed.

## Delivery and verification

Copy all eleven public files from
`D:\LumaOS-builds\native\20261014T170707Z-desktop` together. The image is
`luma-native-lab-20260927-desktop-14.img.zst`, 2,928,680,197 bytes (about
2.73 GiB). Decompression produces a 16,190,013,440-byte raw UEFI disk image
(about 15.08 GiB). The release name retains the pinned reference date; this
candidate was assembled on 2026-10-14.

- Compressed SHA256: `6a6c2a589e03cfce61056c3c5eaed76a7d37b9970b82ebd7f8727be8c2c5d789`.
- Raw SHA256: `ae4b4cbfc1969df065a9b8278806a1a00c980bdbfed250b5e07c30241a725fca`.
- Source lock SHA256: `1313a5e249ecf892818cb63200bb9ac10080175c71659162a264402e2f74a3e6`.
- Verity root: `203f1c99cee3e106c56159184da93ef91261fa50d02eba368638c1d46c6a43ad`.

The foreground assembler and exporter completed with exit code zero. Signed
sealed artifacts, UKIs/PCR policies, verity, GPT and copied payload/ESP ranges
were checked during assembly. Compressed integrity and independent streamed
decompression to the exact raw SHA256 passed. Independent Windows
checks verified all nine exported members listed in `SHA256SUMS`; its tenth row
is the raw image retained in D-backed Linux storage. `build.json` and
`SHA256SUMS` are also exported. No private keys are included.

All 330 captured product-source files match their corresponding files in the
420-file tested snapshot byte for byte. The final software sweep passed 982
Rust tests, warnings-denied all-target checks, 458 native-source tests with no
skips, thirteen OS and thirteen model public-authentication cases, eight UTC
authentication cases, nineteen AppArmor policy parses and disposable PAM and
resource software-TPM cases. Forty-two existing fixture-only Rust entries were
excluded from the unit suite. This is not a final complete fixture run or a
claim that installed confinement, actual model QA or physical TPM checks passed.
See the [machine-readable delivery record](G2_TEST_IMAGE_2026-10-14.json) and
[readiness record](../../docs/gates/g2/production_readiness_2026-10-14.json).

Use sequence 14 for testing these new changes, not the older image. On
2026-10-16 the owner authorized [retirement of superseded assembly disks](ASSEMBLY_RETIREMENT_2026-10-16.json).
Old work/VM disks and work-copy images were removed; historical logs, manifests,
source archives and the separate export directories remain. The sequence-14
delivery and its D-backed Linux artifacts were not changed.

## Prepare media on the separate Ubuntu machine

Use an amd64 UEFI machine, an explicitly selected 32 GB or larger USB device
and a separate disposable installation disk. A 64 GB or larger installation
disk and at least 16 GiB RAM are practical starting points for desktop/4B
testing, not certified minimums. Actual installation and model-resource checks
must pass. Allow at least 18 GiB free for decompression.

With `zstd` available, run from the directory containing all eleven copied files:

```sh
sha256sum --check --ignore-missing SHA256SUMS
zstd --decompress --keep luma-native-lab-20260927-desktop-14.img.zst
sha256sum --check SHA256SUMS
```

Before the first command, confirm the complete eleven-file inventory against
the delivery record. `--ignore-missing` is only intended for the not-yet-created
raw image, not absent sidecars. The final check must verify all ten checksum
rows. Do not force decompression over an existing image; preserve successful
checksum output with the native evidence.

Use Ubuntu Disks to restore the raw image to the explicitly selected test USB.
Restoring erases that USB. Do not select the existing Ubuntu system disk. Boot
the USB in UEFI mode. Secure Boot testing requires owner-approved enrollment
of the supplied laboratory certificate while preserving existing platform keys;
the image does not enroll firmware trust automatically. A disabled Secure Boot
run is not passing security qualification. Do not clear or reset the TPM.

The live installer/recovery environment is console-based; the installed edition
includes GNOME/Wayland. At the live console first run:

```sh
luma-platform --help
luma-platform inventory
luma-platform verify /media/luma
```

Identify the actual disposable installation disk by its stable by-id identity.
Follow the built-in install help and explicit whole-disk erase confirmation.
Installation erases the selected target; it is not dual boot. No physical-disk
installation, host TPM change or firmware change was executed on the
development machine.

## Model download, Admin and isolated QA

The installer downloads pinned, hash-verified weights; weights are not embedded
in the image. Uncached installation therefore needs network access.

- Laboratory `--model qwen3-4b-q4-k-m` retains the existing laboratory model
  selection path. `qwen3-1-7b-q4-k-m` is the smaller supported choice when its
  hardware checks pass.
- For data-only staging with serving left disabled, use
  `--stage-model qwen3-4b-q4-k-m`, or the supported smaller profile. This new
  path binds acquisition to the verified target image and actual locked
  disk/mount/controller, checks capacity/resources and preserves pending
  receipts on interruption. Pending receipts never authorize serving or QA.
- Governed production installation remains inert. Production model operation
  requires genuine signed model/catalog/custody and machine/image-specific
  qualification inputs. No such inputs or certificates are fabricated here.

The implemented native adapters are compact Qwen CPU profiles. This delivery
does not qualify Gemma, GPU inference or 400-450B operation.

Provision the existing-owner local TPM2-backed Admin and the separate resource
checkpoint authority, then bootstrap/adopt the original Admin and establish
protected UTC. Follow [local TPM2 Admin](../LOCAL_TPM2_ADMIN.md) and the
[image operation reference](../image/README.md). A Unix sudo account alone is
not the product's original Admin. Preserve the existing TPM owner and recovery
material; do not substitute host time, reset authority or clear TPM state to
bypass a refusal.

Installed QA has separate execution and cancellation scenarios. Register and
assign `model.qa`, review the actual model, and issue the exact finite grant
scope returned by review:

```sh
sudo luma-platform granted-run model-qa-review MODEL-ID execution
sudo luma-platform granted-run model-qa-run LOGIN GRANT MODEL-ID execution
```

Replace the uppercase arguments with actual installed/reviewed identities;
they are not sample authority. Use `cancellation` instead of `execution` for
the cancellation scenario. QA checks physically verified cached weights,
current original-Admin credentials, protected UTC, finite grants and resource
leases continuously. Inert factual reports are retained under
`/var/lib/luma-os/model-qa`; they neither certify a pass nor enable serving.

The current separate QA session is nonrenewable and lasts 30 seconds, with a
25-second runtime budget. Cold 4B loading may refuse safely. A proposed
30-minute **QA-only** session still awaits explicit owner approval; approved
longer import, activation, export and repair sessions do not authorize it.
Consequently this delivery does not promise successful cold-model QA within
the current budget.

## Native acceptance and production qualification still required

Bind every run to this exact release, raw hash and actual machine inventory.
Use the [physical qualification runbook](../../docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md)
and [Ubuntu qualification guide](../../docs/UBUNTU_QUALIFICATION.md). Cover:

- Real installation, model download interruption/retry, installed A/B and
  recovery boots, boot acknowledgement and model-independent graphical login.
- Existing-owner TPM Admin/checkpoints, Secure Boot/PCR/verity/LUKS enforcement,
  account activation/aging, password/lock recovery and damaged-authority repair.
- Authenticated UTC deployment, seed/control/history, bounds and offline/expired
  refusal, including loss, leap/step, suspend/resume and recovery.
- Actual principal/grant/generation fencing, resource pressure, installed
  AppArmor/seccomp/cgroup confinement, QA execution/cancellation, model admission
  and generated KVM confinement.
- Governed workflows, retention/export and interrupted transactions, storage
  pressure, signed updates, fallback and recovery.
- Required E1/E2 physical executions and genuine production signing/custody and
  externally signed qualification inputs for the actual hardware tuple.

This is lab-signed test media, not production-qualified media. Successful
assembly does not close G2 or Requirement 1 and does not advance Requirement 2.
