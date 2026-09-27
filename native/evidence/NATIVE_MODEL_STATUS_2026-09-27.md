# Native model-enabled development checkpoint — 2026-09-27

G2 remains in progress. This record is separate from the original manual-only
image checkpoint and the frozen Python source-release evidence. It does not
assert production custody, certification, or completion of all G2 software.

## Implemented in source

- Installation-time `--model` selection or an interactive choice, with explicit
  manual-only mode and pre-erasure RAM/CPU/storage admission.
- Pinned Qwen3-4B Q4_K_M and Qwen3-1.7B Q4_K_M CPU profiles. The latter is a
  development option below the governed 4–6B tier, not an equivalent substitute.
- Unprivileged HTTPS downloading, exact byte-count and SHA-256 verification,
  atomic activation, retry from installed Ubuntu, and no cloud inference fallback.
- A digest-pinned llama.cpp CPU runtime in the image; model weights are acquired
  during installation, not stored in Git or embedded in the image.
- A separate model account, enforcing AppArmor, systemd syscall/device/network
  restrictions, per-profile memory limits, no swap, two-CPU quota, and local API
  authentication. Model outputs do not dispatch OS actions.
- Manual boot/workflow availability independent of inference; recovery can
  disable the model while keeping the reference workflow service available.
- Private network-profile persistence in encrypted `/var`, account migration
  for older images, and a bounded local operator inference command.

## Evaluation status

The candidate under evaluation is:

- Build volume: `luma-native-build-20260927T195004Z-headless`.
- Export folder: `dist/native/20260927T195004Z-headless/`.
- Image: `luma-native-lab-20260927-headless-3.img.zst`.
- Raw SHA-256: `8a9f87e31c052646b4b9edad0920de31105bece42231d927e5758b50e1de3429`.
- Compressed SHA-256: `65bb50c0e4ed90836554d89bef04e5b7c32a804b751cdcc82afc9cdc9bce1d20`.
- Source-lock SHA-256: `38bf82de62b75968d808e8b907129c3178df40b4fd4502805fc02005b8cdf4d3`.

The build and three-stage QEMU/KVM model VM test passed: actual installation-time
publisher download (no pre-seeded weights), installed inference, and cached model
health after a network-disconnected reboot. The real response used 18 prompt
tokens and produced 14 completion tokens. API authentication, AppArmor/seccomp,
zero effective capabilities, no-new-privileges, memory/swap/process limits,
primary-user credential denial, wrong-length corrupt-weight refusal, and manual
health with inference disabled were checked in that run.

The exported `evidence-model/result.json` SHA-256 is
`c687ae5556d1f98bc3558bcf314990c42838022f6a8c87dae0bc2cb4317e11ee`.
Its adjacent `evidence-files.json` inventories all retained console/QEMU logs.

A separate three-stage overlay run also passed independent-credential recovery
disablement, healthy manual boot with inference disabled, same-length SHA-256
corruption refusal, and healthy model restart after restoring the original
bytes. It used no network and did not modify the original installation fixture.
`evidence-model-recovery/result.json` SHA-256 is
`4f5de51f1a603edae7e746cd16a7234c2e886de8a0d2ef5cc785ca385dd68278`.

Separate virtual-firmware tests passed a signed live boot with Secure Boot
enabled and refusal of an unsigned bootloader copy. These are QEMU/TCG smoke
and negative tests, **not** a Secure Boot installation pass. Their evidence is
under `evidence-secure-boot/` and `evidence-unsigned-refusal/`.

No full platform-suite, update-interruption, or physical-machine pass is asserted
for this image. Earlier image results cannot be inherited by it. The new
`update_powercut_test.py` exists but has not executed; it is not a test pass.

The repository contains later changes not present in this candidate: inference
redirect refusal, download-progress reporting, build-space checks, expanded
model recovery/corruption tests, sparse VM target allocation, and additional
unit tests/documentation. A new build and image-specific evaluation are required
before delivering those changes as tested image functionality.
The overlay recovery test did execute against this candidate; the later
all-in-one five-stage download/recovery runner has not yet run as a whole.

Native Python boundary tests: six passed on Windows and Ubuntu userspace.
Rust boundary tests: 19 passed against the final downloader source, with
warnings denied. The 320-test reference suite
passed on Windows (five skips) and Ubuntu WSL (one skip). These unit/reference
results do not replace image execution or physical qualification.

## Storage and authority dependencies

The current host is low on free C: space. Two checksum-verified duplicate
Windows exports of superseded builds (`124121Z` and `193444Z`) were removed;
their archives remain in their corresponding Docker build volumes. Their
source/metadata/logs were retained. No unrelated container, key, physical disk,
or firmware was changed. At least 30 GiB additional headroom or a designated
alternative build drive has been requested before more builds/full VM runs.
The next sequence-4 build was actually attempted and refused by its preflight
at 4,769,001,472 free bytes, before creating build artifacts. There is no
sequence-4 image or sequence-4 acceptance claim.

The owner must also select the protected Admin/checkpoint deployment design and
approve the production custody inputs. This does not waive the distinct-human,
Ed25519-capable protected signer, trusted-time, recovery and audit requirements
in `docs/PRODUCTION_SIGNING_CUSTODY.md`. Private production credentials must not
be supplied in chat, Git, the image, or test logs.

Remaining **software** includes integrated native finite Admin/policy/durable
effects, protected production authority/anchors/key lifecycle, the complete
governed model-pack and model-lifecycle contracts, qualified desktop/workflows,
and the remaining interruption/adversarial matrix. These are not relabeled as
hardware-only deferrals. Physical firmware, TPM, GPU, damaged-media/power-loss,
suspend/resume and two-board qualification additionally require approved test
machines and image-specific evidence.

See [the operator/build guide](../image/README.md) and
[the implementation plan](../image/BUILD_PLAN.md) for commands and boundaries.
The [machine-readable record](native_model_2026-09-27.json) binds the delivered
image and each exported log inventory to the exact tested identities.
