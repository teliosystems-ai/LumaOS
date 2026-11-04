# Native Ubuntu platform component

This separately built component provides the laboratory installation/recovery
image and Rust platform implementation. It is outside the historical Python
`0.1.0` source-release inventory; that archive and its evidence remain unchanged.

- [Build and native Ubuntu testing guide](image/README.md)
- [Image-specific implementation and evaluation status](evidence/NATIVE_PLATFORM_STATUS_2026-09-27.md)
- [Machine-readable image and evidence identities](evidence/native_platform_2026-09-27.json)
- [Model-enabled implementation and evaluation checkpoint](evidence/NATIVE_MODEL_STATUS_2026-09-27.md)
- [External-drive build and current evaluation checkpoint](evidence/NATIVE_EXTERNAL_STATUS_2026-09-28.md)
- [Exact-image native Ubuntu test handoff](evidence/TEST_IMAGE_2026-09-28.md)
- [Implementation plan](image/BUILD_PLAN.md)
- [Current G2 software completion register](G2_SOFTWARE_STATUS.md)
- [Current sequences 19 and 20 download-only owner acceptance guide](evidence/NATIVE_DOWNLOAD_ACCEPTANCE_19_20_2026-11-03.md)
- [Current sequence-20 build, offline verification, USB-class and virtio VM and download-set evidence](evidence/candidate20_execution_2026-11-03.json)
- [Previous sequence-19 native Ubuntu test image and installation guide](evidence/G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md)
- [Previous sequence-19 build, offline verification, VM and optical evidence](evidence/candidate19_execution_2026-10-28.json)
- [Previous sequence-18 native Ubuntu test image and installation guide](evidence/G2_NATIVE_DESKTOP_CANDIDATE_18_2026-10-28.md)
- [Previous sequence-17 native Ubuntu test image and installation guide](evidence/G2_NATIVE_DESKTOP_CANDIDATE_17_2026-10-27.md)
- [Previous sequence-16 native Ubuntu test image and installation guide](evidence/G2_NATIVE_DESKTOP_CANDIDATE_16_2026-10-19.md)
- [G3 and Windows delivery development](../docs/G3_GWIN0_DELIVERY.md)
- [Historical sequence-13 assembly resume](evidence/G2_IMAGE_RESUME_2026-10-13.md)
- [Selected local TPM2 Admin design and future external installer](LOCAL_TPM2_ADMIN.md)
- [Native TPM checkpoint evaluation](evidence/NATIVE_TPM_STATUS_2026-09-28.md)
- [Installer TPM admission and VM-fixture evaluation](evidence/NATIVE_TPM_ADMISSION_2026-09-28.md)
- [Source-level storage crash-safety evaluation](evidence/NATIVE_STORAGE_STATUS_2026-09-28.md)
- [Rust trusted platform source](../rust/luma-platform)

G2 remains in progress. Headless and candidate GNOME/Wayland desktop images are
laboratory-signed, not a complete production OS or hardware certification.
Bulk builds, images and VM disks are on the owner-designated D: drive; source
stays on C:. The [current owner handoff](evidence/NATIVE_DOWNLOAD_ACCEPTANCE_19_20_2026-11-03.md)
covers the sequence-20 desktop candidate, exported on 2026-11-03 from `e9a11aa`,
together with sequence 19. No optical drive is used: every image installs
from a downloaded file. Sequence 20's fourteen offline image checks passed. Its
raw disk image booted under emulated Secure Boot in an 8-GiB guest, once as a
removable USB device on xHCI and once as a virtio disk, and passed all ten
required and all five gated checks each time. Download sets for both sequences
are laid out on D: and pinned in the handoff. Agents do not upload them, and
the owner chooses the download location. Live verification or installation of
the desktop payload needs at least 8 GiB of RAM. Installation, the 19-to-20
update, physical USB boot, graphical/installed security and recovery,
physical TPM and production qualification remain open. It is native Ubuntu
media, not a Windows image or complete G3 release. Subsequent G3/GWIN0 source
changes require their own identified builds and tests. The
[sequence-19 handoff](evidence/G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md),
whose signed ISO passed its optical smoke, and the
[sequence-18](evidence/G2_NATIVE_DESKTOP_CANDIDATE_18_2026-10-28.md),
[sequence-17](evidence/G2_NATIVE_DESKTOP_CANDIDATE_17_2026-10-27.md) and
[sequence-16](evidence/G2_NATIVE_DESKTOP_CANDIDATE_16_2026-10-19.md) handoffs
remain available; do not use the sequence-18 ISO. The
[historical export checkpoint](evidence/G2_BROKER_CLIENT_2026-10-01.md)
identifies the earlier sequence-11 candidate and its source/image differences.
Desktop and fresh 4B model acceptance remain pending. Earlier sequence-4 model
and sequence-10 recovery-regression passes do not attest this new image.
Use the software completion register above for outstanding implementation work.

The original manual-only image was built at `8201727` before tooling moved from
`packaging/native/` to `native/image/`; its archived source and test evidence
retain their original identities. No released binary changed in that move.
