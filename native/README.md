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
- [Current sequence-18 native Ubuntu test image and installation guide](evidence/G2_NATIVE_DESKTOP_CANDIDATE_18_2026-10-28.md)
- [Current sequence-18 build, offline verification, VM and optical evidence](evidence/candidate18_execution_2026-10-28.json)
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
stays on C:. The [current image handoff](evidence/G2_NATIVE_DESKTOP_CANDIDATE_18_2026-10-28.md)
identifies the sequence-18 desktop candidate exported on 2026-10-28. Its fourteen
offline image checks and software-emulated Secure Boot live-startup/final-storage
teardown test of the disk image passed. Its optical ISO now boots under emulated
Secure Boot to the verified root, but its signed optical smoke failed four gated
checks: the UTC recovery keeper failed with `226/NAMESPACE`, and live media
verification refused for lack of RAM-backed staging in a 6-GiB guest. Do not
use that ISO for installation. Both causes are fixed in source at `e29187b`. They
need a new signed build, and live verification of the desktop payload needs at
least 8 GiB of RAM. Installation, graphical/installed security
and recovery, physical TPM and production qualification remain open. It is native Ubuntu
media, not a Windows image or complete G3 release. Subsequent G3/GWIN0 source
changes require their own identified builds and tests. The
[sequence-17](evidence/G2_NATIVE_DESKTOP_CANDIDATE_17_2026-10-27.md) and
[sequence-16](evidence/G2_NATIVE_DESKTOP_CANDIDATE_16_2026-10-19.md) handoffs
remain available. The
[historical export checkpoint](evidence/G2_BROKER_CLIENT_2026-10-01.md)
identifies the earlier sequence-11 candidate and its source/image differences.
Desktop and fresh 4B model acceptance remain pending. Earlier sequence-4 model
and sequence-10 recovery-regression passes do not attest this new image.
Use the software completion register above for outstanding implementation work.

The original manual-only image was built at `8201727` before tooling moved from
`packaging/native/` to `native/image/`; its archived source and test evidence
retain their original identities. No released binary changed in that move.
