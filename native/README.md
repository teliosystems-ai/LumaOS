# Native Ubuntu platform component

This separately built component provides the laboratory installation/recovery
image and Rust platform implementation. It is outside the historical Python
`0.1.0` source-release inventory; that archive and its evidence remain unchanged.

- [Build and native Ubuntu testing guide](image/README.md)
- [Image-specific implementation and evaluation status](evidence/NATIVE_PLATFORM_STATUS_2026-09-27.md)
- [Machine-readable image and evidence identities](evidence/native_platform_2026-09-27.json)
- [Implementation plan](image/BUILD_PLAN.md)
- [Rust trusted platform source](../rust/luma-platform)

G2 remains in progress. The available image is headless and manual-only, with
laboratory signing, not a complete production OS or hardware certification.
The recorded image was built at `8201727` before tooling moved from
`packaging/native/` to `native/image/`; its archived source and test evidence
retain their original identities. No released binary changed in that move.
