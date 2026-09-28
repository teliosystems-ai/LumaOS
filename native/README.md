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
- [Rust trusted platform source](../rust/luma-platform)

G2 remains in progress. Images are headless and laboratory-signed, not a complete
production OS or hardware certification. The sequence-4 artifacts and VM disks
are on the owner-designated D: drive. The image has passed full platform regression, Qwen3-4B
installer acquisition/inference/recovery, Qwen3-1.7B installed configuration and
offline inference, and the selected guest update-interruption/retry scenario.
See the current checkpoint for exact image/evidence identities, the separate
Secure Boot scope, source/image differences and remaining implementation work.

The original manual-only image was built at `8201727` before tooling moved from
`packaging/native/` to `native/image/`; its archived source and test evidence
retain their original identities. No released binary changed in that move.
