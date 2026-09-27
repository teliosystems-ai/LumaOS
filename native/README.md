# Native Ubuntu platform component

This separately built component provides the laboratory installation/recovery
image and Rust platform implementation. It is outside the historical Python
`0.1.0` source-release inventory; that archive and its evidence remain unchanged.

- [Build and native Ubuntu testing guide](image/README.md)
- [Image-specific implementation and evaluation status](evidence/NATIVE_PLATFORM_STATUS_2026-09-27.md)
- [Machine-readable image and evidence identities](evidence/native_platform_2026-09-27.json)
- [Model-enabled implementation and evaluation checkpoint](evidence/NATIVE_MODEL_STATUS_2026-09-27.md)
- [Implementation plan](image/BUILD_PLAN.md)
- [Rust trusted platform source](../rust/luma-platform)

G2 remains in progress. Images are headless and laboratory-signed, not a complete
production OS or hardware certification. The newer model-enabled candidate has
passed actual Qwen3-4B acquisition, inference and offline-reboot testing; see its
separate checkpoint for remaining evaluation and source/image differences.

The original manual-only image was built at `8201727` before tooling moved from
`packaging/native/` to `native/image/`; its archived source and test evidence
retain their original identities. No released binary changed in that move.
