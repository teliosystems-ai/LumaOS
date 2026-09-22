# Changelog

All notable changes to Luma OS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Complete staged development plan for Ubuntu, WSL2, VM, dual-boot, large-model,
  distributed, and microkernel research tracks.
- Machine-readable ownership for all 288 B1, B2, and Windows requirement IDs,
  with a dependency-free validation and reporting command.
- Real artifact-version history and version-specific content reads.
- Folder-grant revocation through the local API and browser workspace.
- Complete OpenAPI route coverage and closed-schema validation against runtime
  response objects.

### Changed

- New browser, HTTP API, and CLI enrollments are explicitly read-only; workflow outputs remain in
  managed artifact storage rather than implying writes to source folders.
- Workflow execution now uses cross-process run leases and effect fences so live
  work is not misclassified as interrupted and cancellation cannot be followed
  by a later artifact commit.

### Planned

- Gather developer feedback on intent planning, policy gates, and local operations.
- Stabilize the MVP's internal event and tool-adapter interfaces before declaring them public.

## [0.1.0] - 2026-09-22

### Added

- Initial dependency-free Python developer MVP.
- Local intent-to-workflow reference path with inspectable plans and explicit capability decisions.
- Local browser workspace connected to real grant-scoped reads, durable artifacts, and effect receipts.
- Standard-library unit and integration checks.
- Ubuntu 24.04 and Windows 11/WSL2 developer launch paths.
- Unprivileged user-install and optional systemd user-service scaffolding.
- Architecture, threat model, operations, support matrix, requirements coverage, and roadmap documentation.
- GitHub CI, issue templates, release validation, and deterministic source packaging.

### Security

- Local-only defaults, no bundled model weights, no privileged installer, and documented trust boundaries.

[Unreleased]: https://github.com/teliosystems-ai/LumaOS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/teliosystems-ai/LumaOS/releases/tag/v0.1.0
