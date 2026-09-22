# Changelog

All notable changes to Luma OS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Governing-requirements source records that explicitly block source-derived
  traceability until the three approved inputs and their digests are available.
- Verified state export/restore, transactional schema migration, and audited
  orphan-object retention controls.
- Effect-time workflow cancellation fencing and grant-revocation/concurrency
  regression coverage.
- A provisional 288-ID requirement registry, deterministic gate report, G0/G1
  blocker/evidence records, architecture decisions, and initial lab registers.
- Checked resource admission and telemetry, deterministic fake inference,
  runtime-placement and isolated-cache contracts, and an authenticated local
  inference gateway with no remote fallback.
- Deny-by-default policy, typed-DAG checkpoint/recovery, versioned Linux/fake
  platform adapters, and strict signed model-pack verification contracts.
- Bounded local-IPC framing with strict envelopes, peer-identity checks,
  deadlines, and stale-lease fields.

### Fixed

- Close the SQLite migration connection after initialization.
- Exclude untracked working-tree files from deterministic source archives.
- Assign the `A077` platform-adapter requirement consistently to G1.

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

[Unreleased]: https://github.com/teliosystems/luma-os/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/teliosystems/luma-os/releases/tag/v0.1.0
