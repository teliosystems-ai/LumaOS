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
- Model-pack schema v2 with exact total/active parameter counts, ordered model
  shards, required capabilities, and runtime-bound CPU/CUDA installation
  profiles, plus an immutable multi-profile catalog and hardware-fit contract
  that recognizes governed ranges through 405B.
- Explicit install-time `manual-only`, CPU, and CUDA selection bound into the
  installer plan and confirmation, with storage/load/serve/context checks,
  same-device accelerator qualification, effect-time revalidation, and no
  silent profile or remote fallback.
- A digest-pinned Qwen3-4B Q4_K_M development smoke on native Windows CUDA and
  Ubuntu WSL CPU through direct llama.cpp and authenticated Luma gateway paths;
  the asset remains external, unsigned, non-redistributed, and non-certifying.
- A non-destructive installer safety contract with immutable inventory,
  exact-capacity preflight, confirmation, revalidation, device-capability, and
  durable attempt-journal boundaries.
- A pure A/B boot-state model with authenticated state, monotonic anchoring,
  generation/fence checks, health and data-readability evidence, trial failure,
  and power-loss reconciliation transitions.
- Typed privileged-helper, authority, device, driver-certificate, confinement,
  idempotency, and reconciliation contracts.
- SQLite-backed request and privileged-effect ledgers with keyed record
  integrity, bounded capacity and clock-rollback checks, owner/generation
  fencing, `PREPARED`/`APPLYING`/`COMPLETED`/`FAILED_UNKNOWN` crash semantics,
  completion binding, and no automatic redispatch of an ambiguous effect.
- Mandatory current-state validation around durable preparation, a fail-fast
  `APPLYING` compare-and-swap immediately before typed adapter entry, and
  high-entropy safe-handle capabilities whose raw tokens are not persisted;
  the ledger stores keyed commitments, while the authorization digest relies
  on the mandatory 256-bit CSPRNG contract. The expanded six-module G2
  safety/model boundary has 96 tests passing on native Windows and Ubuntu WSL
  under normal and optimized Python.

The G2 work above is development-contract evidence only. It does not perform a
real installation or boot and does not establish UKI, dm-verity, LUKS, cgroup,
AppArmor, seccomp, KVM, operating-system peer credentials, native ACL/DACL
enforcement, physical power-loss behavior, protected integrity-key custody, or
rollback-resistant external anchoring.

### Fixed

- Close the SQLite migration connection after initialization.
- Build deterministic source archives from canonical committed blobs and an
  explicit executable-file policy, excluding dirty or untracked host inputs
  and runtime-dependent compression output.
- Assign the `A077` platform-adapter requirement consistently to G1.
- Revalidate current authority after the durable `APPLYING` transition and
  restore a rejected, proven-not-applied attempt to `PREPARED` before retry.
- Preserve effect-ledger capacity exhaustion as a known-not-applied helper
  result instead of incorrectly fencing the request as outcome-unknown.

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
