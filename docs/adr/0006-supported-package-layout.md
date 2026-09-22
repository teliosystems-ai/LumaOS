# ADR-0006: Repository and installed package layout

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: release engineer, principal architect, platform lead
- Applies to: G1 source/package work and later Ubuntu packaging

## Context

Version `0.1.0` is intentionally distributed as a checksumed source archive because its runtime assets live at repository root. G1 needs stable names and a production destination without implying that an unfinished wheel, Debian package, or OS image is supported today.

## Decision

### Repository layout

```text
src/luma_os/       Python reference implementation
rust/              future Cargo workspace for production services/libraries
schemas/           normative public and IPC schemas
web/               browser client source
tests/             shared black-box, contract, and reference tests
packaging/         platform packaging and service definitions
docs/              ADRs, operations, requirements, evidence, and registers
examples/          public synthetic fixtures only
```

The product/package prefix is `luma-os`; `llmos-*` names appearing in source requirements are treated as examples until explicitly mapped. The reserved production executable names are `luma-control`, `luma-broker`, and `luma-modeld`. Public schema identifiers and CLI/API names cannot be renamed after G1 without a versioned compatibility path.

### Installed Ubuntu layout

| Content | Location |
| --- | --- |
| Executables | `/usr/libexec/luma-os/` with command links in `/usr/bin/` only where needed |
| Read-only UI and schemas | `/usr/share/luma-os/` |
| Administrator configuration and public trust roots | `/etc/luma-os/` |
| Durable service state and imported packs | `/var/lib/luma-os/` |
| Volatile sockets, leases, and process state | `/run/luma-os/` |
| Service logs | system journal; no secret-bearing private log tree by default |

Configuration, mutable state, model assets, keys, and private fixtures never live beside executables or under the source tree. Runtime asset lookup uses an explicit configured or compiled installation root, never the current working directory.

### Support boundary

- The checksumed source archive remains the only supported `0.1.0` distribution.
- `pyproject.toml` remains developer metadata; a wheel is unsupported until UI, schemas, and examples are deliberately packaged and installed-path tests pass.
- G1 may produce development-only Cargo artifacts and an unsigned Ubuntu package spike. Neither is a supported product package or release image.
- Signed Debian packages, service users, boot integration, A/B images, install/upgrade/remove behavior, and offline media require later gate evidence.
- Model packs, private data, signing secrets, and licensed third-party assets remain external and are referenced by immutable digest.

## Consequences

- Current source-run behavior remains valid while production code can be added without hiding asset-location assumptions.
- Package and executable names are stable inputs to G1 contracts.
- Development package success cannot be cited as installer, boot, recovery, or production-release evidence.

## G1 change control

Changing the product prefix, executable names, authoritative schema locations, mutable-state separation, or claiming an additional distribution format requires a superseding ADR plus clean-install, upgrade, removal, and reproducibility evidence.
