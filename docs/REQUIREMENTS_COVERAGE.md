# Requirements coverage

## Reading this matrix

This document translates the broader Luma OS feasibility, functional, deployment, and testing requirements into the deliberately narrow `0.1.0` developer MVP. It distinguishes implemented runtime evidence from interface simulation and future product intent.

The complete source-ID ownership baseline now lives in
[`requirements/catalog.json`](../requirements/catalog.json). It covers all 288 B1, B2,
and Windows requirement IDs and is validated by `make requirements-check`. The
[staged development plan](DEVELOPMENT_PLAN.md) defines the implementation and test gate
for each stage. Catalog entries marked `reference_partial` are not product acceptance.

Status meanings:

- **Implemented** — present in the reference runtime and expected to have automated evidence.
- **Partial** — a bounded MVP slice exists; the broader requirement is not complete.
- **Documented** — operational or design guidance exists without a full implementation.
- **Deferred** — intentionally outside `0.1.0`.
- **Unsupported** — must not be represented as a current capability.

## Core coverage

| ID | Requirement area | v0.1.0 status | Evidence / boundary |
| --- | --- | --- | --- |
| MVP-001 | Intent-driven user interaction | Partial | Invoice-report request becomes an inspectable prepared workflow; no general natural-language agent |
| MVP-002 | Human-visible plan before effects | Implemented | Separate workflow create/prepare and run operations; workflow/step API records |
| MVP-003 | Explicit approval/capability boundary | Partial | Folder enrollment and explicit run action; not a general policy language |
| MVP-004 | Local-first/offline baseline | Implemented | Standard-library runtime, loopback service, manual workflow works without a model |
| MVP-005 | Explainable/auditable execution | Partial | Persisted steps, errors, provenance, and effect receipts; not certified tamper evidence |
| MVP-006 | Durable workflow state | Implemented | SQLite transactions/WAL and restart-visible state |
| MVP-007 | Idempotent local effects | Implemented | Owner-scoped idempotency key/request hash and unique effect receipts |
| MVP-008 | Scoped local file access | Implemented on POSIX/WSL target | Explicit grant, descriptor-relative no-follow read, root identity and size checks |
| MVP-009 | Semantic file experience | Deferred | Visual product concept exists elsewhere; runtime has scoped paths, not semantic indexing/search |
| MVP-010 | Versioned managed artifacts | Implemented | Application-owned metadata, versions, content hashes, and object storage |
| MVP-011 | Local model integration | Partial | Optional endpoint/configuration/status boundary; weights and model runtime are external |
| MVP-012 | No-model/manual degradation | Implemented | Deterministic vertical slice remains usable when model is absent |
| MVP-013 | Stable local API and schemas | Partial | OpenAPI/JSON schemas provided; compatibility is pre-stable in `0.1.x` |
| MVP-014 | Privacy and permission visibility | Partial | Grant scope/revocation and local state are visible; no complete privacy dashboard or DLP |
| MVP-015 | Ubuntu developer deployment | Implemented | Source runner, unprivileged install, optional systemd user unit for Ubuntu 24.04 |
| MVP-016 | Windows deployment variation | Partial | Windows 11/WSL2 launch path; no native service/installer parity |
| MVP-017 | Dependency-free automated testing | Implemented | Standard-library compile, unittest, metadata, and source-package checks |
| MVP-018 | Operational and security documentation | Implemented | Architecture, threat model, operations, support matrix, security policy |

## Product-scale and deployment requirements

| Requirement | Status | v0.1.0 interpretation |
| --- | --- | --- |
| Model profiles from 4B to 400B | Documented taxonomy only | No weights, inference stack, benchmarks, hardware qualification, or 400B certification |
| Native Ubuntu “OS” experience | Deferred | Local application on Ubuntu, not a distribution, shell, kernel, or boot image |
| Dual boot | Unsupported | No partitioning, bootloader, installer, or recovery tooling |
| Windows native deployment | Deferred | WSL2 is the supported Windows developer route |
| VM deployment | Unsupported | Source may be manually used in a VM; no image/lifecycle/support claim |
| Cluster/datacenter deployment | Unsupported | Single local operator/process only |
| Production hardening | Unsupported | No SLA, HA, remote auth, secrets service, compliance, or security certification |
| External connectors/plugins | Deferred | No dynamic plugin execution or cloud connector boundary |
| Voice and multimodal capture | Deferred | May be represented in UI concept; not a runtime acceptance capability |
| Autonomous background execution | Unsupported | Operator explicitly starts the local workflow |

## Test evidence boundary

The acceptance source for the developer MVP is:

1. `make check` on supported Python versions;
2. CI on Ubuntu and Windows where applicable;
3. schema and release-manifest validation;
4. targeted manual loopback/UI smoke tests; and
5. verification of persistent workflow/artifact/receipt state across restart.

The standalone visual simulator does not call the reference runtime, so simulator clicks, screenshots, or DOM tests are UX evidence only and cannot close a runtime requirement.

## Known gaps before any production discussion

- independent security review and complete negative-test inventory;
- stable authentication/session and API compatibility contract;
- supported backup, migration, retention, and secure-deletion operations;
- packaged UI/schema asset discovery outside source layout;
- accessibility and cross-browser verification;
- performance/resource limits and concurrency characterization;
- model/tool isolation, provenance, and licensing controls;
- remote/multi-user architecture, if ever authorized; and
- installation/recovery engineering appropriate to any true OS distribution.
