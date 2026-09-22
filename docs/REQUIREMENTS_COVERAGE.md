# Requirements coverage

## Reading this matrix

This document translates the broader Luma OS feasibility, functional, deployment, and testing requirements into the deliberately narrow `0.1.0` developer MVP. It distinguishes implemented runtime evidence from interface simulation and future product intent.

The three designated governing DOCX inputs are present under `docs/Requirements`, pinned by byte size and SHA-256, and deterministically parsed into the 288-entry registry. Source text, acceptance/reference fields, and locators are verified. Gate, owner, profile, and environment assignments remain plan-derived, and source traceability is not product acceptance. See [GOVERNING_REQUIREMENTS_SOURCES.md](GOVERNING_REQUIREMENTS_SOURCES.md).

G0 and G1 have two explicit status axes: their repository/local development scope is complete with recorded deferrals, while formal OS certification is blocked until the deferred physical-hardware, model, signing, security, recovery, and performance evidence exists.

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
| MVP-003 | Explicit approval/capability boundary | Partial | Folder enrollment, explicit run action, deny-by-default typed policy, and fixed Admin role with finite receipted delegation; the MVP API is not yet fully mediated by that broker and Admin is not ambient effect authority |
| MVP-004 | Local-first/offline baseline | Implemented | Standard-library runtime, loopback service, manual workflow works without a model |
| MVP-005 | Explainable/auditable execution | Partial | Persisted steps, errors, provenance, and effect receipts; not certified tamper evidence |
| MVP-006 | Durable workflow state | Implemented | SQLite transactions/WAL and restart-visible state |
| MVP-007 | Idempotent local effects | Implemented | Owner-scoped idempotency key/request hash and unique effect receipts |
| MVP-008 | Scoped local file access | Implemented on POSIX/WSL target | Explicit grant, descriptor-relative no-follow read, root identity and size checks |
| MVP-009 | Semantic file experience | Deferred | Visual product concept exists elsewhere; runtime has scoped paths, not semantic indexing/search |
| MVP-010 | Versioned managed artifacts | Implemented | Application-owned metadata, versions, content hashes, and object storage |
| MVP-011 | Local model integration | Partial | Signed model-pack and purpose/lifecycle trust-key contracts, runtime profile, resource lease, and authenticated local gateway; pinned Qwen3-1.7B ran through llama.cpp on Windows CUDA, Ubuntu WSL CPU, and the actual Luma gateway, but is an unsigned development asset below the governed 4–6B range |
| MVP-012 | No-model/manual degradation | Implemented | Deterministic vertical slice remains usable when model is absent |
| MVP-013 | Stable local API and schemas | Partial | OpenAPI/JSON schemas provided; compatibility is pre-stable in `0.1.x` |
| MVP-014 | Privacy and permission visibility | Partial | Grant scope/revocation and local state are visible; no complete privacy dashboard or DLP |
| MVP-015 | Ubuntu developer deployment | Implemented with certification deferral | Source runner, unprivileged install, and optional systemd user unit; current development uses Ubuntu 26.04 WSL, while native Ubuntu 24.04 physical-board certification is deferred |
| MVP-016 | Windows deployment variation | Partial | Current native Windows is a development/smoke lane and WSL2 is the Linux development lane; no native service/installer, Windows broker, VM, or dual-boot parity |
| MVP-017 | Dependency-free automated testing | Implemented | Standard-library compile, unittest, metadata, verified governing-source/registry checks, gate report, and source-package checks |
| MVP-018 | Operational and security documentation | Implemented | Architecture, threat model, operations, support matrix, security policy |

## Product-scale and deployment requirements

| Requirement | Status | v0.1.0 interpretation |
| --- | --- | --- |
| A1 4–6B compact control model | Deferred to formal certification | The selected 1.7B development baseline does not satisfy the governed range; signed candidate comparison and two-board evidence are required |
| 400–405B placement/load and A2 profiles | Documented taxonomy and deferred hardware test | No suitable hardware/assets or large-model certification; 450B is outside the governing sources and requires change control |
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

The current development record additionally includes a digest-pinned 1.7B
model smoke on native Windows CUDA and Ubuntu WSL CPU and an authenticated
loopback call through the Luma resource, policy, lease, and gateway path. This
is real development execution but remains non-closing evidence.

The standalone visual simulator does not call the reference runtime, so simulator clicks, screenshots, or DOM tests are UX evidence only and cannot close a runtime requirement.

## Known gaps before any production discussion

- independent security review and complete negative-test inventory;
- stable authentication/session and API compatibility contract;
- production-grade backup, downgrade migration, policy retention, and secure-deletion operations beyond the bounded verified developer export/restore and orphan-object cleanup;
- packaged UI/schema asset discovery outside source layout;
- accessibility and cross-browser verification;
- performance/resource limits and concurrency characterization;
- model/tool isolation, provenance, and licensing controls;
- protected production signing custody despite the accepted Admin governance model;
- remote/multi-user architecture, if ever authorized; and
- installation/recovery engineering appropriate to any true OS distribution.
