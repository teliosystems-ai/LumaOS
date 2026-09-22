# ADR-0001: Python reference and Rust production split

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: principal architect, platform lead, security lead
- Applies to: G1 and later production architecture

## Context

The repository contains a dependency-free Python developer MVP. It is valuable as an executable reference for contracts, deterministic tests, and failure cases, but it is not a production privilege boundary. G1 needs a direction that permits rapid contract work without treating a Python prototype or a successful simulator run as production evidence.

## Decision

1. JSON schemas and conformance tests, rather than either language implementation, are the cross-implementation contract authority.
2. `src/luma_os/` remains the Python reference implementation. It may host deterministic fake backends, fixtures, migration/evidence tools, and development-only adapters.
3. Production control, policy, resource-admission, model-supervision, artifact-commit, and platform-adapter paths will be implemented in memory-safe Rust. Rust code will use checked integer arithmetic for all byte, token, time, and resource calculations.
4. Python will not be loaded through FFI into a trusted Rust daemon. A Python component needed at runtime runs as an explicitly untrusted, least-privilege worker behind the versioned local IPC contract.
5. A Python result does not close a production requirement unless the requirement explicitly names the reference implementation. Equivalent Rust behavior must pass the same contract and failure tests on the claimed release tuple.
6. The browser client may remain JavaScript. It is an untrusted presentation client and cannot authorize an effect.
7. Python and Rust implementations must consume the same versioned schemas and produce evidence that identifies implementation, commit, platform, and test environment.

## Consequences

- G1 work can use the Python implementation to stabilize semantics while Rust services are built.
- There will be temporary duplication. Drift is controlled by shared schemas and black-box conformance tests.
- Python-only success remains development evidence, not a production or security certification.
- Language choice does not replace sandboxing, peer authentication, effect-time policy checks, or physical-hardware tests.

## G1 change control

Changing the trusted-language boundary, adding in-process Python plugins, or allowing one implementation to bypass a shared contract requires a superseding ADR, threat-model review, and updated conformance tests.
