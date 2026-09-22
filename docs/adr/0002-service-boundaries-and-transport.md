# ADR-0002: Service boundaries and local transport

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: principal architect, platform lead, security lead
- Applies to: G1 service and platform-adapter contracts

## Context

The developer MVP is a single loopback Python process. G1 introduces resource admission, model supervision, policy decisions, platform adapters, and worker failure. Those responsibilities need stable ownership and authenticated local communication before production code is split into daemons.

## Decision

The following logical services are stable G1 boundaries:

| Boundary | Sole authority |
| --- | --- |
| API/session | Loopback listener, request limits, browser session, public error mapping |
| Workflow coordinator | Typed DAG state, idempotency, cancellation, reconciliation |
| Policy broker | Identity, grants, capability decisions, effect-time revalidation |
| Resource manager | Telemetry, domains, reservations, leases, generations, pressure/quarantine |
| Model supervisor | Pack validation, runtime launch, inference deadlines, worker lifecycle |
| Artifact/effect service | Immutable object commit, versions, exports, append-only receipts |
| Platform adapter | Versioned OS operations behind `T40` conformance behavior |

G1 may group trusted logical services into three production processes without merging their APIs:

- `luma-control`: API/session, workflow coordination, and artifact/effect orchestration;
- `luma-broker`: policy, resource management, and the selected platform adapter; and
- `luma-modeld`: model gateway/supervisor, with each model runtime in a separate constrained worker process.

No service reads another service's private database. Calls that cross a logical boundary use the same versioned request/response contract whether the initial deployment is in-process or out-of-process.

### Transport

- The only browser-facing transport is authenticated same-origin HTTP/1.1 with JSON on literal loopback. Non-loopback binding is unsupported and fails closed.
- Linux internal IPC uses filesystem-permissioned Unix-domain sockets. Messages are a four-byte unsigned big-endian length followed by one UTF-8 JSON envelope, with a fixed maximum size per method.
- Every envelope carries `schema_version`, `request_id`, `caller`, `deadline`, and, where applicable, `idempotency_key`, `lease_id`, and `lease_generation`.
- Servers authenticate the OS peer, compare it with the asserted caller, reject unknown fields on security-sensitive messages, bound lengths before allocation, and reject expired deadlines and stale generations.
- A future Windows adapter may map the same envelopes to ACL-protected named pipes. TCP is not an internal control transport, and WSL/host bridging is a separately authenticated Windows work item.
- Cancellation is an explicit idempotent message. A lost client connection does not imply that an effect was cancelled or rolled back.
- Service discovery is static configuration under administrator control; there is no broadcast, dynamic plugin discovery, or network fallback.

## Consequences

- The Python MVP can remain monolithic while contract tests exercise the frozen boundaries.
- Untrusted model code has no direct browser, grant, source-folder, artifact-store, device, or policy authority.
- Peer credentials are necessary but not sufficient; every effect still requires an application identity and current policy decision.
- Message framing, malformed-message handling, deadlines, cancellation, and restart reconciliation become mandatory G1 tests.

## G1 change control

Adding a listener, shared writable database, implicit caller identity, alternate serialization, or direct worker-to-effect path requires a superseding ADR and security review.
