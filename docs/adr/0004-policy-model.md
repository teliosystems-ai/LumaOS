# ADR-0004: Deny-by-default capability policy

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: security lead, workflow lead, platform lead
- Applies to: G1 policy decisions and every later effect-capable skill

## Context

Model output, workflow plans, local content, and workers are untrusted. Authorization must not be inferred from a model response, a UI label, possession of a path, or an earlier successful check.

## Decision

- Policy is deny by default. Only a typed, narrowly scoped capability grant can authorize an effect.
- Identity comes from the authenticated browser session and verified local IPC peer. Caller-supplied identity is never authoritative by itself.
- Grants bind subject, capability, resource selector, permitted operation, constraints, issuance and expiry, grant version, and revocation state. Wildcard write, device, credential, process-execution, and network grants are prohibited.
- Planning performs a preliminary policy check for an explainable plan. Execution revalidates identity, grant state, target identity, constraints, and lease generation immediately before every effect. Revocation therefore blocks new effects in a prepared or resumed workflow.
- Policy decisions are typed records containing decision ID, policy version/digest, subject, capability, normalized resource, outcome, stable reason code, evaluated constraints, and timestamp. Denials disclose no unnecessary secret or path detail.
- A model may propose data but cannot mint a grant, expand a resource selector, approve its own action, reinterpret a denial, or provide authoritative completion evidence.
- Workers receive task-specific handles or descriptors, never ambient access to source folders, state databases, signing keys, credentials, devices, or the network.
- Generated native code and general shell execution remain disabled until the required microVM or independently qualified constrained runtime passes. A normal container is not equivalent evidence.
- There is no G1 break-glass or silent escalation path. Administrative policy changes are separate authenticated, receipted actions and do not retroactively authorize an in-flight effect.
- `Admin` is the fixed Luma OS governance role described by ADR-0007. It may define roles and delegate only finite, declared administrative activities. The role is not Windows Administrator or Linux `root`, does not grant ambient effect authority, and cannot be assumed by a model or worker.
- Administrative delegation never replaces the ordinary capability check. The delegated actor, target, assignment version, expiry/revocation state, and exact resource grant are revalidated at effect time.
- Missing policy, unavailable broker, unknown capability, stale decision, malformed selector, or failed identity lookup fails closed while preserving model-independent manual recovery access.

## Consequences

- Prepare/run separation is preserved, but preparation never reserves future authority.
- Revocation, capability substitution, stale lease, confused-deputy, path replacement, and restart tests are required.
- User convenience may require more explicit grants; broad implicit consent is rejected.
- Policy records can explain decisions without making receipts tamper-proof.
- Admin role and delegation receipts establish product governance provenance; they do not prove host integrity or production signing-key custody.

## G1 change control

Any ambient authority, model-mediated authorization, wildcard effect capability, generally delegable `Admin` role, cached authorization across an effect boundary, or fail-open behavior requires a superseding ADR and adversarial review.
