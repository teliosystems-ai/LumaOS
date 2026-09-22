# ADR-0007: Admin governance, delegation, and signing custody

- Status: Accepted for development; production custody deferred to final certification
- Date: 2026-09-22
- Decision owners: product owner, security lead, release engineer
- Applies to: administrative role governance, activity delegation, and signing authorization

## Context

Luma OS needs one accountable authority that can establish required roles and
assign administrative work without granting workers, models, or ordinary users
ambient authority. The selected governance role is `Admin`.

The word `Admin` is a Luma OS control-plane role. It is not the Windows
Administrator account, Linux `root`, a shared operating-system account, or an
implicit right to bypass policy. A compromised host administrator remains
outside the application's security boundary.

## Decision

### Root governance role

- `Admin` is the fixed product governance role. It defines finite roles,
  assigns or revokes them, and delegates declared administrative activities.
- A role or assignment is versioned, time-bounded where appropriate, and
  linked to an authenticated product principal. Every mutation produces an
  append-only, hash-linked receipt.
- `Admin` itself is not delegated as an ordinary role. Establishing or
  recovering an Admin principal is a separately authenticated bootstrap or
  recovery procedure.
- Delegation names an activity from a versioned catalog. It never grants an
  undeclared activity, wildcard capability, model-selected target, or silent
  escalation.
- Delegation does not replace effect authorization. The acting principal must
  still hold the exact capability and resource grant, and policy is checked
  again immediately before the effect.
- Models, model workers, generated code, and ordinary skills cannot act as
  `Admin`, assign roles, approve their own requests, or access signing keys.

### Signing custody

- `Admin` governs signing roles and can assign declared signing activities to
  authenticated custodians. Lab, release, recovery, and production signing
  are distinct activities and trust roots.
- Signing private keys and recovery material remain outside Git, build
  archives, logs, model packs, and model-accessible processes. An Admin
  authorization does not expose or export raw key material.
- Each signing operation binds the acting principal, role assignment,
  activity and signing purpose, input digest, key identifier, policy version,
  result digest, and timestamp to a receipt. Expired, revoked, wrong-role, or
  wrong-purpose assignments and trust keys fail closed.
- Development may use a single local Admin principal and a clearly marked
  non-production lab key. That is development evidence only.
- Production signing still requires named human custodians, approved protected
  key storage, recovery, rotation and revocation procedures, separation from
  lab trust roots, and a retained verification exercise. Those controls are
  deferred to final OS testing and certification and cannot be inferred from
  the product role model.

## Consequences

- One governance role can assign every required product activity while the
  delegated authority remains explicit, finite, revocable, and auditable.
- Operating-system privilege and product authorization remain separate.
- The development governance decision is closed; operational production
  custody is intentionally still a certification blocker.
- A future multi-person approval rule can be added to selected production
  signing activities without changing the deny-by-default effect boundary.

## Change control

Changing the root role name or semantics, making `Admin` generally delegable,
allowing wildcard or model-mediated delegation, exposing raw keys to the
runtime, or treating a role receipt as proof of production key custody requires
a superseding ADR and security review.
