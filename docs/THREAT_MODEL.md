# Threat model

## Status

This document covers the Luma OS `0.1.0` local developer MVP and the first
repository-local G2 safety-contract tranche. It identifies engineering controls
and residual risk; it is not a security certification or claim of production
fitness. G2 development is in progress and formal certification is blocked.

## Protected assets

- contents and metadata of explicitly enrolled source folders;
- application-owned artifacts and their version history;
- workflow plans, state, manual inputs, and errors;
- folder grants and revocation state;
- append-only effect receipts;
- optional local model endpoint credentials;
- policy grants, resource leases, and local IPC identities;
- Admin role definitions, assignments, revocations, and delegation receipts;
- model-pack trust metadata and certification records;
- installer inventory/plan/confirmation/attempt records, A/B boot-state records,
  and privileged-helper requests, trust decisions, journals, and receipts; and
- integrity and availability of the operator's machine.

## Trust zones

| Zone | Trust assumption | Boundary |
| --- | --- | --- |
| Operator/browser | One local operator controls the browser profile | HTTP requests into loopback server |
| Luma process | Source checkout and Python interpreter are trusted | OS filesystem and sockets |
| Luma state | Private local directory; operator can still modify it | SQLite/object file reads and writes |
| Enrolled folder | Contents are untrusted, access is explicitly granted | Descriptor-relative read API |
| Optional model | Output and availability are untrusted | Configured local HTTP endpoint |
| G1 model worker | Model/runtime code and output are untrusted | Authenticated local gateway, policy decision, and generation-fenced resource lease |
| Admin control plane | Authenticated product principals may exercise only assigned, declared administrative activities | Versioned assignment, revocation, effect-time policy, and receipt boundary |
| Model-pack store | Content is untrusted until complete inventory, signature, digest, license-use, and runtime-tuple validation | Import/verification boundary |
| Signing service/key store | Private keys are external protected material and never model-accessible | Digest-bound signing request, key-role validation, and signed result boundary |
| Logical internal services | Caller assertions are untrusted without OS-peer authentication | Bounded, deadline-bearing local IPC envelope |
| G2 installer contract | Inventory, confirmation, and requested target are untrusted until bound and revalidated | Pure preflight/authorization/capability/journal boundary; injected discovery and executor |
| G2 boot-state contract | Restored state and external boot/health/data claims are untrusted | Pure authenticated, monotonic-anchored transition boundary with injected evidence oracles |
| G2 privileged-helper contract | Wire requests and caller assertions are untrusted | Closed typed actions with injected peer authentication, authority, device/certificate, confinement, journal, and executor boundaries |
| External network | Untrusted and unnecessary for default operation | No supported listener or dependency |

The host OS, Python runtime, browser, WSL distribution, and administrator/root account are outside the security boundary. A compromise of any of them can bypass application controls.

The Luma OS `Admin` role is not an operating-system administrator. It governs
finite product activities and signing-role assignments but cannot make a
compromised Windows Administrator or Linux `root` account safe.

## Threat actors

- malicious content placed in an enrolled folder;
- a local webpage trying to call the loopback service;
- accidental operator actions or duplicated requests;
- an untrusted or compromised model endpoint;
- another unprivileged local process under the same user account;
- a contributor introducing unsafe defaults or supply-chain dependencies; and
- an attacker who persuades an operator to expose the loopback process.

## Threats and controls

| Threat | Relevant controls | Residual risk |
| --- | --- | --- |
| Path traversal outside a grant | Reject absolute/empty/dot components; POSIX descriptor-relative traversal; Windows reserved-name, canonical-containment, reparse, and identity checks | Windows lacks the POSIX `openat` boundary and inherited DACLs are not applied or audited by this MVP |
| Symlink, junction, or rename/swap attack | POSIX `O_NOFOLLOW` and directory descriptors; Windows pre/open/post identity fencing and reparse rejection; root identity and regular-file checks | A hostile same-user process may still attack broader state or availability; certification requires platform-native race and ACL testing |
| Oversized or malformed source file | Configured byte limit, structured parsing, validation errors, bounded request bodies | Complex data may consume CPU within allowed size |
| Unauthorized local website calls API | Same-origin UI, session token/cookie, origin/host validation, loopback binding | Browser extensions or a compromised browser are out of scope |
| DNS rebinding or remote reachability | Literal loopback default; reject non-loopback without explicit unsafe override | Operator can deliberately defeat the protection; such use is unsupported |
| Cross-site request forgery | Local session binding and mutating-request checks | Browser/profile compromise bypasses application controls |
| Prompt/model injection | Model output treated as untrusted; deterministic validation and policy remain authoritative | A future adapter may introduce unsafe use if it bypasses validation |
| Model endpoint exfiltrates data | No endpoint by default; operator configuration required; minimize sent context | Configured endpoint is a separate trust decision and may retain prompts |
| Duplicate or replayed effects | Owner-scoped idempotency keys, stored request hashes, state transitions, receipts | Incorrectly chosen keys can cause intended requests to collide |
| Partial write or process crash | SQLite transactions/WAL, atomic object commits, durable workflow state | Power/filesystem failure can still corrupt local storage; backups remain necessary |
| Receipt tampering | Application-level append-only triggers; receipts linked to workflow/effect | Not externally signed; filesystem owner/root can alter or replace database |
| Leakage through logs/errors | Structured public errors, no secrets in repository, local-only operation | Source paths and workflow metadata may still be sensitive on the local account |
| Malicious repository change | CI compile/tests/manifest checks, dependency-free runtime, review guidance | Maintainer credentials and GitHub platform remain external risks |
| Installer overwrites user files | User-only exact paths, install marker, refuse existing unmarked launcher, no sudo | A user can force unsafe manual changes outside scripts |
| WSL boundary confusion | WSL2 Ubuntu is documented runtime; no automatic distribution install/elevation | Windows host administrators and Windows-mounted file semantics are out of scope |
| Model-pack or template tampering | Canonical strict manifest, detached Ed25519 verifier boundary, complete declared inventory, SHA-256 checks, exact runtime tuple, and purpose/lifecycle-bound trust-key validity and revocation checks | Production signing custody and real protected key storage are not established; model safety is not implied |
| Resource overcommit or stale allocation | Checked 64-bit arithmetic, atomic multi-domain admission, generation-fenced leases, pressure and quarantine state | Prototype accounting is not an OS cgroup/GPU allocation or hardware qualification |
| Capability substitution or post-approval revocation | Typed exact grants, stable denial reasons, policy digest/version, effect-time revalidation | The existing MVP API is not yet fully mediated by the general broker |
| Admin role abuse or delegation expansion | Fixed non-ordinary-delegable Admin role; finite activity catalog; authenticated, versioned, expiring/revocable assignments; hash-linked receipts; ordinary effect policy still applies | A compromised Admin principal can make authorized governance changes; multi-party production approval and protected custody remain certification work |
| Signing-key disclosure or unauthorized signing | Keys remain outside Git/runtime/model context; separate lab and production roots; Admin assigns declared signing activities; digest/key/actor-bound receipts; revoked or wrong-role keys fail closed | Protected production key storage, named human custody, recovery, and ceremony evidence are deferred to final certification |
| Internal IPC spoofing or memory exhaustion | Four-byte bounded framing, strict fields, asserted-caller/peer comparison, deadlines, lease generations | Real Unix peer-credential plumbing and process isolation remain unimplemented |
| Installer target substitution or stale confirmation | Stable disk identity, immutable inventory digest, plan/confirmation binding, effect-time revalidation, exact device capability, replay and in-doubt journal rules | Pure non-destructive contract only; no real disk discovery, OS device handle, installer executor, or destructive race testing |
| A/B state rollback, fork, or false health acknowledgement | Authenticated state, monotonic anchor, hash-chained operations, generation/fence ownership, trusted boot observations, attempt-bound health, and fallback-readability oracle | Pure state machine only; no firmware variables, slot I/O, UKI/dm-verity/LUKS, physical boot, or induced power loss |
| Privileged-helper argument, authority, device, or confinement substitution | Closed schemas/actions, current peer and deadline checks, exact authority/device/driver binding, trusted confinement attestation, durable idempotency and reconciliation | Injected test doubles only; no privileged process or cgroup/AppArmor/seccomp/KVM/OS peer-credential enforcement |
| Cancellation races | Workflow state checks before effect commits and DAG cooperative cancellation/checkpoint rules | A handler that ignores the contract can still perform an external effect; production workers require isolation and termination tests |

## High-risk extension points

The following changes require explicit design and security review before merge:

- allowing any non-loopback bind;
- adding a remote model or tool endpoint;
- adding write access to enrolled source folders;
- executing generated shell commands, code, macros, or office documents;
- adding OAuth tokens, cloud credentials, or secret storage;
- adding plugin discovery or dynamic imports;
- accepting archive extraction or recursive directory ingestion;
- changing model-pack canonicalization, signature trust, or certification-state semantics;
- making `Admin` generally delegable, adding wildcard administrative activities, or allowing product administration to imply host privilege;
- exposing signing material to the model/runtime or removing actor/input/key binding from signing receipts;
- allowing internal messages without authenticated OS-peer binding or bounded framing;
- allowing a backend to allocate or infer without a current generation-fenced lease;
- serving multiple users or accepting an asserted remote identity; and
- replacing append-only local receipts with claims of compliance/audit certification.

## Security test expectations

Automated tests should cover:

- `..`, absolute path, null-byte, and encoded traversal attempts;
- symlinked roots, intermediate directories, and final files;
- grant ownership, revocation, and root identity changes;
- oversized inputs and request bodies;
- invalid state transitions and idempotency-key reuse with a different payload;
- repeated run requests and process restart recovery;
- append-only receipt enforcement;
- malformed JSON/CSV and formula-injection-safe output;
- session, Host, and Origin rejection; and
- optional model outage or invalid output without loss of manual controls;
- model-pack signature, digest, undeclared-file, path, license, tuple, wrong-purpose, not-yet-valid, expired-key, and revoked-key tampering;
- Admin bootstrap, invalid/expired/revoked delegation, role substitution, unauthorized activity, assignment replay, and receipt-chain tampering;
- signing-role separation, wrong-key, revoked-key, lab/production-root confusion, and proof that model-visible processes cannot read key material;
- capability substitution, grant revocation, stale lease, resource overflow,
  concurrent admission, pressure, and quarantine behavior;
- malformed/oversized IPC frames, caller/peer mismatch, expired deadlines, and
  partial lease tokens; and
- cancellation and restart at each checkpoint/effect boundary;
- installer inventory/plan/confirmation/revalidation substitution, replay,
  expiry, exact-capacity, device-capability, and in-doubt attempt cases;
- A/B state authentication, monotonic rollback/fork, inactive-slot,
  anti-downgrade, boot observation, health/data acknowledgement, trial failure,
  and power-loss reconciliation transitions; and
- privileged-helper malformed request, peer/authority/device/certificate/
  confinement substitution, expiry/revocation, replay, concurrency, and restart
  reconciliation cases.

## Data retention and deletion

The MVP stores state until the operator removes the selected `LUMA_HOME` directory while the process is stopped. Revoking a grant stops new reads but does not erase existing artifacts, receipts, or workflow history. There is no certified secure-erasure function. Backups and copied release/state directories may retain data independently.

## Not protected or certified

This release does not claim sandboxing, malware scanning, encrypted local
storage, production key management or custody, tamper-evident external audit,
multi-user isolation, high availability, disaster recovery,
privacy-regulation compliance, boot security, model safety, 400–405B operation,
or cluster security. In particular, the G2 contracts do not claim real disk or
boot effects, UKI/dm-verity/LUKS, cgroup/AppArmor/seccomp/KVM enforcement, a
privileged daemon, or operating-system peer authentication. A 450B profile is
outside the current governing requirement range and would require requirements
change control.

Report suspected vulnerabilities using [SECURITY.md](../SECURITY.md), not a public issue.
