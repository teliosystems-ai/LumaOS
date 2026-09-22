# Threat model

## Status

This document covers the Luma OS `0.1.0` local developer MVP. It identifies engineering controls and residual risk; it is not a security certification or claim of production fitness.

## Protected assets

- contents and metadata of explicitly enrolled source folders;
- application-owned artifacts and their version history;
- workflow plans, state, manual inputs, and errors;
- folder grants and revocation state;
- append-only effect receipts;
- optional local model endpoint credentials; and
- integrity and availability of the operator's machine.

## Trust zones

| Zone | Trust assumption | Boundary |
| --- | --- | --- |
| Operator/browser | One local operator controls the browser profile | HTTP requests into loopback server |
| Luma process | Source checkout and Python interpreter are trusted | OS filesystem and sockets |
| Luma state | Private local directory; operator can still modify it | SQLite/object file reads and writes |
| Enrolled folder | Contents are untrusted, access is explicitly granted | Descriptor-relative read API |
| Optional model | Output and availability are untrusted | Configured local HTTP endpoint |
| External network | Untrusted and unnecessary for default operation | No supported listener or dependency |

The host OS, Python runtime, browser, WSL distribution, and administrator/root account are outside the security boundary. A compromise of any of them can bypass application controls.

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
| Path traversal outside a grant | Reject absolute/empty/dot components; open descriptor-relative; verify root device/inode | Platform semantics vary; native Windows is not the primary secure file-access target |
| Symlink or rename/swap attack | `O_NOFOLLOW`, directory descriptors, root identity check, regular-file check | A hostile same-user process may still attack broader state or availability |
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

## High-risk extension points

The following changes require explicit design and security review before merge:

- allowing any non-loopback bind;
- adding a remote model or tool endpoint;
- adding write access to enrolled source folders;
- executing generated shell commands, code, macros, or office documents;
- adding OAuth tokens, cloud credentials, or secret storage;
- adding plugin discovery or dynamic imports;
- accepting archive extraction or recursive directory ingestion;
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
- optional model outage or invalid output without loss of manual controls.

## Data retention and deletion

The MVP stores state until the operator removes the selected `LUMA_HOME` directory while the process is stopped. Revoking a grant stops new reads but does not erase existing artifacts, receipts, or workflow history. There is no certified secure-erasure function. Backups and copied release/state directories may retain data independently.

## Not protected or certified

This release does not claim sandboxing, malware scanning, encrypted local storage, key management, tamper-evident external audit, multi-user isolation, high availability, disaster recovery, privacy-regulation compliance, boot security, model safety, 400B operation, or cluster security.

Report suspected vulnerabilities using [SECURITY.md](../SECURITY.md), not a public issue.
