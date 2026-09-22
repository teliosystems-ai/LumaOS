# ADR-0003: Artifact and durable-state storage

- Status: Accepted; frozen for G1
- Date: 2026-09-22
- Decision owners: storage lead, security lead, release engineer
- Applies to: G1 artifact, receipt, recovery, and later A1 storage work

## Context

The MVP already uses SQLite WAL metadata and content-addressed files. G1 needs to preserve that inspectable model while defining ownership, crash ordering, and the boundary between authoritative data and rebuildable indexes.

## Decision

1. Production A1 storage remains local ext4 on LUKS2 unless a later versioned decision supersedes it. Network filesystems are not supported for authoritative SQLite or object storage.
2. SQLite WAL databases hold workflow metadata, policy/grant records, artifact identities and versions, and effect receipts. Each production service has one database owner and no other process writes that database directly.
3. Artifact bytes are immutable content-addressed objects keyed by lowercase SHA-256. Logical artifact identity and monotonically increasing version identity are separate from the content digest.
4. A commit writes a private same-filesystem temporary object, streams and verifies its digest and size, applies restrictive permissions, calls `fsync`, atomically renames it to the digest path, and `fsync`s the containing directory before committing metadata and its effect receipt in one SQLite transaction.
5. The ordering may leave an unreferenced object after a crash; it must never commit metadata that points to missing bytes. Garbage collection only removes objects proven unreferenced after a grace period and is itself receipted.
6. Receipts are append-only at the application and database layers. They are local audit evidence, not an externally tamper-proof ledger.
7. Enrolled source files remain external inputs. Luma OS never overwrites them by default. Export is a separate policy-authorized effect with destination validation, idempotency, and a receipt.
8. Semantic/vector/search indexes, caches, previews, and thumbnails are rebuildable derivatives. They are not authorization or durability authorities.
9. Deduplication is limited to one security domain. Cross-user or cross-tenant digest probing is prohibited even if a later deployment supports multiple identities.
10. Every persisted schema carries a version. Forward migration, rollback compatibility, backup, and clean-machine restore require explicit evidence before their later gates can close.

## Consequences

- Existing MVP artifacts remain a valid reference for the G1 contract.
- Atomic rename alone is not accepted as proof of durable commit; filesystem and database ordering must be fault tested.
- Orphan reconciliation, digest verification, database migration, and crash-boundary tests are required.
- Operator/root access can still alter local state; stronger tamper evidence would require a separate design.

## G1 change control

Changing the authoritative database, filesystem, hash algorithm, commit ordering, immutability rule, or receipt semantics requires a superseding ADR plus migration and failure-injection evidence.
