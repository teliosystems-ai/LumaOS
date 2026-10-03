# G2 Descriptor Scoped File Read Checkpoint

Status: bounded source checks passed on 2026-10-03. This checkpoint adds a
native descriptor-relative file-read primitive and uses it to read the
image-owned workflow template during signed registry verification. It does
not enroll or authorize a user folder and does not execute a workflow node.

The caller supplies an already-open directory and its expected device and
inode identity. The reader validates the relative path, opens each component
with `openat` and no-symlink flags, rejects special files, and bounds the
result. It compares the file's identity, size and timestamps before and after
the read. This keeps path resolution under the admitted directory descriptor;
it does not by itself establish that a principal currently holds a grant.
For a user source, the eventual broker must bind the directory identity to an
enrolled grant and recheck principal, scope and revocation immediately before
the read. Concurrent mutation by a privileged writer still requires a
stronger source-snapshot or retry policy in the full workflow.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-scoped-read-targeted-20261003-01`.

- Source snapshot manifest SHA-256: `52bf4ef72681b7d07776b546addbc9bbc7ab6b251f6fd64b8501f0a4329355be`.
- Completed test log SHA-256: `3116a5751eb475cf27b58cd315b0db6321b4a9dcd08e91ccb3fba30a80fe0507`.
- Two scoped-reader tests, three signed-registry and five calculation
  regression tests, formatting and an offline native build with warnings
  denied passed. The read tests cover nested paths, changed root identity,
  traversal, file and directory symlinks, oversized reads, FIFO rejection and
  invalid limits.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs and no
network. Source and evidence remained on D:. No image was rebuilt or booted.

Policy-bound folder enrollment, source snapshot semantics, native DAG
supervision, managed artifact writes, cancellation and restart, and the
distributed-image manual journey remain open. This checkpoint does not close
G2.
