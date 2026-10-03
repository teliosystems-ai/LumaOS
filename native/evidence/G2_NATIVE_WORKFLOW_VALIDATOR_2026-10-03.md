# G2 native file to artifact graph validation

Status: bounded source checks passed on 2026-10-03. This is a read-only native
DAG admission increment for the next image candidate, not a signed skill
registry, workflow supervisor, effect authorization or G2 acceptance.

The Rust platform binary now exposes `workflow-validate GRAPH.json`. Its closed
`file-to-artifact-v1` profile accepts only file-read, deterministic-calculation
and artifact-write node kinds. It bounds the graph and input file, rejects
unknown fields, identifiers, dependencies, cycles, type substitutions and
unused nodes, then reports a stable node order and graph fingerprint. The
image overlay contains a three-node manual-report template at
`/usr/share/luma-os/workflows/file-to-artifact-v1.json`. Validation reads the
file but does not open a source document, execute a node, publish an artifact
or grant an effect capability.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-native-workflow-targeted-20261003-01`.

- Source snapshot manifest SHA-256: `2e10747ac2ec3b5f10b2f05b4deeed2da0092e1df79bb07bec38b5fcbc2e4352`.
- Completed test log SHA-256: `613c5ae4a5f2233d02436b0a3fbf7db1c93920507d8c3ee0bdc3791452ce7cc5`.
- Example graph fingerprint from the compiled CLI: `c5052e5190b7868289835d1b29e5707ea3961472fe8f19be01aab9458194cff3`.

Four native validator tests, formatting, the offline native build with
warnings denied, and a compiled-CLI check of the overlay template passed in a
D-backed container. The run used one CPU, 768 MiB memory with no extra swap,
128 PIDs and no network. It did not boot or rebuild an OS image, execute a
workflow, read a real source file, write an artifact, or use a signed skill.

Signed package trust and registry custody, descriptor-scoped skill handlers,
effect-time grants, durable checkpoints, cancellation, restart reconciliation
and the distributed-image file-to-artifact journey remain open. This template
will be present only in an image built from this source or later; older images
are unchanged.
