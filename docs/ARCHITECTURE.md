# Architecture

## Purpose and boundary

Luma OS `0.1.0` is a local developer application that demonstrates an inspectable intent-to-workflow control plane. It is **not** a kernel, Linux distribution, desktop shell replacement, production agent platform, or remotely hosted service.

The architecture favors a small auditable core over broad integrations:

- Python 3.11+ standard library only;
- a browser UI served from the same loopback process as the API;
- explicit folder enrollment before local reads;
- prepare-before-run workflows;
- durable SQLite metadata, content-addressed objects, and effect receipts; and
- optional model assistance that cannot remove manual operation.

## System context

```text
┌──────────────────────────────────────────────────────────────┐
│ Local operator                                               │
│  Browser on loopback                                         │
└───────────────┬──────────────────────────────────────────────┘
                │ same-origin HTTP + local session
┌───────────────▼──────────────────────────────────────────────┐
│ Luma OS Python process                                       │
│  static web server │ API routes │ validation/error mapping   │
├────────────────────┴────────────┴────────────────────────────┤
│ application services                                         │
│  grants │ workflows │ artifacts │ receipts │ model status    │
├──────────────────────────────────────────────────────────────┤
│ local persistence                                            │
│  SQLite (WAL) │ content-addressed object files               │
└───────────────┬──────────────────────────────────────────────┘
                │ descriptor-relative reads after enrollment
┌───────────────▼──────────────────────────────────────────────┐
│ Explicitly granted local folders                             │
└──────────────────────────────────────────────────────────────┘

Optional: operator-configured model endpoint on the local machine.
No model weights are part of the repository or release.
```

The browser simulator elsewhere in the larger Luma OS workspace is a UX artifact. It is not part of this runtime's trust boundary and does not prove runtime acceptance.

## Component responsibilities

### Web client

The repository-root `web/` directory contains the source UI. It talks only to the colocated API and should not load third-party scripts, fonts, analytics, or CDNs. The server is responsible for a strict same-origin boundary, response security headers, and local-session checks.

### Loopback server and API

The local server owns process startup, static-file delivery, request size limits, JSON parsing, route dispatch, and consistent error responses. The API contract is recorded in `schemas/openapi.yaml`.

The default endpoint is `127.0.0.1:8765`. Non-loopback binding is outside the supported MVP and must never be made an accidental configuration change.

### Folder grants

A folder is inaccessible until the operator enrolls it. A grant records the canonical root, device/inode identity, owner, scope, and revocation state. Source paths are relative to that root.

On supported POSIX systems, every component is opened descriptor-relative with no-follow flags, and the root identity is rechecked. This reduces traversal, symlink, and rename/swap risk. Revocation blocks new access but cannot undo effects already committed.

### Workflow engine

The first vertical workflow is `invoice_report.v1`. Preparation validates the request and returns a visible plan without performing its effects. A separate run command performs the workflow. Stable request and idempotency keys prevent accidental duplicate execution.

A workflow has explicit states and ordered steps. Terminal state, error detail, manual-input requirements, output artifacts, and effect receipts survive process restart.

### Artifact store

Artifacts are application-owned outputs, separate from enrolled source files. Metadata and version history are stored in SQLite. Content is written under a private objects directory using a content digest and an atomic commit pattern. Durable writes are real local effects, not UI simulation.

### Effect receipts

Every committed effect receives a durable receipt. Receipt rows are append-only at the database layer. They are an audit aid, not a tamper-proof external ledger: an operator with filesystem access can still replace or edit the database.

### State transfer and maintenance

The developer state-transfer path creates an atomic ZIP archive containing a
consistent SQLite backup, every referenced immutable object, and a complete
size/SHA-256 inventory. Restore publishes only into a new directory after path,
inventory, digest, database-integrity, and schema-version validation. Retention
maintenance is deliberately narrower: it may report or remove unreferenced
content objects, but cannot delete acknowledged artifact history or append-only
receipts.

### Optional model adapter

Model availability is additive. The deterministic/manual workflow remains usable when no endpoint is configured or the endpoint fails. Model output is untrusted data and must be validated before it can influence a plan or effect.

Model binaries, weights, tokenizers, and remote credentials are external operator assets. Their licenses and security posture are not inherited from this repository.

### G1 contract prototypes

The G1 development surface keeps policy, resource admission, inference, and OS
integration as separate typed boundaries. The resource ledger performs checked
64-bit accounting and generation-fenced atomic leases. Runtime profiles and
placement plans bind exact model, tokenizer, template, backend, context, and
memory choices; the local inference gateway revalidates session identity,
policy, deadline, and lease state without a remote fallback path.

Model packs use a strict canonical manifest, detached Ed25519 verification
interface, complete file inventory, and SHA-256 content checks. Recognized,
loadable, execution-certified, and interactive-certified are distinct monotonic
states. The repository contains no trusted key, real model asset, or
certification evidence.

A deterministic typed DAG publishes restart checkpoints only after successful
typed results. The versioned platform adapter has a deterministic fake and a
read-only Linux/WSL implementation; its `T40-SCAFFOLD` report is explicitly
non-closing until the missing governing source defines the authoritative test.
These modules are reference contracts inside the current Python process, not
the production service split or hardware qualification described by the ADRs.

## Storage layout

The default state root is `${XDG_STATE_HOME}/luma-os` or `~/.local/state/luma-os`:

```text
luma-os/
├── luma.sqlite3       workflow, grant, artifact, and receipt metadata
├── luma.sqlite3-wal   SQLite write-ahead log while active
├── luma.sqlite3-shm   SQLite shared memory while active
└── objects/           application-owned immutable content objects
```

The runtime tightens state directories to user-only permissions where the platform supports it. `LUMA_HOME` selects another state root for development or tests.

## Primary control flow

1. The operator starts the local process and opens the loopback UI.
2. The operator enrolls a local folder for a specific scope.
3. The UI submits an intent/workflow request using a path relative to that grant.
4. The server validates identity, path, size, media assumptions, and idempotency.
5. The workflow is persisted in a prepared state and shown to the operator.
6. An explicit run request transitions the workflow and executes each allowed step.
7. Source bytes are read inside the grant boundary; outputs are committed to the artifact store.
8. Workflow state and append-only effect receipts record the result.

Preparation and execution are separate API actions. UI affordances must not collapse that distinction.

## Architectural invariants

- Loopback is the only supported network boundary.
- The local process runs without elevated privileges.
- No filesystem source read occurs without an active grant.
- A relative path must remain beneath its enrolled root and must not traverse symlinks.
- A workflow is prepared before it is run.
- An idempotency key identifies one logical effect request for one owner.
- Application output is written to managed storage, not back into source folders by default.
- Committed effects have receipts; receipts are never updated or deleted through the application.
- Manual operation remains available when the optional model is absent.
- Secrets and model weights never belong in release archives.

## Source and distribution model

The supported `0.1.0` artifact is the checksumed source archive created by `scripts/build_release.py`. It retains `web/`, `schemas/`, and `examples/` beside `src/`, which is the runtime layout used by the MVP.

`pyproject.toml` supplies project metadata and a developer console entry point. A wheel is **not** a supported `0.1.0` distribution because repository-root runtime assets are not yet relocated into an installed package layout. This decision avoids silently shipping a console command without its UI or schemas.

## Deployment shape

The supported process shape is one operator, one local process, one local state directory, and one browser. Ubuntu 24.04 is the primary target. Windows 11 is supported through WSL2 with Ubuntu 24.04. The systemd unit is optional and runs as a user service.

There is no supported reverse proxy, container deployment, multi-user tenancy, privilege separation daemon, bootable image, dual-boot installer, VM manager, 400–405B model configuration, or cluster topology in this release.

## Change discipline

Changes to any invariant above require:

1. an architecture update;
2. a corresponding threat-model review;
3. tests for failure and policy paths;
4. requirements/support matrix updates; and
5. a changelog entry.
