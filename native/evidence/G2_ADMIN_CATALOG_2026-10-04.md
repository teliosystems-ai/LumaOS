# G2 Finite Admin Activity and Role Definitions

The native source now implements reviewed activity registration and versioned
role definitions above the explicit product Admin bootstrap. Each mutation
retains its semantic payload and binds it into the authenticated TPM journal.
This closes a definition-catalog implementation increment, not role assignment,
the confined Admin service, production effect authorization or G2 acceptance.

## Implemented scope

The installed-system source commands require fresh local PAM authentication of
the original bootstrapped human principal and the fixed credential/TPM backend.
Inspection is read-only; `--commit REVIEW-SHA256` explicitly approves the exact
command, request, current checkpoint head, replay/no-change state and TPM epoch.
Unix root, a role name, metadata or a review digest alone grants no authority.

The reducer starts with the four frozen governance control activity names.
It accepts only finite declared activities and role definitions: no wildcard,
root `Admin` definition, bootstrap delegation or unknown activity is accepted.
The native interface restricts identifiers to 64 ASCII characters, activity
inventory to 128, role inventory to 128 and a definition to 64 unique activities.
CLI activity lists are sorted; duplicates refuse. Version zero explicitly
creates a new role; updating requires its exact current positive version.
Identical registration/definition is a no-op and creates no payload, receipt or
version. These native wire conventions preserve the reference distinction
between creation, compare-exchange update and no-op; they do not extend its
authorization semantics.

Each closed canonical event binds schema, deployment, original enrollment,
complete acting principal, request, sequence, previous checkpoint head, previous
catalog state version and command. Replay verifies the payload against its TPM
journal entry, then rebuilds the catalog in order. Missing/changed payloads,
unknown history, invalid sequence/principal/version/head and matching-digest but
semantically forged events refuse. No unverified file is imported as state.

Stable request replay requires the original exact command and fresh current
Admin authentication. It reports the original proposal/receipt binding alongside
the current catalog; a later role revision is not overwritten. Replay never
extends the TPM. Payloads are retained privately and never overwritten.
An unreferenced preparation fences ordinary status and unrelated mutations;
only its exact request can review/resume at the same head. Partial, substituted,
uncommitted or unsupported no-op preparations remain fenced. A lost TPM reply
requires explicit publication of the exact already committed journal successor,
never automatic redispatch or reset.

Before journal dispatch, the adapter verifies bootstrap and semantic history,
the exact proposed payload and fresh principal/account authentication at every
writer boundary. The native sole-writer lock remains held. Hostile OS root is
outside this boundary. TPM time is an audit/epoch observation, not trusted UTC.

Definitions assign nothing to a subject. Delegation, expiry/revocation,
resource capabilities, signing custody and effect execution remain unavailable.
The current entry point is an installed-root launcher with independently
authenticated product authority, not the still-missing confined daemon/API.

## Verification

Targeted checks passed on 2026-10-04 at
`D:\LumaOS-builds\g2-admin-catalog-targeted-20261004-02`.

- Build manifest SHA-256: `96bc0b1209b57ae08ac24b089f5c869ea4305a56a35c8b339272bffcb84db9d1`.
- Supplementary test-input manifest SHA-256: `00694adbd281a182ca69db10718b7c231d184773c0d5348b65d2d607c310feaa`.
- Completed log SHA-256: `27306cc355e69451129b9fefc8ea82276342dc9a23b97dfdf43e6ed170ea7187`.
- All 167 build inputs and four supplementary test inputs matched the checkout.
- 72 ordinary Rust tests passed: four catalog reducer, 22 governance,
  16 journal, 20 enrollment, six principal and four authentication tests.
- The extended disposable existing-owner TPM fixture passed bootstrap, activity
  registration, role creation, credential reload and exact restart/replay with
  unchanged committed head. It supplies a test identity, not real PAM-to-TPM
  acceptance. Sealing control, native enrollment and the legacy systemd
  nonempty-owner refusal also passed.
- Five source-wiring checks, formatting, offline locked build with warnings
  denied and CI runner Bash syntax passed. The existing runner invokes the
  extended fixture; its complete execution and remote CI were not run here.
- The passing `-01` checkpoint is retained; `-02` additionally qualifies the
  forged semantic-binding tests and unsupported no-op preparation refusal.

Checks used D-backed cache/evidence, one CPU and at most 768 MiB, with no network,
host TPM devices, Docker socket or extra privileges. WSL settings and unrelated
workloads were unchanged. No image, VM, model sweep or physical mutation ran.
The confined service, time-bounded assignments/grants, principal lifecycle and
recovery, trusted time/custody, installed evaluation and the wider G2 backlog
remain open.
