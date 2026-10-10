# Requirement #1 integrated source candidate — 2026-10-10

Status: **integrated source candidate, not Requirement #1 completion or production qualification**.
The owner authorized parallel implementation and requested a single integrated
deliverable. Source remains on C:; build inputs, tool downloads, temporary test
fixtures and eventual images remain on D:. No host service restart, host
clock adjustment, host account mutation or TPM ownership/NV mutation was made
for the source increment. On 2026-10-10 the owner separately approved restarting
Ubuntu WSL, followed by full WSL shutdown after the narrower restart failed.

## Integrated source

| Component | Implemented candidate boundary | Qualification still required |
| --- | --- | --- |
| Account activation/renewal | Explicit protected-UTC day, exact retained shadow transaction, principal-generation fencing, reviewed permission/publication/completion, approved 90-day aging window | Real PAM/TPM lifecycle; expiry, interrupted publication and restart |
| Original Admin OS password/lock recovery | Separate offline-custody actor, prior checkpointed credential, verifier rotation and principal fencing before publication; exact prepare/publish/complete | Native positive/negative custody, OS-lock/password drift and interrupted recovery |
| Protected UTC | Fixed keeper/producer units and profiles; admitted query peer, private live observation, authenticated seed/history; explicit reviewed fixed-unit reacquisition | Installed systemd/AppArmor startup; NTS, clock/rate/suspend envelopes |
| Finite grants | Shared TPM catalog assignments/grants/revocation, exact typed selector and subject generation, finite validity and input/output/unit ceilings; fresh PAM/catalog/live UTC checks | Native issuance/revocation/admission, expiry and concurrency qualification |
| Inference | Live original-client challenge at submit/claim/admit/finish/delivery, exact physical lease binding, durable inert grant attribution, fixed confined launcher | Real installed client/broker/model route, malicious/stale peer and revocation checks |
| Policy evidence | Typed durable decisions with normalized scopes, actual PAM/catalog/grant/role evidence, protected UTC, stable denial reasons and pending/confirmed/uncertain effects; exact archive-before-unlink and separately granted export/custody/grace/disposition | Installed positive/adversarial flows, full-quota throughput and long-running export admission |
| Workflows/artifacts | Signed closed typed DAGs with branched reads, leased bounded batch calculations and artifact writes; principal-isolated journals/catalogs; exact replay/cancellation/committed recovery; historical invoice route retains original provenance | Installed journal/catalog/worker flows, failures at every boundary; migration of old global laboratory state is not automatic |
| Sources and cleanup | Principal input-folder ACL provisioning, retained source descriptors, separate inspection/Retain/Delete grants, protected-UTC artifact grace, explicit offline resource evidence deletion and independent NV-selected pair reconstruction | Effective installed DAC/AppArmor/worker, provisioning and damaged-authority recovery enforcement |

Protected UTC bootstrap does not require inventing a live time capability:
seed-only principal/custody actors can submit an independently reviewed bound.
The keeper seed itself cannot grant effects. Accounts and grants require live
admitted observations afterward. Missing, stale or uncertain state refuses;
there is no serialized `trusted` flag, root-only semantic bypass or automatic
revival of a fenced authority generation.

The owner approved the fixed **90-day password-aging duration** on 2026-10-10.
This is an explicit implementation policy, not a numeric duration in the original
governing requirements. Original installer Admin compatibility is distinct from
subsequent protected aging establishment; do not claim all historical accounts
already have a protected aging epoch.

## Operator interfaces included in the image candidate

The subsequent independent resource checkpoint and history increment is described
in [resource checkpoint custody and recovery](../RESOURCE_CHECKPOINT_CUSTODY.md).
Its separate TPM authority was approved on 2026-10-10 for software/disposable-TPM
tests only. The earlier sweep below remains evidence for its own frozen source,
not the later checkpoint/history bytes.

These are executable source entry points, not tested installation instructions.
Use the produced image only after Linux compilation and candidate validation.
The wrapper loads a fixed enforcing profile; `sudo` supplies execution privilege,
not the product principal, offline custody or a grant.

- `sudo luma-admin-control utc-seed LOGIN SEEDFILE [--commit INSTANCE REVIEW]`
- `sudo luma-admin-control utc-seed-recovery SEEDFILE [--commit INSTANCE REVIEW]`
- `sudo luma-admin-control utc-query LOGIN`
- `sudo luma-admin-control utc-history LOGIN REQUEST STATEMENTFILE [--commit REVIEW]`
- `sudo luma-admin-control utc-reacquire LOGIN [--commit INSTANCE REVIEW]`
- `sudo luma-admin-control utc-reacquire-recovery [--commit INSTANCE REVIEW]`
- `sudo luma-admin-control admin-account-activate LOGIN TARGET TRANSACTION [--commit REVIEW]`
- `sudo luma-admin-control admin-account-renew LOGIN TARGET TRANSACTION [--commit REVIEW]`
- `sudo luma-admin-control admin-account-recover TRANSACTION`, followed by the
  separate typed recovery publication/completion ceremonies described by CLI.
- `sudo luma-admin-control admin-catalog LOGIN REQUEST COMMANDFILE [--commit REVIEW]`

Seed, statement and command files are bounded **inert proposals**, not bearer
authorization. Place the reviewed control inputs in the fixed profile's private
`/run/luma-admin` namespace. The closed catalog JSON route accepts only finite
assignment/grant issuance/revocation commands; it cannot invoke custody recovery
or general account commands through arbitrary JSON.

`sudo luma-platform granted-run COMMAND ...` launches only the fixed governed
inference/workflow/artifact command allowlist under its resource-constrained
profile and real terminal. Inference uses a bounded JSON messages **file**, not
message text on argv. Workflow preparation/review captures CSV stdin before
opening the human PAM terminal. Root-private volatile snapshots are read-only
to the child; they are operator input, not folder grants. Inert input snapshots
remain in `/run` after uncertain outcomes until reboot, rather than being
silently deleted as though an effect had completed.

Invoice workflow review returns exact finite scopes; prepare/advance/cancel/
reconcile require current real human grant boundaries. Existing unscoped lab
effect entry points refuse after product bootstrap. Artifact export checks the
exact canonical receipt and each bounded output block. Already returned bytes
cannot be retracted after revocation; uncertainty must preserve the destination.
Retaining a preparation preserves its bytes—it is not artifact deletion.

## Typed workflow and cleanup interfaces

Terminal-domain history commands use `TYPE` equal to `dag` or `invoice`, the
exact product principal ID and its generation. Run through the fixed
`granted-run` launcher:

- `workflow-history-inspection-review LOGIN TYPE PRINCIPAL GENERATION`
- `workflow-history-proposal LOGIN READ-GRANT TYPE PRINCIPAL GENERATION`
- `workflow-history-export LOGIN READ-GRANT EXPORT-GRANT TYPE PRINCIPAL GENERATION REVIEW`
- `workflow-history-mark-proposal LOGIN READ-GRANT TYPE PRINCIPAL GENERATION ARCHIVE-SHA GRACE`
- `workflow-history-mark LOGIN READ-GRANT RETAIN-GRANT TYPE PRINCIPAL GENERATION ARCHIVE-SHA GRACE REVIEW`
- `workflow-history-delete-proposal LOGIN READ-GRANT TYPE PRINCIPAL GENERATION`
- `workflow-history-delete LOGIN READ-GRANT DELETE-GRANT TYPE PRINCIPAL GENERATION REVIEW`
- `workflow-history-staging-proposal LOGIN READ-GRANT TYPE PRINCIPAL GENERATION`
- `workflow-history-staging-discard LOGIN READ-GRANT RETAIN-GRANT TYPE PRINCIPAL GENERATION REVIEW`

Every run in the selected domain must be terminal, with no unresolved applying
effect. Independently retained artifact receipts must confirm completed writes.
Unpublished partial and empty workflow fragments remain opaque archive-only
members: their filenames are not accepted as content hashes or committed results.
A domain interrupted before its first run can be retired only with a validated
installation database, exact principal namespace and nonempty retained fragments.
Export carries canonical base64 records on a separate framed
payload socket; terminal PAM/systemd messages cannot enter the caller's binary
stdout. Acknowledgements confirm exact delivered bytes and flush, not remote
storage persistence. Validate the saved archive with
`workflow-history-archive-verify FILE` before accepting custody. Grace marking
binds the exact manifest, recorded export, supplied archive digest and selected
3,600–2,592,000-second grace period. Only protected UTC can establish expiry.

Explicit retirement removes only descriptor-pinned terminal workflow copies;
artifact catalogs, acknowledged artifact content and external sources remain.
The out-of-domain history ledger advances a durable epoch. New invoice/DAG
proposals and effect IDs bind that epoch, so old scopes cannot authorize a new
namespace after retirement. Whole-filesystem epoch rollback is not independently
TPM-detected by this history module; archives never authorize reconstruction.

Closed policy archives have separately scoped export, custody acknowledgement,
grace marking, deletion and evidence cleanup commands under `policy-archive-*`.
They refuse active or uncertain operations and unresolved original record copies.
Current PAM/catalog/UTC/grant authorization is checked on each output block.
Successful unchanged checks within an already durably admitted export do not
append repeated Allow records; initial admission, denials and final outcomes stay
durable. This bounds audit growth for large archives without caching authority.

Exports have a fixed 1,800-second unit runtime ceiling and 256MiB payload ceiling;
ordinary commands retain 60 seconds. Socket idle waits are capped at 60 seconds
and the remaining overall deadline. Current PAM sessions independently expire
after 30 seconds; the transport ceiling does not extend authentication. A narrow
export-only lifetime change requires the owner's pending decision. Grant validity
is never extended. Native
maximum-quota throughput and memory measurements remain qualification work.
The confined launcher retains a fixed 8,192-descriptor ceiling because nested
inspection/export can retain three independent 1,024-entry policy archive caches.
This changes no capabilities or writable namespaces. The schema-2 workflow
manifest also binds ext4 inode incarnations and immutable creation timestamps;
a reused inode is not accepted as the former retired namespace.
Interrupted history-ledger staging is inert and cannot replace the published
epoch. Its exact private bytes require separate reviewed disposition; no
cleanup command adopts a staged state or deletes the published ledger. Governed
invoice domains also require their immutable installation/principal owner record.
Unmarked laboratory or older unowned domains are not automatically relabeled.

Retained runs belonging to an older principal generation have explicit
disposition-only recovery interfaces:

- `workflow-recovery-review LOGIN TYPE PRINCIPAL OLD-GENERATION REQUEST`
- `workflow-recovery-inspect LOGIN READ-GRANT TYPE PRINCIPAL OLD-GENERATION REQUEST`
- `workflow-recovery-cancel LOGIN READ-GRANT CANCEL-GRANT TYPE PRINCIPAL OLD-GENERATION REQUEST REVIEW`
- `workflow-recovery-reconcile LOGIN READ-GRANT RESUME-GRANT TYPE PRINCIPAL OLD-GENERATION REQUEST REVIEW`

Only the current usable owner, or the original Admin acting on an independently
verified advanced, disabled or deleted target, can perform these operations.
Cancellation cannot cross an unresolved Applying effect. Reconciliation records
only an exact independently committed artifact outcome; it cannot redispatch a
worker or create another artifact. These recovery scopes do not revive old
execution or write grants.

The lifecycle is bounded: retired principal names/UIDs remain reserved, the
registry supports at most 128 lifetime principals, catalog transaction history is
capped, and owned artifact catalogs retain at most 1,024 receipts. Terminal
workflow retirement frees run capacity, not artifact-receipt or identity capacity.
Quota refusal preserves evidence and does not imply indefinite local operation.

The fixed launcher now also accepts `workflow-dag-review`, `workflow-dag-prepare`,
`workflow-dag-status`, `workflow-dag-advance`, `workflow-dag-cancel` and
`workflow-dag-reconcile`. Review/prepare take bounded JSON proposal **files**;
status/advance/cancel/reconcile take bounded JSON grant-map files. The launcher
captures files into its root-private read-only `/run` snapshots before PAM.
Supported nodes are FileRead, DeterministicCalculate and ArtifactWrite, not
arbitrary shell or model-generated code. Calculation combines at most sixteen
dependencies into a canonical input of at most 1 MiB under a fresh worker lease.

Before use, `workflow-inputs-review LOGIN` returns the exact provisioning scope.
`workflow-inputs-init LOGIN EXECUTE-GRANT REVIEW` performs the separately granted
creation through `granted-run`. Sources belong under the returned fixed
`/var/lib/luma-os/workflow-inputs/<principal-domain>` path. The human can create
files there; the runtime obtains only descriptor-scoped read access. Restrictive
permissions can still refuse a read. No private home access or DAC override is
added. `workflow-source-review ROOT RELATIVE` runs as the ordinary human, not
through sudo, and returns an inert identity for the exact source.

New governed DAG and historical invoice stores and artifact catalogs are
partitioned by the installation principal. Owned catalog identity is schema
version 2; old laboratory catalogs keep their original schema and bytes. Missing,
partial or foreign state is not silently adopted, relabeled or reset.

Owned artifacts use `artifact-owned-export-review LOGIN READ-GRANT ARTIFACT VERSION`
and `artifact-owned-export LOGIN READ-GRANT EXPORT-GRANT ARTIFACT VERSION` through
the fixed launcher. Each output block rechecks both independently authenticated
scopes. Preservation uses `artifact-owned-retain-proposal LOGIN READ-GRANT REQUEST`
then `artifact-owned-retain LOGIN READ-GRANT RETAIN-GRANT REQUEST REVIEW`. These
routes open only the current principal's catalog, not the older global laboratory
catalog. Export emits exact content bytes on stdout; do not treat a partial
destination as a confirmed export.

Artifact cleanup commands, through `granted-run`, are:

- `artifact-gc-inspection-review LOGIN`
- `artifact-gc-proposal LOGIN READ-GRANT object|retained NAME GRACE-SECONDS`
- `artifact-gc-mark LOGIN READ-GRANT RETAIN-GRANT AREA NAME GRACE-SECONDS REVIEW`
- `artifact-gc-delete-proposal LOGIN READ-GRANT MARK-SHA256`
- `artifact-gc-delete LOGIN READ-GRANT DELETE-GRANT MARK-SHA256 REVIEW`
- `artifact-gc-outcomes LOGIN READ-GRANT`

Read inspection and the exact mutation are independently authenticated and may
prompt twice. Grace is explicitly selected between 3,600 and 2,592,000 seconds;
protected UTC must establish its expiry. Referenced committed-version bytes are
never deletion targets. Exact mark/intent/outcome records preserve ambiguous
results for investigation; missing bytes are not evidence of successful deletion.

`policy-evidence-review OPERATION-ID` and
`policy-evidence-retain LOGIN RETAIN-GRANT OPERATION-ID REVIEW` archive exact
closed operations before removing their originals. Pending evidence has separate
`policy-evidence-pending-review MEMBER` and
`policy-evidence-pending-retain LOGIN RETAIN-GRANT MEMBER REVIEW` paths.
Archives and retained partial bytes remain evidence, not restoration authority.
Local evidence quotas refuse safely when exhausted; indefinite external archive
export/deletion has not been implemented.
Active canonical evidence is bounded to 16 MiB, with 4 MiB reserved for terminal
and maintenance records; each archive is at most 8 MiB and all archives together
at most 512 MiB. Interrupted archive sweeps compare exact surviving originals
without expanding all historical graphs into admission memory. Physical residuals
continue to count against actual disk quotas.

`resource-retention --proposal NAME...` returns an exact evidence-deletion scope;
`resource-retention LOGIN RETAIN-GRANT REVIEW NAME...` requires proved offline
drainage and exclusion. It cannot delete referenced history, leases, generations,
retired-owner records or request tombstones. `--outcomes` reports durable results.
The supported native Linux initial PID namespace is verified through the caller's
nsfs descriptor, namespace-type ioctl and kernel initial namespace inode. This
avoids ptrace access to non-dumpable systemd and adds no capabilities. The kernel
contract is pinned to [Linux proc namespace definitions](https://github.com/torvalds/linux/blob/v6.8/include/linux/proc_ns.h)
and [namespace access checks](https://github.com/torvalds/linux/blob/v6.8/fs/proc/namespaces.c);
unsupported or nested layouts refuse.

## Candidate image composition

Selected producer input: official chrony **4.9**, independently pinned archive
SHA-256 `4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0`.
Actual source adaptation checked all eight selected upstream input pins on D:.
The source distinguishes this release candidate from the older isolated fixture.
Archive provenance explicitly records that an upstream signature was not verified;
an independent hash pin is not production release signing custody.

Assembly builds NTS/capability/seccomp support, packages the dedicated producer
UID/GID 987, fixed units/profiles, CA/policy/config, resolved canonical ELF
closure, build-package provenance, license and original corresponding source
plus adapters. Only keeper and producer path units are enabled; the producer
requires seed readiness and the fixed measurement socket. Chrony receives `-U`
for its non-root service identity. Competing time services are masked **inside
the image tree only**. Packaging does not start a host daemon or seed a clock.

The fixed UTC restart helper has no caller-selected unit/action/executable,
is not setuid, checks the real enforcing kernel peer and live PIDFD, and has
bounded parent/child supervision. Restart requires explicit authenticated review,
invalidates the old generation and returns to independent seed acquisition.

## Integrated development test results

The frozen functional candidate passed the coordinated offline Linux sweep:
**782 Rust tests passed, zero failed, 38 fixture-only tests were not directly
selected; 320 native source/packaging tests passed, with two external chrony
fixture checks unavailable.** The 38 Rust fixture entries are not 38 additional
passes; some are child entry points exercised by their ordinary parent tests.
No ignored fixture was reclassified as a passing test.

Source manifest SHA-256:
`6392c479dbd4b4979746ea56b2b3b2090b4db6e821494cb2dfde840bd3dc0dad`.
Evidence is under `/mnt/luma-build/work/r1-integrated-evidence-20261010-final2/sweep`
on the D-backed ext4 store. The actual runner recorded successful exit codes for
both lanes; total elapsed time was 837.307 seconds. Its immutable input closure
includes native C fixtures and the ADR source embedded in the policy digest.

This follows a 724-pass baseline with eighteen failures: seventeen came from a
private temporary ancestor blocking isolated worker UIDs, and one exposed a
call-count-dependent fault injection after a new freshness check. Storage tests
now use a separate private ext4 root while unprivileged fixtures use `/tmp` mode
1777. The fault injection now targets the actual metadata phase; production
permission and freshness checks were not relaxed. An earlier integrated attempt
failed compilation because its snapshot omitted the embedded ADR file. Normal
build snapshots now include `docs/adr`, and that failure remains a failed attempt.

The full sweep used the pinned tools image, one CPU, a 2 GiB memory limit and no
network or attached host TPM. Source was mounted read-only. The disposable
container root was writable for the container-only dracut/udev packaging fixture;
no host system directory was mounted writable. Subsequent changes remove five
unused mutable callback bindings and extend only the test runner's explicit
targeted/PAM modes. Their warning-denied regression result is recorded separately.

The final post-cleanup verification passed with `RUSTFLAGS=-Dwarnings`:
all Rust production and test targets type-checked, **21 workflow regression tests
passed**, the native suite again passed **320 of 322 tests** with the same two
unavailable chrony checks, and **all six real PAM fixture cases passed**. PAM
covered acceptance, lock, account expiry, password aging, nologin and profile
tampering in disposable container accounts; no product Admin was enrolled.
This targeted verification is not a second full 782-test sweep.

Final source manifest SHA-256:
`06d397d24c9249b7a2272867752c357ffef5e877194e2181b9646b03bedc583e`.
Runner SHA-256:
`ffa3f538c57c2d39a3ee43f079ce70033e9d6252ad23a33eef49166368a52d89`.
The four successful lanes took 217.555 seconds in total. Their transcript hashes
and exit codes are preserved in
`/mnt/luma-build/work/r1-integrated-evidence-20261010-final4/sweep/result.json`.
An intermediate warnings-denied attempt failed on two remaining unused mutable
forwarding bindings; its compile and dependent PAM failure remain recorded under
the `final3` evidence directory. Removing those bindings changed no execution
logic. All five forwarding-binding warnings are absent in the final check.

The granted-client profile also parsed with Ubuntu WSL's AppArmor
5.0.0~beta1 parser using `--skip-kernel-load --skip-cache --config-file /dev/null`.
No profile was loaded or cached. This is syntax checking on the host parser,
not enforcement evidence or qualification of the Ubuntu 24.04 image tuple.

## Verified independent checkpoint and history increment

The final immutable snapshot I passed its offline targeted sweep at
`/mnt/luma-build/work/r1-checkpoint-evidence-20261010-i/sweep`:

- Warnings-denied `cargo check --all-targets` passed.
- **48 workflow/recovery tests and 23 policy/admission tests passed**, with no
  failures or ignored tests in either selected lane. These are targeted filters,
  not a repeated full Rust suite.
- **330 native tests passed, zero skips**. The pinned chrony 4.9 release source
  was supplied read-only, so the two previously unavailable upstream checks ran.
- **Six real PAM cases, four independent disposable resource-TPM cases and the
  existing-owner Admin software-TPM driver passed**. Exact fixture invocations
  executed real selected tests; zero matches cannot qualify the resource driver.
- Admin wrapper Bash syntax and both confinement profiles parsed successfully.
  Profiles were not loaded or cached; this does not establish enforcement.

The frozen source manifest SHA256 is
`2f004d5d3df9e2e6f4a8b860866f6127c7a06a990f45e43acb0fbeb6c687c392`.
The runner SHA256 is
`dd383f53af365e728632d8e4ab1f520ae28a0d9080ccae8bda7fe1e967549ca6`.
Case commands, counts, exit codes, elapsed time and transcript digests are in
[the machine-readable evidence](requirement1_2026-10-10.json) and the retained
external `result.json`. Snapshot I differs from passing snapshot H only in
`workflow_history.rs`, where the final security-review fixes and regressions
pin exact staged bytes and retain the original absent-domain parent.

The preceding full sweep G is explicitly **failed**, with 829 Rust passes,
two fixture failures and 42 fixture-only entries not selected in the ordinary
unit invocation. Its denial fixture reused an immutable record ID; its DAG
Applying fixture assumed the wrong signed node order. Both fixtures were
corrected without weakening production guards and passed H/I. G also passed
328 native tests, PAM and the TPM drivers. Failed attempts D/E/F/G remain
recorded, including F's 2GiB compiler OOM and interrupted dependent PAM lane.
They are not relabeled as successful sweeps.

H/I retain the same one-CPU, 2GiB isolated container limit and use
`CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_PROFILE_DEV_DEBUG=0` to bound compiler
memory. No WSL memory increase, host TPM access, host clock/account change or
additional service restart was performed. Network was disabled; source and
chrony fixtures were read-only, and cache/storage/evidence remained on D:.
No installed image or physical qualification is claimed.

## Earlier verification and recovery of the build environment

- Windows targeted integration/account/package/UTC source checks: **37 passed**,
  no skips in that invocation. Assembly tests mock compiler/chroot/link creation;
  they are layout/order checks, not effective Linux permissions or deployment.
- Separate UTC source suite: **32 passed**, two pre-existing external chrony
  fixture checks skipped because their old fixture environment was unavailable.
  These counts overlap the invocation above; do not add them as distinct tests.
- Final expanded portable invocation: **123 discovered, 117 passed, six skipped**
  (two pre-existing external chrony fixtures and four Linux-only shutdown checks).
  It includes the checks above plus principal, service, recovery and resource
  policy checks; these are overlapping totals, not additional distinct passes.
  An earlier broader invocation also selected Linux-only inference tests and
  failed on unavailable Windows `os.geteuid`/native boot-time clock support.
  Those tests remain unexecuted on Linux; they were not converted to passing
  tests by relaxing production identity or clock checks.
- Portable official Rust 1.75 rustfmt parsed/formatted candidate modules. This
  checks Rust syntax only, **not type checking, linking or execution**.
- Python scripts parse successfully. No new Rust unit test was executed.
- Ubuntu WSL launch fails with `Wsl/Service/0x8007274c`, including the existing
  D-backed compiler entry point. No Linux shell executed for the failed calls.
  No C-backed Docker build was substituted and no WSL shutdown was performed.
  Approval to restart only Ubuntu was requested separately; stop/restore may
  interrupt its running Linux processes.

On 2026-10-10 the owner approved the Ubuntu-only restart and the 90-day aging
policy. `wsl.exe --terminate Ubuntu` completed successfully; the subsequent
distribution listing showed Ubuntu stopped and Docker Desktop still running.
Both a diagnostic Bash launch and a minimal `/bin/true` launch then failed with
`Wsl/Service/CreateInstance/0x800705b4` before Linux execution. Windows reports
WslService, vmcompute and hns running. The D-backed build environment is not
restored by this attempt. No global WSL shutdown, Windows service restart or
memory change was performed during that narrower attempt.

The owner subsequently approved `wsl.exe --shutdown`, including interruption of
Docker Desktop's Linux workloads. Shutdown completed, and Ubuntu relaunched
successfully with `/bin/true`. The distribution listing then showed Ubuntu
running and Docker Desktop stopped. The relaunched environment reports Ubuntu
26.04 LTS and kernel `6.18.33.2-microsoft-standard-WSL2`; this does not change
the pinned image build release. `/dev/loop0` mounts ext4 at `/mnt/luma-build`
and is backed by `/mnt/d/LumaOS-builds/docker/luma-build-v1.ext4`. The dedicated
daemon reports `DockerRootDir=/mnt/luma-build/docker`, with approximately 75 GiB
free on that filesystem. The D-backed build environment is restored. No Windows service
restart, WSL memory change or final image/model sweep was performed.

A subsequent bounded offline Linux compile-only check completed successfully:
`cargo check --offline --locked --target-dir /cache/target --tests`. It used
the existing `luma-utc-targeted-tools:20261005` image
(`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`),
read-only source/root filesystem, no network, one CPU and a 1 GiB memory limit.
`/cache` is the existing D-backed `luma-g2-rust-targeted-cache-20261001` volume.
The check type-checked the Rust test target and ran the C helper build script;
it did not execute unit tests or link a production release. It reported three
dead-code warnings for `ShutdownGuard`, its `check` method and `shutdown_guard`,
because damaged-authority recovery does not yet consume that isolation proof.
These warnings remain open integration work; this is not a warnings-denied
production build or native lifecycle qualification.

Existing 2026-10-09 passing evidence remains evidence for those older bytes;
it does not qualify this increment. No final image, native PAM/TPM control flow,
effective confinement, clock qualification or physical certification is claimed.

## Still open before Requirement #1 closes

1. Finish large-export admission: choose an explicitly approved export-only
   30-minute authenticated session or retain the 30-second session and implement
   reviewed resumable transfers. Transport timeouts alone do not extend PAM
   authentication. Write/Admin mutation sessions must not silently gain a longer
   lifetime. This is remaining software work, not just performance qualification.
2. Qualify the actual account/UTC/grant/worker/retention paths together under
   installed confinement. The development failures described above are repaired;
   passing unit and disposable-container tests cannot establish installed
   qualification.
3. Freeze the fully implemented candidate, build once on D:, and perform the
   consolidated image/model sweep followed by separate native Ubuntu/physical
   qualification.

The separately approved checkpoint reconstruction, terminal-domain disposition,
explicit unpublished-staging cleanup and policy-archive lifecycle are implemented
source candidates. They preserve damaged bytes, resolve only independently
authenticated outcomes, and never adopt an unanchored backup or staged epoch.
History publication binds the exact staged inode, incarnation and bytes across
authority I/O; absent-domain retirement retains the marked parent through
tombstone publication. Historical records are never automatically purged.

Requirement #2 has not been started. Neither Requirement #1 nor G2 is marked
complete; the passing development sweep does not eliminate the remaining software.
