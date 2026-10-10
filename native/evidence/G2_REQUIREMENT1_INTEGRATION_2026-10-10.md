# Requirement #1 integrated source candidate — 2026-10-10

Status: **implementation increment, not Requirement #1 completion or production qualification**.
The owner authorized parallel implementation and requested a single integrated
deliverable. Source remains on C:; build inputs, tool downloads, temporary test
fixtures and eventual images remain on D:. No commit, service restart, host
clock adjustment, host account mutation or TPM ownership/NV mutation was made
for the source increment. On 2026-10-10 the owner separately approved restarting
Ubuntu WSL, followed by full WSL shutdown after the narrower restart failed.

## Integrated source

| Component | Implemented candidate boundary | Qualification still required |
| --- | --- | --- |
| Account activation/renewal | Explicit protected-UTC day, exact retained shadow transaction, principal-generation fencing, reviewed permission/publication/completion, finite aging window | Rust compilation; real PAM/TPM lifecycle; expiry, interrupted publication and restart |
| Original Admin OS password/lock recovery | Separate offline-custody actor, prior checkpointed credential, verifier rotation and principal fencing before publication; exact prepare/publish/complete | Native positive/negative custody, OS-lock/password drift and interrupted recovery |
| Protected UTC | Fixed keeper/producer units and profiles; admitted query peer, private live observation, authenticated seed/history; explicit reviewed fixed-unit reacquisition | Linux Rust/C build; systemd/AppArmor startup; NTS, clock/rate/suspend envelopes |
| Finite grants | Shared TPM catalog assignments/grants/revocation, exact typed selector and subject generation, finite validity and input/output/unit ceilings; fresh PAM/catalog/live UTC checks | Native issuance/revocation/admission, expiry and concurrency qualification |
| Inference | Live original-client challenge at submit/claim/admit/finish/delivery, exact physical lease binding, durable inert grant attribution, fixed confined launcher | Real installed client/broker/model route, malicious/stale peer and revocation checks |
| Workflow/artifacts | Principal-bound closed invoice plan, fresh batch grants at worker/effect/checkpoint boundaries, original calculation provenance on retry; reviewed historical acknowledgement without redispatch; exact version export and preserving retention | Native journal/catalog/worker flows, failures at every boundary; wider workflows and retention are not implemented by this path |

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

## Verification and unavailable evidence

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

1. Complete durable ADR-0004 policy decision/outcome records, including normalized
   subject/resource, policy version/digest, stable denial codes, evaluated limits
   and genuine timestamp evidence. Current grant attribution is not that journal.
2. Broader generic DAG, folder-scoped file, worker/resource and multi-consumer
   integration. A governed fixed invoice graph does not implement every graph
   admitted by the schema or all declared grant action kinds.
3. Governed destructive retention/deletion with exact durable outcomes, retention
   quotas and interruption/replay. Preserving rename/export does not close it.
4. Authenticated damaged-authority/ledger/referenced-archive reconstruction from
   exact protected history, after proved drainage. The new shutdown guard is an
   isolation proof, not restoration. Never delete a ledger or substitute an empty
   one to make recovery appear successful.
5. Compile and repair every new Rust/C path in the restored D-backed Linux build
   environment; execute targeted positive/adversarial tests. Then freeze the
   fully implemented candidate, build once on D:, and perform the consolidated
   image/model sweep followed by separate native Ubuntu/physical qualification.

Requirement #2 has not been started. Neither Requirement #1 nor G2 is marked
complete; unavailable compilation does not explain away the remaining software.
