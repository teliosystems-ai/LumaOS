# Support matrix

Luma OS `0.1.0` is a developer MVP. “Supported” means the repository intends to keep its source-run and test path working; it does not mean production certification or an SLA. Development acceptance and formal OS certification are separate axes: G0/G1 development is complete with explicit deferrals, while formal certification remains blocked. G2 development is in progress and its formal certification is also blocked.

## Platforms

| Environment | Level | Notes |
| --- | --- | --- |
| Ubuntu 24.04 LTS, x86_64, Python 3.11/3.12 | Primary certification baseline target | Source run, tests, packaging, user install, optional systemd user service; physical-board qualification is deferred |
| Ubuntu 24.04 LTS, arm64, Python 3.11/3.12 | Best effort | Standard-library design should work; release CI may not exercise arm64 |
| Current Ubuntu 26.04 LTS under WSL2, Python 3.14.4 | Active development environment | Repository checks and CPU model/gateway smoke; not Ubuntu 24.04, native boot, a physical A1 board, or an E8 migration lab |
| Current native Windows 11 build 26200 | Active development environment | Full current Python suite plus RTX 3050 CUDA direct/gateway smoke passed; this is still not a certified Windows product profile |
| Windows 11 + WSL2 + Ubuntu 24.04 | Intended supported developer path | Run inside the Linux distribution; PowerShell helpers do not install or elevate WSL |
| Native Windows 11 + Python 3.11–3.14 | Development test target | The Windows path rejects reserved names and reparse/junction traversal with pre/open/post identity checks. It lacks POSIX `openat` semantics and does not apply or audit a private DACL; installer and certification work must close those boundaries. |
| macOS | Community/best effort | Not a release target or CI requirement |
| Containers, servers, cloud hosts | Unsupported | No deployment, isolation, authentication, or remote exposure claim |

## Browsers

| Browser | Level | Notes |
| --- | --- | --- |
| Current Firefox on Ubuntu | Primary manual target | Loopback UI |
| Current Chromium/Chrome on Ubuntu | Supported | Loopback UI |
| Current Edge on Windows connecting to WSL loopback | Supported developer path | Windows/WSL forwarding behavior depends on host configuration |
| Embedded/legacy browsers | Unsupported | No compatibility or security guarantee |

## Runtime and data

| Capability | v0.1.0 status |
| --- | --- |
| Dependency-free Python runtime | Supported |
| Loopback web/API process | Supported |
| One local operator/profile | Supported |
| Explicit folder enrollment and scoped local reads | Supported on the documented POSIX/WSL path; native Windows development path passes current traversal/junction tests but is not ACL/broker-certified |
| Durable application-owned local artifact writes | Supported |
| SQLite workflow state and effect receipts | Supported |
| Verified local state export and clean-directory restore | Supported developer operation |
| Unreferenced-object retention preview/prune | Supported developer operation; not secure deletion |
| Invoice report vertical slice | Developer MVP |
| Offline/manual operation without a model | Required baseline |
| Operator-configured local model endpoint | Optional/best effort |
| G1 resource/policy/DAG/model-pack/platform contracts | Development prototype only; not product or hardware certification |
| Install-time model-profile selection | Development-only contract; explicit manual-only, CPU, or CUDA profile is bound into the plan and must pass exact runtime, host RAM, single-device VRAM, storage-peak, context, load, and serving checks; no silent substitution or remote fallback |
| Deterministic fake inference | Test-only; never runtime, quality, or performance evidence |
| Admin role/delegation | Development implementation; fixed product super-role for finite declared activities, not host administrator/root or a production custody certificate |
| Durable Admin authorization events | Development-only singleton SQLite log with canonical exact events, hash chaining, injected HMAC integrity, mandatory external writer authorization, exact catalog-authorization reads, and external-checkpoint matching; independent stores must not share a secret/namespace, and there is no production Admin identity service, process isolation, deployment-domain separation, protected HMAC-secret custody, trusted clock, rollback-resistant anchor, or cross-system atomicity |
| Signed model-catalog verification and admission | Development-only request-before-approval, detached-signature, root-signed public-trust, and exact catalog-admission contracts with distinct production roles, lifecycle/revocation, and transitive catalog/trust freshness; the trusted composition root retains one live clock/provider and exact pack-verification snapshots, which do not live-read pack/runtime bytes, certification/revocation services, or loadability; no private-key handling, provisioned production roots, HSM ceremony, production external anchor, or actual signed production catalog |
| Offline installation-source descriptor | Development-only inert digest-binding contract; validates canonical raw descriptor bytes against a supplied pin, edition, environment, release, anchored catalog context, and trust bundle; a prior result remains readable historical data but is never reusable authority, and the contract does not establish that the pin/edition is governed or verify referenced image, payload, package, SBOM, or signature bytes |
| Ubuntu host inventory and admission | Read-only development contract; trusted absolute probes, fresh inventory, explicit E1/E2 class, and live OS/kernel/identity/security/firmware/accelerator corroboration are required for native-candidate admission; WSL can never pass native admission and a pass never authorizes a disk write |
| G2 installer contract | Development-only and non-destructive; schema v3 binds offline-source/catalog/trust metadata and repeats validation from fresh raw inputs before device/journal entry and after journaling at the effect boundary before current authorization/executor entry; it remains a pure inventory/preflight/confirmation/revalidation/capability/journal boundary, not a disk installer |
| G2 A/B boot-state contract | Development-only pure transition model; no firmware, slot I/O, UKI, dm-verity, LUKS, or actual boot behavior |
| G2 privileged-helper/confinement contract | Development-only typed boundary with injected trust evidence; no privileged service, cgroup/AppArmor/seccomp/KVM, native ACL/DACL, or real peer-credential enforcement |
| G2 durable request/effect ledgers | Development-only bounded SQLite contracts with keyed integrity, owner/generation fencing, `PREPARED`/`APPLYING`/`COMPLETED`/`FAILED_UNKNOWN` crash semantics, fail-fast dispatch CAS, post-CAS current-state validation, safe known-not-applied restoration, semantic completion binding, and keyed commitments instead of stored raw safe-handle tokens; no protected key custody, external rollback anchor, induced power loss, or physical effect adapter |
| G2 safety/catalog/admission boundary | The evolving installer, boot, helper, durable-effect, model, signing-trust, catalog-admission, Admin-event, offline-source, host-inventory, and Ubuntu-preflight suites are green on native Windows and Ubuntu WSL under normal and optimized Python; both lanes share one physical host, and this remains contract/readiness work rather than physical certification |
| Qwen3-4B Q4_K_M + llama.cpp b11100 | Recommended pinned development profile; real Windows CUDA, Ubuntu WSL CPU, and authenticated Luma gateway smoke passed; external unsigned asset, not certified |
| Gemma 4 E2B | Alternative compact candidate only; 5.1B total / 2.3B effective must be recorded explicitly; not downloaded, run, signed, or certified here |
| Gemma 4 E4B | Alternative mainstream candidate; 8B total / 4.5B effective and therefore not a 4–6B-total compact candidate; not downloaded, run, signed, or certified here |
| Real signed 4–6B compact-model inference | Not yet available or certified; the Qwen3-4B smoke does not replace a signed pack, base-image workflow, comparison, or two-board qualification |
| Remote/cloud model service | Unsupported by default |
| Bundled models, weights, tokenizers, or datasets | Not included |
| General autonomous tool execution | Unsupported |
| Writes back into enrolled source folders | Unsupported by default |
| Multiple users or remote identity | Unsupported |
| Production backup, downgrade migration, or HA | Unsupported |

## Installation and deployment

| Method | Status |
| --- | --- |
| Run from checksumed source archive | Supported release method |
| Run from Git checkout | Supported developer method |
| Unprivileged user install script | Supported developer convenience |
| Optional systemd user service | Supported convenience; not enabled automatically |
| Non-destructive installer safety contract | Development prototype only; schema-v3 source revalidation does not verify consumed release artifact bytes and cannot install or alter a disk |
| Pure A/B boot-state contract | Development prototype only; cannot stage, select, boot, or roll back a physical slot |
| Python wheel | Not a supported `0.1.0` artifact; root assets require source layout |
| Bootable ISO | Not implemented |
| Dual-boot installer | Not implemented |
| VM image or lifecycle automation | Not implemented |
| Native Windows installer/service | Not implemented |
| Kubernetes/cluster package | Not implemented or certified |

## Model scale language

The A1 requirements select a 4–6B compact control model. The governed large-model experiment and later A2 work use the 400–405B range. Those ranges are requirements, **not** claims that this MVP certifies them. A pinned Qwen3-4B model has run locally only as an unsigned development profile. Gemma 4 E2B is 5.1B total / 2.3B effective; Gemma 4 E4B is 8B total / 4.5B effective. A 450B target is outside the current governing sources and requires controlled requirements change.

Version `0.1.0` includes model-pack, purpose/lifecycle-bound trust-key, resource, real-loopback-adapter, and fake-backend development contracts, but no shipped weights, signed certified 4–6B pack, qualified scheduler, distributed inference, certified performance baseline, two-board hardware qualification, or cluster certification.

Operators who connect a model are responsible for its license, hardware, runtime, endpoint security, privacy, output validation, and cost.

## Simulator relationship

The standalone visual simulator demonstrates intended interactions. It is not packaged as the reference runtime, does not exercise this process or storage boundary, and is not an acceptance test. Runtime acceptance comes from the source tests and documented manual verification against the API and durable state.
