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
| Deterministic fake inference | Test-only; never runtime, quality, or performance evidence |
| Admin role/delegation | Development implementation; fixed product super-role for finite declared activities, not host administrator/root or a production custody certificate |
| G2 installer contract | Development-only and non-destructive; pure inventory/preflight/confirmation/revalidation/capability/journal boundary, not a disk installer |
| G2 A/B boot-state contract | Development-only pure transition model; no firmware, slot I/O, UKI, dm-verity, LUKS, or actual boot behavior |
| G2 privileged-helper/confinement contract | Development-only typed boundary with injected trust evidence; no privileged service, cgroup/AppArmor/seccomp/KVM, or real peer-credential enforcement |
| G2 safety tests | 49 tests across installer, boot-state, and helper modules under normal and optimized-Python execution; contract evidence only, not physical certification |
| Qwen3-1.7B Q4_K_M + llama.cpp b11100 | Pinned development smoke baseline; real Windows CUDA, Ubuntu WSL CPU, and authenticated Luma gateway smoke passed |
| Real signed 4–6B compact-model inference | Not yet available or certified; 1.7B smoke does not satisfy it |
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
| Non-destructive installer safety contract | Development prototype only; cannot install or alter a disk |
| Pure A/B boot-state contract | Development prototype only; cannot stage, select, boot, or roll back a physical slot |
| Python wheel | Not a supported `0.1.0` artifact; root assets require source layout |
| Bootable ISO | Not implemented |
| Dual-boot installer | Not implemented |
| VM image or lifecycle automation | Not implemented |
| Native Windows installer/service | Not implemented |
| Kubernetes/cluster package | Not implemented or certified |

## Model scale language

The A1 requirements select a 4–6B compact control model. The governed large-model experiment and later A2 work use the 400–405B range. Those ranges are requirements, **not** claims that this MVP runs or certifies them. A pinned 1.7B model has run locally only as a development smoke baseline. A 450B target is outside the current governing sources and requires controlled requirements change.

Version `0.1.0` includes model-pack, purpose/lifecycle-bound trust-key, resource, real-loopback-adapter, and fake-backend development contracts, but no shipped weights, signed certified 4–6B pack, qualified scheduler, distributed inference, certified performance baseline, two-board hardware qualification, or cluster certification.

Operators who connect a model are responsible for its license, hardware, runtime, endpoint security, privacy, output validation, and cost.

## Simulator relationship

The standalone visual simulator demonstrates intended interactions. It is not packaged as the reference runtime, does not exercise this process or storage boundary, and is not an acceptance test. Runtime acceptance comes from the source tests and documented manual verification against the API and durable state.
