# Support matrix

Luma OS `0.1.0` is a developer MVP. “Supported” means the repository intends to keep its source-run and test path working; it does not mean production certification or an SLA.

## Platforms

| Environment | Level | Notes |
| --- | --- | --- |
| Ubuntu 24.04 LTS, x86_64, Python 3.11/3.12 | Primary | Source run, tests, packaging, user install, optional systemd user service |
| Ubuntu 24.04 LTS, arm64, Python 3.11/3.12 | Best effort | Standard-library design should work; release CI may not exercise arm64 |
| Windows 11 + WSL2 + Ubuntu 24.04 | Supported developer path | Run inside the Linux distribution; PowerShell helpers do not install or elevate WSL |
| Native Windows 11 + Python 3.11/3.12 | Smoke only | Core import/tests where platform semantics permit; secure folder traversal is designed for POSIX/WSL |
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
| Explicit folder enrollment and scoped local reads | Supported on the documented POSIX/WSL path |
| Durable application-owned local artifact writes | Supported |
| SQLite workflow state and effect receipts | Supported |
| Verified local state export and clean-directory restore | Supported developer operation |
| Unreferenced-object retention preview/prune | Supported developer operation; not secure deletion |
| Invoice report vertical slice | Developer MVP |
| Offline/manual operation without a model | Required baseline |
| Operator-configured local model endpoint | Optional/best effort |
| G1 resource/policy/DAG/model-pack/platform contracts | Development prototype only; not product or hardware certification |
| Deterministic fake inference | Test-only; never runtime, quality, or performance evidence |
| Real signed compact-model inference | Not yet available or certified |
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
| Python wheel | Not a supported `0.1.0` artifact; root assets require source layout |
| Bootable ISO | Not implemented |
| Dual-boot installer | Not implemented |
| VM image or lifecycle automation | Not implemented |
| Native Windows installer/service | Not implemented |
| Kubernetes/cluster package | Not implemented or certified |

## Model scale language

The broader Luma OS product requirements discuss model sizes from compact models through 400B-class systems. That range is a product/deployment taxonomy, **not** a claim that this MVP runs or certifies those models. Version `0.1.0` includes model-pack, resource, and fake-backend development contracts, but no weights, qualified GPU runtime, certified scheduler, distributed inference, performance baseline, hardware qualification, or cluster certification.

Operators who connect a model are responsible for its license, hardware, runtime, endpoint security, privacy, output validation, and cost.

## Simulator relationship

The standalone visual simulator demonstrates intended interactions. It is not packaged as the reference runtime, does not exercise this process or storage boundary, and is not an acceptance test. Runtime acceptance comes from the source tests and documented manual verification against the API and durable state.
