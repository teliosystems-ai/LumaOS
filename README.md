# Luma OS

Luma OS is a local-first, intent-driven operating-environment **developer MVP**. It demonstrates how a user can describe an outcome, inspect a deterministic plan, approve sensitive capabilities, and review an auditable result from one coherent interface.

> [!WARNING]
> Version `0.1.0` is an engineering preview, not a production operating system. It does not replace Ubuntu or Windows, and it is not safety-, security-, or availability-certified.

## What this repository is

The MVP is deliberately small and dependency-free at runtime. It provides a Python reference implementation and a local browser experience for exercising the core contract:

1. capture a user intent;
2. turn that intent into an inspectable workflow;
3. apply deterministic policy and approval gates;
4. execute only the bounded local tools included in the repository; and
5. retain a transparent event trail.

The implementation is intended for design reviews, local development, automated tests, and early integration experiments. The invoice workflow performs actual grant-scoped local reads and durable application-owned local writes; those effects are not UI simulation. The separate visual simulator is useful for UX exploration, but **simulator behavior is not acceptance evidence** for this runtime.

## v0.1.0 support boundary

| Area | Status |
| --- | --- |
| Ubuntu 24.04 LTS, Python 3.11+ | Primary physical-board certification baseline target |
| Current Ubuntu 26.04 LTS under WSL2 | Active development and test environment; not a certified physical Ubuntu baseline |
| Current native Windows 11 | Active development and CUDA smoke environment; not a certified Windows product profile |
| Windows 11 with WSL2 + Ubuntu 24.04 | Intended supported developer path |
| Native Windows Python | Full current suite passes on Python 3.14; product qualification and Windows ACL/broker work remain |
| Local deterministic/demo model adapter | Included in MVP scope |
| Qwen3-4B Q4_K_M + llama.cpp | Recommended current development profile; real Windows CUDA and Ubuntu WSL CPU/gateway smoke passed, with weights/runtime obtained separately |
| Gemma 4 E2B / E4B | Catalog candidates only: E2B is the compact comparison candidate; E4B is an 8B-total mainstream candidate; neither has been run or signed here |
| Install-time model profiles | Development contract supports explicit manual-only, CPU, and CUDA choices with exact pack/runtime identity and fail-closed RAM, VRAM, storage, context, load, and serving checks |
| Signed 4–6B compact control model | Required for formal G1 closure; not yet certified |
| External model weights | User-supplied and governed by their own licenses |
| G2 safety, catalog, and Ubuntu-admission contracts | Development-only reference contracts; the expanded 128-test nine-module boundary passes on native Windows and Ubuntu WSL under normal and optimized Python, with no physical effects, production signing ceremony, or OS enforcement |
| Bootable ISO, installer image, or hardware provisioning | Not supported |
| Dual boot or VM lifecycle automation | Not supported |
| 400–405B model operation or cluster certification | Not supported |
| Production deployment, multi-user tenancy, or remote exposure | Not supported |

See the complete [support matrix](docs/SUPPORT_MATRIX.md) and [requirements coverage](docs/REQUIREMENTS_COVERAGE.md).

The repository also contains repository-local gate engineering artifacts and
reference contracts. G0/G1 development remains complete with explicit
deferrals, but neither gate has passed formal certification. G2 development is
now **in progress**: code commits
`4ec25b849b3db4363191532bdb06f42894e11253` and
`80980acbac461a9d639df483349bb47a639eefca`, with the safety correction at
`8a8fc8291b42b9a76003dd3e71fa99f9a3117e62` and multi-model selection at
`5667e3d8f337dec326dc8afdec91ed34c1c2eb2a`, add a non-destructive installer
preflight/authorization contract, a pure A/B boot-state transition model,
typed privileged-helper/confinement contracts, and SQLite-backed request and
effect ledgers. The effect ledger records `PREPARED`, `APPLYING`, `COMPLETED`,
and `FAILED_UNKNOWN` crash states, fences owners by generation, uses a
fail-fast compare-and-swap before adapter entry, and persists a keyed
commitment instead of a raw high-entropy safe-handle token. It revalidates
again after the durable `APPLYING` transition, restores a proven-not-applied
attempt to `PREPARED`, and preserves pre-effect capacity exhaustion as safely
retryable. The expanded 128-test G2 boundary (76 installer/boot/helper/durable
tests, 20 model-pack/model-selection tests, and 32 signed-catalog/host-
inventory/Ubuntu-admission tests) passes on native Windows and Ubuntu WSL
under normal and optimized Python.
These contracts do not discover or modify a real disk, boot an image, validate
or install a UKI/dm-verity/LUKS stack, or enforce cgroup, AppArmor, seccomp,
KVM, native ACL/DACL policy, or operating-system peer credentials. The catalog
contract verifies a fully bound request/approval/signature envelope without
handling private keys; it does not claim that a production catalog or custody
ceremony exists. The Ubuntu probes are read-only and WSL can never pass native
candidate admission.

The installer contract also accepts an explicit model-profile catalog and
selected profile. It binds the exact catalog, pack, runtime, context,
execution mode, resource snapshot, and CUDA device into the installation-plan
digest, then revalidates them before the injected executor. It never silently
selects a smaller model or remote service. `manual-only` is an explicit choice,
not an error fallback.

Formal G2 certification is blocked. The deterministic
[gate report](docs/GATE_REPORT.md) and retained
[blocker/deferral records](docs/gates) distinguish development evidence from
missing physical boards, Ubuntu 24.04/E8 fixtures, disposable disks, protected
production signing custody, signed 4–6B packs, the 400–405B experiment, and
qualification runs. Native Windows and its Ubuntu WSL guest share one physical
laptop and therefore never count as two reference boards. The durable ledgers
also remain application-level contracts: power-loss qualification, protected
integrity-key custody, native directory permissions, and a rollback-resistant
external anchor are not present.

## Quick start

### Ubuntu 24.04 or the current Ubuntu WSL development environment

Prerequisites: Python 3.11 or newer and a POSIX shell. No third-party Python package is required to run or test the MVP from source.

```bash
./scripts/run.sh
```

Pass CLI options after the script name:

```bash
./scripts/run.sh --help
```

Run all repository checks:

```bash
make check
```

Prepare Ubuntu evidence without installing software or selecting a disk:

```bash
python3 scripts/collect_g2_host.py --environment-id DEV-UBUNTU --compact
python3 scripts/ubuntu_preflight.py --mode development --pretty
```

Native qualification requires a fresh collector file, an explicit `e1` or
`e2` hardware class, and live corroboration; a pass is admission to the next
lab step, not permission to write a disk. See
[`docs/UBUNTU_QUALIFICATION.md`](docs/UBUNTU_QUALIFICATION.md) and the
[`G2 operator hand-off`](docs/gates/g2/OPERATOR_APPROVAL_AND_EXECUTION.md).

With Node 22+ and Chrome/Chromium installed, run the complete local browser
journey as an additional check:

```bash
make browser-test
```

### Windows PowerShell

The intended supported Windows path is WSL2 with Ubuntu 24.04. The current
Ubuntu 26.04 WSL guest is accepted for development, not certification:

```powershell
.\packaging\wsl\install.ps1
.\packaging\wsl\launch.ps1
```

For a native Python smoke run:

```powershell
.\scripts\run.ps1 --help
```

The WSL scripts never install a distribution or elevate privileges. If WSL2 or Ubuntu is missing, they stop and print the prerequisite command rather than changing the machine.

## Developer install

The optional user install is intentionally unprivileged. It copies the current release under the user's XDG data directory and writes one marked launcher under `~/.local/bin`.

```bash
./scripts/install-user.sh
```

It refuses to replace an existing install unless `--upgrade` is given. Uninstall requires an explicit confirmation flag and removes only paths carrying Luma OS install markers:

```bash
./scripts/uninstall-user.sh --yes
```

An optional systemd **user** service template is available under [`packaging/systemd`](packaging/systemd/README.md). Installation does not enable or start the service unless explicitly requested.

## Repository map

```text
src/luma_os/          Reference runtime
tests/                Standard-library automated tests
scripts/              Source runners, checks, packaging, user install
packaging/systemd/    Optional Ubuntu user-service template
packaging/wsl/        Windows 11 / WSL2 helpers
docs/                 Architecture, security, scope, roadmap, operations
requirements/         Provisional requirement/evidence registry
.github/               CI and contribution templates
```

## Security defaults

- Run locally and bind services to loopback only.
- Treat every tool invocation as untrusted input/output.
- Require explicit approval for capabilities that can mutate data or cross a trust boundary.
- Treat `Admin` as the Luma OS governance role for finite declared delegation, never as implicit Windows Administrator/Linux root authority or a way around effect-time policy.
- Do not place secrets, credentials, personal data, or proprietary model weights in the repository.
- Do not expose the MVP directly to a network or use it for production decisions.

Read the [threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md) before extending tools or adapters.

Release maintainers should follow the non-publishing checklist in [docs/RELEASE.md](docs/RELEASE.md).

## Models and licensing

No model weights are shipped in this repository or release archives. For this
16 GiB laptop and 4 GiB RTX 3050, the recommended current development profile
is the digest-pinned `Qwen3-4B-Q4_K_M.gguf` with llama.cpp `b11100`. It produced
recorded exact-output native Windows CUDA and Ubuntu WSL CPU results, including
authenticated calls through the Luma gateway. This is real 4B development
execution, but the external artifact remains an unsigned developer asset and
is not a signed, execution-certified, or interactive-certified model pack.

Gemma 4 E2B and E4B are retained as alternatives, not as measured results.
Their labels describe effective sizes for dense models with per-layer
embeddings: E2B records 2.3B effective and 5.1B total parameters, while E4B
records 4.5B effective and 8B
total. E2B may enter the governed compact comparison after the requirements
owner accepts that interpretation; E4B belongs in the mainstream 8B comparison
and is not represented as a 4–6B-total model.

Any optional runtime, weights, tokenizer, or remote service must be obtained
separately by the operator. The operator is responsible for its license,
export controls, privacy terms, resource requirements, and output validation.
Luma OS project licensing does not grant rights to third-party models. The
governed large-model range is 400–405B; 450B is outside the current sources and
requires controlled requirements change.

The supported `0.1.0` distribution is the checksumed source archive created by `make package`. Python wheels are not a supported artifact in this release because the runtime intentionally uses repository-root `web/`, `schemas/`, and `examples/` assets. `pyproject.toml` provides metadata and a developer entry point; it does not make a wheel production-complete.

## Contributing

Contributions are welcome within the documented MVP boundary. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and run `make check` before opening a pull request.

## License

Luma OS source code is licensed under the [Apache License 2.0](LICENSE). Model weights, datasets, generated content, trademarks, and third-party components remain subject to their respective terms.
