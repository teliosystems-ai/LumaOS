# Contributing to Luma OS

Thank you for helping improve the Luma OS developer MVP. Contributions should make the local, inspectable intent-to-workflow contract easier to understand, test, or evaluate without implying production readiness.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues follow the private process in [SECURITY.md](SECURITY.md).

## Before you start

Open an issue for significant behavior, interfaces, security boundaries, packaging, or scope changes. A small fix may go directly to a pull request. Keep proposals inside the [v0.1 support boundary](docs/SUPPORT_MATRIX.md).

The following are intentionally out of scope for this release:

- production deployments or remote multi-user hosting;
- a bootable ISO, dual-boot installer, or VM lifecycle automation;
- 400B model or cluster certification;
- bundled model weights or datasets; and
- treating the visual simulator as runtime acceptance evidence.

## Set up a development environment

Use Ubuntu 24.04, WSL2 with Ubuntu 24.04, or a compatible local Python 3.11+ environment.

```bash
git clone <your-fork-url>
cd luma-os
./scripts/run.sh --help
make check
```

There are no third-party runtime or test dependencies. Do not add one without an accepted design discussion that covers maintenance, licensing, platform support, and a standard-library alternative.

## Make a focused change

- Prefer small, reviewable commits with a single purpose.
- Add or update `unittest` coverage for behavior changes.
- Preserve deterministic behavior in tests and demo adapters.
- Keep network access opt-in and disabled in default paths.
- Make policy and approval decisions explicit in code and events.
- Use synthetic fixtures; never commit secrets, personal data, proprietary prompts, model weights, or customer files.
- Update architecture, threat model, support, and coverage documents when their claims change.

## Validate locally

```bash
make check
```

The check compiles source in a temporary directory, runs the standard-library test suite, validates release metadata, and checks required documentation. Packaging can be tested separately:

```bash
make package
```

Review the generated manifest and checksums under `dist/`. Generated archives are not committed.

## Pull request checklist

- [ ] The change has a clear user or engineering outcome.
- [ ] Tests cover the success path and relevant failure/policy path.
- [ ] `make check` passes on a clean checkout.
- [ ] No secrets, sensitive data, model weights, build outputs, or local state are included.
- [ ] User-visible changes are recorded under `Unreleased` in `CHANGELOG.md`.
- [ ] Documentation and threat-model assumptions are updated where needed.
- [ ] The change does not claim unsupported production or hardware certification.

By submitting a contribution, you agree that it is licensed under the repository's Apache License 2.0 and that you have the right to contribute it.
