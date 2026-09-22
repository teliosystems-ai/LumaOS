# Release procedure

This is a review checklist for a source release candidate. It does not initialize Git, push a tag, create a GitHub release, publish a package, or upload model assets.

## 1. Confirm scope

- Review `CHANGELOG.md`, `SUPPORT_MATRIX.md`, and `REQUIREMENTS_COVERAGE.md`.
- Confirm the release still says it is not production-ready.
- Confirm no claim is made for a bootable ISO, dual boot, VM lifecycle, 400B models, or cluster certification.
- Confirm visual-simulator behavior is not cited as runtime acceptance.
- Confirm model weights, datasets, secrets, local state, and customer data are absent.

## 2. Synchronize the version

The version must match in:

- `pyproject.toml`;
- `RELEASE_MANIFEST.json`;
- `CHANGELOG.md`;
- `src/luma_os/__init__.py`; and
- API/schema version fields where applicable.

`scripts/check.py` validates the primary metadata pair. Review the remaining human-facing locations before approval.

## 3. Validate a clean candidate

```bash
make check
bash -n scripts/*.sh packaging/systemd/*.sh
make browser-test
```

Run the documented manual smoke flow with synthetic inputs on Ubuntu 24.04 and Windows 11/WSL2. Verify prepare-before-run, durable artifact creation, idempotent repeat behavior, receipts, and restart recovery.

## 4. Build reproducible source archives

```bash
SOURCE_DATE_EPOCH=0 make package
cd dist
sha256sum --check SHA256SUMS
```

Build twice from the same tree and epoch, then compare `SHA256SUMS`. Inspect both archive listings. The archive must include `src/`, `tests/`, `web/`, `schemas/`, `examples/`, `docs/`, `requirements/`, `scripts/`, and `packaging/`. The three governing `.docx` files remain external; verify their pinned digests with `make requirements-sources-check` in the documented workspace layout.

The official `0.1.0` candidate is source-only. Do not publish a wheel: repository-root runtime assets do not yet have a supported installed-package location.

## 5. Independent review

Have a second maintainer verify:

- CI results and supported-platform smoke evidence;
- source/archive checksums;
- license and third-party/model separation;
- security and unsupported-scope language; and
- that the tag intended by a maintainer matches `v<manifest version>`.

The GitHub release-check workflow uploads a temporary candidate artifact only. It deliberately does not create a public release. Publication, signing policy, and tag pushing require a separate authorized maintainer action outside these scripts.
