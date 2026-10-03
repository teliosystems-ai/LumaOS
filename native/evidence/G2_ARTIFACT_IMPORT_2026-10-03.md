# G2 Reviewed Legacy Artifact Import Checkpoint

Status: explicit lab-pair copy implementation and focused source/CLI checks
passed on 2026-10-03. This completes the narrow import path from committed
laboratory invoice pairs into the native ADR-0003 catalog. It does not complete
product schema/principal migration, the production workflow or G2 acceptance.

## Operator review and source preservation

On an installed candidate containing this implementation, root can run
`luma-platform artifact-catalog-legacy-inspect LEGACY-REQUEST-ID` to inspect
the verified source receipt, its review SHA-256 and the proposed catalog receipt.
The operator then passes that exact review digest to
`luma-platform artifact-catalog-import-legacy LEGACY-REQUEST-ID REVIEW-SHA256`.
Inspection proposes a copy; it is not a grant or a workflow execution.

Only the fixed installed source and catalog paths are supported. Both stores
must already exist, match the current installation and share the catalog's
private ext4 filesystem. No initialization, automatic boot migration, path
override, deletion or format downgrade occurs. The native owner takes the
legacy-source lock before the catalog lock and holds both through commit,
replay acknowledgement and database close.

Source admission validates the complete bounded store inventory, canonical
receipts and report digests. Any unresolved source preparation blocks import,
including a replay; the existing reviewed recovery/abort commands remain
separate operator decisions. Retained source preparations are preserved, not
imported or removed. The report's source digest must match its receipt.

The importer copies the exact committed report bytes and preserves workflow,
source and content provenance. It does not recalculate results, fabricate a
signature or bypass a withdrawn workflow. Actual import revalidates the current
installation and signed workflow before publication and immediately before
metadata commit or replay acknowledgement. It rechecks the locked source
snapshot at those boundaries too. Changed reviews, corruption, revocation and
conflicting destination requests cause refusal; already published objects may
remain as verified orphans after a refused commit.

## Stable identity and durable retry

The review digest is SHA-256 of the complete canonical source receipt. The
destination request ID and logical artifact ID both use SHA-256 of the bytes
`luma-artifact-legacy-import-v1`, one NUL byte, then that canonical receipt.
This domain-separated mapping binds the source installation, request and
provenance while keeping logical identity independent of the content digest.
The original source receipt remains available for that mapping.

Import creates version 1 in the existing native `local-root` lab domain. It
uses the unchanged catalog schema/receipt format and the existing synchronized
object-before-transaction ordering. Metadata, version and append-only receipt
commit together. Exact retries after an interruption either finish the same
commit or return its prior receipt without duplicates. Repeating import after
a later version has been published returns the original version-1 receipt;
it does not downgrade or overwrite the current version. This format continuity
is not installed-image update/rollback qualification.

## Verification

Final evidence: `D:\LumaOS-builds\g2-artifact-import-targeted-20261003-03`.

- Source snapshot manifest SHA-256: `6c55e34591bbd67299fbc04e031cdc77076b2095d12aa5608026523eccb22510`.
- Completed test log SHA-256: `645d29f22e7e0419e92ef9e108174704dad61f5a72aa44868532413de4854d3b`.
- All 23 selected Rust tests passed: 13 catalog tests, seven laboratory pair
  store tests and three signed-registry tests. This targeted run did not rerun
  every Rust fixture or promote previously ignored fixtures to passing evidence.
- Formatting, the offline locked build with warnings denied and two
  skill-registry builder tests passed.
- The compiled CLI fixture passed legacy-store, catalog and explicit-import
  checks. Import checks cover independently computed mapped IDs, wrong reviews,
  non-root refusal, byte-for-byte source inventory preservation, unresolved
  source preparation refusal, retry/replay and preservation of later versions.
- Import processes exited abruptly after object publication, before SQL commit
  and after SQL commit. Each exact retry produced only one receipt and left
  source bytes unchanged. Rust hooks additionally checked source mutation,
  report/receipt provenance mismatch, commit-time revocation, competing source
  ownership and destination conflicts.

The fixture uses test-only installed-boot and abrupt-exit interposers, never
packaged into the OS runtime. Operations use real SQLite/ext4 in a disposable
container, not an installed boot, LUKS/TPM qualification or physical power loss.
Native CI inherits the CLI checks through the existing artifact fixture;
remote CI execution was not observed.

The earlier `-01` run passed the narrower import checks. Run `-02` passed Rust
and build checks but failed the new CLI comparison because calculator stdout
has a trailing newline and raw stored artifacts do not. The corrected fixture
uses the same newline handling as the existing calculator check. Failed
evidence was retained; only the fresh final `-03` run binds the completed scope.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs, no network
and no host devices. Docker storage, cache, snapshots and logs stayed on D:;
source stayed on C:. No image rebuild, WSL memory change, TPM ownership change
or unrelated-workload interruption occurred.

## Remaining integration

These commands remain installed-root laboratory interfaces. Product Admin and
principal-bound effect grants, generic/public artifact-schema integration,
trusted timestamps, native DAG supervision and cancellation/checkpoint/restart
are still required. Broader schema/reference/principal migration, receipted
garbage collection, installed recovery/restore and protected rollback remain
open. Existing SQLite dependency qualification limits also remain unchanged;
see the [catalog checkpoint](G2_ARTIFACT_CATALOG_2026-10-03.md).

The consolidated candidate image and separate native Ubuntu evaluation must
exercise the integrated implementation before any G2 completion claim.
