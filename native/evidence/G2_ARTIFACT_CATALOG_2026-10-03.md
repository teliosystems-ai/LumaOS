# G2 Native Artifact Catalog Checkpoint

Status: native backend and bounded source/CLI verification passed on 2026-10-03.
This checkpoint implements ADR-0003's content-object and transactional
metadata ordering in Rust. The current invoice commands remain installed-root
laboratory interfaces, not the completed principal-authorized workflow or G2.

## Native storage behavior

The separate private ext4 catalog stores immutable objects under lowercase
SHA-256 names. Logical artifact identity and monotonically increasing version
identity are independent of object identity. Deduplication is restricted to
the current installation's `local-root` domain; no other principal/domain or
digest-probing API is admitted.

A commit synchronizes its temporary object, publishes it without overwrite,
synchronizes the object directory and then inserts the version, current
version pointer and canonical receipt in one SQLite transaction. Expected
current versions implement compare-exchange. Objects published before a
failed metadata commit remain visible as unreferenced objects; no successful
receipt can refer to absent or corrupt content. Exact retries revalidate
current installation/signed workflow and the prior object/receipt before
returning the earlier outcome. Changed requests and stale versions are refused.

SQLite uses WAL with full synchronization, bound parameters, private files,
foreign keys and a closed, versioned schema. Database triggers reject changes
or deletion of receipt/version history, identity changes, artifact deletion
and skipped version advancement. Admission validates schema, database
integrity, version continuity, canonical receipts and object digests. Unknown
formats or inconsistent state are refused without reset or downgrade.
The synchronization choice follows the
[SQLite synchronous documentation](https://www.sqlite.org/pragma.html#pragma_synchronous).

Interrupted complete temporary bytes can be retried only with matching content,
current authority and expected version. Partial bytes are never truncated or
automatically deleted. Status exposes a review digest; explicit retention
moves reviewed bytes intact to retained state and blocks reuse of the request
ID. Other requests may proceed within the shared capacity bounds. Orphans and
retained preparations have no automatic garbage collector.

Limits are 1,024 committed versions, 2,048 object/preparation files, 64 MiB of
their bytes and a 2 MiB object. Metadata has a separate 4,096-page/4 KiB limit;
database/WAL/shared-memory file admission is bounded. New object writes observe
a 16 MiB filesystem reserve but do not reserve capacity against external root
allocation. No weak filesystem or durability fallback is allowed.

Fresh-install setup and the SQLite runtime dependency are wired into source.
Updated older installations require explicit catalog initialization. The
earlier laboratory pair store remains untouched; it is not silently migrated.
The existing offline recovery archive includes the catalog through
`lib/luma-os`. An isolated, quiescent-copy test is not installed-image archive
restore or TPM enrollment continuity qualification.

## SQLite ownership and qualification

One native owner holds the exclusive directory lock before opening SQLite,
including initialization, reads, recovery and connection close. Competing
native owners are refused. Direct SQL writers/checkpoint tools must remain
offline; the test's schema inspection closes its connection before native
commands resume. WAL must accompany a live database for a valid backup; see
[SQLite WAL file handling](https://www.sqlite.org/wal.html#the_wal_file).

The fixture uses Ubuntu `libsqlite3-0:amd64` version
`3.45.1-1ubuntu2.8` from the existing pinned tools image. The root/tools package
lists now explicitly include that dependency. Upstream documents a
[WAL-reset race](https://www.sqlite.org/wal.html#walreset) involving concurrent
writing/checkpointing connections in older releases. This backend's ownership
rule excludes that usage, but the distribution backport/patch status still
requires qualification before release. A package version and source test do
not by themselves certify the library or the OS security baseline.

## Verification

Evidence: `D:\LumaOS-builds\g2-catalog-targeted-20261003-03`.

- Source snapshot manifest SHA-256: `0fcbdfdc1ac34864ce1fd1d2e45df78600a6c76ae6c27504f722db646ad42c27`.
- Completed test log SHA-256: `68240e1a112ff9d20dcd6112b7998f3c3a52d1c1bee9174256bdafd2f66c05e0`.
- All 164 enabled Rust tests passed; 18 emulator, PAM or privileged mount
  fixtures were explicitly ignored, not reported as passes. Nine catalog tests
  cover durable versions/replay/deduplication, stale-version refusal, object
  publication before metadata, transaction rollback, revocation, lost commit
  acknowledgement, reviewed retention, append-only triggers, corruption,
  missing objects, schema/installation mismatch, concurrency, non-ext4 refusal,
  path/link guards and quiescent copy/unknown-format refusal.
- Formatting, the offline native build with warnings denied, both compiled CLI
  exercises and two skill-registry builder checks passed. The catalog CLI
  checks actual WAL storage, versions, deduplication, current-version conflicts,
  abrupt exits after object rename/before SQL commit/after SQL commit, exact
  retries, retained partial bytes, non-root rejection, SQL mutation refusal and
  corrupt-object rejection.

Earlier `-01` and `-02` runs passed narrower/earlier versions of these checks;
their evidence was retained, not substituted for the final source binding.

The fixture supplies a synthetic installed boot marker using a test-only C
interposer. Another test-only interposer exits the native process at the named
boundaries without running destructors. Neither enters the OS runtime. These
checks exercise real SQLite/ext4 operations under simulated installed/crash
conditions, not an OS boot, LUKS qualification or physical power loss. Native
CI uses the same disposable CLI fixture; remote CI execution is unobserved.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs, no network,
no host devices and a disposable ext4-backed container volume. No image was
rebuilt, no WSL memory setting changed, and no unrelated workload was stopped.
D: holds Docker storage, cache and evidence; C: holds source.

Product Admin/principal-bound grants, generic artifact and public-schema
integration, trusted timestamps, native DAG supervision, cancellation/restart,
format/legacy migration, receipted garbage collection, installed backup/restore
and protected rollback remain open. The consolidated candidate and separate
Ubuntu machine must evaluate the integrated implementation before G2 closes.
