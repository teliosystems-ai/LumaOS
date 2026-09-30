# Recovery archive publication checkpoint — 2026-09-30

G2 remains incomplete. This is source-level Linux execution evidence, not
installed-image, physical power-loss, production custody or Admin acceptance.

## Implemented repair

The native recovery exporter previously wrote directly to `luma-user-data.tar`.
A failed producer could therefore leave incomplete bytes under the completed
archive name; the parent directory was not synchronized before reporting success.

`rust/luma-platform/src/recovery_export.rs` now implements the actual recovery
command's tar invocation and publication boundary:

- Walk an absolute destination using directory descriptors without following
  symlinks. Require an operator-owned directory not writable by other users.
- Hold an exclusive nonblocking directory lock and require an empty inventory.
- Create only `luma-user-data.tar.partial`, exclusively and privately (0600).
- Run the fixed tar producer without inherited environment or stdin. Synchronize
  completed bytes, verify the partial's identity/link count/private permissions,
  publish with no-overwrite rename, then synchronize the directory.
- Retain failed partials and refuse automatic retry into a nonempty destination.
  Never delete existing operator data or silently fall back to weaker filesystem
  semantics. A final directory-sync failure remains an uncertain outcome.

Archives remain unencrypted and contain user/account/state material. This is
not encrypted backup, resumable export, authority enrollment or protection
against a malicious root controlling the whole machine. Unsupported destination
permissions, locking, synchronization or no-overwrite rename cause refusal.

## Executed evidence

Pinned tools image: `luma-native-tools:20260929-auth`.

`D:\LumaOS-builds\native-tests-20260930-recovery-export-02`:

- 49 ordinary Rust tests passed; 7 specialized tests were explicitly ignored in
  that ordinary invocation. Seven new ordinary tests cover actual tar round-trip
  and producer failure, partial retention, no overwrite, competing exporters,
  path/symlink rejection, renamed directories and substituted/hard-linked partials.
- The additional ignored export test was explicitly executed and passed in a
  private mount namespace. A real 1 MiB tmpfs returned `ENOSPC` during a 2 MiB
  write; the partial remained, no final name appeared and retry was refused.
- 43 Linux Python tests passed in that immutable source snapshot. A subsequent
  pinned-container run, after adding three recovery-fixture oracles, passed all
  46 Python tests with no skips.

Evidence inventory SHA-256:
`c01d989aace078cfc7096f646aefa295c6a2562583e69eab41df1020e527cd97`.
`enospc-test.txt` SHA-256:
`5051a4a0f46c2720e693df12137e10dd12e0d9480d2b7e19d122503df9a7c658`.

The earlier `native-tests-20260930-recovery-export-01` snapshot also passed the
native software-TPM/PAM runner and 43 Python tests. Its result SHA-256 is
`c9e8d42661531706527fa086d3766632be490896938cf124b2f4f21701d0148b`.
That snapshot predates the tar-wrapper and real-full-filesystem additions; its
results are not substituted for the later export-specific execution.

No host block device or TPM was exposed. The mount test used only a disposable
container/private tmpfs; evidence was written to D:. No prior VM or artifact
was deleted.

## Image acceptance still required

Sequence 9 predates this repair. A subsequent rebuild and image execution are
required before it can be distributed as containing the new export behavior.

`vm_test.py --require-atomic-export` adds a complete archived-content hash
check, real guest tmpfs exhaustion, partial preservation, retry refusal and
private-mode checks to the full recovery sequence. It cannot be combined with
smoke-only testing. The fixture flag is implemented/unit-tested but has not
passed against a rebuilt image. Actual interrupted-power durability, damaged
source media, filesystem/device compatibility and the broader G2 matrix remain
separate requirements.
