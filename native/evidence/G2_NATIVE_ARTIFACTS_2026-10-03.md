# G2 Native Laboratory Artifact Checkpoint

Status: bounded source and compiled-CLI checks passed on 2026-10-03. This
checkpoint adds a native installed-root invoice artifact prototype and reviewed
interruption recovery. It does not complete the production artifact-write
skill, native workflow supervisor, product Admin or G2.

## Implemented scope

The fresh installer initializes a private store on encrypted `/var`, bound to
the existing installation identity. Runtime operations never silently create
or reset missing state. An explicit `artifact-store-init` supports older
installations with the required principal registry and refuses existing state.

`artifact-publish-invoice REQUEST-ID` consumes bounded CSV on stdin, verifies
the fixed image-owned lab skill signature/workflow, calculates deterministic
monthly totals and publishes a complete report/receipt directory. The receipt
binds input and content hashes, byte count, installation, workflow, root UID,
request and fixed report metadata. Synchronization precedes no-overwrite
publication and a successful acknowledgement; failures retain uncertain state.
Exact retries verify and resynchronize the existing pair, with current
installation/signed-workflow checks both before processing and before returning
success. Conflicting request data is refused. `artifact-read` verifies the
receipt and report before returning content.

One pending preparation fences new publications. `artifact-store-status`
provides a publication review hash only for a complete intact pair. Explicit
`artifact-reconcile` revalidates the review and current signed workflow before
publication. Safe incomplete preparations instead expose an abort review hash
binding every observed member's name, length and digest. `artifact-abort`
moves those bytes intact into retained state, permanently prevents request-ID
reuse and permits a new request. Recovery retries verify and synchronize their
existing outcome. Unknown members, links, unsafe ownership/modes, stale reviews,
integrity failures and inconsistent identities are refused, not deleted.

An exclusive nonblocking descriptor lock serializes store operations. Inventory
and reads are bounded to 1,024 committed/retained records, 64 MiB of their
report/receipt bytes, a 2 MiB report and one pending preparation. Publication
observes a 16 MiB filesystem reserve; it does not reserve capacity against
external root processes. Retained records consume capacity and are not garbage
collected. The existing recovery archive includes this store through
`lib/luma-os`; its export remains sensitive and unencrypted.

This is a root-only laboratory pair store, not the authoritative product
storage specified by [ADR-0003](../../docs/adr/0003-artifact-storage.md). It does
not supersede production SQLite WAL metadata, content-addressed objects,
logical artifact/version identities or their transactional receipt ordering.
Product storage integration remains required. A valid lab signature is an
integrity check, not a product Admin or principal-bound effect grant. Root can
still alter or roll back local state; no TPM anchor is claimed.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-artifacts-targeted-20261003-05`.

- Source snapshot manifest SHA-256: `ed9f073946321c56e7d3f24564d8ca03def9c69ed4269aecae1477425192d4ec`.
- Completed test log SHA-256: `32b2bb7db241893e93a0cbf4217aa0159a9802dc74e02f4fa0a540204e94c67a`.
- Seven artifact tests, five calculation, three signed-registry and six
  principal regression tests passed. Artifact tests inject interruption after
  preparation-directory creation, content synchronization, receipt
  synchronization and publication; cover lost acknowledgements, conflicting
  retries, reviewed completion, retained abort/replay, current authorization,
  revocation, preserved bytes, request reuse refusal, tampering, symlinks,
  unknown members, installation mismatch and concurrent-store exclusion.
- The offline native build with warnings denied, formatting, two skill-registry
  builder tests and the repeatable compiled-CLI fixture passed. The CLI checks
  explicit initialization/refusal, actual publication/read/replay, conflicts,
  malformed inputs, non-root rejection, reviewed completion, retained abort,
  stale reviews, further publication and integrity refusal.

`native/image/test_artifact_cli.sh` is wired into native CI. It requires a
fresh disposable tools container with no Luma runtime state or TPM devices.
The test-only C interposer supplies a synthetic installed `/proc/cmdline`
marker, and the Python fixture constructs interrupted preparations. These
are simulated boot/interruption conditions, not an installed boot, physical
power loss, PAM authentication or TPM qualification. The interposer is not
packaged into the OS runtime. CI execution itself has not been observed here.

The successful local run used one CPU, 768 MiB memory with no extra swap,
128 PIDs, no network and no host devices. Docker cache and evidence stayed on
D:, source on C:, and WSL memory/unrelated workloads were unchanged. The
earlier `-01` attempt failed because Docker refused a `/proc/cmdline` bind
mount; its evidence was retained. `-02` and `-03` passed earlier publication
implementations, and `-04` passed the recovery changes before the shared CI
runner. Those snapshots do not replace the final `-05` source binding.

No image was rebuilt or booted. The consolidated candidate must evaluate
fresh-install integration, archive retention, shutdown/recovery interruption,
storage pressure and the completed principal-authorized workflow. Native
supervision, policy-bound source grants, production artifact storage,
cancellation/checkpoint/restart semantics and product Admin/trust integration
remain open implementation work.
