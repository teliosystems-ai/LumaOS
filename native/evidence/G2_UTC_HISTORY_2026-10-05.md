# G2 UTC history backend checkpoint

On 2026-10-05, the native source gained monotonic UTC floor records, shared
Admin checkpoint replay and a private reviewed history transaction adapter.
The final bounded checks passed on D-backed storage. This implements the
durable semantic backend, **not a deployed UTC writer, authenticated live
provider or completed history integration**. Admin, workflows and G2 remain
open. No host TPM, clock, account, WSL setting, disk ownership or service was
changed, and no image or heavyweight VM/model sweep was run.

## Implemented semantic boundary

`utc_history.rs` defines canonical inert records for a committed minimum UTC
floor. Records bind the deployment/enrollment, authenticated governance
principal, exact request, global journal position and previous checkpoint head.
Their independent history version and previous floor must match the replayed
history exactly. New floors strictly increase; regression, duplicate transitions
and version overflow refuse. An equal-floor no-op creates no payload, version
or checkpoint write. An initial zero floor means no floor event in the verified
history, never permission to infer a missing committed payload was empty.

The source statement also binds the fixed policy digest, boot identity,
producer/source-clock/keeper generations and runtime digest. These are **data
bindings**, not approval of that runtime or proof that a timestamp authenticated.
Missing/unknown fields, noncanonical bytes, unsupported policy, zero identities,
invalid generations and out-of-range values refuse. No serialized live UTC
estimate or grant is introduced.

The Admin semantic replayer now validates interleaved catalog and history
records against the same `Store::snapshot()` and per-position checkpoint heads.
History and catalog versions remain separate. Missing, changed or foreign
payloads deny both history and catalog use. Existing journal canonicalization,
genesis, deployment domain and TPM extension rules are unchanged. There is no
second writable store, new NV index, ownership operation or heartbeat-driven
TPM write.

The private transaction adapter requires the existing explicitly bootstrapped
human principal and a matching observation callback. A proposed floor cannot
exceed the supplied current interval's lower bound; the complete context must
match and interval width/range must remain supported. Review binds the exact
record, current head and TPM reset/restart epoch. Observation and principal
callbacks are renewed during preparation and at all three journal writer
checks, including the final TPM dispatch boundary. Potentially blocking
observation work precedes renewed payload/history checks and principal checks.
Payloads use exclusive no-follow creation and retained exact bytes; uncertain
state is preserved, not overwritten or automatically retried.

An exact historical request can acknowledge its past commit without acquiring
time, lowering the latest floor or writing again. A lost TPM reply leaves the
existing pending-journal fence. Only explicit reviewed publication of the exact
TPM-proven successor can resolve that inert commit; publication never repeats
the write. A different retained proposal, orphan intent, changed epoch or stale
review denies. This is not a clock-seed or trust-reset recovery operation.

**The writer has no CLI, IPC or installed-service route.** Its callback seams
are not authenticators merely because they return successfully. The future
protected composition root must supply approved live UTC provenance and fresh
principal authentication. `Stream::attach` still receives a numeric floor;
binding the current authenticated history to keeper and effect checks is not
implemented by this checkpoint. A historic floor cannot restore UTC, satisfy
certificate bootstrap or enable `trusted_utc_available`.

## Executed checks and retained evidence

Final run: `D:\LumaOS-builds\g2-utc-history-targeted-20261005-03`.
All 188 captured source files and five supplementary test inputs matched current
repository bytes. Passing scope:

- 170 selected ordinary Rust tests, including five new history-model tests and
  thirteen new governance/history transaction tests. These cover mixed replay
  and restart, exact acknowledgement, no-ops/regression, cross-activity request
  collisions, principal and source loss at final dispatch, stale review/TPM
  epochs, payload substitution, journal rollback, orphan intent and explicitly
  reviewed publication after a lost write reply. Semantically forged records
  are rejected even when their fake checkpoint matches.
- Five explicit Rust fixtures: 16 datagram cases, ten receiver/keeper cases,
  one final-queue case and retained C binary/JSON decoder interoperability.
  There were 175 passing Rust test invocations, including 27 kernel cases.
- 26 Python checks without skips, formatting, warnings-denied locked offline
  native build and isolated runner shell syntax.

**The new history transaction tests use fake checkpoint and observation
adapters.** Real filesystem preparation/replay is exercised, but these tests
are not physical TPM writes, delivered PAM authentication, NTS traffic,
power-loss qualification or installed-service evidence. The existing kernel
fixtures exercise credentials/processes/timers, not historical UTC truth.
The ordinary tests are covered by the full isolated runner's default Rust test
selection; that complete TPM/PAM runner and remote CI were not executed here.

The runner used one CPU, 768-MiB memory and memory-plus-swap ceilings, pids limit
128, all capabilities dropped, no network, no host devices/Docker socket and
D-backed cache/evidence. Docker root was `/mnt/luma-build/docker`. Tools image:
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
Unchanged C artifacts and pinned upstream source were reused from the
[JSON transport checkpoint](G2_UTC_JSON_TRANSPORT_2026-10-05.md); no C/chronyd
rebuild or fixture daemon execution occurred in this batch.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `af5704ca98e8715898f0c28e65bd57c48657b07e8a35a986efba6587149c7ec5` |
| `test-inputs.sha256` | `b08c5291afed38b6fefaaa24a4c4ddbb911ec36312779d0c69205c0a53c3bbec` |
| `test.log` | `f8a91871b82651bafc30b9506754e6a08727550b9c3f11c3d3b9e867c144d132` |
| Reused `c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |
| Reused `c-envelope.bin` | `25afbe5bf754baf6f8cda9abe2d5c91ff7a25b1a72498da93ca30fdb8f88b0aa` |

Failed trials `01` and `02` are retained. Trial `01` exposed an incorrect test
expectation for the catalog's initial version; trial `02` passed Rust/build but
failed a formatting-sensitive Python assertion. Both assertions were corrected;
trial `03` attests the final unchanged source/test inputs. Hashes bind evidence,
not production signatures, certification or reproducibility.

## Remaining integration and qualification

Complete the protected UTC runtime/provider and independently approved service
composition; then connect this writer and current floor replay to keeper
acquisition and final authorization/effect boundaries. Implement the reviewed
certificate seed/bootstrap and recovery ceremony without resetting history,
with complete lifecycle/resume delivery and qualified rate bounds. Review
deployment interfaces and future history/policy/principal migration before
activating them. No new transport or authority endpoint is approved here.

Native finite Admin assignment/revocation, current resource/effect grants,
production workflow/supervisor integration, installer/boot/update/recovery
composition and production custody remain open. The consolidated image and
separate native Ubuntu target must qualify the actual paths, including physical
TPM durability and interrupted recovery. See the
[completion register](../G2_SOFTWARE_STATUS.md) and
[implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md).
