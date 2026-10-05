# G2 UTC history binding checkpoint

On 2026-10-05, the native source connected shared Admin semantic history to the
non-authorizing UTC stream. The production-source constructor now requires a
fresh internal history reader instead of a caller-supplied numeric floor.
Bounded D-backed checks passed. This closes that source input gap, **not the
deployed UTC provider, history writer, effect authority or G2 acceptance**.
No host clock, TPM ownership, account, service or WSL setting was changed;
no image build, VM/model sweep or live NTS journey was run.

## Shared history reader

`admin_governance::HistoryReader` borrows the Admin owner's existing checkpoint
store. It requires verified explicit bootstrap, current enrollment bytes and
complete semantic replay of the mixed catalog/history journal. Every payload
must match its authenticated journal entry and prefix. Orphan or pending state,
missing/substituted payloads, invalid transitions and disk/anchor mismatches
deny. No separate anchor, credential loader, NV allocation or writer is added.

Each read brackets semantic replay with fresh checkpoint snapshots, then
repeats the replay before returning. A matching journal head alone cannot
prove payload integrity. TPM reset/restart epochs must remain unchanged and
powered-time cannot regress within or between successful reads by that reader.
An unverifiable read sticks in the fenced state, even if the test restores
the affected input. TPM powered-time is not treated as UTC.

The private, non-serializable binding includes deployment, enrollment digest,
historical governance principal, exact shared checkpoint head, floor/version
and TPM reset/restart epoch. A verified bootstrapped history with no floor
records returns zero; an unbootstrapped or damaged history does not. The
historical writer identity is not current human authentication, and the floor
is not a current UTC estimate or capability.

## Stream binding and final freshness checks

`utc_stream::BoundStream` obtains that binding during construction and checks
it again before and after each poll's candidate work. The numeric assembly
routine is private; the external numeric constructor exists only in test
builds. Any shared-head change, including a catalog-only mutation with an
unchanged floor, fences rather than silently refreshing the binding. Failure
requires explicit reconstruction; it does not reset history, automatically
reacquire UTC or redispatch an effect.

After potentially blocking history replay, the stream checks the current
producer and quiet queue, samples fresh local clocks, reprojects the current
source inventory and checks its kernel step watch. It never returns the
candidate sampled before those reads. Slow replay cannot extend the producer
heartbeat deadline; telemetry arriving during the final replay also denies.
A candidate behind the verified floor retains reconciliation-required state.
Before the first fresh measurement, polling still returns no estimate.

This source composition does not give a separate keeper daemon TPM-owner
credentials, enable a listener, serialize time authority, write per heartbeat
or change Admin's `trusted_utc_available: false`. Immutable runtime approval,
logical service ownership and confinement remain deployment work.

## Executed checks

Final evidence: `D:\LumaOS-builds\g2-utc-history-binding-targeted-20261005-03`.
All 188 source-manifest entries and five supplementary test inputs were
checked against current repository raw-byte hashes. Passing scope:

- 174 selected ordinary Rust tests, including four new history-reader tests
  covering bootstrap, floor replay, read-only behavior, powered-clock/epoch
  fencing, catalog-only head changes and payload/enrollment/pending/orphan
  mutations after the first semantic pass.
- Six explicit Rust fixtures: 16 datagram cases, ten receiver/keeper cases,
  one final-queue case, twelve new shared-history/UTC cases and retained C
  binary/JSON decoder interoperability. Total: 180 passing Rust test
  invocations, including 39 kernel cases.
- 28 Python checks without skips, formatting, warnings-denied locked offline
  native build and shell syntax for the isolated runner.

The twelve new composition cases cover quiet polling without checkpoint
writes, initial absence of time, a floor ahead of measurements, catalog/floor
changes, pending state, enrollment changes, missing payloads, TPM epoch change,
invalid anchor head, messages or payload changes during final history reads,
and a read delayed beyond the heartbeat deadline. The delay and queued-message
cases assert the exact final-boundary refusal. New cases are wired into the
full isolated runner, but that complete TPM/PAM runner and remote CI were not
executed here.

**History tests use fake checkpoint and observation adapters.** The case named
`anchor-unavailable` injects an unusable fake anchor head; it is not a TPM
transport-outage experiment. Kernel sockets, credentials, processes, timers
and the D-backed Linux filesystem are real, but the fixtures do not establish
authenticated UTC truth, physical TPM durability, PAM delivery, installed
confinement, power-loss behavior or actual clock-step/suspend delivery.

The source test container used one CPU, a 768-MiB memory/memory-plus-swap ceiling,
128-pid limit, all capabilities dropped, no network, no host devices or Docker
socket and D-backed cache/evidence. Docker root was `/mnt/luma-build/docker`.
The tools image ID was checked against
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
Unchanged C artifacts and pinned upstream source were reused from the
[JSON transport checkpoint](G2_UTC_JSON_TRANSPORT_2026-10-05.md), not rebuilt or
run as a time daemon.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `e8f70654397ccfe21c506c5b7c0848392b525dfd69e34f8b6246f506579f12a8` |
| `test-inputs.sha256` | `f6334868cde7e2f7e4ea15ca020907516ff37c8ac8fbb90f8a9ae3853d0c76a7` |
| `test.log` | `df4c5725f15e1f680dd6a7012295a799f1b61c1d376cc87d110c503faf87d1ef` |

Trial `01` is retained: its future-floor fixture observation exceeded the
supported year-2100 upper bound and was correctly refused. The fixture was
corrected without weakening validation. Trial `02` passed; trial `03` reran
the final source after stronger exact-error assertions and documentation.
Evidence hashes bind inputs/results, not production signatures or certification.

## Remaining implementation and qualification

Complete the approved protected runtime/provider and actual authenticated
history writer, reviewed certificate seed/bootstrap and recovery, full lifecycle
delivery, qualified clock/rate bounds and final effect-time revalidation.
Maximum-capacity replay latency, device outages and concurrent installed-service
behavior need qualification. The separate Ubuntu machine must evaluate the
actual distributed image, not this source fixture.

Finite Admin assignment/revocation and resource/effect grants, production
workflow supervision, broader model leases/rollback, generated-code isolation,
installed desktop/account journeys, installer/boot/update/recovery integration
and production custody remain open. See the [completion register](../G2_SOFTWARE_STATUS.md)
and [implementation sequence](../G2_IMPLEMENTATION_FIRST.md).
