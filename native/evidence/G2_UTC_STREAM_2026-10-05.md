# G2 receiver and keeper composition checkpoint

On 2026-10-05, the Linux receiver-to-keeper source composition passed bounded
checks on D-backed storage. It closes this composition increment, **not the
trusted UTC service, Admin, workflows or G2**. No product listener, CLI, assignment
or effect authority was enabled. Host clocks, accounts, devices, TPM ownership
and WSL settings were unchanged; no final image or heavyweight sweep was run.

## Implemented behavior

The receiver now returns every validated round in its bounded batch, rather than
only the last one. `utc_stream.rs` owns the receiver and keeper and reduces rounds
in order. An intermediate loss of quorum or disagreement fences the session even
when later samples would otherwise form a usable candidate. No earlier candidate
escapes a failed batch. Producer source-clock and keeper acquisition generations
are explicitly distinct; changed producer epochs refuse rather than being adopted.

The keeper retains the current complete source inventory separately from sample
replay history. Quiet polls recompute/project from that inventory at fresh local
clock boundaries, never return the saved interval or resurrect a missing source.
The producer heartbeat must remain within the conservative one-second real-age
deadline (at most 999 measured milliseconds under the assumed rate envelope).
Expired heartbeats, clock errors, process/queue changes and explicit lifecycle
invalidation fence the session without automatic recovery. The composition
rechecks the peer/queue and reads live clocks before its final projection.

This is still measurement data and arithmetic, not UTC authority. Observing a
process does not approve its binary, certificate configuration or confinement.
The supplied numeric floor is not authenticated TPM history; notification delivery
and the 100-ppm clock-rate assumption remain unqualified. Kernel REALTIME is a
consistency coordinate, not a substitute UTC source. The publisher's leap
invalidation contract is inherited, not an independently executed NTS proof.

## Executed evidence

Final run: `D:\LumaOS-builds\g2-utc-stream-targeted-20261005-03`.
All 186 captured source files and five supplementary test inputs matched current
repository bytes after completion. Passing checks were:

- 142 selected ordinary Rust tests across UTC, Admin, authentication/principal
  and workflow modules, including 11 new composition tests.
- Four explicitly selected fixtures: 14 datagram cases, eight receiver/keeper
  cases, one final-queue-recheck case and retained C-frame interoperability.
  The run has 146 passing Rust test invocations, including 23 kernel cases.
- 21 Python checks, including real pinned-source preparation/guard checks;
  none skipped. Rust formatting, warnings-denied locked offline build and
  isolated-runner shell syntax checks also passed.

Composition kernel cases include valid batches, quiet projection, queued quorum
loss followed by restored samples, explicit loss, descriptor rejection, producer
exit, explicit invalidation and a history conflict. Synthetic helper intervals
are test data, not provider traffic or authority. Helpers own and reap their
child processes; no unrelated workload is stopped.

The cached tools container was
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
It ran with one CPU, a 768-MiB memory and memory-plus-swap ceiling, pids limit 128,
all capabilities dropped, no network, no host devices/Docker socket and a
D-backed Linux target volume. Docker root was `/mnt/luma-build/docker`.
The unchanged C frame and pinned chrony source were reused from the
[publisher checkpoint](G2_UTC_PUBLISHER_2026-10-05.md); no C/chronyd rebuild was
performed in this batch.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `13dd3db04648d61fa6c8f5af8582fe629307202d690f21b0aa746cbcb670950e` |
| `test-inputs.sha256` | `3655282b5e91f5861bf60ad278dbf2b27ad3b12965ba58bd124e2ce75e9c2098` |
| `test.log` | `d40cdbda1c0161926a2d559cb9bd93858e2f147e5be0a8a9fa89be39d87eba29` |
| Reused `c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |

Failed evidence remains retained. Trial `01` passed its Rust checks but a Python
wiring assertion did not tolerate a formatting line break. Trial `02` reached
the kernel executable-change case and exceeded its 500-ms child synchronization
wait. Trial `03` fixes the text assertion, bounds that test-only wait at five
seconds and asserts the exact process/runtime-change refusal. Receiver processing
and heartbeat deadlines were not loosened. Only final unchanged captured inputs
support this passing checkpoint; hashes are not production signatures.

## Test automation and remaining integration

`native/tests/run_tpm_boundaries.sh` now explicitly selects all three UTC kernel
fixtures and retains their logs. Each fixture can also be selected in isolated
Linux tools, for example:

```sh
cargo test --offline --locked utc_receiver::tests::kernel_keeper_composition -- --ignored --exact --nocapture --test-threads=1
```

The complete TPM runner, remote/full CI, other ignored PAM/TPM integrations and
the full workflow fault matrix were not executed by this batch. No live provider,
NTS certificate/packet attack, installed confinement, final image or native Ubuntu
qualification is claimed.

Next integration requires an approved protected supervisor, immutable producer
code/configuration and confinement, protected lifecycle/resume notification
delivery, authenticated time history and reviewed bootstrap/recovery. Rebuilding
this source object is not recovery consent and cannot bypass history conflicts.
Transport review/adaptation under ADR 0002 remains required before deploying the
experimental telemetry endpoint. Admin finite assignment/revocation and current
effect grants, production workflow/supervisor integration and installer/update/
recovery composition remain open. See the [completion register](../G2_SOFTWARE_STATUS.md)
and [implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md).
