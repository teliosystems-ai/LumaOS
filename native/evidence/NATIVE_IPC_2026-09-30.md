# Native broker deadline and rebuild checkpoint — 2026-09-30

G2 is not complete. These are bounded IPC transport changes to the existing
laboratory broker, not implementation of the remaining Admin/policy service.

## Implemented boundary

The broker previously used a two-second socket timeout with `read_exact`.
That is a per-read limit: a peer sending another fragment within each timeout
could keep the single connection handler occupied indefinitely.

The native framing code now sets one monotonic deadline across the complete
header and body, recomputes the remaining kernel timeout for each partial
read/write, and refuses expired operations even if bytes are already buffered.
Zero/oversized frames are refused before body allocation; truncation and
interrupted calls are bounded. Response writes use the same whole-frame
discipline. The broker uses two seconds per read/write frame; the local client
retains its three-second allowance, now also measured across the entire frame.

This does not implement fair scheduling under a connection flood, effect
deadlines around systemctl, cancellation/reconciliation, finite Admin roles,
resource leases or durable effect receipts. The current UID/action authorization
surface is unchanged. No new write-capable request or authority was granted.

## Executed evidence

`D:\LumaOS-builds\native-tests-20260930-ipc-export-02` passed:

- 55 ordinary Rust tests. Seven specialized tests were ignored in that ordinary
  invocation; the real-full-filesystem export test was then explicitly run and
  passed in a private namespace.
- Six new real Unix-socket tests: fragmented success, slow header/body sharing
  one budget, expired buffered input/output, zero/truncated frames, stalled
  response receiver, and response round-trip/size bounds.
- All 50 Linux Python tests, no skips. Four new guest-probe oracles cover
  response framing/truncation, current identity binding and root refusal.

Evidence inventory SHA-256:
`cad9907c3329576840077731d2d716991e25f5f055e0fb3c565492f27bbb5060`.
Rust transcript SHA-256:
`e553ad62f3680bc6cce89f12e7fb56e0208b501ee302a11887327aa9324d4749`.

The preceding `native-tests-20260930-ipc-01` source snapshot passed the full
software-TPM/PAM runner and 46 Python tests. Its result SHA-256 is
`5659ce702940a5423195d17d5a84cabe50edb68899e7e81c6c9e4853304444e7`.
It predates the final preservation of the client's three-second allowance and
the four probe tests; the later combined run above covers the final source.

Tools: `luma-native-tools:20260929-auth`, network disabled, read-only repository.
Only the isolated ENOSPC test used mount privileges/private tmpfs. No host TPM,
block device or production private key was exposed.

## Sequence-10 image integration

Later status: assembly and verified export completed after repair of a
shell-driver continuation failure; the retained artifacts were reused without
rebuilding. The original test queue stopped, and a corrected serialized queue
now follows the resumed sequence-9 model suite. See the
[build-resumption checkpoint](NATIVE_BUILD_RESUME_2026-09-30.md). The paragraphs
below retain the original build-start context; queued tests are still not passes.

Build `20260930T073705Z-headless` is running:

- Work: `D:\LumaOS-builds\work\20260930T073705Z-headless`.
- Expected export: `D:\LumaOS-builds\native\20260930T073705Z-headless`.
- Linux volume: `luma-native-build-20260930T073705Z-headless`.
- Release: `luma-native-lab-20260927-headless-10`.

Preflight observed 13,502,210,048 free bytes on C: and 303,388,688,384 on D:;
the builder's capacity checks were not bypassed. Existing artifacts, VM disks,
private lab keys and unrelated workloads remain untouched.

The image contains the candidate transactional exporter and bounded IPC code.
The serialized pipeline waits for exact verified export and the current
sequence-9 VM pipeline to finish, then uses **the sequence-10 build's source
snapshot**, not a mutable checkout, to run fresh disposable-disk suites:

1. Full regression with Secure Boot/TCG, strict late shutdown, atomic-export
   failure/retry checks and slow-frame broker probes as UID 990.
2. Four-stage PAM/PCR/strict-shutdown fixture (not Admin enrollment).
3. Qwen3-4B acquisition, inference, fresh offline completion and recovery disable.

Only the model install guest permits publisher-download networking. Each suite
must pass before evidence export and the next suite. The new guest export/IPC
checks are queued, not passed. Build success alone is not installation or G2
acceptance; real hardware, production custody and the other software components
in the completion register remain open.
