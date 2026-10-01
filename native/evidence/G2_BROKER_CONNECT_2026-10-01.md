# Bounded native broker connection - 2026-10-01

Commit `c0345fe` saved the preceding verified response-validation repair and
sequence-11 export checkpoint. No push was performed. G2 remains incomplete.

## Runtime change

The client previously used a blocking Unix-socket connection before creating
its three-second I/O deadline. A full broker listen queue could therefore
hold the CLI before its framed-I/O timeout applied.

The Linux native client now creates its pathname socket with nonblocking and
close-on-exec flags atomically. A busy queue or any other connection error is
a refusal, with the owned descriptor closed; it does not retry, reuse an
uncertain connection, change endpoints or select a weaker transport. On
immediate success, it restores blocking I/O for the existing deadline-aware
framing helpers. One monotonic deadline now begins before connection and is
retained through kernel peer authentication and request/reply transfer.

The fixed product endpoint, root-peer check, request/response identity checks
and server authorization rules are unchanged. The private connector rejects
relative, abstract, embedded-NUL and overlong pathnames rather than truncating
them. Its small Linux FFI boundary initializes the full address, passes its
exact structure size and transfers each successful socket allocation to RAII
before any later fallible operation.

This follows the Linux [connect(2) nonblocking Unix-socket semantics](https://man7.org/linux/man-pages/man2/connect.2.html)
and [unix(7) pathname addressing](https://man7.org/linux/man-pages/man7/unix.7.html).
It is queue-admission refusal, not a guarantee of broker fairness, cancellation
of server-side effects, a real-time scheduler bound, or protection against a
compromised root. Root remains distinct from the required product Admin.

## Executable checks

Two new Rust tests check invalid/missing/expired endpoints and a real Linux
listen queue with backlog one. The latter fills the queue, requires prompt
`WouldBlock`, verifies kernel peer identity and descriptor flags, drains only
its own fixture connections, and proves a new connection can then succeed.

The disposable-container CLI integration now fills its real private broker
queue before running the actual binary with a five-second outer deadline.
It requires nonzero exit and no success output without accepting any queued
connection. After explicitly releasing capacity, the existing successful
exchange and 13 malformed/denied response cases run unchanged. This tests
actual process behavior, not a mocked `connect()` return value.

Verification completed successfully from frozen source under
`D:\LumaOS-builds\g2-broker-connect-tests-20261001-01`, using the dedicated
D-backed tools container, no network or host devices, 768 MiB and one CPU.
Offline locked Rust tests/build and formatting/warnings checks passed, along
with **61 ordinary Rust tests**, all **15 real CLI cases**, and all **112 native
Linux Python tests** (warnings treated as errors). Seven specialized Rust
tests were ignored in this ordinary run, not rerun or counted as new passes.
`git diff --check` passed. The CLI refused the full queue in approximately
5 ms in this fixture, then passed the valid exchange after capacity returned;
that observed duration is not a certified performance bound. The complete
verification process exited zero. The prior checkpoint retains its separate
executed evidence.

Frozen input SHA-256 identities:

- `source/build-inputs.json`:
  `50cd14d99cd9ad04c26139b7f3284e05c6ba34a4d857acda9095e5488294c716`.
- `source/native/tests/broker_client_integration.py`:
  `43ea8cf9a6ee463b0e5b5e5498b798d08bfedf12573bd76940de6d005eb1c5fc`.
- Completed `test.log`:
  `bf9089c6dbdea7c55f7886de1c465868b65ca8d34e3bca707ba5e33e93a7d5f9`.
- `cli/result.json`:
  `613db1672df2b72af96172b6a0ea53b970e7384a7960944b83b7b7a817f4ad1c`.
- Executed debug binary (also recorded in the CLI result):
  `1db790eac1c268ec6e853db0b39c9b920a06cba1c768964f1a116e4d63a8f115`.

The standard source manifest includes the native Rust implementation; native
tests are copied separately into the frozen source tree. The second digest
identifies the executed CLI fixture. Later documentation edits do not alter
the tested source or active VM harness.

## Image acceptance status

All ten sequence-11 artifact checksum entries passed. The frozen desktop
runner also verified the exact raw image digest and started a fresh 32 GiB
virtual-target installation using virtual Secure Boot, software TPM and
software display. The guest passed live readiness (including verity, AppArmor,
Secure Boot and TPM observations) and refused a modified release signature and
4B admission on the 4 GiB greeter fixture. Both refusal probes preserved the
checked first MiB of the fresh target; this is not a whole-disk no-write proof.
The manual-only installation command is now running. Neither a completed
installation, installed desktop result nor graphical login has passed yet.

Current logs:

- `D:\LumaOS-builds\g2-desktop-acceptance-20261001-01\run.log`.
- `D:\LumaOS-builds\work\20261001T090338Z-desktop\vm-desktop-greeter-20261001-01\install\serial.log`.

The 4B model queue remains serialized behind a passing desktop result. The
active image/harness are frozen and were not modified. **Neither this change
nor the response-validation repair is in sequence 11**; both require a later
image rebuild and evaluation. All bulk output remains on D:, source on C:.
No physical disk, firmware or TPM state was changed.
