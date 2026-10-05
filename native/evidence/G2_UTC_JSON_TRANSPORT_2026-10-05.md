# G2 UTC JSON transport checkpoint

On 2026-10-05, the experimental UTC publisher and receiver were adapted to
ADR-0002's length-prefixed JSON envelope and passed bounded source checks on
D-backed storage. This removes the binary serialization mismatch in source,
**not the remaining deployment review or trusted UTC integration**. Admin,
workflows and G2 remain open. No product listener, time authority or assignment
was enabled, and no host clock, TPM ownership, WSL setting or device was changed.

## Implemented source boundary

The publisher now emits a four-byte unsigned big-endian payload length followed
by UTF-8 JSON, with a 2048-byte bound including the prefix. Every bounded C
append checks its remaining capacity. Formatting failure produces no sendable
length and invalidates observations. The hook sends only the actual encoded
length and asserts its real PID and UID, not a configured role or identity.
The prior binary snapshot routine remains an internal C helper and historical
fixture; the Rust binary decoder is compiled only for tests. The runtime
receiver accepts **JSON only**, with no binary fallback.

The closed experimental method profile requires schema version 1, exact
`utc_measurements`, a request identity derived from the boot/process/source-clock
epoch and round sequence, and a BOOTTIME deadline exactly 999 milliseconds
after capture. Overflow refuses. This is a boot-scoped acquisition budget, not
trusted UTC expiry. The existing receiver validates age and clock consistency
with fresh kernel readings before returning every admitted batch.

JSON PID and real UID must equal the actual per-message `SCM_CREDENTIALS`.
The receiver separately requires the pinned producer's PID, UID and GID and
rechecks its live process/runtime observation. Every nested object rejects
missing, duplicate or unknown fields and wrong types. Fixed lowercase policy
and boot identities, nonzero generations/sequences, capture ordering and the
exact ordered three-source inventory are checked. Unavailable sources carry
zero sample fields; measured sources retain their own identity and age.
Malformed UTF-8, truncated/trailing/oversized payloads and invalid intervals
refuse. Kernel descriptor passing is still rejected and received descriptors
closed; any error retains the existing sticky stream fence.

These wire objects carry measurements, not authority. They do not make an
observed process an approved publisher, authenticate a supplied history floor
or prove certificate/sample provenance. The keeper/receiver/stream do not gain
serializable authority or a product CLI. The image continues to use its prior
clock service; the experimental chronyd is not installed or run as a daemon.

## Executed checks and retained evidence

Final run: `D:\LumaOS-builds\g2-utc-json-targeted-20261005-02`. All 187 captured
source files and five supplementary test inputs matched repository bytes.
Passing scope:

- Sanitized C publisher tests, strict warnings-denied hook compilation and a
  newly patched chronyd build reporting `+NTS`. The C tests include framing,
  caller/deadline refusal, overflow and maximum-width numeric output.
- 152 selected ordinary Rust tests across UTC, Admin, principal/authentication
  and workflow modules. Five new JSON tests cover closed fields, caller claims,
  every truncation, malformed UTF-8, wrong types, duplicate fields, epoch/policy
  substitution, inventory/age limits and maximum counters.
- Five explicitly selected Rust fixtures: 16 actual-kernel datagram cases,
  ten receiver/keeper cases, one final-queue case, historical C-frame decoding
  and new C-to-Rust JSON decoding. There were 157 passing Rust test invocations,
  including 27 kernel cases. Caller-spoofing cases use the correct pinned kernel
  sender and assert the exact JSON caller-refusal reason.
- 24 Python checks without skips, formatting, warnings-denied locked offline
  native build and isolated runner shell syntax.

The C-to-Rust decoder fixture supplies expected PID 246 and UID 1001 as test
data; it is not kernel authentication of that file. Separate live datagram
fixtures exercise Linux credentials with owned helper processes. `chronyd -v`
proves linkage/features only, not live NTS traffic, certificate checks,
production hardening or installed service confinement. The build fixture has
`-PRIVDROP -SCFILTER` and must not be distributed as the production daemon.
No actual clock step, suspend, final image or heavyweight VM/model sweep ran.

The cached tools image was
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
Docker root was `/mnt/luma-build/docker`; the isolated runner used one CPU,
768-MiB memory and memory-plus-swap ceilings, pids limit 128, all capabilities
dropped, no network, no host devices/Docker socket and D-backed cache/evidence.
The pinned chrony archive digest remains
`d168e1cc284c16941c114929bf015acee8d7993e2c705ce53f97304b7f5c01b8`.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `5104e3c3c8195658033cb0aeed4ff70fecd99cd439fe46730260ee87fa4dcc6e` |
| `test-inputs.sha256` | `c085a5ec3a82c68cdf3330042500cfcadf9543f87d2b6343064af5bb351374d1` |
| `test.log` | `f34526b05c1aa886be5abe1a34a87604f853cde3b7cf810b9b8749188f5a28a3` |
| `artifacts/c-envelope.bin` | `25afbe5bf754baf6f8cda9abe2d5c91ff7a25b1a72498da93ca30fdb8f88b0aa` |
| Historical `artifacts/c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |
| `artifacts/luma-hook-inputs.json` | `4b98535129538400226ecbb64beff9e134642f958660f250c44a42294f5732ea` |
| Fixture `artifacts/chronyd` | `32194f9fa61f8d851bf1113f10b0cf4aed9e97419af9f4b88568ef6b1b48bd39` |

Passing trial `01` is also retained. Final trial `02` strengthens the exact
caller-denial assertion and invalid-UTF-8 check. Only its unchanged captured
inputs attest this checkpoint. Artifact hashes are evidence identities, not
production signatures, reproducibility or certification.

## Remaining implementation and qualification

[ADR-0002](../../docs/adr/0002-service-boundaries-and-transport.md) is not
superseded by this adaptation. Before enabling any endpoint, review the
experimental method and BOOTTIME deadline profile, socket type, logical
service owner, protected provisioning and confinement. Implement the approved
runtime/supervisor, complete lifecycle/resume delivery, authenticated TPM time
history and reviewed bootstrap/recovery, then integrate current finite Admin
assignment/revocation and effect-time grants. No new NV domain or TPM ownership
operation is implied.

Production dependency/custody, live NTS attack journeys, clock-rate and
step/resume qualification, installed services and installer/boot/update/recovery
composition remain required. The full TPM/PAM runner, remote CI and wider
workflow fault matrix were not executed in this batch. Follow the
[software completion register](../G2_SOFTWARE_STATUS.md) and
[implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md) before freezing
the consolidated image and qualifying it on the separate native Ubuntu target.
