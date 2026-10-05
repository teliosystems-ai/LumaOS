# Authenticated UTC publisher source fixture

This is the pinned-source chrony good-sample hook and closed measurement codec
for G2 development. It is **not installed**, not a trusted-time service and not
an authorization API. Admin's trusted-time status remains false. The production
dependency, approved confined receiver/supervisor, reviewed bootstrap, deployed history and grant
integration remain open. Do not start the fixture daemon on the host.

## Source boundary and retained samples

`prepare_chrony.py` prepares a new build directory from the audited upstream
commit `120dfb8b36b942c31ddfc0220ca1475159ac5031`. `test_fixture.sh` verifies the
full input archive digest before extraction; preparation verifies the five
auth-boundary/build files and exact single-occurrence patch anchors. This is
an integration baseline, not signed-release verification or selection of a
current security-qualified Ubuntu production package. Reaudit and repin the
whole eventual dependency and patch before packaging it.

The hook is inside authenticated good-packet admission, before chrony processes
the sample for local discipline. Operator identity is the configured exact NTS
hostname, not a reverse lookup, address count or report flag. The dedicated
publisher disables on unknown sources, duplicate operator instances, non-NTS
configuration, source offset overrides, nondefault source certificate sets, copy mode or
disabled certificate-time checks. NTS mode and the upstream per-packet
validator are both required. Missing samples and source resets remove retained
observations. Destroying an instance, clock steps/unknown changes, added
dispersion, an authenticated non-normal leap report, detected suspend/jump and
send failure invalidate all observations.

The producer retains each accepted observation's own sequence and BOOTTIME
anchor. A heartbeat never changes either. At the configured 100-ppm rate bound,
an observed age above 179982 ms is unavailable because its conservative real
age exceeds 180 seconds. Invalid replacements remove the previous sample.
Round and clock counter overflow refuse rather than wrapping.

UTC conversion uses the accepted sample's remote-minus-local offset, complete
root delay/dispersion, cooked-clock capture error, acquisition-age drift and
bracketed capture duration, with outward integer rounding and a 2-ms guard on
each side. Cooked local time is a coordinate combined with the authenticated
offset; bare REALTIME is not UTC authority. Conversion is deliberately bounded
to 1970 through 2100, a five-second acquisition age, a 20-ms capture span and
finite limited errors/offsets. These are refusal limits, not new owner-approved
authorization policy. The total 100-ppm envelope, honest operator error claims,
capture math and cooked-clock discipline assumptions still need runtime and
hardware qualification. Secondary BOOTTIME/MONOTONIC checks cannot prove every
suspend or small clock step was observed.

## JSON measurement envelope

The source publisher sends ADR-0002's four-byte unsigned big-endian payload
length followed by UTF-8 JSON. The complete datagram is bounded to 2048 bytes
before decoding. Its length must match exactly. The receiver accepts no raw
binary fallback; the former 232-byte `LUMAUTC1` codec remains only an internal
C snapshot helper and Rust test fixture.

| Field | Required meaning |
| --- | --- |
| `schema_version`, `method` | Integer 1 and exact `utc_measurements` |
| `request_id` | `utc-BOOTHEX-PROCESSGEN-CLOCKGEN-ROUNDSEQ`, matching the measurement epoch |
| `caller` | Positive signed-32-bit PID and unsigned-32-bit real UID, both checked against per-message kernel credentials; the receiver separately pins the kernel GID |
| `deadline`, `deadline_clock` | Capture BOOTTIME plus exactly 999 milliseconds, with exact `boottime`; overflow refuses |
| `measurements` | Lowercase fixed-length policy digest and boot UUID; nonzero process/source-clock/round generations; BOOTTIME/MONOTONIC/REALTIME capture coordinates; exactly three ordered sources |
| Each source | Operator 1, 2 or 3, boolean availability, sample sequence, observed BOOTTIME, signed UTC lower and upper milliseconds; all sample fields zero when unavailable |

BOOTTIME deadlines are boot-scoped acquisition limits, not trusted UTC expiry.
The existing receiver checks them with fresh kernel clocks before returning
measurements, including conservative rate-error accounting. Missing, duplicate
or unknown fields at every object level, wrong numeric types, invalid UTF-8,
truncated/trailing data, reordered IDs, changed policy, stale/future samples
and negative/inverted intervals refuse. Parsing establishes neither NTS proof
nor authority. REALTIME remains a jump-detection coordinate only.

The fixture sends nonblocking datagrams only to
`/run/luma-utc/measurements.sock`, with a nominal 500-ms heartbeat. There is no
scraper, caller-selected destination, retransmission of failed batches or
public time token. A queued previously good datagram can outlive a failure;
the integrating service must enforce live peer, queue-age/deadline and epoch checks
and invalidate pending authorizations. The producer's source-clock generation
is separate from the keeper's reviewed reacquisition generation; never treat
them as automatically identical or silently reset either.

The native `utc_receiver.rs` boundary now receives per-message kernel
credentials, pins an observed producer with a pidfd and before/after process
fingerprints, drains at most eight queued rounds under a 100-ms return budget
and rejects stale/replayed/mismatched epochs and sample identities. Unknown or
truncated ancillary data and descriptor passing refuse; delivered descriptors
are closed before denial. A bad later queued frame prevents returning an earlier
good frame. Failure fences the stream; no cached round is returned when it is
empty. These are decoded measurements, not clock authority.

The receiver preserves every round in its bounded batch. `utc_stream.rs` joins
that batch to the keeper, so an intermediate loss of quorum/disagreement cannot
be hidden by a later restored source set. Producer source-clock and keeper
acquisition generations are mapped explicitly, not treated as identical. A quiet
poll reprojects the current source inventory using fresh local clocks only while
the last producer heartbeat is within the conservative one-second deadline;
it does not return a saved interval or restore an unavailable operator. Errors
and lifecycle notifications fence the session with no automatic recovery.
The source composition performs a final peer/queue and live-clock check. It
still lacks independently approved runtime, installed history and lifecycle
notification delivery, and cannot enable assignments or effect authority.

The composition now owns a nonblocking, close-on-exec `CLOCK_REALTIME` timer
armed with absolute cancel-on-set semantics. It checks this kernel clock-step
notification before and after candidate work. Cancellation, expiration, read
errors or unverifiable outcomes fence the session; consuming the event does not
rearm the watch or restore time. This supplements numeric clock comparisons,
not NTS provenance, rate qualification or complete suspend/resume notification
delivery. Source checks verify real timer configuration/expiration and injected
cancellation-result handling without setting any host clock. Actual clock-step,
step-and-restore and suspend races need separate kernel/image qualification.

`BoundStream` now takes an internal semantic `HistoryReader`, not a numeric
floor. The reader borrows the Admin owner's existing shared checkpoint store
and replays all catalog/history payloads around fresh checkpoint checks. Its
private binding includes the deployment, enrollment, historical writer, exact
shared head, monotonic floor/version and TPM reset/restart epoch. Each poll
checks that binding before and after candidate work; any shared-head change,
unverifiable replay or epoch change fences. After blocking history reads, it
rechecks the peer/queue, samples fresh clocks, reprojects and checks the kernel
step watch. A delayed read cannot extend the producer-heartbeat deadline.
Raw numeric construction is test-only outside private module assembly.

This is a source composition, not a new listener or authority token. It gives
the keeper no TPM-owner credentials and writes no history per poll. A saved
floor cannot create an initial estimate, approve the publisher or authenticate
the current human. The protected runtime, actual history writer, effect-time
composition, certificate bootstrap and recovery ceremony remain open. See the
[history binding evidence](../../evidence/G2_UTC_HISTORY_BINDING_2026-10-05.md).

This module accepts an already-provisioned socket descriptor and an observed
process context. It does not bind a production listener, approve that process's
code/confinement, restore protected history or authorize recovery. The integrating
supervisor must supply independently approved immutable code/configuration,
enforcing profiles and current lifecycle/clock notifications. An unchanged
fingerprint or live PID does not establish those approvals, and polling cannot
prove an unreported transition never occurred. Re-executing the same image
also requires generation/lifecycle handling, not inode checks alone.

This source adaptation removes the binary-serialization mismatch with ADR-0002.
The experimental measurement method, BOOTTIME deadline profile, socket type,
logical service owner, provisioning and confinement still need deployment
architecture/security review before an installed endpoint is enabled. It does
not supersede the ADR or approve a new listener, time service or role authority.

## Targeted build on Ubuntu

Run only in an isolated build environment with no host clock privilege or
network during tests. Required compiler packages include GCC, make, bison,
pkg-config, GnuTLS and nettle development headers, Python 3 and the repository's
offline Rust dependencies. The small tools Dockerfile extends the existing
tools image; it is not a final OS image.

```sh
bash native/image/utc/test_fixture.sh /path/to/pinned-chrony-source.tar.gz /new/output
cd rust
cargo test --offline --locked utc_protocol::
cargo test --offline --locked utc_stream::
cargo test --offline --locked utc_step_watch:: -- --test-threads=1
cargo test --offline --locked utc_receiver::tests::kernel_keeper_composition -- --ignored --exact --nocapture --test-threads=1
cargo test --offline --locked utc_receiver::tests::kernel_shared_history_composition -- --ignored --exact --nocapture --test-threads=1
LUMA_UTC_C_FRAME=/new/output/c-frame.bin cargo test --offline --locked \
  utc_protocol::tests::c_publisher_cross_language_frame -- --ignored
LUMA_UTC_C_ENVELOPE=/new/output/c-envelope.bin cargo test --offline --locked \
  utc_protocol::tests::c_publisher_cross_language_envelope -- --ignored --exact
```

The C fixture checks finite-input rejection, interval direction, preserved
age/identity, loss, leap refusal, exact age boundaries and generation overflow.
The Rust tests bound all truncations and protocol substitutions and explicitly
decode the C-produced JSON envelope and historical binary fixture. A compiled `+NTS` daemon proves source linkage,
not an encrypted packet/certificate journey or installed confinement. Controlled
NTS authentication attacks and service delivery tests remain required.

The linked C publisher/hook/test sources are GPL-2.0-only, matching upstream
chrony. Production distribution must retain upstream notices, corresponding
source, the patch and license text. This does not change the independent Rust
program's repository license.
