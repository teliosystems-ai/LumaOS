# Authenticated UTC publisher source fixture

This is the pinned-source chrony good-sample hook and closed measurement codec
for G2 development. It is **not installed**, not a trusted-time service and not
an authorization API. Admin's trusted-time status remains false. The production
dependency, confined receiver, reviewed bootstrap, protected history and grant
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

## Measurement frame

All integers are little endian. The complete frame is exactly 232 bytes, with
one fixed magic/version and three ordered source entries. Reserved fields are
zero; unavailable entries contain no sample payload.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `LUMAUTC1` |
| 8 | 32 | Domain-separated digest of the exact approved policy bytes |
| 40 | 16 | Kernel boot UUID |
| 56 | 8 | Random nonzero producer-process generation |
| 64 | 8 | Producer source-clock invalidation generation |
| 72 | 8 | Increasing complete-round sequence |
| 80 | 8 | Capture BOOTTIME milliseconds |
| 88 | 8 | Capture MONOTONIC milliseconds |
| 96 | 8 | Signed host REALTIME milliseconds, jump-detection coordinate only |
| 104 | 8 | Reserved zero |
| 112, 152, 192 | 40 each | Operator ID, state, six zero bytes, then sample sequence, observed BOOTTIME, signed UTC lower and upper milliseconds |

State zero is unavailable; state one is a normal-leap accepted sample. Unknown
states, duplicate/reordered IDs, invalid timestamps, stale/future samples,
nonzero reserved bytes, changed policy, truncated/extra bytes and negative or
inverted intervals refuse in `utc_protocol.rs`. Parsing establishes neither
NTS proof nor freshness at use: those checks belong to the protected receiver.

The fixture sends nonblocking datagrams only to
`/run/luma-utc/measurements.sock`, with a nominal 500-ms heartbeat. There is no
scraper, caller-selected destination, retransmission of failed batches or
public time token. A queued previously good datagram can outlive a failure;
the future receiver must enforce live peer, queue-age/deadline and epoch checks
and invalidate pending authorizations. The producer's source-clock generation
is separate from the keeper's reviewed reacquisition generation; never treat
them as automatically identical or silently reset either.

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
LUMA_UTC_C_FRAME=/new/output/c-frame.bin cargo test --offline --locked \
  utc_protocol::tests::c_publisher_cross_language_frame -- --ignored
```

The C fixture checks finite-input rejection, interval direction, preserved
age/identity, loss, leap refusal, exact age boundaries and generation overflow.
The Rust tests bound all truncations and protocol substitutions and explicitly
decode the C-produced frame. A compiled `+NTS` daemon proves source linkage,
not an encrypted packet/certificate journey or installed confinement. Controlled
NTS authentication attacks and service delivery tests remain required.

The linked C publisher/hook/test sources are GPL-2.0-only, matching upstream
chrony. Production distribution must retain upstream notices, corresponding
source, the patch and license text. This does not change the independent Rust
program's repository license.
