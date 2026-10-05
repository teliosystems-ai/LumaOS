# G2 authenticated UTC publisher source checkpoint

On 2026-10-05, the pinned chrony good-sample publisher fixture, closed measurement
codec and related targeted checks passed on D-backed storage. This completes
the source-hook/codec increment, **not the live trusted-time service or G2**.
No time service was installed or activated, no host clock/TPM/account was changed
and no final image, VM/model sweep or physical qualification was run.

## Implemented boundary

The source preparation script verifies five audited upstream files and exact
single-occurrence patch anchors before modifying a new fixture directory. The
runner first verifies the full source archive SHA-256. Upstream commit
`120dfb8b36b942c31ddfc0220ca1475159ac5031` remains a bounded integration baseline,
not selection of a security-qualified production Ubuntu dependency or verified
upstream signing custody.

The hook runs inside authenticated good-packet admission, before local sample
discipline. A separate authenticated valid-packet hook invalidates all sources
on a non-normal leap report. Source registration requires one instance per
approved exact NTS hostname, strict certificate-time checks, default source
certificate set and no offset/copy override. Authentication configuration alone
does not admit a sample. The pinned source's mode matching and NTS response
validator precede good-sample admission; the retained source-wiring checks verify
this position. These are source/linkage checks, not executed encrypted packet or
certificate attacks. [Upstream NTP admission](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/ntp_core.c),
[authentication dispatch](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/ntp_auth.c).

The publisher emits complete, fixed 232-byte rounds to one nonblocking Unix
datagram destination. Samples retain their sequence, UTC bounds and BOOTTIME
anchor across heartbeats; unavailable payloads are zero. Stale data, missing
samples, source resets/destruction, clock steps/unknown changes, added dispersion,
authenticated leap ambiguity, detected suspend/jump and send failure invalidate
the applicable observations. Counters refuse overflow. Conversion bounds include
the accepted offset/root errors, cooked capture error, age drift, bracketed
capture duration and outward rounding; their clock/error assumptions remain
conditional and must be qualified. The 100-ppm total envelope is not proved by
these tests or by clock comparisons.

`utc_protocol.rs` rejects changed policy, malformed version/length, nonzero
reserved data, duplicate/reordered operator IDs, unknown states, unavailable
payloads and stale/future/negative/inverted/out-of-range samples. It decodes data,
not provenance or a time token. The producer's source-clock generation is
deliberately distinct from the keeper's reviewed reacquisition generation.
See [the protocol and fixture instructions](../image/utc/README.md).

## Executed evidence

The final run is `D:\LumaOS-builds\g2-utc-publisher-targeted-20261005-03`.
All 184 source-manifest files and four supplementary test inputs were checked
against current repository bytes after completion. The tools container used
one CPU, a 768-MiB memory/swap ceiling, a D-backed Linux target volume, no network
and no Linux capabilities. Package acquisition for the small compiler container
was separate; no daemon was run beyond its version-report exit.

Passing scope:

- C publisher assertions with undefined-behavior sanitization and strict
  compiler warnings; separate strict compilation of the actual chrony hook.
- Complete patched chronyd build with `+NTS`, including GnuTLS/nettle linkage.
  The fixture deliberately has `-PRIVDROP -SCFILTER`; it is not a deployable
  hardened daemon, installed service or production release.
- 107 selected ordinary Rust tests and one explicitly executed C-produced-frame
  interoperability test, all with warnings denied; formatting and offline build.
- 17 Python checks, including both pinned-source checks with real captured
  source inputs. No Python test was skipped in this run.

Other ignored PAM/software-TPM/socket integration tests in the selected Rust
modules were not executed by this batch. No upstream NTS unit/attack suite,
live kernel-credential receiver, provider traffic or installed confinement
journey is claimed.

Evidence SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `test.log` | `3800b81a36204bbde5494d2da96541f0b4e4fa7b8f98c3b7a3e5417e8d7fe5b9` |
| `source/build-inputs.json` | `a31d2a734636e0199b055d215ac8c099d6f59600ea23d058b4adec1dfedbc80b` |
| `test-inputs.sha256` | `12cbeb8953594fdf81ed83b72e42abff9107239ed0056f0a98c9b6dfc01182d2` |
| `artifacts/luma-hook-inputs.json` | `c108d7fdc81eed72452259247efc2f9b0b523b290fd131c065bfe3230d409034` |
| `artifacts/chronyd` | `39576c96165267ba498e9227507d8a04db0e33f3c48e243530d07ab185b50f70` |
| `artifacts/c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |

The exact archive SHA-256 is
`d168e1cc284c16941c114929bf015acee8d7993e2c705ce53f97304b7f5c01b8`.
The final targeted compiler container ID is
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
These hashes bind retained test inputs/artifacts; they are not production
signatures, reproducibility proofs or certification.

Failed evidence is retained: compiler trial 01 could not resolve package servers;
the successful retry used WSL networking without host DNS edits. Publisher trial
01 could not restore NTFS archive metadata with capabilities dropped. Trial 02
built/ran the C and Rust checks but had a Python text assertion mismatch and
missing parser-generator warnings. Trial 03 used the D-backed Linux cache,
corrected assertion/dependencies and the authenticated leap invalidation repair.
Only its unchanged captured bytes support the passing checkpoint.

## Open software and qualification

Implement protected live reception with kernel peer/process/runtime verification,
bounded queues/deadlines, replay/epoch handling and genuine resume/clock-change
notifications. A previously queued good frame can survive a publisher failure;
the integrating service must detect and fence that state rather than trusting
parsing or heartbeat age alone. Complete reviewed certificate seed/reacquisition,
TPM-bound time history and uncertain-outcome recovery without resetting ownership
or trust; integrate finite assignment/revocation and final effect-time checks.

Reaudit and pin the eventual production dependency/configuration, constrain its
default certificate store and complete enforcing service confinement. Package
the publisher/receiver and license/corresponding-source obligations into
installer, boot, update and recovery only after those paths exist. Execute
controlled NTS certificate/authentication/replay/leap/outage attacks, then the
consolidated image and separate native Ubuntu qualification. Admin continues to
report `trusted_utc_available: false`; root/decoded frames still confer no grants.
