# G2 UTC interval arithmetic checkpoint

The [trusted UTC design](../TRUSTED_UTC_DESIGN.md) is a proposal, not an approved
or activated source policy. This checkpoint implements and tests its inert
interval arithmetic. It does not qualify a trusted clock or complete G2.
ADR-0004, ADR-0007 and ADR-0010 remain unchanged.

## Implemented scope

`rust/luma-platform/src/utc_bounds.rs` now compiles into the native source tree.
It has no product entry point, clock reader, network client, IPC endpoint,
serialized authority token or authorization integration. Measurement, epoch
and policy inputs are arithmetic data; they do not prove authentication,
operator independence, correct acquisition timing or a protected live clock.

The core provides validated nonnegative integer intervals, whole-interval
finite-window checks with strict expiry, checked elapsed-time projection,
outward rounding, bounded age/uncertainty, distinct policy-local operator IDs,
and boot/provider/clock/policy epoch matching. Under the conditional one-fault
assumption, three inputs retain the hull of all pair intersections; two
overlapping inputs retain the full union hull. It never chooses the narrowest
pair merely to make authorization pass.

Review tightened rate-error projection: a slow elapsed clock can make true
age greater than observed age. Drift is rounded up using the denominator
`1000000-drift_ppm`; maximum possible real age must also satisfy freshness.
The live adapter must establish that total rate-error envelope, including
clock discipline and timing quantization; source arithmetic cannot prove it.

Admin still reports `trusted_utc_available: false`. Assignments, delegation
and resource effects remain unavailable through the catalog interface.
No chrony dependency/configuration, time service, host clock or TPM state was
changed. The UTC provider, history lifecycle and authorization integration
are still open implementation work, not merely waiting for physical testing.

## Verification

Targeted checks passed on 2026-10-04 at
`D:\LumaOS-builds\g2-utc-bounds-targeted-20261004-02`.

- Build-input manifest SHA-256: `0bb460328462b67491dc6813456f4dea5cbe0c499bb182c7ff99893fb1c0e53e`.
- Supplementary test-input manifest SHA-256: `0c03aca052887c77375862d887d66b3bc39972238853ae605f145678b55140bb`.
- Completed log SHA-256: `5111d42e02a59a164765ea0d6f8a05970937faefb1783d7c80a18a2fe7beab28`.
- All 171 captured build inputs and three supplementary test inputs matched
  the final checkout bytes.
- Fifteen UTC tests passed, covering expiry edges, malformed intervals/policy,
  source-count bounds, duplicate/unknown operators, order independence,
  disagreement/outliers, ambiguous majorities, two-source uncertainty,
  drift rounding, real-age limits, future/stale input, all epoch fields,
  uncertainty limits and integer overflow. Two bounded exhaustive tests
  checked 700 one-fault cases; they do not authenticate actual inputs.
- Sixty-five ordinary Admin regression tests passed: seven service, 22
  governance, four role catalog, 16 journal, five authentication, six principal
  and five credential tests. Environment-dependent ignored fixtures were
  not executed or counted as passing here.
- Ten existing Python source-wiring checks, formatting and the warnings-denied
  offline locked native build passed.

The earlier `-01` run is retained but does not qualify the final tightened
source. The final run used offline disposable containers, one CPU and at most
768 MiB, with build/cache/evidence on D:. No WSL resource changes, host accounts,
host hardware, image build, VM, LLM load or consolidated sweep were used.

## Remaining integration

Approve provider/policy/bootstrap/offline choices, audit the pinned chrony
authentication/telemetry boundary, implement the protected live adapter and
confinement, and add durable clock/seed/history recovery. Then integrate finite
assignments, revocation and effect-time checks and package the installed
boot/update/recovery flows. Actual certificate/NTS/delay/outage/clock attacks
and service enforcement need controlled integration fixtures, followed by
the consolidated image and separate native Ubuntu qualification.
