# G2 Native Invoice Calculation Checkpoint

Status: bounded source checks passed on 2026-10-03. This checkpoint adds a
pure native calculation for an invoice CSV, not an authorized skill execution
or the complete file-to-artifact workflow.

The reusable native `report_bytes` function and its `invoice-calculate`
command read at most 1 MiB of input and return deterministic JSON monthly
totals grouped by currency. They use exact integer cents, checked sums and a
SHA-256 binding to the original input bytes. The strict CSV contract requires
`invoice_date`, `amount` and `currency`
columns, valid `YYYY-MM-DD` dates, amounts with at most two decimal places and
uppercase three-letter currency codes. It bounds rows, columns and fields,
handles quoted fields and CRLF, and rejects malformed or ambiguous data. The
sample `examples/invoices.csv` produces five records and USD 1420.20 for
September 2026. This is a narrower native input contract than the Python
reference workflow's text and manual-input paths.

The calculation opens no source pathname, accepts no folder grant, invokes no
model, publishes no artifact and records no effect. The native supervisor and
policy broker do not call it yet. It is reusable calculation code, not proof
that the signed registry's calculation descriptor is executable.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-invoice-calculation-targeted-20261003-03`.

- Source snapshot manifest SHA-256: `c86524a48ba97a1cf0ec2aff01aaa741e49dc754d85bee54dd2e9842acc323e9`.
- Completed test log SHA-256: `e1a2a3da2e3c66baec2c9cedd865fb2838195451681499d59a74ed997c136986`.
- Five calculator tests, three signed-registry regression tests, formatting,
  an offline native build with warnings denied, and positive and negative
  compiled-CLI checks passed. Tests cover the sample total, leap days,
  multiple currencies, negative totals, CSV quoting, malformed input and
  source-size, field and row limits.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs and no
network. Source and evidence remained on D:. No full image was rebuilt or
booted; an image built from this source or later is needed before installed
behavior can be tested.

Descriptor-scoped file reads, effect-time policy, managed artifact writes,
durable cancellation and restart, and the distributed-image manual journey
remain open G2 work. This checkpoint does not close G2.
