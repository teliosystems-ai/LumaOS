# G2 laboratory broker receipt boundary hardening

Status: bounded source and isolated CLI checks passed on 2026-10-03. This
increment hardens the laboratory root-only worker-effect path; it is not
product Admin, production policy integration, or G2 acceptance.

The broker effects log now accepts only the exact JSON serialization its
writer emits. Equivalent whitespace or field-order rewrites are rejected on
open and subsequent reads, preserving the changed file for review. The local
CLI now makes a fresh 128-bit random request ID instead of using a recycled
process ID; failure to obtain randomness refuses the request. The public CLI
currently exposes only `status`, while other socket clients remain responsible
for providing their own unique request IDs. Neither change anchors receipts
against malicious root or disk rollback.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-broker-receipt-targeted-20261003-01`.

- Source snapshot manifest SHA-256: `550f68f9ef9243e3b325596abf185459d123ad06cac4676c249cd66f9a7eb24a`.
- Completed test log SHA-256: `791ecdd853abe35502381608508a6a09b77d829a1d8920d41d1fcc292688036e`.
- Separately copied CLI fixture SHA-256: `43ea8cf9a6ee463b0e5b5e5498b798d08bfedf12573bd76940de6d005eb1c5fc`.
- CLI fixture result SHA-256: `9a5d47085c4a1a9f57dec974c7317dd60c58917c53713a4089ee710a444c757c`.

The offline D-backed tools container passed formatting, 9 effects-log tests,
17 broker/service tests, 2 packaging checks, the native build with warnings
denied, and a real CLI exchange with a private fixture socket. The fixture
covered valid and refused replies, framing faults and a full listen queue;
it did not run the installed broker or worker. The container had one CPU,
768 MiB memory with no extra swap, 128 PIDs, no network, and no host Docker
socket or TPM. WSL memory settings were unchanged.

Product Admin assignment, effect-time resource grants, protected production
receipts, reviewed uncertain-outcome reconciliation, installed-image behavior,
and physical qualification remain open. A source-only result cannot close the
G2 policy and durable-effects work package.
