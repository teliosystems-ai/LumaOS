# Requirement and gate report

> Deterministic report generated from `requirements/registry.json` and `docs/governing_sources.json`. It reports requirement-register readiness; it is not by itself a product gate certificate.

## Outcome

- Registry state: **PROVISIONAL_BLOCKED**.
- Explicit catalog entries: **288 / 288**.
- G0 requirement-traceability status: **BLOCKED**.
- Requirements with blocked latest evidence: **288**.
- Requirements with provisional mappings: **288**.
- No product requirement is closed by this report.

The ID catalog and plan-level assignments are structurally complete. G0 cannot close while the three governing sources are unavailable, their immutable digests are absent, and the provisional mappings have not been semantically reconciled. G1 cannot close while G0 is blocked or while its required runtime, hardware, security, recovery, and performance evidence remains unavailable.

## Catalog coverage

| Family | Expected | Registered |
| --- | ---: | ---: |
| FR | 60 | 60 |
| NF | 18 | 18 |
| A | 140 | 140 |
| Q | 20 | 20 |
| W | 44 | 44 |
| QW | 6 | 6 |

## Governing sources

| Source | Precedence | Availability | Validation | SHA-256 |
| --- | ---: | --- | --- | --- |
| GOV-WIN-001 | 1 | missing | blocked | — |
| GOV-UBU-001 | 2 | missing | blocked | — |
| GOV-FEA-001 | 3 | missing | blocked | — |

## Gate register status

| Gate | Requirements | In progress | Not started | Pass | Fail | Blocked | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| G0 | 0 | 0 | 0 | 0 | 0 | 0 | BLOCKED |
| G1 | 88 | 88 | 0 | 0 | 0 | 88 | BLOCKED |
| G2 | 34 | 0 | 34 | 0 | 0 | 34 | BLOCKED |
| G3 | 45 | 0 | 45 | 0 | 0 | 45 | BLOCKED |
| G4 | 31 | 0 | 31 | 0 | 0 | 31 | BLOCKED |
| G5 | 2 | 0 | 2 | 0 | 0 | 2 | BLOCKED |
| G6 | 18 | 0 | 18 | 0 | 0 | 18 | BLOCKED |
| G7 | 19 | 0 | 19 | 0 | 0 | 19 | BLOCKED |
| RX | 1 | 0 | 1 | 0 | 0 | 1 | BLOCKED |
| GWIN0 | 17 | 0 | 17 | 0 | 0 | 17 | BLOCKED |
| GWIN1 | 20 | 0 | 20 | 0 | 0 | 20 | BLOCKED |
| GWIN2 | 13 | 0 | 13 | 0 | 0 | 13 | BLOCKED |

## Assignment readiness

- Planned gate owner assigned: **288 / 288**.
- Provisional profile applicability assigned: **288 / 288**.
- Provisional environment assignment present: **288 / 288**.
- Numbered planned test IDs present: **287 / 288**.
- Exact A077 test mapping recorded: **T40**.
- Missing numbered procedure: **FR54** (the plan requires RX requirements change control before execution).

Implementation status is a stage-level planning signal, not semantic requirement completion. Gate suites are attached provisionally unless the development plan states an exact mapping.

## Open blockers

| Blocker | State | Owner | Decision date | Affects | Reason |
| --- | --- | --- | --- | --- | --- |
| BLK-GOVERNING-SOURCES | blocked | requirements-and-release-owner | — | G0, G1, G2, G3, G4, G5, G6, G7, RX, GWIN0, GWIN1, GWIN2 | All three governing DOCX inputs are absent and lack immutable digests. |
| BLK-RX-TEST-PROCEDURE | blocked | rx-research-team | — | RX | FR54 has no source-numbered RX verification procedure; change control is required before RX execution. |

## Status totals

| Dimension | State | Count |
| --- | --- | ---: |
| Implementation | in_progress | 88 |
| Implementation | not_started | 200 |
| Latest evidence | blocked | 288 |
| Mapping | provisional | 288 |
