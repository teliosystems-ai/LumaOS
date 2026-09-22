# Requirement and gate report

> Deterministic report generated from `requirements/registry.json` and `docs/governing_sources.json`. It reports requirement-register readiness; it is not by itself a product gate certificate.

## Outcome

- Registry state: **SOURCE_VERIFIED_PLAN_MAPPINGS_PROVISIONAL**.
- Explicit catalog entries: **288 / 288**.
- G0 governing-source traceability status: **VERIFIED**.
- Requirements with verified structural source fields: **288 / 288**.
- Requirements with blocked latest evidence: **288**.
- Requirements with provisional mappings: **288**.
- No product requirement is closed by this report.

The three pinned governing sources and the complete 288-ID structural traceability catalog are verified. This resolves the governing-source prerequisite only. The broader G0 gate is not certified by this report, plan-derived mappings remain provisional, and G1 cannot close while its required runtime, hardware, security, recovery, and performance evidence remains unavailable.

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

| Source | Precedence | Revision | Date | Availability | Validation | SHA-256 |
| --- | ---: | --- | --- | --- | --- | --- |
| GOV-WIN-001 | 1 | VAR WIN 01 / Version 1.0 | 2026-09-19 | present | verified | 479b310e4027a45ccc3bf09a1f1850672e7841f40a3c2a018e34059109e7166d |
| GOV-UBU-001 | 2 | Version 2.0 | 2026-09-13 | present | verified | 25b6026916f9cdeb0a108d3f8ad875a704a9162436d317c0c825f00fe8b4f38b |
| GOV-FEA-001 | 3 | Version 1.0 | 2026-09-10 | present | verified | 05b2e8568e8582c435b10fe6f609f2c7a10737d4efd82d5f1adaea2f37e821e5 |

## Gate register status

| Gate | Requirements | In progress | Not started | Pass | Fail | Blocked | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| G0 | 0 | 0 | 0 | 0 | 0 | 0 | SOURCE-VERIFIED; BROADER GATE OPEN |
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

Implementation status is a stage-level planning signal, not semantic requirement completion. `source_test_ids` contains only explicit source-row references; planned gate suites remain attached separately and provisionally unless the development plan states an exact mapping.

## Open blockers

| Blocker | State | Owner | Decision date | Affects | Reason |
| --- | --- | --- | --- | --- | --- |
| BLK-RX-TEST-PROCEDURE | blocked | rx-research-team | — | RX | FR54 has no source-numbered RX verification procedure; change control is required before RX execution. |

## Status totals

| Dimension | State | Count |
| --- | --- | ---: |
| Implementation | in_progress | 88 |
| Implementation | not_started | 200 |
| Latest evidence | blocked | 288 |
| Mapping | provisional | 288 |
