# Governing requirements sources

## Purpose

This record identifies the three pinned DOCX artifacts that govern the Luma OS requirement catalog. The machine-readable record is [governing_sources.json](governing_sources.json); the generated registry retains the exact source text and structural locator for each of the 288 requirement IDs.

Source verification establishes artifact identity and structural traceability. It does not prove implementation, test execution, product acceptance, or gate closure. Gate, owner, environment, and development-profile assignments remain explicitly plan-derived until their separate reviews are complete.

## Verified repository snapshot

On 22 September 2026, all three governing packages were read successfully as DOCX/ZIP containers. Their byte sizes and SHA-256 digests matched the controlled record, their Word core titles and visible revision/date lines matched the revisions below, and deterministic Word XML extraction produced exactly 60 `FR`, 18 `NF`, 140 `A`, 20 `Q`, 44 `W`, and 6 `QW` entries.

| Dependency ID | Precedence | Controlled document | Revision and date | Requirements | SHA-256 | State |
| --- | ---: | --- | --- | ---: | --- | --- |
| GOV-WIN-001 | 1 | `docs/Requirements/LLM_OS_Windows_Deployment_Requirements_Variation.docx` | VAR WIN 01 / Version 1.0, 19 September 2026 | 50 | `479b310e4027a45ccc3bf09a1f1850672e7841f40a3c2a018e34059109e7166d` | **Verified** |
| GOV-UBU-001 | 2 | `docs/Requirements/Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx` | Version 2.0, 13 September 2026 | 160 | `25b6026916f9cdeb0a108d3f8ad875a704a9162436d317c0c825f00fe8b4f38b` | **Verified** |
| GOV-FEA-001 | 3 | `docs/Requirements/LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx` | Version 1.0, 10 September 2026 | 78 | `05b2e8568e8582c435b10fe6f609f2c7a10737d4efd82d5f1adaea2f37e821e5` | **Verified** |

The precedence is the order stated by the Windows variation: that variation governs its added deployment profiles, followed by the Ubuntu Option A baseline, followed by the original feasibility specification where it has not been superseded.

The Windows document names its B2 baseline internally as `Option_A_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx`; the supplied controlled artifact is named `Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx`. Its title, Version 2.0 date, requirement ranges, and digest are pinned above, so the filename difference is recorded rather than silently normalized.

## Deterministic extraction boundary

`scripts/build_requirement_registry.py` uses only the Python standard library (`zipfile` and `xml.etree.ElementTree`) and verifies each pinned size and digest before reading `word/document.xml` and `docProps/core.xml`. For every requirement it records:

- exact requirement ID and governing source;
- structural Word XML table-row or paragraph locator;
- source title when present;
- explicit source release scope and deployment profiles when present;
- exact normative text and acceptance/reference text; and
- exact numbered `T` or `V` references when they occur in that requirement entry.

The parser also verifies the source procedure catalogs: `T01`–`T08` in the original feasibility document, `T01`–`T62` in the controlling Ubuntu baseline, and `V01`–`V18` in the Windows variation. The later Ubuntu baseline has precedence for its `T` procedures; the earlier feasibility procedure catalog is retained as source history rather than merged silently.

## Non-normative reference

`docs/Requirements/LLM_OS_Practical_Implementation_Research_Paper.docx` is recorded separately as `REF-RES-001`, Version 1.0 dated 20 September 2026, SHA-256 `40492ebbe83bec0d3677fbf2ab14d3ad5cb59318078a186fdc13371a7f3c9a48`. The paper explicitly says it interprets and evaluates the three project documents and does not silently amend them, so it is not used as a fourth governing source.

## Current impact

- The governing-source digest and 288-ID structural-traceability blocker is resolved.
- The requirement registry still labels development-plan gate, owner, profile, environment, and broad gate-suite assignments as provisional.
- Every latest product-evidence state remains blocked until applicable implementation and acceptance evidence is attached; source verification alone does not change it to pass.
- `FR54` remains blocked for RX execution because its governing row specifies a learned-scheduling experiment but no source-numbered RX verification procedure. A new procedure still requires requirements change control.

## Recheck procedure

Run the deterministic registry builder and focused test from the repository root:

```powershell
wsl.exe -d Ubuntu -- bash -lc "cd /mnt/c/path/to/LumaOS && python3 scripts/build_requirement_registry.py --check"
wsl.exe -d Ubuntu -- bash -lc "cd /mnt/c/path/to/LumaOS && python3 -m unittest tests.test_requirement_registry -v"
```

Any content, package, title, revision-line, requirement-catalog, or procedure-catalog change fails validation until the controlled source record and affected traceability have been reviewed deliberately.
