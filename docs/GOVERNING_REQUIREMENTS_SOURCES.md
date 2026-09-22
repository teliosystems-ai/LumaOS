# Governing requirements source dependencies

## Purpose

This file explains the controlled documents that the staged development plan names as governing inputs. The corresponding machine-readable status record is [governing_sources.json](governing_sources.json). Neither file substitutes for the source documents or proves that their contents have been reviewed in this checkout.

## Repository verification snapshot

On 2026-09-22, a repository-root search for `*.docx` files and a check of Git-tracked paths found none. In particular, none of the three exact filenames below is present or tracked. This observation validates only their absence from this checkout; it does not validate a document revision or any requirement text attributed to it. The JSON record captures the same checkpoint for automated validation.

| Dependency ID | Precedence | Expected document | Intended scope | Repository state | Controlled locator | SHA-256 | Validation state |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| GOV-WIN-001 | 1 | `LLM_OS_Windows_Deployment_Requirements_Variation.docx` | Native, Dual boot, WSL2, and VM profile variations | Missing | Not recorded | Not available | **Blocked: exact artifact unavailable** |
| GOV-UBU-001 | 2 | `Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx` | Option A Ubuntu product baseline | Missing | Not recorded | Not available | **Blocked: exact artifact unavailable** |
| GOV-FEA-001 | 3 | `LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx` | Original architecture and research rationale where not superseded | Missing | Not recorded | Not available | **Blocked: exact artifact unavailable** |

The precedence column records the order asserted by the development plan. Because the source artifacts are unavailable, that ordering has not been independently confirmed against their own revision or approval metadata.

## Acceptance evidence required

The requirements/release owner must complete all of the following for each dependency before changing its validation state to **Verified**:

1. Obtain the exact approved revision and confirm that the project may retain or access it.
2. Record a stable repository path or controlled external locator, document revision/date, byte size, and SHA-256 digest. A mutable filename or an inaccessible local path is not a sufficient locator.
3. Have a second reviewer verify the digest, that the DOCX package opens without repair, and that its title/revision metadata matches the approved source.
4. Reconcile the applicable requirement IDs, exact normative wording, test IDs, profile applicability, and supersession rules into the machine-readable requirement register.
5. Record conflicts through requirements change control; do not silently choose wording from this plan or another summary.

If redistribution is not permitted, the controlled source may remain outside Git, but the repository must retain its non-secret immutable digest, revision metadata, access owner, and verification result. The source document itself must never be replaced by a fabricated placeholder.

## Current impact

- G0 governing-source digest verification is blocked.
- Completeness and semantic correctness of the planned `FR`, `NF`, `A`, `Q`, `W`, and `QW` mappings cannot yet be certified from repository evidence.
- Local MVP implementation and tests may continue as development evidence, but no requirement or gate that depends on these sources may be marked closed solely from the development plan or requirements coverage summary.
- Any later source acquisition or revision change must update this record and invalidate affected mappings until they are re-reviewed.

## Recheck procedure

From the repository root, reviewers can recheck the repository portion of this record with:

```powershell
rg --files -g '*.docx'
git ls-files '*.docx'
```

After a source becomes available, record its digest using an approved SHA-256 tool for the host environment and retain the verification result with the requirement register evidence.
