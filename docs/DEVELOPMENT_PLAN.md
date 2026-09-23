# Luma OS staged development plan

## Purpose and governing decision

This plan turns the designated feasibility, Ubuntu, and Windows requirements into an implementation sequence with a separate test phase and an objective exit gate for every stage. The program builds the Linux-based product first, develops the Windows-hosted profiles against the same contracts, and treats large-model, cluster, and microkernel work as separately gated expansions.

Passing a stage means that its required behavior was exercised on the stated environment and that the evidence is retained. A simulator, mocked allocation, sparse memory mapping, successful file parsing, or model-generated claim cannot substitute for the specified runtime, hardware, security, recovery, or artifact evidence.

The source precedence is:

1. `LLM_OS_Windows_Deployment_Requirements_Variation.docx` for Native, Dual boot, WSL2, and VM profile variations.
2. `Option_Ubuntu_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx` for the Option A Ubuntu product baseline.
3. `LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx` for the original architecture and research rationale where the later documents do not supersede it.

These three governing inputs are present under `docs/Requirements` and pinned by controlled locator, byte size, and SHA-256 in [GOVERNING_REQUIREMENTS_SOURCES.md](GOVERNING_REQUIREMENTS_SOURCES.md). The deterministic registry verifies all 288 source requirements, their normative and acceptance/reference text, and source locators. Gate, owner, profile, and environment mappings remain plan-derived; source verification is necessary traceability evidence, not product acceptance.

All product source, schemas, build definitions, tests, and public fixtures remain in this repository. Model weights, signing secrets, private test data, customer data, and licensed third-party assets stay outside Git and are referenced by immutable digest.

## Current starting point

Version `0.1.0` is a developer MVP and a useful input to G0. It currently demonstrates:

- an explicit folder-grant boundary and bounded POSIX/WSL reads;
- separate workflow preparation and execution;
- restart-visible SQLite workflow state;
- idempotent local effects, immutable managed artifacts, and append-only receipts;
- a loopback-only browser interface with manual operation when no model is configured;
- source-run paths for Ubuntu and Windows 11 through WSL2;
- the current native Windows 11 and Ubuntu 26.04 WSL development lanes on one physical laptop;
- a fixed Luma OS `Admin` governance role with finite, receipted delegation;
- a pinned Qwen3-4B Q4_K_M development model through llama.cpp on Windows CUDA, Ubuntu WSL CPU, and the authenticated Luma gateway;
- versioned multi-model manifests and install-time profiles with exact total
  and active parameter counts, manual-only/CPU/CUDA choices, and fail-closed
  RAM, VRAM, storage, context, load, and serving checks;
- a non-destructive installer contract, pure A/B boot-state model, typed privileged-helper/confinement contracts, SQLite-backed request/effect ledgers, exact multi-model selection, signed-catalog verification, and read-only Ubuntu admission with an expanded 128-test nine-module boundary on native Windows and Ubuntu WSL under normal and optimized-Python execution; and
- repository, API-contract, browser-journey, and deterministic source-package checks.

It has **not** passed formal G0 or G1. Their repository/local development scope is recorded as **complete with deferrals**, while formal certification remains **blocked**. Repository-local G1 prototypes now cover purpose/lifecycle-bound signed model-pack contracts, checked resource admission, deny-by-default policy and Admin delegation, a typed DAG, deterministic fake inference, real loopback inference, local-gateway fencing, platform-adapter scaffolding, and state recovery. It still does not provide a signed certified 4–6B model pack, qualified two-board model runtime, signed skills, worker sandboxing, semantic indexing, multimodal interaction, a bootable image, A/B updates, hardware certification, a Windows file broker, VM or dual-boot lifecycle, 400–405B qualification, or cluster execution. Existing simulator, fake-backend, WSL, one-laptop real-model, and MVP results are development evidence only.

G2 repository development is **in progress** and formal G2 certification is
**blocked**. The G2 work at
`4ec25b849b3db4363191532bdb06f42894e11253` models installer authorization,
A/B update decisions, privileged-helper dispatch, and confinement evidence as
pure, fail-closed contracts. Commit
`80980acbac461a9d639df483349bb47a639eefca` adds SQLite-backed request and
effect ledgers, generation/owner fencing, explicit crash-state semantics, and
a fail-fast pre-dispatch compare-and-swap. Commit
`8a8fc8291b42b9a76003dd3e71fa99f9a3117e62` adds post-transition current-state
revalidation, safe `PREPARED` restoration, and known-not-applied capacity
handling. Commit `5667e3d8f337dec326dc8afdec91ed34c1c2eb2a` adds exact
multi-model catalog/profile selection, hardware admission, installer-plan
binding, and effect-time revalidation. It neither performs
installation/boot/host effects nor enforces UKI, dm-verity, LUKS, cgroup v2,
AppArmor, seccomp, KVM, native ACL/DACL policy, or real peer credentials.
Native Windows and Ubuntu WSL remain two development lanes on one physical
laptop, not the two required A1 boards.

### Current stage status

| Stage | Status at this checkpoint |
| --- | --- |
| G0 | **Development complete with deferrals; formal certification blocked.** Governing source ingestion and 288-ID traceability are verified; the development baseline, decisions including Admin governance, registers, current Windows/WSL inventory, checks, and source-package evidence exist. Two designated physical boards, the Ubuntu 24.04/E8 baselines, disposable disks, protected production signing custody, and complete qualification evidence are deferred in `docs/gates/g0/blockers.json` and `docs/gates/final_certification_deferrals.json`. |
| G1 | **Development complete with deferrals; formal certification blocked.** Contract evidence covers resources, policy/Admin delegation, typed DAG, model-pack trust lifecycle, fake and real inference, authenticated gateway, cancellation/concurrency/revocation fencing, state transfer, telemetry, and platform adapters. Qwen3-4B passed bounded native Windows CUDA and Ubuntu WSL CPU/gateway development smoke, but the external artifact is unsigned and not a certified pack. Signed candidate comparison, two-board workflows, boot/recovery, full security/performance evidence, and the real 400–405B experiment are deferred. No deferral waives G0 or G1 exit criteria. |
| G2 | **Development in progress; formal certification blocked.** The repository-local expanded boundary has 128 tests on native Windows and Ubuntu WSL under normal and optimized-Python execution for non-destructive installer authorization, exact multi-model/hardware selection, pure A/B boot-state transitions, typed helper/confinement boundaries, durable request/effect coordination, signed-catalog verification, and read-only Ubuntu host admission. No production signing ceremony, real disk, boot, cryptographic boot-chain, encryption, kernel-control, VM, native ACL/DACL, or peer-credential enforcement has been exercised. |
| G3, G4, G5 | **Not started.** |
| GWIN0, GWIN1, GWIN2 | **Not started.** |
| G6, G7 | **Not started and separately capacity-gated.** |
| RX | **Not started and not yet authorized.** |

## Program sequence

| Gate | Planned window | Product outcome | Primary requirement scope |
| --- | --- | --- | --- |
| G0 | Weeks 1–2 | Engineering baseline and lab readiness | Non-normative program setup; no product requirement closes here |
| G1 | Weeks 3–8 | P0 feasibility and core control contracts | FR09–FR21, FR41–FR42, FR44–FR49, FR57–FR59; NF02–NF07, NF10–NF11, NF16–NF17; A009–A028, A030–A037, A039–A047, A049–A056, A077, A079–A086 |
| G2 | Weeks 9–16 | Ubuntu platform alpha | FR01–FR07, NF18, A001–A008, A101–A116, A118, Q15 |
| G3 | Weeks 17–28 | Functional beta | FR22–FR35, FR37–FR40, FR50–FR53, FR55; NF01, NF08, NF12, NF14; A057–A071, A073–A075 |
| G4 | Weeks 29–40 | A1 hardening | FR60, NF09, NF13, NF15, A093–A096, A098–A100, A131–A135, A138, A140, Q01–Q03, Q06–Q13, Q17–Q18 |
| G5 | Weeks 41–48 | A1 product release | A097, Q14, plus every applicable inherited A1 and quality gate on the final images |
| G6 | Experiments from P0; formal certification after G5, approximately months 12–16 | A2 large local edition | FR08, FR36, FR43, FR56, A029, A038, A048, A072, A076, A078, A087–A090, A117, A119, Q04–Q05 |
| G7 | Approximately months 16–22, if funded | A3 distributed edition | A091–A092, A120–A130, A136–A137, A139, Q16, Q19–Q20 |
| RX | Separate six-to-nine-month feasibility track | Microkernel feasibility research | FR54 |

G6 experiments may begin during P0, but G6 depends on G5 and no A2 capability can be released until it inherits the stable A1 security, durability, and recovery controls. G7 depends on a stable large-model service from G6. RX depends on G3 and is not on the Option A product critical path.

The Windows gates run as a parallel swim lane after the common contracts stabilize:

| Gate | Scheduling placement | Outcome |
| --- | --- | --- |
| GWIN0 | After G1; overlaps G2 | Actual compact inference in WSL, host-file ingestion, qualified confinement, and a complete VM desktop proof |
| GWIN1 | After GWIN0 and G3; overlaps G4 | WSL product beta with Windows file automation, recovery, candidate updates, and migration |
| GWIN2 | After GWIN1 and the A1 release baseline | Dual-boot and full-VM qualification plus all inherited profile evidence |

The Windows requirements do not provide reliable calendar estimates before GWIN0. Windows effort shall be re-estimated from measured GWIN0 results rather than hidden inside the Ubuntu schedule.

```text
G0 -> G1 -> G2 -> G3 -> G4 -> G5 -> G6 -> G7
       |      |      |
       +-> GWIN0 -> GWIN1 -> GWIN2
       |
       +-> early A2 experiments -- evidence input only --+

G5 ---------------------------> GWIN2

G3 -> RX feasibility, when separately authorized and funded
```

## G0 Engineering baseline and lab readiness

**Duration and ownership:** Weeks 1–2. Principal architect, QA lead, release engineer, platform lead, and inference lead. A four-to-six-person P0 team is sufficient.

**Entry:** A clean, reproducible `v0.1.0` checkout and its existing tests.

**Primary requirement:** None. G0 is a non-normative program-readiness gate.
Platform-adapter requirement `A077` and its real `T40` conformance test close in
G1. Release construction, complete evidence, and four-profile closure begin
here as program infrastructure but close under G4, G5, and GWIN2.

**Deliverables:**

- A machine-readable register for every B1 `FR01–FR60` and `NF01–NF18`, B2 `A001–A140` and `Q01–Q20`, and Windows `W001–W044` and `QW01–QW06` requirement.
- For every requirement: release, profile applicability, owner, dependency, implementation status, test IDs, environment, and latest evidence state.
- Architecture decision records for the Python-reference/Rust-production split, service boundaries, transport, artifact storage, policy model, model-pack format, Admin delegation/signing custody, and supported package layout.
- Two named x86-64 A1 reference machines with firmware and device inventories; an Ubuntu 24.04 reproducible baseline; a separate 26.04 evaluation path; disposable disk fixtures; and initial E0, E1, E2, and E8 environments.
- Initial workload, adversarial, failure-injection, and license registers. Private fixtures remain outside the public repository.
- CI lanes for deterministic unit tests, fake-backend contracts, Ubuntu integration, Windows-hosted integration, and reproducible build checks.

**Dependencies:** Hardware access, release ownership, operational signing custody, and an agreed requirements-change process. The Admin governance/signing-role design is accepted; protected production custody is external certification work.

**Testing phase:**

- **Automated:** Preserve `make check` and the browser journey. Add requirement-register completeness, governing-source digest verification, schema compatibility, database migration, malformed-input, static-analysis, dependency-inventory, and reproducible-build checks. G0 has no source-numbered verification procedure; early `T40–T41`, `V02`, and `V18` scaffolding is non-closing preparation for later gates.
- **Manual:** Reproduce the current workflow from a clean checkout on native Windows and Ubuntu/WSL. Verify that the two environments are recorded as one physical host and that the simulator is not cited as runtime evidence.
- **Security:** Threat-model review, repository secret scan, third-party/model license inventory, and an initial exposed-interface review.
- **Performance:** Record the current MVP's startup, request, memory, and storage baseline without assigning a certified service class.

**Exit gate:** Equipment and reproducible baseline images are available; every requirement has an owner and planned test; critical architecture choices for G1 are frozen; unresolved blockers have an owner and decision date.

**2026-09-22 development disposition:** The repository/local G0 tranche is
accepted as complete with deferrals. Native Windows and the current Ubuntu
26.04 WSL guest are the active development environments, but they share one
physical laptop. The host is only an E1 candidate; E2 and E8 are absent, and
the WSL guest is neither a second board nor the Ubuntu 24.04 physical baseline.
Those missing environments and destructive/boot/custody tests remain required
for formal certification.

## G1 P0 feasibility and core control contracts

**Duration and ownership:** Weeks 3–8. P0 team of four to six covering platform, systems/inference, workflow/storage, security, and UI integration.

**Primary requirements and work packages:** B1 core contracts `FR09–FR21`, `FR41–FR42`, `FR44–FR49`, and `FR57–FR59`; B1 quality foundations `NF02–NF07`, `NF10–NF11`, and `NF16–NF17`; model and control requirements `A009–A028`, `A030–A037`, `A039–A047`, `A049–A056`, `A077`, and `A079–A086`; `WP02–WP06`, `WP10`, `WP14–WP16`, and early supporting work in `WP01`, `WP17`, and `WP18`. A2-only requirements `A029`, `A038`, and `A048`, and G3 storage requirements `A057–A064`, may inform prototypes but are not G1-owned closure items.

**Deliverables:**

- Immutable signed model-manifest schema with recognized, loadable, execution-certified, and interactive-certified states.
- Checked 64-bit `MemoryDomain`, `PlacementPlan`, `ResourceLease`, allocation, cache, and runtime-profile contracts.
- Deterministic fake backend plus actual host/GPU telemetry adapter; atomic admission, lease generation, cleanup, pressure, and quarantine prototypes.
- Real local 4–6B compact inference through an authenticated gateway with explicit model, tokenizer, template, context, deadline, and lease identity.
- A generic typed DAG, policy decision, cancellation, artifact, receipt, and recovery contract evolved from the invoice workflow.
- Versioned platform-adapter interfaces with `T40` contract tests against Linux and a deterministic fake platform.
- Ubuntu service-package spike, signed UKI/A/B boot spike, and model-independent recovery experiment.
- Measured comparison of at least two 4–6B candidates and one mainstream candidate using the same OS tasks.
- A real 400–405B placement/load experiment on suitable hardware, or a measured blocking constraint. Sparse mappings or fake tensors are not a successful result.
- An explicit Ubuntu 24.04/26.04 decision and exact candidate runtime tuples.

**Dependencies:** G0 decisions, E1/E2 machines, access to a large-model test host, and legal permission to evaluate candidate assets.

**Testing phase:**

- **Automated:** `T06–T16`, `T18–T20`, `T22–T33`, and `T40–T42`; exact arithmetic, concurrent reservation, cache isolation/eviction, platform-adapter conformance, invalid-plan, idempotency, cancellation, session recovery, evidence export, remote-fallback denial, and crash-boundary tests.
- **Manual:** Offline compact inference, missing-model operation, worker termination during each lifecycle phase, pressure recovery, and one full authorized local-file-to-artifact workflow on both A1 boards.
- **Security:** Initial indirect-prompt, capability substitution, revoked grant, malformed IPC, stale lease, model tampering, and sandbox escape fixtures. No model output is an authorization oracle.
- **Performance:** Baselines for `Q01`, `Q02`, and `Q06–Q08`; model loading peak, context growth, protected reserve, cancellation latency, and estimator error.

**Exit gate:** The compact workflow operates offline on both boards; no accepted allocation exceeds a domain budget; model failure preserves manual access and recovery; the exact platform, compact model, mainstream candidate, backend, storage, sandbox, and signing directions are selected from recorded evidence.

**2026-09-23 model-profile addendum:** The repository/local G1 tranche remains
accepted as complete with deferrals. Qwen3-4B Q4_K_M with llama.cpp b11100 is
the recommended current development profile and has produced exact bounded
output on native Windows CUDA and Ubuntu WSL CPU, including authenticated calls
through the Luma resource, policy, lease, and gateway path. It is an unsigned
external developer tuple and is not G1-closing evidence. Gemma 4 E2B is retained
as a conditional compact candidate with both 5.1B total and 2.3B effective
counts recorded; Gemma 4 E4B is the 8B-total mainstream candidate, not a
4–6B-total model. Neither Gemma candidate has been acquired or tested here.
The two-board 4–6B comparison, physical boot/recovery/security/performance
suite, and real 400–405B experiment remain deferred to final OS testing and
certification. A 450B target is outside the current governing requirements.

## G2 Ubuntu platform alpha

**Duration and ownership:** Weeks 9–16. Platform, systems/inference, agent/workflow, storage, security, QA, and release owners.

**Primary requirements and work packages:** B1 platform requirements `FR01–FR07` and `NF18`; installation and recovery `A001–A008`; Ubuntu platform and confinement `A101–A116` and `A118`; `Q15`; `WP01`, `WP14`, `WP16–WP18`, with the G1 control contracts as inherited dependencies. A2 requirement `A117` is not a G2 closure item.

**Deliverables:**

- Offline Ubuntu installer and recovery media for two selected x86-64 boards.
- Installer-time choice among cataloged model parameter/configuration profiles
  or explicit manual-only mode, with unavailable choices explained after
  effective hardware and peak-resource checks.
- Signed UKI, read-only A/B ext4 roots protected by dm-verity, LUKS2 data storage, trial boot, health acknowledgement, and automatic prior-slot selection.
- Model-independent manual desktop, file export, repair, diagnostics, and clean shutdown.
- Full model lifecycle, atomic leases, generation fencing, device quarantine, cgroup v2 budgets, pressure state machine, and measured cleanup.
- Signed skill package, registry, typed DAG validation, supervisor, idempotent effects, cancellation, durable checkpoints, and restart reconciliation.
- Policy broker before any write-capable skill, with current-identity and effect-time grant validation.
- AppArmor/seccomp profiles, finite device and pinned-memory limits, and a fail-closed KVM microVM or separately qualified constrained runtime for generated code.
- Initial file-read, deterministic-calculation, and managed-artifact-write skills through the production interfaces.

**Dependencies:** Frozen G1 interfaces and tuples, signing/recovery keys for the lab, disposable installation disks, and qualified kernel/driver candidates.

**Testing phase:**

- **Automated:** Complete `T01–T16`; relevant `T27–T30`, `T33`, `T40`, `T45–T51`, and `T62` coverage; package, schema, helper-fuzz, boot-manifest, migration, and fault-injection tests.
- **Manual:** Install, recover, suspend/resume, update, roll back, and run the vertical workflow from distributed media on both boards. Developer checkouts alone cannot pass.
- **Security:** Package/boot tampering, policy revocation, forged peer identity, helper argument substitution, confinement disablement, prohibited code access, encryption-key recovery, and no-network operation.
- **Performance:** `Q01`, `Q02`, `Q06–Q09`; 1,000 compact lifecycle cycles, resource-pressure runs, cancellation boundaries, and initial storage crash matrix.

**Exit gate:** The requirements-defined G2 gate is met: `T01–T16` and the vertical workflow pass on both A1 boards. The alpha survives missing models, worker crashes, a failed staged artifact commit, and a failed trial boot without an unauthorized effect or loss of acknowledged content.

**2026-09-22 development checkpoint:** G2 is in progress, not passed. Commit
`4ec25b849b3db4363191532bdb06f42894e11253` adds three repository-local
safety-contract modules and 49 tests that also pass with Python assertions
disabled. The installer module is
non-destructive: inventory discovery and the executor are injected, and tests
exercise preflight, explicit short-lived confirmation, effect-time
revalidation, exact device binding, replay handling, and an in-doubt journal.
The A/B module is a pure state-transition model requiring authenticated state,
a monotonic anchor, trusted observations, health acknowledgement, and fallback
data-readability evidence. The privileged-helper module defines a closed typed
request surface, authority/device/certificate binding, attested confinement,
idempotency, and restart reconciliation.

This checkpoint is development-contract evidence only. It does not mutate a
disk, select a firmware entry, boot either slot, build or verify a real UKI or
dm-verity root, unlock LUKS, impose cgroup limits, load AppArmor/seccomp policy,
launch a KVM microVM, or authenticate a real Unix socket/named-pipe peer. Those
effects and the two-board Ubuntu 24.04 qualification remain mandatory for G2
formal certification.

**2026-09-23 durable-effect checkpoint:** G2 remains in progress and has not
passed. Commits `80980acbac461a9d639df483349bb47a639eefca` and
`8a8fc8291b42b9a76003dd3e71fa99f9a3117e62` add and harden a bounded
SQLite request journal and typed privileged-effect ledger. `PREPARED` records
prove that no adapter was entered and may be reclaimed only through an
owner/generation compare-and-swap with unchanged request semantics and fresh
authorization evidence. `APPLYING` is durably committed by a fail-fast
compare-and-swap and current state is revalidated again before adapter entry;
a proven-not-applied denial is restored to `PREPARED`, while an unprovable
restoration stays fenced. `APPLYING` is never automatically
redispatched after a crash. Only action-specific reconciliation can move an
ambiguous `APPLYING` or `FAILED_UNKNOWN` record to a semantically bound,
immutable `COMPLETED` result. Raw CSPRNG-issued 256-bit safe-handle tokens are
not written to the effect ledger; keyed commitments are retained instead.

The four G2 modules now have 71 contract tests passing in both native Windows
and Ubuntu WSL under normal and optimized Python. These two lanes are on the
same physical host and the tests use in-process typed adapters. They do not
establish a privileged service, kernel peer credentials, native ACL/DACL
enforcement, protected integrity-key custody, resistance to database deletion
or rollback, induced power-loss durability, external rollback anchoring, or
physical hardware effects. All such evidence remains required for formal G2
certification.

**2026-09-23 model-selection checkpoint:** G2 remains in progress and has not
passed. Model-pack schema v2 now binds exact total/active parameter counts,
ordered shards, required capabilities, runtime tuples, and CPU/CUDA
installation profiles. A separate immutable catalog supports multiple model
sizes and explicit `manual-only` operation. Installer schema-v2 plans bind the
requested catalog/profile, verified pack and runtime digests, context,
execution mode, effective hardware snapshot, peak storage, load/serve memory,
and one qualifying CUDA device; the same exact selection is re-evaluated before
the injected executor. Unknown, unavailable, unverified, incompatible, or
under-resourced profiles are denied without CPU/manual/remote substitution.
This is non-destructive contract evidence. The current Qwen3-4B artifact is
unsigned and outside the release, and no production catalog, base image, model
import/rollback, destructive installer, or physical-board workflow exists.

**2026-09-23 catalog and Ubuntu-readiness checkpoint:** G2 remains in progress
and has not passed. Commit `0d7685aaaec2301b9340b710061a447cd3569b83`
adds a bounded detached model-catalog verification contract, a request-first
no-private-key ceremony utility, a trusted-probe Linux host inventory, and a
fresh live-corroborated Ubuntu admission probe. Production catalog approval
requires three distinct exact-event approvers and a separate custodian, while
native admission requires an explicit E1/E2 class and cannot pass on WSL. The
operator package now defines exact destructive-disk, signing-custody, boot,
security, recovery, lifecycle, evidence, and sign-off inputs. These additions
prepare `T01`, `T06`, `T45`, `T49`, `T50`, and the wider physical suite; they
do not supply production keys or signatures, authorize disk mutation, build a
bootable image, enforce kernel controls, or replace execution on both physical
A1 boards.

## G3 Functional beta

**Duration and ownership:** Weeks 17–28. Storage, desktop/application, inference, compatibility, security, QA, and product/UX owners.

**Primary requirements and work packages:** B1 functional requirements `FR22–FR35`, `FR37–FR40`, `FR50–FR53`, and `FR55`; B1 quality requirements `NF01`, `NF08`, `NF12`, and `NF14`; semantic, interaction, content, hardware, and application requirements `A057–A071` and `A073–A075`; `WP07–WP09`, `WP14–WP16`, with early supporting work for operations and documentation. A2 requirements `A072`, `A076`, and `A078` are not G3 closure items. `A077` closes in G1 and is inherited here. Operations requirements assigned to G4 remain G4 closure items even when implementation begins during beta.

**Deliverables:**

- Stable artifact identity, immutable versions, semantic collections, ACL-filtered search, rebuildable indexes, external-edit conflict handling, retention, export, backup, and clean-machine restore.
- Accessible conversational shell with ordinary manual controls, visible progress, keyboard operation, screen-reader semantics, reduced motion, and responsive cancellation.
- Push-to-talk speech, explicit image/screen input, bounded sampled video, visible capture indicators, and grounded-reference clarification.
- Deterministic spreadsheet/data, document, diagram, and programmatic-animation engines with editable sources, provenance, reopen, recalculation, and render validation.
- Sandboxed generated-code results with real build/test receipts and no default network or secrets.
- Named, versioned LibreOffice/browser adapters and allowlisted hardware-policy adapters with actual completion receipts.
- User-visible conflict, partial-effect, model-unavailable, and recovery states.

**Dependencies:** Stable G2 policy, resource, workflow, artifact, and sandbox contracts.

**Testing phase:**

- **Automated:** `T20`, `T29`, `T31–T42`, `T56`, `T58–T59`; deterministic numeric/file oracles, index rebuild, external-edit races, backup restore, adapter contracts, and accessibility automation.
- **Manual:** Keyboard and screen-reader core journeys, capture permission/stop behavior, ambiguous references, editable output reopen, persistent app sessions, and model-disabled operation.
- **Security:** Cross-user search/cache isolation, indirect prompt injection, code escape, credential-broker redaction, permission revocation, prohibited remote fallback, and hardware-policy bounds.
- **Performance and quality:** `Q01–Q03`, `Q06–Q10`, and `Q13`; weekly execution of the 500-task held-out corpus with failures, false refusals, repairs, memory, latency, and energy retained.

**Exit gate:** Core user journeys work with real local inference, real source files, and durable editable artifacts. Fault recovery passes. A held-out quality baseline and all material limitations are published. No tested step is marked successful solely because a model said it succeeded.

## G4 A1 hardening

**Duration and ownership:** Weeks 29–40. All component owners under QA, security, release, and architecture leadership. Feature freeze begins at entry.

**Primary requirements:** `FR60`; `NF09`, `NF13`, and `NF15`; `A093–A096`, `A098–A100`, `A131–A135`, `A138`, and `A140`; and `Q01–Q03`, `Q06–Q13`, and `Q17–Q18`. G4 also closes and retests all inherited applicable A1 requirements, including the G2 `Q15` gate. Final release construction `A097` and reproducibility/supportability `Q14` close in G5. `Q04–Q05` belong to G6, while `Q16`, `Q19`, and `Q20` belong to G7.

**Deliverables:**

- Frozen release tuples and support matrix for hardware, kernels, firmware, drivers, runtimes, models, quantization, contexts, skills, application adapters, and images.
- Corrected capacity estimators, thermal/power profiles, quota and diagnostic behavior, update compatibility, schema migration, backup/restore, and recovery procedures.
- Reproducible signed release pipeline, complete SBOM and license register, redacted evidence exporter, incident runbooks, and user/administrator/developer/recovery guides.
- External security review and a pilot-ready release candidate.

**Dependencies:** G3 feature completeness, exact production hardware, final distributable model/runtime licenses, and an independent security reviewer.

**Testing phase:**

- **Automated:** All applicable `T01–T42`, `T45–T51`, `T56–T59`, and `T62`; requirement-to-evidence completeness; reproducible clean builds; migration and rollback matrices.
- **Manual:** Clean offline installation, documented recovery, accessibility, application adapter, backup/restore, update, and rollback procedures on every advertised tuple.
- **Security:** All 300 adversarial cases, helper/API fuzzing, privilege-boundary review, package and boot tampering, cache/retrieval isolation, secret handling, and external assessment. Any unauthorized effect blocks release.
- **Performance and reliability:** Full applicable Q protocol, 100 warm requests per workload point in three runs, 30-minute sustained profiles, battery profiles, 1,000 lifecycle cycles, 1,000 crash trials, suspend/resume, update interruption, and the 72-hour mixed workload soak.

**Exit gate:** A1 traceability is complete, the candidate passes the 72-hour soak, and there are no open severity-0 or severity-1 defects. A missed performance target removes or relabels that certification; it never relaxes a security or durability invariant.

## G5 A1 product release

**Duration and ownership:** Weeks 41–48. Release lead, QA lead, security lead, platform owners, product/UX, and support owner.

**Primary requirements:** `A097` and `Q14`. G5 also repeats every applicable inherited A1 and quality requirement for each advertised tuple and profile against the final release bytes.

**Deliverables:**

- Signed Ubuntu desktop and headless installation images plus recovery media.
- Published hardware, model, skill, application, performance, and limitation catalogs.
- Reproducible source and binary provenance, SBOMs, checksums, qualification reports, support procedures, and incident response package.
- Controlled pilot results and a final release decision.

**Dependencies:** Successful G4 candidate, production signing custody, support ownership, release hosting, and exact redistribution approvals.

**Testing phase:**

- **Automated:** Repeat all applicable `T01–T42`, `T45–T51`, `T56–T59`, and `T62` from the complete G4 release gate against the exact final image bytes and manifests.
- **Manual:** Clean offline installation and first-use journeys on every reference system; pilot update, rollback, backup, restore, and model-disabled recovery.
- **Security:** Final signature, provenance, secret, license, exposed-interface, and severity review.
- **Performance:** Reconfirm published values on the final image; any changed bound dependency invalidates the prior certificate.

**Exit gate:** Every mandatory item is pass or justified not-applicable, every advertised tuple has current evidence, and all base offline workflows pass from the distributed image. Blocked hardware or model options remain unavailable rather than weakening the release gate.

## GWIN0 Windows hosted-platform proof

**Scheduling and ownership:** Begin after G1 and run alongside G2. Architecture/platform, Windows/release, storage/security, and inference leads. Re-estimate the remainder of the Windows program at this gate.

**Primary requirements and work packages:** `W005–W012`, `W021–W022`, `W030–W032`, `W035–W036`, and `W042–W043`; `WPW01–WPW02` with the required proof work from `WPW03`, `WPW04`, and `WPW06`. Foundational work for the program-wide `W001–W004` and `W041` obligations starts here, but those requirements close only in GWIN2 after every profile and final release artifact can be tested.

**Deliverables:**

- Common capability schema and extended ReleaseTuple.
- Signed Windows companion and WSL package without replacing an existing distribution or changing its default.
- Actual compact inference in WSL, authenticated launcher/bridge, one scoped host-file ingestion path, resource coexistence, and manual model-disabled controls.
- Qualified confinement composition and explicit fail-closed behavior when nested virtualization or another mandatory mechanism is unavailable.
- Complete Hyper-V Generation 2 desktop proof with explicit CPU, memory, disk, network, identity, and recovery behavior.

**Dependencies:** G1, supported Windows 11 x64 test hosts, WSL2, a Hyper-V Pro/Enterprise host for V, and appropriate driver/runtime access.

**Testing phase:**

- **Automated:** `V01`, `V03–V06`, `V08–V10`, `V15–V16`, and `V18`; adapted `T02`, `T13`, `T24–T25`, `T29–T30`, `T40`, `T42`, `T45`, `T51`, and `T62` coverage.
- **Manual:** Install beside an existing WSL distribution, start real compact inference, read an enrolled Windows file, disable the model, and use the complete VM desktop.
- **Security:** Two Windows users, denied folders, forged IPC/origin, executable interoperability denial, capture/clipboard denial, nested-virtualization absence, and host/LAN listener scans.
- **Performance:** WSL/VM loading peak, host reserve, cancellation, Windows foreground latency, and initial `Q02`/`QW04` measurements.

**Exit gate:** Actual core services and compact inference run in WSL; host-file ingestion is scoped and authenticated; the required confinement boundary holds; and the VM desktop is functional. A failed confinement gate keeps executable skills disabled.

## GWIN1 WSL product beta

**Scheduling and ownership:** Begin after GWIN0 and G3, then run alongside G4. `WPW03–WPW05` owners with QA and operations.

**Primary requirements:** `W013–W020`, `W023–W024`, `W034`, and `W037–W040`; filing and lifecycle targets `QW01–QW04` and `QW06`. GWIN0 requirements `W021–W022`, `W035–W036`, and `W042–W043` remain inherited gates. Program-wide release evidence under `W041` is assembled here but closes in GWIN2.

**Deliverables:**

- User-selected Windows folder enrollment with distinct read/index/organize grants and effect-time ACL checks.
- Persistent Windows event queue with stable-file detection, overflow recovery, rescan, cloud-placeholder handling, conflict-safe cross-volume operations, classification/review, and authorized retrieval.
- Opt-in background lifecycle with accurate pause/restart status.
- Private Linux metadata/journal placement, encrypted state, consistent backup, clean restore, and profile migration.
- Verified candidate-distribution update, writer fencing, compatible state migration, rollback/forward recovery, and safe uninstall.

**Dependencies:** GWIN0 and G3. G2 is already inherited through G3.

**Testing phase:**

- **Automated:** `V01`, `V03–V12`, and `V16–V18`; adapted `T04`, `T32–T36`, `T41–T42`, `T56–T57`, and `T59`; plus file/path/property fuzzing.
- **Manual:** Three required Windows-source journeys, user switching, sleep/logout/restart, update failure, backup/restore, uninstall, and W-to-N migration.
- **Security:** ACL revocation, junction/reparse races, hostile filenames, cloud hydration authority, credential isolation, host encryption state, and network policy.
- **Performance:** `QW01–QW04`, `QW06`, host/guest storage pressure, 1,000-event outage reconciliation, and declared Windows foreground workload.

**Exit gate:** File automation, outage reconciliation, candidate updates, recovery, and migration pass on the declared compact profile with no unauthorized read, silent overwrite, duplicate logical artifact, or lost acknowledged version.

## GWIN2 Dual boot and virtual machine qualification

**Scheduling and ownership:** Begin after GWIN1 and the G5 native A1 release baseline are stable. Platform, Windows, security, QA, release, and support owners.

**Primary requirements:** `W001–W004`, `W025–W029`, `W033`, `W041`, `W044`, and `QW05`, plus all inherited requirements applicable to each announced profile. The VM foundation `W030–W032` and architecture/threat requirements `W042–W043` remain GWIN0-owned inputs that are retested here.

**Deliverables:**

- Dual-boot preflight, separate-disk/prepared-space policy, BitLocker and hibernation safety, Windows Boot Manager preservation, Secure Boot coexistence, update recovery, and safe Linux removal.
- Qualified Hyper-V Gen 2 image/template, unique clone identity, guest A/B roots, LUKS2 recovery, safe checkpoint reconciliation, and opt-in host integration.
- Complete per-profile install, administration, development, recovery, removal, migration, and support documentation.

**Dependencies:** GWIN1 and G5, plus disposable encrypted Windows disk fixtures and a firmware-key recovery lab. G5 carries the final native release baseline needed to close the all-profile packaging and evidence obligations.

**Testing phase:**

- **Automated:** All applicable `V01–V18`; explicit adapted coverage for `T01`, `T05`, `T39–T40`, `T45–T47`, `T49`, and `T51`; then every other inherited baseline suite required by the announced profile.
- **Manual:** Repeated boot of both OSs, Windows/Linux/firmware update disturbance, Linux removal, ISO/template install, clone, checkpoint restore, host termination, and real end-to-end journeys.
- **Security:** Partition hash comparison, encrypted-volume protection, boot-trust preservation, no reusable VM identity, scoped sharing, and no public service by default.
- **Performance:** Exact B2 Q measurements for each host/guest tuple; a usable virtual display does not certify accelerator compute.

**Exit gate:** Each profile may be announced only after its own applicability and evidence register is complete and `W044` passes with real local inference, file operations, and durable artifacts. The program must record an explicit decision that staged independent profile certification is permitted despite `W001` describing all four profiles as the final product set.

## G6 A2 large local edition

**Duration and ownership:** Experiments may begin during P0; formal certification and release begin after G5, approximately months 12–16. Add two specialist equivalents for multi-GPU inference and qualification to the A1 team.

**Primary requirements and work packages:** `FR08`, `FR36`, `FR43`, and `FR56`; `A029`, `A038`, `A048`, `A072`, `A076`, `A078`, `A087–A090`, `A117`, and `A119`; `Q04–Q05`; `WP11` plus the A2 extensions of `WP08–WP09` and the inherited resource, security, operations, and verification packages.

**Deliverables:**

- Qualified 70–200B profiles and one real 400–405B model configuration.
- Per-rank memory, KV, staging, communication, topology, NUMA, huge-page/fallback, cancellation, recovery, and offload evidence.
- Headless authenticated service profile with no public administration endpoint.
- Explicit dense/MoE, quantized-KV, CPU-offload, or weight-paging certificates only where tested.
- A separately qualified heavy image/video model pack sharing the same resource-admission boundary, with accurate effect completion and provenance.
- An explicit optional Windows-compatibility certificate—compatibility layer or licensed VM—with complete resource reservation and an application allowlist; otherwise the capability remains unavailable.
- Native installation and certification on the named E6 ARM64 board, covering boot, storage, display/input, suspend, network, peripherals, compact runtime, and supported applications. Emulation, WSL, or hosted ARM64 execution cannot substitute for this evidence.
- Separate interactive and asynchronous service classes.

**Dependencies:** G5; E3/E4/E5 access; an E6 ARM64 board with qualified runtime and peripherals; sufficient power/cooling/storage/network; model and media-model distribution rights; a backend supporting the exact model; and a licensed compatibility stack if that capability is advertised.

**Testing phase:**

- **Automated:** `T01`, `T05`, `T17`, `T21`, `T25–T26`, `T31`, `T37`, `T43`, `T51–T52`, and `T54`; full inherited policy, artifact, cancellation, and recovery regression.
- **Manual:** Real 8K and 32K 400–405B runs; rank/device failure, pressure, driver restart, authenticated use, and headless recovery; an E6 clean install with 100 suspend/device cycles; concurrent media generation; and supported/unsupported compatibility-matrix runs.
- **Security:** User quotas, service identity, management-port isolation, per-rank lease ownership, secret handling, ARM64 boot/driver boundaries, compatibility/media sandboxing, and no mislabeled fallback path.
- **Performance:** `Q04` for an interactive certificate or `Q05` for asynchronous certification, plus `Q07–Q12`; raw placement, transfer, thermal, energy, latency, and task-success evidence. ARM64, media-generation, and compatibility results are published separately and never inferred from a 400–405B certificate.

**Exit gate:** The actual selected model completes `T43` within every physical domain budget and passes inherited security/durability requirements. `A072` media, `A076` compatibility, and `A078` ARM64 capabilities are advertised only after `T37`, `T31`, and `T01`/`T05` respectively pass on their declared tuples; any conditional capability without evidence remains unavailable. Fake tensors, sparse mappings, smaller substitutes, and vendor capacity claims cannot close the gate.

## G7 A3 distributed edition

**Duration and ownership:** Approximately months 16–22 if funded. Add three-to-five distributed-systems, SRE/storage, PKI, and test equivalents.

**Primary requirements and work packages:** `A091–A092`, `A120–A130`, `A136–A137`, and `A139`; `Q16` and `Q19–Q20`; `WP12`, `WP19`, and `WP20`. A1 backup requirement `A138` is inherited and retested but is not G7 primary ownership.

**Deliverables:**

- Authenticated node enrollment, complete-replica reservation, rank generation fencing, private collective fabric, and readiness-gated routing.
- Three-member Kubernetes control plane with redundant ingress and aligned containerd/kubelet cgroups.
- PostgreSQL with one fenced writer and separately managed quorum, durable replicated object storage, rebuildable indexes, backup, and disaster restore.
- Bounded model prefetch, node cache quotas, replica-aware rollout/drain, tenant quotas, credential rotation, and separately reported gateway/model/task health.
- Published real-hardware envelope for each certified 2-, 8-, or 32-worker tier.

**Dependencies:** G6, E7/E9/E10 labs, PKI, storage and network ownership, and funded real scale access.

**Testing phase:**

- **Automated:** `T41`, `T44`, `T52–T55`, `T58`, and `T60–T62`; split-brain, stale-generation, incomplete-placement, storage ordering, credential rotation, observability/evidence completeness, and rollout tests.
- **Manual:** Member, ingress, primary database, storage member, worker, rank, and network-partition failures; node drain and disaster restore.
- **Security:** Untrusted-node rejection, per-tenant cache/resource isolation, encrypted or isolated control/storage/collective paths, direct-admin-port denial, and effect-time revocation.
- **Performance:** `Q16`, `Q19`, and `Q20`; 60-minute stepped load, 30-minute twofold burst, queue/fairness/load/recovery measurements at every claimed real tier.

**Exit gate:** A full replica is ready only after every rank lease exists; stale generations cannot serve or duplicate effects; the stated metadata fault scope holds; and every published node/replica/tenant/request limit is backed by real hardware evidence. Simulated larger scale is labeled separately.

## RX Microkernel feasibility research

**Duration and ownership:** Separate six-to-nine-month feasibility track after G3, followed by a separate multi-year product program only if the gate justifies it. Dedicated kernel/platform, driver, security, compatibility, and inference researchers; not borrowed invisibly from A1 maintenance.

**Primary requirement and scope:** The catalog assigns `FR54` to RX. Preserve the G1-owned platform adapter semantics from `A077`/`T40` as an inherited input. On one documented board, investigate deterministic address spaces, tasks, IPC, interrupts, timers, storage, display/input, capability enforcement, DMA isolation, and CPU-only then accelerator inference. The `FR54` learned-scheduling work remains a bounded comparison against the default Linux policy and never places an LLM in the interrupt or scheduling path.

**Dependencies:** G3. RX may prepare research infrastructure before A1 product release, but it is separately authorized, funded, staffed, and cannot weaken or delay the Option A release gates.

**Deliverables:**

- One documented reference-board boot image and reproducible toolchain for the research kernel.
- Versioned platform-adapter conformance results for task, IPC, timer, storage, display/input, capability, and DMA-isolation boundaries.
- CPU-only and accelerator inference feasibility evidence, including driver/runtime gaps and recovery behavior.
- A separate `FR54` learned-scheduling experiment report comparing the candidate policy with the default Linux policy on identical workloads.
- A go/no-go decision record covering security value, performance overhead, compatibility, staffing, driver ownership, and multi-year product cost.

**Testing phase:** The catalog currently assigns no RX-specific numbered verification procedure. Add one through requirements change control before executing the research gate; the following evidence categories define the intended procedure.

- **Automated:** Platform-contract conformance, capability revocation, memory/DMA isolation, IPC, timer, crash recovery, filesystem durability, fuzzing, and generated-code review pipeline.
- **Manual:** Real-board boot, storage, display, input, networking, service restart, application compatibility, and model execution.
- **Security:** Kernel proof-assumption review, driver/server isolation, signed privileged code, IOMMU behavior, and Linux-guest boundary disclosure.
- **Performance:** Compare memory overhead, latency, throughput, recovery, energy, and compatibility with the same Option A workload.

**Exit gate:** Continue only if one board supports the required devices and inference runtime, recovery works, required applications run, overhead is acceptable, and measured security or maintainability value justifies the driver and compatibility program. A UI demonstration is insufficient.

## Ubuntu and Windows profile distinctions

| Concern | Native Ubuntu N | Dual boot D | WSL2 W | Hyper-V VM V |
| --- | --- | --- | --- | --- |
| Running kernel | Qualified Ubuntu kernel | Qualified Ubuntu kernel while selected | Qualified Microsoft WSL kernel | Qualified Ubuntu guest kernel |
| User experience | Product Wayland desktop | Product Wayland desktop after reboot | WSLg workspace window or qualified local web fallback | Complete guest desktop |
| Boot/update | Signed UKI, dm-verity A/B roots | Same, plus Windows boot coexistence | Signed candidate distribution and state migration; QW03 replaces physical-slot Q15 | Guest UKI/A/B plus template maintenance |
| Data protection | LUKS2 and recovery credential | Independent Linux/Windows protected state | Verified encrypted Windows storage or qualified product encryption | Guest LUKS2 plus protected host storage |
| Hardware authority | Qualified direct devices | Qualified direct devices while booted | Guest limits and explicitly delegated host broker actions | Assigned virtual devices and explicitly delegated host actions |
| Windows files | Explicit import/export if used | Authorized exchange and next-session reconciliation | Scoped Windows ACL-aware broker required | Same broker when host folders are enabled |
| Accelerator claim | Exact physical tuple | Exact physical tuple | Actual exposed compute API and host driver certificate | Separately qualified compute assignment; display is not evidence |
| Principal trust boundary | Linux user/system identities | Separate identities in each OS | Windows SID mapped to product principal; Windows host/admin trusted | Guest identity plus Windows/hypervisor trust boundary |

Windows host administrators, WSL, and the hypervisor remain trusted host components for W and V. Product documentation must not claim protection from a compromised host administrator.

## Test execution and evidence policy

Every stage contains implementation work followed by a named test phase. Tests are also run continuously at these cadences:

- Pure arithmetic, schema, policy, migration, and state-machine tests on every relevant change.
- Fake-backend fault and concurrency tests on every service integration build.
- A real compact-model workflow nightly on both consumer boards once G1 provides it.
- Boot, update, recovery, hardware, performance, thermal, and migration suites on release candidates and whenever a bound dependency changes.
- Actual large-model and distributed tests only on the environments required to support those claims.

Every evidence record contains the requirement and test IDs, environment, source/build/model/hardware digests, preconditions, scenario revision, timestamps, observations, raw performance distributions where relevant, result, and redacted supporting artifacts. Valid states are `pass`, `fail`, `blocked`, and `not_applicable`; every non-passing mandatory item has a reason and owner.

Deterministic properties use exact oracles. Probabilistic plans and generated content use held-out rubrics and human adjudication where necessary, but an LLM is never the sole judge of authorization, arithmetic, effect completion, or test success.

Severity 0 includes unauthorized effects, secret disclosure, committed-data corruption, privilege escape, and uncontrolled installation damage. Severity 1 includes unrecoverable boot on a supported system, host OOM, post-cancellation effects, invalid resource reuse, and failure of a core supported journey. Either severity blocks the affected release.

## Staffing and ownership assumptions

| Discipline | A1 FTE | Primary ownership |
| --- | ---: | --- |
| Principal architect and technical lead | 1 | Interfaces, integration, decisions, and scope |
| Platform and Linux engineers | 2 | Images, kernels, drivers, boot, device policy, recovery |
| Systems and inference engineers | 3 | Resource service, runtimes, KV, placement, performance |
| Backend and agent engineers | 2 | Workflow, skills, artifact APIs, persistence |
| Desktop and application engineers | 2 | Shell, content, adapters, accessibility |
| Security engineer | 1 | Authorization, isolation, adversarial testing |
| QA and performance engineers | 2 | Automation, hardware, reliability, evidence |
| Release and infrastructure engineer | 1 | Builds, signing, laboratories, operations |
| Product and UX support | 1 combined equivalent | Journeys, usability, pilot, documentation |
| **Total A1 planning baseline** | **15** | Allocation varies by gate |

P0 can start with four to six people. A2 adds approximately two specialist equivalents. A3 adds three to five distributed-systems, SRE/storage, PKI, and test equivalents. Windows work packages require explicit Windows, storage, security, inference, QA, and release allocations; they are not assumed to be free work inside the Linux estimates.

External penetration testing, device-lab access, large-model hardware rental or acquisition, cluster-lab access, pilot support, signing infrastructure, model/runtime redistribution review, and ongoing security maintenance require separate budget and ownership.

## Decisions and risks that must remain visible

- Freeze repository, package, service, and public schema names before declaring APIs stable. Requirements use `llmos-*` examples while the product is named Luma OS.
- Decide which core services become Rust production daemons and which Python components remain isolated workers or reference implementations.
- B2's embedded 4–6B control model supersedes the earlier 8–9B default for A1. Freeze the actual model, tokenizer, quantization, runtime, context, license, and redistribution rights in P0.
- Retain Ubuntu 24.04 as the committed baseline until every retained 26.04 tuple passes the promotion gate.
- Use the authoritative B2 ext4-on-LUKS2 design unless a versioned decision changes it; do not combine it accidentally with the earlier Btrfs recommendation.
- Record whether Windows profiles can release independently. This plan assumes independent certification, consistent with the Windows release-gate language, while preserving all four as the intended final profile set.
- Treat boot, partition, Secure Boot, encryption, suspend, power-loss, GPU reset, 400–405B, and cluster evidence as physical-lab work. CI simulation cannot close those gates. A 450B target requires requirements change control.
- Keep the Luma OS `Admin` role distinct from Windows Administrator and Linux `root`. Admin can assign finite declared activities, but every effect still requires scoped policy and production signing still requires protected human custody.
- Keep generated native code disabled until the required microVM or independently qualified constrained runtime passes; a normal container is not an equivalent substitute.
- Keep A2, A3, and RX outside the first A1 commitment unless separately funded. Their schema recognition in A1 is not an execution certificate.
- Do not use the visual simulator, allocation simulation, vendor TOPS, nominal RAM/VRAM, or a successful model load as evidence for a complete product claim.

## Immediate execution order

Development used `v0.1.0` as the G0 seed rather than restarting the reference implementation. The first implementation tranche is:

1. add the requirement/evidence registry and gate report;
2. freeze versioned service, error, artifact, plan, capability, and resource schemas;
3. add migration, export/restore, retention, and stronger negative tests to the current runtime;
4. introduce the deterministic fake inference/resource backend and checked resource ledger;
5. integrate one real compact local model without weakening manual operation;
6. establish the two Ubuntu reference machines and Windows GWIN0 hosts; and
7. run the G1 test phase before adding broader skills or boot-image scope.

Repository-local items 1–5 are implemented, together with Admin governance,
purpose/lifecycle-bound model-pack trust, policy, typed-DAG, local-gateway,
telemetry, platform-adapter, and recovery contracts. Item 5 now uses a pinned
Qwen3-4B development profile, but its unsigned external asset and one-host
smoke do not close the governed signed-pack/base-image/comparison deliverable.
Item 6 and every gate-closing physical-board, boot, recovery,
signing-custody, security/performance, and 400–405B test are recorded as final
certification deferrals. Development has entered the G2 safety-contract tranche
without representing those G0/G1 deferrals as passes or the pure G2 contracts
as OS certification.

No later-stage support claim should be merged into the support matrix until that stage's exit evidence exists.
