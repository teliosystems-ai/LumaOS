# Roadmap

This roadmap communicates direction, not a delivery promise. Scope changes require tests, threat-model review, and support-matrix updates.

G0/G1 repository development is recorded as complete with explicit deferrals.
Formal OS certification is still blocked; the deferrals move hardware-dependent
testing to the final qualification environments but do not turn it into a pass.

## v0.1 — Developer MVP

Goal: prove one complete, local, inspectable workflow through a shared core.

- dependency-free Python loopback runtime and browser UI;
- explicit local folder grants and safe bounded reads;
- prepare-before-run invoice report workflow;
- durable versioned artifacts and effect receipts;
- restart-safe workflow state and idempotency;
- manual/offline baseline with optional model status;
- current native Windows and Ubuntu 26.04 WSL development lanes, with Ubuntu 24.04 retained as the physical-board certification baseline;
- a pinned Qwen3-1.7B/llama.cpp development smoke through Windows CUDA, Ubuntu WSL CPU, and the authenticated Luma gateway;
- an Admin product governance role for finite, receipted delegation, distinct from host administrator/root and production key custody;
- source release, checksums, CI, and architecture/security documentation.

Exit evidence is the automated repository checks plus documented manual smoke testing. The separate visual simulator is not exit evidence.

## v0.2 — Contract and security hardening

Candidate work, subject to review:

- stabilize API/schema compatibility rules;
- harden Admin bootstrap/recovery, delegation review, and signing-purpose lifecycle tests;
- expand negative tests for filesystem, session, request, and state-machine boundaries;
- add explicit export and retention controls;
- improve backup/restore validation and schema migration tests;
- define a signed receipt/export format without claiming external tamper proofing;
- accessibility and browser compatibility review;
- reproducible source-build provenance; and
- supported package layout that can include UI/schema assets, if wheel distribution is needed.

## v0.3 — Controlled extensibility

Candidate work:

- a narrow, typed tool-adapter contract;
- an isolated local model adapter with strict input/output schemas;
- resource budgets, cancellation, and workflow recovery controls;
- additional deterministic vertical workflows;
- policy explanation and diff tooling; and
- a compatibility test kit for approved adapters.

Remote services, write-capable tools, or dynamic plugins would need separate threat models and remain disabled by default.

## Research track — OS integration and scale

The following are research themes, not commitments or current support:

- desktop/session integration on Ubuntu;
- hardware-aware model profiles;
- native Windows experience beyond WSL2;
- VM or image distribution;
- multi-device orchestration; and
- larger-model or distributed inference integration.

The governed large-model target is 400–405B. A 450B target is not part of the
current requirements and would enter this track only through change control.

## Explicitly not promised

No roadmap item should be interpreted as a promise of:

- a production operating system or replacement kernel;
- a bootable ISO, dual-boot installer, or certified VM image;
- production remote/multi-user hosting;
- bundled model weights or rights to third-party models;
- 400–405B model support, benchmarks, or cluster certification;
- safety-critical, regulated, or autonomous operation; or
- acceptance equivalence between the visual simulator and the reference runtime.
