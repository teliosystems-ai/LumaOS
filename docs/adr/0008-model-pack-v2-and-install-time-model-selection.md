# ADR-0008: Model-pack schema v2 and install-time multi-profile selection

- Status: Accepted for development; production activation remains blocked
- Date: 2026-09-23
- Decision owners: requirements and release owner, inference lead, platform lead, security lead, license owner
- Supersedes: the schema-v1 and single-profile assumptions in ADR-0005
- Retains: ADR-0005 signing purposes, trust roles, lifecycle states, tuple-bound certification, and protected-key rules

## Context

The governing Ubuntu baseline requires a verified 4–6B control model, exact
model identity and parameter information, checked arithmetic through 405B,
per-machine support states, compatibility rejection, loading- and serving-peak
admission, and support for multiple installed model files. It also requires the
installer to inventory hardware before proposing an edition and model size.

The version-1 model-pack schema represented the parameter class as free text,
allowed only one model blob, and did not carry an installable resource profile.
It could not express total versus active parameters for efficient architectures,
multi-shard weights, or the exact host, accelerator, storage, context, and
runtime constraints needed to decide whether a model may be selected during
installation.

The product must support several model configurations without promising that
every configuration runs on every machine. A successful file download, nominal
parameter label, or nominal GPU capacity is not a loadability or certification
result. Selection must use the effective resource limits visible to the target
environment; for example, a WSL guest limit is not the Windows host's entire
physical memory.

## Decision

### Model-pack schema version 2

Schema version 2 is a breaking manifest revision. Every v2 pack records:

- immutable model identity, architecture, source, quantization, and parameter
  class;
- a non-empty canonical list of required runtime capabilities;
- exact `total_parameters`, `active_parameters_min`, and
  `active_parameters_max` integer fields;
- one or more ordered model shards, each with a zero-based contiguous shard
  index, digest, and byte size;
- the tokenizer, prompt template, auxiliary, and license blobs by digest and
  byte size;
- one or more exact runtime tuples; and
- one or more installation profiles binding a profile ID to a runtime-tuple
  digest, CPU or CUDA execution mode, minimum host memory, minimum accelerator
  memory, minimum model storage, and maximum context.

Parameter and byte fields reject booleans, zero where a positive value is
required, unsafe JSON integers, overflow, inconsistent active-parameter bounds,
and installation profiles that understate pack storage or exceed the declared
model context.

For the current governing 4–6B compact-model range, eligibility is determined
from `total_parameters`, not a marketing or effective-parameter label. Active
or effective counts are retained because they affect execution and comparison,
but they do not silently redefine the governed tier. Any different
interpretation requires controlled requirements change.

This gives the following candidate classification:

- Qwen3-4B, 4.0B total, is an unambiguous compact candidate.
- Gemma 4 E2B, 5.1B total and 2.3B effective, may be evaluated as a compact
  candidate while both counts remain visible.
- Gemma 4 E4B, 8B total and 4.5B effective, is an optional mainstream 8–14B
  candidate. It is not a governed 4–6B base-model candidate.

These classifications select candidates only. They do not approve a license,
sign a pack, prove runtime compatibility, or grant a certification state.

### Install-time model-profile catalog

A separate release-controlled model-profile catalog describes selectable
configurations. Each model profile binds:

- total and active parameter counts;
- model-pack manifest and runtime-tuple digests;
- installed bytes and the full storage peak, including staging and rollback;
- minimum effective host and accelerator memory;
- phase-specific loading and serving reservations for each memory domain;
- context limit and execution mode; and
- availability, identity-verification, development-test, and certification
  states.

Every catalog also contains exactly one explicit `manual-only` profile. Manual
operation is a user-visible selection and recovery path, never an implicit model
fallback. Remote inference fallback is false for every local installation
profile.

A trusted platform adapter supplies an immutable hardware snapshot containing
effective host memory, available model storage, exact supported runtime-tuple
digests, and verified available accelerators. Assessment returns either a
digest-bound selection or typed rejection reasons. A requested CUDA profile is
never silently replaced by a CPU profile, another model, a smaller context, or
a remote service.

The installation plan must bind the selected profile digest, catalog digest,
hardware-snapshot digest, model-pack manifest digest, runtime-tuple digest,
execution mode, and selected accelerator identity before destructive
confirmation. Effect-time revalidation must reject drift. Production setup must
not download, activate, or substitute a model outside the reviewed plan.

### Lifecycle and evidence boundary

ADR-0005 lifecycle meanings remain unchanged. A pack becomes loadable only
after its signature, blobs, license decision, runtime tuple, and compatibility
checks pass. Execution and interactive certification still require separately
signed evidence for the exact release and machine tuple.

An unsigned, digest-pinned artifact may be used in an explicit development
mode and recorded as a development smoke. It cannot be represented as a signed
pack, placed in a production-selectable catalog, or inherit execution or
interactive certification. One Windows host and its WSL guest count as one
physical machine.

Feature support is never inferred from a family model card or successful text
generation. Text, image, audio, tool use, thinking mode, and long-context claims
remain unavailable until the exact runtime and pack tuple has corresponding
evidence and is published in the support matrix.

## Migration and compatibility

Version-1 manifests are not silently accepted as version 2. A retained v1 asset
must be rebuilt with exact v2 identity and resource fields, reviewed under the
current license decision, signed again, and retested. Existing certification
does not float to the rebuilt manifest, a new model revision, quantization,
template, runtime, context, driver, or material resource limit.

Historical v1 development records remain immutable evidence of what was tested
at that time. New evidence is added in dated files rather than rewriting those
records.

## Consequences

- Installation can present multiple explicit parameter and execution profiles
  while failing closed when the selected hardware cannot satisfy one.
- Storage, loading peak, serving peak, context, and per-device fit become part
  of the reviewed selection rather than UI hints.
- Efficient-model labels no longer conceal total residency-relevant parameter
  counts.
- The schema migration requires new pack fixtures, negative tests, signing
  exercises, and compatibility documentation.
- Qwen3-4B development smoke evidence can advance local integration work, but
  G1 and G2 remain certification-blocked until signed packs, two physical A1
  boards, full offline workflows, pressure and recovery testing, task-quality
  adjudication, sustained-load evidence, and protected signing custody exist.

## Change control

Changing parameter-tier semantics, mandatory v2 identity fields, allowed
execution modes, selection binding, fallback behavior, signing or hash
algorithms, trust roles, lifecycle states, or tuple-bound certification requires
a superseding ADR and migration/security review. Changing the governed 4–6B or
400–405B ranges requires a controlled revision of the governing requirements,
not an implementation-only ADR.
