# ADR 0013 Native model governance and generated runtime

- Status: Accepted for development integration; production custody and native qualification remain separate
- Date: 2026-10-12
- Extends: ADR 0005, 0007, 0008, 0009 and 0012
- Scope: The closed native CPU model adapter and static-amd64 KVM execution profile

## Native model authority

The native adapter consumes the frozen model trust, catalog, pack and
certification contracts without changing their fields, signing purposes or
canonical encoding. Its independently provisioned immutable root policy is
`/usr/share/luma-os/model-roots.json`. Model roots and leaves cannot reuse OS or
skill signing identities. Trust publication, catalog approval, signing
authorization and admission use the existing TPM-selected Admin journal and
protected UTC, not a parallel caller-selected authority file.

Production catalog approval requires the actual distinct license, release and
security custodians and a separately authorized signer. A custodian authenticates
through a purpose-separated real PAM session with an exact finite assignment.
Original Admin governs those assignments but cannot replace that quorum. The
committed signing authorization returns the exact canonical statement to sign
outside the application; it exposes no private key and does not fabricate the
signature. Historical event replay and exact retained-outcome recovery do not
renew a session or make historical timestamps current authority.

Public image inputs are inert data packaged before sealing. They contain no
weights, private keys or fabricated approval receipts. A factory catalog envelope
is optional because the real installation-bound custody events may occur only
after installation. Production setup remains manual-only until its actual
release, Admin, UTC and model authorities are explicitly admitted.

The compiled CPU adapters support only the exact pinned Qwen3-1.7B and Qwen3-4B
Q4_K_M artifacts, context and llama.cpp tuple. Catalog capacity for other parameter
ranges does not install an unsupported backend or imply GPU/Gemma/large-model
qualification. Effective memory, storage and peak reservations remain mandatory.
Import and activation use separate exact finite resource scopes; neither is an
inference grant. Governing standard session limits remain unchanged unless the
owner separately approves an import-only extension.

Every signed tokenizer and template sidecar must match the exact metadata in
the GGUF bytes actually consumed by the runtime. Tokenizer encoding retains
GGUF value bytes and types losslessly, rather than reconstructing approximate
text. Preparation retains bounded digest-bound incomplete state; uncertainty
cannot become loadability or activation. Background physical byte verification
does not cache trust, account, grant, UTC, revocation or admission authority.

## Exact native qualification evidence

The frozen certificate's evidence digest must authenticate a closed native
qualification descriptor, not an opaque caller assertion. The descriptor binds
the complete acknowledged release manifest, exact signed model profile and
runtime tuple, anchored installation identity, certification level, external test-report digest and actual
measured CPU/memory tuple. Its hardware fields are vendor, family, model,
stepping, sorted features, logical CPU count and total memory bytes. Ambiguous
or heterogeneous observations are refused by this adapter.
The installation identity prevents a certificate for an identical hardware
tuple on another installation from being replayed as this machine's evidence.

Production qualification artifacts are externally delivered under the fixed
private model-qualification namespace. Their certificate signatures and exact
evidence digests are verified against current purpose-separated trust and UTC.
They are untrusted transport data until verified. Storing a certificate inside
the verity root cannot bind that same root's final hash without self-reference;
therefore immutable factory certificates do not substitute for this final-image
qualification. Exact matching is deliberately conservative and establishes no
portable machine-class, accelerator or performance claim.

An updated image, model profile, backend, context, material resource limit or
observed machine requires matching new external qualification. Existing opaque
certificates cannot silently inherit these native claims. No developer fixture
or signature alone supplies the real QA report.

## Generated-code boundary

The G2 generated-code profile is a fixed KVM microVM with a packaged kernel,
static guest init, runtime manifest and constrained QEMU process. Only bounded
static Linux amd64 ELF input is accepted. Payload bytes never execute on the
host. No caller-selected device, host filesystem, network, TPM, writable disk,
runtime argument or TCG fallback is allowed.

The original private PAM boundary, current finite grant and exact request join
the shared acquisition broker through nonce-bound live challenges. Cancellation
fences the exact leased cgroup generation, and physical charges persist until
measured drainage. Clean completion requires a current authenticated
acknowledgment for that same released generation; disconnected, expired or
premature completion is not equivalent.

Guest UID/capability/seccomp and fixed CPU, memory, wall and output limits are
independent of host confinement. Trusted receipt framing treats payload output
as data and binds results to exact runtime/input digests, broker lease and output
epochs. It never conveys signing or general effect authority.

## Closure evidence

Source, signature, real-PAM, disposable-TPM, KVM guest and AppArmor-parser checks
retain separate evidence scopes. A direct KVM guest pass does not prove the
installed PAM/broker/cgroup/AppArmor journey. Final distributed image testing,
both required native boards, live NTS/error-bound behavior, interruption/recovery,
production custodians and qualification reports remain mandatory. This ADR
does not close G2 or authorize advancement to Requirement 2.
