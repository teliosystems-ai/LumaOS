# Governed native model lifecycle

The native production adapter consumes externally signed model trust, catalogs,
packs and qualification. It does not generate production keys, approval receipts,
signatures or QA results. A downloaded GGUF or successful inference is not
certification. See [ADR 0013](../docs/adr/0013-native-model-governance-and-generated-runtime.md)
for the trust and runtime boundaries.

## Factory inputs

Set `LUMA_NATIVE_MODEL_PUBLIC_INPUTS` to an exact existing public-input directory
when building. The driver mounts it read-only, separately from OS/skill public
trust, and assembly packages it before verity sealing. The closed group includes
`model-roots.json`, `model-trust.json`, `catalog.json` and the declared signed
pack manifests and auxiliary blobs under `model-packs/<manifest-sha256>/`.
Weights and private keys are forbidden. `catalog-envelope.json` is optional:
installation-bound approval events can be created after installation.

Production qualification is delivered after the image exists, not embedded in
the root whose final hash it must certify. Laboratory certificates have a
separate explicit scope and cannot qualify production. With no model-public
group, the explicit laboratory pinned-model path is retained; damaged, enrolled
or production authority cannot fall back to that path.

The installed immutable root policy independently names accepted trust/catalog
policy versions, root environments and validity bounds. OS, skill and model
signing identities are separated. Native profile mapping remains closed to the
two compiled CPU Qwen3 Q4_K_M tuples; other backends or parameter configurations
need their own implementation and qualification.

## Custody and import

Original Admin uses `luma-admin-control admin-model-command LOGIN REQUEST FILE`
to review a closed trust-publication or catalog-admission command, followed by
the same request with `--commit REVIEW-SHA256`. Review is not authority. Trust
rotation, irreversible revocation and catalog admission floors use the existing
TPM-selected journal and current protected UTC.

Assigned human custodians use
`luma-admin-control admin-model-custodian-command LOGIN REQUEST FILE`, then the
exact reviewed commit form. The closed intent is either catalog approval or
signing authorization; it cannot supply its own authoritative decision receipt
or signing time. Production needs distinct license/release/security approvers
and a separately assigned signer. Original Admin is not a quorum substitute.
After committed signing authorization, sign only the returned
`canonical_signing_statement` with external protected custody. Do not regenerate
its time or modify its bytes.

Use `granted-run model-pack-import-review MODEL-ID` to obtain the exact finite
`Resource`/`resource.acquire` scope. Import with
`granted-run model-pack-import LOGIN GRANT MODEL-ID`. This prepares the exact
signed pack in the private CAS and never activates serving. Its conservative
storage peak includes cache, CAS, staging and reserve. Tokenizer/template
sidecars must match the losslessly encoded GGUF metadata actually used by
llama.cpp. Normal session limits apply; a long download cannot borrow the
separate export or repair session purpose.

Interrupted preparation remains digest-bound unverified state. Review it with
`granted-run model-pack-pending-review MODEL-ID` and explicitly retain the exact
reviewed bytes with `granted-run model-pack-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256`.
Retention does not verify, delete, activate or certify those bytes.

## Qualification and activation

After real QA produces its report, obtain the unsigned measured descriptor with
`granted-run model-qualification-observe MODEL-ID LEVEL REPORT-SHA256`.
An external authorized execution/interactive certifier signs the frozen
certification record whose evidence digest authenticates that exact descriptor.
The descriptor binds the anchored installation, full acknowledged image, signed model profile,
runtime and measured CPU/memory tuple. The command supplies no QA pass or
signature. Interactive qualification cannot skip execution qualification.

Review the closed public package with
`granted-run model-qualification-review MODEL-ID INPUT`, then install using
`granted-run model-qualification-install LOGIN GRANT MODEL-ID INPUT`.
The transfer envelope has exactly `package` and `expected_previous_sha256`;
`package` contains the frozen `record`, raw Ed25519 `signature_hex` and closed
`evidence` descriptor. The predecessor is null for first installation or the
exact current package digest for replacement. Use the command's fixed protected
input namespace `/run/luma-admin/model-qualifications/NAME.json`; an arbitrary
path is not a privileged transfer interface. The launcher validates and snapshots
that public transfer into its separate private request namespace before PAM.
The writer requires original Admin and an exact finite provisioning grant.
Current trust, UTC, tuple and signature checks apply; certificate rotation binds
the exact reviewed predecessor. A single atomic
`/var/lib/luma-os/model-qualifications/<manifest-sha256>/<level>.qualification.json`
keeps record, signature and evidence together. Uncertain or conflicting bytes
remain for explicit reconciliation, not silent overwrite.
For interrupted transfer bytes, use
`granted-run model-qualification-pending-review MODEL-ID` and
`granted-run model-qualification-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256`.
This is exact unverified-byte retention, not certificate installation or deletion.

Once the actual certified catalog is admitted, review activation with
`granted-run model-activate-review MODEL-ID`. Supply the returned exact provision,
worker-start and planned-worker-stop scopes through
`granted-run model-activate LOGIN GRANTS-JSON MODEL-ID`. Import, qualification,
activation, worker management and inference are distinct authorizations.
`GRANTS-JSON` is the closed inline map `{"provision":"GRANT-ID","start":"GRANT-ID","stop":"GRANT-ID"}`,
not a path or a caller-defined list of worker actions.
Activation preserves the existing trial, atomic configuration, quarantine,
rollback and reconciliation checks; it cannot bypass them by calling the old
laboratory installation path.

## Qualification limits

Current physical-byte witnesses reduce repeated hashing, but model authority
still reconstructs its TPM, trust/floor, protected UTC, custodians, certification
and selection. Human inference and operation boundaries separately reconstruct
their original PAM account and exact finite grant. Cached bytes are not cached permission.
Source crypto and disposable tests cannot replace external signing ceremonies,
real model quality/performance evidence, final-image authorization/confinement,
native installation/recovery or the required physical boards.
