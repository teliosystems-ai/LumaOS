# Parallel G2 source integration, 2026-10-11

Three agents worked on workflow/platform integration, native OS release trust/
updates and UTC dependency authentication. The integrated source passed the
final offline development sweep. **This does not close Requirement #1 or G2.**
Two production installation/recovery policy decisions still block their complete
software implementation; final-image/native qualification is also pending.

## Delivered scope

The closed FileRead/DeterministicCalculate/ArtifactWrite workflow profile now
has a reviewed round-robin scheduler for one step in each of at most sixteen
distinct runs. Every step enters the existing fresh identity/grant/UTC/resource/
effect boundaries. Duplicate grant selectors, stale/terminal/uncertain reviews
and malformed acknowledgements refuse. A failed item preserves its uncertain
outcome and undispatched suffix without retry or rollback. Final aggregation
contains only bounded inert invocation acknowledgements, not private plans,
paths, account bindings or receipt contents from expired earlier sessions.

Native OS release trust and increasing admission floors now use the shared
Admin TPM journal, with root-signed purpose-specific public keys, irreversible
revocation, exact signed candidates, explicit prepare/resolve transitions and
bounded write/readback/EFI guards. Immutable release metadata, UKI parameters
and actual verity geometry/device bindings protect health acknowledgement.
Stable acknowledged/manual boot and exact prior fallback remain independent
of online UTC. Machine health does not impersonate the Admin journal writer.
See [the release lifecycle](../RELEASE_TRUST.md) for operational boundaries.

Chrony 4.9 inputs now undergo actual detached-signature verification against
the fixed reviewed public key, archive and signature. Source extraction and
distribution consume the actual crypto-verified private snapshot, eliminating
caller-path replacement between verification and use. Runtime also requires
closed readonly provenance and patched-source review records. The approved
providers, bounds and offline-refusal policy are unchanged. Static upstream
release authentication is not a live key-revocation service or native clock
certification; see [the dependency review](../image/utc/README.md).

## Executed verification

The final 360-file source manifest SHA-256 is
`2e42f69f4484a50bb6c2f71ad7ff517d2943986dbb235e96c8fac45a865260dd`.
After verification, a fresh current-source capture produced the identical
manifest, confirming no intervening source-byte changes before the commit.
Source stayed on C:; snapshots, caches, containers, UTC packages and raw evidence
stayed on the approved D-backed ext4 build store. WSL memory and unrelated
workloads were unchanged. No physical disk, host TPM, account or clock changed.

- All Rust production/test targets checked with warnings denied. The full
  default suite passed **888 tests**, with zero failures and 42 pre-existing
  fixture-only entries ignored by that default invocation. It is not a claim
  that all 42 fixtures executed.
- Linux native source/packaging discovery passed **345 tests with zero skips**,
  including six public-only release-ceremony tests using real disposable
  Ed25519 signatures.
- Mandatory actual UTC signature/source authentication passed **eight tests
  with zero skips**. The candidate built with NTS, privilege drop and seccomp;
  no daemon ran.
- Separate capability-free/network-disabled dependency tests freshly
  authenticated, extracted and built the same source, then passed all
  **sixteen crypto/NTS unit cases**. Upstream zero-exit `SKIP` is rejected.
- Six actual PAM cases, four independent resource software-TPM cases and the
  existing-owner Admin software-TPM driver passed. These are disposable fixtures,
  not installed product authorization or physical-TPM qualification.

The combined container was limited to 4 GiB, no additional swap and two CPUs;
the separate UTC unit container to 1 GiB, no additional swap and one CPU.
Both had no network. The UTC unit lane required all five capability sets zero.
All result/transcript identities and paths are in the
[machine evidence](g2_parallel_integration_2026-10-11.json).
Earlier failed attempts remain on D:. The full first compilable suite exposed
an actual missing candidate/trust-environment comparison, which was fixed
before the final full pass. Review also removed delayed private scheduler
status delivery. Failed or superseded bytes are not qualified by the final run.

## Remaining implementation and owner decisions

Production installation is still installed-authority dependent before a target
exists. Choose either authenticated UTC before any write, or explicitly approve
immutable signed offline staging followed by first-boot Admin/TPM/current-UTC/
trust activation, with protected operations disabled until activation succeeds.
A seed or wall clock alone must never activate production authority.

Production/anchored-target repair still needs a typed exact target-mount/TPM/
principal/history/UTC adapter and a separate finite original-Admin custody
session. The existing 30-second bound cannot reliably cover multi-GiB writes
and readback. Proposed policy: at most 30 minutes, exact reviewed disk/image,
continuous target/TPM/journal/custody/current-UTC checks, no automatic renewal.
The approved export-only duration is not reused. Recovery and UTC agents agreed
the typed interface design but made no recovery-mode source changes pending
these decisions. Current denial is a safety fence, **not implementation completion**.

Production model/skill catalog governance remains separately unfinished; the
current skill registry is laboratory-only. General populated schema/reference/
principal portability is provisionally G4 (A134/Q18), not silently waived.
The present closed workflow profile has explicit old-generation disposition
and historical acknowledgement, not arbitrary credential/authority migration.

No new final image was built from this stage. The older sequence-12 image and
its live smoke results do not qualify these changed bytes. Native installation,
NTS/certificate/provider attacks, step/suspend/rate-error/confinement, update/
fallback, power-loss/recovery and the required physical-board/TPM results remain
separate. Actual production public roots/signatures and custody cannot be
manufactured by development fixtures. Do not advance to Requirement #2.
