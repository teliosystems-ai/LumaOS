# Approved G2 staging recovery skills and UTC integration

The three owner-requested tracks were implemented in parallel and integrated
into one frozen software candidate on 2026-10-11. This closes the scoped source
gaps for approved inert production staging, reviewed activation, target-bound
governed repair, native closed-profile skill governance and recovery UTC delivery.
It does not close Requirement #1 or G2 native/production qualification.

## Implemented scope

- Workflow/platform: governed schema-2 skill registry, immutable separated root
  policy, retained revocations and monotonic admission floors; pinned immutable
  registry/graph verification and downgrade refusal; reviewed skill publication
  and admission commands; duplicate-refusing DAG/scheduling inputs and one final
  UTC projection across account aging, finite grants and both signing domains.
- Production trust/update: exact offline root-signed staging without protected
  authority, retained first-boot evidence and explicit Admin/TPM/current-UTC
  activation; production worker/effect fences; a narrow usable release-command
  route; private exact image/target proofs, read-only target custody/history,
  existing TPM/PCR policy and nonrenewable thirty-minute repair authorization
  around bounded writes, readback and EFI publication.
- UTC dependency: authenticated pinned source, reviewed immutable provenance,
  mandatory release/crypto lanes and separate enforcing recovery keeper,
  producer and fixed restart adapters. Authenticated target-bound seed,
  reacquisition and query delivery gives the keeper neither target secrets nor
  TPM credentials. Final projections preserve the original query/session bounds.

Public input packaging verifies actual Ed25519 root/leaf signatures and exact
registry/graph digests before verity sealing. It accepts no private key and
activates no journal authority. The lab builder remains a lab builder, not a
production private-key ceremony. See [ADR 0012](../../docs/adr/0012-production-staging-repair-and-skill-trust.md),
[the release commands](../RELEASE_TRUST.md) and [the skill trust protocol](../SKILL_TRUST.md).

## Final source verification

The final source snapshot contains 375 files. Its manifest SHA-256 is
`afb568a77f8f1274cf18218555682fcd22c018929e881ec00f873ac15ccbcd4c`.
An independent post-test capture of the current build/test inputs is byte-identical.
Full transcripts, authenticated source and intermediate artifacts remain on D;
exact paths and hashes are retained in the [machine-readable record](G2_APPROVED_INTEGRATION_2026-10-11.json).

| Lane | Final result |
| --- | --- |
| Rust all-target compilation | Passed offline/locked with warnings denied |
| Rust full default suite | 920 passed, zero failures; 42 fixture-only entries ignored |
| Native source/packaging suite | 358 passed, zero failures/skips |
| Public trust crypto packaging | 13 passed, zero failures/skips |
| UTC release signature/source authentication | 8 passed, zero failures/skips |
| Authenticated UTC release build | NTS, privilege-drop and seccomp enabled; no daemon run |
| Upstream NTS/auth/crypto units | 16 exact PASS results, zero skips, all capabilities dropped |
| Real PAM fixture | Six stated cases passed in disposable accounts |
| Resource TPM fixture | Four independent fresh software-TPM cases passed |
| Existing-owner Admin TPM driver | Passed |
| AppArmor and fixed launcher syntax | All 13 profiles parsed with Ubuntu 24 parser 4.0.1; build and both launchers parsed |

Selected fixture drivers execute their stated cases, not all 42 default-ignored
entries. Tests run against the frozen source, not an installed image. The combined
container was bounded to 4 GiB memory plus swap total, two CPUs and no network;
the serialized upstream lane used 1 GiB, one CPU, no network and zero capabilities.
There was no physical TPM access, host account/clock/disk/firmware change, WSL
restart or memory resize. Policy parsing used `-Q -K`: no host policy load or
actual kernel-confinement claim. Syntax-only output remains in tool transcripts.

The first full attempt failed on two test-only JSON assignments and three
source-inspection assertions. Those defects were corrected, and its failed
evidence is retained. The next candidate passed all combined lanes, but the
operator-route review found that release prepare/resolve/trust rotation had no
external entry point. The final candidate adds that closed route and three tests,
then repeats the full sweep. No older candidate's pass qualifies changed bytes.

## Remaining qualification

Build the new final image from this source on D and test the distributed image,
not the prior sequence-12 image. The separate Ubuntu machine must exercise
installation, first-boot activation, confined services/workflows, compact-model
resource cycles, update/trial confirmation/fallback and target recovery, including
interruption/storage pressure. Physical tests must qualify existing-owner TPM,
approved PCR policy, Secure Boot and firmware behavior. Native UTC tests must
qualify certificate bootstrap, quorum/loss/leap, clock-step/suspend/rate bounds
and enforcing installed/recovery confinement.

Production roots, signed bundles and actual signing custody remain externally
provisioned qualification inputs. Static upstream signature verification does
not certify live key revocation or the installed TLS/libc/kernel/CA closure.
Production model catalog/pack governance, arbitrary generated-code capability
and general populated migration are separate scope, not supplied by this closed
skill adapter. Requirement #1 and G2 remain open; do not advance to Requirement #2.
