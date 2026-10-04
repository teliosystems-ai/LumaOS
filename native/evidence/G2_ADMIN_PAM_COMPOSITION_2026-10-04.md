# G2 Admin PAM and TPM composition checks

The local catalog path now has a targeted fixture that composes kernel peer
identity, real PAM authentication, principal revalidation, sealed credential
reload and the native software-TPM catalog backend. It supplements the earlier
protocol-only checks. It does not qualify an installed service or complete G2.
The governing authorization distinctions in ADR-0007 and ADR-0010 are unchanged.

## Authentication fix and shared composition

The previous authenticated identity method performed another account read after
its bounded freshness check. A slow second read could return an observation
after its 30-second lifetime. The native UID and identity methods now share a
private guard that checks freshness before and after the complete observation,
including identity projection. A deterministic regression makes the observation
expire during its read and verifies that no projected result is returned.
Root and ordinary peer identities also refuse before entering PAM.

The product service and the disposable fixture share the peer-to-PAM binding
and catalog request adapter. Production still uses only the fixed installed
helper, registry, identity directory, TPM device and credential inputs.
Alternate fixture paths/backend constructors are compiled only under
`cfg(test)`, guarded for disposable-container use and have no product CLI or
IPC selector. No unconfined fallback was added to the installed daemon.

## Integrated scenarios

`admin_service::tests::pam_catalog_connection` runs 17 actual socket requests
from a client dropped to UID 1001 before connecting. Each accepted request
uses the real compiled PAM helper and the packaged authentication profile.
The fixture socket uses root:1001 ownership and 0660 permissions. Random test
passwords reach children through a protected memfd, never arguments or
environment variables, and replies are checked for credential disclosure.

- Status, registration inspection/commit, exact registration replay,
  role-update inspection/commit and exact role-update replay pass. Commits make
  two TPM-backed catalog changes; inspection/replay leave the journal unchanged.
- Wrong password, a valid password for another UID, an invalid review digest,
  a disabled principal, a changed generation, disablement after PAM and a locked
  account all return generic denial with no result and unchanged journal bytes.
- The final freshly authenticated status verifies the restored fixture identity,
  the TPM/journal continuity and the updated role at version 2. Fixture resets
  are test actions, not a product account or principal recovery API.

The checkpoint enrollment and initial bootstrap use the existing disposable
test seams; they are not real PAM-authenticated enrollment/bootstrap acceptance.
Catalog requests use genuine PAM observations, not fixture identity objects.
The test invokes the shared request adapter directly, not the installed
`admin-service`/`admin-service-request` entry points or terminal client.

## Verification

Targeted checks passed on 2026-10-04 at
`D:\LumaOS-builds\g2-admin-pam-targeted-20261004-02`.

- Build-input manifest SHA-256: `282e4427beb182ee886132a5d1a265638e1cebf98814768cc3d3268795f44fa9`.
- Supplementary test-input manifest SHA-256: `ae6ca47831365005a8b2c2be0cca85500470385edc2158ac44db9ce306cc1d6b`.
- Completed log SHA-256: `e2d433ae178c9794f973d40e45b63c012f81ca95f8af598d8b00361ec6768065`.
- All 170 build inputs and seven supplementary inputs matched the checkout.
- 65 ordinary Rust tests passed: seven service, 22 governance, four catalog,
  16 journal, five authentication, six principal and five credential tests.
  Environment-dependent ignored tests are excluded from that count.
- The existing three-case kernel-peer fixture and the new 17-request real-PAM
  composition fixture passed. Signed-PCR sealing control, legacy systemd
  nonempty-owner refusal, native existing-owner enrollment and the existing
  bootstrap/catalog restart fixture also passed on the disposable software TPM.
- Ten source-wiring checks, formatting, warnings-denied offline locked build
  and repeatable-runner Bash syntax passed. The runner invokes the new fixture;
  its full execution and remote CI were not run here. Earlier `-01` results are
  retained but do not qualify the final changed input bytes.

Checks used an offline disposable container, one CPU and at most 768 MiB, with
all build/cache/evidence storage on D:. No host TPM, Docker socket, additional
privileges, host account/policy changes, WSL settings changes, image build,
VM or model sweep were used. Private test keys, account credentials and emulator
state were not exported into evidence or Git.

## Remaining scope

Installed terminal input, actual systemd/AppArmor/seccomp/cgroup/device
enforcement, real enrollment/bootstrap, service timeout/restart, interruption,
boot/update/fallback and physical TPM qualification remain required on the
consolidated candidate. The fixture does not replace those tests or demonstrate
production custody. Time-bound assignment/revocation still needs a reviewed
live trusted-UTC provider; unchecked wall time and TPM powered-time are not
substitutes. Principal recovery, effect grants, signing custody and the other
implementation-first work packages remain open.
