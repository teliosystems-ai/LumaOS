# G2 approved UTC policy and keeper checkpoint

On 2026-10-05 the owner approved the suggested Cloudflare, Netnod and PTB
providers, initial bounds and offline-refusal policy. The [UTC design](../TRUSTED_UTC_DESIGN.md)
records that decision separately from implementation and qualification. It does
not approve a supplied clock seed, TPM ceremony, host clock change or physical
operation. No time service was activated; G2 remains incomplete.

## Fixed policy and lifecycle implementation

`native/image/utc/approved-policy.json` fixes the three operator identities,
two-source minimum, 180-second real-age limit, 500-ms uncertainty width,
100-ppm total rate-error assumption, offline denial and leap fencing.
`utc_policy.rs` verifies both the exact compiled bytes and their closed semantics.
Its domain-separated digest binds lifecycle epochs; caller-selected policies,
reformatted bytes, additional fields, duplicate fields, substituted providers
or looser limits refuse. This digest is an integrity binding, not release
signing authority or proof of an authenticated time source.

`utc_keeper.rs` implements a non-authorizing lifecycle reducer. Each round must
contain all three ordered operator states, including explicit unavailability.
It checks round/source sequence, unchanged-sample identity, acquisition timing,
epochs and clock consistency before applying the conservative interval core.
Lost quorum and invalid observations discard the retained estimate immediately.
Fresh measurements cannot be manufactured by re-aging a retained sample.
Explicit reacquisition increments the clock generation and requires measurements
after its new barrier. Generation overflow refuses rather than wrapping.

A candidate behind the supplied history floor enters reconciliation with no
reset/reacquisition path. An overlapping interval can be clipped by that floor,
but the floor alone cannot produce current time. `Bounded` is only an arithmetic
candidate, not live-service eligibility or a permission token.

Clock observations, suspend notifications, measurement provenance and the history
floor are still supplied data in this reducer, not authenticated publisher or
TPM proofs. There is no product CLI, IPC interface, live clock reader or grant
integration. Actual event notifications and the qualified total rate envelope
must supplement the consistency checks; comparing clocks alone cannot detect
every small step or establish absolute UTC. Admin still reports
`trusted_utc_available: false` and has no assignment/effect interface.

## Bounded upstream chrony audit

Read-only source capture on D: resolved upstream tag 4.5 to immutable commit
`120dfb8b36b942c31ddfc0220ca1475159ac5031`. Thirteen source/header files and the
tag reference are retained at `D:\LumaOS-builds\g2-chrony-source-audit-20261005-01`.
The source-input manifest SHA-256 is
`acb29358545ecc5981bad94c91dad2e7cbb8fb6b8a9276b40936712f6eec9c52`.
This is a bounded authentication/reporting review, not a full vulnerability
audit, signed release verification or selection of the production Ubuntu
package tuple. The eventual exact package and publisher changes require review.

- `NAU_CheckResponseAuth` refuses a response mode different from the configured
  mode and delegates NTS responses to its NTS validator. That validator checks
  request identity, authenticated extension decryption and one-response state.
  [Authentication dispatch](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/ntp_auth.c),
  [NTS response validation](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/nts_ntp_client.c).
- `process_response` includes authentication in valid-packet admission and
  applies additional synchronization/sample checks. The retained NTP report's
  authenticated field is assigned from authentication configuration. A report
  flag alone therefore cannot replace those admission checks.
  [NTP core](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/ntp_core.c).
- `SRC_GetSelectReport` copies stored selection bounds and stored sample age.
  `SST_DoSourceReport` aligns the source sample timestamp to whole seconds.
  Neither interface supplies an atomic Luma boot/process/clock-generation
  measurement record. It would be incorrect to re-age stored selection bounds
  at report retrieval and label them fresh authenticated UTC.
  [Selection reporting](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/sources.c),
  [Source sample reporting](https://github.com/mlichvar/chrony/blob/120dfb8b36b942c31ddfc0220ca1475159ac5031/sourcestats.c).

The implementation decision is to add a bounded protected publisher at the
authenticated good-measurement boundary, retaining configured operator/TLS
identity, sample timing/error bounds and generation together. It must also
publish failures/clock transitions without replaying old observations. This
publisher has not been implemented; stock CSV or `Auth=Y` is not an interim
authority path. Strict certificate bootstrap, confinement, durable history
and final effect-time revalidation remain open integrations.

## Verification

Targeted checks passed on 2026-10-05 at
`D:\LumaOS-builds\g2-utc-keeper-targeted-20261005-01`.

- Build-input manifest SHA-256: `aae7aa8f47b091e6faa22f6f0f14a5bf0d64d0b0b4b42961a38c9d8f69275a0f`.
- Supplementary test-input manifest SHA-256: `0c03aca052887c77375862d887d66b3bc39972238853ae605f145678b55140bb`.
- Completed log SHA-256: `0ac5ea48ff197291fb5a842864b904a45bfca1639508ea9dab558195038e202c`.
- All 174 build inputs and three supplementary inputs matched the checkout.
- 101 ordinary Rust tests passed: 15 interval, three fixed-policy, 18 keeper
  lifecycle and 65 Admin regressions. Keeper cases include acquisition/replay,
  re-aging, unavailable/quorum states, explicit reacquisition, every epoch
  field, leap ambiguity, suspend, steps/regression, history and overflow.
- Ten Python wiring checks, formatting and the warnings-denied offline locked
  native build passed. Environment-dependent ignored fixtures were not run
  or counted as passing. No live NTS handshake or publisher fixture was run.

Checks used offline disposable containers, one CPU, at most 768 MiB and
D-backed build/cache/evidence storage. The audit downloaded public source
without executing it. No WSL settings, host services/accounts, clock, TPM
ownership, firmware or disks were changed. No image, VM or LLM sweep ran.
