# Native OS release trust and update lifecycle

This describes the native source implementation, not a production signing
ceremony or an installed-image qualification. Model catalogs, model packs,
certificates and skill registries have separate signing purposes; an OS release
key cannot approve them.

## Public trust and custody

The existing Admin TPM journal reconstructs the public release trust, monotonic
admission floor, acknowledged release and exact pending/retained identities.
No extra TPM namespace or private signing key is introduced. Configuration,
public receipts and command files are inert inputs, not capabilities.

The immutable public root is `/usr/share/luma-os/release.pub` for laboratory
releases or `/usr/share/luma-os/production-release-root.pub` for production.
Root signatures cover canonical recursively sorted JSON. Release signatures
cover the original exact manifest bytes, not a reserialized equivalent.
Production roots cannot also be delegated release signing keys. Public trust
versions increase exactly; historical key IDs/public values cannot be reused
or removed, and revocation cannot be reversed. A trust/key validity interval
is finite and at most 366 days. The whole protected UTC interval must fit the
applicable validity periods.

`scripts/release_trust_ceremony.py` prepares and verifies public proposals.
It accepts no private key, does not sign, and cannot authorize deployment.
Its `prepare-trust`, `assemble-trust`, `prepare-initialize` and `prepare-update`
subcommands expose their exact required arguments with `--help`. Outputs must
be new files; a failed or prior output is never silently overwritten. Actual
production signatures must come from approved external custody.

## Reviewed native transitions

Use `sudo luma-admin-control admin-release-command LOGIN REQUEST FILE` to review
one complete JSON command below, then repeat the exact request/input with
`--commit REVIEW-SHA256`. Stage bounded public inputs under `/run/luma-admin`;
the command captures a regular, nonsymlink file of at most 131072 bytes before
authentication and refuses duplicate/unknown fields and trailing JSON. It
accepts only these four release transitions, including public proposals emitted
by `scripts/release_trust_ceremony.py`. The existing `admin-catalog` command
remains restricted to finite role assignment/grant governance. Fresh original
Admin identity, current protected UTC, semantic replay and the hardware-selected
journal are checked at the commit boundaries. Input JSON and review digests
are not authority, signatures or replacement immutable roots.

| Action | Required state and outcome |
| --- | --- |
| `publish_release_trust` | Exact prior trust version, independently provisioned root and root-authorized public bundle; preserves floor and release identities. |
| `initialize_release` | Anchored trust with a virgin floor and no acknowledged/pending/retained release; binds the running immutable identity and signed release. Cannot reset existing authority. |
| `prepare_release` | Exact floor, prior acknowledged release, trust version/digest and signed candidate; unchanged environment, edition and geometry; candidate sequence strictly increases. Advances the floor before image writes. |
| `resolve_release` | Exact pending candidate digest and reviewed `confirmed`, `fallback` or `abandoned` outcome. Never lowers the floor or infers a successful write from missing evidence. |

The machine updater requires the exact prepared candidate. It rechecks current
trust, revocation, protected UTC and journal identity around bounded writes,
readback and EFI publication. Interrupted/uncertain outcomes remain pending;
another candidate cannot replace them. The operation lock excludes concurrent
machine update/health operations.

Health verification compares immutable release metadata, signed UKI parameters
and actual dm-verity geometry/device bindings. A stable acknowledged boot and
exact known prior-slot fallback do not require online UTC. Confirmation of a
new candidate does. Machine health can bless the exact trial or select its
known prior slot, but cannot impersonate the Admin journal writer. Fresh Admin
resolution is required before another governed update.

Deleting an enrollment/anchor file while retained enrollment or the fixed Luma
TPM handles remain cannot enable the static laboratory-key fallback.

## Approved initial staging and target recovery

The owner approved immutable signed offline staging followed by first-boot
activation and a separate repair-only session capped at thirty minutes.
[ADR 0012](../docs/adr/0012-production-staging-repair-and-skill-trust.md) records
the scope and security boundaries. These approvals are not qualification evidence.

Before initial production writes, `release-trust.json` beside the release bundle
must verify against the independently provisioned immutable production public
root; the exact manifest signature and artifact hashes are also checked. The
installer retains signed evidence in `/var/lib/luma-os/staged-release.json`,
leaves the model disabled and creates an uncounted first boot. There is no health
acknowledgement, timed grant or protected worker/effect authority from staging.

After enrollment, original-Admin bootstrap and authenticated UTC delivery, use
`luma-admin-control admin-release-trust-stage LOGIN REQUEST`, review its digest,
and repeat with `--commit REVIEW`. Then separately review and commit
`admin-release-activate LOGIN REQUEST`. Both consume the exact retained signed
evidence and existing hardware-selected journal. Neither accepts a replacement
root. An approximate seed or wall clock cannot activate authority. The broker
and model can be started explicitly only after successful activation. During an
unresolved trial update, protected account/grant/skill changes remain unavailable
until fresh Admin resolution acknowledges the running candidate; exact release
resolution and candidate health remain possible.

The recovery adapter mints private typed image/target contexts from exact
live-media and selected disk/mount identities, loads only that target's sealed
credentials and principal/history state, and preserves the existing TPM owner,
handles and approved PCR policy. Arbitrary directories, serialized contexts,
chroot execution, media-journal substitution and new clock authority are not
acceptable substitutes. Keeper processes receive neither target secrets
nor TPM credentials. Manual unlock/export/model-disable stays available
independently of models and online UTC.

The fixed `luma-recovery-control` launcher exposes only `utc-seed`,
`utc-reacquire`, `repair-a` and `repair-b`. Seed proposals use
`utc-seed DISK /run/luma-recovery-input/seed.json`; delivery repeats the exact
proposal with `--commit KEEPER-INSTANCE REVIEW`. Reacquisition follows the same
review/delivery pattern and still requires a new independent seed. Repair uses
`repair-a|repair-b DISK /run/luma-recovery-bundle`, with explicit local review and
disk confirmation. Inputs must be operator-staged at these confined locations
or `/media/luma`; the launcher is not a general shell or directory authority.

The target data mount remains read-only with journal replay disabled. Existing
original-Admin offline custody, target TPM epoch/head/principals/history and
release trust/floor are rechecked around each bounded write/readback and EFI
publication. The repair lifetime cannot renew, serialize or become a PAM/export
session. Ordinary Admin/seed-control thirty-second limits remain unchanged.

## Still required before production deployment

Production public roots/signatures and actual custody, final image builds,
installed services/confinement, power-loss/interruption and physical firmware/
TPM qualification remain separate evidence. General populated schema/principal
migration and production model catalog/pack governance are not completed by this
OS-release implementation. The separate native skill-registry adapter and its
public-input packaging are described in [SKILL_TRUST.md](SKILL_TRUST.md).
