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

The existing original-Admin `admin-catalog` review/commit path accepts these
closed commands. Fresh identity, current protected UTC, semantic replay and
the hardware-selected journal are checked at the commit boundaries.

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

## Still required before production deployment

Production initial installation and target-mounted governed repair are not
implemented end to end. They remain fail-closed, not qualified capabilities.
The owner must choose the initial installation policy and a separately bounded
repair-custody session before their coordinated implementation:

- Either authenticated UTC before any production installation write, or explicit
  approval of immutable signed offline staging followed by first-boot
  Admin/TPM/UTC/trust activation. A seed or wall clock cannot authorize activation.
- A finite repair session suitable for multi-GiB write/readback. The existing
  custody bound is 30 seconds; the export-only 30-minute approval does not cover
  repair. A proposed separate 30-minute session must retain continuous
  target/TPM/journal/custody/UTC checks and cannot renew automatically.

The recovery adapter must mint private typed image/target contexts from exact
live-media and selected disk/mount identities, load only that target's sealed
credentials and principal/history state, and preserve the existing TPM owner,
handles and approved PCR policy. Arbitrary directories, serialized contexts,
chroot execution, media-journal substitution and new clock authority are not
acceptable substitutes. Keeper processes must receive neither target secrets
nor TPM credentials. Manual unlock/export/model-disable must stay available
independently of models and online UTC.

Production public roots/signatures and actual custody, final image builds,
installed services/confinement, power-loss/interruption and physical firmware/
TPM qualification remain separate evidence. General populated schema/principal
migration and production model/skill governance are not completed by this
OS-release implementation.
