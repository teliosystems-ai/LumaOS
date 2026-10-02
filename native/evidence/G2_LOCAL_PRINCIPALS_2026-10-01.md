# Installation-scoped local principals - 2026-10-01

G2 remains **incomplete**. This implementation-first increment leaves WSL
memory, host accounts, TPM hardware and unrelated services unchanged. No VM,
model sweep or image build was started. Earlier uncommitted changes remain.

## Native integration

The installer now initializes a private local principal registry after creating
the two Unix human accounts. Both receive independent random 256-bit IDs under
a random installation namespace, generation 1 and an enabled flag. No field
assigns `Admin` or another role. The registry is bounded to 64 KiB/128 entries;
it accepts unique human UID/login/ID mappings and a closed versioned schema.
Creation requires a fresh 0700 directory and exclusive 0600 file creation,
followed by file and directory synchronization. Runtime missing state never
creates a new identity universe or resets a generation.

`principal.rs` captures a nonserializable account binding. It checks the private
registry and fixed local identity files, requires the exact local UID/login,
rejects duplicate UID/shadow records and unsupported home/shell mappings, and
hashes the current passwd/shadow entry in memory. Each account database is
bounded to 16 KiB and must be a singly linked, ordinary root-owned file under
a non-writable-by-others directory. Links, unsafe access, growth and metadata
changes during the read fail closed. Group-readable shadow is permitted as in
the packaged Ubuntu baseline; world-readable shadow is not.

Shadow bytes are held in the existing locked, nondumpable, wiped buffer, not
an owned plaintext String or Vec. The digest is an observation, not a password
verifier or bearer capability, and is not persisted/exported. PAM still performs
password/account authentication; parsing a shadow entry never substitutes for it.

`authentication.rs` captures this binding before the fixed PAM helper runs,
matches the returned UID afterwards, and revalidates it on every consumption
of the 30-second authenticated observation. Changed installation/principal
identity, generation, enabled state, account mapping or credentials deny use.
Any observed validation failure latches invalidation for the object's remaining
lifetime. A later account unlock cannot revive that object. The helper output
continues to report `product_admin_active=false` and `role_grant=false`; its
public diagnostic format is unchanged.

## Deliberate limits

This is installation-scoped identification and authentication binding, not
TPM-sealed Admin enrollment, role assignment, a capability service or complete
account lifecycle. The registry has no protected anti-rollback anchor. It does
not detect a privileged root replacing/restoring identical bytes between
observations, and it is not an atomic transaction across account/registry
writers. PAM policy is evaluated during authentication; the later recheck is
not another complete PAM exchange or a trusted-time service. Product effect
authorization must still use serialized current principal/grant state.

There is no public registry mutation/recovery API and no automatic migration
from an older image without this registry. Such installations fail this new
authentication path until a reviewed migration exists. Future account services
must update protected generations for disablement/replacement/recovery without
treating Unix UID reuse or a caller's role string as product identity authority.
No unknown account is automatically registered. Full-image testing of fresh
installation, GDM/PAM, reboot, updates, migration and account lifecycle is
deferred to the consolidated candidate sweep.

## Bounded development verification

Targeted checks select six principal tests, three ordinary authentication tests,
two packaging checks, six explicit real-PAM fixture modes and an offline native
build with warnings denied. The ordinary selection skips the isolated PAM test;
the dedicated fixture then executes that test explicitly. Its six modes cover
normal authentication, account lock, expired account, required password change,
nologin shell and substituted PAM policy. Normal mode also checks wrong/empty
passwords, unknown/root accounts, post-authentication credential locking,
persistent invalidation after unlock and authentication expiry.

The fixture owns one new UID-32001 account inside a fresh network-isolated
container and refuses existing fixture accounts. No host account is changed.
No TPM emulator is required for these targeted PAM checks. Rust tests use real
temporary files plus synthetic account records; they do not prove installed
image behavior. The full regression and all heavyweight acceptance are deferred.

Final evidence location: `D:\LumaOS-builds\g2-principal-targeted-20261001-02`.
The initial `-01` run passed but predates strengthened independent unsafe-file
assertions; it remains separate. The final run is capped at 768 MiB, one CPU
and 128 processes. Compiler artifacts are retained in the dedicated D-backed
volume `luma-g2-rust-targeted-cache-20261001` for reuse by future serialized
checks, rather than repeatedly rebuilding dependencies. Source snapshots and
logs remain on D:.

The final run **passed all nine selected ordinary Rust tests, six real-PAM
fixture modes, both packaging checks, formatting and the offline native build**.
The real-PAM test's initial ordinary-suite skip was explicitly resolved by the
six isolated invocations, not counted as a pass merely because it was skipped.
`git diff --check` passed. The full regression and image acceptance remain
deferred as requested.

- Final input-manifest SHA-256:
  `c83866f9832301cda0c837a49526e1d5e154c619a332f671f5d3f897588f022f`.
- Completed test-log SHA-256:
  `f2bde7afd16111a2aeb5ca1b4086563766d9cef34a899cd623e450061d23ed3d`.

Native Python tests were copied separately into the frozen tree. These changes
are not in the currently exported sequence-11 image and do not complete G2.
