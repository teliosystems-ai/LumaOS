# G2 laboratory skill registry admission

Status: bounded source checks passed on 2026-10-03. This checkpoint adds
read-only admission of one signed, image-owned skill registry. It does not
execute a skill, authorize an effect, qualify signing custody or complete G2.

The image assembler now creates or reuses a private laboratory Ed25519 skill
key in its separate key volume. It refuses a linked, exposed or non-owned key
and rejects reuse of the release public key. The future image root receives
only the skill public key, a signed closed registry and the existing workflow
template. The signed registry binds the template's exact SHA-256 bytes and the
three permitted descriptors: file read, deterministic calculation and artifact
write. Neither private key is copied into the image or build artifacts.

The native `skill-registry-status` command uses fixed image paths. It verifies
the laboratory signature, exact descriptor set, workflow digest and native
typed-DAG contract. It reports admission without running nodes or granting
capabilities. Verification assumes the installed image's verity-protected
immutable root; this command is not a verifier for attacker-writable
directories or a substitute for production custody.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-skill-registry-targeted-20261003-05`.

- Source snapshot manifest SHA-256: `786316426a1cb209384deb2ada5f0104fb13c3c84d3fd1a7cc57c7adefabb797`.
- Completed test log SHA-256: `642e507988a63fdd53fd4d6a74a8e4a76c4cc10a413d2efcfb8f9da3110c9e1d`.
- Two native registry tests, four native DAG tests, two assembler fixture tests,
  formatting and the offline native build with warnings denied passed. The
  tests include signature, trust-key, registry-byte and workflow substitution,
  linked inputs, distinct keys and private-key permission rejection.

The run used one CPU, 768 MiB memory with no extra swap, 128 PIDs and no
network. Its source snapshot and log are on D:, and its temporary Unix test
files used the D-backed Docker Linux filesystem. Failed diagnostic attempts
remain in earlier numbered D: evidence directories; only `-05` passed.

No OS image was rebuilt or booted for this checkpoint. The new package will be
present only in an image built from this source or later. Product Admin
governance of signers, protected production key custody, registry rotation and
revocation, descriptor-scoped handlers, effect-time grants, durable supervision
and the full file-to-artifact journey remain open.
