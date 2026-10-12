# Finite generated-code runtime

The native runtime executes only static Linux amd64 ELF payloads in a fixed KVM
guest. Host-side code treats the executable as data. Python, shell scripts,
dynamic ELF files, other architectures, caller-supplied QEMU options and TCG
fallback are not supported. The manual desktop and other typed skills do not
depend on KVM availability.

## Review and execute

Use the installed `/usr/libexec/luma-os/prepare_generated_request.py` to encode
an existing static executable and optional input into the closed canonical
request. This helper neither compiles nor executes it. It checks bounded,
single-link inputs and emits the exact JSON bytes accepted by the controller.
Review through `granted-run generated-review REQUEST-JSON`, then obtain a finite
grant for the returned exact `GeneratedCode` selector and `generated.execute`
action. Execute through `granted-run generated-execute LOGIN GRANT REQUEST-JSON`.
An altered request requires another review and a matching grant.

The original PAM session stays private in the confined client. A nonce-bound
broker connection joins its current account, protected UTC, grant and effect
checks to the exact leased helper generation. Losing that authority cancels the
controller and revokes the held lease; capacity remains charged until observed
cgroup drainage. Normal completion requires an authenticated acknowledgment for
that exact released generation. A socket close, caller boolean or unit name
alone is not a release or output-provenance receipt.

## Fixed boundary

The image packages its actual kernel, static guest init, initrd, QEMU identity,
runner and runtime manifest before sealing. Payload and input use sealed
anonymous descriptors. The QEMU process drops capabilities and host credentials,
has no NIC, host filesystem mount, writable disk, TPM or caller-selected device,
and runs under the separate generated-QEMU AppArmor profile. Its `/dev/kvm`
access must match the installed identity and permissions.

Guest payloads run with UID/GID 1000, no supplementary groups or capabilities,
`no_new_privs`, and a syscall allowlist. Filesystem opening, network sockets,
forking, mounts, tracing and further execution are refused. The guest has
128 MiB and one vCPU; each payload has a 32 MiB address-space limit, one CPU
second, a three-second wall limit, and at most 32 KiB each of stdout and stderr.
Executable input is bounded to 1 MiB and stdin to 64 KiB.

The trusted guest init emits one bounded receipt. The host validates its exact
runtime/input digests and status, then binds it to the broker's committed lease
and all shared output-domain epochs before publishing it. Guest stdout is data,
including text that resembles receipt framing; it cannot manufacture authority.

## Evidence limits

The disposable KVM corpus exercises actual guest execution, capability loss,
prohibited syscalls, forged output, memory/output/wall limits and abnormal exit.
That corpus does not load installed AppArmor policy or exercise the original
PAM-to-broker handoff. Parser, state-machine and signature tests have their own
scopes. Final-image confinement, end-to-end authorization/cancellation, pressure,
recovery and physical-platform qualification remain required; none is inferred
from a direct guest test.
