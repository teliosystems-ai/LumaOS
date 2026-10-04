# G2 local Admin catalog service boundary

The native source now provides a local catalog daemon and an unprivileged human
client above the existing reviewed bootstrap and TPM-backed catalog. This is
an implementation increment, not completion of the Admin lifecycle or G2.
No new OS image was built and no installed service acceptance is claimed.

## Implemented scope

The fixed `/run/luma-governance/control.sock` has a root-owned 0711 parent and
root:1001 0660 socket. The daemon accepts only kernel-observed UID 1001, not
caller-supplied identity, root privilege, worker credentials or role text.
Linux [SO_PEERCRED semantics](https://man7.org/linux/man-pages/man7/unix.7.html)
bind the observed credentials at connection establishment; the positive fixture
therefore drops its client UID before connecting, rather than using a socketpair
created as root. Hostile OS root remains outside the supported trust boundary.

Each request separately authenticates the named human through the fixed PAM
helper, checks that its UID matches the kernel peer, and revalidates the
installation/principal/account observation through the existing governance
adapter. There is no serialized session or bearer-authority constructor.
The API accepts only status, activity registration and role definition; bootstrap,
assignment/revocation, principal mutation, signing, shell and resource effects
are not exposed. Review/commit and historical replay retain the existing exact
request/command/head bindings and uncertain-outcome fences.

Metadata is closed JSON, at most 16 KiB. The password is a separate 1025-byte
binary frame read directly into the locked, nondumpable, wiped private buffer.
It is never JSON, argv, environment or an exception reply. Terminal input is
masked and protected in the human client; the helper keeps its existing private
input protections. This does not claim all PAM allocations or kernel socket
buffers are locked. Authentication/execution failures return a generic denial;
framing errors close the connection without serializing raw inputs or errors.

Header, metadata and credential share one two-second monotonic input deadline.
Replies are bounded to 1 MiB. Each request runs in one fixed executable child,
with a cleared environment and a 60-second parent deadline. Timeout kills and
reaps only that unreaped child's own process group. Normal completed children
are detached from the guard before their PIDs can be reused. A timeout/lost
reply never automatically repeats a TPM mutation or removes a pending fence.

The source unit runs in the named enforced AppArmor profile with no-new-privileges,
seccomp, AF_UNIX only, a closed device policy, CAP_CHOWN only, 256 MiB memory,
zero swap and 16 tasks. Writable paths are limited to Admin journal/event and
volatile runtime locations; enrollment credentials and principal metadata are
read-only, and model/artifact/boot/device effects are denied. The native parent
and request child refuse startup unless the expected enforced profile, cgroup,
memory/swap/task limits, seccomp and capability ceiling are observed. There is
no unconfined fallback. The unit has a bootstrap-file startup condition but
every request independently verifies actual bootstrap authority. It neither
enrolls nor activates Admin automatically and is not a boot-health dependency.

## Targeted verification

Checks passed on 2026-10-04 at
`D:\LumaOS-builds\g2-admin-service-targeted-20261004-02`.

- Build-input manifest SHA-256: `3a0136d373c0c2ddb42c2064b3b21cc48884b9c62803c323373309a17cb021d5`.
- Supplementary test-input manifest SHA-256: `74ade73a2e4db51b1e75448cdf53829897f7dec751c1c6bab03e51f92e42699c`.
- Completed log SHA-256: `d4260331e8ba2aea79fcae6c6e36c706aea1c3e04cdc23e4132382e39f20d1b8`.
- All 170 build inputs and five supplementary inputs matched the checkout after
  execution. The earlier passing `-01` evidence remains retained separately.
- 53 ordinary Rust tests passed: seven service, 22 governance, four catalog,
  16 journal and four authentication tests. They cover closed requests, root-peer
  refusal before credentials/execution, size/deadline bounds, response binding,
  confinement refusals and owned-child cleanup, plus existing semantic/journal
  regressions. Four environment-dependent tests were excluded from those counts.
- The explicitly selected ignored kernel-peer fixture passed with three actual
  UID-1001 child connections: success, generic denial and truncated credential.
  Its executor is a fixture, not real PAM or a TPM transaction. Its permissive
  temporary test socket is not the production socket policy.
- Eight source-wiring checks, Rust formatting, warnings-denied offline locked
  build, assembler syntax and updated CI-runner Bash syntax passed.
- Cached Ubuntu image AppArmor parser 4.0.1 compiled the profile with `-Q -K`
  (no kernel load/cache write); systemd 255.4 verified the unit. These are syntax
  checks, not enforcement or an executed service. An initial WSL-host unit check
  could not resolve the product executable and was not counted as a pass.
- The repeatable native runner now invokes the kernel-peer fixture and hashes
  the new unit/profile. Its full execution and remote CI were not run here.

Tests used D-backed snapshots/cache/evidence, one CPU, at most 768 MiB and no
network, host TPM, Docker socket or extra privileges. Policy parsing used a
256 MiB disposable cached-root container. WSL settings, unrelated processes and
host services/policies were unchanged. No image, VM or model sweep ran.

## Still required

On the consolidated installed image, evaluate real client terminal input,
PAM/NSS/helper execution, protected buffer/unseal behavior under actual
AppArmor/seccomp/device/cgroup enforcement, TPM mutation/replay, stale principal
and credentials, service restart/timeout and interruption recovery. Validate
the actual policy against the packaged boot/update/fallback configuration;
syntax success cannot prove it permits the supported complete flow.

Trusted UTC must be live and reviewed; neither TPM powered-time nor an unchecked
system clock satisfies expiry. Time-bound assignments/revocation, resource/effect
grants, governed principal/bootstrap and credential recovery, full enrollment
reconciliation, signing/custody lifecycle and the other implementation-first
work packages remain open. Production custody approvals and physical qualification
remain separate. This checkpoint closes none of those acceptance requirements.
