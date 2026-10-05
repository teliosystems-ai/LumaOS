# G2 UTC measurement receiver source checkpoint

On 2026-10-05, the native Linux measurement receiver and bounded targeted checks
passed on D-backed storage. This completes a measurement-stream boundary, **not
the trusted UTC service, Admin, workflows or G2**. The new module has no product
listener, CLI, persisted authority or grant API. No host clocks, accounts, TPM
ownership, WSL settings or devices were changed. No final image or heavyweight
VM/model sweep was run.

## Implemented boundary

`rust/luma-platform/src/utc_receiver.rs` accepts an already-provisioned Unix
datagram socket and an expected producer epoch/process from a future protected
composition root. It checks credentials on every datagram, not socket-creation
credentials. Linux provides these through `SO_PASSCRED`/`SCM_CREDENTIALS`;
privileged credential overrides mean that an approved confinement policy is
still necessary. [Linux Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html).

A pidfd and bounded process observations pin the observed lifetime, executable
device/inode, credentials, profile, cgroup and security-control values. A pidfd
supports exit observation without depending on a reusable numeric PID.
[Linux pidfd interface](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
Unchanged observations do **not** approve the executable, its configuration or
its confinement. Same-image re-execution still requires independent lifecycle
generation/notification integration. Denied process observations refuse rather
than selecting a weaker fallback.

The receiver bounds frame/control sizes and drain work to eight rounds within
100 ms. It rejects oversized/truncated frames, unexpected or duplicate ancillary
data, wrong senders, changed epochs, replay, stale/future captures, sample
re-aging, restored lost samples and observed clock discontinuities. Every
delivered descriptor is closed before rejecting descriptor-passing messages,
including a truncated-control-buffer case. Received descriptors are installed
in the recipient; close-on-exec and truncation handling are therefore explicit.
[Linux receive interface](https://man7.org/linux/man-pages/man2/recvmsg.2.html),
[descriptor-passing semantics](https://man7.org/linux/man-pages/man7/unix.7.html).

It rechecks the producer and live clocks before returning a complete validated
round. Any receive/validation error fences the instance; no data returns no
cached estimate. Kernel REALTIME is a coordinate, not an authenticated UTC
estimate. This module does not qualify a clock-rate bound, establish quorum
authority, restore protected history or make Admin assignments available.

## Executed evidence

The final run is `D:\LumaOS-builds\g2-utc-receiver-targeted-20261005-02`.
All 185 source-manifest entries and four supplementary test inputs were compared
with current repository bytes after the run and matched. Formatting, the locked
offline native build and tests with Rust warnings denied passed.

- 131 selected ordinary Rust tests across receiver, UTC bounds/policy/keeper/
  codec, Admin, authentication/principal and workflow modules.
- Two explicitly selected integration fixtures: a real Linux datagram fixture
  containing 13 cases, and interoperability with the unchanged retained C frame.
  There were 133 passing Rust test invocations in total.
- 19 Python checks, including both pinned-upstream-source checks; none skipped.

The 13 kernel cases cover one/two messages, source invalidation, wrong PID,
producer death, same-PID executable change, replay, sample re-aging, descriptor
passing, truncated descriptor control data, oversized payload, truncated payload
and queue flooding. Synthetic clock/sample data are confined to test helpers;
they are not NTS traffic or UTC authority. The fixture terminates/reaps only its
own child processes and checks that rejected descriptor traffic does not leak
received descriptors.

The cached compiler container was
`sha256:69fd23acb13ac259eb28e84bad65c65756e53d3980085f8275ecb8fb94d391c0`.
It had one CPU, a 768-MiB memory and memory-plus-swap ceiling, a D-backed Linux
target volume, no network, all capabilities dropped and no host devices or
Docker socket. Docker's root was `/mnt/luma-build/docker`. The pinned chrony
source and C frame were reused from the
[publisher checkpoint](G2_UTC_PUBLISHER_2026-10-05.md); no upstream chronyd/C
rebuild was performed in this batch.

| Retained artifact | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `ae6374097df55f9fd384023f6071536398c7644915017a0e5492f47419a533db` |
| `test-inputs.sha256` | `c289bc565271c9bc4afd499f1ad8edaed842cfc6dee28a2d74ea6963d51d158e` |
| `test.log` | `148aa9800a36ce36f08461757eee95e98696ff8b5cb858a856e45b5311ac4699` |
| Reused `c-frame.bin` | `19b03cacb85a11149bd5d3446044d206880d2a26f78384520d6f0ec8e2a14bdd` |

The earlier receiver trial `01` is retained. It passed a narrower implementation
with 12 kernel cases and had two skipped Python pinned-source checks. Final
trial `02` adds the executable-change/return-boundary checks, supplies the pinned
source inputs and reruns the selected checks. Its unchanged captured inputs
support this checkpoint; the hashes are evidence bindings, not release signatures.

To select the kernel fixture explicitly inside the isolated Linux test tools:

```sh
cargo test --offline --locked utc_receiver::tests::kernel_datagram_boundary -- --ignored --exact --nocapture --test-threads=1
```

Other ignored PAM/TPM/IPC fixtures, the complete workflow CLI fault matrix,
remote/full CI, live provider/NTS attacks and installed AppArmor/service
enforcement were **not** executed by this batch. It does not qualify an installed
trusted-time service or any physical recovery/security boundary.

## Remaining integration and closure

The protected supervisor must approve immutable producer code/configuration and
confinement, provision sockets, enforce credential-forgery/ptrace restrictions,
bind lifecycle/resume/source-clock notifications and explicitly map the producer
generation to the keeper's distinct reviewed reacquisition generation. Protected
time history, reviewed bootstrap/recovery and final-boundary authority checks
remain open. Source observations alone cannot prove unreported transitions absent.

The experimental binary telemetry fixture does not supersede the frozen internal
control transport. ADR 0002 requires transport review/adaptation before a product
endpoint is enabled. No deployed listener or approval is claimed here.

Admin still requires finite assignment/revocation, current effect grants,
principal/account recovery and signing custody lifecycle. Workflows still require
governed supervisor/service delivery, principal-bound resources, effect-time
identity/lease checks, trusted timestamps and broader scheduling/reconciliation/
schema/retention integration. Installer, boot, update and recovery must consume
the integrated implementation before the consolidated image and separate native
Ubuntu qualification. See the [software completion register](../G2_SOFTWARE_STATUS.md)
and [implementation-first sequence](../G2_IMPLEMENTATION_FIRST.md).
