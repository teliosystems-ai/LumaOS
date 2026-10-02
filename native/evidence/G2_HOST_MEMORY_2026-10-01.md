# G2 VM host-memory admission - 2026-10-01

G2 remains **incomplete**. The source checkout was clean at commit `eb13a17`
when this continuation began. No new OS image was built or modified.

## Observed desktop result

The D-backed ext4 workspace successfully staged and read-back verified all
three inputs, including the exact sequence-11 desktop raw image:
`96f0083cf64e7d968992256da96f3ed9f1a24d1696ed6c5d8be7a72ca66e264b`.
Staging is not image acceptance. The third desktop attempt booted and passed
the tampered-bundle refusal without changing the target's initial digest, but
did not reach the real installer's destructive confirmation prompt.

A WSL progress request returned `Wsl/Service/0x8007274c`. A later minimal
Ubuntu command succeeded, followed by bounded read-only diagnostics. Around
14:23 UTC these showed 7,847 MiB total, 20 MiB available and 556 MiB swap used;
the 6 GiB QEMU guest was active alongside unrelated host services. Swap usage
is a host-wide observation, not evidence that this VM used swap. Some processes
were waiting on pages; this does not by itself identify the original I/O-error
cause or prove physical disk failure.

Only container `luma-g2-desktop-linux-vm-20261001-01` was stopped. The stop
completed successfully; the following host observation showed 7,101 MiB
available. No unrelated services, WSL settings, physical disks or firmware were
changed. The run's target disk, NVRAM and software-TPM volumes remain intact.
This was not a clean guest-shutdown acceptance pass and the failed disk must
not be reused for fresh-install qualification.

The retained queue reports timeout waiting for `Type exactly: ERASE
LUMA-VM-TARGET`, exits 1, and never starts its conditional model test:
`D:\LumaOS-builds\g2-desktop-linux-queue-20261001-01\run.log`.
Completed queue log SHA-256:
`8623754b4038010cff20b4dc82d83814da5e4df9b7436b7b40362a74ad998497`.
The named workspace and TPM volume locations remain those in the
[workspace checkpoint](G2_VM_LINUX_WORKSPACE_2026-10-01.md). Private disks,
NVRAM, TPM state and backing-store contents must not be published.

A subsequent read-only retained-volume check found `failure.json` with
`stage=install`, no completed stages and no captured guest diagnostics. There
is no passing `result.json` and no model-run directory. The target qcow2 remains
197,120 bytes. Public metadata and log digests are recorded in the test
directory's `retained-run.log`; the dedicated daemon lists no running job after
the stop. This confirms retained failure, not storage-integrity qualification.

## Source safeguard and verification

`native/image/vm_memory.py` performs a bounded, read-only observation of the
kernel's `MemTotal` and `MemAvailable`. Missing, duplicate, malformed or
inconsistent values refuse admission. Only the existing integer 4096/6144 MiB
guest fixtures are accepted; available RAM must cover the full guest plus
2 GiB for QEMU/TCG, host activity and cache headroom. Swap never adds capacity.
The shared `VM` constructor invokes this before creating stage state,
provisioning a software TPM or starting QEMU, and logs an admitted observation.

This is not an atomic reservation, cgroup-limit check, concurrent-job
coordinator or proof against OOM. It does not change the signed image or patch
the frozen failed harness. New runs require a new source snapshot and fresh
virtual target/TPM state.

All **127 native Linux Python tests passed**, with warnings treated as errors,
including six new host-memory tests. A real read-only host probe then refused
a 6 GiB launch: 6,204,866,560 bytes available against 6,442,450,944 guest bytes
plus 2,147,483,648 reserve bytes. No VM was launched by the probe. Rust was
unchanged and not retested in this continuation.

Evidence: `D:\LumaOS-builds\g2-host-memory-tests-20261001-01`.

- Frozen build-input manifest SHA-256:
  `6f02b70b1d04c24e64983b59226e6a4a13158d2968d6b41cd2f3615b8f78cefc`.
- Completed test log SHA-256:
  `8e65fd2eb6e2f6aeb6b65006692e11cd905df3077af0e592d5bcc0d2a8e2d9d1`.

Native tests are copied separately into that frozen source tree. Passing these
tests does not resolve desktop login, model inference, production Admin or
other G2 implementation/qualification requirements.

## Next image-level execution

The current 8 GiB WSL limit cannot provide the required 8 GiB *available* for
this 6 GiB fixture. Use the separate adequately provisioned native Ubuntu host,
or obtain approval for a WSL-memory change and planned restart after reviewing
Windows memory availability. A possible 10 GiB limit is not an automatic pass:
recheck actual available memory, container limits and D-backed storage first.
No such host change has been made. Keep the existing image and all failed
evidence; start a new frozen desktop fixture, then the 4B suite only after its
success. Later guest-source fixes still require a new image rebuild.
