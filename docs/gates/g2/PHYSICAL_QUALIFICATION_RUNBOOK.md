# G2 physical Ubuntu qualification runbook

## Purpose and evidence boundary

This runbook turns the open G2 physical-platform blockers into an operator
handoff. It covers destructive installation and boot evidence, hardware-bound
security controls, encryption recovery, lifecycle and power-loss testing on
the exact retained Ubuntu tuples.

The repository does not currently contain a production installer, signed
Ubuntu image, signed production model catalog, production signing keys, or a
privileged Linux enforcement service. This runbook therefore defines the lab,
authorization, execution and evidence contract; it does not claim that those
missing implementations or their acceptance tests have passed.

Ubuntu WSL is a useful development lane for source tests, schema validation,
the non-destructive collector and userspace preflight. It cannot prove UEFI,
Secure Boot, a physical disk install, dm-verity, LUKS recovery after TPM loss,
native suspend/resume, device reset, IOMMU isolation or physical power loss.
Only native execution on the designated physical boards can close those rows.

The requirements-defined G2 exit still requires `T01` through `T16`, the
applicable `T27` through `T30`, `T33`, `T40`, `T45` through `T51`, and `T62`,
plus the complete vertical workflow on both physical A1 boards. An inventory
record or a successful boot is preparation, not gate closure.

## What the environment owner must provide

The following items require an explicit decision, physical access, or custody
outside the repository. One provided native Ubuntu system can advance the work,
but G2 cannot close until both E1 and E2 have passed.

| Item | E1 compact board | E2 mainstream board | Required owner action |
| --- | --- | --- | --- |
| Physical identity | One dedicated x86-64 physical machine; 16 GiB class; supported CPU plus one GPU or NPU path | A second, independent x86-64 physical machine; 32-64 GiB; a different retained accelerator path | Designate the boards in writing. A VM, WSL guest, or two boots of one machine do not count as two boards. |
| Ubuntu baseline | Native Ubuntu 24.04 LTS amd64 | Native Ubuntu 24.04 LTS amd64 | Permit native boot and package/image inspection. Ubuntu 26.04 is a separate E8 evaluation until promoted. |
| Destructive storage | A separately identified disposable disk with no retained data | A separately identified disposable disk with no retained data | Supply the raw serial/WWN to the authorized operator outside Git and approve erasure of only that disk. |
| Recovery media | Signed, offline recovery media plus a separate evidence destination | Same | Permit boot-order changes and recovery-media boot. Evidence storage must not be the disk being destroyed. |
| Firmware access | UEFI setup access; current firmware recovery package; ability to inspect/enroll/restore Secure Boot state | Same | Authorize only the approved key-enrollment procedure and retain a firmware recovery path. |
| Power interruption | Controllable AC/battery isolation or a lab power controller; serial/remote-console capture | Same | Authorize forced interruption only on the disposable fixture. Do not run on a machine containing irreplaceable data. |
| Encryption fixture | TPM 2.0 where the retained tuple uses TPM enrollment; offline LUKS2 recovery credential | Same | Authorize TPM-unavailable recovery simulation. A motherboard replacement may be represented by disabling/withholding the enrolled TPM only if the approved procedure says so. |
| Model assets | Signed, legally approved 4-6B pack and exact runtime tuple; Qwen3-4B is the current development recommendation | Signed compact pack plus every additional shipped mainstream profile | Approve licenses/redistribution and transfer the offline bundle through the signing-custody process. Unsigned development weights cannot close `T02`. |
| Test operator access | Local console plus an independent evidence observer | Same | Name the platform operator and QA witness. Security rows also require independent security review. |

Before scheduling a destructive run, the environment owner must answer and
sign the following five decisions:

1. **Board designation:** identify which physical machine is E1 and which is
   E2, including firmware version and the pseudonymous inventory identity.
2. **Disk destruction:** state the exact raw serial/WWN, capacity and current
   contents of the disposable target; confirm that its loss is acceptable.
3. **Firmware changes:** approve the exact Secure Boot enrollment/restoration
   procedure and confirm that recovery media and firmware recovery are tested.
4. **Credential custody:** name the human custodians and approved protected
   stores for lab signing keys and LUKS recovery credentials. Do not provide a
   private key or recovery secret in an issue, chat, repository, screenshot or
   model prompt.
5. **Fault injection:** authorize planned forced reboots, power cuts, TPM
   unavailability, driver mismatch, resource exhaustion and tamper tests on the
   disposable fixtures.

## Non-destructive inventory on WSL and native Ubuntu

The authoritative host-fact collector is
`scripts/collect_g2_host.py`. It uses a fixed shell-free allowlist of read-only
commands, never invokes `sudo`, never chooses a disk and labels every disk
`unclassified-never-auto-selected`. The stable output contract is
`schemas/g2-host-inventory.schema.json`.

Command names are not resolved through ambient `PATH`. The collector resolves
them only under `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`; WSL may additionally
use `/usr/lib/wsl/lib` for `nvidia-smi` only. It rejects a resolved executable or
ancestor that is not root-owned or is group/world-writable, executes the
absolute path under a minimal non-inherited environment, and records its
SHA-256 plus ownership/mode provenance. A
rejected or failed probe cannot assert Secure Boot or another positive state.

Accelerator visibility is vendor-neutral: bounded, non-recursive,
no-symlink scans cover DRM render nodes, `/dev/accel` nodes and WSL `/dev/dxg`,
while successful trusted `nvidia-smi` execution adds NVIDIA model, driver and
memory observations. Device visibility alone does not prove driver support,
memory capacity, isolation, reset behavior or model-runtime compatibility.

Run it first in the current Ubuntu WSL development lane:

```sh
python3 scripts/collect_g2_host.py \
  --environment-id DEV-WSL-UBUNTU \
  --output /path/outside-the-repository/dev-wsl-host-inventory.json
```

The WSL record must report `system.environment_kind` as `wsl2`,
`system.native_ubuntu_24_04_amd64_candidate` as `false`, and
`evidence_boundary.gate_closing` as `false`.

Run it again, without `sudo`, after booting each physical candidate:

```sh
python3 scripts/collect_g2_host.py \
  --environment-id E1 \
  --require-native-ubuntu-24.04 \
  --output /evidence/E1/preinstall-host-inventory.json

python3 scripts/collect_g2_host.py \
  --environment-id E2 \
  --require-native-ubuntu-24.04 \
  --output /evidence/E2/preinstall-host-inventory.json
```

Status `3` means the host was collected but did not satisfy the native Ubuntu
24.04 amd64 candidate check. Probe failures are retained as findings rather
than silently assumed to pass. Even a candidate result remains non-closing
until the procedures below pass.

By default, disk serials, WWNs and accelerator identifiers are replaced with
pseudonymous SHA-256 comparison values. A disk digest is hardware-backed only
when the device reported a WWN or serial; the explicitly labeled path/kernel
name fallback can change across boots and must never authorize destruction.
The host digest is derived from `/etc/machine-id`, which may be cloned or reset:
it binds the record to the observed OS installation, not cryptographically to a
physical board. Physical designation still requires the firmware/DMI record,
current observation and human-controlled raw inventory. The lab custodian may use
`--include-sensitive-identifiers` for the private evidence copy used to approve
the target, but that copy must remain in the protected evidence store and out
of Git. The redacted record and its digest can be attached to the gate record.

## Stop conditions before any destructive command

The operator stops before disk mutation if any of these conditions is true:

- the board is not the designated E1 or E2 physical machine;
- the selected raw disk serial/WWN does not exactly match the signed
  destruction authorization;
- the disk contains mounted filesystems, active swap, an active LVM/MD member,
  the running root, the evidence destination, or data not explicitly released;
- capacity is below the generated partition/model/storage plan;
- the release image, model catalog, runtime tuple, recovery media or their
  signatures/digests differ from the approved release record;
- the firmware recovery path or LUKS recovery credential is unavailable;
- Secure Boot state, kernel/driver tuple, architecture or required device
  support differs from the retained support tuple;
- the serial/remote console or evidence clock is unavailable for a planned
  interruption test; or
- either the platform operator or QA witness withdraws approval.

An Admin may assign the finite platform, QA, release and security activities,
but the Admin role is not ambient disk authority and does not expose private
signing or recovery material to model-visible processes. Each destructive run
still requires a run-specific authorization bound to the board, disk identity,
image digest, operation, time window and named operators.

## Execution and evidence matrix

Every row produces a test record with the source requirement/test IDs, exact
environment and artifact tuple, preconditions, timestamps, commands or manual
steps, result, observations, raw-artifact digests, operator and reviewer. Valid
results are `pass`, `fail`, `blocked`, and `not_applicable`; a mandatory row
cannot be omitted.

### Installation, boot and encrypted recovery

| Run | Governing coverage | Execution | Required evidence | Pass criteria and owner |
| --- | --- | --- | --- | --- |
| P0 inventory freeze | `A001`, `A002`, `A108`, `T01` | Collect before-state inventory; compare raw target identity with the signed authorization; render the complete partition, A/B root, data, recovery and model-space plan without mutation. Attempt an unsupported architecture and an unselected disk in a controlled negative fixture. | Private raw inventory; redacted collector JSON; plan JSON; authorization digest; before block map; rejection logs. | Unsupported architecture is rejected before mutation; only the approved stable disk identity can progress; no unselected disk changes. Platform lead + QA witness. |
| P1 offline install | `A003`, `A006`, `A108`, `T01`, `T02`, `T48` | Physically disconnect all external network paths. Install the exact signed image and selected signed 4-6B profile to the disposable disk. Create the first user and administrator explicitly. | Image/catalog/runtime/signature digests; network-disconnect evidence; console transcript; after block map; created-principal audit with secrets redacted. | Exact selected disk only; capacity checks pass; no default/shared credential; baseline workflow succeeds offline from distributed assets. Platform + release + QA. |
| P2 model-independent recovery | `A004`, `A007`, `T03` | Remove or corrupt only the disposable model pack. Boot normal manual mode and recovery media; inspect disks, export a test file, repair the selected slot, disable the failing model, then shut down without inference. | Boot/recovery logs; exported-file pre/post digest; model-integrity rejection; repair record. | Kernel, desktop/manual controls, file access, export and clean shutdown remain available without a model response. QA. |
| P3 signed boot chain | `A005`, `A097`, `A101-A104`, `T04`, `T45`, `T46` | From a recoverable copy, separately alter the bootloader, UKI/kernel, initramfs and bound verity digest/root. Repeat for desktop and headless editions where shipped. | Public certificates; signed-manifest verification; TPM event log if applicable; `mokutil`, bootloader and journal output; tamper-case logs. | Every alteration is rejected or enters verified recovery; the installed tuple matches the approved Ubuntu/kernel/package release; no altered component reaches trusted service activation. Release + platform + security. |
| P4 inactive-slot update | `A095`, `A105`, `A106`, `A110`, `T04`, `T47`, `Q15` | Starting from slot A, write only inactive slot B. Interrupt each documented write/verify/activation boundary. Inject boot and essential-service health failures. Repeat B-to-A. | Slot maps and digests before/after; trial counter/monotonic-anchor records; serial console; power-controller timestamps; committed-data digests. | Active slot is never written; previous root remains bootable; at most three unsuccessful trial boots occur before fallback; permanent activation requires essential health and never a model response; committed data remains readable. Platform + QA. |
| P5 LUKS recovery | `A107`, `A108`, `T48` | Verify ext4 data-on-LUKS2 layout. Make TPM enrollment unavailable using the approved method; unlock with the offline recovery credential; export data; restore normal enrollment. Exercise an invalid credential as a negative case. | LUKS metadata digest with key material redacted; enrollment/recovery logs; custody event IDs; file digests; restored-state inventory. | Recovery succeeds independently of inference; invalid credentials fail closed; no secret appears in logs; selected disk and capacity remain exact. Two custodians + platform + QA. |
| P6 pinned offline rebuild | `A109`, `A110`, `T49` | Rebuild from the pinned repository/package lock with external network blocked. Substitute one package and test an expired repository policy. Attempt a live-root privileged package mutation from a worker. | Source/lock/SBOM/repository snapshot digests; build transcript; substitution/expiry rejection; root-integrity result. | Rebuild bytes meet the declared reproducibility rule; substituted/expired inputs are rejected; product updates use only the signed image flow; worker cannot mutate the live root. Release + QA. |

### Hardware security and confinement

| Run | Governing coverage | Execution | Required evidence | Pass criteria and owner |
| --- | --- | --- | --- | --- |
| S0 enforcement baseline | `A111-A116`, `T50-T51`, `T62` | Capture cgroup v2 controllers, AppArmor enforcement, seccomp policy, device ACLs, IOMMU groups, `/dev/kvm`, peer-credential transport and signed driver/runtime tuple. | Redacted host inventory; signed policy digests; kernel config/package origins; service unit and device-rule digests. | Every mandatory control is present and enforcing on the exact tuple. A disabled/permissive mandatory profile blocks certification. Security + platform. |
| S1 resource ceilings | `A024`, `A026`, `A028`, `A111`, `A112`, `T13`, `T15`, `T50`, `Q01`, `Q07` | Saturate CPU, IO, memory, PIDs, GPU/device memory and pinned/locked memory independently, then in the approved combined pressure matrix. | Per-second cgroup/device telemetry; OOM and pressure events; UI latency distributions; admission decisions; reserve accounting. | Each workload is bounded in its assigned domain; protected controls remain responsive; no host OOM; no accepted request exceeds its pool; estimator error is at most 10 percent with no underestimation beyond reserve. Systems + QA. |
| S2 device ownership and reset | `A027`, `A030`, `A116`, `A118`, `T16`, `T51` | Delay completion, cancel/revoke the lease, attempt early reuse, inject unknown/reset allocation state, attempt second-worker exclusive access, then change driver/firmware/runtime. | Allocation generations; device/reset logs; quarantine transitions; qualification-certificate state. | No allocation is reused before fencing; unknown state quarantines the domain; a second worker cannot acquire an exclusive device; dependency change revokes performance/cache qualification until retest. Systems + security. |
| S3 generated-code isolation | `A053`, `A081`, `A114`, `T29`, `T62` | In the retained KVM microVM or separately approved constrained runtime, attempt host filesystem escape, prohibited device access, prohibited network, fork/process exhaustion, CPU/memory/IO exhaustion and guest escape. | Test payload digests; VM/policy configuration; denial and resource telemetry; host-integrity comparison. | All prohibited access is denied and bounded without host compromise. If the qualified boundary is unavailable, native generated code remains disabled. Security lead. |
| S4 authority and secret boundary | `A054`, `A079`, `A080`, `A082`, `A086`, `T30`, `T62` | Alter an approved argument before effect time; revoke authority after planning; inject claimed authority through files, images, tool replies and cached content; fuzz typed helper requests and forge peer identity. Scan prompts, logs and artifacts for seeded secrets. | Grant/policy/effect receipts; kernel peer credentials; fuzz corpus/version; denial logs; secret-scan report. | Every protected effect is reauthorized against current identity and exact target; forged or stale requests fail; no unintended action or seeded-secret disclosure occurs. Security + QA. |
| S5 immutable code and model inputs | `A009`, `A017`, `A049`, `A083`, `T06`, `T27` | Alter one model shard, tokenizer/template/runtime constraint and skill executable/manifest at a time; interrupt offline import and resume it. | Signed catalog/skill manifests; altered-byte cases and digests; import journal; activation decisions. | Incomplete, unsigned, incompatible or altered content never activates; resume verifies every immutable input before atomic activation. Release + security. |

### Lifecycle, crash recovery and performance

| Run | Governing coverage | Execution | Required evidence | Pass criteria and owner |
| --- | --- | --- | --- | --- |
| R0 suspend/resume | `A008`, `T05` | Execute 100 suspend/resume cycles under the declared idle, loaded and cancellation states; include orderly shutdown/restart. Unsupported hibernation must be disabled. | Cycle-indexed power, worker, lease, device and artifact records; failures and temperature. | All 100 cycles complete without leaked leases, corrupted artifacts or unsafe device reuse; backend state restores or reloads as declared. Platform + QA. |
| R1 load/interruption | `A013`, `A015`, `A096`, `T09` | Install three models where supported; switch under budget; interrupt every load phase; fill model, cache, log and download quotas. | Peak host/device/staging measurements; cleanup and catalog state; quota telemetry. | Loading peak is reserved; temporary copies are bounded; interruption reclaims capacity and preserves prior catalog state; no unbudgeted duplicate or recovery-space exhaustion. Inference + QA. |
| R2 accounting/admission | `A019-A028`, `A032`, `A040`, `T07`, `T11-T16` | Run exact size/overflow cases, real allocation instrumentation, 100-client admission race, context boundary plus one token, cache exhaustion, cancellation and device-loss fencing. | Request/lease traces; real allocation samples; arithmetic oracle; terminal-state records. | No overflow, double reservation, silent truncation, premature reuse, host OOM or unexplained accounting gap. Systems + QA. |
| R3 workflow crash matrix | `A051`, `A052`, `A055`, `A059`, `A063`, `T28`, `T33`, `Q09` | Kill workers and cut power at each documented prepare/apply/commit/index boundary; repeat idempotency requests; rebuild indexes. The governed target is 1,000 injected crash trials. | Trial-indexed fault point and power timestamps; database/WAL and artifact digests; receipts; reconciliation outcomes. | Zero acknowledged committed versions lost in 1,000 trials; zero duplicate committed effects; no committed metadata points to missing bytes; rebuilt indexes preserve authorized artifact identity. QA + storage owner. |
| R4 interactive/cancel performance | `Q01`, `Q02`, `Q06` | Run declared 30-minute foreground workloads and model request distribution; cancel at each dispatch/execution boundary. | Raw latency samples, percentiles, token counts/rates, cancellation timestamps and backend stop evidence. | Input acknowledgement P95 at most 100 ms and no unresponsive interval above 1 s; TTFT P95 at most 3 s; at least 95 percent of completed requests average at least 15 decode tokens/s; cancellation UI acknowledgement at most 250 ms, no new effect dispatch and backend stop within the certified bound no longer than 10 s. Performance + QA. |
| R5 lifecycle leak | `Q08` | Execute 1,000 governed load/release or request cycles after a warmup and retained-baseline snapshot. | Per-cycle host/device/pinned/cache allocations and fitted trend with raw samples. | No monotonic leak; retained unreferenced use is at most 2 percent of the pool or 256 MiB, whichever is larger. Performance + QA. |
| R6 vertical failures | G2 exit | Run the complete offline vertical workflow on E1 and E2 with a missing model, worker crash, failed staged-artifact commit and failed trial boot. | Workflow DAG/events, receipts, artifact/file hashes, boot/recovery logs and human-visible result. | Each normal workflow passes and each injected failure recovers without unauthorized effect or loss of acknowledged content. Cross-functional G2 owners. |

The later A1 release also requires its complete inherited test scope and a
72-hour mixed-workload soak. That later release criterion should be scheduled
with the same retained tuples; it must not be inferred from the shorter G2
runs above.

## Recovery and key-custody rules

- Use separate lab and production trust roots. Keep boot/image signing, model
  catalog signing and recovery credentials in separately authorized roles even
  when Admin assigns those roles.
- Generate private keys and recovery credentials outside model-visible
  processes. Use an approved protected key store; maintain an offline recovery
  copy under documented human custody.
- Record public certificates, key IDs, algorithms, validity, purpose,
  lifecycle, revocation state, ceremony ID and artifact signatures. Never
  record private keys or LUKS recovery secrets in repository evidence.
- Require two-person control for a production signing ceremony and recovery
  credential retrieval. The signer must verify exact input digests and purpose;
  an independent verifier must validate the resulting signature from the
  distributed offline media.
- Exercise bootstrap, backup recovery, rotation and revocation. After exposing
  a lab recovery credential during a test, rotate it according to the approved
  lab procedure and record only the custody event and new public metadata.
- Demonstrate that ordinary workers, the model runtime, prompts, logs and
  artifacts cannot read a private key or recovery credential.
- Preserve a tested path to restore firmware key state before any tamper case.
  Do not improvise PK/KEK/db or MOK changes during the run.

## Evidence bundle structure

Keep raw evidence in the approved protected store, not automatically in Git.
Use an immutable run directory such as:

```text
G2-<E1-or-E2>-<release-id>-<UTC-run-id>/
  authorization/
  inventory/
  release-inputs/
  console/
  boot-and-storage/
  security/
  lifecycle/
  performance/
  test-records/
  redacted/
  evidence-index.json
  evidence-index.sig
```

`evidence-index.json` must contain:

- source commit and release/image/SBOM/package-lock digests;
- model pack, tokenizer, template, runtime, policy and public signing-key
  digests;
- environment ID, pseudonymous OS-installation identity with its stated
  limitations, separately reviewed physical-board designation,
  firmware/kernel/driver/device tuple and exact test-plan revision;
- target disk identity digest and a reference to the private raw authorization;
- UTC start/end, synchronized clock source, operator, witness and reviewer;
- one record for every mandatory row with requirement/test IDs, preconditions,
  steps, expected oracle, observed result, result status, defect ID and hashes
  of supporting artifacts;
- raw distributions, not only averages, for performance/lifecycle criteria;
- redaction log identifying removed fields and the unredacted custody location;
  and
- an evidence-index signature made only after every referenced file digest is
  final.

Serial-console output and power-controller timestamps are preferred for boot
and interruption cases because logs on the interrupted disk may be incomplete.
Photographs can corroborate physical cabling or displayed firmware state, but
they do not replace machine-readable logs and artifact digests.

## Result and signoff policy

Any unauthorized effect, secret disclosure, committed-data corruption,
privilege escape, installation damage outside the approved disk, unrecoverable
supported boot, host OOM, post-cancellation effect, invalid resource reuse, or
loss of acknowledged content fails the affected release. Such a severity 0 or
1 result cannot be accepted by waiver as a passing test.

Required approvals are:

| Decision | Pre-execution approval | Evidence review | Closure authority |
| --- | --- | --- | --- |
| Exact destructive disk/install run | Admin-assigned platform lead and environment owner; QA witness confirms identity | QA lead | Requirements/release owner after both boards pass |
| Firmware/Secure Boot/tamper run | Platform lead and release engineer; recovery path confirmed | Security lead and QA lead | Requirements/release owner |
| LUKS/TPM recovery run | Two recovery custodians and platform lead | Security lead; no secret in evidence | Requirements/release owner |
| Signing ceremony inputs | Release engineer/custodian and independent verifier | Security lead validates isolation and revocation status | Named production release authority |
| Resource, isolation and adversarial rows | Security lead and environment owner | Independent security reviewer plus QA | Requirements/release owner |
| Final G2 disposition | All row owners report pass and all severity 0/1 defects are closed | QA, platform, release, inference and security leads | Requirements-and-release owner records the governed gate decision |

A reviewer records `blocked`, not `pass`, when a required physical fixture,
signed artifact, protected key, implementation or raw measurement is absent.
WSL evidence stays development-only even when every repository test passes.
