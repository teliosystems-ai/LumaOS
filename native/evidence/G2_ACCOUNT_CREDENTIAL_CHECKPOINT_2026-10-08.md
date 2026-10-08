# Account credential checkpoint software evidence

Date: 2026-10-08. This implements a durable account-record integrity prerequisite
for governed sessions and catalog control. It does not complete account lifecycle,
protected UTC, grants/admission, broader workflow/recovery, Requirement #1 or G2.
No final image, installed service enforcement or physical qualification is claimed.

## Implemented boundary

The fixed-source local `admin-accounts-checkpoint` ceremony requires explicit
bootstrap/principal adoption, fresh governed Admin PAM, an exact request and
reviewed proposal. It accepts no credential bytes, password hash, account source
path or caller-supplied commitments. The general Admin socket rejects the
checkpoint command; it cannot adopt client-provided hashes.

The proposal commits every enabled baseline account's exact protected
passwd/shadow records, separated by installation, principal and UID. Secret rows
remain in locked private buffers. Only domain-separated commitments enter the
semantic event/catalog, never passwords or their stored password hashes. Every
original account and registry handle stays pinned through authentication,
preparation and final journal dispatch. A changed protected source refuses even
if the caller presents the previously correct commitment.

The existing TPM semantic journal anchors the checkpoint. Equal historical
requests replay without another extend; an identical new request is a no-op.
Incomplete inventories, changed snapshots and silent replacement checkpoints
refuse. Principal disable/generation changes and Admin rotation preserve the
original credential commitments. Legacy history retains its canonical bytes
without automatic enrollment; diagnostics explicitly report its unchecked state.

After adoption, both general and Admin-catalog governed login/session replay
require current account commitments to match anchored history. Fresh PAM, a new
reader or a reopened store cannot adopt a different account record. Live original
file pins, bounded PAM, shared-head checks and retained TPM clock floors remain
necessary too. Restoration can permit a fresh login to the authorized records,
but cannot revive a session that already observed invalidation.

Injected writer revocation after pending preparation preserves event/pending
evidence without dispatch. Injected lost TPM replies require exact reviewed
committed publication, not another extend or automatic retry. These tests do not
implement password/account mutation recovery or provide physical interruption
evidence.

## Retained evaluation

Final policy/integration snapshot:
`D:\LumaOS-builds\g2-principal-session-20261008-21`.
Full ordinary Rust evidence:
`D:\LumaOS-builds\g2-principal-session-20261008-20`.
The evaluation is deliberately composite, not a claim that snapshot 20's entire
runner passed or that all ordinary tests ran again in snapshot 21.

Run 17 retains a fixture compilation failure from a missing `Read` trait call.
Run 18 retains the full suite's six-minute timeout. Run 19 retains 651 ordinary
passes and 15 catalog fixture refusals because the private ext4 test-root variable
was absent. The runner supplied that existing required fixture without weakening
assertions. Run 20 passed the complete ordinary Rust suite, build and initial
kernel/PAM integrations, but stopped on a formatter-sensitive new Python
assertion. Only that assertion was corrected to recognize whitespace between the
same required Rust expression components.

Run 21 first compared the complete build-input manifest and CI file byte-for-byte
with run 20 and retained its log/runner digests. All 218 build inputs were identical;
no Rust source changed. It reran the four new credential-checkpoint Rust tests,
offline native build, explicit kernel/PAM checks, all 60 selected Python policy
checks and the real PAM/software-TPM catalog integration. Full native Python
discovery then ran against that same snapshot. Both final runners exited zero.

Results and limits:

- Complete ordinary Rust suite: 666 passed, zero failed, 38 fixture-dependent
  tests ignored by ordinary discovery. The four repeated checkpoint tests are
  included in 666, not four additional distinct passes.
- Explicit kernel credential, descriptor, task inventory and FSUID tests, six
  real PAM modes and three human-kernel-peer modes passed. This is not installed
  observer/AppArmor/seccomp enforcement.
- All 49 real PAM/kernel-peer/software-TPM catalog child scenarios passed through
  governed control. The parent also completed seven governed issuance, twelve
  protected projection, five offline custody recovery, nineteen catalog
  continuation and ten new account-checkpoint markers.
- The ten checkpoint cases cover protected inspection/no hash disclosure,
  reviewed complete adoption, replay/no-op without another extend, fresh PAM
  binding, both human accounts' credential-record drift despite valid PAM,
  ordinary Admin rebind refusal, sticky old-session invalidation after restoration
  and commitment preservation through governed Admin rotation.
- Full native Python discovery: 279 tests, 277 passed and two existing upstream
  UTC checks skipped because their isolated pinned-source fixture is absent.
  Skips are not passes. The 60 selected policy tests are included in discovery.
- Both AppArmor profiles parsed without kernel loading. No final image, live
  time acquisition, real model workload, reboot or native-machine test ran.

The offline Docker runs used the pinned tools image, one CPU and 1 GiB without
swap, warnings-denied locked/offline compilation and enumerated fixture
capabilities. Cache, ext4 test directories and evidence remained D:-backed. No
host account, service, clock, physical TPM ownership or WSL setting changed;
neither a host TPM nor Docker socket was passed into a test container.

All 218 captured build inputs, 59 test inputs and the CI workflow matched the
checkout after evaluation. SHA256 records:

| Artifact | SHA256 |
| --- | --- |
| Shared build-input manifest, runs 20/21 | `ef49a1a4807c58fa852a430ec92cb4a296b630c08652699f145485046f097ed2` |
| Run 20 ordinary Rust/initial-check log | `4cedb5466e154cbcf4bad67abf405cf52384f6550efef08fc0b8fd88e8f240e7` |
| Run 20 frozen runner | `432732e6cabc0e497273f6bc7afb62864a0e5ada060addc37fbaaab8d9e4fdf6` |
| Run 21 test-input manifest | `18f7dc633c0df4de2bf6c9e2fbe2e437a566500402c407624069a2ec4fa7cb57` |
| Run 21 integration/policy log | `d9db9a83054cb456075b17535f965490f748dc6db9f55cb70ae9ff02577c882f` |
| Run 21 frozen runner | `6e630127c91dadb30536249f357a1d572fba3d52e70aa9018cecbde807866da9` |
| Run 21 native executable | `687f7b91c6040a49bbe77be707f43f96fdf46a4ec4d4f5ccdf6f94b304302472` |
| Full native regression log | `30efb8e92f32ed0121f4c05a76df0e50d10eca2651b22db794908f82a9d7e789` |
| Frozen regression runner | `4d668cb75815a509af2594b78cdcf51f3e2af904d976c399acdeb03c4fd3a14e` |

## Remaining implementation

Account create/delete, password rotation/reset and Linux lock changes need
governed transactions, commitment advancement and exact interrupted-file
publication/reconciliation. The checkpoint cannot repair or legitimize changed
credentials. The approved protected UTC producer/keeper still needs deployment,
independent seed, authenticated control/history delivery and explicit recovery.
Finite time-bound assignments and principal-bound folder/effect/resource/inference
grants must be joined to preparation and final-dispatch admission.

Generic workflow workers, all inference consumers, governed export/deletion and
retention, damaged-authority reconstruction, device/multiworker adapters and
integrated interruption paths remain software work. Their current inventory is
in the [G2 software register](../G2_SOFTWARE_STATUS.md#checkpointed-account-credentials)
and [Requirement #1 register](../RESOURCE_LEASES.md#still-required-before-requirement-1-closes).
Final-image and physical/security/recovery qualification is additional work, not
the sole remaining work. Requirement #2 remains unstarted.
