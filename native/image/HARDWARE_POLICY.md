# Native hardware policy operator guide

This guide describes the installed Ubuntu hardware controller implemented by
`hardware_policy::console`. It is not permission to change the development
host, an installed-hardware qualification certificate, or a Windows custody
bridge. Use these ceremonies only on an explicitly approved native test or
qualified installation. Unsupported devices, kernels, drivers, confinement or
authority refuse; a refusal is not evidence that a device is absent.

The policy-aware active CPU/I/O guard and controller passed the same strict
workspace/all-targets source check and scoped hardware regression cut. Their
implemented boundary is described below; compilation and software fixtures do
not establish native acceptance. Memory and network changes require complete
worker drainage, not that active-guard path.

## Prerequisites and authority

The installation must have its actual installed identity, original product
Admin enrollment, current principal/account and protected password epoch, TPM/NV
custody, authenticated protected UTC, enforcing AppArmor profiles and systemd
available. Worker controls additionally require the actual resource Manager.
Unix root or `sudo` supplies an execution identity,
not product authority. The actual original Admin authenticates through local
PAM on the controlling terminal. Passwords and custody secrets never belong in
request JSON, command arguments, environment variables or saved review files.

Hardware uses three distinct finite activities: `hardware.inspect`,
`hardware.apply` and `hardware.restore`. Register/define and assign the required
finite roles through the existing Admin catalog; then issue the exact finite
grants. A role definition, Admin title, grant identifier, serialized grant,
review digest or earlier observation alone authorizes nothing. Current
assignment/grant versions, subject generation, revocation and the entire
protected UTC interval are checked independently.

The fixed ordinary-writer policy must also verify. It denies ordinary PPD
profile mutations/holds and ordinary login1 backlight writes, removes backlight
`uaccess`, and checks root-only actual sysfs permissions. Root, firmware and the
trusted platform daemons remain trusted platform boundaries. These adapters do
not claim an atomic CAS against those writers.

## Entry point and limits

From the enrolled Admin's original terminal, on the approved installed machine:

```sh
login="$(id -un)"
sudo /usr/libexec/luma-os/luma-platform hardware-run "$login"
```

The launcher asks for **one complete JSON Task line** on `/dev/tty`. Paste a
request prepared below. Piping stdin does not substitute for this terminal.
Requests and responses are bounded to 65,536 bytes, with unknown/duplicate
members refused. A root-owned immutable staged request binds one fresh
`luma-hardware-<unit-generation>.service`, the exact account and Task. The
internal `hardware-console` and `hardware-cleanup` verbs are not alternate
unconfined execution interfaces.

The controller has zero capabilities, fixed AppArmor, no-new-privileges and
seccomp, 256 MiB memory, no swap and at most 16 tasks. It uses the standard
nonrenewable **30-second original PAM session**, not a model/QA/export session.
A Plan allows **1–20,000 ms** from its protected Prepare activation, followed
by at most **5,000 ms** of precommitted cleanup. Each actual device callback
has an original one-second suspend-aware budget; nested bus/helper work cannot
reset it. These bounds do not authorize blind retries or guarantee that a
kernel driver can be forcibly interrupted in process.

## Supported controls

The Task `adapter` values and Setting `kind` values are the same strings in the
first column. Worker values are `model` or `acquisition`; global controls use
`worker: null`.

| Adapter | Fixed control and admitted changes |
| --- | --- |
| `cpu-quota` | The selected worker's parent `cpu.max`: `period_us=100000`, `quota_us=1000..200000` (1%–200% of one CPU). This is a ceiling, not a resource reservation. |
| `cpu-weight` | Parent `cpu.weight`, integer `weight=1..10000`; relative scheduling weight, not guaranteed CPU time. |
| `storage-rate` | Parent `io.max` for the discovered whole backing device of `/var`; `read_bytes_per_second` and `write_bytes_per_second` are each `1..67108864`. Device substitution, other devices and non-default IOPS are refused. |
| `memory-profile` | Model worker only, fully drained, no active lease. The same admitted `qwen3-4b-q4-k-m` or `qwen3-1-7b-q4-k-m` profile; Apply uses its exact admitted memory limit, no larger than the observed baseline. Both baseline and replacement must be at most 4,831,838,208 bytes so exact undo also stays bounded. No weight selection, profile switch or envelope expansion. |
| `worker-network` | Fully drained selected worker, no active lease. `IPAddressDeny` remains IPv4/IPv6 any; only `IPAddressAllow` changes between empty (`deny-all`) and exact `127.0.0.0/8` plus `::1/128` (`loopback-only`). No unrestricted profile, other prefixes or custom filter paths. |
| `backlight` | One actual `intel_backlight`/`i915` Intel eDP slot. Preserve observed `maximum` (`1..1000000`); requested brightness must be within it and nonzero. Blanking, quantization, driver/path drift or unequal requested/actual brightness refuses exact control. |
| `power-profiles` | Pinned Ubuntu `power-profiles-daemon` 0.21-1ubuntu3, actual supported hardware driver and no active profile holds. Only `balanced` and `power-saver`, including the baseline; no performance selection, hold or fallback backend. |

Worker directories are exactly `/sys/fs/cgroup/lumamodel.slice` and
`/sys/fs/cgroup/lumaacquisition.slice`. The cgroup controller writes only
`cpu.max`, `cpu.weight`, `memory.max` or the selected `io.max` record. Leaf
worker/guardian limits are not loosened to accommodate a parent policy.

Backlight discovery starts at `/sys/class/backlight/intel_backlight`, pins its
actual sysfs inodes and resolved Intel PCI/eDP path, and requires driver
`/sys/bus/pci/drivers/i915`. Only `brightness` is written; `actual_brightness`,
`max_brightness`, `type`, `bl_power` and PCI identity are read and rechecked.

Network uses PID1's fixed `org.freedesktop.systemd1.Manager` and the two fixed
slice objects, runtime-only `SetUnitProperties`, and independent actual
cgroup-BPF observations. Both ingress/egress must retain ancestor filters and
replace their own effective program IDs after a changed prefix policy. Merely
reading updated D-Bus properties or finding an old attached BPF program is not
success. This does not assert that other network/LSM layers permit traffic.

PPD uses the fixed `/org/freedesktop/UPower/PowerProfiles` object, actual shared
owner of `org.freedesktop.UPower.PowerProfiles` and `net.hadess.PowerProfiles`,
and one typed `Properties.Set` of `ActiveProfile`. No shell command, daemon
activation or arbitrary D-Bus destination/path is supplied by a Task.

### Active allocations versus drained changes

CPU quota/weight and I/O may bind one exact active worker lease; multiple
candidate allocations are refused. The Manager retains the real exclusive
kernel file description and complete intent, and independently checks the
controller's pidfd, executable, AppArmor profile and transient unit. Its
protected-authority fingerprint excludes only the hardware-policy state and
catalog state-version increments, not account, role, grant, password or other
authority changes. It checks actual parent policy against the current phase.
The before/after transition is tolerated only inside the first one second of
the durable DispatchStarted record, not as an extended allocation or grant.

Original allocation, grant/assignment and policy deadlines still apply. A
revocation, controller loss or unknown readback retains exclusion and charged
capacity; it is not permission for new admission. An active allocation is bound
to its first actual handoff window, typically no more than ten seconds; a later
heartbeat does not renew that original deadline merely because a Plan allows
twenty seconds. The Manager separately verifies a terminal Restored outcome and
its original actual baseline before retiring its reference, including a lost
finish acknowledgement. Reconciled instead depends on fresh independently
granted Admin recovery observation or qualified absence; it may explicitly
retain external/new-generation state and does not assert an undo.

Memory/network require actual empty cgroups and complete worker, guardian and
request drainage. The handoff prevents new admission during configuration.
Stopping a process, closing a receipt or observing one empty child is not that
proof. Global backlight/PPD controls never borrow a worker lease or Manager
epoch.

## Review, inspect, grant and apply

### 1. Review an exact inspection request

This example prints a real current-boot backlight review Task; it performs no
hardware write, issues no grant and invents no device identifier:

```sh
python3 - <<'PY'
import json
from pathlib import Path
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
print(json.dumps({'operation': 'review-inspection', 'inspection': {
    'schema_version': 1, 'adapter': 'backlight', 'worker': None, 'boot': boot
}}, separators=(',', ':')))
PY
```

Paste the printed line into a fresh `hardware-run` prompt. For a worker
inspection select its actual adapter and worker instead. `review-inspection`
returns the exact finite `hardware.inspect` Use: selector kind `hardware`,
compiled adapter ID, discovery-contract generation 1 and exact request digest;
input/output bounds are 65,536 bytes and one unit. This review is data, not PAM
or permission. Have the Admin independently issue that scope for the actual
subject/current assignment.

The existing issuance interface is
`sudo luma-admin-control admin-catalog LOGIN REQUEST FILE`, followed by the
same command and `--commit REVIEW-SHA256` after explicit review. `FILE` contains
the typed `issue_grant` command for the actual catalog assignment, subject,
versions, protected-UTC validity and returned selector/limits. Do not copy
fixture identities, use local wall-clock time as protected UTC, or treat an
uncommitted command file as an issued grant. This interface does not issue its
own operation grant.

### 2. Inspect with the separately issued grant

Print the Task using the **same reviewed Inspection object** and actual issued
grant identifier. The prompts intentionally require real deployment data:

```sh
python3 - <<'PY'
import json
import sys
sys.stdin = open('/dev/tty', encoding='utf-8')
inspection = json.loads(input('Paste the exact reviewed Inspection JSON object: '))
grant = input('Actual issued inspection grant identifier: ').strip()
print(json.dumps({'operation': 'inspect', 'inspection': inspection, 'grant': grant},
                 separators=(',', ':')))
PY
```

Run this Task in a fresh hardware console and authenticate when asked. Retain
the complete JSON result, including `observation`, `subject`,
`subject_generation` and `latest_policy`. Inspection captures actual target
identity/capability/source digests, boot and device generation, exact baseline,
and, for a worker, its actual Manager epoch/lease. It is not a reusable session.

### 3. Construct and review one changed Plan

A Plan contains exactly `schema_version`, `transaction`, `subject`,
`subject_generation`, `apply_grant`, `restore_grant`, `target`,
`expected_revision`, `before`, `after`, `lifetime_ms` and `cleanup`.
`lifetime_ms` is a **decimal JSON string**, not a JSON number. Copy the actual
target/baseline and subject from inspection, and the latest policy revision
(or zero if none). Choose a new transaction and two distinct grant identifiers;
choosing names does not issue those grants.

The following generates a complete backlight review Task from actual inspection
output. It does not assume a baseline, device hash, actor or existing grant:

```sh
python3 - <<'PY'
import json
import re
import sys
import uuid
sys.stdin = open('/dev/tty', encoding='utf-8')
result = json.loads(input('Paste the complete Inspect result JSON object: '))
before = result['observation']['setting']
if before['kind'] != 'backlight':
    raise SystemExit('This generator requires an actual backlight inspection.')
brightness = int(input('Different requested nonzero brightness: '))
if not 1 <= brightness <= before['maximum'] or brightness == before['brightness']:
    raise SystemExit('Brightness must be changed, nonzero and within the observed maximum.')
apply_id = input('Chosen new Apply grant identifier for separate issuance: ').strip()
restore_id = input('Chosen different Restore grant identifier for separate issuance: ').strip()
if apply_id == restore_id or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', x)
                                for x in (apply_id, restore_id)):
    raise SystemExit('Two distinct valid catalog identifiers are required.')
latest = result['latest_policy']
plan = {
    'schema_version': 1, 'transaction': 'hardware-' + uuid.uuid4().hex,
    'subject': result['subject'], 'subject_generation': result['subject_generation'],
    'apply_grant': apply_id, 'restore_grant': restore_id,
    'target': result['observation']['target'],
    'expected_revision': 0 if latest is None else latest['revision'],
    'before': before, 'after': dict(before, brightness=brightness),
    'lifetime_ms': '10000',
    'cleanup': 'restore-exact-before-only-if-same-generation-and-still-exact-applied-value'
}
print(json.dumps({'operation': 'review-plan', 'plan': plan}, separators=(',', ':')))
PY
```

Retain that exact Plan. `review-plan` returns its digest and **two independent
Uses**, `hardware.apply` and `hardware.restore`, both bound to this exact Plan
and actual target generation. Issue each separately through the current Admin
catalog using the chosen identifiers and actual finite assignment/subject.
Changing either identifier, baseline, target, requested value or lifetime changes
the reviewed Plan and requires matching newly reviewed scopes.

### 4. Apply the identical reviewed Plan

```sh
python3 - <<'PY'
import json
import sys
sys.stdin = open('/dev/tty', encoding='utf-8')
plan = json.loads(input('Paste the identical reviewed and separately granted Plan JSON object: '))
print(json.dumps({'operation': 'apply', 'plan': plan}, separators=(',', ':')))
PY
```

Paste the line into a fresh `hardware-run`. Inspect the printed Plan, type
`APPLY` only if it is correct, and perform original Admin PAM authentication.
The controller rechecks the baseline/target, authenticates both current grants,
commits Prepare, obtains any real worker exclusion, and commits DispatchStarted
before one actual write. Exact current readback precedes an Applied commit.

Enter `q` then Enter to request early restoration. At the policy deadline or
lost allocation, the controller attempts a new RestoreStarted and exact undo
only while its original session and scopes are still valid. It never opens a
new PAM session or extends a lease to finish an old policy. Successful normal
undo requires the same actual generation and still-exact applied value, then
readback and a Restored commit. External drift is not overwritten.

## Interruption and explicit reconciliation

Prepare/DispatchStarted/Applied/Restored records are TPM-authenticated
obligations, not portable capabilities. A lost write/TPM reply, failed readback,
changed actor/catalog/UTC, timeout or disconnected terminal preserves the
obligation. An outstanding logical device blocks a new policy even after its
boot, inode or daemon generation changes. Do not delete journal, pending files,
locks, staged evidence or the resource ledger to clear it.

Scalar/sysfs precommitted cleanup may inspect/restore the exact original
baseline under current NV and the original bounded cleanup window. It does not
issue a grant, update the hardware journal, release charges, or itself mark a
transaction terminal. ExecStopPost is an attempted cleanup, not evidence it
succeeded.

**D-Bus timeout is not cancellation.** A queued PPD or PID1 method may outlive
its client. After an ambiguous external dispatch, a new connection, live-daemon
baseline observation or fresh password cannot prove that old work cannot run
later. Automatic cleanup does not redispatch that method. Fresh reconciliation
requires actual retirement of the recorded old daemon process generation:
PPD owner exit, or native reboot/old PID1 exit for an uncertain network request.
A D-Bus name change, same-process exec, service timeout or PID reuse without
the start-generation check is insufficient. This guide does not authorize
restarting a daemon or rebooting a machine; arrange that remediation separately.

Even a fully acknowledged Applied policy can remain changed if original
authorization is lost before a valid RestoreStarted. The safe result is a
retained obligation, not a claim of guaranteed automatic undo. Do not assume
that a 20-second requested lifetime means every failure outcome was restored.

For recovery, obtain a fresh actual current-boot inspection scope. Run
`review-reconciliation` with that Inspection, its issued inspection grant, the
actual old transaction and one explicit disposition:

| Disposition | Required observation and meaning |
| --- | --- |
| `baseline-observed` | Current observation of the same logical slot exactly equals the old baseline; no guessed restoration. |
| `external-state-retained` | Explicitly retain the reviewed actual state of the same logical slot; it need not equal the old requested value or baseline. |
| `device-unavailable` | Actual qualified kernel-path absence where supported. A PPD/permission/driver/authority error is not an absence probe. |

The exact Task shape can be generated without inventing deployment identifiers:

```sh
python3 - <<'PY'
import json
import sys
sys.stdin = open('/dev/tty', encoding='utf-8')
inspection = json.loads(input('Paste the fresh reviewed Inspection JSON object: '))
grant = input('Actual issued fresh inspection grant identifier: ').strip()
transaction = input('Actual retained transaction identifier: ').strip()
disposition = input('Disposition: baseline-observed, external-state-retained or device-unavailable: ').strip()
if disposition not in ('baseline-observed', 'external-state-retained', 'device-unavailable'):
    raise SystemExit('Choose one explicit supported disposition.')
print(json.dumps({'operation': 'review-reconciliation', 'inspection': inspection,
                 'grant': grant, 'transaction': transaction, 'disposition': disposition},
                 separators=(',', ':')))
PY
```

Review returns the exact reconciliation `plan` and `fresh_restore_scope`. Issue
a **new** matching `hardware.restore` grant; the old operation's restore grant
does not authorize this different recovery digest. Then submit:

```sh
python3 - <<'PY'
import json
import sys
sys.stdin = open('/dev/tty', encoding='utf-8')
plan = json.loads(input('Paste the exact returned reconciliation Plan JSON object: '))
grant = input('Actual issued grant matching fresh_restore_scope: ').strip()
print(json.dumps({'operation': 'reconcile', 'plan': plan, 'grant': grant},
                 separators=(',', ':')))
PY
```

Reconcile authenticates a fresh original Admin, current protected UTC, exact
revision and fresh scope, re-observes the reviewed state/absence and verifies
any ambiguous old daemon has actually exited before committing Reconciled. It
does not execute the old Apply or grant a new policy. A Manager separately
reconciles actual worker drainage/charges; a printed observation or
`resource_released: false` is not a release receipt.

## Independent observations and qualification

`/usr/libexec/luma-os/hardware-bpf-query` is an independent query-only helper,
not a worker, grant issuer or BPF mutation endpoint. The separate
`/usr/libexec/luma-os/hardware-daemon-observer` has only SYS_PTRACE for fixed-role
read-only executable/process observation, drops effective/permitted capability
before replying and cannot access Admin/TPM/resource state. The existing peer
observer is not broadened. Kernel-delivered credentials and pidfds, fixed
profiles/units, exact request challenges and the same original callback budget
authenticate replies. JSON cannot fabricate those descriptors.

The query endpoints are `/run/luma-hardware/query.sock` and
`/run/luma-hardware-daemon-observer/observe.sock`, activated by
`luma-hardware-query.socket` and `luma-hardware-daemon-observer.socket`; their
one-request workers use the matching `@.service` templates. They neither read
nor advance the Admin journal; a controller can query them while retaining its
own journal lock. Worker exclusion uses the actual
descriptions of `/run/luma-hardware/worker-model.lock` and
`/run/luma-hardware/worker-acquisition.lock`. Staged input lives under
`/run/luma-hardware/requests/<unit-generation>/input.json`; it is neither
permission nor the protected hardware history. That history is reconstructed
from `/var/lib/luma-os/admin/journal.json` and its exact authenticated event
files, not from these runtime paths. See [local Admin custody](../LOCAL_TPM2_ADMIN.md)
and [independent resource recovery](../RESOURCE_CHECKPOINT_CUSTODY.md) before
attempting any authority repair.

Image inputs pin systemd 255.4-1ubuntu8.17, the actual DBus executable/service/
socket, PPD 0.21-1ubuntu3, their exact binaries and merged ordinary-writer policy.
The systemd `-BPF_FRAMEWORK` build flag does not alone disable built-in IP
firewalling: upstream v255 compiles `bpf-firewall.c` unconditionally; the optional
framework controls other generated BPF skeletons. Actual attached/effective
kernel filters remain mandatory. See the primary
[v255 core build definition](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/meson.build)
and [built-in firewall implementation](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/bpf-firewall.c).

Before acceptance, test the produced installed image's real PAM/account/UTC/TPM
binding, enforcing AppArmor and systemd resource bounds, exclusive ordinary
writer policy, supported i915 brightness/readback, actual PPD driver behavior,
kernel BPF attachment/replacement and traffic behavior, active CPU/I/O guardians,
revocation, deadlines, interruption, old-daemon retirement, exact cleanup and
reconciliation. Include unsupported hardware, missing/failed providers and
power-loss cases. Software fixtures, private buses and disposable TPMs establish
their stated mechanism coverage only; they do not certify those native results.
