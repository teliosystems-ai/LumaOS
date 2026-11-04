# GWIN0 installed and manual qualification runbook (profile W)

## Purpose and evidence boundary

This runbook turns the open GWIN0 installed-qualification items into an
owner-run handoff for the Windows-hosted WSL product (profile W). It covers
the rows that repository software tests cannot close:

- installed first launch, TTY/PAM account setup and authenticated health;
- host protection and the TPM key provider;
- real compact inference;
- scoped ingestion;
- lifecycle;
- resource coexistence, including Windows headroom;
- confinement;
- the W022 two-user proof.

The repository contains the hosted authority, the profile-W package builder,
the read-only preflight and coexistence planners and their software tests (see
`packaging/windows/README.md` and the `docs/gates/gwin0/*.json` records).
Those records state their own limits. None of them installs the service,
commissions TPM custody, imports a distribution, runs the model in an
installed guest or proves Windows responsiveness. This runbook defines the
authorization, execution and evidence contract. It does not claim that any
row has passed.

The product is installed from a downloaded location: a local folder such as
`D:\LumaOS-downloads\<release-id>\` on a fixed NTFS volume. Optical media,
network shares, removable drives, cloud-synced folders (OneDrive and
similar) and recalled/offline placeholders are out of scope. The installer
refuses linked, offline and recall-on-access sources, so it must refuse them.

The development host (Windows 11 Home Single Language 10.0.26200, WSL 2.7.13,
16 GiB class) is not a qualified host. Its read-only protection observation
on 2026-10-20 was `query-timed-out` with policy `unknown`, and admission was
refused. Its WSL kernel reported AppArmor disabled on 2026-10-31. On
2026-11-03 the coexistence planner returned `no-feasible-limit`. Evidence from
that host stays development-only.

GWIN0 requirements in scope: W005 to W013, W017, W019, W021 and W022. Tests in
scope: V03, V04, V05, V09, V10 and V16. Targets in scope: QW04 and QW05. The
Hyper-V profile V rows (W030 to W032) belong to a separate runbook.

## What the environment owner must provide

| Item | Requirement | Required owner action |
| --- | --- | --- |
| Qualified host | One designated x86-64 Windows 11 host, at least 16 GiB, on the supported WSL release; BitLocker-capable edition (Pro, Enterprise or Education) with a TPM 2.0 | Designate the host in writing with its edition, build, WSL version and pseudonymous identity. The development host does not count. |
| Mains power | Mains power for every row; battery charge above 80 percent before any run longer than one hour | Confirm before each session. Record `Get-CimInstance Win32_Battery` before long rows. |
| Downloaded release | The authority bundle (four files), the profile-W package (`manifest.json`, `rootfs.tar`), the package signature and trust anchor, the release policy and time attestation, a lab-signed release description and signature for the exact package, and the `packaging\windows` tools at the release commit | Approve the download source. Supply the expected SHA-256 values through a channel independent of the download, such as the signed release record. |
| Native UTC authority | A commissioned native U appliance reachable over canonical HTTPS from this host, with its public time key and a native Admin who can authorize Windows sources | Confirm the endpoint and key out of band. The native Admin performs every `utc-windows-key-*` ceremony personally. |
| Lab trust keys | The lab release public key and lab time public key in the 72-byte form `commission` takes | Supply the public keys only. Never supply a private key. |
| Service installation | Explicit permission to create and start `LumaHostedAuthority` (LocalSystem, demand start) under `%ProgramFiles%\LumaOS-HostedAuthority` | Sign decision 2. The installer refuses if the folder or service already exists. |
| Two Windows accounts | The commissioned first Admin (OWNER) and a second standard account (USER2), both created manually by the owner before the run | Create and later remove them yourself. No script, tool or agent creates, expires or locks an account. |
| Protection fault window | Permission to suspend and then resume BitLocker on the system volume once, for row P3 | Sign decision 4, or record P3 as `blocked`. |
| AppArmor-capable WSL kernel | An enforcing AppArmor LSM in the kernel that the service's WSL VM runs | Decide separately, as owner maintenance, whether to provide it (decision 5). Without it, record C2 as `blocked`. |
| Declared workload | The Windows foreground workload for QW04 (applications, documents, typing script), the latency instrument and an optional memory-pressure tool | Declare these, with versions and hashes, before R3 starts. |
| Other WSL distribution | One other registered WSL2 distribution with a representative workload (for example Ubuntu running a build) | Keep it running during the R rows. Never unregister or reset it for this runbook. |
| Operator and witness | A named operator and an independent witness; a security reviewer for C and U rows | Name them in the authorization record. |

Before scheduling any run, the environment owner must answer and sign the
following decisions:

1. **Host designation:** identify the qualified host, its Windows edition and
   build, its WSL version (`wsl.exe --version`) and its pseudonymous identity.
   State that it holds no irreplaceable data that a protection fault could
   lock.
2. **Service lifetime:** approve installing and starting the LocalSystem
   `LumaHostedAuthority` service, plus the uninstall decision afterwards.
   Uninstall is a separate owner action. This runbook never deletes the
   service, its state or its imported slot.
3. **WSL settings:** state whether the coexistence planner's proposal may be
   applied. Applying it is an owner maintenance action, outside every row:
   back up `.wslconfig`, change one `[wsl2] memory` value and restart WSL at a
   planned time. The product, the planner and this runbook never raise the
   WSL memory limit automatically and never run `wsl --shutdown`.
4. **Protection fault injection:** approve one `Suspend-BitLocker` /
   `Resume-BitLocker` cycle on the system volume for row P3. Name the custodian
   of the BitLocker recovery key. The key itself never enters evidence, chat,
   the repository or a screenshot.
5. **Confinement kernel:** state whether an AppArmor-enforcing WSL kernel will
   be provided. If one is, record the kernel source, build and hash. Any change
   to `.wslconfig` or the kernel is owner maintenance, not part of a row.
6. **Accounts:** confirm that OWNER and USER2 already exist, were created
   manually and will be removed manually. Confirm that no row creates,
   expires, locks or deletes an account.

## Download layout and conventions

Place the release in its own new, empty folder on a fixed local NTFS volume,
for example:

```text
D:\LumaOS-downloads\<release-id>\
  authority\Luma.HostedAuthority.exe
  authority\Luma.PackageInspector.dll
  authority\Luma.PlatformCustody.dll
  authority\Luma.PlatformSignature.dll
  package\manifest.json
  package\rootfs.tar
  signature\        package signature, trust anchor, policy, time attestation
  release\          lab-signed release description and its signature
  tools\            packaging\windows from the release commit
  SHA256SUMS
```

The `authority` and `package` names are fixed by the installer and the
package inspector. The other file names are those the release's download
record gives. Use these PowerShell variables in every row:

```powershell
$Release  = '<release-id>'
$Download = "D:\LumaOS-downloads\$Release"
$Tools    = "$Download\tools"
$Evidence = "D:\LumaOS-evidence\GWIN0-W-$Release-<UTC-run-id>"
$Client   = "$env:ProgramFiles\LumaOS-HostedAuthority\Luma.HostedAuthority.exe"
New-Item -ItemType Directory -Path $Evidence | Out-Null
```

Keep the evidence folder on a protected volume, outside every product folder
and outside the download folder.

Downloaded scripts carry a Mark of the Web (`Zone.Identifier`), which the
`RemoteSigned` policy blocks. After I0 has matched every hash, the owner
either unblocks `$Tools` with `Unblock-File` (a recorded owner decision) or
starts each tool in its own process with
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <tool> <arguments>`.
Never change the machine or user execution policy. Under Windows PowerShell
5.1, `>` writes UTF-16 text; that is acceptable, and the file is hashed as
written.

The hosted authority client refuses redirected input or output (`The original
interactive client must review and confirm directly.`). Run it directly in a
console window. Never pipe it, redirect it or start it with redirected
streams. Capture its output with the terminal's own export (Windows Terminal:
tab menu, Export Text) into `$Evidence\<row>\console-<n>.txt`, plus a
screenshot of each review and confirmation prompt. Type `CONFIRM <hash>` by
hand only after comparing the hash with the review text shown above it.
Read-only PowerShell commands may write their output directly to evidence
files.

Hash every evidence file at the end of each row:

```powershell
Get-ChildItem -LiteralPath "$Evidence\<row>" -File -Recurse |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\<row>\SHA256.csv"
```

## Non-destructive inventory

Run this inventory before I0, after the last row of each session, and after
every reboot or sleep series. Every command is read-only. Run the
`Get-BitLockerVolume` and `reg query` lines from an elevated console.

```powershell
$Inv = "$Evidence\inventory\$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
New-Item -ItemType Directory -Path $Inv | Out-Null
wsl.exe --version                    > "$Inv\wsl-version.txt"
wsl.exe --list --verbose             > "$Inv\wsl-list.txt"
Get-FileHash -Algorithm SHA256 "$env:USERPROFILE\.wslconfig" -ErrorAction SilentlyContinue |
    Format-List                      > "$Inv\wslconfig-hash.txt"
Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber,CsTotalPhysicalMemory |
    Format-List                      > "$Inv\os.txt"
Get-CimInstance Win32_Battery | Format-List BatteryStatus,EstimatedChargeRemaining > "$Inv\power.txt"
Get-Service LumaHostedAuthority -ErrorAction SilentlyContinue | Format-List * > "$Inv\service.txt"
Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,
    EncryptionMethod,EncryptionPercentage,LockStatus,
    @{n='Protectors';e={($_.KeyProtector.KeyProtectorType) -join ','}} |
    Format-List                      > "$Inv\bitlocker.txt"
Get-Tpm | Format-List TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned > "$Inv\tpm.txt"
reg query HKLM\SOFTWARE\Policies\WSL /s 2>&1 > "$Inv\wsl-policy.txt"
dsregcmd /status                     > "$Inv\dsregcmd-raw.txt"
& "$Tools\preflight.ps1" -StorageDrive D -GuestMemoryGiB <guest-GiB> > "$Inv\preflight.json"
& "$Tools\coexistence.ps1" -Samples 10 > "$Inv\coexistence.json"
```

Never use `manage-bde -protectors -get` or print the `KeyProtector` objects
whole: both show the numerical recovery password. Before `dsregcmd-raw.txt`
leaves the protected store, redact its device, tenant and user identifiers and
log the redaction.

Inventory differences between two snapshots must be explained by a row's
expected effect. The only host-state changes this runbook expects are:

- the service and its `%ProgramFiles%` and `%ProgramData%` folders (I2, I3);
- the service-owned WSL slot (I3);
- the OWNER workspace account inside that slot (F1);
- protected snapshot files that S3 creates;
- the one approved P3 BitLocker suspend/resume cycle.

## Stop conditions

Stop, preserve the state and record the row as `fail` or `blocked` (never
`pass`) when any of the following happens:

- a downloaded file's SHA-256, size or signature differs from the
  independently supplied value, or a source sits in a linked, offline,
  recalled or cloud-synced location;
- the user's `.wslconfig` hash, the default distribution, or the
  `wsl --list --verbose` set of other distributions changes without an approved
  owner maintenance action;
- the coexistence planner reports anything but `current-limit-fits` before
  install (R1). `change-proposed` waits for decision 3, `no-feasible-limit`
  ends resource qualification on this host, and `blocked-observation` must be
  resolved as its blocker names;
- host protection is not observed as fully encrypted and protected before I2,
  or P3's resume does not return `ProtectionStatus On`;
- a client run shows a review whose text or hash differs from the operator's
  expectation. Do not confirm it; let the purpose expire;
- any result reports `production_qualified`, a product grant, publication or
  qualification that the row did not expect;
- a host out-of-memory condition, a Windows Resource-Exhaustion-Detector
  event 2004, an application hang over the QW04 bound or an unexpected reboot;
- a step would need `wsl --shutdown`, `wsl --unregister`, a `.wslconfig` edit,
  a kernel change, a service, firewall, registry or account change, or a
  reduced-security fallback that this runbook does not list. Any such change
  is a separate owner decision, never part of a row.

## Execution and evidence matrix

| Run | Governing coverage | Execution | Required evidence | Pass criteria and owner |
| --- | --- | --- | --- | --- |
| I0 | W005, QW05, release custody | Verify the download and its signatures | Hashes, verifier JSON, zone streams | Every hash and signature matches; operator and witness |
| I1 | W005, W009, W019 | Preflight and coexistence before install | Preflight and planner JSON, inventory | Admission inputs complete, `current-limit-fits`; operator |
| I2 | W011, W017 | Bundle review, service install | Independent bundle hash, installer JSON, `sc.exe` and ACL output | Hash equality, `service-installed-not-started`; owner and witness |
| I3 | W006, W011, W012, W017 | Start, commission, review, import, activate | Console exports, status, slot folder, inventory diff | Slot imported under the service; user WSL state unchanged; owner and witness |
| F1 to F5 | W006, W007, W013 | First launch, TTY/PAM, health, manual console, recovery, refusals | Console exports and prompt screenshots | Expected messages and refusals; operator, witness |
| P1 to P4 | W005, W011, W022, V09 | Protection, provider, suspension, managed policy | Read-only protection output, refusals | Protected state admitted; every other state refused; security reviewer |
| M1 to M3 | W010, V16 | Real compact inference, interruption, enrolled-file inference | Request files, receipts, timings | Bounded output, exact receipt, clean recovery; inference lead |
| S1 to S4 | W013, W017, V05 | Scoped read, enrollment, persistent read, manual save, negatives | Intents, UTC authorization, console exports | Exact reads only; all negatives refuse; security reviewer |
| L1 to L3 | W007, W008, V03 | Sleep/resume, forced stops, bounded restart, manual controls | Event logs, status before and after | No leaked lease or adoption; QA |
| R1 to R4 | W009, V04, QW04, QW05 | Coexistence, saturation, responsiveness | Planner JSON, samples, latency data, event logs | Reserve honored, no host OOM, QW04 bounds, no settings change; QA and owner |
| C1, C2 | W021, V05 | Fail-closed without AppArmor; enforcement with it | Kernel observation, refusals, confined receipts | Refusal without AppArmor; enforcing profiles with it; security reviewer |
| U1 to U4 | W022, V05, V10 | Second user, forged IPC, user switch, data locations | Console exports, ACLs, volume protection | Zero unauthorized effect; per-user separation recorded; security reviewer |

### I0: download and verification

Preconditions: decision 1 is signed. The release folder is new and was filled
only by the approved download. The expected hashes came through an independent
channel.

```powershell
New-Item -ItemType Directory -Path "$Evidence\I0" | Out-Null
Get-ChildItem -LiteralPath $Download -File -Recurse |
    Get-FileHash -Algorithm SHA256 | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\I0\download-hashes.csv"
Get-ChildItem -LiteralPath $Download -File -Recurse |
    ForEach-Object { Get-Item -LiteralPath $_.FullName -Stream * } |
    Select-Object FileName,Stream,Length | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\I0\streams.csv"
Get-ChildItem -LiteralPath $Download -Recurse -Force |
    Select-Object FullName,Attributes,Length | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\I0\attributes.csv"
& "$Tools\validate-package.ps1" -PackageDirectory "$Download\package" > "$Evidence\I0\validate-package.json"
& "$Tools\verify-package-signature.ps1" -PackageDirectory "$Download\package" `
    -SignaturePath "$Download\signature\<package-signature>" -AnchorPath "$Download\signature\<anchor>" `
    -AnchorSha256 <anchor-sha256> -OpenSslPath '<approved openssl.exe>' -OpenSslSha256 <openssl-sha256> `
    -WorkRoot "$Evidence\I0\work-signature" > "$Evidence\I0\package-signature.json"
& "$Tools\verify-release-policy.ps1" <the release record's exact arguments> > "$Evidence\I0\release-policy.json"
& "$Tools\verify-platform-signature.ps1" <the release record's exact arguments> > "$Evidence\I0\platform-signature.json"
```

Expected: every hash equals its independent value. No file carries a
`ReparsePoint`, `Offline`, `RecallOnOpen` or `RecallOnDataAccess` attribute.
`validate-package.ps1` reports a valid structure and content but no
authentication. Each verifier reports success for the exact anchor, nonce,
sequence and environment that the release record names. Record any
`Zone.Identifier` stream. Do not remove one unless the owner decides to,
after the hashes match.

Evidence: the CSV and JSON files above and the release record reference.

### I1: preflight and coexistence before install

Preconditions: I0 passed. The other WSL distribution is running its
representative workload. The declared foreground workload is open. No other
user is signed in.

```powershell
New-Item -ItemType Directory -Path "$Evidence\I1" | Out-Null
& "$Tools\preflight.ps1" -StorageDrive D -GuestMemoryGiB <guest-GiB> `
    -StoragePlanPath "$Download\release\<windows-storage-plan.json>" `
    -ReleasePolicyPath "$Download\release\<windows-release-comparison.json>" > "$Evidence\I1\preflight.json"
& "$Tools\coexistence.ps1" -Samples 60 -IntervalMilliseconds 1000 > "$Evidence\I1\coexistence.json"
Get-FileHash -Algorithm SHA256 "$env:USERPROFILE\.wslconfig" | Format-List > "$Evidence\I1\wslconfig-hash.txt"
```

`<guest-GiB>` and the two planning JSON files come from the release record.
The preflight `-DistributionName` accepts only `LumaOS-` names, so it does
not observe the service's `LumaHosted-` slot; I3 records that slot instead.

Expected: the preflight lists no blocker that this runbook cannot clear. The
coexistence status is `current-limit-fits`, with `applied`,
`global_wsl_settings_changed`, `wsl_shutdown_issued` and
`automatic_memory_change` all `false`. The `.wslconfig` hash is unchanged
across the run. On `change-proposed`, stop for decision 3. On
`no-feasible-limit`, record the R rows as `fail` for this host.

Evidence: both JSON files, the `.wslconfig` hash and an inventory snapshot.

### I2: bundle review and service installation

Preconditions: decision 2 is signed and I1 passed. Run from an elevated
Windows PowerShell 5.1 console. Compute the bundle hash independently
(canonical form: header line, then one `name<TAB>bytes<TAB>sha256` line per
file in fixed order):

```powershell
New-Item -ItemType Directory -Path "$Evidence\I2" | Out-Null
$names = 'Luma.HostedAuthority.exe','Luma.PackageInspector.dll','Luma.PlatformCustody.dll','Luma.PlatformSignature.dll'
$text = "luma-windows-hosted-runtime-bundle-v1`n"
foreach ($n in $names) {
    $f = Get-Item -LiteralPath "$Download\authority\$n"
    $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $text += "$n`t$($f.Length)`t$h`n"
}
$sha = [Security.Cryptography.SHA256]::Create()
$Bundle = -join ($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($text)) | ForEach-Object { $_.ToString('x2') })
$text  | Set-Content -NoNewline -Encoding ascii "$Evidence\I2\bundle-canonical.txt"
$Bundle | Set-Content -Encoding ascii "$Evidence\I2\bundle-sha256.txt"
& "$Tools\install-hosted-authority.ps1" -PackageDirectory "$Download\authority" -ReviewedBundleSha256 $Bundle |
    ConvertTo-Json -Depth 6 > "$Evidence\I2\review-only.json"
```

Compare `$Bundle` with the release record's bundle hash. Only if they are
equal, and the review-only result has status `review-only`, install:

```powershell
& "$Tools\install-hosted-authority.ps1" -PackageDirectory "$Download\authority" -ReviewedBundleSha256 $Bundle -Install |
    ConvertTo-Json -Depth 6 > "$Evidence\I2\install.json"
sc.exe qc LumaHostedAuthority        > "$Evidence\I2\sc-qc.txt"
sc.exe qsidtype LumaHostedAuthority  > "$Evidence\I2\sc-qsidtype.txt"
Get-Acl -LiteralPath "$env:ProgramFiles\LumaOS-HostedAuthority" | Format-List > "$Evidence\I2\acl-programfiles.txt"
Get-ChildItem -LiteralPath "$env:ProgramFiles\LumaOS-HostedAuthority" -File |
    Get-FileHash -Algorithm SHA256 | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\I2\installed-hashes.csv"
```

Expected: the status is `service-installed-not-started`. `sc qc` shows
`OWN_PROCESS`, `DEMAND_START` and `LocalSystem`, with the binary path under
`%ProgramFiles%\LumaOS-HostedAuthority`. The SID type is `UNRESTRICTED`. The
installed hashes equal the downloaded ones. A mismatching hash must throw
even in review-only mode; if the owner wants that negative case, run it once,
before installing, with a deliberately wrong `-ReviewedBundleSha256` and record
the refusal.

### I3: start, commission, import and activate

Preconditions: I2 passed, and the native UTC endpoint and keys are confirmed.
OWNER, the commissioned first Admin, runs every client command from an
interactive console that is not redirected.

```powershell
Start-Service -Name LumaHostedAuthority
& $Client commission host-deployment lab <RELEASEKEYHEX> <TIMEKEYHEX> https://<native-utc-host>/<path>
& $Client status host-deployment
& $Client release-review "$Download\release\<description>" "$Download\release\<signature>"
& $Client import "$Download\release\<description>" "$Download\release\<signature>" "$Download\package\rootfs.tar"
& $Client activate "$Download\release\<description>" "$Download\release\<signature>"
& $Client status host-deployment
```

Review and confirm each `CONFIRM <hash>` prompt within its purpose: 30
seconds for commission and review, 1800 seconds for import and activate. Then
collect, read-only and from an elevated console:

```powershell
New-Item -ItemType Directory -Path "$Evidence\I3" | Out-Null
Get-ChildItem -LiteralPath "$env:ProgramData\LumaOS-HostedGuests" -Force |
    Select-Object FullName,Attributes,CreationTimeUtc > "$Evidence\I3\guest-slots.txt"
Get-Acl -LiteralPath "$env:ProgramData\LumaOS-HostedGuests" | Format-List > "$Evidence\I3\acl-guests.txt"
Get-Acl -LiteralPath "$env:ProgramData\LumaOS-HostedAuthority" | Format-List > "$Evidence\I3\acl-state.txt"
reg query "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Lxss" /s > "$Evidence\I3\system-lxss.txt"
wsl.exe --list --verbose > "$Evidence\I3\owner-wsl-list.txt"
Get-FileHash -Algorithm SHA256 "$env:USERPROFILE\.wslconfig" | Format-List > "$Evidence\I3\wslconfig-hash.txt"
```

Expected:

- `commission` prints `Commissioned exact host-deployment identity <hash>; no
  guest activated; production qualification false.`
- `release-review` prints the publisher-signature and fresh-UTC confirmation,
  with no image imported.
- One slot folder named
  `LumaHosted-<installation64hex>-<sequence>-<package32hex>` appears under
  `%ProgramData%\LumaOS-HostedGuests`.
- The slot is registered for the service account (LocalSystem), not for
  OWNER. OWNER's `wsl --list --verbose`, default distribution and `.wslconfig`
  hash are unchanged.

If the import runs but the slot is registered under OWNER, or WSL refuses to
run under LocalSystem, record `fail` with the console export. Record the
active release SHA-256 that `status host-deployment` reports as `$Active` for
the later rows.

### F1 to F5: first launch, TTY/PAM and authenticated health

Preconditions: I3 passed. `$Active` is the active release SHA-256. `$Login` is
a lowercase nonroot login (letters, digits, `_` and `-`; starts with a letter;
at most 31 characters; not `root`, `nobody` or `nogroup`). OWNER runs each
command in a fresh interactive console.

**F1, first launch and account setup (W006):**

```powershell
& $Client workspace-setup $Active $Login
```

Expected: a review shows the exact operation, release, login and nonce bound
to OWNER's SID. After `CONFIRM <hash>`, the confined bootstrap asks for the
new password on the hidden TTY (no echo) and confirms it through PAM, all
within 30 seconds. The client then prints `Original owned console exited and
exact guest request drainage completed. Account ceremony closed; run a fresh
workspace-health before opening manual workspace.` The default WSL user stays
UID 65534, and root and `nobody` stay locked.

**F2, authenticated health (W007):**

```powershell
& $Client workspace-health $Active $Login
```

Expected: `Fresh challenge-bound account/runtime/UTC health joined to
protected Windows history. Manual workspace available; model not requested,
no native product grant bridge or production qualification.`

**F3, manual console (W007, model-free operation):**

```powershell
& $Client workspace-open $Active $Login
```

Expected: health runs first, then the menu shows `1 Read exact scoped
snapshot`, `2 Save completed scoped snapshot to new protected NTFS file`,
`3 Authenticated diagnostics`, `4 Explicit account interruption repair`,
`5 Fresh health` and `0 Cancel/close`, with the model disabled. Exercise 3, 5
and 0. Leave 1 and 2 to S1 and S3. Each choice starts its own authenticated
ceremony; the idle menu holds no lease.

**F4, interruption and recovery:**

1. Start `workspace-setup` or `workspace-repair`. After confirming, press
   Ctrl+C before the ceremony completes. Expected: `Workspace cancelled;
   uncertain account generation remains fenced for explicit recovery.`
2. Read the pending generation from `status host-deployment`, then run
   `& $Client workspace-recover $Active <GENERATION>`. Expected: `Exact
   original-controller exit and confined request revocation/drain observed.
   No account retry/adoption...`
3. Then run `& $Client workspace-repair $Active $Login` and a fresh
   `workspace-health`.

Expected: no automatic retry and no adopted partial account.

**F5, required refusals:**

- `& $Client status host-deployment | Out-File "$Evidence\F5\redirected.txt"`
  must refuse with `Hosted authority refused: The original interactive client
  must review and confirm directly.`
- Waiting more than 30 seconds at any `CONFIRM` prompt must expire the
  purpose. No effect follows.
- Typing a `CONFIRM` line with one wrong hex digit must refuse.
- `workspace-open` while health is incomplete must refuse with `Manual
  launcher refuses incomplete account health.`

Evidence: a console export and prompt screenshots for each step, and
`status host-deployment` before and after F4.

### P1 to P4: host protection and provider

Preconditions: I3 passed. Run the read-only checks from an elevated console.

**P1, protected admission (W005, W022):** record the inventory
`bitlocker.txt` and `tpm.txt`. Expected: every volume that holds
`%ProgramFiles%`, `%ProgramData%`, the service profile and the WSL swap and
VHDX files is `FullyEncrypted` with `ProtectionStatus On`, and the TPM is
present and ready. I2, I3 and F1 succeeded only in that state.

**P2, provider (W011):** with the service running, `status host-deployment`
reports commissioned custody. Read-only:

```powershell
certutil -csp "Microsoft Platform Crypto Provider" -key > "$Evidence\P2\pcp-keys.txt"
```

Expected: the machine key container
`LumaOS.HostedAuthority.v1.host.<installation>.signing` exists in the Microsoft
Platform Crypto Provider, plus its `.content.` counterpart when the content
domain is commissioned. Both are ECDSA P-256 keys created with export policy
0, and no software-provider key for the authority appears. Record key names
only.

**P3, suspended protection refused (decision 4 required):**

```powershell
Suspend-BitLocker -MountPoint 'C:' -RebootCount 0
Get-BitLockerVolume -MountPoint 'C:' | Select-Object MountPoint,VolumeStatus,ProtectionStatus
& $Client compute $Active <OPERATION> <PAYLOAD_FILE>      # or infer, as approved
Resume-BitLocker -MountPoint 'C:'
Get-BitLockerVolume -MountPoint 'C:' | Select-Object MountPoint,VolumeStatus,ProtectionStatus
```

Expected: `ProtectionStatus Off` while suspended. The new compute or
inference request refuses before any guest effect, while explicit read-only
`status` stays available. After the resume, `ProtectionStatus On` is
restored and a fresh request is admitted again. If the resume does not report
`On`, stop and escalate to the recovery-key custodian.

**P4, managed policy:** record `wsl-policy.txt` and the redacted `dsregcmd`
output. Expected: an absent signal never proves "unmanaged". A managed or
unknown state cannot create enterprise authorization. When the owner's policy
disables a WSL capability that the product needs, admission refuses.

Evidence: the read-only outputs, the console exports and screenshots of the
P3 refusal.

### M1 to M3: real compact inference (V16)

Preconditions: F2 passed. The release's inference profile is lab-only, so the
environment is `lab`. Use the runtime manifest and profile SHA-256 values from
the release record. For the 2026-11-03 `e9a11aa` package these are
`f4b0a49240ccbda3bb1d667ccf9e3a556f090b9dd8725b1319ac60486762e42a` and
`6625d600b1be72aebed54c3333b569a84d38ac2c898679c19d9119c097a3084c`, for the
model Qwen3-4B Q4_K_M
(`7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`, 2497280256
bytes) on llama.cpp b11100 CPU.

**M1, exact request:**

```powershell
New-Item -ItemType Directory -Path "$Evidence\M1" | Out-Null
$prompt = 'Summarize the purpose of a release checklist in one sentence.'
$utf8 = [Text.UTF8Encoding]::new($false)
$sha = [Security.Cryptography.SHA256]::Create()
$hex = { param([byte[]] $b) -join ($b | ForEach-Object { $_.ToString('x2') }) }
$random = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($random)
$nonce = & $hex $random
$promptSha = & $hex $sha.ComputeHash($utf8.GetBytes($prompt))
$json = '{"schema_version":1,"profile":"luma-windows-hosted-inference-v1","nonce":"' + $nonce +
    '","model_sha256":"<model-sha256>","runtime_manifest_sha256":"<runtime-manifest-sha256>",' +
    '"profile_sha256":"<profile-sha256>","prompt":"' + $prompt +
    '","prompt_sha256":"' + $promptSha + '","context_tokens":2048,"max_tokens":128}'
[IO.File]::WriteAllBytes("$Evidence\M1\request.json", $utf8.GetBytes($json))
& $Client infer $Active "$Evidence\M1\request.json"
```

The authority accepts only the exact canonical bytes, with no BOM and no
trailing newline. The prompt is embedded literally, so it must be printable
ASCII with no `"` or `\`. Do not use `ConvertTo-Json`: Windows PowerShell 5.1
escapes `'`, `<`, `>` and `&`, which makes the request noncanonical. The
prompt must be 1 to 4096 UTF-8 bytes and `max_tokens` 1 to 512. Use a fresh
nonce for every request.

Expected: the client confirms the exact request and prints bounded output
only after its receipt check. The whole run finishes inside the five-minute
purpose. The authority admits the run only if the guest reports the cgroup
`0::/lumahosted.slice/luma-hosted-inference.service` with `memory.max`
4831838208 and `memory.swap.max` 0, and only if Windows keeps the 1-GiB
low-water reserve. Record the wall time from confirmation to the receipt.
Repeat M1 five times and record every timing, not only the mean.

**M2, interruption:** start M1 and press Ctrl+C during generation. Then run
`& $Client infer-recover $Active <REQUEST_GENERATION>`, with the generation
taken from `status host-deployment`. Expected: `Closed exact inference
generation after original exit and confined drainage; head <hash>. No model
rerun or partial output adoption.`

**M3, enrolled-file inference:** after S2 has enrolled a file, run
`& $Client infer-enrolled-file $Active <INSTALLATION> <ROOT> <RELATIVE_PATH>
<BYTES> <SHA256> <RUNTIME_MANIFEST_SHA256> <PROFILE_SHA256> <MAX_TOKENS>`.

Expected: first, a read-only ceremony of at most 4096 bytes and 30 seconds
ends with `READ COMPLETED and its pipe CLOSED`. A separate `INFER <sha256>`
confirmation follows. Declining stops with no inference.

Every advertised tuple (CPU now; any later accelerator path) and every WSL or
driver change requalifies M1 to M3.

### S1 to S4: scoped ingestion (W013, W017)

Preconditions: F2 passed. OWNER owns a test file `source.txt` of at most
1 MiB under `C:\Users\OWNER\Documents`, with known bytes and SHA-256. The
native Admin can authorize Windows sources.

**S1, single-session read:**

1. Run `& $Client read-intent <INSTALLATION> C:\Users\OWNER\Documents source.txt
   <BYTES> <SHA256>`. It prints the intent SHA-256 and hex and accesses no
   source.
2. On the native appliance, the native Admin builds the UTC source
   configuration. It lists the installation, the transport hash and one
   `authorized_sources` entry with purpose `host-file-read` and that intent
   SHA-256. The Admin then runs the three commands below, in order. The
   `inspect` step runs under the finite Read grant from the native PAM
   ceremony.

   ```sh
   sudo luma-admin-control utc-windows-key-authorize-review <login> <config.json>
   sudo luma-admin-control utc-windows-key-authorize-inspect <login> <grant> \
       <config.json> <inspection-review-sha256>
   sudo luma-admin-control utc-windows-key-authorize <login> <grant> \
       <config.json> <mutation-review-sha256>
   ```

3. Run `& $Client read-enrolled-file` with the same five arguments, and
   confirm within 30 seconds.

Expected: an object, ancestor and ACL review appears before any data is read.
Delivery uses acknowledged 32-KiB chunks and a complete-hash receipt. No file
is saved or published.

**S2, persistent enrollment:**

- `file-enrollment-status <ID>`;
- `enrollment-intent create <ID> 1 <64 zeros> <REGISTRY_SOURCE> <JOURNAL_HEAD>
  <NOT_BEFORE_UTC_MS> <EXPIRES_UTC_MS> <INSTALLATION> C:\Users\OWNER\Documents
  source.txt <BYTES> <SHA256>`;
- native authorization under purpose `host-file-enrollment`;
- `file-enrollment-change <INTENT_HEX>`;
- `read-persistent-file <ID> 1 <ENTRY_SHA256> <REGISTRY_SOURCE> <JOURNAL_HEAD>
  <INSTALLATION> C:\Users\OWNER\Documents source.txt <BYTES> <SHA256>`.

Then supersede (generation 2) and revoke (next generation, both UTC bounds
`0`). Expected: each step needs its own fresh 30-second review. The old
generation refuses after supersession, and every read refuses after
revocation.

**S3, manual save:** from the F3 menu choose 2, or run
`& $Client save-enrolled-snapshot <INSTALLATION> C:\Users\OWNER\Documents
source.txt <BYTES> <SHA256> D:\LumaOS-evidence\snapshots\s3-<n>.txt`.
Expected: a new file that only the owner and SYSTEM can access, with a full
readback match. An existing target refuses.

**S4, negatives (each must refuse with no data delivered):**

- a junction or symbolic link in the source path;
- a hard-linked source;
- the source replaced, or its ACL changed, between review and read;
- one wrong byte count or hash digit;
- a OneDrive "online-only" placeholder;
- a file over 1 MiB;
- a source owned by USER2;
- a snapshot target on a volume without BitLocker protection;
- an expired UTC interval.

Build the junction and hard-link cases inside a scratch folder under
`D:\LumaOS-evidence\negatives`, using `New-Item -ItemType Junction` and
`New-Item -ItemType HardLink` as OWNER. Never build them in system folders.

Evidence: intents, the native authorization outputs (hashes only), console
exports, snapshot hashes and the refusal text for every negative case.

### L1 to L3: lifecycle (V03)

Preconditions: F2 passed, on mains power. Keep a tally sheet with one row per
cycle.

**L1, 100 sleep/resume cycles:** before each cycle, run
`status host-deployment` and start a `workspace-health`, or an `infer` with
`max_tokens` 512 on every tenth cycle. Put the host to sleep from Start, then
Power, then Sleep, and resume it after at least 30 seconds. Afterwards run
`status host-deployment` and a fresh `workspace-health`. Read the power log:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; Id=1} -MaxEvents 120 |
    Select-Object TimeCreated,Message | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\L1\resume-events.csv"
```

Expected: an operation in flight across sleep either completes or refuses
with an explicit recovery requirement. No lease, account generation or
inference generation stays pending without being named in `status`.
`*-recover` closes every pending generation exactly once.

**L2, forced stops:**

- Variant A: run `Stop-Service -Name LumaHostedAuthority -Force` during an
  in-flight `infer`, then `Start-Service` again.
- Variant B: run `Restart-Computer` during an in-flight `workspace-repair`.

Expected: after the restart, `status` names the interrupted generation and
recovery closes it with no adoption or rerun. A guest-only forced stop of the
service's slot has no supported command from OWNER's account. Record that
case as `blocked` until the product provides an Admin-only stop operation.

**L3, model-free operation:** with the model never requested, show that the
F3 menu (diagnostics, read and save) and keyboard-only navigation work. The
client exits when its console window is closed, and later `status` shows no
leaked lease.

Evidence: the tally sheet, the event CSVs, and `status` before and after each
tenth cycle.

### R1 to R4: resource coexistence and Windows headroom (W009, V04, QW04)

Preconditions: I1 passed, the declared workload and instrument are approved,
the other WSL distribution runs its workload, and no other user is signed in.

**R1, planner before and after:** in OWNER's account, run
`coexistence.ps1 -Samples 60 -ProductDistribution <slot name from I3>` before
the product starts and again after it stops. Expected:
`current-limit-fits` both times, with an unchanged `.wslconfig` hash and
inventory. While the service's WSL VM runs, a second `vmmemWSL` exists and
the planner must report `blocked-observation`. That fail-closed result is
expected and recorded; it is not a defect.

**R2, sampling under load:** while M1 runs five times back to back, sample
read-only once per second:

```powershell
1..600 | ForEach-Object {
    $os = Get-CimInstance Win32_OperatingSystem
    $vm = Get-Process vmmemWSL -ErrorAction SilentlyContinue |
        Select-Object Id,SessionId,WorkingSet64,PrivateMemorySize64
    [pscustomobject]@{ utc = (Get-Date).ToUniversalTime().ToString('o')
        free_kib = $os.FreePhysicalMemory; total_kib = $os.TotalVisibleMemorySize
        vms = ($vm | ConvertTo-Json -Compress) }
    Start-Sleep -Seconds 1
} | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\R2\samples.csv"
```

Expected: Windows available memory never falls below the 1-GiB
(1073741824-byte) running reserve. The authority starts inference only when
Windows reports at least 5905580032 bytes (5.5 GiB) available: the 4.5-GiB
guest inference budget plus that reserve. When the owner's declared
memory-pressure tool holds available memory below 5.5 GiB, a new `infer`
refuses with `Inference lacks observed Windows memory headroom` before the
model starts.

**R3, QW04, three 30-minute runs:** run the declared foreground workload
(typing into the declared editor and switching windows by the declared
script) while the product runs M1 continuously and the other distribution
runs its workload. Capture with the declared instrument. The default is
in-box Windows Performance Recorder:

```powershell
wpr.exe -start GeneralProfile -filemode
# ... 30 minutes of declared workload ...
wpr.exe -stop "$Evidence\R3\run-<n>.etl"
```

Extract the raw per-interaction acknowledgement latencies to CSV with the
declared analysis tool and its version. Expected, for each of the three runs:
input and window-switch acknowledgement P95 is at most 150 ms, and no
unresponsive interval is longer than 1 second. If no approved instrument
yields raw per-interaction latencies, record R3 as `blocked`.

**R4, no host OOM and no settings change:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\R4\resource-exhaustion.csv"
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Hang'} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message | Export-Csv -NoTypeInformation -Encoding ascii "$Evidence\R4\app-hang.csv"
```

Expected: no event during the run window. The `.wslconfig` hash, the
`wsl --list --verbose` output and the WSL policy query equal the I1 snapshot
(QW05). The service never edited a global WSL setting.

### C1 and C2: confinement (W021)

The confinement units start only with `ConditionSecurity=apparmor`. The
authority accepts a guest observation only when it names the expected
AppArmor profile (`luma-hosted-compute`, `luma-hosted-inference`,
`luma-hosted-workspace-bootstrap`) and the expected `lumahosted.slice` cgroup.

**C1, fail-closed without AppArmor:** on a stock WSL kernel, read from the
other distribution:

```powershell
wsl.exe -d Ubuntu -- cat /sys/module/apparmor/parameters/enabled
wsl.exe -d Ubuntu -- cat /sys/kernel/security/lsm
```

Then run a `compute` or `infer` request. Expected: AppArmor reads as disabled
or absent, and the request refuses with a confinement or profile mismatch. No
unconfined worker runs, and no reduced-security fallback is offered. This
proves fail-closed behavior, not enforcement.

**C2, enforcement (decision 5 required):** with the owner-provided
AppArmor-enforcing kernel in place, repeat M1, F2 and one `compute`. Expected:
the guest observations name the enforcing profiles, and the requests
complete. Then run the V05 adversarial cases from the release's security
test plan (prompt injection in the source file, generated code that tries
`/mnt/c`, Windows executable interop or networking). Each must produce zero
unauthorized effect. Without an enforcing kernel, record C2 as `blocked`.

Evidence: the kernel observation, refusal and receipt exports and the
adversarial case log.

### U1 to U4: W022 two-user proof (V05, V10)

Preconditions: OWNER and USER2 exist (decision 6). F2 and S2 passed for OWNER.
USER2 signs in with fast user switching while OWNER stays signed in.

**U1, second-user denial:** as USER2, run each of the following.

- `& $Client status host-deployment`
- `& $Client workspace-health $Active <OWNER login>`
- `& $Client read-enrolled-file` against OWNER's file
- `Get-ChildItem "$env:ProgramData\LumaOS-HostedAuthority"`
- `Get-ChildItem "$env:ProgramData\LumaOS-HostedGuests"`
- `Get-ChildItem C:\Users\OWNER\Documents`

Expected: every authority operation refuses because USER2 is not the
commissioned first Admin, and every folder listing is denied.

**U2, forged IPC:** as USER2:

```powershell
$p = [IO.Pipes.NamedPipeClientStream]::new('.', 'LumaOS.HostedAuthority.v1', [IO.Pipes.PipeDirection]::InOut)
try { $p.Connect(3000); $b = [byte[]](1..64); $p.Write($b, 0, $b.Length); $p.Flush() }
catch { $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
finally { $p.Dispose() }
```

Expected: either access is denied at connect, or the server drops the
malformed frame. OWNER's `status host-deployment` is byte-identical before
and after.

**U3, user switching:** start an OWNER `workspace-open` menu and an OWNER
`infer`, switch to USER2 and back, then repeat with sign-out. Expected:
USER2 sees no OWNER console, output or receipt. OWNER's client either
continues within its purpose or refuses with an explicit recovery. No
generation is left unrecovered.

**U4, data, swap and export locations (V10):** read-only, elevated:

```powershell
$paths = "$env:ProgramData\LumaOS-HostedAuthority", "$env:ProgramData\LumaOS-HostedGuests",
         "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Temp", 'D:\LumaOS-evidence\snapshots'
foreach ($p in $paths) { [pscustomobject]@{ path = $p; volume = (Get-Item -LiteralPath $p -Force).PSDrive.Root } }
Get-ChildItem -LiteralPath "$env:ProgramData\LumaOS-HostedGuests" -Recurse -Force -Filter *.vhdx | Select-Object FullName,Length
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Temp" -Force -Filter swap*.vhdx -ErrorAction SilentlyContinue |
    Select-Object FullName,Length
```

Expected: every product VHDX, swap file and snapshot file sits on a volume
that P1 showed as protected.

Per-user state and credentials: the current product admits one commissioned
first Admin per installation and has no ordinary-user state mapping. Record
the W022 clause "each Windows user shall receive separate state and
credentials" as `blocked` (implementation absent), even when U1 to U4 show no
unauthorized effect. Record the clause on authenticated manual recovery-key
export the same way unless the release under test provides that path.

Evidence: USER2 console exports, the pipe test output, OWNER status hashes
before and after, and the location and volume tables.

## Recovery and key-custody rules

- Keep lab and production trust roots separate. This runbook uses only the lab
  environment; the inference profile is lab-only.
- Never record a private key, a BitLocker recovery password, a PAM password or
  a native grant secret in evidence, chat, screenshots or the repository.
  Record key identifiers, public blobs and hashes only.
- The native Admin performs every UTC authorization personally on the native
  appliance. A Windows-side operator or agent never relays approval.
- Never resend an uncertain NV write or adopt an uncommitted policy. Use only
  the product's explicit `*-recover`, `*-abort` and `workspace-recover` paths,
  and only for the exact generation that `status` names.
- If P3's resume fails or the host requests BitLocker recovery, stop. The
  named custodian performs recovery outside the evidence capture and records
  only the custody event.
- Removing the service, its `%ProgramData%` state, the service-owned slot or
  the test accounts is a separate owner decision after evidence review. This
  runbook never deletes them.

## Evidence bundle structure

Keep raw evidence in the approved protected store, not automatically in Git.
Use an immutable run directory:

```text
GWIN0-W-<release-id>-<UTC-run-id>/
  authorization/
  inventory/
  I0/ I1/ I2/ I3/
  F1/ ... F5/
  P1/ ... P4/
  M1/ M2/ M3/
  S1/ ... S4/
  L1/ L2/ L3/
  R1/ ... R4/
  C1/ C2/
  U1/ ... U4/
  redacted/
  evidence-index.json
  evidence-index.sig
```

`evidence-index.json` must contain:

- the source commit, release ID, authority bundle hash, package manifest and
  rootfs hashes, and the model, runtime manifest and profile hashes;
- the host designation, Windows edition and build, WSL version, kernel
  version and TPM state, and the exact runbook revision (Git blob SHA-1 of
  this file);
- the operator, witness and reviewer, with UTC start and end times and the
  clock source;
- one record per row, with its requirement and test IDs, preconditions, the
  exact commands, the expected oracle, the observed result, the status
  (`pass`, `fail`, `blocked` or `not_applicable`), any defect ID and the
  hashes of its supporting files;
- raw distributions for M1 timings, R2 samples and R3 latencies, not only
  summaries;
- the redaction log, naming each removed field and its unredacted custody
  location; and
- an index signature made only after every referenced digest is final.

## Result and signoff policy

The release under test fails for any of the following:

- an unauthorized effect;
- secret disclosure;
- second-user access to OWNER state;
- a host OOM;
- an automatic WSL setting change;
- a reduced-security fallback;
- an adopted partial result;
- a lost acknowledged write.

Such a result cannot be waived into a pass.

| Decision | Pre-execution approval | Evidence review | Closure authority |
| --- | --- | --- | --- |
| Service install and commission (I2, I3) | Environment owner and release engineer | QA lead | Requirements and release owner |
| Protection fault (P3) | Environment owner and recovery-key custodian | Security lead; no secret in evidence | Requirements and release owner |
| WSL settings or kernel maintenance (decisions 3 and 5) | Environment owner, before and outside any row | Security lead | Environment owner |
| Inference rows (M1 to M3) | Inference lead and environment owner | QA and inference leads | Requirements and release owner |
| Isolation, confinement and two-user rows (C, U, S4) | Security lead and environment owner | Independent security reviewer plus QA | Requirements and release owner |
| Final GWIN0 disposition | Every row owner reports a status | QA, platform, release, inference and security leads | Requirements and release owner records the gate decision |

A reviewer records `blocked`, not `pass`, when any of these is absent: a
required host capability (BitLocker, TPM, AppArmor), a signed artifact, the
native UTC authority, a second Windows account, an approved instrument or a
product implementation. Development-host evidence stays development-only
even when every repository test passes.
