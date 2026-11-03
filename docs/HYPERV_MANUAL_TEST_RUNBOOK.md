# Hyper-V manual test runbook (Profile V)

This runbook is for the owner. It covers preparing a Windows host, creating
the Profile V Hyper-V Generation 2 test VM from downloaded media, and the
manual checks for W030 to W033 in the
[Windows deployment requirements](Requirements/LLM_OS_Windows_Deployment_Requirements_Variation.md)
(lines 280, 286, 292 and 298). The scripts never install an optical drive or
read a physical disc. They take a downloaded `.iso` or `.vhdx`, check it
against `SHA256SUMS`, copy it next to the VM and attach the copy as a file.

**Expected outcome with the current image.** Candidate 19 is signed only with
the LumaOS laboratory key. That key is not in any Hyper-V Secure Boot template,
so the firmware should refuse the image. This is inferred, not yet observed,
because Hyper-V cannot run on the current host. Recording that refusal is the
first manual result. Secure Boot stays on: this runbook has no step that turns
it off and no reduced-security fallback. [Secure Boot trust](#secure-boot-trust)
lists the owner's options for an image that Hyper-V will start.

## 1. What the host needs

`check-hyperv-host.ps1` reads the host and prints JSON. It changes nothing. On
2026-11-03 it reported this for the development laptop. The evidence is in
`D:\LumaOS-builds\gwin0-hyperv-20261103-a\check-hyperv-host.json`, SHA256
`50f7249a04be173e6a25f639e4ddbb9c59ac811c79c485e5a6f89481bcc365db`.

| Check | Observed | Needed | Status |
| --- | --- | --- | --- |
| edition | Windows 11 Home Single Language | Pro, Enterprise or Education | **fail** |
| os_build | 26200 AMD64 | Windows 11 x64, 22621 or later | pass |
| hyperv_feature | `Microsoft-Hyper-V-All` absent | Enabled | **fail** |
| firmware_virtualization, slat, hypervisor_running | yes (the hypervisor runs for WSL2) | yes | pass |
| hyperv_management | no module, no VMMS | module present and VMMS running | **fail** |
| memory_total | 15.82 GiB | 12 GiB (8 GiB guest + 4 GiB Windows headroom) | pass |
| memory_available | 4.17 GiB | 10 GiB (guest + 2 GiB start margin) | **fail** |
| wsl_coexistence | WSL running, 12 GiB limit from `.wslconfig` | WSL stopped, or 24 GiB total | **fail** |
| logical_processors | 16 | vCPUs + 2 | pass |
| vm_storage | D: exFAT, 198.74 GiB free | NTFS with enough free space (see below) | **fail** |

The owner makes these changes. No script makes them.

1. **Edition.** Upgrade Windows 11 Home to Pro (Settings > System >
   Activation), then reboot. Home cannot run Hyper-V.
2. **Hyper-V.** From an elevated Windows PowerShell, run
   `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`,
   then reboot. This also installs the Hyper-V PowerShell module and VMMS.
3. **NTFS storage for the VM.** The VM needs an NTFS volume. D is exFAT and
   reports bad blocks, and C has about 15 GB free, so neither is suitable.
   For candidate 19 the volume needs **at least 137 GiB free**: the 128 GiB
   target VHDX, the 6.73 GiB ISO copy and 2 GiB of metadata. If the download
   also goes to that volume, add another 7 GiB. Without a downloaded image, the
   checker assumes a 16 GiB image and asks for 163 GiB. An internal SSD is
   best. A USB NTFS disk works, but it is slower and must stay attached. The
   target VHDX is dynamic, so the disk space is used as the guest writes.
4. **Memory at test time.** Run `wsl --shutdown` and close large
   applications, so that at least 10 GiB is available when the VM starts. With
   16 GB of RAM the VM and WSL cannot run together. 32 GB of RAM lets the VM
   run beside WSL's 12 GiB limit.
5. **Permission.** Run `-Apply` from an elevated prompt. Membership in Hyper-V
   Administrators (SID S-1-5-32-578) lets you use the Hyper-V cmdlets, but the
   vTPM step creates certificates in the LocalMachine store. That step may need
   elevation; this has not been verified.

**Memory policy (owner decision).** This tool needs total RAM of at least
guest + 4 GiB, and available RAM of at least guest + 2 GiB when the VM starts.
The WSL preflight in `packaging/windows/README.md` keeps an 8 GiB reserve on
*available* memory. To use that rule here, pass `-StartMarginGiB 8`. An 8 GiB
guest then needs 16 GiB available, which this 15.82 GiB host can never provide;
such a host needs 32 GB of RAM. The guest cannot go below 8 GiB: staging the
candidate-19 payload needs more than 6,732 MiB.

## 2. Get the media from a download location

The owner puts the candidate-19 export on a download location of their choice.
Agents never upload or publish it. The files come from
`D:/LumaOS-builds/native/20261028T162354Z-desktop`. That D disk reports bad
blocks, so copy them to sound storage first. A copy counts only if its
`SHA256SUMS` check passes. The test needs only two files:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `SHA256SUMS` | 1,069 | `d440805f8c8aabe69a7dfc852acabadbbdb57eb04ff19e587d59847ce85492bf` |
| `luma-native-lab-20260927-desktop-19.iso` | 7,225,784,320 | `a4fbfec8eb760ffae246eb85567c15e47314e89e300836cc0c7422fedef11ca5` |

The ISO row comes from the
[candidate-19 evidence record](../native/evidence/G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md)
(line 32). The `SHA256SUMS` hash was computed on 2026-11-03 from the export
copy on D. Its ISO, `.img`, `.img.zst` and `secureboot.cer` entries match that
record. It is the independent pin: it reaches the test host through this
repository, not through the download location. The `SHA256SUMS` file itself
proves only that the download is intact, not where it came from. The plan
reports this as `origin_authenticated: false`.

Download over HTTPS on the Hyper-V host. `curl.exe` comes with Windows 11, and
`--proto =https` keeps any redirect on HTTPS:

```powershell
$dl = 'E:\LumaOS-download\c19'   # any new folder; NTFS preferred
New-Item -ItemType Directory -Path $dl | Out-Null
curl.exe --fail --location --proto =https --output "$dl\SHA256SUMS" 'https://<download location>/SHA256SUMS'
curl.exe --fail --location --proto =https --output "$dl\luma-native-lab-20260927-desktop-19.iso" 'https://<download location>/luma-native-lab-20260927-desktop-19.iso'
```

You do not need to check the hashes by hand. The plan holds both files open
with no write or delete sharing and hashes them while they are held. It
refuses if any of these is true:

- the pin differs;
- the file is not listed in `SHA256SUMS`;
- the hash differs;
- the ISO lacks `CD001` at byte 32769.

## 3. Check, plan, apply

Run every command from the repository root in **Windows PowerShell 5.1**
(`powershell.exe`), not PowerShell 7. Under `pwsh` 7.6, the existing
`Luma.Preflight.psm1` fails to compile `WindowsHostProtection.cs`, and the
Hyper-V module loads it. Process-only `RemoteSigned` does not change the saved
execution policy. In the commands below, `E` is the NTFS volume for the VM.

**Host check (read-only, no elevation needed):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\check-hyperv-host.ps1 -StorageDrive E -ImageDrive E > "$dl\host-check.json"
```

Continue only when `host_capable` is `true`. `required_host_changes` lists the
remedy for every failing check.

**Plan (read-only, the default):**

```powershell
$pin = 'd440805f8c8aabe69a7dfc852acabadbbdb57eb04ff19e587d59847ce85492bf'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\plan-hyperv.ps1 `
  -Sha256SumsPath "$dl\SHA256SUMS" -Sha256SumsSha256 $pin `
  -ImagePath "$dl\luma-native-lab-20260927-desktop-19.iso" -StorageDrive E > "$dl\plan.json"
```

Review the plan. Check each of these values:

| Setting | Expected value |
| --- | --- |
| `media.sha256` | `a4fbfec8…11ca5` |
| `generation` | 2 |
| `fixed_memory_bytes` | 8 GiB, with `dynamic_memory` false |
| `processor_count` | 4 |
| `secure_boot_enabled` | true |
| `secure_boot_template` | `MicrosoftUEFICertificateAuthority` |
| `vtpm_enabled` | true, with `key_protector` `local` |
| `network_attached` | false |
| `integration_services_enabled` | empty |
| `checkpoint_type` | `Disabled` |
| `automatic_start` | `Nothing` |

`apply_admitted` must be `true` and `blockers` must be empty. `known_gaps`
lists the four open items in this runbook. They do not block apply.

These options are opt-in:

- `-SecureBootTemplate OpenSourceShieldedVM` picks the other template that is
  allowed. `MicrosoftWindows` is refused.
- `-SwitchName <name>` attaches one adapter, but only to a switch that already
  exists and is `Internal` or `Private`. `External` switches are refused, and
  no switch is created. The built-in `Default Switch` is `Internal` with NAT:
  it gives the guest outbound internet, and the LAN cannot reach the guest.
- `-EnableIntegrationService 'Heartbeat','Shutdown'` and similar enable named
  services. The names are English only.
- `-GuestMemoryGiB`, `-CpuCount`, `-InstalledDiskGiB`, `-VmRoot` (default
  `E:\LumaOS-VMs`) and `-Name` (default `LumaOS-Desktop-Lab`) set sizes and
  locations.

**Apply (elevated, only after reviewing the plan):** run the same command with
`-Apply` added, and redirect the output to `"$dl\apply.json"`. Apply first runs
fresh checks. It refuses if the plan has blockers, if a VM with that name
exists, or if the VM folder exists. It never replaces anything. Then it:

1. copies the ISO into `<VmRoot>\<Name>\Media\`, hashing while it writes and
   re-hashing the closed copy;
2. creates a dynamic VHDX in `<VmRoot>\<Name>\Disks\`;
3. runs `New-VM -Generation 2 -NoVHD`;
4. sets checkpoints off, automatic start to Nothing and automatic stop to
   ShutDown;
5. sets fixed memory and the vCPU count;
6. removes every network adapter, then adds the opted-in one if there is one;
7. disables every integration service that was not opted in;
8. attaches the target VHDX and exactly one DVD drive, which holds the ISO
   copy;
9. runs `Set-VMFirmware -EnableSecureBoot On` with the template, and sets the
   DVD as the first boot device;
10. runs `Set-VMKeyProtector -NewLocalKeyProtector` and `Enable-VMTPM`;
11. reads every setting back.

The VM is not started. If a step fails, apply stops. It deletes nothing it
created, and the error lists what it created along with the cleanup commands.

## 4. First boot (owner)

Run the [initrd driver check](#5-initrd-driver-check) first. It uses WSL, so
do it before stopping WSL. Then:

```powershell
wsl --shutdown
Start-VM -Name 'LumaOS-Desktop-Lab'
vmconnect.exe localhost 'LumaOS-Desktop-Lab'
```

With candidate 19, expect the Hyper-V firmware to refuse the DVD. The
**Virtual Machine Boot Summary** typically shows *"The signed image's hash is
not allowed (DB)"* for `SCSI DVD`, then *"No operating system was loaded"*.
The exact wording may differ by host build. Take a screenshot. That turns the
inferred refusal into an observed result.

The integration services are disabled, so `Stop-VM` cannot ask the guest to
shut down. Stop the VM from inside the guest. At the firmware screen, use
`Stop-VM -Name 'LumaOS-Desktop-Lab' -TurnOff`, which is a hard power-off and
is safe there because nothing is running.

The optical initrd needs **exactly one CD-ROM-class device**. Apply attaches
one DVD drive, and the read-back checks that. Do not add a second one.

## 5. initrd driver check

On Gen2 VMs, the DVD and the disks sit behind the synthetic SCSI controller,
and there is no i8042 keyboard. To see the disc and accept keyboard input
before switch-root, the initrd needs `hv_vmbus`, `hv_storvsc` and
`hyperv_keyboard`. Keyboard input before switch-root is where a LUKS2
recovery key is typed.

`native/image/assemble.py` (lines 645 to 648) builds one initrd with
`dracut --no-hostonly`. Its `--add-drivers` list names `virtio` and optical
drivers, not Hyper-V ones. Generic `dracut` may still include the Hyper-V
modules, but that is unverified. The same initrd goes into all four UKIs:
slots `a`, `b`, `live` and `optical` (lines 668 to 680). Checking
`slot-a.efi`, which sits in the ISO root, therefore also covers the optical
boot.

Check in an interactive WSL Ubuntu shell. Type the commands at the shell
prompt; do not pass them through `wsl.exe -- ...`. `lsinitrd` comes from
`dracut-core`, and `bsdtar` from `libarchive-tools`.

```sh
mkdir -p ~/c19-initrd && cd ~/c19-initrd
bsdtar -xf /mnt/e/LumaOS-download/c19/luma-native-lab-20260927-desktop-19.iso slot-a.efi
objcopy -O binary --only-section=.initrd slot-a.efi initrd.img
lsinitrd initrd.img | grep -E 'hv_|hyperv'
```

If you see `hv_vmbus.ko*`, `hv_storvsc.ko*` and `hyperv_keyboard.ko*`, the
modules are present. Built-in drivers do not show up there; check the kernel
config for `CONFIG_HYPERV*=y`. If the modules are missing, the next image must
add them. That is a change to the native image pipeline, which belongs to the
pipeline owner. Save the output as evidence.

## 6. W030 to W033 checks

| Requirement | Check | Status with candidate 19 |
| --- | --- | --- |
| **W030** (line 280): Gen2, Ubuntu guest kernel, virtual UEFI, complete desktop, guest recovery, edition and virtualization checks, ISO | `Get-VM` shows Generation 2; the host check covers the edition and virtualization; the ISO is the media | Gen2, UEFI and the host checks can be shown. The desktop and recovery are blocked by Secure Boot trust. |
| **W031** (line 286): explicit CPU, memory, disk and network limits; Windows headroom; fixed memory first; sharing opt-in; no public service | `Get-VMMemory` (dynamic off, 8 GiB), `Get-VMProcessor`, `Get-VMHardDiskDrive`, `Get-VMNetworkAdapter` (none), `Get-VMIntegrationService` (all off) | Can be shown from the read-back in `apply.json`. |
| **W032** (line 292): verified guest boot, LUKS2 and recovery credentials tested on the virtual firmware; a working display is not GPU certification | Boot with Secure Boot on; install; LUKS2 unlock; enter the recovery key at the initrd prompt | Blocked: the firmware refuses the lab-signed loader. The Hyper-V synthetic display proves nothing about CUDA, NPU or passthrough. |
| **W033** (line 298): no credentials or machine identity in templates; new identities on first boot and cloning; checkpoints are not backups | `Get-VM \| Select CheckpointType, AutomaticCheckpointsEnabled`; the VM is created fresh and not cloned; each VM gets a new `.vmgs` and vTPM | Checkpoints are disabled. Cloning is not tested. |

## Secure Boot trust

The image boots its laboratory-signed systemd-boot and UKIs directly, with no
shim and no MOK. Hyper-V gives each VM a fixed template db, and client Hyper-V
has no supported way to enroll a custom db certificate such as
`secureboot.cer`. These are the owner's options. Each one is a decision for
the owner and the native image pipeline. None of them is implemented here.

- **A. A Microsoft-signed distribution shim, plus MOK.** A distribution shim
  starts systemd-boot, and `secureboot.cer` is enrolled through MokManager at
  the VM console.
  - Cost: the image's ESP layout changes, every VM needs a manual enrollment,
    and the image depends on that distribution's shim and SBAT level.
  - The candidate-19 record (line 186) says MOK enrollment does not replace
    trusting the directly booted image, so this is a design change.
- **B. Our own shim through shim-review,** signed by the Microsoft UEFI CA
  2023.
  - Cost: an EV code-signing certificate, a Partner Center account, and weeks
    to months of public review.
  - Microsoft stopped signing with the 2011 UEFI CA when it expired in June
    2026, so the host's template db must contain the 2023 CA. Check this on
    the Pro host.
- **C. Another hypervisor that can enroll a custom db.** Examples are
  QEMU/KVM with OVMF, which already ran the signed candidate-19 optical
  smoke, or VirtualBox 7 with custom NVRAM keys.
  - Cost: this does not meet W030's Hyper-V target. W030 also requires a
    separate exact-version certificate before VirtualBox or VMware can be
    advertised.

**PCR7 and LUKS2.** Installed sealing binds PCR7 and a signed PCR11 policy
(`rust/luma-platform/src/sealed_credential.rs`, lines 334 and 335). PCR7
measures the Secure Boot state and db, so it changes when the template or the
boot chain changes. A shim chain adds its own PCR7 events. After any such
change, the data needs the recovery credentials until the sealing is rebuilt.
Test recovery before you rely on TPM unlock.

**vTPM custody.** `-NewLocalKeyProtector` wraps the vTPM state with the host's
`UntrustedGuardian` certificates in `Cert:\LocalMachine\Shielded VM Local
Certificates`. Every VM on this host that uses a local key protector shares
them.

- Any host administrator can unwrap the vTPM.
- If those certificates are lost, for example by reinstalling Windows, the vTPM
  cannot be recovered, and neither can TPM-sealed guest data without the
  recovery credentials.

This is not independently commissioned custody. Do not export the certificates
for this lab test.

## 7. Evidence to return

Put these files in one folder, for example `D:\LumaOS-builds\hyperv-manual-<yyyymmdd>\`,
and keep a second copy on sound storage:

- `host-check.json`, from before and after the host changes;
- `plan.json` and `apply.json`;
- the output of
  `Get-VM`, `Get-VMFirmware`, `Get-VMSecurity`, `Get-VMMemory`, `Get-VMProcessor`,
  `Get-VMNetworkAdapter`, `Get-VMIntegrationService`, `Get-VMHardDiskDrive` and
  `Get-VMDvdDrive`, each for `-VMName LumaOS-Desktop-Lab` and each piped to
  `Format-List *`;
- a screenshot of the Boot Summary;
- the last 50 events from the `Microsoft-Windows-Hyper-V-Worker-Admin` and
  `Microsoft-Windows-Hyper-V-VMMS-Admin` logs (`Get-WinEvent`);
- the output of the initrd driver check;
- `Get-FileHash` of the downloaded ISO after the test, to show it did not
  change.

## 8. Cleanup (owner, elevated)

```powershell
Stop-VM -Name 'LumaOS-Desktop-Lab' -TurnOff   # only if it is not already Off
Remove-VM -Name 'LumaOS-Desktop-Lab' -Force
Remove-Item -LiteralPath 'E:\LumaOS-VMs\LumaOS-Desktop-Lab' -Recurse
```

`Remove-VM` leaves the files in place. The `Remove-Item` command deletes the
VM configuration, the `.vmgs` file (which holds the vTPM state), the target
VHDX and the ISO copy. Leave the `Shielded VM Local Certificates` alone: other
VMs may depend on them, and removing them is a separate owner decision.

## Script tests

These suites run with mocked Hyper-V cmdlets. They need no Hyper-V and change
no host state. Run them in Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\test-hyperv-deploy.ps1 -WorkRoot D:\LumaOS-builds
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\packaging\windows\test-hyperv-plan.ps1 -WorkRoot D:\LumaOS-builds
```
