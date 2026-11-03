# GWIN0 package owner test note, 2026-11-03

This note is for the owner's own installed and manual tests of the refreshed
profile-W package. The agents built and inspected the package. They did not
import, register, launch or sign it, and they did not upload it anywhere.

## The package

| Item | Value |
|---|---|
| Release ID | `luma-wsl-dev-g3-gwin0-integrated-20261103` |
| Source cut | `ce84c8c3d014e80864ca2538df333092079bbd96`, the local `feature/g3-functional-beta` head: the `ae16cde` merge of `feature/g3-gwin0-beta` `a5a5bc7` (read-only coexistence planner, Hyper-V download tooling) plus the `ce84c8c` release-inventory fix |
| Record | [combined_workspace_inference_2026-11-03.json](combined_workspace_inference_2026-11-03.json) |
| Location on D | `D:\LumaOS-builds\gwin-integrated-package-20261103-ce84c8c-J2BhtOSg-public\package` |
| `rootfs.tar` | 2,636,566,528 bytes, SHA-256 `14699de8367fd2f962335d5c67bcb71022bc569a0ad7b0392c49b89e6ede13f0` |
| `manifest.json` | 14,863 bytes, SHA-256 `0ab2bb43951a4e90d083a29d24c045f371ce4fe4ca29ade3375e83718271646f` |
| Archive | 225 members, 91 publisher-required files |
| Inference profile | profile SHA-256 `458f229f4763df7323ad602535621425ec10b543d16db17e8f273e569ffeda4f`, runtime manifest SHA-256 `1130d69b9e2aabce6530500adec0f3c663f5da7c342c5c1d416000eb3f65a817` |
| Windows tools | `packaging\windows` at the source cut, including `validate-package.ps1`, `preflight.ps1` and `coexistence.ps1`; a copy is in `D:\LumaOS-builds\gwin-integrated-package-20261103-ce84c8c-J2BhtOSg-public\source\packaging\windows` |

The public directory one level above the package also holds `SHA256SUMS`. It
names the same two files under build-container paths
(`/evidence/integrated-package/...`), so compare the hashes, not the paths.
The 2026-10-31, 2026-10-27 and 2026-10-20 packages remain on D and are
unchanged.

The package is unsigned, and this refresh produced only the two package
files. It did not produce the hosted authority bundle
(`Luma.HostedAuthority.exe` and its three DLLs), a package signature, trust
anchor, release policy, time attestation or a lab-signed release description.
A hash that arrives through the same channel as the download does not
authenticate the package. Compare against the record in the repository,
obtained separately.

`packaging\wsl\install.ps1` and `launch.ps1` are the older Ubuntu developer
path. They do not install this package.

## Installing from a downloaded location

Nothing here assumes optical media or the build drive. How the files are made
downloadable is the owner's choice. None of these steps has been run by an
agent. The layout follows `docs/gates/gwin0/MANUAL_QUALIFICATION_RUNBOOK.md`
(section "Download layout and conventions"), which requires a new, empty
folder on a fixed local NTFS volume. Network shares, removable drives,
cloud-synced folders (OneDrive and similar) and recalled or offline
placeholders are out of scope. This host's D drive is exFAT, so it does not
qualify as the download location; check free space on the NTFS volume you use
(about 2.7 GB for the download, and an unmeasured amount for the imported
virtual disk).

1. Create the folder and download into it:

   ```powershell
   $Release  = 'luma-wsl-dev-g3-gwin0-integrated-20261103'
   $Download = "<NTFS drive>:\LumaOS-downloads\$Release"
   $Tools    = "$Download\tools"
   ```

   Put `manifest.json` and `rootfs.tar` in `$Download\package` (that folder
   holds nothing else) and the `packaging\windows` folder from the source cut
   in `$Tools`. A LumaOS checkout at `ce84c8c` can serve as `$Tools` instead.

2. Check sizes, hashes and file attributes against the table above, as in the
   runbook's row I0:

   ```powershell
   Get-ChildItem -LiteralPath "$Download\package" | Select-Object Name, Length
   Get-FileHash -Algorithm SHA256 -LiteralPath "$Download\package\rootfs.tar", "$Download\package\manifest.json"
   Get-ChildItem -LiteralPath $Download -Recurse -Force | Select-Object FullName, Attributes, Length
   ```

   No file may carry a `ReparsePoint`, `Offline`, `RecallOnOpen` or
   `RecallOnDataAccess` attribute.

3. Validate the content without importing it. Downloaded scripts carry a Mark
   of the Web, which `RemoteSigned` blocks. Following the runbook, start each
   downloaded tool in its own process with `-ExecutionPolicy Bypass` (or
   `Unblock-File` it after the hashes match, as a recorded decision). Never
   change the machine or user execution policy.

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Tools\validate-package.ps1" -PackageDirectory "$Download\package"
   ```

   This is the same `Test-LumaWslPackage` inspection the record pins. Expect
   `structure_valid` and `content_valid` true, 225 members and 91
   required files, and `package_authenticated`, `runtime_qualified` and
   `product_installation_admitted` false. It does not extract, import or run
   anything.

4. Optional, read-only: observe WSL coexistence before the import.

   ```powershell
   wsl.exe --list --verbose
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Tools\coexistence.ps1" -ProductDistribution LumaOS-GWIN0-20261103 -Samples 10
   ```

   It never writes `.wslconfig` or stops WSL. On this development host it
   returned `no-feasible-limit` on 2026-11-03 (runbook, "Purpose and evidence
   boundary").

5. Development import, as the owner only. This is not the runbook's
   qualified installation: row I3 imports through the hosted authority and
   needs the signed release that this refresh did not produce. A manual
   import registers a new WSL distribution for the signed-in Windows user.
   Use a name that starts with `LumaOS-`, which `preflight.ps1` and
   `coexistence.ps1` accept, and never reuse or replace `Ubuntu`, which hosts
   the build daemons:

   ```powershell
   wsl.exe --import LumaOS-GWIN0-20261103 <NTFS install folder> "$Download\package\rootfs.tar" --version 2
   ```

6. The package's `/etc/wsl.conf` asks for systemd, no automatic drive mounts,
   no Windows interoperation, no Windows PATH, and the default user `nobody`
   (UID 65534). A manual `wsl --import` does not make the
   `WslConfigureDistribution(65534, 0)` call that the hosted authority's own
   import makes, so record the configuration actually observed. For example:

   ```powershell
   wsl.exe -d LumaOS-GWIN0-20261103 --exec /usr/bin/id
   wsl.exe -d LumaOS-GWIN0-20261103 --exec /usr/bin/cat /usr/lib/luma/platform.json
   wsl.exe -d LumaOS-GWIN0-20261103 -u root --exec /usr/bin/systemctl --failed
   ```

   `nobody` has `/bin/false` as its shell, so use `--exec` rather than a shell
   command line. `platform.json` should name the release ID above, profile `W`
   and schema 3.

7. To remove it afterwards: `wsl.exe --unregister LumaOS-GWIN0-20261103`. This
   deletes that distribution and its virtual disk, but not the downloaded
   files.

## Manual GWIN0 qualification that remains the owner's

None of the following is established by this package, its inspection or its
software tests. The owner-run procedure is
`docs/gates/gwin0/MANUAL_QUALIFICATION_RUNBOOK.md` at the source cut: the six
owner decisions, then rows I0 to I3, F1 to F5, P1 to P4, M1 to M3, S1 to S4,
L1 to L3, R1 to R4, C1 and C2, and U1 to U4. Read it in full first. In brief:

1. Prerequisites this refresh does not supply: a designated qualified host
   (a BitLocker-capable Windows 11 edition with TPM 2.0; this Windows 11 Home
   development host does not count), the hosted authority bundle, the package
   signature and trust anchor, release policy, time attestation and lab-signed
   release description (row I0), a commissioned native UTC authority, and the
   two manually created Windows accounts.
2. Service installation, commissioning, release review, import and activation
   through the hosted authority (I2, I3), with the owned slot read back as
   default UID 65534 and flags 0.
3. First launch, TTY/PAM account setup, authenticated health, the manual
   workspace, interruption recovery and the required refusals (F1 to F5).
4. Host protection and the TPM key provider, including the one approved
   BitLocker suspend/resume fault (P1 to P4).
5. Real compact inference with the packaged Qwen3-4B model, interruption and
   enrolled-file inference (M1 to M3). Use the inference profile and runtime
   manifest SHA-256 values in the table above for this package; the runbook
   at `ce84c8c` quotes the 2026-10-31 package's values, and later revisions
   quote these.
6. ACL-aware scoped ingestion and its negative cases (S1 to S4).
7. Lifecycle: sleep/resume cycles, forced stops and model-free operation (L1
   to L3).
8. Resource coexistence and Windows headroom (R1 to R4). R1 runs
   `coexistence.ps1`, which is included at this cut.
9. Confinement (C1, C2). The current WSL kernel
   (`6.18.33.2-microsoft-standard-WSL2`) reports AppArmor `N` and no LSM
   interface, so C1 can show fail-closed refusal but C2 needs an
   owner-provided AppArmor-enforcing kernel (decision 5).
10. The W022 two-user proof (U1 to U4).

A qualified VM desktop proof is profile V, covered separately by
`docs/HYPERV_MANUAL_TEST_RUNBOOK.md`; this Windows Home host does not support
Hyper-V. Native Ubuntu G3 (profile N) image, boot, security, recovery and
hardware acceptance are separate deliverables and are not covered here.
