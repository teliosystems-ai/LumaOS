# Windows 11 / WSL2 developer path

The supported Windows route runs Luma OS inside Ubuntu 24.04 on WSL2. The PowerShell helpers do **not** install WSL, create a distribution, request administrator rights, change networking, or enable a background service.

## Prerequisites

From an administrator-approved Windows setup, WSL2 and Ubuntu 24.04 must already exist. Installation, if authorized by the machine owner, is normally initiated separately:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart/sign-in requirements and corporate device policy are outside Luma OS.

## Install for the WSL user

From PowerShell in the repository:

```powershell
.\packaging\wsl\install.ps1
```

The script verifies the named distribution and invokes the unprivileged Linux user installer. It refuses to overwrite an unmarked install. For a reviewed replacement of the same version:

```powershell
.\packaging\wsl\install.ps1 -Upgrade
```

## Launch

```powershell
.\packaging\wsl\launch.ps1
```

Arguments after the recognized parameters are passed to Luma OS. The process runs inside WSL and binds to loopback. Modern WSL commonly forwards loopback to Windows, but host policy and WSL configuration can affect browser access.

## Boundaries

- Use Linux paths inside the WSL distribution for the strongest documented folder-grant behavior.
- Windows-mounted paths under `/mnt` have different metadata and permission semantics.
- No native Windows service, installer, filesystem security parity, VM image, dual-boot support, or production certification is provided.
- Model runtimes and weights are external and must be installed/licensed separately by the operator.
