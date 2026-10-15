# Windows GWIN0 prerequisite observations

This new product-development lane is separate from the historical
`packaging/wsl` source-MVP launchers. It does not install a WSL distribution,
change the default distribution, edit global WSL settings, enable Hyper-V,
open a listener or enroll host folders.

Run in native Windows PowerShell under an execution policy that permits local
repository scripts:

```powershell
.\packaging\windows\test-preflight.ps1
.\packaging\windows\preflight.ps1 -StorageDrive D -DistributionName LumaOS-Dev -GuestMemoryGiB 12
```

The owner approved process-only RemoteSigned execution for development tests;
that approval does not override managed policy or authorize permanent changes.
The scripts do not alter execution policy themselves.

The probe writes JSON to stdout only. Exit zero means the observation completed,
not that installation is admitted: inspect `development_observations_passed`,
`blockers` and `pending_qualification`. Unknown capabilities remain unqualified.
Read-only inventory cannot prove host encryption, enterprise authorization,
worker confinement, nested virtualization, supported-release qualification or
compute acceleration. Host administrators, Windows and WSL/the hypervisor
remain trusted host components.

The proposed guest-memory check uses observed Windows available RAM plus an
8-GiB host planning reserve; swap is not counted. It neither reserves memory
nor changes WSL limits. A smaller constrained profile needs its own measured
budget and qualification; do not lower the reserve simply to obtain a pass.
Storage free space is observed, but full active/candidate/model/state/backup
and recovery capacity admission is not yet implemented by this first slice.

GWIN0 still needs signed independent packaging, authenticated launcher/bridge,
scoped Windows ACL-aware ingestion, actual compact inference and confinement,
resource/lifecycle coexistence and a complete qualified VM desktop proof.
The current Home host can support WSL development; the plan requires a separate
qualified Pro/Enterprise Hyper-V host for the full VM proof. Do not change the
host edition or enable virtualization features automatically.

See [the shared implementation plan](../../docs/G3_GWIN0_IMPLEMENTATION.md).
