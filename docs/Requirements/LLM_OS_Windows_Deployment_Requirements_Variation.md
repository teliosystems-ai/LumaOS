# LLM OS Windows Deployment Requirements Variation

Native installation dual boot WSL 2 and virtual machines

Prepared for Hakim Mosleh and the LLM computer engineering team  
Variation VAR WIN 01 | Version 1.0 | 19 September 2026  
Status: Proposed engineering variation for implementation

## 1 Decision and feasibility

The Ubuntu based LLM OS can be delivered on an existing Windows computer as a WSL 2 distribution or as a complete Linux virtual machine. It can also be installed directly on hardware, either as the only operating system or alongside Windows with a boot menu. These are four deployment profiles of the same product, sharing the LLM services, skills, artifact model and policy contracts.

The current Option A specification does not yet define a supported Windows hosted edition. Its production design assumes an Ubuntu kernel, a Wayland desktop session, signed boot assets, encrypted Linux data and A/B root slots. That bootable image cannot simply be installed as an ordinary Windows application or imported unchanged into WSL. A WSL package needs a separate filesystem image and platform adaptation. Microsoft supports custom distributions, including the current .wsl packaging format and tar import route. [E01, E02]

This variation adds a Windows delivery program while retaining native installation. WSL 2 is the recommended first Windows experience for users who want LLM workflows alongside their existing applications. A full VM is the appropriate route for the complete LLM OS desktop and guest boot behavior. Dual boot provides direct hardware access, but requires restarting to switch operating systems.

| Profile | User experience | Control boundary | Delivery artifact |
|---|---|---|---|
| N Native | LLM OS is the computer desktop | Linux controls the qualified hardware | Signed bootable ISO or USB image |
| D Dual boot | Select Windows or LLM OS at startup | Each OS controls hardware while running | Native image with a coexistence installer |
| W WSL 2 | LLM workspace runs alongside Windows apps | Windows controls host boot, desktop and physical devices | Signed Windows installer plus .wsl and importable root filesystem |
| V Virtual machine | Complete LLM OS desktop in a window or full screen | Linux controls virtual hardware; Windows controls the host | ISO and a qualified Hyper V Generation 2 VHDX template |

WSL 2 runs Linux through a managed virtualized environment. It is not a replacement for the Windows kernel. WSLg integrates Linux application windows into Windows; Microsoft explicitly distinguishes this from a full Linux desktop. The W profile therefore presents the conversational workspace as an application window. [E03, E04]

The core outcome driven experience remains available in every profile: describe a task, create editable artifacts, classify files, search by meaning and continue a workflow without manually choosing a separate application for each step. Deterministic document engines, adapters and storage services still perform the underlying operations. Automatic organization covers enrolled locations and declared formats; it does not imply unrestricted access to every file on the computer.

## 2 Source baseline and change control

### Controlling documents

| Ref | Existing document | Version and use |
|---|---|---|
| B1 | LLM Based Operating System Engineering Specification | Version 1.0, 10 September 2026. Original architecture and FR01 to FR60. |
| B2 | Ubuntu Based LLM Operating System Engineering Requirements | Version 2.0, 13 September 2026. Controlling Option A baseline: A001 to A140, Q01 to Q20 and T01 to T62. |

B1 file: LLM_OS_Feasibility_HLD_LLD_Engineering_Requirements.docx

B2 file: Option_A_LLM_OS_Functional_Requirements_Development_Testing_4B_to_400B.docx

B2 Section 1 makes version 2 authoritative for Option A where earlier documents left platform decisions open. This variation references B2 requirements by their actual IDs and B1 requirements where they explain the original intent. It is a separate addendum; it does not renumber or replace the original documents.

On adoption, the precedence for the added deployment profiles is this variation, then B2, then B1. The changes in Section 6 are limited to their stated profiles. All other applicable baseline obligations remain mandatory. The existing A1, A2 and A3 release triggers remain: this variation does not make local 400B inference or cluster service mandatory on a Windows laptop.

W001 to W044 are new requirements. Their profile tags define applicability; their references identify obligations reused or adapted. V01 to V18 are additional verification procedures, separate from the existing T series. Every shall statement is mandatory within its profile. All hardware quantities and new timing thresholds are proposed engineering targets, not measured results or vendor minimums.

### Existing requirements retained across profiles

The model catalog and inference contracts A009 to A018, resource accounting and admission A019 to A040, gateway and scheduling A041 to A048, skills and workflows A049 to A056, artifact contracts A057 to A064, content outputs A068 to A072, portability A077, policy A079 to A086, and operations A093 to A100 are reused, subject to their original release triggers. Host boundaries require additional enforcement but do not weaken these contracts. A003, A006, A082 to A085, A109 and A131 to A140 remain central to offline delivery, identity, signing, maintenance and recovery.

A029, A038, A048, A072, A076, A078, A087 to A092, A117, A119 to A130, A136, A137 and A139 retain their original conditional release scope. A WSL or VM desktop is not automatically an A2 large model server or A3 cluster node. All baseline requirements not expressly varied in Section 6 are inherited whenever their original scope applies.

## 3 Architecture and supported configurations

### Shared services and deployment adapters

The common Ubuntu userland shall retain the planner, authenticated inference gateway, model manager, resource ledger, policy broker, workflow journal, skill supervisor, artifact service and rebuildable index. B2 Sections 3, 7 and 10 remain the service and portability foundation. The platform adapter gains native Linux, WSL and VM implementations; dual boot uses the native implementation with additional installation and recovery logic.

| Component | Native and dual boot | WSL 2 | Full VM |
|---|---|---|---|
| Kernel and boot | Qualified Ubuntu kernel and product boot chain | Qualified Microsoft WSL kernel under Windows | Qualified Ubuntu guest kernel and virtual UEFI |
| Shell | Product Wayland session | Workspace window through WSLg; qualified local web UI fallback | Product Wayland session through virtual display |
| Hardware policies | Allowlisted physical device operations | Guest limits and host reported capabilities | Guest limits and assigned virtual devices |
| Windows file integration | Optional offline import when safely mounted | Required scoped Windows file bridge | Same bridge when host folder integration is enabled |
| Updates | Existing signed A/B root design | Signed candidate distribution and controlled state migration | Guest A/B root design plus template maintenance |
| Trust root | Firmware and Linux boot chain | Windows, WSL runtime and product signatures | Host hypervisor and guest verified boot |

The Windows companion shall consist of a user session launcher, folder event collector, narrowly scoped file broker and recovery interface. Services run with the signed in user's authority by default. Administrator elevation is limited to explicit prerequisite installation or other approved privileged operations. The companion does not expose arbitrary PowerShell or a general host command execution endpoint.

The local bridge contract shall carry a Windows security identifier, mapped product principal, capability ID, operation, file identity, expected version or hash, idempotency key, deadline and correlation ID. The broker rechecks Windows access controls at execution time and returns a durable receipt or typed failure. Cross boundary IPC shall authenticate both ends; a localhost address alone is insufficient authentication.

Extend B2 ReleaseTuple with deployment_profile, host_OS_edition_build, WSL_version, WSL_kernel_digest, hypervisor_version, virtual_firmware_profile, host_driver_version, companion_digest, sandbox_profile_digest and capability_matrix_digest. Fields that do not apply shall be explicitly marked not applicable. Ubuntu kernel fields shall identify a guest kernel only where one exists; the WSL record must not falsely identify an Ubuntu kernel as the running kernel.

### Initial support policy and sizing

Initial Windows qualification targets supported Windows 11 x64 Home and Pro or Enterprise releases. WSL 2 is available on Home; the full Hyper V role has different edition requirements. Qualify Hyper V on Pro or Enterprise first. Do not require a Home user to obtain Pro merely to use WSL. Other hypervisors and Windows on ARM are separate qualification work. [E04, E10]

| Profile | Initial engineering configuration | Release condition |
|---|---|---|
| N and D | Retain B2 certified consumer configurations | Full native tests plus D coexistence tests |
| W compact | 32 GiB host RAM, 12 to 16 GiB guest budget, 4 to 6B model | Host reserve, actual loading peak and Q02 must pass |
| V compact | 32 GiB host RAM, 16 GiB guest RAM, 4 virtual CPUs | CPU correctness first; Q02 required for interactive certification |
| W or V constrained | 16 GiB host with a measured compact configuration | Limited evaluation only until the complete declared workload passes |
| Larger specialists | Capacity determined by B2 admission estimates and actual measurements | No certification inherited from physical RAM size alone |

For the 32 GiB examples, initially reserve at least 8 GiB for Windows and ordinary host activity; include other VMs and WSL distributions in the remaining budget. Treat this as a planning floor to validate, not an OS reservation guarantee. Disk preflight shall calculate active and candidate system images, model packs, state migration copies, user quota, backup staging and a recovery reserve. An 80 GiB free space lab target is a starting point for compact testing, not a substitute for the calculated requirement.

CPU inference is the portable qualification path. A compatible NVIDIA GPU is an initial WSL acceleration target; it requires a qualified Windows driver and Linux userspace runtime, without installing a Linux display driver inside WSL. WSL CUDA has specific memory and telemetry limitations. A usable virtual display does not prove compute GPU or NPU access. AMD, Intel, NPU, multi GPU and VM passthrough combinations require their own certificates. [E08]

## 4 New deployment requirements

### Product packaging and capability contracts

#### W001 Deployment selection

Profiles N D W V. The product shall offer all four installation profiles and explain whether Windows remains running or a restart is required. The selected profile shall be visible in setup, settings and diagnostics. Native and dual boot shall use the same service release as the corresponding Windows editions.

References: B2 A001, A097, A101, A102; B1 FR01, FR03. Verification: V01 and T45.

#### W002 Shared core and profile adapters

Profiles N D W V. Builds shall share versioned APIs, artifact schemas, model manifests and skill contracts. Host specific boot, storage, device and UI behavior shall reside in explicit adapters. Common workflows shall produce equivalent artifact identities and effect semantics across profiles; profile differences shall be declared in the capability contract.

References: B2 A049, A057, A077, A102; B1 FR09 to FR31. Verification: V02 and T40.

#### W003 Signed release artifacts

Profiles N D W V. The release shall produce the native ISO, WSL root filesystem and .wsl package, signed Windows installer and companion, and qualified VM template from a pinned build manifest. Offline bundles shall include the verified compact model and all dependencies for declared offline workflows, with redistribution terms and component notices recorded.

References: B2 A003, A009, A017, A097, A109, A131; B1 FR05, FR44. Verification: V01, V18 and T49.

#### W004 Capability negotiation

Profiles N D W V. DescribePlatform shall report each capability as available, unavailable or unqualified, with reason, controlling authority and certificate reference. It shall distinguish physical and virtual devices, Windows hosted inference and remote inference. Unsupported hardware actions shall return a typed unsupported result before execution.

References: B2 A011, A012, A020, A073, A074, A100; B1 FR46, FR50. Verification: V02 and T39.

### WSL installation and lifecycle

#### W005 WSL prerequisite checks

Profile W. Setup shall verify Windows edition and build, x64 architecture, virtualization availability, WSL 2 mode, qualified WSL version, storage, host encryption and applicable enterprise policy. It shall identify required elevation or restart before changes. WSL 1 shall be rejected for this edition. Managed device restrictions shall be respected rather than bypassed.

References: B2 A001, A011, A101, A108; B1 FR03. Verification: V01. Platform basis: E01, E04.

#### W006 Independent distribution installation

Profile W. Setup shall create a uniquely named product distribution without replacing an existing Ubuntu distribution or changing the user's default distribution. It shall support .wsl installation on qualified versions and a documented tar import fallback. First launch shall create a nonroot user and product administrator explicitly, with no preinstalled shared credentials.

References: B2 A006, A101, A102, A109; B1 FR06. Verification: V01 and V03. Platform basis: E01, E02.

#### W007 Services and manual operation

Profile W. The image shall provide qualified systemd service supervision and WSL specific unit configuration. The launcher shall start the selected distribution, wait for authenticated service health and open the workspace. Model failure shall leave manual file export, diagnostics, cancellation and repair available. A fallback UI shall pass the same accessibility and authorization tests.

References: B2 A004, A045, A065, A099, A135; B1 FR04, FR35, FR60. Verification: V03 and T24. Platform basis: E03, E05.

#### W008 Background lifetime and restart

Profile W. Opt in background filing shall use a qualified Windows user session process that maintains the required runtime connection, detects termination and restarts under a bounded policy. It shall not rely on systemd alone to keep WSL alive. At logout, sleep, shutdown or policy suspension, it shall checkpoint the event queue and show when processing is paused. No processing shall be promised while the computer is off.

References: B2 A008, A051, A055, A056, A062; B1 FR13, FR29. Verification: V03 and V08. Platform basis: E05.

#### W009 Resource coexistence

Profile W. Admission shall account for the effective WSL VM limit, other WSL workloads and a measured Windows foreground reserve. Per service cgroups shall constrain product workers. Setup shall preserve existing global WSL settings and show any proposed change and affected distributions; it shall not issue a global WSL shutdown without a reviewed maintenance action. Swap shall not be counted as resident model capacity.

References: B2 A021 to A028, A111, A112; B1 FR45, FR53. Verification: V04 and T13. Platform basis: E06.

#### W010 Accelerator qualification

Profiles W V. Each runtime shall probe the actual exposed compute API and execute a certification workload before advertising acceleration. Host driver changes shall invalidate dependent certificates. WSL packaging shall exclude conflicting Linux display driver packages. No generic GPU, NPU, unified memory, exclusive device or multi GPU guarantee shall be inferred from a Windows device listing.

References: B2 A012, A026, A037, A047, A100, A116, A118; B1 FR46, FR52. Verification: V04, V16 and T51. Platform basis: E08.

#### W011 Host authority boundary

Profiles W V. Hardware skills shall limit themselves to guest controls and explicitly delegated host operations. Host reboot, firmware, driver, partition and power changes shall require typed host broker actions with separate privileges. Ordinary skill execution shall have no direct Windows executable interoperability or unrestricted host drive access. Host administrators remain within the platform trust boundary.

References: B2 A054, A073, A074, A079, A081, A115; B1 FR17, FR50. Verification: V05 and T30.

#### W012 Local networking

Profiles W V. Initial APIs shall remain local and authenticated. A bridge shall use per user credentials, authenticated sessions, bounded requests and replay protection. Web endpoints shall validate origin and prevent request forgery. NAT, mirrored networking, VPN changes and port collisions shall not create an unauthenticated listener or unintended LAN exposure. Remote serving remains separately authorized.

References: B2 A041, A079, A082, A085, A119; B1 FR59. Verification: V06 and T42. Platform basis: E07.

### Windows files and automatic organization

#### W013 Folder enrollment and identity

Profiles W V. The Windows file broker shall enroll only user selected folders with distinct read, index and organize grants. It shall map the signed in Windows user to the product principal and enforce current Windows access control lists before every read or effect. Linux root or a mounted drive shall not be treated as authority to access a Windows file.

References: B2 A057, A060, A079, A082, A086; B1 FR17, FR22, FR58. Verification: V05 and V07.

#### W014 Reliable change capture

Profiles W V when host integration is enabled. A Windows event collector shall detect new and changed files in enrolled locations, wait for a stable readable version, persist a bounded queue and reconcile missed events after outages. Watcher overflow, duplicate events, journal rollover and revoked permissions shall trigger safe rescan or explicit failure. Linux inotify alone shall not be the correctness mechanism for Windows origin writes.

References: B2 A052, A059, A062, A063; B1 FR20, FR29. Verification: V07 and V08. Implementation basis: E12, E13.

#### W015 Classification policy

Profiles N D W V. Automatically received or saved files shall be classified using content, metadata and user rules into managed collections. The engine shall retain classifier version, confidence and provenance. Low confidence cases shall enter a visible review queue. Physical moves shall require an enrolled rule or a specific grant; semantic grouping shall be available without moving the source file.

References: B2 A057, A058, A061, A079; B1 FR24 to FR26. Verification: V07 and T32.

#### W016 Natural language save and retrieval

Profiles N D W V. A save request shall commit the artifact before confirming success and apply authorized filing policy. Queries such as invoices for the past week and the last sales presentation for customer X shall resolve document type, customer, date field, timezone and version. Ambiguous dates or customer identity shall be clarified or exposed as explicit filters. Search shall return authorized artifacts with their source and version.

References: B2 A052, A057 to A060, A063, A068; B1 FR22, FR23, FR27. Verification: V07 and T36.

#### W017 Windows path and file semantics

Profiles W V. The bridge shall validate normalized paths and stable file identities at effect time, handling case collisions, reserved names, long paths, junctions, symlinks, reparse points and cross volume changes. It shall distinguish cloud placeholders from local bytes and require authorization for hydration. Locked, encrypted or unsupported files shall remain untouched with a visible reason. Relevant access controls and origin security metadata shall be preserved or the operation refused.

References: B2 A057, A059, A062, A079, A086; B1 FR23, FR27, FR29. Verification: V05 and V08.

#### W018 Source ownership and transactional moves

Profiles N D W V. Each enrolled location shall declare index in place, copy into managed storage or move under an authorized rule. The receipt shall identify the authoritative copy and retention behavior. A cross filesystem move shall copy, validate and commit its destination before conditionally retiring the unchanged source; interrupted work shall be reconciled without duplicate logical artifacts or silent overwrite. External changes shall create a version or conflict.

References: B2 A052, A057, A059, A061, A062; B1 FR20, FR21, FR27, FR29. Verification: V08 and T33.

#### W019 Storage placement

Profiles W V. Authoritative metadata, journals and model caches shall reside on a qualified private Linux filesystem, separate in policy from enrolled Windows documents. The product shall not place its live SQLite database in a Windows shared folder or sync client directory. Storage tests shall cover host free space exhaustion as well as guest quotas, and backups shall capture a consistent application state.

References: B2 A059, A063, A064, A096, A138; B1 FR28, FR31. Verification: V09 and T35. Placement basis: E09.

#### W020 Windows application and capture adapters

Profiles W V. Opening files in Windows applications, invoking supported application operations, clipboard exchange, microphone input and screen capture shall use named, versioned adapters and explicit capabilities. Shell launch shall be distinct from verified application automation. The UI shall show capture state and provide immediate stop. Failure of an optional adapter shall preserve core local workflows.

References: B2 A066, A067, A075, A076, A135; B1 FR32 to FR35, FR55, FR56. Verification: V05, V07 and T59.

### Isolation updates and recovery

#### W021 Worker confinement

Profiles W V. Setup shall probe enforcing cgroups, namespaces, seccomp and available mandatory access controls. The release shall qualify the exact confinement composition under V05. Untrusted native code shall require the B2 A114 microVM boundary; when nested virtualization is unavailable, execution shall be denied or limited to a separately qualified constrained runtime such as WebAssembly. A normal container shall not silently substitute for a microVM.

References: B2 A053, A079 to A083, A111, A113, A114; B1 FR11, FR41. Verification: V05, T29 and T62.

#### W022 Encryption and user separation

Profile W. Persistent product data, WSL disk files, swap, exports and backups shall remain on verified encrypted storage or use qualified product encryption. Windows volume encryption may satisfy the powered off device protection objective when verified on the actual edition and volume. The product shall detect suspended or absent protection. Each Windows user shall receive separate state and credentials; recovery keys shall be exportable through an authenticated manual path.

References: B2 A006, A035, A064, A082, A107, A138; B1 FR06, FR31, FR47. Verification: V09 and V10.

#### W023 WSL update activation

Profile W. Product updates shall create and verify a candidate distribution, checkpoint and fence the current writer, migrate a consistent copy of authoritative state and run health checks before switching the launcher. Failed activation shall preserve the previous distribution and committed data. After new writes, rollback shall use a compatible current state migration or forward recovery; restoring an old snapshot shall not silently discard acknowledged work. Host Windows and WSL kernel servicing remain separate.

References: B2 A005, A095, A104 to A106, A110, A134; B1 FR05, FR07. Verification: V11 and T04.

#### W024 Recovery and uninstall

Profiles W V. A model independent recovery interface shall export data, verify backups and restore onto a clean supported installation. Uninstall shall first identify product instances, offer verified export and distinguish application removal from data deletion. It shall preserve unrelated distributions, VMs, Windows files and global settings. Destructive distribution unregister shall require explicit data deletion authorization.

References: B2 A007, A061, A064, A099, A138, A140; B1 FR04, FR30, FR31. Verification: V09 and V12. Platform basis: E14.

### Native and dual boot installation

#### W025 Native profile preservation

Profile N. The standalone edition shall retain the existing Ubuntu boot, signed A/B root, LUKS2 data encryption, model free recovery and hardware qualification requirements. Windows support shall not replace or weaken these mechanisms. The native ISO shall remain independently installable without Windows or a Microsoft account.

References: B2 A001 to A008, A101 to A110; B1 FR01 to FR07. Verification: V01 and existing T01 to T05, T45 to T51.

#### W026 Dual boot preflight

Profile D. Setup shall inventory UEFI mode, GPT layout, stable disk IDs, existing boot entries, encryption, storage controllers and Windows hibernation state before offering changes. It shall prefer a separate disk or prepared free space. The user shall review partition effects and confirm a recovery plan before mutation. Unsupported layouts and locked encrypted volumes shall be rejected safely.

References: B2 A001, A002, A007, A108; B1 FR02, FR03. Verification: V13. Platform basis: E11, E15.

#### W027 Encryption and partition protection

Profile D. The installer shall never resize an encrypted Windows filesystem directly. Any required Windows resize or decryption shall use a documented Windows procedure before Linux installation; suspending BitLocker protection shall not be treated as decrypting a volume. Existing Windows boot and recovery partitions shall be preserved. Writes to hibernated or unsafe NTFS volumes shall be blocked, including Fast Startup states that leave the volume unsafe.

References: B2 A002, A054, A107, A108; B1 FR02, FR06. Verification: V13.

#### W028 Secure coexistence and boot recovery

Profile D. The qualified installation shall preserve Windows Boot Manager and provide deterministic selection of either OS. Product signing and firmware trust enrollment shall retain the existing Windows trust path; disabling Secure Boot shall not be the default solution. A/B Linux updates, Windows updates and firmware boot order changes shall have tested recovery procedures. Linux removal shall preserve a bootable Windows installation.

References: B2 A005, A007, A104 to A106, A140; B1 FR05, FR07. Verification: V14 and T46, T47.

#### W029 Data separation in dual boot

Profile D. Both operating systems shall retain independent credentials, encrypted private state and system partitions. Optional document exchange shall use an explicitly selected export location or authenticated import process. Neither OS shall share the other's live metadata database or model cache as a concurrent writer. Files created while Windows runs shall be reconciled on the next authorized LLM OS session.

References: B2 A057 to A064, A082, A138; B1 FR22 to FR31. Verification: V14 and V17.

### Full virtual machine profile

#### W030 Guest image and hypervisor support

Profile V. The initial template shall target a qualified Hyper V Generation 2 configuration with Ubuntu guest kernel, virtual UEFI, complete product desktop and guest recovery. Setup shall check the supported Windows edition and virtualization prerequisites. The release shall also provide an ISO; VMware or VirtualBox support shall require a separate exact version certificate before being advertised.

References: B2 A001, A005, A065, A101 to A104, A140; B1 FR01, FR03. Verification: V15. Platform basis: E10.

#### W031 VM resources and integration

Profile V. The VM shall have explicit CPU, memory, virtual disk and network limits, reserving Windows headroom. Fixed guest memory is the initial qualification configuration; ballooning or dynamic memory needs pressure tests. Host folder, clipboard and device sharing shall be opt in through the same scoped broker contracts. The VM shall not expose a public service by default.

References: B2 A024, A028, A074, A079, A096, A111; B1 FR45, FR50. Verification: V04, V06 and V15.

#### W032 Guest security and device limits

Profile V. Verified guest boot, LUKS2 data protection and recovery credentials shall be tested on the selected virtual firmware. CPU inference shall be available where certified; accelerated inference shall require verified compute access and its own isolation evidence. Virtual graphics acceleration or a working display shall not certify CUDA, NPU, passthrough or exclusive GPU allocation.

References: B2 A011, A012, A100, A104, A107, A116; B1 FR05, FR06, FR46. Verification: V10, V15 and V16.

#### W033 VM cloning and checkpoints

Profile V. Templates shall contain no deployment credentials or reusable machine identity. First boot and cloning shall generate new identities and keys. Checkpoints shall not replace backups; restoring a checkpoint shall reconcile task receipts before replaying external effects. Guest update failure and host termination shall preserve all acknowledged commits within the certified storage fault scope.

References: B2 A006, A052, A059, A064, A095, A138; B1 FR13, FR20, FR21, FR31. Verification: V09, V11 and V15.

### Portability operation and release evidence

#### W034 Migration between profiles

Profiles N D W V. Export and import shall preserve artifact IDs, versions, provenance, workflow receipts and user approved policy. Identity mapping shall be reviewed; credentials and device grants shall be reissued rather than copied blindly. Derived indexes and caches shall be rebuilt as needed. The source shall remain recoverable until the target verifies content, permissions and history; migration shall establish one authoritative writable state.

References: B2 A057, A063, A064, A082, A134, A138; B1 FR23, FR28, FR31. Verification: V17 and T56.

#### W035 Local inference and offline installation

Profiles N D W V. Declared offline installation shall include required product packages, model and skill assets; Windows prerequisites shall be provided through permitted offline packages or stated as prerequisites. Loss of internet access or GPU capacity shall never authorize remote inference. An optional remote service shall identify its endpoint, data scope and policy before use.

References: B2 A003, A017, A046, A085, A109; B1 FR44, FR46. Verification: V18, T02 and T42.

#### W036 Profile specific performance claims

Profiles N D W V. Each profile shall rerun the applicable B2 quality suite with its exact host and guest tuple. Windows foreground contention shall be part of W and V certification. CPU correctness alone shall not earn an interactive certificate when Q02 or Q03 fails. A limited evaluation configuration shall show measured limitations and shall not silently relax the production A1 performance gate.

References: B2 A011, A047, A098, A100; Q01 to Q14; B1 Section 16.2. Verification: V04, V16 and T25.

#### W037 Suspension and host failure

Profiles W V. Runtime recovery shall cover host lock, logout, sleep, restart, forced termination and driver reset. The product shall fence stale leases, reconcile effects and revalidate devices before new work. UI connection loss shall not imply task success or cancellation. Accepted background work shall report paused, resumable, failed or reconciled status accurately.

References: B2 A008, A027, A030, A045, A052, A055; B1 FR13, FR19 to FR21, FR52. Verification: V03, V08 and V11.

#### W038 Host dependent maintenance

Profiles W V. Support records shall include Windows, WSL, hypervisor and host driver versions as well as Ubuntu packages. A change to a bound dependency shall trigger affected requalification. Unsupported host releases shall receive a visible support state and migration guidance. Product updates shall not silently pin, replace or disable host security servicing to preserve a certificate.

References: B2 A094, A100, A118, A131 to A134; Q17; B1 FR60. Verification: V16 and T57.

#### W039 Host integration diagnostics

Profiles W V. Diagnostics shall show bridge health, enrolled scope, queue depth, oldest event, last successful reconciliation, paused reason and host or guest pressure. Export shall include the release tuple and redacted failure receipts without credentials, private file content or unnecessary full paths. Manual diagnostics shall work with inference disabled.

References: B2 A004, A084, A093, A094, A139; B1 FR57, FR60. Verification: V03, V07 and T41.

#### W040 Installation guides and support matrix

Profiles N D W V. Each supported profile shall ship user, administrator, developer and recovery instructions covering prerequisites, exact installation path, first user, offline operation, data locations, privileges, backup, updates and removal. The matrix shall identify unsupported hardware operations and unavailable adapters. Examples shall distinguish installing the product from merely running its browser simulator.

References: B2 A099, A100, A140; B1 Sections 5 and 17. Verification: V01, V12, V18 and T59.

#### W041 Complete requirements evidence

Profiles N D W V. Release reports shall include one applicability and evidence record for every B2 A and Q requirement and every W requirement. Each record shall identify inherited, extended, substituted or conditional status, the controlling variation ID, exact test runs and pass, fail, blocked or justified not applicable result. A missing mandatory result shall block that profile's release.

References: B2 A098; Q14; B1 Section 17.1. Verification: V02 and V18.

#### W042 Architecture extensions

Profiles W V. Windows on ARM, nested virtualization deployments and additional hypervisors shall be separate supported profiles only after complete relevant tests. B2 A078 remains the native ARM64 gate; successful Windows hosted ARM64 execution shall not satisfy native board qualification. Architecture dependent model, driver, sandbox and export compatibility shall be recorded explicitly.

References: B2 A012, A078, A100, A103, A114; B1 FR08. Verification: V01, V05 and V16 when such support is proposed.

#### W043 Threat boundary disclosure

Profiles W V. The security profile shall state that Windows and the hypervisor or WSL runtime are trusted host components, with host administrators able to control guest storage and execution. Product isolation shall protect scoped workflows and ordinary user separation; it shall not claim protection from a compromised host administrator. Detection of missing mandatory isolation or encryption shall block protected workload certification.

References: B2 A079 to A083, A107, A113, A114; Q11; B1 Section 12. Verification: V05 and V10.

#### W044 End to end acceptance

Profiles N D W V. Each supported profile shall complete the three user journeys in Section 7 using real local inference, real file operations and durable artifacts. Simulated classifiers, mocked file events or a browser demonstration may support development but shall not satisfy product acceptance. Required manual workflows shall also pass with the model stopped.

References: B2 A003, A045, A057 to A065, A098; Q10, Q13; B1 FR22 to FR31. Verification: V07 and V18.

## 5 Quality targets added by this variation

The original Q01 to Q14, Q17 and Q18 apply wherever their underlying workflows apply. Q04 and Q05 retain the large model certification conditions. Q16, Q19 and Q20 remain A3 cluster obligations. Q15 applies to actual native or guest boot slots and is replaced for WSL activation by QW03 below. Windows background load is part of the W and V measurement record.

| ID | Proposed measurable target | Verification |
|---|---|---|
| QW01 Filing latency | On the certified compact profile, 95 percent of stable supported text, PDF or Office files up to 10 MiB enter a collection or review queue within 30 seconds. Test 100 mixed files at up to 6 files per minute with no inference queue backlog. OCR and media have separately published limits. | V07 |
| QW02 Event recovery | After reconnect, reconcile 1,000 supported files in a 10,000 file enrolled tree within 10 minutes; zero missed final file states, duplicate logical artifacts or unauthorized reads. Force watcher overflow and a 30 minute runtime outage. | V08 |
| QW03 WSL activation recovery | After at most three failed product health attempts, stop candidate activation and make manual recovery and the compatible previous release available within 120 seconds. Model warmup is excluded; loss of acknowledged data is never allowed. | V11 |
| QW04 Host coexistence | Retain Q01 guest UI and Q06 cancellation targets. In three 30 minute runs, Windows typing and window switching acknowledgement shall have P95 at most 150 ms and no unresponsive interval over 1 second, with the declared host foreground workload. | V04 |
| QW05 Safe installation and removal | Zero unintended changes to unrelated distributions, disks, VMs, documents or settings in the prescribed install, repair and removal suite. Compare pre and post inventories and hashes of protected fixtures. | V01, V12 to V15 |
| QW06 Filing policy accuracy | On 200 held out labeled invoices, presentations and other documents, at least 95 percent of items automatically assigned above the chosen confidence threshold shall match the approved collection; publish coverage and review rate. Zero incorrect destructive moves in the test corpus. | V07 |

Thresholds may be changed only through explicit versioned requirements change. The filing benchmark measures classification or review routing, not unrestricted understanding of arbitrary content. Queries and calculation outputs shall retain the baseline deterministic and authorization checks even when a model's classification is uncertain.

## 6 Explicit variations to existing requirements

This table defines the changes to existing obligations. The linked W requirements provide the replacement or extension behavior. The native profile is unchanged unless N or D is specified. For full VMs, references to physical boards and hardware shall mean qualified virtual hardware plus its recorded Windows host where appropriate; real hardware claims still need physical evidence.

| Existing references | Profile and treatment | Controlling variation |
|---|---|---|
| B1 FR01; B2 A001, A002, A108 | W and V extend installation to a selected distribution location or VM disk. No host partition mutation. D adds safe coexistence; N retains direct boot. | W001, W005, W006, W024 to W030 |
| B1 FR04; B2 A004, A007 | W substitutes model free launcher and distribution recovery for independent Linux boot recovery. V keeps guest recovery and adds host restore. | W007, W024, W033 |
| B1 FR05, FR07; B2 A005, A104 to A106, A110; Q15 | W substitutes signed distribution activation and state migration for UKI, root verity and physical boot slot requirements. It does not claim Linux verified boot parity. N, D and V retain the product boot and A/B obligations. | W023, W025, W028, W032; QW03 |
| B2 A008 | W and V extend suspend and recovery to Windows lifecycle events, device loss and guest termination. | W008, W037 |
| B2 A065 to A067, A135 | W substitutes an accessible workspace window for the primary Wayland desktop session; Windows capture is brokered. V retains the guest desktop with optional host capture. | W007, W020 |
| B2 A073, A074 | W and V narrow physical hardware authority to exposed guest controls and expressly delegated host actions. Direct host thermal, firmware and driver control is not implied. | W004, W010, W011 |
| B2 A075, A076 | W and V extend compatibility with explicitly scoped host application adapters. B2 A076 still governs running Windows applications inside a Linux controlled compatibility layer or VM. | W020 |
| B2 A078 | Native ARM64 remains conditional under A2. Hosted ARM64 would need an independent certificate and does not substitute for native board evidence. | W042 |
| B2 A101, A102 | Extend edition choices with WSL and VM; retain Ubuntu 24.04 LTS amd64 userland until the existing promotion gate passes. | W001 to W003, W006, W030 |
| B2 A103, A116, A118 | W substitutes a qualified Microsoft WSL kernel and host driver interface for an Ubuntu kernel track and Linux display modules. V qualifies Ubuntu guest drivers and exposed devices; host updates enter both certificates. | W004, W010, W032, W038 |
| B1 FR06; B2 A107 | W substitutes verified encryption of host volumes holding all sensitive guest material, or qualified product encryption, for mandatory LUKS2. N, D and V retain LUKS2 data protection. | W022, W025, W027, W032 |
| B2 A111, A112 | W and V retain worker quotas and backend budgets and add host pressure and effective guest limit checks. Product leases do not reserve all Windows resources. | W009, W010, W031, W036 |
| B2 A113 | W requires enforcing AppArmor where the qualified WSL kernel supports it. Otherwise a signed WSL confinement profile shall specify namespaces, seccomp, capability removal, immutable worker mounts, broker only files and denied direct Windows interop, with V05 proving equivalent required effects protection. No blanket exemption. V retains AppArmor. | W011, W013, W021, W043 |
| B2 A114, A115 | W and V retain the microVM or separately qualified constrained runtime rule and extend typed helper restrictions to the Windows bridge. Nested virtualization is never assumed. | W011, W021, W042 |
| B2 A057 to A064, A079 to A086 | Extend unchanged identity, durability and policy guarantees across Windows file operations, including ACL revocation and partial cross volume moves. | W013 to W019, W034 |
| B2 A095, A097 to A100, A109 | Extend manifests, rollback, offline bundles and evidence to installer, companion, WSL and hypervisor versions. | W003, W023, W036, W038 to W041 |
| B2 A131 to A135, A138, A140 | Extend maintenance, migration, backup and manuals to the selected host profile. Ubuntu promotion still requires the full retained profile matrix. | W024, W034, W038 to W041 |

Existing tests shall be reused for their original invariants, with environment adapters where required. T01, T03 to T05, T45 to T51 and T59 need W and V variants. T29, T30, T32 to T35, T42 and T62 must include the Windows trust boundary. B2 T46 is not a WSL Linux boot test; WSL integrity is evidenced by V01, V05 and V11. B2 T47 is replaced only for WSL root activation, while its data compatibility and failure objectives remain.

## 7 Verification and acceptance procedures

### Required user journeys

For W and V, use Windows source files. For N, use Linux Downloads and Linux adapters. For D, create Windows files before rebooting and import from an authorized exchange location. Apply the same artifact, policy and recovery assertions.

1. Download and retrieve invoices. Enroll Downloads, receive real files and request invoices for the past week. Verify dates, timezone, authorized results, bytes, versions and collections. Include a file received while WSL is stopped and another with access revoked before processing.
2. Save and find a sales presentation. Create an editable presentation, save it for customer X and retrieve that customer's latest presentation. Edit externally and repeat. Verify the committed version, conflict handling, provenance and export location.
3. Continue after failure or migration. Interrupt a save, stop the model and terminate the guest in separate trials. Recover manually, verify artifacts and pending effects, then migrate to native Linux. Check permissions and mapped identities before new writes.

### Additional test catalogue

| Test | Procedure and pass condition |
|---|---|
| V01 Install and packaging | On clean and populated hosts, verify signed assets, offline dependencies, prerequisites and destination choice. Reject tampering, WSL 1 and unsupported tuples before mutation. Preserve existing Ubuntu, default distro and protected files. |
| V02 Contract and traceability | Run common API and artifact tests on N, D, W and V. Exercise unavailable capabilities. Expand the applicability register to every A, Q and W ID; missing or unjustified mandatory evidence blocks release. |
| V03 Lifecycle and manual controls | Run 100 sleep, resume and forced guest stop cycles. Close the UI with background filing enabled. Check event recovery, bounded restart, no leaked leases and model free export, diagnostics and keyboard controls. |
| V04 Host pressure and budgets | Saturate CPU, host RAM, guest RAM, model budget and virtual disk under Windows foreground work and another WSL distribution. Verify Q01, Q06, QW04, no host OOM and no unauthorized global settings changes. |
| V05 Security boundary | Test two Windows users, denied folders, junction races, forged IPC, prompt injection, executable interop, clipboard and capture denial, malicious generated code and nested virtualization absence. Require zero unauthorized effects and enforcing confinement. |
| V06 Network isolation | Scan host, LAN and guest before and after NAT or mirrored mode changes, VPN reconnect and port collision. Test forged origin, expired credential and replay. No unauthenticated API, direct worker egress or unintended LAN listener may appear. |
| V07 Filing and retrieval | Execute the three journeys with the labeled corpus and date boundary cases. Verify QW01 and QW06, exact deterministic filters, review routing and current ACL checks. Remove the model and repeat manual access. |
| V08 File fault recovery | Inject event overflow, file locks, partial downloads, rename storms, cross volume move failure, cloud placeholders and concurrent edits. Meet QW02 and preserve authoritative versions with no silent overwrite or unauthorized hydration. |
| V09 Backup and storage failure | Quiesce and back up populated state, exhaust guest and host storage, then restore to a clean machine. Verify all acknowledged objects, metadata and receipts; rebuild indexes and preserve required recovery keys. |
| V10 Encryption and identities | Inspect all data, swap and export locations, simulate missing keys and disabled host encryption, clone a VM and switch Windows users. Reject unsafe certification; recover authorized data and prove fresh clone identities. |
| V11 Update fault injection | Kill each candidate creation, copy, migration, activation and health step. Write new data after activation and test supported rollback. Meet QW03 with zero lost acknowledged versions; keep incompatible old schemas fenced. |
| V12 Removal | Remove a product installation with and without requested data deletion. Verify export recovery first where selected. Keep unrelated WSL distributions, VMs, user documents and global settings intact; check QW05. |
| V13 Dual boot disk safety | Use disposable disk fixtures for separate disk and shared disk layouts, encryption, hibernation, controller differences and insufficient space. Compare protected partition hashes; reject unsafe operations and verify approved partition effects only. |
| V14 Dual boot continuity | Boot both OSs repeatedly, perform Windows and product updates, disturb boot order and remove Linux. Restore either boot path through documented recovery; verify Windows bootability, user data and Secure Boot trust. |
| V15 Full VM qualification | Import the template and install from ISO, test virtual UEFI, guest A/B, LUKS2 recovery, desktop, host termination and checkpoint restore. Verify sharing defaults, new clone identity and no duplicate external effect. |
| V16 Platform and inference | Run real compact inference and B2 Q measurements on every advertised CPU or accelerator tuple. Change host driver, WSL or hypervisor version; revoke stale certificates and requalify affected paths. |
| V17 Migration | Exercise W to N, N to W, W to V and V to W using two users, grants, versions and receipts. Reject identity conflicts, prove source recoverability and one writer, and compare every sampled artifact digest and permission. |
| V18 Offline release rehearsal | Follow all profile guides with external networking blocked. Verify real inference and user journeys, dependency completeness, support labels and the requirement evidence register. Simulator only results fail acceptance. |

### Minimum qualification environments

Retain B2 native environments. Add Windows 11 x64 Home with CPU inference and Pro or Enterprise with a supported NVIDIA GPU; use the latter for Hyper V and a CPU guest profile. Cover existing WSL distributions, enterprise policies, VPNs and disposable dual boot disks with encrypted Windows. Publish exact tested tuples and supported update ranges.

Retain fault preconditions, timelines, expected invariants, results, artifact hashes and recovery evidence. The baseline 1,000 crash trial durability gate and 72 hour mixed workload soak remain applicable.

## 8 Implementation work and release gates

| Work package | Owner and dependencies | Required output |
|---|---|---|
| WPW01 Common profile contracts | Architecture and platform leads; extends B2 WP01 and WP17 | Capability schema, ReleaseTuple extension, shared API tests and applicability register |
| WPW02 Windows installer and runtime | Windows and release engineers; WPW01 | Signed companion, WSL package, setup, first user, lifecycle supervision and uninstall |
| WPW03 Windows artifact bridge | Storage and security engineers; WPW01 and WPW02 | Scoped broker, event queue, path safety, classification, reconciliation and search integration |
| WPW04 Hosted isolation and inference | Security and inference leads; WPW01 and WPW02 | Sandbox profiles, CPU and GPU certificates, budgets and host pressure handling |
| WPW05 Recovery and migration | Storage and release leads; WPW02 to WPW04 | Candidate activation, encrypted backup, schema recovery and profile migration |
| WPW06 Dual boot and full VM | Platform lead; existing native image plus WPW01 | Coexistence installer, guest template, boot recovery and device matrix |
| WPW07 Qualification and manuals | QA and operations; all preceding packages | V01 to V18 evidence, adapted baseline suites, manuals and support matrix |

Gate GWIN0 shall demonstrate actual core service startup and compact inference on WSL, host file ingestion, the required confinement boundary and a complete VM desktop. Failure of the WSL confinement gate restricts executable skills until a qualified constrained runtime is available; it does not waive the security requirement.

Gate GWIN1 shall complete Windows file automation, failure recovery, candidate updates and migration on the declared compact profile. Gate GWIN2 shall complete dual boot coexistence, full VM recovery, the inherited baseline suites and all applicable additional tests. A profile may ship only after its own evidence is complete; the release announcement shall identify which of the four profiles are certified.

The first deliverable should be the shared core plus WSL companion, developed alongside the native image. Full VM packaging provides an early complete desktop environment; dual boot release follows disk and boot recovery qualification. Effort shall be estimated against the actual implementation backlog after GWIN0. This specification defines the required work and does not treat the existing simulator as a completed OS or installer.

## 9 External technical references

The following primary documentation was checked on 19 September 2026. It establishes platform capabilities and constraints. Product design choices and acceptance targets in this variation remain engineering requirements to implement and measure.

- E01 Microsoft Learn, Build a Custom Linux Distribution for WSL. The .wsl format guide applies to WSL 2.4.4 and later. https://learn.microsoft.com/en-us/windows/wsl/build-custom-distro
- E02 Microsoft Learn, Import any Linux distribution to use with WSL. Root filesystem import and first user setup. https://learn.microsoft.com/en-us/windows/wsl/use-custom-distro
- E03 Microsoft Learn, Run Linux GUI apps on WSL. Application window integration and desktop limitations. https://learn.microsoft.com/en-us/windows/wsl/tutorials/gui-apps
- E04 Microsoft Learn, Frequently asked questions about WSL. Home edition availability and host environment boundaries. https://learn.microsoft.com/en-us/windows/wsl/faq
- E05 Microsoft Learn, Use systemd to manage Linux services with WSL. Service support and instance lifetime. https://learn.microsoft.com/en-us/windows/wsl/systemd
- E06 Microsoft Learn, Advanced settings configuration in WSL. Global and distribution settings, resource limits and interoperability. https://learn.microsoft.com/en-us/windows/wsl/wsl-config
- E07 Microsoft Learn, Accessing network applications with WSL. NAT, mirrored networking and firewall considerations. https://learn.microsoft.com/en-us/windows/wsl/networking
- E08 NVIDIA, CUDA on WSL User Guide. Windows driver ownership and WSL compute limitations. https://docs.nvidia.com/cuda/wsl-user-guide/
- E09 Microsoft Learn, Working across file systems. Linux and Windows storage integration. https://learn.microsoft.com/en-us/windows/wsl/filesystems
- E10 Microsoft Learn, Windows Hyper V system requirements. Host editions and virtualization prerequisites. https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-requirements
- E11 Canonical, BitLocker during Ubuntu installation. Encrypted Windows installation constraints. https://ubuntu.com/desktop/docs/en/24.04/reference/bitlocker-during-ubuntu-installation/
- E12 Microsoft Learn, ReadDirectoryChangesW. Directory notifications and overflow recovery. https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
- E13 Microsoft Learn, Change Journals. Persistent volume change records for qualified reconciliation. https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals
- E14 Microsoft Learn, Basic commands for WSL. Distribution import, export and destructive unregister semantics. https://learn.microsoft.com/en-us/windows/wsl/basic-commands
- E15 Canonical, Install Ubuntu Desktop for Ubuntu 24.04. Installation and partition selection. https://ubuntu.com/desktop/docs/en/24.04/tutorial/install-ubuntu-desktop/
