# Native external-drive checkpoint - 2026-09-28

G2 remains in progress. This checkpoint supersedes the storage/build blocker
in the historical 2026-09-27 model checkpoint, not its image-specific results.
It is not production signing, physical qualification, or complete G2 acceptance.

## Repository and storage

The previous implementation was already committed at `100f624`. External-drive
support and the extended regression runners are committed at `dbf04ea`.
No push was performed. The frozen Python source-release inventory was unchanged.

The owner-designated build directory is `D:\LumaOS-builds`, mounted in Ubuntu
WSL at `/mnt/d/LumaOS-builds`. D: is exFAT: large regular image files, VM disks,
and exported logs use this drive. Linux rootfs/source/compiler staging remains
in a fresh Docker volume; private lab keys remain in the existing separate key
volume. QEMU sockets use private container `/tmp` directories. No physical disk
was formatted, no firmware was enrolled, and unrelated Docker services and
existing D: contents were not changed.

The regular-file/fsync, cross-process locking, and qcow2 write/read/check probe
passed. An older-image live-boot smoke also passed with external VM storage;
that smoke validates the harness and is not acceptance evidence for sequence 4.

## Produced image

- Export: `D:\LumaOS-builds\native\20260928T124255Z-headless`.
- Working artifacts/VMs: `D:\LumaOS-builds\work\20260928T124255Z-headless`.
- Retained Linux volume: `luma-native-build-20260928T124255Z-headless`.
- Image: `luma-native-lab-20260927-headless-4.img.zst` (2,156,815,854 bytes).
- Raw SHA-256: `5408c3d8430dc085c52b0d816abfcdd3fe68f9b079925a2e469aa7643a5f5197`.
- Compressed SHA-256: `b7f98803ee732525124f27b594cc87b4f2f8b71eb1d833f6da568e386a50514e`.
- Source-lock SHA-256: `e5472afa5be7ea7fc5cc130a211dde76e039ba5285a6caa37b3cfd6f70f0d644`.
- Ubuntu 24.04 amd64, kernel `6.8.0-142-generic`, headless, laboratory-signed.

The date in the image filename is the pinned release label; this build actually
ran on September 28. The compressed export was read back and checksum-verified.
The source archive and source lock identify the exact captured bytes. Runtime
and assembly inputs match the committed workspace. Later documentation and
regression-runner changes are identified separately by test-source hashes in
each result; they are not silently attributed to the archived build snapshot.

## Evaluation

All six selected laboratory runners passed under label `seq4-01`, with 26 VM
stages and separately exported evidence. This is not the complete governed G2
matrix or physical qualification.

All 58 exported result/log files were rechecked against their hash inventories;
the compressed image and the other available `SHA256SUMS` members were also
rehashed and matched the checkpoint. The raw image identity was independently
computed by each applicable runner, not inferred from the compressed filename.

| Runner | VM stages | Result and scope |
| --- | ---: | --- |
| Platform | 14 | Pass: installation, security, fallback and recovery |
| Qwen3-4B | 5 | Pass: installer download, inference, isolation and recovery |
| Qwen3-1.7B | 2 | Pass: installed configuration and offline inference |
| Interrupted update | 3 | Pass: guest cut, reconciliation, retry and older-release refusal |
| Secure Boot positive | 1 | Pass: virtual signed live-boot smoke only |
| Secure Boot negative | 1 | Pass: virtual unsigned-loader refusal only |

The full 14-stage platform runner passed on this image, including actual
installation, kernel/peer security checks, three-attempt essential-health
fallback, independent-credential recovery/export, data preservation, corrupted
root detection/fallback, and repaired-slot boot. Secure Boot was not enabled in
this KVM run. Its exported result is
`evidence-seq4-01-full/result.json`, SHA-256
`db99d0a836e97de01cf053d3044a2de40828ba731c3416f2c34abcf6c047f72d`.

The five-stage Qwen3-4B runner also passed: actual publisher acquisition by the
native installer, real inference (18 prompt / 14 completion tokens), API and
kernel isolation, wrong-length and same-length corruption refusal, disconnected
reboot, independent recovery disablement, and healthy manual boot afterward.
No weights were pre-seeded. Its result is `evidence-seq4-01-model/result.json`,
SHA-256 `75101636706e24ffa60128f25eb2e54d0bee52f1d5d4f3318fc24d5133ec48a3`.

The two-stage Qwen3-1.7B runner passed in a 4 GiB/two-vCPU VM on an overlay of
the complete platform fixture. It exercised real installed-command download,
retained recovery disablement until explicit re-enablement, the smaller memory
limit, real offline inference (18 prompt / 14 completion tokens), and refusal
of an unknown model ID without stopping the valid model. This is not a fresh
OS installation test for the 1.7B profile. Its result is
`evidence-seq4-01-small/result.json`, SHA-256
`b1ffcc615cad6a178ae2765ca85f17a3f8ebea2fa78ac3bf250badcae139f207`.

The three-stage interrupted-update runner passed on a new overlay of the
read-only sequence-1 fixture. It killed QEMU after 37,515,264 observed target
write bytes in the inactive-slot write window (excluding pre-consent snapshot
writes), recovered the old slot, reconciled the pending transaction, retried,
booted/promoted sequence 4, preserved user data and model disablement, and
refused the older signed release. This is guest interruption injection, not
physical power-loss qualification or protected production anti-rollback.
Its result is `evidence-seq4-01-powercut/result.json`, SHA-256
`2e52e23f6e872919864f04f66d87939587b3fda0625ed03d541c8d30707c64af`.

Separate QEMU/TCG firmware runners passed a signed live boot with the Secure Boot
flag enabled and refusal of an unsigned bootloader copy. Their results are
`evidence-seq4-01-secure/result.json` (SHA-256
`a02931bb14afad7d7ba24cc432c82b88d81c0b07324cb77cb84e364867b62ed8`)
and `evidence-seq4-01-unsigned/result.json` (SHA-256
`1a2089d25e302a0e10b10d02ffd9d99a13c19c4d7de8d0974e1d5e32e00dca5a`).
Neither is a Secure Boot installation pass or physical firmware qualification.
Each completed result binds the exact image, and its adjacent inventory hashes
the retained console/QEMU logs. The exported builder's original
`built-not-yet-boot-tested` record is intentionally preserved as build-time
metadata; these separate executed results provide the later evaluation status.

The [machine-readable checkpoint](native_external_2026-09-28.json) records the
image and each completed result/inventory identity separately.

Source-level checks passed: 19 Rust tests with warnings denied; nine native
Python tests on Windows and Ubuntu userspace; 320 reference tests on Windows
(five skips) and Ubuntu WSL (one skip); shell/Python syntax checks. These are
not substitutes for running the produced image.

## Remaining boundaries

The installer acquires pinned Qwen3 weights over HTTPS after hardware admission;
weights are not embedded in the image. The 4B profile is the requested compact
tier. The 1.7B profile is a smaller development fallback, not an equivalent
4-6B qualification. GPU and larger-model tiers have not been qualified here.

Open software remains: native finite Admin/policy and durable-effect integration,
protected production identity/time/rollback anchors and key lifecycle, complete
governed model-pack/lifecycle contracts, qualified desktop/vertical workflows,
and the remaining migration/interruption/adversarial matrix. The owner must
select the protected Admin/checkpoint deployment design and approve production
custody inputs before production integration is claimed. Physical firmware,
TPM, accelerator, real power-loss/damaged-media, suspend/resume and two-board
qualification additionally require approved native test machines.

Source review also identifies normal-exit-only cleanup for private verified
bundle snapshots. A killed operation can leave root-private staging files in
encrypted `/var`; bounded crash-orphan reconciliation/retention/cleanup and
repeated interruption/storage-pressure testing remain open. A passing single
power-cut/retry scenario must not be interpreted as that cleanup qualification.

See [the exact-image handoff](TEST_IMAGE_2026-09-28.md) and
[the build/operator guide](../image/README.md) for installation and recovery.
This is a bootable installation/recovery image, not an in-place Ubuntu upgrade
or a production OS. Physical installation erases the explicitly confirmed
target disk; do not use the existing Ubuntu system disk as an implicit target.
