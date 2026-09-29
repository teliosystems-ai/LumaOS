# Sequence-8 installed Admin/PCR fixture - 2026-09-30

**Four-stage VM fixture and evidence export passed. G2 remains incomplete.**
This result qualifies the stated laboratory paths only, not authenticated
Admin enrollment, clean-shutdown acceptance, physical hardware or production
custody. A later shutdown repair is not part of this image.

## Exact image and evidence

Export: `D:\LumaOS-builds\native\20260929T195529Z-headless`.
Image: `luma-native-lab-20260927-headless-8.img.zst`.

| Artifact | SHA-256 |
| --- | --- |
| Compressed image | `c9fde1a3273d8abb43794ab8755b65988ec3cdd3b6429bf5e041da3e05041f61` |
| Raw image | `a80bb00f8f400b19baedfb58766dd52a50aefcf6fe8fda1c839182b1b549b53e` |
| Source lock | `31d664cd946d70c88ea11438c99a93c7b454a9921b350dab9646f6999bf2fb6b` |
| Source archive | `2fb6cae33678ae54d42e8b88bc01d97de35e02b96b260ccbe2237df0f1107d07` |
| Boot policy | `17d65d23acbc85a9d9b4b95079a876cc82eb58ce26319838627e830550e32fa6` |
| Exported VM `result.json` | `484e71b4ff776bca88c7cf96d8a2047a9474b1ed7b2147cd54f7a5d678646f40` |

VM logs, result and per-file digest inventory are under `admin-vm-evidence`
in the export directory. The raw VM run remains under
`D:\LumaOS-builds\work\20260929T195529Z-headless\vm-admin-seq8-tcg-01`.
It used TCG, Secure Boot and a persistent private software TPM. No physical
disk or TPM was attached. Tools image:
`sha256:40d9d50237189a8880580e16edcaf1a3ff81ac996be9b4f180d397c7140b1bce`.

## Observed passing scope

- Live Secure Boot, dm-verity, enforced AppArmor, service readiness and payload
  mounting; `/dev/tpmrm0` observed as root:root 0600 and native probe succeeded.
- Tampered bundle rejected specifically at signature verification; target disk
  prefix unchanged. The 4B profile was rejected for the 4 GiB fixture's RAM
  limits before installation, also without modifying the target prefix.
- Manual-mode installation completed onto the fresh virtual disk with separate
  accounts, encrypted data, independent recovery passphrase and pending local
  TPM2 enrollment intent. This fixture did not download model weights.
- Installed login, boot health, startup storage maintenance and measured-phase
  services; boot-provided PCR public key matched the immutable image key.
- PAM authentication of the public fixture account succeeded; wrong-password
  and non-root diagnostic attempts failed. Authentication reported no product
  Admin role or authority, and the supplied password was not echoed.
- A public fixture value was sealed using TPM-only PCR7 plus signed PCR11 and
  recovered initially, after a full power-off/reboot, and after signed slot B
  selection without resealing. Extending an unapproved PCR event denied recovery.

The fixture source hashes in the result identify the exact evaluation code.
Subsequent checkout edits add stricter shutdown checks; they are not claimed
to have been executed in this result. The original `build.json` is unchanged;
its build-time status is not a substitute for this separate test evidence.

## Shutdown defect and remaining work

Every stage powered off, but serial logs contain a failed `/var` unmount and
`Unable to finalize remaining DM devices`. The fixture at that time checked
exit status, not positive late-storage teardown, so clean shutdown is **not**
qualified. Inspection found that the packaged dracut restore service was not
activated, its conventional initrd filename was absent, and the custom data
mount path did not explicitly request shutdown restoration.

Source work now connects that service to the verity-protected `luma-initrd`,
requests restoration from the boot hook, and adds an observed-clean marker
only after old-root mounts and device-mapper devices are absent. The builder
checks the teardown inventory; the optional stricter VM fixture requires the
marker for each stage. A rebuilt-image execution is still required.

The source repair passed the retained-root, kernel-less initrd check in
`D:\LumaOS-builds\initrd-shutdown-20260930-01.json` and the complete source suite
in `D:\LumaOS-builds\native-tests-20260930-shutdown-01`: 42 ordinary Rust tests,
20 TPM and 6 PAM explicit invocations, and 32 Linux Python tests. Invocation
counts are not all distinct functions; the ordinary suite intentionally ignores
six isolated functions which the runner invokes separately. Sequence 9 was
started after these checks; its image/boot acceptance is pending.

Full Admin enrollment/service, policy/effects, governed model lifecycle and
1,000 real compact-model cycles, skills/DAG workflow, Wayland desktop,
generated-code isolation and the remaining fault/recovery matrix stay open.
Production inputs and both physical boards remain separate acceptance work.
See [G2 software status](../G2_SOFTWARE_STATUS.md); this image is not the final
all-components G2 release.
