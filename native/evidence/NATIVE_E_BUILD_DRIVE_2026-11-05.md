# Build drive moved from D: to E:, 2026-11-05

The owner installed a new drive and asked that all builds use E: instead of D:.
Source remains on C:. The previous drive record is the
[D: build host checkpoint](NATIVE_D_BUILD_HOST_2026-09-30.md).

| Drive | Hardware | Filesystem | Windows disk |
| --- | --- | --- | --- |
| D: (former) | Sonnics USB 3.0, 931.5 GiB | exFAT | Disk 2 |
| E: (current) | Lexar SSD M7 1TB, NVMe | NTFS | Disk 0 |

## Copy result

The owner copied `D:\LumaOS-builds` to `E:\LumaOS-builds` with Explorer.
90,256 of 90,257 files arrived (373.75 GiB). The one missing file is the
160 GiB dedicated build store, `docker\luma-build-v1.ext4`
(UUID `23304139-0498-4bc6-99a2-c041a29b2e9e`). Explorer stopped at 30% with
"Can't read from the source file or disk", removed its partial copy, and
left an "Interrupted Action" dialog for the owner. The Windows System log
recorded Disk event 7 (`\Device\Harddisk2\DR2, has a bad block`) nine times
at 11:45:23–11:45:55. Disk 2 is D:. Earlier the same day, at 09:33–09:34,
the log has eight more event-7 entries and ten event-153 retries at logical
block addresses `0x5e073800`–`0x5e077200`. This is a media read failure on
D:, consistent with the bad sectors found by `chkdsk` on 2026-09-29.

## Verified on E:

Checked on 2026-11-05 by reading the E: copies only:

| Folder under `E:\LumaOS-builds` | Result |
| --- | --- |
| `downloads\candidate19-20261028T162354Z-desktop-a` | 14 of 14 on-disk files match `SHA256SUMS` |
| `downloads\candidate20-20261103T215655Z-desktop-a` | 14 of 14 on-disk files match `SHA256SUMS` |
| `native\20261028T162354Z-desktop` | 11 of 11 on-disk files match `SHA256SUMS` |
| `native\20261103T215655Z-desktop` | 11 of 11 on-disk files match `SHA256SUMS` |
| `gwin-integrated-package-20261103-e9a11aa-2wCUNqTs-public` | 7 of 7 match, with the build-container `/evidence/...` paths mapped to the folder |

Each `SHA256SUMS` above also lists the raw `.img`. That entry is checked
after decompressing the `.img.zst`; the raw image was not stored in these
folders on D: either.

## Old `build-store.ext4`

`docker\build-store.ext4` (274,877,906,944 bytes, created 2026-09-29 for an
abandoned daemon proposal) copied without error. A full read of the E: copy
found only zero bytes and no ext4 signature, matching the 2026-09-30 record
that it was never formatted or used. It held no keys. The owner deleted
both the D: and E: copies on 2026-11-05.

## Host profile

Each WSL Ubuntu start runs `luma-build-store.service`, which still named D:.
At 11:34 and 11:39, while Explorer was reading the store file, the service
failed and the dedicated daemon did not start. From 11:51 to 11:57 four
distro restarts mounted the D: store read-write and started the dedicated
Docker daemon; each ended with a clean stop and unmount. No Luma container
was running when checked at 11:52.

At 11:57:45 the repository versions of `build_storage.py`, `environment.sh`
and the three unit files were installed to `/usr/local/libexec`,
`/etc/luma-build` and `/etc/systemd/system`. The previous files are kept in
`/root/luma-build-pre-e-20261105`. At 11:57:46 the store service refused to
start because `E:\LumaOS-builds\docker\luma-build-v1.ext4` does not exist.
The dedicated daemon is therefore unavailable until the store is on E:. It
does not fall back to D: or C:.

## Second copy attempt and what the bad blocks hold

The owner restarted the Explorer copy. It ran at about 73 MiB/s and stopped
again at 30% at 12:39 with the same error. The System log recorded event 7
eight times and event 153 four times, at logical block addresses
`0x5e073818`, `0x5e073c18`, `0x5e074018` and `0x5e074418`. These lie inside
the 09:34 range, so the same sectors fail on every read.

The store file's exFAT cluster map (`FSCTL_GET_RETRIEVAL_POINTERS`, 15
extents; cluster area at sector 32,768; 256 KiB clusters; partition offset
1 MiB) places that range at file offsets 51,791,527,936–51,799,130,112
(48.23 GiB, 30.1% of the file). That is at most 1,857 ext4 blocks,
12,644,416–12,646,272, in block group 385. Reading the D: file without
mounting it (`dumpe2fs`, `debugfs testb`/`icheck`):

| Check | Result |
| --- | --- |
| Filesystem | UUID `23304139-…`, state `clean`, no `needs_recovery`, last write 11:57:45 |
| Owner of all 1,857 blocks | inode 8, the ext4 journal (512 MiB, 131,072 blocks) |
| Journal layout | journal blocks 0–131,071 at filesystem blocks 12,615,680–12,746,751; the bad range is journal blocks 28,736–30,592 |
| Journal header | journal block 0 (filesystem block 12,615,680) is outside the bad range |
| Journal state | `Journal start: 0`, so the journal is empty and nothing is replayed |

The unreadable sectors therefore hold old journal log space, which a clean
mount never reads and later overwrites. No file, Docker layer or key is on
them, and a copy that zero-fills them loses no data.

## Rescue copy

After the analysis above, a Windows rescue copy ran from 13:04:27 to 13:43:37
(2,350 s, about 70 MiB/s). It opened the D: file for reading only, shared for
reading only, so nothing could write it during the copy. It wrote a new
file, `E:\LumaOS-builds\docker\luma-build-v1.ext4.partial`. It read 8 MiB at a
time, then re-read the one failed 8 MiB chunk (at 51,791,265,792) through an
unbuffered handle at 256 KiB and then 4 KiB, filling only unreadable 4 KiB
blocks with zeros.

| Item | Result |
| --- | --- |
| Bytes written | 171,798,691,840 (the full file) |
| Unreadable | 12,288 bytes: offsets 51,791,884,288 (4 KiB) and 51,791,892,480 (8 KiB) |
| ext4 blocks zero-filled | 12,644,503, 12,644,505, 12,644,506 = journal blocks 28,823, 28,825, 28,826 |
| D: file size and modification time | unchanged from start to end |

The other 1,854 blocks in the logged range were read on retry. All three
zero-filled blocks are in the empty journal's log space.

## Check and bring-up on E:

Read-only checks of the `.partial`, finished 13:44:44:

| Check | Result |
| --- | --- |
| Size | 171,798,691,840 bytes |
| UUID | `23304139-0498-4bc6-99a2-c041a29b2e9e`, matching `/etc/luma-build/storage.json` |
| State | `clean`, last write 11:57:45, `Journal start: 0`, same features as on D: |
| `e2fsck -fn` | exit 0; passes 1–5 clean; 957,453 inodes and 36,112,051 of 41,943,040 blocks in use. It suggested three optional extent-tree optimisations (inodes 689,492, 1,335,727 and 7,235,180), which are not errors |

At 13:45 the file was renamed to `luma-build-v1.ext4`. The services then
started from the E: file, and every later WSL start brought them up again
without help (the last time at 13:47:07).

| Check | Result |
| --- | --- |
| Services | `luma-build-store`, `luma-build-containerd`, `luma-build-docker` active |
| Mount | `/dev/loop0` (back file `/mnt/e/LumaOS-builds/docker/luma-build-v1.ext4`) on `/mnt/luma-build`, ext4, `rw,noatime` |
| `build_storage.py verify` | "Verified dedicated E:-backed ext4 store.", identity marker UUID matches |
| Daemon | `DockerRootDir /mnt/luma-build/docker`, `overlay2`, 33 containers (0 running), 89 image layers; tagged images `luma-native-root`, `luma-native-tools`, `luma-utc-targeted-tools`, `ubuntu:24.04` present |
| Volumes | all 28 present, including the build volumes of sequences 19 (`20261028T162354Z`) and 20 (`20261103T215655Z`) and `luma-native-lab-keys` |
| Lab keys | `pcr-policy.key`, `release.key`, `secureboot.key`: mode 600, uid 0; public-key hashes equal to the C:-backed daemon's copies |
| `skills-lab.key` | mode 600, uid 0; its public key hash `46f98d76f5d4d327` equals the `usr/share/luma-os/skills/skills.pub` built into sequences 19 and 20 |

The store therefore arrived on E: intact. Only key metadata and public-key
hashes were printed.

## Build headroom

`build_storage.py preflight --edition desktop` fails:
`/mnt/luma-build: 23866953728 free bytes; minimum 32 GiB`. E: itself has
723,968,188,416 bytes free, well over the 60 GiB minimum. The free-block count
(5,830,989) is the same as on D: at 11:57:45, so the shortfall dates from the
sequence 20 build. The move did not cause it. The store is 86% used: the
Docker root holds 93 GiB, of which the sequence 19 and 20 build volumes are
27 GiB each, and `work/` holds 45 GiB, including five GWIN package folders of
about 5 GiB each. No limit was lowered. The next desktop build needed about
10 GiB more room. The owner then approved both remedies: remove old build
data, and grow the store file on E:.

## Old build data removed

Removed 17:27:30–17:29:12 by a script that stopped on any unexpected result.
Its output is in this section.

| Removed from the store | Bytes | Copy kept on E: (checked before removal) |
| --- | --- | --- |
| volume `luma-native-build-20261027T132536Z-desktop` (sequence 17) | 7,383,705,853 | `native\20261027T132536Z-desktop`, 11 of 11 files match `SHA256SUMS` |
| volume `luma-native-build-20261028T114956Z-desktop` (sequence 18) | 7,300,506,439 | `native\20261028T114956Z-desktop`, 11 of 11 files match `SHA256SUMS` |
| `work/gwin-integrated-package-20261020-2fZO16wr` | 5,434,075,803 | `gwin-integrated-package-20261020-2fZO16wr-public`, 7 of 7 match |
| `work/gwin-integrated-package-20261027-xD2dTQpC` | 5,289,738,179 | `gwin-integrated-package-20261027-xD2dTQpC-public`, 7 of 7 match |
| `work/gwin-integrated-package-20261031-cAX3a2u0` | 5,289,788,612 | `gwin-integrated-package-20261031-cAX3a2u0-public`, 7 of 7 match |

Checks before removal:

- The `.img.zst` inside each removed volume was hashed in the store and
  matched the E: export:
  - sequence 17, `luma-native-lab-20260927-desktop-17.img.zst`:
    `201f66662307e8373f75f9a50be742bbd92123600ef1a57f9b93c2ba4eb9070d`;
  - sequence 18, `luma-native-lab-20260927-desktop-18.img.zst`:
    `c7bf36c7f4c33e47e664967aab727962759abc127c2f31af8562d6fc966564a3`.
- No container, running or stopped, referenced either volume.
- No container was running at the start or just before removal.

What was kept is in `E:\LumaOS-builds\retired-store-evidence-20261105`
(35,907,581 bytes, with a `README.txt`). Each removed item has:

- a full listing (`full-listing.txt.gz`);
- the small records in `files/`:
  - for each volume, every file up to 16 MiB outside `root/`, `cargo/` and
    `source/`, including each VM smoke `result.json`: 845 files
    (17,309,703 bytes) for sequence 17 and 851 files (16,654,931 bytes) for
    sequence 18;
  - for each work folder, its 10 top-level files;
- `files.sha256`, checked against the originals before removal.

The paths under `/mnt/luma-build/docker/volumes/luma-native-build-20261027T132536Z-desktop/`
named in
[candidate17_execution_2026-10-27.json](candidate17_execution_2026-10-27.json)
are now under `volumes\luma-native-build-20261027T132536Z-desktop\files\` in
that folder.

Result: 31,040,106,496 bytes freed; 54,907,060,224 bytes available in the
store. 26 volumes remain, including sequences 19 and 20 and
`luma-native-lab-keys`. `build_storage.py verify` passed afterwards.

## Store grown from 160 to 256 GiB

The grow followed the
[2026-10-31 procedure](NATIVE_D_BUILD_STORE_GROW_2026-10-31.md). It ran online
from 17:29:42 to 17:38:41 (+01:00) with no container running. The log is in
`E:\LumaOS-builds\store-grow-20261105-a\grow.log`.

1. Prechecks:
   - The installed checker verified the store.
   - The file was exactly 160 GiB and backed `/dev/loop0`.
   - The filesystem had 41,943,040 blocks.
   - E: had room for the grow plus the 60 GiB build minimum.
   - The installed checker matched the repository's except for the size
     line.
2. `dd` appended 96 GiB (103,079,215,104 bytes) of zeros at offset 160 GiB
   with `conv=notrunc,fsync`. It took 536 s (192 MB/s).
3. `losetup -c` refreshed the loop capacity. The kernel logged
   `loop0: detected capacity change from 335544320 to 536870912`.
4. Online `resize2fs 1.47.2` grew the filesystem to 67,108,864 4 KiB blocks
   (descriptor blocks 20 to 32). The kernel logged `resizing filesystem from
   41943040 to 67108864 blocks` and `resized filesystem to 67108864`. No I/O
   or filesystem errors were logged.

| Observation | Before | After |
| --- | --- | --- |
| Backing file size | 171,798,691,840 | 274,877,906,944 |
| Filesystem state | clean | clean |
| Block count | 41,943,040 | 67,108,864 |
| Free blocks | 13,409,140 | 38,180,212 |
| Reserved GDT blocks | 1,016 | 1,004 |
| `/mnt/luma-build` total bytes | 168,503,267,328 | 269,965,578,240 |
| `/mnt/luma-build` used bytes | 113,579,429,888 | 113,579,429,888 |
| `/mnt/luma-build` available bytes | 54,907,060,224 | 156,369,371,136 |
| E: available bytes | 723,927,384,064 | 620,847,898,624 |

The storage check stays exact. The only change is the expected size, which
went from `SIZE = 160*1024**3` to `SIZE = 256*1024**3` in
`native/image/build_storage.py`. The preflight minimums are unchanged: 32 GiB
desktop and 24 GiB headless for the store, and 60 GiB and 40 GiB for E:.

- The installed copy at `/usr/local/libexec/luma-build-storage.py` changed
  from sha256 `b3b1a32c227d6a774d0921dc9c6dcea0cb04a4af0811135b9f788644b7ab7a08`
  to `778b1e1552f5cb3fc094bb9ce07f2e53fd344a48d97c2cb0f7ac9ae87bf05297`. Its
  full diff is that one line, and it is now identical to the repository
  file. The previous copy is kept as `luma-build-storage.py.before-256g`.
- The installed and repository checkers each printed `Verified dedicated
  E:-backed ext4 store.`
- The desktop preflight passed: `/mnt/luma-build: 156369371136 free bytes;
  minimum 32 GiB`, and `/mnt/e/LumaOS-builds: 620847898624 free bytes;
  minimum 60 GiB`.
- At 17:39:
  - the three services were active;
  - the daemon used `/mnt/luma-build/docker` with `overlay2`;
  - 26 volumes were present;
  - `native/tests/test_build_storage.py` ran 12 tests, all passing.

The grow did not restart the WSL distro, so the 256 GiB file has not yet
been mounted from a cold start. The start-up path uses the same exact-size
check that passed here, so the next WSL start mounts it.

## Open

- None for the build drive. The original store file on D:
  (`D:\LumaOS-builds\docker\luma-build-v1.ext4`) has not been touched;
  deleting it is the owner's decision.
