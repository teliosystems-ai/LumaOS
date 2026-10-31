# Dedicated D-backed build store grow - 2026-10-31

The owner approved growing the dedicated build store from 96 GiB to 160 GiB
and deleting a listed set of rebuildable Rust caches. Both steps are complete
and verified. This is development-host storage evidence, not G2/G3/GWIN0
OS-image, physical recovery or signing qualification. No image, evidence
directory, volume or container was deleted.

Retained logs: `D:\LumaOS-builds\store-grow-20261031-a` (grow) and
`D:\LumaOS-builds\cache-clear-20261031-a` (cache clear).

## Why

Before the grow, `/mnt/luma-build` had 6643523584 bytes (about 6.2 GiB) of
100861726720 available (94% used). That is below the unchanged 32 GiB desktop
preflight minimum, so a desktop image build would have been refused.

## Grow

The store is the ext4 filesystem `23304139-0498-4bc6-99a2-c041a29b2e9e` in the
regular file `D:\LumaOS-builds\docker\luma-build-v1.ext4` on exFAT, attached
as `/dev/loop0` and mounted at `/mnt/luma-build`. The grow ran online from
2026-10-31T06:21:14Z to 06:52:49Z with no build containers running:

1. The installed checker verified the store before any change.
2. `dd` appended 64 GiB (68719476736 bytes) of zeros at offset 96 GiB with
   `conv=notrunc,fsync`. It took 1891 seconds (about 36 MB/s over USB 3.0).
3. `losetup -c` refreshed the loop capacity. The kernel logged
   `loop0: detected capacity change from 201326592 to 335544320`.
4. Online `resize2fs 1.47.2` grew the filesystem from 25165824 to 41943040
   4 KiB blocks (descriptor blocks 12 to 20). The kernel logged
   `resizing filesystem from 25165824 to 41943040 blocks` and
   `resized filesystem to 41943040`. No I/O or filesystem errors were logged.

| Observation | Before | After |
| --- | --- | --- |
| Backing file size | 103079215104 | 171798691840 |
| Filesystem state | clean | clean |
| Block count | 25165824 | 41943040 |
| Free blocks | 1626050 | 18140098 |
| Reserved GDT blocks | 1024 | 1016 |
| `/mnt/luma-build` total bytes | 100861726720 | 168503267328 |
| `/mnt/luma-build` used bytes | 94201425920 | 94201425920 |
| `/mnt/luma-build` available bytes | 6643523584 | 74285064192 |
| D: available bytes | 284629401600 | 215901274112 |

## Storage check

The storage check stays exact. Only its expected size moved, from
`SIZE = 96*1024**3` to `SIZE = 160*1024**3`. No other check changed. The
32 GiB desktop and 24 GiB headless preflight minimums are unchanged, as are
the 60 GiB and 40 GiB external minimums.

- The installed copy at `/usr/local/libexec/luma-build-storage.py` changed
  from sha256 `4d19d6e14a569d059efeeb3e2aa73a86a8eabe36558a5636c604b9902ffd8602`
  to `6b7ca488936bb4ccc73952a83719fd173498574cff3b4e393a57bfa4e0099f2d`.
  Its full diff is that one line. The previous copy is retained as
  `luma-build-storage.py.before`. The installed copy is an older revision of
  `native/image/build_storage.py`. It does not have the later
  `assembly-memory` action, and this grow did not update it beyond the size
  line.
- In the repository, `native/image/build_storage.py` changes only the same
  line.
- After the grow, the installed and repository checkers each printed
  `Verified dedicated D:-backed ext4 store.`

## Cache clear

The owner approved deleting six old rebuildable Rust target directories and
the leftover `resources-tmp` test directories inside the Docker volume
`luma-g2-rust-targeted-cache-20261001`. The approval described about 30
`resources-tmp` directories, but a list-only survey found 61 (about 995 MB).
Because the count did not match, none of them were deleted. They stay until
the owner decides.

The six target directories were deleted from 2026-10-31T06:54:23Z to
06:54:26Z, with no build containers running. Sizes are from `du -sb`:

| Directory | Bytes |
| --- | --- |
| `target` | 1414067881 |
| `target-claude-g3-strict` | 1430261597 |
| `g2-integrated-20261012` | 986623642 |
| `debug` | 660788943 |
| `target-claude-g3` | 448199782 |
| `target-nf08-core-20261020` | 441650056 |

The volume's top-level entries went from 212 to 206, and the diff lists
exactly those six names. Used bytes went from 94201425920 to 88806985728, so
79679504384 bytes (about 74.2 GiB) are available. The volume itself, the
current `target-claude-g3-functional` directory and every other entry remain.
The checker still printed `Verified dedicated D:-backed ext4 store.`

## Open host matters

- Windows reports D: as "Full Repair Needed". No repair or `chkdsk` was run.
  The owner should back up and repair D: on their own schedule.
- The backing file contains private laboratory keys and is **not encrypted**.
  Do not publish it or use it for production signing custody.
