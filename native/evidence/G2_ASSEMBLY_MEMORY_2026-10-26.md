# Fat-LTO assembly memory - 2026-10-26

G2, G3 and GWIN0 remain **incomplete**. This record changes a build bound and
the builder's WSL memory ceiling; it builds no image and qualifies nothing.

## Why sequence-17 assembly failed

Sequence-17 inputs were frozen from commit `4acc3a0` in
`/mnt/luma-build/work/candidate17-source-20261022-a` (877 records,
`build-inputs.json` SHA-256
`0bd95ca5ec7b3ae83c64a2fec97dacb4d9eeb7b4ef067ee1326b88cad5f539ba`). The
committed release profile is unchanged throughout: `lto = true` (fat),
`panic = "abort"`, `overflow-checks = true`, `strip = true`, default codegen
units. Every diagnostic below compiled that frozen tree read-only in the
pinned tools image with one Cargo job and `RUSTFLAGS=-Dwarnings`, on the
dedicated D-backed daemon, with nothing else running.

| Run | Bound | Result |
| --- | --- | --- |
| Assembly `20261023T201237Z-desktop` | 5 GiB | Kernel memory-cgroup OOM kill of rustc in fat-LTO `lto everything`, anon-rss 5,209,388 kB. No image or signing output. |
| Diagnostic, `lto=thin` override | 5 GiB | Passed in 632 s; peak 3,526,074,368 bytes; binary 23,472,640 bytes. Not adopted. |
| Diagnostic, fat with one codegen unit | 5 GiB | No OOM kill, but reclaim livelock for 24.6 h (anon about 5.35 GB, 3,169,504 `max` events, about 16% CPU). Stopped by the operator; container exit 137. |
| Diagnostic, committed profile | 8 GiB | **Passed** in 724 s; peak 6,571,802,624 bytes; largest anon sample 5,639,208,960 bytes; `max`, `oom` and `oom_kill` all 0; zero memory pressure. Binary 22,120,944 bytes. |

Retained public evidence under `D:\LumaOS-builds`:

- Failed assembly, copied without removing its volume:
  `failed-assembly-preserved\20261023T201237Z-desktop\preservation.json`,
  SHA-256 `c9177eb4f13fd56f50c402c290e0b11439d2c36f269c0f1d440e3d089571d8e1`.
  Volume `luma-native-build-20261023T201237Z-desktop` is retained.
- `candidate17-lto-diagnostic-20261023-thin-a.log`, SHA-256
  `8bc56f5e79bc089b90a4eb03f13d2904dd522526e3de7a9ce65d3900f6c63456`.
- `candidate17-lto-diagnostic-20261023-fat-cgu1-a.log`, SHA-256
  `e6ad92df70e225dd31404091d180582153328a4b34ffe9c10bd0e55152648ab9`, and its
  stall observation `candidate17-lto-diagnostic-20261023-fat-cgu1-a.stall.txt`,
  SHA-256 `b7d7248d9818fbcaecd689132fbdaab3288769b320ad4be569ce052b91079c3b`.
- `candidate17-lto-diagnostic-20261026-fat-8g-a.log`, SHA-256
  `1321bc61364e99e4169e423ed78b78aac85f75f37824d91e494fd2ce410f1cf0`;
  8 GiB binary SHA-256
  `c146fe8a3dff98fca693ae51279e46fc9083493f3f29b0288eb851f58f19b7d0`.

Diagnostic binaries are compile evidence only; none is an image input.

## Owner-approved host change

The owner chose to keep fat LTO and expand memory rather than weaken the
release profile. `%UserProfile%\.wslconfig` was created with `[wsl2]`
`memory=12GB` and `swap=2GB`; none existed before. After a coordinated graceful
stop of Docker Desktop, Ubuntu's `docker.service`, and the dedicated
`luma-build-*` services with the store verified unmounted, WSL was restarted.
It then reported 11,959 MiB RAM (previously 7,847 MiB), 2,048 MiB swap and 16
CPUs. The store remounted, the dedicated services were active and the owner's
workloads were restored. No other WSL, Windows or power setting changed.

## Source change

`native/image/build.sh` and `native/image/build_storage.py` accept exactly
`LUMA_NATIVE_ASSEMBLY_MEMORY_GIB` 4, 5 or 8; absent still selects 4 and every
other value is refused. Only the assembly container takes the selected bound;
tools, package and export containers keep 4 GiB. Admission still requires
`MemAvailable` of at least the bound plus a 1-GiB build-host reserve, read
immediately before assembly; swap is never capacity, so 8 GiB needs 9 GiB
available and is refused on the former ~8 GiB WSL VM. The observation is not a
reservation. Release optimization, runtime security checks and VM admission are
unchanged.

`native/tests/test_build_storage.py` now covers the 8 GiB boundary on a 12 GiB
observation, refusal on an 8 GiB host and refusal of 6, 7, 9, 16 and malformed
spellings. All 11 of its tests, and 52 tests across the six modules that read
`build.sh`, the READMEs or the storage module, passed in Ubuntu WSL with
warnings as errors; `bash -n native/image/build.sh` passed.

## Limits

The 8 GiB compile left 2,018,131,968 bytes below its bound. That margin
belongs to this workspace; future source growth must be observed again rather
than assumed. On this 16 GiB machine Windows keeps only about 4 GiB beyond the
WSL ceiling, so heavy Windows applications must be closed during assembly and
VM runs. Sequence 17 must be re-frozen from the commit carrying this change and
rebuilt; this record is not image, boot, installer or hardware evidence.
