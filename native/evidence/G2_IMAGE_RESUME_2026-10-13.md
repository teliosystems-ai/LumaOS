# G2 image assembly resume

The desktop sequence-13 laboratory image is being packaged from the retained,
sealed OS components. This checkpoint records the resumed build and its source
archive correction. It does not attest a completed export, a successful boot,
production signing, or closure of G2 or Requirement 1.

## Committed implementation and verification

All pre-existing changes were committed and pushed as `07c6b0f`. The verified
resume implementation is committed as `e4a4360`; the actual ext4 recovery-directory
format correction is committed as `b74bd5b`. The final frozen packager passes
407 native regression tests with zero failures and zero skips, including
thirteen focused resume tests. The retained Chrony 4.9 fixture supplies the two
UTC tests that were unavailable in the first, incomplete fixture run.

The real retained FAT inventory and its four boot/menu files pass the ESP
verifier. The real ext4 recovery directory contains only the canonical empty
slots; its payload root directory contains the nine expected members and
`lost+found`. These checks are not boot or installation qualification.

The packager SHA256 is
`6232a4f9851ddef80ecedd32be2eba66d8ba9fc337028c90f56e1ccf34378443`.
Its regression file SHA256 is
`86eb819fb83317de8b29e9a14e7f9b5654eea03cff16c433550c498608abfd51`.
The frozen test source is `/mnt/luma-build/work/g2-image-resume-source-20261013-d`;
the completed test container is `luma-image-resume-native-tests-20261013-d`.

## Source archive correction

The interrupted build's source directory acquired a Python cache during
dependency preparation. Its source archive also contains two cache files
created when the original assembler imported its boot helpers before archiving.
Strict resume validation rejected both inputs; it did not ignore undeclared
files or change the locked source inventory.

A clean capture contains exactly the original 314 product source files. Its
source-lock SHA256 remains
`58be10695ba8165541d4f4caa0f1853190fcf62cb8177230d886e9234e509885`.
The replacement archive was constructed from these files, excluding only the
separate `build-inputs.json` inventory metadata. Independent validation checks
every archived file, its size and digest, and the complete archive tail.

| Archive | SHA256 |
| --- | --- |
| Retained rejected original | `990b8e4d2c25e5a25f5546d269b0ace2b35d0b1ff849b73c2a4bc613d91b970d` |
| Corrected source archive | `7c6dc0689b6b3586e1f1ba85ea5617dba4f2f5d4447d96b2f2ad13ac1055c4ed` |

The original remains in the interrupted build's artifact directory. The corrected
archive is `/mnt/luma-build/work/g2-image-resume-source-archive-20261013-c/native-source.tar.zst`
and is mounted read-only over the resume input's exact archive path. It is an
explicit metadata correction, not byte-for-byte reuse of every old artifact.
The root filesystem, verity data, UKIs, release manifest and signatures remain
unchanged. No private signing key is mounted or used, and no product is rebuilt.

## Running assembly and output

The foreground WSL job uses container `luma-image-resume-20261013-d`, the pinned
tools image `sha256:28e1138fa7e0616b0518a95c1f2599a2205929e247391862bf48319fe5f7594d`,
4 GiB memory, two CPUs, and no network. A prior detached attempt received
SIGTERM when the dedicated Docker service stopped; Docker reports no OOM.
The foreground client stays active through packaging and export. Do not shut
down Ubuntu WSL or the dedicated daemon while this job is running.

The new raw image and working metadata use D-backed ext4 storage at
`/mnt/luma-build/work/g2-image-resume-20261013-d/artifacts`.
After verified packaging succeeds, the same job exports the compressed image
and public metadata to `D:\LumaOS-builds\native\20261013-resumed-desktop-13`.
The interrupted raw image and all rejected attempts remain retained.

The resume checks signed release artifacts, independently pinned public custody,
actual verity, embedded source/release identity, all three UKIs and their PCR
policies, exact payload and ESP contents, both GPT copies, copied partition
ranges, compression integrity and decompressed-image equality. It then writes
checksums and the honest `built-not-yet-boot-tested` build record. The exporter
copies only public files and verifies their destination bytes; it does not
export private keys or the raw image.

Read-only progress command from Windows PowerShell:

```powershell
wsl -d Ubuntu -u root -- docker -H unix:///run/luma-build-docker.sock logs --tail 50 luma-image-resume-20261013-d
```

The image is ready for handoff only after successful packaging and export, with
the compressed image, `build.json` and `SHA256SUMS` present and verified. The raw
image checksum is also retained in `SHA256SUMS`; the raw file remains in ext4
working storage rather than the export directory. Native Ubuntu installation,
boot, security, recovery, model/custody qualification and required physical
hardware executions remain separate acceptance work.
