# G2 regression result and snapshot build repair — 2026-10-01

G2 remains **incomplete**. This checkpoint closes a selected image regression
and repairs a build dependency conflict; it does not claim complete product
Admin, workflow, model lifecycle, desktop or physical acceptance.

## Committed baseline

Commit `a3fefa2` (`Bound model inference and strengthen G2 VM acceptance checks`)
contains the previous inference/VM acceptance repairs. The working tree was
clean immediately after that commit. No push was performed. The snapshot
bootstrap repair and this follow-up evidence are subsequent changes.

## Sequence-10 image regression: passed

The exact headless image with SHA-256
`7470551731871555f04764353dde7aafb62700e76e0fb7f2dfd5f7a088cac096`
passed all 14 stages in `vm-regression-seq10-20261001-01`: install, installed,
three failed trials, fallback, recovery, repaired boot, three corrupt-root
trials, corrupt-root fallback, corruption repair and repaired-A boot.

The run used UEFI Secure Boot, TCG and isolated software TPM state. It verified
atomic recovery export and bounded broker IPC. Eight normal stages completed
guest-requested poweroff with fresh verified late-storage-cleanup markers.
The installed UID-990 slow-header and slow-body requests were refused in
approximately 2.005 and 2.008 seconds; a fresh status request succeeded after
each refusal. No physical device qualification or full-G2 gate closure is
claimed. The install-stage TPM timeout and initial `/var` unmount warnings
remain in the transcript; the overall run passed, but is not warning-free.

Public evidence was exported using the run's frozen collector to:

`D:\LumaOS-builds\native\20260930T073705Z-headless\regression-vm-evidence-20261001-01`

- `result.json` SHA-256:
  `a7e803a35b3b2b1790f0a2a6483d6e7bcfda49bc0fdb228bdb353b1f157c6deb`.
- `evidence-files.json` SHA-256:
  `69b1563b3eaac82d4c9574bc1a4fb422ebdc3b116b2e69e10113561162c01fad`.

Only the result, serial/QEMU logs and their digest inventory were exported.
Disks, NVRAM and private software TPM state were excluded. Source identities
are recorded in `result.json`; this historical harness/image does not inherit
the later bounded model helper or follow-up-runner changes.

## Desktop package failure and repair

The first queued desktop sequence-11 attempt, build ID
`20261001T072028Z-desktop`, failed in the tools container before image assembly.
Its retained log is
`D:\LumaOS-builds\g2-desktop-build-20261001-01\build.log`.
The unpinned CA bootstrap upgraded `libssl3t64` to `3.0.13-0ubuntu3.16` from
moving updates. Later, the fixed `20260927T000000Z` snapshot supplied
`libssl-dev` requiring exactly `3.0.13-0ubuntu3.15`. No desktop image was
assembled by this failed attempt.

Both native Dockerfiles now bootstrap exact CA/keyring/OpenSSL versions from
the signed release-only `noble main` archive, excluding other source lists
for that operation. The pinned base already contains the Ubuntu archive
verification keyring. The temporary source file is removed; subsequent
package operations continue to select the pinned HTTPS snapshot. The tools
Dockerfile's standalone default base now matches the driver's existing digest
pin. No signature/TLS bypass, forced downgrade or snapshot advancement is used.

Direct HTTP snapshot bootstrap was evaluated but redirects to HTTPS, so it
cannot solve the missing-CA problem. The failed isolated probes were retained,
not treated as passing evidence. A third real disposable-container probe
successfully installed the exact bootstrap packages, then used the verified
HTTPS snapshot to install `libssl-dev`; OpenSSL, `libssl3t64` and `libssl-dev`
all finished at `.15`. Probe transcript:

`D:\LumaOS-builds\g2-snapshot-bootstrap-probe-20261001-03\probe.log`

Transcript SHA-256:
`14beaf7222ab60bcaa3713c7908350d42d3dd71291f3d02afb3dc5b172a1cefb`.

Three new source-policy tests check matching digest-pinned bases/bootstrap,
release-only authenticated exact bootstrap inputs, and snapshot selection on
every subsequent package operation. These tests do not substitute for a
successful real build. The full **96-test native Linux Python suite passed**
with warnings treated as errors and no skips before the build began. Its
transcript is the first section of the retry log below.
The three new portable source-policy tests also passed under native Windows
Python. `git diff --check` passed.

## Fresh desktop build: running, not accepted

A fresh sequence-11 attempt, build ID `20261001T090338Z-desktop`, runs after
the full native Python suite, with the same verified cached runtime and a new
137-file frozen source capture. Its log is:

`D:\LumaOS-builds\g2-desktop-build-20261001-02\build.log`

Source capture:
`D:\LumaOS-builds\native-sources\20261001T090338Z-desktop`.
`build-inputs.json` SHA-256:
`8596a569b0cb3be9ef065d90e816bf22ce783676ab8978cbc92828e6d8a6d85b`.
The real Docker bootstrap step has succeeded; the tools package build is
currently fetching the pinned snapshot packages. Assembly/export and VM
acceptance have not yet completed.

Bulk Docker/containerd, temporary files, source capture, packages, image
artifacts and exports remain on the dedicated D: profile. The checkout remains
on C:. Prior failed builds and images were preserved. An eventual successful
assembly still requires installed desktop/GDM/session evaluation and the
bounded model retry; neither result is claimed here.
