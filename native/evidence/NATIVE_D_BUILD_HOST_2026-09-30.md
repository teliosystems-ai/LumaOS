# Dedicated D-backed build-host acceptance - 2026-09-30

The requested host setup is complete and verified. This is development-host
storage evidence, not G2 OS-image, physical recovery or signing qualification.
No complete desktop OS image was built during this setup.

## Layout and preservation

The Git/source checkout remains at `C:\Users\hakim\LumaOS`. Public installers,
images, VM disks and logs remain in `D:\LumaOS-builds`. A new 96 GiB regular
file, `D:\LumaOS-builds\docker\luma-build-v1.ext4`, contains the Linux build
filesystem mounted at `/mnt/luma-build`. Its UUID is
`23304139-0498-4bc6-99a2-c041a29b2e9e`.

The pre-existing 256 GiB `build-store.ext4` was not recognized as an ext4
filesystem and was left untouched. The new file was exclusively created and
only that new regular file was formatted. Allocation on exFAT took about
24 minutes; the subsequent read-only `e2fsck -fn` passed. No physical partition
was formatted, old image/evidence deleted, or default WSL distribution moved.

The dedicated Docker socket is `unix:///run/luma-build-docker.sock`. Its classic
`overlay2` data root is `/mnt/luma-build/docker`. A separate containerd 2.2.2
service uses `/mnt/luma-build/containerd`, with its own socket, execution state
and `luma-build` container namespace. Both services use the verified store and
the `luma-build.slice` no-swap boundary. Client configuration/temp files and
daemon/containerd temp files are inside this Linux store. Small systemd config
files and normal Windows/WSL system activity remain on C:; zero C: writes are
not claimed. Existing Docker/containerd services and their historical data are
preserved. There is no Docker-wide migration, pruning or global WSL shutdown.

The initial isolated Docker startup still connected to Ubuntu's shared
containerd. Validation caught that before copying images or keys. The final
setup explicitly separates containerd too, and admission checks its effective
configuration: Ubuntu merges default configuration imports, so checking only
our TOML file would be insufficient.

## Migration and live checks

Five selected image tags were streamed from the old local engine to the new
one: the two current tool aliases, headless/Wayland package roots and Ubuntu
24.04. Their architecture, OS, variant, execution configuration and rootfs-layer
hashes match. Displayed backend image IDs differ between containerd and classic
Docker, so equality was verified on those content/configuration identities,
not assumed from tag names or displayed IDs. `image-identities.jsonl` records
both backend IDs and the normalized content/configuration digest.

The lab-key volume was streamed directly between trusted local containers;
no public archive or source-tree key file was created. All file identities and
permissions matched without printing key contents or their inventory. The
original key volume remains intact. The D: backing file is not encrypted and
contains laboratory private keys; do not publish it or treat it as production
custody. Linux permissions do not prevent Windows/physical-drive access to the
whole backing file.

The final host run passed:

- Non-root D: preflight, checking the real loop backing file, writable ext4
  mount, identity marker, daemon/runtime placement, client temp/config paths
  and actual Linux-store/D: free capacity rather than an 8 GiB C: reservation.
- A real volume test: file/directory fsync, permission bits, hardlinks,
  symlinks, extended attributes and a private null device node.
- A real network-disabled Docker image build and execution on the new engine.
- Stop of only the new daemon/store, positive refusal while unmounted, then
  successful remount/restart and identical volume contents and image output.
  The refusal traceback in the log is the expected negative assertion.
- All **75 native Linux Python tests**, warnings treated as errors, no skips,
  executed on the new D:-backed Docker daemon. The ordinary daemon remained
  active throughout the explicit stop/remount fixture.

Final observed free capacity was 96,372,764,672 bytes inside the Linux store
and 164,466,786,304 on D:. New desktop builds require 32 GiB inside the store
and 60 GiB on D: (headless 24/40 GiB). The source checkout is still on C:;
its observed free space was 9,444,139,008 bytes, but it is no longer the build
workspace reservation for this verified host profile.

## Evidence and use

Public evidence: `D:\LumaOS-builds\dedicated-build-host-20260930-01`.
`setup.log` and `setup-resume.log` retain earlier stopped validation attempts;
`setup-final.log` ends with the successful completion marker. The expected
initial backend-ID comparison failure was not relabeled as a successful run.

Evidence SHA-256:

- `setup-final.log`: `3471cc6d67ed411cac1e4b656624bb1605b8a449e175b8682374ae5bc5cde0c7`.
- `image-identities.jsonl`: `8296dc349805509c4e47dbb29c4dfd62533cfd61851960668408f85a566ede6a`.

The installed host profile is automatically selected by `native/image/build.sh`.
For an explicit entry point, use `native/image/build-on-d.sh`. Missing D: or a
wrong daemon is a refusal, never an automatic C: fallback. Existing historical
test scripts that explicitly name the old daemon are not silently migrated.
See [the host runbook](../host/README.md) for commands, network scope, no-swap
limitations and safe removal of the drive. These changes are not a pass for
the still-open sequence-9 model timeout or sequence-10 guest acceptance.
