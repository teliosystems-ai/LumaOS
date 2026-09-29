# TPM-rule sysroot integration checkpoint - 2026-09-29

The owner freed C: space; the new build preflight passed with approximately
18.8 GiB available on C:. Large image artifacts remain on D:, while cached
Docker layers, Linux workspaces and private lab keys remain on C:.

## Build failure caught before image generation

Sequence 7 (`20260929T194815Z-headless`) compiled and generated an initrd, but
the exact-content check rejected it because the root-only TPM udev rule was
absent. No completed raw/compressed image or verified export was produced.
The failed build/logs were retained.

The earlier kernel-less fixture ran without `--sysroot` and passed. In the
actual builder, dracut's `inst_simple` first checks the build host path, not
the target root; the rule existed only inside the target. The module now uses
`inst_multiple`, which resolves the separate root through dracut-install, and
propagates an installation failure. The builder still checks exact rule bytes
alongside the measured-phase helper, unit, activation and TPM library.

## Executed regression

`native/tests/initrd_sysroot.py` generated and verified a kernel-less initrd
against the real retained sequence-7 root, mounted read-only, with the repaired
module overlaid read-only. The build host explicitly had no Luma TPM rule.
Temporary output stayed in the disposable container. No TPM, private signing
keys, physical disks, host mount namespace or added privileges were supplied.

Retained passing evidence: `D:\LumaOS-builds\initrd-sysroot-20260929-01.json`.
It pins the runner, verifier, rule and candidate module bytes. Tools image:
`sha256:40d9d50237189a8880580e16edcaf1a3ff81ac996be9b4f180d397c7140b1bce`.
This is a kernel-less assembly regression, **not** an OS boot or enrollment test.

The complete native regression rerun also passed in
`D:\LumaOS-builds\native-tests-20260929-sysroot-01`: 42 ordinary Rust tests,
20 explicit TPM and 6 PAM invocations, and 27 Linux Python tests. Six isolated
Rust functions are ignored in the ordinary suite and invoked by the runner;
invocation counts are not all distinct functions. That runner retains its
transcripts and exact source inventory, including the new sysroot regression.

Reproduce inside a fresh tools container with the same read-only mounts and
a writable evidence directory mounted at `/out`:

```sh
python3 /repo/native/tests/initrd_sysroot.py --output /out/FRESH-RESULT.json
```

The runner requires `/work/root` to be read-only, refuses an existing output,
and rejects a build-host copy of the rule that could mask the original defect.
For a source repair, bind the candidate `module-setup.sh` read-only over
`/work/root/usr/lib/dracut/modules.d/92luma-pcrphase/module-setup.sh`.

## Current rebuild

Sequence 8 (`20260929T195529Z-headless`) is building with the corrected module.
It has passed the full-kernel initrd check and reached filesystem assembly.
Work: `D:\LumaOS-builds\work\20260929T195529Z-headless`.
Expected export: `D:\LumaOS-builds\native\20260929T195529Z-headless`.

An environment-local bounded pipeline waits for that exact build to finish,
requires its successful verified-export log markers and artifact records, then
runs `admin_vm_test.py` on a fresh `vm-admin-seq8-tcg-01` virtual disk with
Secure Boot and a private software TPM. No VM starts if the build fails or the
wait expires. Successful VM evidence is exported only after every stage passes.
The build, pipeline and VM logs are separate under the ignored `.luma/` folder.

Export and VM acceptance remain pending. The [G2 software register](../G2_SOFTWARE_STATUS.md)
still applies; a passing assembly check is not a completed installer, Admin
enrollment, hardware qualification or all-components G2 release.
