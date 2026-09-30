# Sequence-9 image checkpoint — 2026-09-30

G2 is not complete. This is a laboratory-signed headless image, not the final
all-components image or production/hardware qualification.

## Built artifacts

Build/export completed for `20260929T221048Z-headless`:

- Export: `D:\LumaOS-builds\native\20260929T221048Z-headless`.
- Work: `D:\LumaOS-builds\work\20260929T221048Z-headless`.
- Raw image: `luma-native-lab-20260927-headless-9.img`.
- Raw SHA-256: `c89206eb0ce0a846c08b81b43092392485ea956e399086bfa1df7084f3846299`.
- Compressed SHA-256: `9c296d7d651a36ace809336731531e02d959928857a91326c194bcd212e533db`.

This image includes the late-shutdown repair but predates the transactional
recovery-export implementation added later on September 30. Later source
changes do not modify these built artifacts or retroactively strengthen results.

## Evaluation

`vm-admin-seq9-tcg-01` booted the live image with virtual Secure Boot/software
TPM, passed tampered-bundle and insufficient-RAM refusal checks, then timed out
waiting for manual installation. Its final progress showed both slot writes
and encrypted-data/key-slot setup; there was no reported native installer
error. The 900-second operation deadline expired. The partial disposable disk
and serial/QEMU logs are retained. This is a failed/timed-out evaluation, not
an installation pass or evidence that the image itself is necessarily defective.

The pipeline stopped before installed/PAM/PCR/shutdown, recovery and model
evaluation. It did not export successful evidence for that failed run.

A fresh `vm-admin-seq9-tcg-02` retry passed under Secure Boot, TCG and
`--require-clean-shutdown`, with a 5,400-second whole-stage budget and a
2,700-second manual-install operation allowance. It used a new disposable disk.
All four stages (install, installed, cold reboot, other signed slot) passed
native PAM checks, measured-credential continuity/refusal and the strict late
filesystem/DM teardown assertion. It did not test product Admin enrollment.

Evidence is exported under `admin-shutdown-vm-evidence-02` in the image export
directory. Its `result.json` SHA-256 is
`9e064aad4b5c8db7f613d3a6cd31f5089cf075fb8e9a23f290799b260c618f0e`.
All four serial logs contain a fresh `LUMA_SHUTDOWN_STORAGE_CLEAN` marker.
They still show an initial `/var` unmount warning before switching into the
shutdown initrd; dracut subsequently unmounts `/oldroot` and the observation
hook verifies that old-root mounts and DM devices are gone. This is verified
late teardown, not a claim of warning-free early shutdown or physical power-off
qualification.

The full 14-stage regression subsequently **passed** in
`vm-regression-seq9-tcg-02`, including failed-health trial fallback, recovery
export/disable/repair, three corrupted-root trial failures, fallback and repair
of slot A. All eight normal poweroff stages passed strict late teardown.
Evidence is exported under `regression-vm-evidence-02`; result SHA-256:
`d253aa26629e5ffa0032a38b08cc89ad4177c3772dd15b0975d645cef4faf1f6`.
Its `atomic_export_tested` remains false: sequence 9 predates that repair.

The following model command failed at argument parsing because the retained
`model_vm_test.py` did not accept `--timeout`. No model test passed on that
invocation and no guest was created by it. The resumed five-stage Qwen3-4B
download/inference/offline/recovery suite now runs in `vm-model-seq9-tcg-02`
with the exact retained sequence-10 harness source and its existing internal
5,400-second stage deadline, omitting the unsupported option. That harness
records its source hashes; it does not modify the sequence-9 image. The
checkout separately adds and tests an explicit bounded timeout CLI option.
All three suites require clean shutdown on normal poweroff stages. Failed
trial/panic stages retain their separate expected reboot assertions.

Only the model suite's install guest permits publisher-download networking.
There are no host disks, physical firmware/TPM changes, forwarded ports or
production private keys in the fixtures. The resumed model result remains
pending until its own `result.json` and exported evidence exist.

## Harness repairs

Normal stages in the broader regression now require actual guest poweroff;
host termination is failure cleanup, not acceptance. Strict mode records the
verified shutdown marker and exact `poweroff_stages`. The console reader drains
all queued output after QEMU exit instead of potentially discarding a final
marker. Three unit tests cover queued multi-chunk tails, no-output exit and
nonzero exit. These checks do not themselves qualify an OS shutdown.
