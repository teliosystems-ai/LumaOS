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

A fresh `vm-admin-seq9-tcg-02` retry is running under Secure Boot, TCG and
`--require-clean-shutdown`, with a 5,400-second whole-stage budget and a
2,700-second manual-install operation allowance. No existing disk is reused.
The current retry pipeline queues the full 14-stage regression and five-stage
Qwen3-4B download/inference/offline/recovery suite only after prior success.
All three suites require clean shutdown on normal poweroff stages. Failed
trial/panic stages retain their separate expected reboot assertions.

Only the model suite's install guest permits publisher-download networking.
There are no host disks, physical firmware/TPM changes, forwarded ports or
production private keys in the fixtures. Results remain pending until their
own `result.json` and exported evidence exist.

## Harness repairs

Normal stages in the broader regression now require actual guest poweroff;
host termination is failure cleanup, not acceptance. Strict mode records the
verified shutdown marker and exact `poweroff_stages`. The console reader drains
all queued output after QEMU exit instead of potentially discarding a final
marker. Three unit tests cover queued multi-chunk tails, no-output exit and
nonzero exit. These checks do not themselves qualify an OS shutdown.
