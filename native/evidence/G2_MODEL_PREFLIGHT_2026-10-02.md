# G2 model reconfiguration preflight checkpoint

Date: 2026-10-02. The native `model-install-check MODEL-ID` command now reads
the selected image-owned profile and checks installed-system RAM, effective
cgroup-v2 limit and available storage without stopping the running model or
creating a model cache. Its success reports `preflight_admitted: true`,
`reservation: false` and `activation_guaranteed: false`. `model-install` uses
the same preliminary check under its operation lock before issuing the
`systemctl stop` request. Activation repeats admission after the stop; a
preflight result is never reused as authority for the later operation.

The final bounded offline run used
`D:\LumaOS-builds\g2-model-preflight-targeted-20261002-02`. The frozen source
manifest `source/build-inputs.json` has SHA-256
`2c04f692123af2a1959a5e1996f94b7123c6c86a061be487d23a275b97029fa4`.
The `test.log` SHA-256 is
`ead6fb89f423df20ebe558e32c23a90e43b1becd5d3d9c1891e52b0afe38a1b0`.
The D-backed Docker run had no network, host TPM, VM or model load and used one
CPU/Cargo job, 768 MiB with no extra swap and a 128-PID limit.

Nineteen Rust model tests passed, including refusal before the simulated
service stop, successful operation ordering, safe read-only cache inspection,
and the earlier cgroup/runtime tests. Two model-runtime policy checks and
fifteen existing VM-harness unit tests passed, as did formatting, a
warning-clean offline build and compiled CLI help. The earlier `-01` snapshot
failed to compile because the new helper's stop/restart closures returned
command output instead of unit; its log is retained. The final `-02` source
fixed that mismatch and passed.

This reduces predictable capacity-related downtime; it does not guarantee
activation after preflight. Network/download failures, an unexpectedly changed
resource observation, the `systemctl stop` result, partial credential or
selection writes, and restart failure can still leave the previous worker
stopped. No transaction, generation lease, pressure manager or reviewed
interrupted-activation recovery is claimed. The new command and transition
must be exercised on the consolidated image and separate native Ubuntu
machine. G2 remains open.
