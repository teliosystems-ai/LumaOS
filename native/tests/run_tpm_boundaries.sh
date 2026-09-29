#!/bin/bash
# No host devices, privilege grants, network or Docker socket are needed.
set -euo pipefail
if [ "${LUMA_TPM_RUNNER_SNAPSHOT:-0}" != 1 ]; then
    task_runner=$(mktemp /tmp/luma-tpm-runner-XXXXXXXX)
    cp -- "$0" "$task_runner"
    export LUMA_TPM_RUNNER_SNAPSHOT=1
    exec bash "$task_runner" "$@"
fi
output=${1:?supply a fresh evidence directory}
test -f /.dockerenv
test ! -e "$output"
snapshot=$(mktemp -d /tmp/luma-tpm-source-XXXXXXXX)
mkdir "$snapshot/rust"
cp -a /repo/rust/.cargo /repo/rust/Cargo.toml /repo/rust/Cargo.lock /repo/rust/luma-platform "$snapshot/rust/"
cp -a /repo/native "$snapshot/"
cmp -- "$0" "$snapshot/native/tests/run_tpm_boundaries.sh"
cd "$snapshot/rust"
cargo fmt --check
python3 "$snapshot/native/tests/tpm_integration.py" --repository "$snapshot" --output "$output"
python3 -W error -m unittest discover -s "$snapshot/native/tests" -v 2>&1 | tee "$output/native-tests.txt"
cd "$snapshot"
sha256sum rust/Cargo.toml rust/Cargo.lock rust/.cargo/config.toml \
    rust/luma-platform/Cargo.toml rust/luma-platform/build.rs \
    rust/luma-platform/src/*.rs rust/luma-platform/src/*.c \
    native/tests/run_tpm_boundaries.sh native/tests/*.py native/image/*.py \
    native/image/overlay/usr/lib/dracut/modules.d/92luma-pcrphase/module-setup.sh \
    native/image/overlay/usr/lib/dracut/modules.d/91luma/*.sh \
    native/image/overlay/etc/pam.d/luma-admin \
    native/image/overlay/etc/udev/rules.d/99-luma-tpm.rules \
    native/image/overlay/usr/lib/systemd/system-generators/luma-boot-generator \
    native/image/overlay/etc/systemd/system/media-luma.mount \
    native/image/overlay/etc/systemd/system/luma-live-*.service \
    native/image/Dockerfile.tools > "$output/source-sha256.txt"
