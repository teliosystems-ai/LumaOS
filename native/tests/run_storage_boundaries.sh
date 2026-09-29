#!/bin/bash
# Disposable Linux container only. A private mount namespace and CAP_SYS_ADMIN
# are required for the tmpfs/bind tests; never mount a host device into this run.
set -euo pipefail
# Bash otherwise reads later lines from the writable bind-mounted checkout
# while long tests execute. Re-exec an immutable per-container script copy.
if [ "${LUMA_STORAGE_RUNNER_SNAPSHOT:-0}" != 1 ]; then
    task_runner=$(mktemp /tmp/luma-storage-runner-XXXXXXXX)
    cp -- "$0" "$task_runner"
    export LUMA_STORAGE_RUNNER_SNAPSHOT=1
    exec bash "$task_runner" "$@"
fi
output=${1:?supply a fresh evidence directory}
test -f /.dockerenv
test ! -e "$output"
mkdir -- "$output"
snapshot=$(mktemp -d /tmp/luma-storage-source-XXXXXXXX)
mkdir "$snapshot/rust"
cp -a /repo/rust/.cargo /repo/rust/Cargo.toml /repo/rust/Cargo.lock /repo/rust/luma-platform "$snapshot/rust/"
cp -a /repo/native "$snapshot/"
cmp -- "$0" "$snapshot/native/tests/run_storage_boundaries.sh"
cd "$snapshot/rust"
export CARGO_TARGET_DIR=/tmp/luma-storage-target
export RUSTFLAGS=-Dwarnings
cargo fmt --check
cargo test --offline --locked 2>&1 | tee "$output/rust-tests.txt"
cargo build --offline --locked
install -D -m 0755 "$CARGO_TARGET_DIR/debug/luma-platform" /usr/libexec/luma-os/luma-platform
unit_directory=$(mktemp -d /tmp/luma-storage-units-XXXXXXXX)
install -m 0644 "$snapshot/native/image/overlay/etc/systemd/system/luma-staging-clean.service" "$unit_directory/"
systemd-analyze verify "$unit_directory/luma-staging-clean.service" 2>&1 | tee "$output/unit-verification.txt"
python3 "$snapshot/native/tests/staging_linux_integration.py" \
    --binary "$CARGO_TARGET_DIR/debug/luma-platform" --output "$output/linux-storage.json"
python3 -W error -m unittest discover -s "$snapshot/native/tests" -v 2>&1 | tee "$output/native-tests.txt"
cd "$snapshot"
sha256sum rust/Cargo.toml rust/Cargo.lock rust/.cargo/config.toml \
    rust/luma-platform/Cargo.toml rust/luma-platform/build.rs \
    rust/luma-platform/src/*.rs rust/luma-platform/src/*.c native/tests/*.py native/image/*.py \
    native/tests/run_storage_boundaries.sh native/image/overlay/etc/systemd/system/luma-staging-clean.service \
    native/image/overlay/usr/lib/systemd/system-generators/luma-boot-generator \
    native/image/overlay/etc/systemd/system/media-luma.mount \
    native/image/overlay/etc/systemd/system/luma-live-*.service \
    native/image/overlay/etc/udev/rules.d/99-luma-tpm.rules \
    native/image/Dockerfile.tools native/image/overlay/etc/pam.d/luma-admin > "$output/source-sha256.txt"
