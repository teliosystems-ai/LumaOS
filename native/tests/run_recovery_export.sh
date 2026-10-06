#!/bin/bash
# Isolated Linux recovery-export checks. No host disk, TPM, or network access.
set -euo pipefail
if [ "${LUMA_EXPORT_RUNNER_SNAPSHOT:-0}" != 1 ]; then
    task_runner=$(mktemp /tmp/luma-export-runner-XXXXXXXX)
    cp -- "$0" "$task_runner"
    export LUMA_EXPORT_RUNNER_SNAPSHOT=1
    exec bash "$task_runner" "$@"
fi
output=${1:?supply a fresh evidence directory}
test -f /.dockerenv
test ! -e "$output"
mkdir -- "$output"
snapshot=$(mktemp -d /tmp/luma-export-source-XXXXXXXX)
mkdir "$snapshot/rust"
cp -a /repo/rust/.cargo /repo/rust/Cargo.toml /repo/rust/Cargo.lock /repo/rust/luma-platform "$snapshot/rust/"
cp -a /repo/native "$snapshot/"
cmp -- "$0" "$snapshot/native/tests/run_recovery_export.sh"
cd "$snapshot/rust"
export CARGO_TARGET_DIR=/tmp/luma-export-target
export RUSTFLAGS=-Dwarnings
cargo fmt --check
cargo test --offline --locked 2>&1 | tee "$output/rust-tests.txt"
# Only this separate test process can mount the 1 MiB disposable tmpfs.
unshare --mount --propagation private env LUMA_EXPORT_MOUNT_TEST=1 \
    cargo test --offline --locked \
    recovery_export::tests::actual_full_filesystem_retains_partial_and_never_publishes_final \
    -- --exact --ignored --test-threads=1 2>&1 | tee "$output/enospc-test.txt"
python3 -W error -m unittest discover -s "$snapshot/native/tests" -v 2>&1 | tee "$output/native-tests.txt"
cd "$snapshot"
sha256sum rust/Cargo.toml rust/Cargo.lock rust/.cargo/config.toml \
    rust/luma-platform/Cargo.toml rust/luma-platform/build.rs \
    rust/luma-platform/src/*.rs rust/luma-platform/src/*.c rust/luma-platform/src/model/*.rs \
    native/tests/model_supervision_fixture.c \
    native/tests/run_recovery_export.sh native/tests/*.py native/image/*.py \
    > "$output/source-sha256.txt"
