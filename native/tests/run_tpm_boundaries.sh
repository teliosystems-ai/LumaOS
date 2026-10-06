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
# Each helper guards fresh root tools containers and starts its own disposable
# software TPM. Logs contain test outcomes, never hierarchy authorization or state.
python3 -W error "$snapshot/native/tests/admin_enrollment_integration.py" 2>&1 | tee "$output/admin-enrollment.txt"
python3 -W error "$snapshot/native/tests/admin_enrollment_resume_integration.py" 2>&1 | tee "$output/admin-enrollment-resume.txt"
python3 -W error "$snapshot/native/tests/admin_enrollment_pending_integration.py" 2>&1 | tee "$output/admin-enrollment-publication.txt"
python3 -W error "$snapshot/native/tests/admin_recovery_integration.py" 2>&1 | tee "$output/admin-journal-recovery.txt"
python3 -W error "$snapshot/native/tests/admin_bootstrap_integration.py" 2>&1 | tee "$output/admin-bootstrap.txt"
python3 -W error "$snapshot/native/tests/admin_service_pam_integration.py" 2>&1 | tee "$output/admin-service-pam.txt"
# This fixture drops its own client to UID 1001 before connecting. It proves
# kernel-peer/framing behavior only, not installed PAM/TPM or AppArmor operation.
timeout 60 cargo test --offline --locked admin_service::tests::kernel_human_connection -- --ignored --exact --nocapture 2>&1 | tee "$output/admin-service-ipc.txt"
# UTC fixtures use only owned child processes, Unix sockets and read-only
# kernel observations. They do not install a time service or contact providers.
timeout 60 cargo test --offline --locked utc_receiver::tests::kernel_datagram_boundary -- --ignored --exact --nocapture --test-threads=1 2>&1 | tee "$output/utc-receiver-kernel.txt"
timeout 60 cargo test --offline --locked utc_receiver::tests::kernel_keeper_composition -- --ignored --exact --nocapture --test-threads=1 2>&1 | tee "$output/utc-keeper-composition.txt"
timeout 60 cargo test --offline --locked utc_receiver::tests::kernel_final_queue_recheck -- --ignored --exact --nocapture --test-threads=1 2>&1 | tee "$output/utc-final-queue.txt"
# Shared-history faults here use a fake anchor, not the disposable TPM above.
timeout 60 cargo test --offline --locked utc_receiver::tests::kernel_shared_history_composition -- --ignored --exact --nocapture --test-threads=1 2>&1 | tee "$output/utc-shared-history.txt"
python3 -W error -m unittest discover -s "$snapshot/native/tests" -v 2>&1 | tee "$output/native-tests.txt"
cd "$snapshot"
sha256sum rust/Cargo.toml rust/Cargo.lock rust/.cargo/config.toml \
    rust/luma-platform/Cargo.toml rust/luma-platform/build.rs \
    rust/luma-platform/src/*.rs rust/luma-platform/src/*.c rust/luma-platform/src/model/*.rs \
    native/tests/model_supervision_fixture.c \
    native/tests/run_tpm_boundaries.sh native/tests/*.py native/tests/fixtures/*.c native/image/*.py \
    native/image/overlay/usr/lib/dracut/modules.d/92luma-pcrphase/module-setup.sh \
    native/image/overlay/usr/lib/dracut/modules.d/91luma/*.sh \
    native/image/overlay/etc/pam.d/luma-admin \
    native/image/overlay/etc/apparmor.d/luma-admin \
    native/image/overlay/etc/systemd/system/luma-admin.service \
    native/image/overlay/etc/udev/rules.d/99-luma-tpm.rules \
    native/image/overlay/usr/lib/systemd/system-generators/luma-boot-generator \
    native/image/overlay/etc/systemd/system/media-luma.mount \
    native/image/overlay/etc/systemd/system/luma-live-*.service \
    native/image/Dockerfile.tools > "$output/source-sha256.txt"
