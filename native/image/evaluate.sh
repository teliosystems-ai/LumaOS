#!/bin/bash
# Run inside the tools container, one VM at a time. Never touches host disks.
set -euo pipefail
if [ "$#" -ne 4 ]; then
    echo 'usage: evaluate.sh /work/artifacts/IMAGE /baseline/artifacts/OLD-IMAGE /baseline/vm-PASSED RUN-LABEL' >&2
    exit 2
fi
image=$1
baseline_image=$2
baseline_run=$3
label=$4
if ! [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]]; then echo 'invalid run label' >&2; exit 2; fi
scripts=/repo/native/image
export_run() {
    python3 "$scripts/collect_evidence.py" --run "/work/vm-$label-$1" --output "/out/evidence-$label-$1"
}
trap 'echo "Evaluation stopped; keep diagnostics. No aggregate pass or gate closure is implied." >&2' ERR
python3 "$scripts/vm_test.py" --image "$image" --work "/work/vm-$label-full"
export_run full
python3 "$scripts/model_vm_test.py" --image "$image" --work "/work/vm-$label-model"
export_run model
python3 "$scripts/model_reconfigure_test.py" --image "$image" --base-run "/work/vm-$label-full" --work "/work/vm-$label-small"
export_run small
python3 "$scripts/update_powercut_test.py" --base-image "$baseline_image" --base-run "$baseline_run" --candidate "$image" --work "/work/vm-$label-powercut"
export_run powercut
python3 "$scripts/vm_test.py" --image "$image" --work "/work/vm-$label-secure" --secure-boot --accel tcg --smoke-only
export_run secure
python3 "$scripts/secure_boot_negative.py" --image "$image" --work "/work/vm-$label-unsigned"
export_run unsigned
echo 'All six selected lab runners completed and exported their evidence. This is not full G2 or physical qualification.'
