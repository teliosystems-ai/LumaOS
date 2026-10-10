#!/bin/bash
set -euo pipefail
# Bash parses the entire function before executing it. In particular, it must
# not resume reading a changed checkout at an old byte offset after Docker's
# long assembly step. Build inputs are separately captured before package work.
main() {
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
case "${LUMA_BUILD_PROFILE:-auto}" in
    auto) if [ -f /etc/luma-build/environment.sh ]; then source /etc/luma-build/environment.sh; fi ;;
    dedicated-d) source /etc/luma-build/environment.sh ;;
    standard) ;; # Explicit legacy/portable mode; retains its original guards.
    *) echo 'unknown build profile' >&2; exit 2 ;;
esac
edition=${1:-headless}
sequence=${2:-1}
build_network=${LUMA_BUILD_NETWORK:-default}
case "$build_network" in default|host|none) ;; *) echo 'unsupported build network' >&2; exit 2;; esac
case "$edition" in headless|desktop) ;; *) echo 'edition must be headless or desktop' >&2; exit 2;; esac
if ! [[ "$sequence" =~ ^[1-9][0-9]*$ ]]; then
    echo 'sequence must be a positive integer' >&2; exit 2
fi
build_root=${LUMA_BUILD_ROOT:-}
if [ -n "$build_root" ]; then
    build_root=$(realpath -e -- "$build_root")
    case "$build_root" in /|/mnt|/mnt/?|*','*) echo 'select a dedicated build directory, without commas' >&2; exit 2;; esac
    test -d "$build_root"
fi
# Only a verified dedicated D:-backed daemon may replace the C: reservation.
# Missing mounts, wrong daemons and C:-backed client temp paths fail closed.
python3 "$repository/native/image/build_storage.py" preflight \
    --repository "$repository" --external "$build_root" --edition "$edition"
run_id=$(date -u +%Y%m%dT%H%M%SZ)
volume="luma-native-build-$run_id-$edition"
export_container="luma-native-export-$run_id"
tools=luma-native-tools:20260927
base=ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
runtime_context="${build_root:-$repository/dist}/native-inputs/$run_id-$edition"
source_context="${build_root:-$repository/dist}/native-sources/$run_id-$edition"
destination="${build_root:-$repository/dist}/native/$run_id-$edition"
artifact_mount=()
artifact_mount_ro=()
assembly_args=()
if [ -n "$build_root" ]; then
    external_work="$build_root/work/$run_id-$edition"
    mkdir -p -- "$build_root/work"
    mkdir -- "$external_work"
    mkdir -- "$external_work/artifacts"
    artifact_mount=(--mount "type=bind,src=$external_work/artifacts,dst=/work/artifacts")
    artifact_mount_ro=(--mount "type=bind,src=$external_work/artifacts,dst=/work/artifacts,readonly")
    assembly_args=(--external-artifacts)
fi
runtime_args=(--output "$runtime_context")
if [ -n "${LUMA_RUNTIME_ARCHIVE:-}" ]; then runtime_args+=(--cached "$LUMA_RUNTIME_ARCHIVE"); fi
# Capture before any long download/package build, not only before compilation.
python3 "$repository/native/image/snapshot.py" --repository "$repository" --output "$source_context"
python3 "$source_context/native/image/prepare_runtime.py" "${runtime_args[@]}"
utc_args=(--output "$runtime_context")
if [ -n "${LUMA_UTC_ARCHIVE:-}" ]; then utc_args+=(--cached "$LUMA_UTC_ARCHIVE"); fi
python3 "$source_context/native/image/utc/prepare_release_input.py" "${utc_args[@]}"
docker build --network "$build_network" --build-arg "UBUNTU_BASE=$base" -f "$source_context/native/image/Dockerfile.tools" -t "$tools" "$source_context/native/image"
docker build --network "$build_network" --build-arg "EDITION=$edition" -f "$source_context/native/image/Dockerfile.root" -t "luma-native-root:20260927-$edition" "$runtime_context"
docker volume create "$volume"
docker volume create luma-native-lab-keys
docker run --rm --network none --mount "type=volume,src=$volume,dst=/work" "$tools" mkdir /work/root
docker create --name "$export_container" "luma-native-root:20260927-$edition"
docker export "$export_container" | docker run --rm -i --network none --mount "type=volume,src=$volume,dst=/work" "$tools" tar -xpf - -C /work/root
# Remove only the stopped export container created by this invocation.
docker rm "$export_container"
docker run --rm --network none \
    --mount "type=volume,src=$volume,dst=/work" \
    "${artifact_mount[@]}" \
    --mount type=volume,src=luma-native-lab-keys,dst=/keys \
    --mount "type=bind,src=$source_context,dst=/repo,readonly" \
    --mount "type=bind,src=$runtime_context,dst=/inputs,readonly" \
    "$tools" python3 /repo/native/image/assemble.py --edition "$edition" --sequence "$sequence" "${assembly_args[@]}"
mkdir -p -- "$(dirname -- "$destination")"
mkdir -- "$destination"
docker run --rm --network none \
    --mount "type=volume,src=$volume,dst=/work,readonly" \
    "${artifact_mount_ro[@]}" \
    --mount "type=bind,src=$source_context,dst=/repo,readonly" \
    --mount "type=bind,src=$destination,dst=/out" \
    "$tools" python3 /repo/native/image/export.py
echo "Image output: $destination"
echo "Retained Linux build volume: $volume"
echo "Captured build inputs: $source_context"
if [ -n "$build_root" ]; then
    echo "External artifact/VM work directory: $external_work (bind at /work for VM tests)"
else
    echo "VM work remains in volume: $volume"
fi
echo 'Laboratory private keys remain in Docker volume luma-native-lab-keys; do not publish that volume.'
}
main "$@"
