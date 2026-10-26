#!/bin/bash
set -euo pipefail
# Bash parses the entire function before executing it. In particular, it must
# not resume reading a changed checkout at an old byte offset after Docker's
# long assembly step. Build inputs are separately captured before package work.
main() {
export PYTHONDONTWRITEBYTECODE=1
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
case "${LUMA_BUILD_PROFILE:-auto}" in
    auto) if [ -f /etc/luma-build/environment.sh ]; then source /etc/luma-build/environment.sh; fi ;;
    dedicated-d) source /etc/luma-build/environment.sh ;;
    standard) ;; # Explicit legacy/portable mode; retains its original guards.
    *) echo 'unknown build profile' >&2; exit 2 ;;
esac
assembly_memory_gib=${LUMA_NATIVE_ASSEMBLY_MEMORY_GIB-4}
case "$assembly_memory_gib" in
    4|5|8) ;;
    *) echo 'LUMA_NATIVE_ASSEMBLY_MEMORY_GIB must be exactly 4, 5 or 8; absent defaults to 4' >&2; exit 2 ;;
esac
if [ "${1:-}" = production-continue ]; then
    if [ "$#" -ne 5 ]; then
        echo 'usage: build.sh production-continue {pcr|pe|release} VOLUME CAPTURED_SOURCE RESPONSE_DIRECTORY' >&2; exit 2
    fi
    phase=$2; volume=$3; source_context=$4; response=$5
    case "$phase" in pcr|pe|release) ;; *) echo 'invalid production response phase' >&2; exit 2;; esac
    if ! [[ "$volume" =~ ^luma-native-build-[0-9]{8}T[0-9]{6}Z-(headless|desktop)$ ]]; then
        echo 'production continuation requires its exact retained native build volume' >&2; exit 2
    fi
    edition=${volume##*-}
    for path in "$source_context" "$response"; do
        test ! -L "$path"; test -d "$path"
        case "$path" in /|*','*) echo 'select exact readonly public phase directories' >&2; exit 2;; esac
    done
    source_context=$(realpath -e -- "$source_context")
    response=$(realpath -e -- "$response")
    build_root=${LUMA_BUILD_ROOT:-}
    if [ -n "$build_root" ]; then build_root=$(realpath -e -- "$build_root"); fi
    python3 "$repository/native/image/build_storage.py" preflight --repository "$repository" --external "$build_root" --edition "$edition"
    docker run --rm --memory 4g --memory-swap 4g --cpus 2 --network none \
        -e PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=volume,src=$volume,dst=/work" \
        --mount "type=bind,src=$response,dst=/production-response,readonly" \
        luma-native-tools:20260927 python3 /work/source/native/image/production_finalize.py "$phase"
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    destination="${build_root:-$repository/dist}/native/$run_id-production-$phase"
    mkdir -p -- "$(dirname -- "$destination")"; mkdir -- "$destination"
    if [ "$phase" = release ]; then
        helper=export.py; next_args=()
    else
        helper=production_request_export.py
        if [ "$phase" = pcr ]; then next_args=(pe); else next_args=(release); fi
    fi
    docker run --rm --memory 4g --memory-swap 4g --cpus 2 --network none \
        -e PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=volume,src=$volume,dst=/work,readonly" \
        --mount "type=bind,src=$destination,dst=/out" \
        luma-native-tools:20260927 python3 "/work/source/native/image/$helper" "${next_args[@]}"
    echo "Production phase output: $destination"
    echo 'Production signing custody and native qualification remain external; no private keys were mounted.'
    return
fi
edition=${1:-headless}
sequence=${2:-1}
environment=${LUMA_NATIVE_ENVIRONMENT:-lab}
case "$environment" in lab|production) ;; *) echo 'environment must be lab or production' >&2; exit 2;; esac
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
# Bound build work independently of the host's WSL memory/CPU configuration.
# Compilation and assembly run after the source sweep, not concurrently with it.
build_limits=(--memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 200000)
run_limits=(--memory 4g --memory-swap 4g --cpus 2)
assembly_limits=(--memory "${assembly_memory_gib}g" --memory-swap "${assembly_memory_gib}g" --cpus 2)
base=ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
runtime_context="${build_root:-$repository/dist}/native-inputs/$run_id-$edition"
source_context="${build_root:-$repository/dist}/native-sources/$run_id-$edition"
destination="${build_root:-$repository/dist}/native/$run_id-$edition"
artifact_mount=()
artifact_mount_ro=()
assembly_args=()
public_trust_mount=()
model_public_mount=()
# Raw roots, payload, ESP, sparse copies and compression remain in the Linux
# build volume. The verified dedicated daemon places that volume on D-backed
# ext4. Only final compressed/public exports go to the outer D: filesystem.
private_key_mount=()
production_public_mount=()
assembly_args+=(--environment "$environment")
if [ "$environment" = production ]; then
    test -n "${LUMA_NATIVE_PRODUCTION_PUBLIC_INPUTS:-}"
    test -n "${LUMA_NATIVE_PUBLIC_TRUST:-}"
    test -n "${LUMA_NATIVE_MODEL_PUBLIC_INPUTS:-}"
    test ! -L "$LUMA_NATIVE_PRODUCTION_PUBLIC_INPUTS"
    production_input=$(realpath -e -- "$LUMA_NATIVE_PRODUCTION_PUBLIC_INPUTS")
    test -d "$production_input"
    case "$production_input" in /|*','*) echo 'select an exact public production input directory' >&2; exit 2;; esac
    production_public_mount=(--mount "type=bind,src=$production_input,dst=/production-public,readonly")
    assembly_args+=(--production-public-inputs /production-public)
    if [ -n "${LUMA_NATIVE_PRODUCTION_RELEASE_ID:-}" ]; then assembly_args+=(--release-id "$LUMA_NATIVE_PRODUCTION_RELEASE_ID"); fi
else
    private_key_mount=(--mount type=volume,src=luma-native-lab-keys,dst=/keys)
fi
if [ -n "${LUMA_NATIVE_PUBLIC_TRUST:-}" ]; then
    test ! -L "$LUMA_NATIVE_PUBLIC_TRUST"
    public_trust_input=$(realpath -e -- "$LUMA_NATIVE_PUBLIC_TRUST")
    test -d "$public_trust_input"
    case "$public_trust_input" in /|*','*) echo 'select an exact public trust input directory' >&2; exit 2;; esac
    public_trust_mount=(--mount "type=bind,src=$public_trust_input,dst=/public-trust,readonly")
    assembly_args+=(--public-trust-inputs /public-trust)
fi
if [ -n "${LUMA_NATIVE_MODEL_PUBLIC_INPUTS:-}" ]; then
    test ! -L "$LUMA_NATIVE_MODEL_PUBLIC_INPUTS"
    model_public_input=$(realpath -e -- "$LUMA_NATIVE_MODEL_PUBLIC_INPUTS")
    test -d "$model_public_input"
    case "$model_public_input" in /|*','*) echo 'select an exact model public input directory' >&2; exit 2;; esac
    model_public_mount=(--mount "type=bind,src=$model_public_input,dst=/model-public,readonly")
    assembly_args+=(--model-public-inputs /model-public)
fi
runtime_args=(--output "$runtime_context")
if [ -n "${LUMA_RUNTIME_ARCHIVE:-}" ]; then runtime_args+=(--cached "$LUMA_RUNTIME_ARCHIVE"); fi
# Capture before any long download/package build, not only before compilation.
python3 "$repository/native/image/snapshot.py" --repository "$repository" --output "$source_context"
python3 "$source_context/native/image/prepare_runtime.py" "${runtime_args[@]}"
utc_args=(--output "$runtime_context")
if [ -n "${LUMA_UTC_ARCHIVE:-}" ]; then utc_args+=(--cached "$LUMA_UTC_ARCHIVE"); fi
python3 "$source_context/native/image/utc/prepare_release_input.py" "${utc_args[@]}"
speech_args=(--output "$runtime_context")
if [ -n "${LUMA_SPEECH_INPUTS:-}" ]; then speech_args+=(--cached-directory "$LUMA_SPEECH_INPUTS"); fi
python3 "$source_context/native/image/prepare_speech.py" "${speech_args[@]}"
docker build "${build_limits[@]}" --network "$build_network" --build-arg "UBUNTU_BASE=$base" -f "$source_context/native/image/Dockerfile.tools" -t "$tools" "$source_context/native/image"
docker build "${build_limits[@]}" --network "$build_network" --build-arg "EDITION=$edition" -f "$source_context/native/image/Dockerfile.root" -t "luma-native-root:20260927-$edition" "$runtime_context"
docker volume create "$volume"
if [ "$environment" = lab ]; then docker volume create luma-native-lab-keys; fi
docker run --rm "${run_limits[@]}" --network none --mount "type=volume,src=$volume,dst=/work" "$tools" mkdir /work/root
docker create --name "$export_container" "luma-native-root:20260927-$edition"
docker export "$export_container" | docker run --rm -i "${run_limits[@]}" --network none --mount "type=volume,src=$volume,dst=/work" "$tools" tar -xpf - -C /work/root
# Remove only the stopped export container created by this invocation.
docker rm "$export_container"
# Observe physical RAM immediately before assembly. This is not a reservation;
# leave the build host 1 GiB and do not count swap or alter WSL/other workloads.
LUMA_NATIVE_ASSEMBLY_MEMORY_GIB="$assembly_memory_gib" python3 "$source_context/native/image/build_storage.py" assembly-memory
docker run --rm "${assembly_limits[@]}" --network none \
    -e CARGO_BUILD_JOBS=1 -e RUSTFLAGS=-Dwarnings \
    -e PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=volume,src=$volume,dst=/work" \
    "${artifact_mount[@]}" \
    "${public_trust_mount[@]}" \
    "${model_public_mount[@]}" \
    "${production_public_mount[@]}" \
    "${private_key_mount[@]}" \
    --mount "type=bind,src=$source_context,dst=/repo,readonly" \
    --mount "type=bind,src=$runtime_context,dst=/inputs,readonly" \
    "$tools" python3 /repo/native/image/assemble.py --edition "$edition" --sequence "$sequence" "${assembly_args[@]}"
if [ "$environment" = production ]; then
    destination="${build_root:-$repository/dist}/native-signing/$run_id-$edition-pcr"
    mkdir -p -- "$(dirname -- "$destination")"; mkdir -- "$destination"
    docker run --rm "${run_limits[@]}" --network none -e PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=volume,src=$volume,dst=/work,readonly" \
        --mount "type=bind,src=$source_context,dst=/repo,readonly" \
        --mount "type=bind,src=$destination,dst=/out" \
        "$tools" python3 /repo/native/image/production_request_export.py pcr
    echo "Public production PCR signing request: $destination"
    echo "Retained production build volume: $volume"
    echo "Captured build inputs: $source_context"
    echo 'Continue with production-continue pcr/pe/release and independently produced signature responses.'
    echo 'No production private key was generated, mounted, exported or used by Docker.'
    return
fi
mkdir -p -- "$(dirname -- "$destination")"
mkdir -- "$destination"
docker run --rm "${run_limits[@]}" --network none \
    -e PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=volume,src=$volume,dst=/work,readonly" \
    "${artifact_mount_ro[@]}" \
    --mount "type=bind,src=$source_context,dst=/repo,readonly" \
    --mount "type=bind,src=$destination,dst=/out" \
    "$tools" python3 /repo/native/image/export.py
echo "Image output: $destination"
echo "Retained Linux build volume: $volume"
echo "Captured build inputs: $source_context"
echo "Raw artifact/VM work remains on the verified Linux ext4 build volume: $volume"
echo 'Laboratory private keys remain in Docker volume luma-native-lab-keys; do not publish that volume.'
}
main "$@"
