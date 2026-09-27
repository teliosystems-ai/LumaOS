#!/bin/bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
edition=${1:-headless}
sequence=${2:-1}
case "$edition" in headless|desktop) ;; *) echo 'edition must be headless or desktop' >&2; exit 2;; esac
run_id=$(date -u +%Y%m%dT%H%M%SZ)
volume="luma-native-build-$run_id-$edition"
export_container="luma-native-export-$run_id"
tools=luma-native-tools:20260927
base=ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
docker build --build-arg "UBUNTU_BASE=$base" -f "$repository/native/image/Dockerfile.tools" -t "$tools" "$repository/native/image"
docker build --build-arg "EDITION=$edition" -f "$repository/native/image/Dockerfile.root" -t "luma-native-root:20260927-$edition" "$repository/native/image"
docker volume create "$volume"
docker volume create luma-native-lab-keys
docker run --rm --network none --mount "type=volume,src=$volume,dst=/work" "$tools" mkdir /work/root
docker create --name "$export_container" "luma-native-root:20260927-$edition"
docker export "$export_container" | docker run --rm -i --network none --mount "type=volume,src=$volume,dst=/work" "$tools" tar -xpf - -C /work/root
# Remove only the stopped export container created by this invocation.
docker rm "$export_container"
docker run --rm --network none \
    --mount "type=volume,src=$volume,dst=/work" \
    --mount type=volume,src=luma-native-lab-keys,dst=/keys \
    --mount "type=bind,src=$repository,dst=/repo,readonly" \
    "$tools" python3 /repo/native/image/assemble.py --edition "$edition" --sequence "$sequence"
destination="$repository/dist/native/$run_id-$edition"
mkdir -p -- "$destination"
docker run --rm --network none \
    --mount "type=volume,src=$volume,dst=/work,readonly" \
    --mount "type=bind,src=$repository,dst=/repo,readonly" \
    --mount "type=bind,src=$destination,dst=/out" \
    "$tools" python3 /repo/native/image/export.py
echo "Image output: $destination"
echo "Retained build and VM volume: $volume"
echo 'Laboratory private keys remain in Docker volume luma-native-lab-keys; do not publish that volume.'
