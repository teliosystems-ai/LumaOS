#!/bin/bash
# Bounded isolated source fixture, not an installer or a production service.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'usage: test_fixture.sh PINNED_SOURCE_ARCHIVE NEW_OUTPUT_DIRECTORY' >&2
  exit 2
fi
archive=$(realpath "$1")
output=$2
assets=$(dirname "$(realpath "$0")")
test ! -e "$output"
test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = d168e1cc284c16941c114929bf015acee8d7993e2c705ce53f97304b7f5c01b8
mkdir "$output"
output=$(realpath "$output")
mkdir "$output/upstream"
tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$output/upstream"
python3 "$assets/prepare_chrony.py" \
  --source "$output/upstream/chrony-120dfb8b36b942c31ddfc0220ca1475159ac5031" \
  --output "$output/patched"
gcc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=undefined -fno-sanitize-recover=all \
  -I "$output/patched" "$assets/publisher.c" "$assets/test_publisher.c" -lm \
  -o "$output/test-publisher"
"$output/test-publisher" "$output/c-frame.bin" "$output/c-envelope.bin"
cd "$output/patched"
./configure --disable-readline --without-editline --without-libcap --without-seccomp
grep -qx '#define FEAT_NTS 1' config.h
gcc -Wall -Wextra -Werror $(pkg-config --cflags gnutls) -c chrony_hook.c -o checked-hook.o
timeout 180 make -j1 chronyd
./chronyd -v | tee "$output/chronyd-version.txt"
grep -q '+NTS' "$output/chronyd-version.txt"
# Never run this fixture daemon: no host clock, network, TPM or service mutation.
sha256sum chronyd luma-hook-inputs.json "$output/c-frame.bin" "$output/c-envelope.bin"
echo UTC_CHRONY_FIXTURE_PASSED
