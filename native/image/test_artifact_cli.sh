#!/bin/bash
# Run only in a fresh disposable tools container; never on an installed OS.
set -euo pipefail
test -f /.dockerenv
test "$(id -u)" = 0
test ! -e /dev/tpm0
test ! -e /dev/tpmrm0
test ! -e /var/lib/luma-os
test ! -e /usr/share/luma-os
test -x "${CARGO_TARGET_DIR:?}/debug/luma-platform"
fixture_directory=$(dirname "$(readlink -f "$0")")
cd "$fixture_directory"
cc -Wall -Wextra -Werror -shared -fPIC fixtures/artifact_cmdline.c \
  -o /tmp/luma-artifact-test.so -ldl
cp fixtures/artifact-test-cmdline.txt /tmp/luma-artifact-cmdline-fixture
LD_PRELOAD=/tmp/luma-artifact-test.so python3 test_artifact_cli.py
