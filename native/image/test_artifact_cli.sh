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
if [ -z "${LUMA_PUBLICATION_TEST_EXECUTABLE:-}" ]; then
  artifact_manifest=$(mktemp "${TMPDIR:-/tmp}/luma-publication-artifacts.XXXXXX")
  trap 'rm -f -- "$artifact_manifest"' EXIT
  (cd "$fixture_directory/../../rust"
   cargo test --offline --locked --no-run --message-format=json) > "$artifact_manifest"
  LUMA_PUBLICATION_TEST_EXECUTABLE=$(python3 -c '
import json, pathlib, sys
items = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
binaries = [item["executable"] for item in items if item.get("reason") == "compiler-artifact"
            and item.get("profile", {}).get("test") and item.get("executable")
            and item["target"]["name"] == "luma-platform"]
assert len(binaries) == 1, binaries
print(binaries[0])' "$artifact_manifest")
  export LUMA_PUBLICATION_TEST_EXECUTABLE
fi
test -x "${LUMA_PUBLICATION_TEST_EXECUTABLE:?}"
cd "$fixture_directory"
cc -Wall -Wextra -Werror -shared -fPIC fixtures/artifact_cmdline.c fixtures/catalog_faults.c \
  -o /tmp/luma-artifact-test.so -ldl
cp fixtures/artifact-test-cmdline.txt /tmp/luma-artifact-cmdline-fixture
LD_PRELOAD=/tmp/luma-artifact-test.so python3 test_artifact_cli.py
