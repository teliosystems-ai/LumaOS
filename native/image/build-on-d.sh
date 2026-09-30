#!/bin/bash
set -euo pipefail
# The installed root-owned profile selects the dedicated daemon, client temp
# storage and output drive. Do not fall back if setup or the mount is absent.
source /etc/luma-build/environment.sh
export LUMA_BUILD_PROFILE=dedicated-d
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/build.sh" "$@"
