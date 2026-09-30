# Source this file in Ubuntu WSL before Luma builds and tests.
# Use an explicit endpoint; never silently fall back to the C:-backed daemon.
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///run/luma-build-docker.sock
export DOCKER_CONFIG="/mnt/luma-build/client/$(id -un)/docker"
export TMPDIR="/mnt/luma-build/client/$(id -un)/tmp"
export DOCKER_BUILDKIT=0
export LUMA_BUILD_ROOT=/mnt/d/LumaOS-builds
# The isolated daemon does not alter shared bridges/firewall rules. Package
# builds needing the internet use explicit host networking; assembly stays none.
export LUMA_BUILD_NETWORK=host
