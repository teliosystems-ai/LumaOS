#!/usr/bin/env sh
set -eu

ENABLE=0
REPLACE=0
for argument in "$@"; do
    case "$argument" in
        --enable) ENABLE=1 ;;
        --replace) REPLACE=1 ;;
        --help|-h)
            echo "Usage: $0 [--replace] [--enable]"
            echo "Installs a systemd user unit. It starts only when --enable is supplied."
            exit 0
            ;;
        *) echo "Unknown option: $argument" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$SCRIPT_DIR/luma-os.service"
UNIT_DIR="${XDG_CONFIG_HOME:-"$HOME/.config"}/systemd/user"
DESTINATION="$UNIT_DIR/luma-os.service"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd user services are not available in this environment." >&2
    exit 2
fi
if [ ! -x "${XDG_BIN_HOME:-"$HOME/.local/bin"}/luma-os" ]; then
    echo "Install Luma OS for the current user before installing its service." >&2
    exit 2
fi
mkdir -p "${XDG_STATE_HOME:-"$HOME/.local/state"}/luma-os" "$UNIT_DIR"

if [ -e "$DESTINATION" ] && ! cmp -s "$SOURCE" "$DESTINATION" && [ "$REPLACE" -ne 1 ]; then
    echo "A different unit already exists at $DESTINATION; use --replace to replace it." >&2
    exit 2
fi
cp "$SOURCE" "$DESTINATION"
systemctl --user daemon-reload
echo "Installed $DESTINATION"

if [ "$ENABLE" -eq 1 ]; then
    systemctl --user enable --now luma-os.service
    echo "Enabled and started luma-os.service on loopback."
else
    echo "The service was not enabled or started."
    echo "Review it, then run: systemctl --user enable --now luma-os.service"
fi
