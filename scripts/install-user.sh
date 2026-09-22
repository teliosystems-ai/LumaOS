#!/usr/bin/env sh
set -eu

VERSION=0.1.0
UPGRADE=0

usage() {
    echo "Usage: $0 [--upgrade]"
    echo "Installs a versioned Luma OS source tree for the current user; never uses sudo."
}

for argument in "$@"; do
    case "$argument" in
        --upgrade) UPGRADE=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $argument" >&2; usage >&2; exit 2 ;;
    esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DATA_HOME=${XDG_DATA_HOME:-"$HOME/.local/share"}
BIN_HOME=${XDG_BIN_HOME:-"$HOME/.local/bin"}
INSTALL_ROOT="$DATA_HOME/luma-os"
RELEASE_ROOT="$INSTALL_ROOT/releases/$VERSION"
LAUNCHER="$BIN_HOME/luma-os"
MARKER="$INSTALL_ROOT/.luma-os-install"

case "$INSTALL_ROOT" in
    ""|/|"$HOME") echo "Refusing unsafe install root: $INSTALL_ROOT" >&2; exit 2 ;;
    *"'"*|*"
"*) echo "Install path cannot contain a quote or newline." >&2; exit 2 ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.11 or newer is required." >&2
    exit 127
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Python 3.11 or newer is required." >&2
    exit 2
fi

if [ -e "$INSTALL_ROOT" ] && [ ! -f "$MARKER" ]; then
    echo "Refusing to use an unmarked existing path: $INSTALL_ROOT" >&2
    exit 2
fi
if [ -e "$RELEASE_ROOT" ] && [ "$UPGRADE" -ne 1 ]; then
    echo "Luma OS $VERSION is already installed. Use --upgrade to stage a replacement." >&2
    exit 2
fi
if [ -e "$LAUNCHER" ] && ! grep -q '^# luma-os-managed-launcher$' "$LAUNCHER" 2>/dev/null; then
    echo "Refusing to replace an unmarked launcher: $LAUNCHER" >&2
    exit 2
fi

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/luma-os-install.XXXXXX")
trap 'rm -rf -- "$STAGE"' EXIT HUP INT TERM
STAGED_RELEASE="$STAGE/$VERSION"
mkdir -p "$STAGED_RELEASE"

for entry in src web schemas examples README.md LICENSE SECURITY.md pyproject.toml RELEASE_MANIFEST.json; do
    if [ ! -e "$PROJECT_DIR/$entry" ]; then
        echo "Required release input is missing: $entry" >&2
        exit 2
    fi
    cp -R "$PROJECT_DIR/$entry" "$STAGED_RELEASE/$entry"
done
find "$STAGED_RELEASE" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$STAGED_RELEASE" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
printf '%s\n' "luma-os-user-install:$VERSION" > "$STAGED_RELEASE/.luma-os-release"

mkdir -p "$INSTALL_ROOT/releases" "$BIN_HOME"
printf '%s\n' "luma-os-user-install:$VERSION" > "$MARKER"

if [ -e "$RELEASE_ROOT" ]; then
    BACKUP="$INSTALL_ROOT/releases/$VERSION.replaced.$(date -u +%Y%m%dT%H%M%SZ)"
    if [ -e "$BACKUP" ]; then
        echo "Backup path already exists; refusing replacement: $BACKUP" >&2
        exit 2
    fi
    mv "$RELEASE_ROOT" "$BACKUP"
    echo "Previous release preserved at $BACKUP"
fi
mv "$STAGED_RELEASE" "$RELEASE_ROOT"

LAUNCHER_TEMP="$STAGE/luma-os-launcher"
printf '%s\n' \
    '#!/usr/bin/env sh' \
    '# luma-os-managed-launcher' \
    'set -eu' \
    "LUMA_RELEASE_ROOT='$RELEASE_ROOT'" \
    'if [ -n "${PYTHONPATH:-}" ]; then' \
    '    export PYTHONPATH="$LUMA_RELEASE_ROOT/src:$PYTHONPATH"' \
    'else' \
    '    export PYTHONPATH="$LUMA_RELEASE_ROOT/src"' \
    'fi' \
    'cd "$LUMA_RELEASE_ROOT"' \
    'if [ "$#" -eq 0 ]; then set -- serve; fi' \
    'exec python3 -m luma_os.cli "$@"' > "$LAUNCHER_TEMP"
chmod 0755 "$LAUNCHER_TEMP"
mv "$LAUNCHER_TEMP" "$LAUNCHER"

echo "Installed Luma OS $VERSION for the current user."
echo "Launcher: $LAUNCHER"
echo "No service was enabled or started."
case ":${PATH:-}:" in
    *":$BIN_HOME:"*) ;;
    *) echo "Add $BIN_HOME to PATH before running: luma-os" ;;
esac
