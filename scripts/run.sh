#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN=${PYTHON:-python3}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Luma OS requires Python 3.11 or newer; '$PYTHON_BIN' was not found." >&2
    exit 127
fi

if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Luma OS requires Python 3.11 or newer." >&2
    exit 2
fi

if [ ! -f "$PROJECT_DIR/src/luma_os/cli.py" ]; then
    echo "Luma OS source is incomplete: src/luma_os/cli.py was not found." >&2
    exit 2
fi

if [ -n "${PYTHONPATH:-}" ]; then
    export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"
else
    export PYTHONPATH="$PROJECT_DIR/src"
fi

cd "$PROJECT_DIR"
if [ "$#" -eq 0 ]; then
    set -- serve
fi
exec "$PYTHON_BIN" -m luma_os.cli "$@"
