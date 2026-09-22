#!/usr/bin/env sh
set -eu

CONFIRM=0

case "${1:-}" in
    --yes) CONFIRM=1 ;;
    --help|-h)
        echo "Usage: $0 --yes"
        echo "Moves a marked user install to a recoverable quarantine path. Runtime state is retained."
        exit 0
        ;;
    "") ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
esac

if [ "$CONFIRM" -ne 1 ]; then
    echo "No changes made. Re-run with --yes after reviewing the resolved paths." >&2
    exit 2
fi

DATA_HOME=${XDG_DATA_HOME:-"$HOME/.local/share"}
BIN_HOME=${XDG_BIN_HOME:-"$HOME/.local/bin"}
INSTALL_ROOT="$DATA_HOME/luma-os"
LAUNCHER="$BIN_HOME/luma-os"
MARKER="$INSTALL_ROOT/.luma-os-install"

case "$INSTALL_ROOT" in
    ""|/|"$HOME") echo "Refusing unsafe install root: $INSTALL_ROOT" >&2; exit 2 ;;
esac

if [ ! -f "$MARKER" ] || ! grep -q '^luma-os-user-install:' "$MARKER"; then
    echo "No marked Luma OS user install exists at $INSTALL_ROOT; nothing changed." >&2
    exit 2
fi

QUARANTINE="$DATA_HOME/luma-os-uninstalled-$(date -u +%Y%m%dT%H%M%SZ)"
if [ -e "$QUARANTINE" ]; then
    echo "Quarantine path already exists; nothing changed: $QUARANTINE" >&2
    exit 2
fi

if [ -e "$LAUNCHER" ]; then
    if grep -q '^# luma-os-managed-launcher$' "$LAUNCHER" 2>/dev/null; then
        rm -f -- "$LAUNCHER"
    else
        echo "Unmarked launcher was preserved: $LAUNCHER" >&2
    fi
fi

mv "$INSTALL_ROOT" "$QUARANTINE"
echo "The user install was moved to: $QUARANTINE"
echo "Runtime state under XDG_STATE_HOME (or ~/.local/state/luma-os) was not changed."
echo "Delete the quarantine manually only after confirming it is no longer needed."
