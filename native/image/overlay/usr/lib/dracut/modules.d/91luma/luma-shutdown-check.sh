#!/bin/sh
# Arguments make the pure inventory check testable; the product hook supplies
# only fixed kernel paths. This is an observation, not permission to remove data.
luma_shutdown_storage_check() {
    [ -r "$1" ] && [ -d "$2" ] || return 1
    seen=0
    while read -r device mountpoint rest; do
        case "$mountpoint" in /*) seen=1 ;; *) return 1 ;; esac
        case "$mountpoint" in
            /oldroot|/oldroot/*) return 1 ;;
        esac
    done < "$1"
    [ "$seen" = 1 ] || return 1
    for device in "$2"/dm-*; do
        [ ! -e "$device" ] && [ ! -L "$device" ] || return 1
    done
    return 0
}
