#!/usr/bin/env sh
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/autopsy_main.py" "$@"
