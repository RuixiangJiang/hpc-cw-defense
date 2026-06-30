#!/usr/bin/env bash
set -euo pipefail

# Locate repository root.
THIS_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if git -C "$THIS_SCRIPT_DIR" rev-parse --show-toplevel >/dev/null 2>&1; then
    REPO_ROOT_DETECTED="$(git -C "$THIS_SCRIPT_DIR" rev-parse --show-toplevel)"
else
    REPO_ROOT_DETECTED="$(cd "$THIS_SCRIPT_DIR/.." && pwd)"
fi

source "$REPO_ROOT_DETECTED/repo_env.sh"

if [ ! -d "$REPO_ROOT" ]; then
    echo "[error] REPO_ROOT does not exist: $REPO_ROOT" >&2
    exit 1
fi

if [ ! -d "$CW_FIRMWARE_DIR" ]; then
    echo "[error] CW_FIRMWARE_DIR does not exist: $CW_FIRMWARE_DIR" >&2
    exit 1
fi

if [ ! -d "$PQM4_ROOT" ]; then
    echo "[error] PQM4_ROOT does not exist: $PQM4_ROOT" >&2
    exit 1
fi
