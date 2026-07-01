#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

PLATFORM_NAME="${PLATFORM:-$DEFAULT_PLATFORM}"
SS_VERSION="${SS_VER:-$DEFAULT_SS_VER}"
CRYPTO_TARGET_NAME="${CRYPTO_TARGET:-$DEFAULT_CRYPTO_TARGET}"

TARGET_NAME="${FW_TARGET_NAME}-baseline"
OUT_HEX="${TARGET_NAME}-${PLATFORM_NAME}.hex"
OUT_ELF="${TARGET_NAME}-${PLATFORM_NAME}.elf"
OUT_MAP="${TARGET_NAME}-${PLATFORM_NAME}.map"

cd "$FW_APP_DIR"

make clean CRYPTO_TARGET="$CRYPTO_TARGET_NAME"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM_NAME" \
     SS_VER="$SS_VERSION" \
     CRYPTO_TARGET="$CRYPTO_TARGET_NAME" \
     EXTRA_CFLAGS="-DATTACK_DECODER_SKIP_QHALF=0" \
     "$OUT_HEX"

echo
echo "[ok] baseline build outputs:"
ls -lh "$OUT_ELF" "$OUT_HEX" "$OUT_MAP" 2>/dev/null || true