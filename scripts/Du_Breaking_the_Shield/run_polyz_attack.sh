#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="${MODEL:-zero}"
if [ -z "$MODEL" ] || [ "$MODEL" = "none" ]; then
  MODEL="zero"
fi
TARGET_COEFF="${TARGET_COEFF:-17}"
TARGET_LOAD="${TARGET_LOAD:-1}"
STALE_BYTE="${STALE_BYTE:-90}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 -DDU_HPC_TARGET_CYCLES_MIN=${DU_HPC_TARGET_CYCLES_MIN} -DDU_HPC_TARGET_CYCLES_MAX=${DU_HPC_TARGET_CYCLES_MAX} -DDU_STALE_FIXED_BYTE=${STALE_BYTE}"

make TARGET="$TARGET_NAME" PLATFORM="$PLATFORM" SS_VER="$SS_VER" CRYPTO_TARGET=NONE \
     DU_SRC=simpleserial-du-polyz-unpack.c EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" 2>&1 | tee build_du_polyz_singlebin.log

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/test_du_polyz_unpack.py" \
  --hex "$HEX_PATH" --label "du-polyz-${MODEL}-c${TARGET_COEFF}-l${TARGET_LOAD}" \
  --baud "$BAUD" --trials "$TRIALS" --model "$MODEL" \
  --target-coeff "$TARGET_COEFF" --target-load "$TARGET_LOAD" --stale-byte "$STALE_BYTE" \
  --message-tweak "$MESSAGE_TWEAK" --expected-faults 1 \
  --read-detail --read-digest --read-hpc-hw --verbose-packets
