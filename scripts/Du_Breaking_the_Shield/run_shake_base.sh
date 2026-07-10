#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="none"
STOP_BLOCK="${STOP_BLOCK:-4}"
SKIP_BLOCK="${SKIP_BLOCK:-3}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 -DDU_HPC_TARGET_CYCLES_MIN=${DU_HPC_TARGET_CYCLES_MIN} -DDU_HPC_TARGET_CYCLES_MAX=${DU_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" PLATFORM="$PLATFORM" SS_VER="$SS_VER" CRYPTO_TARGET=NONE \
     DU_SRC=simpleserial-du-shake256.c EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" 2>&1 | tee build_du_shake256_singlebin.log

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/test_du_shake256_absorb.py" \
  --hex "$HEX_PATH" --label "du-shake-baseline" --baud "$BAUD" --trials "$TRIALS" \
  --model "$MODEL" --stop-block "$STOP_BLOCK" --skip-block "$SKIP_BLOCK" \
  --message-tweak "$MESSAGE_TWEAK" --expected-faults 0 \
  --read-digest --read-hpc-hw --verbose-packets
