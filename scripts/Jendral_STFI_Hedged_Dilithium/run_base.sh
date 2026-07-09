#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="none"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DJENDRAL_HPC_TARGET_CYCLES_MIN=${JENDRAL_HPC_TARGET_CYCLES_MIN} \
-DJENDRAL_HPC_TARGET_CYCLES_MAX=${JENDRAL_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_jendral_seedabsorb_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "jendral-baseline" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --message-tweak "$MESSAGE_TWEAK" \
  --expected-faults 0 \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
