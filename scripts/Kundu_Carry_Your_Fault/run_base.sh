#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="none"
TARGET_COEFF="${TARGET_COEFF:-17}"
TARGET_BIT="${TARGET_BIT:-7}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DKUNDU_HPC_TARGET_CYCLES_MIN=${KUNDU_HPC_TARGET_CYCLES_MIN} \
-DKUNDU_HPC_TARGET_CYCLES_MAX=${KUNDU_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_kundu_carry_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "kundu-baseline-c${TARGET_COEFF}-b${TARGET_BIT}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --target-coeff "$TARGET_COEFF" \
  --target-bit "$TARGET_BIT" \
  --message-tweak "$MESSAGE_TWEAK" \
  --expected-faults 0 \
  --read-detail \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
