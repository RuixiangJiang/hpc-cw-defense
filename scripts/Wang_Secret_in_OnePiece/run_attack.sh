#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

if [ -z "${MODEL:-}" ] || [ "${MODEL:-}" = "none" ]; then
  MODEL="skip"
fi

TARGET_WORD="${TARGET_WORD:-17}"
TARGET_BIT="${TARGET_BIT:-5}"
PREVIOUS_BIT="${PREVIOUS_BIT:-0}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DONEPIECE_HPC_TARGET_CYCLES_MIN=${ONEPIECE_HPC_TARGET_CYCLES_MIN} \
-DONEPIECE_HPC_TARGET_CYCLES_MAX=${ONEPIECE_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_wang_onepiece_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "onepiece-${MODEL}-w${TARGET_WORD}-b${TARGET_BIT}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --target-word "$TARGET_WORD" \
  --target-bit "$TARGET_BIT" \
  --previous-bit "$PREVIOUS_BIT" \
  --message-tweak "$MESSAGE_TWEAK" \
  --expected-faults 1 \
  --read-detail \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
