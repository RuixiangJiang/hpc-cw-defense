#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="${MODEL:-block}"
TARGET_ROW="${TARGET_ROW:-0}"
TARGET_COL="${TARGET_COL:-0}"
TARGET_COEFF="${TARGET_COEFF:-17}"
FAULT_VALUE="${FAULT_VALUE:-0}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

KRAHMER_A_HPC_TARGET_CYCLES_MIN="${KRAHMER_A_HPC_TARGET_CYCLES_MIN:-0}"
KRAHMER_A_HPC_TARGET_CYCLES_MAX="${KRAHMER_A_HPC_TARGET_CYCLES_MAX:-0}"

TARGET_NAME="${TARGET_NAME:-cw-dilithium-krahmer-afault-singlebin}"
HEX_PATH="$FW_APP_DIR/${TARGET_NAME}-${PLATFORM}.hex"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DKRAHMER_A_HPC_TARGET_CYCLES_MIN=${KRAHMER_A_HPC_TARGET_CYCLES_MIN} \
-DKRAHMER_A_HPC_TARGET_CYCLES_MAX=${KRAHMER_A_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     APP_SRC=simpleserial-dilithium-krahmer-afault.c \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_krahmer_afault_singlebin.log

cd "$REPO_ROOT"

python3 "$SCRIPT_DIR/test_krahmer_afault.py" \
  --hex "$HEX_PATH" \
  --label "krahmer-afault-${MODEL}-r${TARGET_ROW}c${TARGET_COL}n${TARGET_COEFF}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --target-row "$TARGET_ROW" \
  --target-col "$TARGET_COL" \
  --target-coeff "$TARGET_COEFF" \
  --fault-value "$FAULT_VALUE" \
  --message-tweak "$MESSAGE_TWEAK" \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
