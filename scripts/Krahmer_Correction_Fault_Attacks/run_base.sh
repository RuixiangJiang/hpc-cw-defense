#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="none"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DKRAHMER_HPC_TARGET_CYCLES_MIN=${KRAHMER_HPC_TARGET_CYCLES_MIN} \
-DKRAHMER_HPC_TARGET_CYCLES_MAX=${KRAHMER_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_krahmer_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "krahmer-baseline-coeff${TARGET_COEFF}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --target-coeff "$TARGET_COEFF" \
  --message-tweak "$MESSAGE_TWEAK" \
  --expected-faults 0 \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
