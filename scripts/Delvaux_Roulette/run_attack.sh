#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DROULETTE_HPC_TARGET_CYCLES_MIN=${ROULETTE_HPC_TARGET_CYCLES_MIN} \
-DROULETTE_HPC_TARGET_CYCLES_MAX=${ROULETTE_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_roulette_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "roulette-${MODEL}-coeff${TARGET_COEFF}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --target-coeff "$TARGET_COEFF" \
  --const-value "$CONST_VALUE" \
  --bit-mask "$BIT_MASK" \
  --rand-seed "$RAND_SEED" \
  --expected-faults 1 \
  --read-hpc-hw \
  --verbose-packets
