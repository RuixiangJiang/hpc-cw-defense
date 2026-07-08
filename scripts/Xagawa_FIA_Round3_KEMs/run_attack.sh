#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DXAGAWA_HPC_TARGET_CMOV_CYCLES_MIN=${XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN} \
-DXAGAWA_HPC_TARGET_CMOV_CYCLES_MAX=${XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_xagawa_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "xagawa-attack-skip-cmov" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --fault-enable 1 \
  --corrupt-offset "$CORRUPT_OFFSET" \
  --corrupt-mask "$CORRUPT_MASK" \
  --expect-fail 1 \
  --expected-fault-skips 1 \
  --read-hpc-hw \
  --verbose-packets
