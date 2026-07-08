#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

FAULT_ENABLE=1

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DISLAM_HPC_SIGN_CYCLES_MIN=${ISLAM_HPC_SIGN_CYCLES_MIN} \
-DISLAM_HPC_SIGN_CYCLES_MAX=${ISLAM_HPC_SIGN_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_islam_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "islam-attack-s1off${S1_BYTE_OFFSET}-mask${BIT_MASK}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --fault-enable "$FAULT_ENABLE" \
  --s1-byte-offset "$S1_BYTE_OFFSET" \
  --bit-mask "$BIT_MASK" \
  --restore-after-sign "$RESTORE_AFTER_SIGN" \
  --verify-after-sign "$VERIFY_AFTER_SIGN" \
  --expected-faults 1 \
  --read-hpc-hw \
  --verbose-packets
