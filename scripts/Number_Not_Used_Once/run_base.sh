#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

echo "[info] experiment  : Number Not Used Once"
echo "[info] mode        : baseline"
echo "[info] firmware    : $FW_APP_DIR"
echo "[info] target      : $TARGET_NAME"
echo "[info] target call : $TARGET_CALL"
echo "[info] stale nonce : $STALE_NONCE"
echo "[info] hex         : $HEX_PATH"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DNNUO_CHECK_NONCE_PROGRESS=${NNUO_CHECK_NONCE_PROGRESS} \
-DNNUO_HPC_TARGET_SAMPLE_CYCLES_MIN=${NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN} \
-DNNUO_HPC_TARGET_SAMPLE_CYCLES_MAX=${NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_nnuo_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "nnuo-baseline-call${TARGET_CALL}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --fault-enable 0 \
  --target-call "$TARGET_CALL" \
  --stale-nonce "$STALE_NONCE" \
  --message-hex "$MESSAGE_HEX" \
  --expected-fault-skips 0 \
  --expect-defense-error 0 \
  --read-hpc-hw \
  --verbose-packets
