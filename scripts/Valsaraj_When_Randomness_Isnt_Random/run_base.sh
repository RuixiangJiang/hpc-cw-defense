#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

MODEL="none"
INTENDED_DOMAIN="${INTENDED_DOMAIN:-2}"
WRONG_DOMAIN="${WRONG_DOMAIN:-1}"
MESSAGE_TWEAK="${MESSAGE_TWEAK:-0}"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DHPC_HW_ENABLE=1 \
-DVALSARAJ_HPC_TARGET_CYCLES_MIN=${VALSARAJ_HPC_TARGET_CYCLES_MIN} \
-DVALSARAJ_HPC_TARGET_CYCLES_MAX=${VALSARAJ_HPC_TARGET_CYCLES_MAX}"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_valsaraj_wrongseed_singlebin.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "valsaraj-baseline-d${INTENDED_DOMAIN}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --model "$MODEL" \
  --intended-domain "$INTENDED_DOMAIN" \
  --wrong-domain "$WRONG_DOMAIN" \
  --message-tweak "$MESSAGE_TWEAK" \
  --expected-faults 0 \
  --read-detail \
  --read-digest \
  --read-hpc-hw \
  --verbose-packets
