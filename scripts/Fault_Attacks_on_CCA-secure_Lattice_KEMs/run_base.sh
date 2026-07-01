#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
TEST_SCRIPT="$SCRIPT_DIR/test_kyberprobe_upload_ct_dec.py"

PLATFORM="${PLATFORM:-CWLITEARM}"
SS_VER="${SS_VER:-SS_VER_2_1}"
TARGET_COEFF="${TARGET_COEFF:-0}"

# Threshold calibrated from current observation:
#   baseline target_coeff_cycles = 20
#   attack   target_coeff_cycles = 29
#
# Therefore:
#   target_coeff_cycles > 24 => DWT hardware-counter anomaly.
HPC_HW_TARGET_COEFF_CYCLES_MAX="${HPC_HW_TARGET_COEFF_CYCLES_MAX:-24}"

TARGET_NAME="${TARGET_NAME:-cw-kyber51290s-decoder-skip-hwdef-baseline}"
HEX_PATH="$FW_APP_DIR/${TARGET_NAME}-${PLATFORM}.hex"

echo "[info] repo root       : $REPO_ROOT"
echo "[info] firmware        : $FW_APP_DIR"
echo "[info] target          : $TARGET_NAME"
echo "[info] platform        : $PLATFORM"
echo "[info] target coeff    : $TARGET_COEFF"
echo "[info] DWT cycles max  : $HPC_HW_TARGET_COEFF_CYCLES_MAX"
echo "[info] hex             : $HEX_PATH"

cd "$FW_APP_DIR"

echo "[clean] removing old build outputs"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_BASE="-DATTACK_DECODER_SKIP_QHALF=0 -DATTACK_TARGET_COEFF=${TARGET_COEFF} -DHPC_HW_ENABLE=1 -DHPC_HW_TARGET_COEFF_CYCLES_MAX=${HPC_HW_TARGET_COEFF_CYCLES_MAX} -DDEFENSE_DUP_SELECTED=0 -DDEFENSE_REDUNDANT_FULL=0"

echo "[build] baseline hardware-counter defense firmware"
echo "[build] EXTRA_CFLAGS=$EXTRA_CFLAGS_BASE"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_BASE" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_hwdef_baseline.log

if [[ ! -f "$HEX_PATH" ]]; then
    echo "[error] hex file not generated: $HEX_PATH" >&2
    exit 1
fi

echo "[test] programming target and running baseline hardware-counter defense test"

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "hwdef-baseline" \
  --expected-fault-skips 0 \
  --expect-ss-match 1 \
  --expect-defense-error 0 \
  --read-hpc-hw \
  --verbose-packets

echo "[done] baseline hardware-counter defense test passed"