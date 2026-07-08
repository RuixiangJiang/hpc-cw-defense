#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
TEST_SCRIPT="$SCRIPT_DIR/test_kyberprobe_upload_ct_dec.py"

PLATFORM="${PLATFORM:-CWLITEARM}"
SS_VER="${SS_VER:-SS_VER_2_1}"
TARGET_COEFF="${TARGET_COEFF:-0}"
TRIALS="${TRIALS:-1}"
BAUD="${BAUD:-230400}"

# Current calibrated single-binary baseline envelope:
#   baseline target_coeff_cycles = 25
#   attack   target_coeff_cycles = 24
#
# Therefore:
#   attack is rejected because target_coeff_cycles < 25.
#
# Set either bound to 0 to disable that bound in the C preprocessor.
HPC_HW_TARGET_COEFF_CYCLES_MIN="${HPC_HW_TARGET_COEFF_CYCLES_MIN:-25}"
HPC_HW_TARGET_COEFF_CYCLES_MAX="${HPC_HW_TARGET_COEFF_CYCLES_MAX:-25}"

TARGET_NAME="${TARGET_NAME:-cw-kyber51290s-decoder-skip-singlebin-hwdef}"
HEX_PATH="$FW_APP_DIR/${TARGET_NAME}-${PLATFORM}.hex"

echo "[info] repo root       : $REPO_ROOT"
echo "[info] firmware        : $FW_APP_DIR"
echo "[info] test script     : $TEST_SCRIPT"
echo "[info] target name     : $TARGET_NAME"
echo "[info] platform        : $PLATFORM"
echo "[info] target coeff    : $TARGET_COEFF"
echo "[info] trials          : $TRIALS"
echo "[info] baud            : $BAUD"
echo "[info] DWT cycles min  : $HPC_HW_TARGET_COEFF_CYCLES_MIN"
echo "[info] DWT cycles max  : $HPC_HW_TARGET_COEFF_CYCLES_MAX"
echo "[info] hex             : $HEX_PATH"

cd "$FW_APP_DIR"

echo
echo "============================================================"
echo "[clean] removing old build outputs"
echo "============================================================"

rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_SINGLEBIN="-DPQM4_EXP_FAULT_ATTACKS_ON_CCA_SECURE_LATTICE_KEMS=1 \
-DHPC_HW_ENABLE=1 \
-DHPC_HW_TARGET_COEFF_CYCLES_MIN=${HPC_HW_TARGET_COEFF_CYCLES_MIN} \
-DHPC_HW_TARGET_COEFF_CYCLES_MAX=${HPC_HW_TARGET_COEFF_CYCLES_MAX} \
-DDEFENSE_DUP_SELECTED=0 \
-DDEFENSE_REDUNDANT_FULL=0"

echo
echo "============================================================"
echo "[build] single-binary hardware-counter firmware"
echo "============================================================"
echo "[build] EXTRA_CFLAGS=$EXTRA_CFLAGS_SINGLEBIN"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_SINGLEBIN" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_singlebin_hwdef.log

if [[ ! -f "$HEX_PATH" ]]; then
    echo "[error] hex file not generated: $HEX_PATH" >&2
    exit 1
fi

echo
echo "============================================================"
echo "[test] attack mode"
echo "============================================================"

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "singlebin-hwdef-attack-coeff${TARGET_COEFF}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --attack-enable 1 \
  --target-coeff "$TARGET_COEFF" \
  --expected-fault-skips 1 \
  --allow-defense-fail \
  --expect-defense-error 1 \
  --read-hpc-hw \
  --verbose-packets

echo
echo "[done] attack single-binary hardware-counter test passed"
