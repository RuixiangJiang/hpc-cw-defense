#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

export TRIALS="${TRIALS:-20}"
OUT_DIR="$SCRIPT_DIR/cycle_stats/nnuo_call${TARGET_CALL}_stale${STALE_NONCE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

"$SCRIPT_DIR/run_base.sh" 2>&1 | tee "$OUT_DIR/baseline.log"

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --no-program \
  --label "nnuo-attack-observe-call${TARGET_CALL}-stale${STALE_NONCE}" \
  --baud "$BAUD" \
  --trials "$TRIALS" \
  --fault-enable 1 \
  --target-call "$TARGET_CALL" \
  --stale-nonce "$STALE_NONCE" \
  --message-hex "$MESSAGE_HEX" \
  --expected-fault-skips 1 \
  --expect-defense-error 1 \
  --read-hpc-hw \
  2>&1 | tee "$OUT_DIR/attack.log"

echo "[done] logs written to $OUT_DIR"
