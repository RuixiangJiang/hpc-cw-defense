#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
TEST_SCRIPT="$SCRIPT_DIR/test_kyberprobe_upload_ct_dec.py"

PLATFORM="${PLATFORM:-CWLITEARM}"
SS_VER="${SS_VER:-SS_VER_2_1}"
TARGET_COEFF="${TARGET_COEFF:-0}"
TRIALS="${TRIALS:-20}"

EXP_MACRO="-DPQM4_EXP_FAULT_ATTACKS_ON_CCA_SECURE_LATTICE_KEMS=1"

OUT_DIR="$SCRIPT_DIR/cycle_stats/coeff${TARGET_COEFF}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

BASE_TARGET="cw-kyber51290s-cycle-stat-baseline-coeff${TARGET_COEFF}"
ATTACK_TARGET="cw-kyber51290s-cycle-stat-attack-coeff${TARGET_COEFF}"

BASE_HEX="$FW_APP_DIR/${BASE_TARGET}-${PLATFORM}.hex"
ATTACK_HEX="$FW_APP_DIR/${ATTACK_TARGET}-${PLATFORM}.hex"

echo "[info] repo root    : $REPO_ROOT"
echo "[info] firmware     : $FW_APP_DIR"
echo "[info] platform     : $PLATFORM"
echo "[info] target coeff : $TARGET_COEFF"
echo "[info] trials       : $TRIALS"
echo "[info] output dir   : $OUT_DIR"

build_firmware() {
    local target_name="$1"
    local attack_enable="$2"
    local log_file="$3"

    cd "$FW_APP_DIR"

    echo
    echo "============================================================"
    echo "[build] $target_name"
    echo "============================================================"

    rm -rf "objdir-$PLATFORM"
    rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

    EXTRA_CFLAGS="$EXP_MACRO \
-DATTACK_DECODER_SKIP_QHALF=${attack_enable} \
-DATTACK_TARGET_COEFF=${TARGET_COEFF} \
-DHPC_HW_ENABLE=1 \
-DDEFENSE_DUP_SELECTED=0 \
-DDEFENSE_REDUNDANT_FULL=0"

    echo "[build] EXTRA_CFLAGS=$EXTRA_CFLAGS"

    make TARGET="$target_name" \
         PLATFORM="$PLATFORM" \
         SS_VER="$SS_VER" \
         CRYPTO_TARGET=NONE \
         EXTRA_CFLAGS="$EXTRA_CFLAGS" \
         "${target_name}-${PLATFORM}.hex" \
         2>&1 | tee "$log_file"
}

run_test() {
    local label="$1"
    local hex_path="$2"
    local expected_fault_skips="$3"
    local log_file="$4"

    cd "$REPO_ROOT"

    echo
    echo "============================================================"
    echo "[test] $label"
    echo "============================================================"

    python3 "$TEST_SCRIPT" \
      --hex "$hex_path" \
      --label "$label" \
      --trials "$TRIALS" \
      --expected-fault-skips "$expected_fault_skips" \
      --allow-defense-fail \
      --read-hpc-hw \
      2>&1 | tee "$log_file"
}

parse_stats() {
    local baseline_log="$1"
    local attack_log="$2"
    local csv_file="$3"
    local summary_file="$4"

    python3 - "$baseline_log" "$attack_log" "$csv_file" "$summary_file" <<'PY'
import csv
import re
import statistics
import sys
from pathlib import Path

baseline_log = Path(sys.argv[1])
attack_log = Path(sys.argv[2])
csv_file = Path(sys.argv[3])
summary_file = Path(sys.argv[4])

FIELDS = [
    "available",
    "anomaly",
    "decode_cycles",
    "decode_cpi",
    "decode_exc",
    "decode_lsu",
    "decode_fold",
    "target_coeff_cycles",
    "coeff_cycles_min",
    "coeff_cycles_max",
    "coeff_cycles_sum",
]

pat = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*:\s*([0-9]+)\s*$")

def parse_log(path, label):
    rows = []
    cur = None

    for line in path.read_text(errors="replace").splitlines():
        if line.strip() == "[hpc-hw]":
            if cur:
                rows.append(cur)
            cur = {"label": label}
            continue

        if cur is not None:
            m = pat.match(line)
            if m:
                k, v = m.group(1), int(m.group(2))
                if k in FIELDS:
                    cur[k] = v

    if cur:
        rows.append(cur)

    return rows

rows = parse_log(baseline_log, "baseline") + parse_log(attack_log, "attack")

with csv_file.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["label", "trial"] + FIELDS)
    writer.writeheader()

    counters = {"baseline": 0, "attack": 0}
    for r in rows:
        label = r["label"]
        counters[label] += 1
        out = {"label": label, "trial": counters[label]}
        for field in FIELDS:
            out[field] = r.get(field, "")
        writer.writerow(out)

def stats(values):
    if not values:
        return "n=0"
    if len(values) == 1:
        return f"n=1 min={values[0]} max={values[0]} mean={values[0]:.2f} stdev=0.00"
    return (
        f"n={len(values)} "
        f"min={min(values)} "
        f"max={max(values)} "
        f"mean={statistics.mean(values):.2f} "
        f"stdev={statistics.stdev(values):.2f}"
    )

def get(label, field):
    return [
        r[field]
        for r in rows
        if r.get("label") == label and field in r
    ]

base_target = get("baseline", "target_coeff_cycles")
atk_target = get("attack", "target_coeff_cycles")

lines = []
lines.append("Cycle statistics")
lines.append("================")
lines.append("")
lines.append(f"baseline trials parsed: {len(base_target)}")
lines.append(f"attack trials parsed  : {len(atk_target)}")
lines.append("")

for field in [
    "target_coeff_cycles",
    "decode_cycles",
    "coeff_cycles_sum",
    "coeff_cycles_min",
    "coeff_cycles_max",
    "decode_cpi",
    "decode_lsu",
]:
    lines.append(f"{field}:")
    lines.append(f"  baseline: {stats(get('baseline', field))}")
    lines.append(f"  attack  : {stats(get('attack', field))}")
    lines.append("")

if base_target and atk_target:
    bmin, bmax = min(base_target), max(base_target)
    amin, amax = min(atk_target), max(atk_target)

    lines.append("Threshold suggestion")
    lines.append("====================")
    lines.append(f"baseline target range: [{bmin}, {bmax}]")
    lines.append(f"attack target range  : [{amin}, {amax}]")
    lines.append("")

    if amax < bmin:
        lines.append("Non-overlapping ranges: attack is always faster than baseline.")
        lines.append("")
        lines.append("Suggested compile-time threshold:")
        lines.append(f"  -DHPC_HW_TARGET_COEFF_CYCLES_MIN={bmin}")
        lines.append("")
        lines.append("Detection rule:")
        lines.append(f"  target_coeff_cycles < {bmin} => anomaly")
    elif amin > bmax:
        lines.append("Non-overlapping ranges: attack is always slower than baseline.")
        lines.append("")
        lines.append("Suggested compile-time threshold:")
        lines.append(f"  -DHPC_HW_TARGET_COEFF_CYCLES_MAX={bmax}")
        lines.append("")
        lines.append("Detection rule:")
        lines.append(f"  target_coeff_cycles > {bmax} => anomaly")
    else:
        lines.append("WARNING: baseline and attack target_coeff_cycles overlap.")
        lines.append("A deterministic single-threshold rule may cause false positives or false negatives.")
        lines.append("Consider collecting more trials or combining multiple counters.")

summary_file.write_text("\n".join(lines) + "\n")

print("\n".join(lines))
print(f"\n[csv]     {csv_file}")
print(f"[summary] {summary_file}")
PY
}

BASE_BUILD_LOG="$OUT_DIR/build_baseline.log"
ATTACK_BUILD_LOG="$OUT_DIR/build_attack.log"
BASE_RUN_LOG="$OUT_DIR/run_baseline.log"
ATTACK_RUN_LOG="$OUT_DIR/run_attack.log"
CSV_FILE="$OUT_DIR/cycles.csv"
SUMMARY_FILE="$OUT_DIR/summary.txt"

build_firmware "$BASE_TARGET" 0 "$BASE_BUILD_LOG"

if [[ ! -f "$BASE_HEX" ]]; then
    echo "[error] missing baseline hex: $BASE_HEX" >&2
    exit 1
fi

run_test "cycle-stat-baseline-coeff${TARGET_COEFF}" "$BASE_HEX" 0 "$BASE_RUN_LOG"

build_firmware "$ATTACK_TARGET" 1 "$ATTACK_BUILD_LOG"

if [[ ! -f "$ATTACK_HEX" ]]; then
    echo "[error] missing attack hex: $ATTACK_HEX" >&2
    exit 1
fi

run_test "cycle-stat-attack-coeff${TARGET_COEFF}" "$ATTACK_HEX" 1 "$ATTACK_RUN_LOG"

parse_stats "$BASE_RUN_LOG" "$ATTACK_RUN_LOG" "$CSV_FILE" "$SUMMARY_FILE"

echo
echo "[done] cycle statistics completed"
echo "[out]  $OUT_DIR"
