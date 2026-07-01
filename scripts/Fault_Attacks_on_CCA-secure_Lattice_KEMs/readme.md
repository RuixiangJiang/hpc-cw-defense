# Fault Attacks on CCA-secure Lattice KEMs: Kyber512-90s Decoder-Skip Defense

This directory contains scripts and firmware support for testing a ChipWhisperer-based Kyber512-90s decoder-skip experiment on `CWLITEARM`.

The current implementation targets the attack style inspired by *Fault Attacks on CCA-secure Lattice KEMs*: a fault in the `DecodeMessage` path of Kyber decapsulation, specifically around the `+ KYBER_Q / 2` rounding step inside `poly_tomsg()`.

The current verified setup supports:

- Kyber512-90s, `m4fspeed`, pqm4 Round3 implementation.
- ChipWhisperer Lite + CW308 STM32F3 / `CWLITEARM`.
- SimpleSerial2 (`SS_VER_2_1`) at `230400` baud.
- Baseline KEM flow: `K -> E -> T -> C -> D -> H`.
- Hardware-counter observation and defense using Cortex-M DWT counters.
- Single-coefficient source-level decoder-skip attack.

---

## Directory layout

Relevant files:

```text
scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/
├── README.md
├── run_hwobs_baseline.sh
├── run_hwobs_attack_coeff.sh
└── test_kyberprobe_upload_ct_dec.py

firmware/cw-kyber51290s-decoder-skip/
├── Makefile
└── simpleserial-kyberprobe.c

third_party/pqm4/crypto_kem/kyber512-90s/m4fspeed/
├── poly.c
└── poly_decode_hpc.inc
```

The `poly.c` file should keep most original pqm4 code unchanged. The modified `poly_tomsg()` is replaced with:

```c
#include "poly_decode_hpc.inc"
```

The actual decoder-skip attack simulation and DWT hardware-counter instrumentation live in:

```text
poly_decode_hpc.inc
```

---

## Attack model

The current attack model is a **single-coefficient DecodeMessage skip**.

It is enabled with:

```bash
-DATTACK_DECODER_SKIP_QHALF=1
-DATTACK_TARGET_COEFF=0
```

The faultable DecodeMessage path is conceptually:

```c
#if ATTACK_DECODER_SKIP_QHALF
    if ((int)coeff_idx == ATTACK_TARGET_COEFF) {
        hpc_cw_fault_skips++;
        return ((x << 1) / KYBER_Q) & 1;
    }
#endif

return (((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
```

Therefore, when `ATTACK_TARGET_COEFF=0`, only the first coefficient in `poly_tomsg()` is affected:

```text
i = 0, j = 0, coeff_idx = 0
```

Expected attack-side status:

```text
fault_skips = 1
```

This confirms that exactly one coefficient was affected by the source-level decoder-skip model.

This is **not** an all-coefficient skip and **not** a persistent patch that removes `+ KYBER_Q / 2` for every coefficient.

---

## Hardware counters used

The current hardware-counter defense uses real Cortex-M DWT counters, not the earlier software qhalf token.

Main counter used for the defense decision:

```text
DWT_CYCCNT
```

Additional DWT profiling counters are read back for observation:

```text
DWT_CPICNT
DWT_EXCCNT
DWT_LSUCNT
DWT_FOLDCNT
```

The firmware measures:

```text
DecodeMessage region cycles
per-coefficient cycles
target coefficient cycles
coefficient min/max/sum cycles
CPI events
exception events
LSU events
folded instruction events
```

The test script reads these values using the `Y` SimpleSerial command.

---

## Current calibrated threshold

Current observation on the verified setup:

```text
baseline:
  target_coeff_cycles = 20

attack:
  target_coeff_cycles = 29
```

Therefore the current default threshold is:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MAX=24
```

Detection rule:

```text
target_coeff_cycles > 24  =>  hardware-counter anomaly
```

When this threshold fires, the firmware sets:

```text
decode_error = 64
```

where:

```text
64 = 0x40 = HPC_CW_DECERR_HW_COUNTER
```

The hardware anomaly field is expected to contain:

```text
hpc_hw_anomaly = 16
```

where:

```text
16 = 0x10 = HPC_HW_ERR_TARGET_CYCLES_HIGH
```

---

## SimpleSerial command flow

The verified full-flow test uses:

```text
P  -> ping
K  -> keypair
E  -> encaps
T  -> read target-generated ciphertext in 128-byte chunks
C  -> upload ciphertext back to target in 128-byte chunks
D  -> decaps
H  -> short status
Y  -> DWT hardware-counter status
```

The ciphertext chunk size is:

```text
CT_CHUNK = 128
```

This is known to work with the verified script style using:

```python
target.simpleserial_write(...)
target.simpleserial_read_witherrors(..., glitch_timeout=...)
```

---

## Baseline hardware-counter defense test

Run:

```bash
cd /home/ruixiang/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_hwobs_baseline.sh
```

The script performs:

1. Clean build.
2. Compile baseline firmware with DWT hardware-counter defense enabled.
3. Flash the target.
4. Run full KEM test.
5. Read the `H` status and `Y` hardware-counter status.

Expected result:

```text
fault_skips       = 0
decode_error      = 0
hpc_hw_anomaly    = 0
target_ss_match   = 1
host_ss_match     = 1
```

Expected DWT hardware-counter behavior:

```text
target_coeff_cycles <= 24
```

---

## Attack hardware-counter defense test

Run:

```bash
cd /home/ruixiang/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_hwobs_attack_coeff.sh
```

The script performs:

1. Clean build.
2. Compile attack firmware with single-coefficient decoder skip.
3. Enable DWT hardware-counter threshold.
4. Flash the target.
5. Run full KEM test.
6. Read the `H` status and `Y` hardware-counter status.

Expected result:

```text
fault_skips       = 1
decode_error      = 64
hpc_hw_anomaly    = 16
```

The decapsulation wrapper may reject the result and return `0xFD`. The script accepts this with:

```bash
--allow-defense-fail
```

Expected DWT hardware-counter behavior:

```text
target_coeff_cycles > 24
```

---

## Testing another coefficient

To test a different coefficient:

```bash
TARGET_COEFF=17 ./run_hwobs_attack_coeff.sh
```

The script compiles with:

```bash
-DATTACK_TARGET_COEFF=17
```

If the cycle distribution changes for another coefficient, recalibrate the threshold:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MAX=<new_threshold> ./run_hwobs_attack_coeff.sh
```

---

## Overriding the hardware-counter threshold

Default:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MAX=24
```

Override example:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MAX=26 ./run_hwobs_attack_coeff.sh
```

or for baseline:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MAX=26 ./run_hwobs_baseline.sh
```

---

## Script: `run_hwobs_baseline.sh`

Recommended content:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
TEST_SCRIPT="$SCRIPT_DIR/test_kyberprobe_upload_ct_dec.py"

PLATFORM="${PLATFORM:-CWLITEARM}"
SS_VER="${SS_VER:-SS_VER_2_1}"
TARGET_COEFF="${TARGET_COEFF:-0}"

HPC_HW_TARGET_COEFF_CYCLES_MAX="${HPC_HW_TARGET_COEFF_CYCLES_MAX:-24}"

TARGET_NAME="${TARGET_NAME:-cw-kyber51290s-decoder-skip-hwdef-baseline}"
HEX_PATH="$FW_APP_DIR/${TARGET_NAME}-${PLATFORM}.hex"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_BASE="-DATTACK_DECODER_SKIP_QHALF=0 -DATTACK_TARGET_COEFF=${TARGET_COEFF} -DHPC_HW_ENABLE=1 -DHPC_HW_TARGET_COEFF_CYCLES_MAX=${HPC_HW_TARGET_COEFF_CYCLES_MAX} -DDEFENSE_DUP_SELECTED=0 -DDEFENSE_REDUNDANT_FULL=0"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_BASE" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee build_hwdef_baseline.log

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "hwdef-baseline" \
  --expected-fault-skips 0 \
  --expect-ss-match 1 \
  --expect-defense-error 0 \
  --read-hpc-hw \
  --verbose-packets
```

---

## Script: `run_hwobs_attack_coeff.sh`

Recommended content:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
TEST_SCRIPT="$SCRIPT_DIR/test_kyberprobe_upload_ct_dec.py"

PLATFORM="${PLATFORM:-CWLITEARM}"
SS_VER="${SS_VER:-SS_VER_2_1}"
TARGET_COEFF="${TARGET_COEFF:-0}"

HPC_HW_TARGET_COEFF_CYCLES_MAX="${HPC_HW_TARGET_COEFF_CYCLES_MAX:-24}"

TARGET_NAME="${TARGET_NAME:-cw-kyber51290s-decoder-skip-hwdef-attack-coeff${TARGET_COEFF}}"
HEX_PATH="$FW_APP_DIR/${TARGET_NAME}-${PLATFORM}.hex"

cd "$FW_APP_DIR"
rm -rf "objdir-$PLATFORM"
rm -f ./*.elf ./*.hex ./*.map ./*.lss ./*.lst ./*.sym

EXTRA_CFLAGS_ATTACK="-DATTACK_DECODER_SKIP_QHALF=1 -DATTACK_TARGET_COEFF=${TARGET_COEFF} -DHPC_HW_ENABLE=1 -DHPC_HW_TARGET_COEFF_CYCLES_MAX=${HPC_HW_TARGET_COEFF_CYCLES_MAX} -DDEFENSE_DUP_SELECTED=0 -DDEFENSE_REDUNDANT_FULL=0"

make TARGET="$TARGET_NAME" \
     PLATFORM="$PLATFORM" \
     SS_VER="$SS_VER" \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="$EXTRA_CFLAGS_ATTACK" \
     "${TARGET_NAME}-${PLATFORM}.hex" \
     2>&1 | tee "build_hwdef_attack_coeff${TARGET_COEFF}.log"

cd "$REPO_ROOT"

python3 "$TEST_SCRIPT" \
  --hex "$HEX_PATH" \
  --label "hwdef-attack-coeff${TARGET_COEFF}" \
  --expected-fault-skips 1 \
  --allow-defense-fail \
  --expect-defense-error 1 \
  --read-hpc-hw \
  --verbose-packets
```

---

## Important interpretation note

This experiment uses **real Cortex-M DWT hardware counters** for detection.

However, the injected attack is still a **source-level simulated single-coefficient decoder skip**. It is not yet a physical clock/voltage/EM glitch.

Therefore, the correct claim is:

```text
DWT hardware counters detect the implemented single-coefficient source-level decoder-skip model.
```

Do not overclaim:

```text
DWT counters always detect a physical instruction skip of `+ KYBER_Q / 2`.
```

For a physical glitch, the cycle direction and threshold may differ. A new calibration step is required from measured traces.

---

## Verified status

Current verified values:

```text
baseline:
  available           = 3
  anomaly             = 0
  decode_cycles       = 15938
  decode_cpi          = 92
  decode_exc          = 0
  decode_lsu          = 77
  decode_fold         = 0
  target_coeff_cycles = 20
  coeff_cycles_min    = 20
  coeff_cycles_max    = 20
  coeff_cycles_sum    = 5120

attack:
  available           = 3
  anomaly             = 0 before threshold
  decode_cycles       = 16043
  decode_cpi          = 32
  decode_exc          = 0
  decode_lsu          = 111
  decode_fold         = 0
  target_coeff_cycles = 29
  coeff_cycles_min    = 22
  coeff_cycles_max    = 29
  coeff_cycles_sum    = 5639
```

With:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MAX=24
```

expected hardware-counter defense result:

```text
baseline:
  decode_error   = 0
  hpc_hw_anomaly = 0

attack:
  decode_error   = 64
  hpc_hw_anomaly = 16
```
