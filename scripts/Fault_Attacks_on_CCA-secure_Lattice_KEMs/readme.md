# Fault Attacks on CCA-secure Lattice KEMs: single-coefficient DecodeMessage fault simulation with DWT hardware counters

This directory contains the ChipWhisperer/Cortex-M experiment for the Kyber part of **Fault Attacks on CCA-secure Lattice KEMs**.

The experiment emulates a single-coefficient DecodeMessage fault in Kyber decapsulation and uses the Cortex-M DWT hardware performance counter (`DWT_CYCCNT`) to detect the resulting coefficient-level cycle-count deviation.

The current implementation uses a **single firmware binary** for both baseline and attack trials. Baseline/attack mode is selected at runtime through SimpleSerial, not by compiling two different binaries.

---

## Files

Important files:

```text
scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/
├── run_base.sh
├── run_attack_coeff.sh
├── run_cycle_stats_20.sh
├── test_kyberprobe_upload_ct_dec.py
└── readme.md

firmware/cw-kyber51290s-decoder-skip/
└── simpleserial-kyberprobe.c

third_party/pqm4/crypto_kem/kyber512-90s/m4fspeed/
├── poly.c
└── poly_decode_hpc.inc
```

The experiment-specific Kyber DecodeMessage modification is gated by:

```bash
-DPQM4_EXP_FAULT_ATTACKS_ON_CCA_SECURE_LATTICE_KEMS=1
```

If this macro is not set, the normal pqm4 Kyber implementation should be used.

---

## Fault model

### Normal DecodeMessage operation

In Kyber `poly_tomsg()`, each message bit is decoded from one polynomial coefficient. The normal coefficient-level decoding primitive is:

```c
t = ((((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1);
```

In this experiment, the monitored coefficient index is the flattened index:

```c
coeff_idx = 8 * i + j;
```

Therefore:

```text
target_coeff = 0  =>  i = 0, j = 0
target_coeff = 1  =>  i = 0, j = 1
target_coeff = 17 =>  i = 2, j = 1
```

### Faulted DecodeMessage primitive

The software-emulated faulted primitive skips the `+ KYBER_Q / 2` term for exactly one selected coefficient:

```c
t = (((x << 1) / KYBER_Q) & 1);
```

The normal and faulted primitives are both compiled into the same firmware image:

```c
__attribute__((noinline))
static uint16_t hpc_cw_decode_round_normal(int32_t x)
{
    return (uint16_t)((((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1);
}

__attribute__((noinline))
static uint16_t hpc_cw_decode_round_faulted_no_qhalf(int32_t x)
{
    return (uint16_t)(((x << 1) / KYBER_Q) & 1);
}
```

---

## Prefix-target-suffix simulation structure

Earlier versions used an `if` inside every coefficient decode to decide whether the current coefficient was the target. That polluted the cycle measurement because the attack path included extra branch and bookkeeping logic.

The current version avoids that by splitting the flattened coefficient traversal into three parts:

```text
prefix:  coefficients before target_coeff are decoded normally
target:  only target_coeff is decoded normally or faulted depending on runtime mode
suffix:  coefficients after target_coeff are decoded normally
```

Conceptually:

```c
if (target_coeff < ncoeff) {
    for (coeff_idx = 0; coeff_idx < target_coeff; coeff_idx++) {
        normal_decode(coeff_idx);
    }

    if (attack_enable) {
        faulted_decode(target_coeff);
    } else {
        normal_decode(target_coeff);
    }

    for (coeff_idx = target_coeff + 1; coeff_idx < ncoeff; coeff_idx++) {
        normal_decode(coeff_idx);
    }
}
```

This preserves the target position while avoiding an additional target-check branch in every loop iteration.

---

## Runtime baseline/attack selection

Baseline and attack use the same firmware binary. The runtime mode is controlled by these global variables in `poly_decode_hpc.inc`:

```c
volatile unsigned int hpc_cw_attack_enable = 0;
volatile unsigned int hpc_cw_attack_target_coeff = 0;
```

The SimpleSerial wrapper configures them using the `F` command:

```text
F payload:
  byte 0 = attack_enable
           0 -> baseline mode
           1 -> attack mode

  byte 1 = target_coeff
           0..255
```

The Python test script exposes this through:

```bash
--attack-enable 0      # baseline
--attack-enable 1      # attack
--target-coeff 0       # selected coefficient
```

For example:

```bash
--attack-enable 0 --target-coeff 0
```

runs baseline mode for coefficient 0, while:

```bash
--attack-enable 1 --target-coeff 0
```

runs the single-coefficient faulted mode for coefficient 0.

---

## DWT hardware counter measurement

The experiment uses the Cortex-M DWT hardware cycle counter:

```text
DWT_CYCCNT
```

The firmware also exposes several additional DWT profiling counters for observation:

```text
DWT_CPICNT
DWT_EXCCNT
DWT_LSUCNT
DWT_FOLDCNT
```

The key detector field is:

```text
target_coeff_cycles
```

This is the measured cycle count of the selected target coefficient.

The firmware also records:

```text
decode_cycles       whole DecodeMessage region cycles
coeff_cycles_min    minimum per-coefficient cycle count among all 256 coefficients
coeff_cycles_max    maximum per-coefficient cycle count among all 256 coefficients
coeff_cycles_sum    sum of all 256 per-coefficient cycle counts
```

The Python script reads the hardware-counter snapshot through the `Y` SimpleSerial command when `--read-hpc-hw` is passed.

Example output:

```text
[hpc-hw]
  available           : 3
  anomaly             : 0
  decode_cycles       : ...
  decode_cpi          : ...
  decode_exc          : ...
  decode_lsu          : ...
  decode_fold         : ...
  target_coeff_cycles : ...
  coeff_cycles_min    : ...
  coeff_cycles_max    : ...
  coeff_cycles_sum    : ...
```

---

## Calibration and threshold computation

Let \(x_i\) be the measured fault-free target coefficient cycle count in the \(i\)-th calibration run.

The baseline mean and sample standard deviation are:

```text
mu_R    = mean(x_i)
sigma_R = sample_stdev(x_i)
```

Given a confidence parameter \(\lambda\), the calibrated acceptance envelope is:

```text
tau_R^- = mu_R - lambda * sigma_R
tau_R^+ = mu_R + lambda * sigma_R
```

The detector accepts an execution only if:

```text
tau_R^- <= target_coeff_cycles <= tau_R^+
```

It rejects an execution when the target coefficient cycle count is below the lower bound or above the upper bound.

### Current calibration result

In the current single-binary experiment, 20 baseline runs produced:

```text
baseline target_coeff_cycles = 25 for every run
```

Therefore:

```text
mu_R    = 25
sigma_R = 0
```

For any finite confidence parameter \(\lambda\):

```text
tau_R^- = 25
tau_R^+ = 25
```

The corresponding compile-time thresholds are:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MIN=25
-DHPC_HW_TARGET_COEFF_CYCLES_MAX=25
```

For the current attack, the target coefficient is measured at 24 cycles, so it is rejected by the lower bound:

```text
24 < tau_R^- = 25
```

For this specific experiment, the lower bound alone is enough to detect the attack:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MIN=25
```

However, the two-sided envelope is the more general detector form.

---

## Current experimental result

### Baseline mode

In baseline mode:

```bash
--attack-enable 0 --target-coeff 0
```

all 256 coefficients use the normal DecodeMessage primitive.

Observed coefficient-level result:

```text
coeff_cycles_min = 25
coeff_cycles_max = 25
coeff_cycles_sum = 6400 = 25 * 256
target_coeff_cycles = 25
fault_skips = 0
```

Expected detector result:

```text
hpc_hw_anomaly = 0
decode_error   = 0
```

### Attack mode

In attack mode:

```bash
--attack-enable 1 --target-coeff 0
```

only the selected target coefficient uses the faulted DecodeMessage primitive. All other coefficients use the normal primitive.

Observed coefficient-level result:

```text
coeff_cycles_min = 24
coeff_cycles_max = 25
coeff_cycles_sum = 6399 = 25 * 255 + 24
target_coeff_cycles = 24
fault_skips = 1
```

This confirms that the experiment faults exactly one coefficient.

With the calibrated lower bound:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MIN=25
```

the attack is rejected because:

```text
target_coeff_cycles = 24 < 25
```

Expected detector result:

```text
hpc_hw_anomaly = 8
decode_error   = 64
```

The values are bit flags:

```text
8  = 0x08 = HPC_HW_ERR_TARGET_CYCLES_LOW
64 = 0x40 = HPC_CW_DECERR_HW_COUNTER
```

---

## Building and running

### Baseline

```bash
cd ~/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_base.sh
```

Expected result:

```text
fault_skips       = 0
target_ss_match   = 1
host_ss_match     = 1
hpc_hw_anomaly    = 0
decode_error      = 0
```

### Attack

```bash
cd ~/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_attack_coeff.sh
```

Expected result:

```text
fault_skips       = 1
hpc_hw_anomaly    = 8
decode_error      = 64
```

### Repeated trials

```bash
TRIALS=20 ./run_base.sh
TRIALS=20 ./run_attack_coeff.sh
```

### Testing another coefficient

```bash
TARGET_COEFF=17 ./run_base.sh
TARGET_COEFF=17 ./run_attack_coeff.sh
```

The target coefficient is selected at runtime through SimpleSerial, so this does not require compiling a separate attack binary.

---

## Direct use of the Python test script

Baseline mode:

```bash
cd ~/hpc-cw-defense

python3 scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py \
  --hex firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-singlebin-hwdef-CWLITEARM.hex \
  --label singlebin-hwdef-baseline-coeff0 \
  --attack-enable 0 \
  --target-coeff 0 \
  --expected-fault-skips 0 \
  --expect-ss-match 1 \
  --expect-defense-error 0 \
  --read-hpc-hw
```

Attack mode:

```bash
cd ~/hpc-cw-defense

python3 scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py \
  --hex firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-singlebin-hwdef-CWLITEARM.hex \
  --no-program \
  --label singlebin-hwdef-attack-coeff0 \
  --attack-enable 1 \
  --target-coeff 0 \
  --expected-fault-skips 1 \
  --allow-defense-fail \
  --expect-defense-error 1 \
  --read-hpc-hw
```

---

## Observation mode

To observe cycle counts without triggering the detector, compile or run with thresholds disabled:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MIN=0 \
HPC_HW_TARGET_COEFF_CYCLES_MAX=0 \
./run_base.sh
```

For attack observation, remove the `--expect-defense-error 1` check or run the Python script directly without that argument:

```bash
python3 scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py \
  --hex firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-singlebin-hwdef-CWLITEARM.hex \
  --label observe-attack-coeff0 \
  --attack-enable 1 \
  --target-coeff 0 \
  --expected-fault-skips 1 \
  --allow-defense-fail \
  --read-hpc-hw
```
