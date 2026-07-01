# Coefficient-level DWT hardware counter monitoring

This section documents how the current Kyber DecodeMessage defense uses Cortex-M DWT hardware counters to monitor one selected coefficient.

---

## How the DWT hardware counter monitors one DecodeMessage coefficient

The current defense monitors the execution cost of a selected DecodeMessage coefficient using the Cortex-M DWT hardware cycle counter.

The monitored coefficient is selected at compile time:

```bash
-DATTACK_TARGET_COEFF=0
```

For example, `ATTACK_TARGET_COEFF=0` means the first coefficient decoded by `poly_tomsg()`:

```c
coeff_idx = 8 * i + j;
```

Therefore:

```text
ATTACK_TARGET_COEFF = 0  =>  i = 0, j = 0
ATTACK_TARGET_COEFF = 17 =>  i = 2, j = 1
```

---

## Per-coefficient DWT measurement

Inside `poly_tomsg()`, each coefficient decode is wrapped by DWT cycle-counter reads:

```c
for (i = 0; i < KYBER_SYMBYTES; i++) {
    msg[i] = 0;

    for (j = 0; j < 8; j++) {
        unsigned int coeff_idx = (unsigned int)(8 * i + j);
        uint32_t coeff_cycle_start;

        coeff_cycle_start = hpc_hw_coeff_begin();

        t = hpc_cw_decode_round_faultable(a->coeffs[coeff_idx], coeff_idx);

        hpc_hw_coeff_end(coeff_idx, coeff_cycle_start);

        msg[i] |= t << j;

        hpc_cw_decode_coeff_progress(coeff_idx);
    }
}
```

The monitored operation is the DecodeMessage rounding step:

```c
t = hpc_cw_decode_round_faultable(a->coeffs[coeff_idx], coeff_idx);
```

The DWT cycle counter is read before and after this operation. The cycle difference is then recorded.

---

## DWT cycle read helpers

The coefficient measurement uses `DWT_CYCCNT`:

```c
static inline uint32_t hpc_hw_coeff_begin(void)
{
#if HPC_HW_ENABLE
    return HPC_HW_DWT_CYCCNT;
#else
    return 0;
#endif
}

static inline void hpc_hw_coeff_end(unsigned int coeff_idx, uint32_t start)
{
#if HPC_HW_ENABLE
    uint32_t delta;

    if ((hpc_hw_available & 0x01u) == 0u) {
        return;
    }

    delta = HPC_HW_DWT_CYCCNT - start;

    hpc_hw_coeff_cycles_sum += delta;

    if (delta < hpc_hw_coeff_cycles_min) {
        hpc_hw_coeff_cycles_min = delta;
    }

    if (delta > hpc_hw_coeff_cycles_max) {
        hpc_hw_coeff_cycles_max = delta;
    }

    if ((int)coeff_idx == ATTACK_TARGET_COEFF) {
        hpc_hw_target_coeff_cycles = delta;
    }
#else
    (void)coeff_idx;
    (void)start;
#endif
}
```

The important value is:

```c
hpc_hw_target_coeff_cycles
```

This stores the measured DWT cycle count for the selected coefficient.

---

## Single-coefficient attack model

The source-level attack skips `+ KYBER_Q / 2` for only one coefficient:

```c
__attribute__((noinline))
static uint16_t hpc_cw_decode_round_faultable(int32_t x, unsigned int coeff_idx)
{
#if ATTACK_DECODER_SKIP_QHALF
    if ((int)coeff_idx == ATTACK_TARGET_COEFF) {
        hpc_cw_fault_skips++;
        return ((x << 1) / KYBER_Q) & 1;
    }
#endif

    return (((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
}
```

With:

```bash
-DATTACK_DECODER_SKIP_QHALF=1
-DATTACK_TARGET_COEFF=0
```

only coefficient `0` is affected. The expected status is:

```text
fault_skips = 1
```

This means the experiment is not skipping all 256 coefficients. It is a single-coefficient DecodeMessage skip model.

---

## Hardware-counter threshold

The defense compares the selected coefficient's cycle count against a compile-time threshold.

Example threshold:

```bash
-DHPC_HW_TARGET_COEFF_CYCLES_MAX=24
```

Detection rule:

```text
if target_coeff_cycles > 24:
    hpc_hw_anomaly |= HPC_HW_ERR_TARGET_CYCLES_HIGH
    decode_error   |= HPC_CW_DECERR_HW_COUNTER
```

The corresponding implementation is:

```c
#if HPC_HW_TARGET_COEFF_CYCLES_MAX
    if (hpc_hw_target_coeff_cycles > HPC_HW_TARGET_COEFF_CYCLES_MAX) {
        hpc_hw_anomaly |= HPC_HW_ERR_TARGET_CYCLES_HIGH;
    }
#endif

if (hpc_hw_anomaly != 0u) {
    hpc_cw_decode_defense_error |= HPC_CW_DECERR_HW_COUNTER;
}
```

The expected hardware-counter detection result is:

```text
decode_error   = 64
hpc_hw_anomaly = 16
```

where:

```text
64 = 0x40 = HPC_CW_DECERR_HW_COUNTER
16 = 0x10 = HPC_HW_ERR_TARGET_CYCLES_HIGH
```

---

## Reading the measured values

The firmware exposes the DWT hardware-counter snapshot through the `Y` SimpleSerial command.

The Python test script reads it with:

```bash
--read-hpc-hw
```

Example output:

```text
[hpc-hw]
  available           : 3
  anomaly             : 0
  decode_cycles       : 15938
  decode_cpi          : 92
  decode_exc          : 0
  decode_lsu          : 77
  decode_fold         : 0
  target_coeff_cycles : 20
  coeff_cycles_min    : 20
  coeff_cycles_max    : 20
  coeff_cycles_sum    : 5120
```

The key field for coefficient-level detection is:

```text
target_coeff_cycles
```

---

## Running the baseline

```bash
cd ~/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_base.sh
```

Expected result:

```text
fault_skips       = 0
decode_error      = 0
hpc_hw_anomaly    = 0
target_ss_match   = 1
host_ss_match     = 1
```

---

## Running the single-coefficient attack

```bash
cd ~/hpc-cw-defense/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs
./run_attack_coeff.sh
```

Expected result:

```text
fault_skips       = 1
decode_error      = 64
hpc_hw_anomaly    = 16
```

---

## Testing another coefficient

To monitor and attack another coefficient:

```bash
TARGET_COEFF=17 ./run_attack_coeff.sh
```

This compiles the firmware with:

```bash
-DATTACK_TARGET_COEFF=17
```

If the cycle distribution changes for another coefficient, recalibrate the threshold:

```bash
HPC_HW_TARGET_COEFF_CYCLES_MAX=26 TARGET_COEFF=17 ./run_attack_coeff.sh
```

---

## Interpretation note

This is a hardware-counter defense against the current source-level single-coefficient decoder-skip model. It uses real Cortex-M DWT hardware counters, but the injected skip itself is still implemented at source level with a conditional branch.

This result should be reported as:

```text
DWT hardware counters detect the implemented single-coefficient source-level decoder-skip model.
```

It should not be overclaimed as proof that DWT counters always detect a physical clock-glitch instruction skip. For a real physical glitch, the cycle direction may differ and the threshold must be recalibrated from measured traces.