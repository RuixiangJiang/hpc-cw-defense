# Number Not Used Once: Dilithium `nonce++` skip-update experiment

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Ravi et al., **“Number Not Used Once”**.

The experiment models the attack as a skipped nonce/domain-separation update:

```c
nonce++;
```

The sampler itself is **not** skipped and is **not** modified. The semantic
effect is that the target sampling call observes the stale `nonce_state` left by
the skipped update.

---

## Experiment scope

This is an SRAM-safe kernel-mode experiment for CWLITEARM/STM32F3.

It does not execute full Dilithium signing or full Dilithium keypair generation,
because the complete Dilithium2/m4f code path allocates large stack objects and
is not reliable on the small STM32F3 SRAM.

Instead, the firmware executes a small deterministic sampling kernel that
captures the nonce/domain-separation behavior relevant to the attack:

```text
for each sampling call:
    update nonce
    run sampler with the resulting nonce
```

The purpose is to test whether the detector can identify a skipped nonce update
without contaminating the target measured window with attack-selection logic.

---

## Files

```text
scripts/Number_Not_Used_Once/
├── exp_env.sh
├── run_base.sh
├── run_attack_nonce.sh
├── run_cycle_stats.sh
├── test_dilithium_nonce_fault.py
└── readme.md

firmware/cw-dilithium-nnuo/
├── Makefile
└── simpleserial-dilithium-nnuo.c

third_party/pqm4/crypto_sign/dilithium2/m4f/
└── ravi_nnuo_nonce_fault.inc
```

The firmware source:

```text
firmware/cw-dilithium-nnuo/simpleserial-dilithium-nnuo.c
```

includes:

```c
#include "params.h"
#include "poly.h"
#include "polyvec.h"

#include "ravi_nnuo_nonce_fault.inc"
```

The Makefile adds the Dilithium2/m4f include directory:

```makefile
DILITHIUM_DIR := $(PQM4_ROOT)/crypto_sign/dilithium2/m4f
EXTRAINCDIRS += $(DILITHIUM_DIR)
```

Therefore this experiment does not require modifying the original pqm4
`sign.c`.

---

## Correct fault model

The target fault is a skipped nonce update.

Baseline target update:

```c
nonce_state++;
```

Faulted target update:

```c
/* nonce_state++ is skipped */
```

The sampler then runs normally:

```c
sampler(out, nonce_state);
```

This is different from directly forcing the sampler to receive a chosen stale
nonce. In this experiment, the stale nonce is a consequence of the skipped
`nonce++` instruction itself.

---

## No target-window pollution

The detector measures the target nonce-update primitive.

Normal measured primitive:

```c
nnuo_nonce_update_normal_measured(&nonce_state);
```

Faulted measured primitive:

```c
nnuo_nonce_update_skip_increment_measured(&nonce_state);
```

The attack-selection logic is outside the measured window:

```c
static uint32_t nnuo_nonce_update_target_measured(uint16_t *nonce_state)
{
    if (nnuo_fault_enable != 0u) {
        return nnuo_nonce_update_skip_increment_measured(nonce_state);
    }

    return nnuo_nonce_update_normal_measured(nonce_state);
}
```

The measured functions themselves do not contain:

```c
if (attack) {
    skip nonce++;
}
```

Therefore `target_update_cycles` measures only the selected nonce-update
primitive, not the simulator dispatch overhead.

---

## Sampling sequence

The kernel uses `L + K` sampling calls.

For Dilithium2:

```text
L = 4
K = 4
L + K = 8
```

The `nonce_state` starts at:

```text
0xffff
```

Each call first performs an update and then uses the resulting nonce.

Baseline sequence:

```text
call 0: nonce++ -> 0
call 1: nonce++ -> 1
call 2: nonce++ -> 2
call 3: nonce++ -> 3
call 4: nonce++ -> 4
call 5: nonce++ -> 5
call 6: nonce++ -> 6
call 7: nonce++ -> 7
```

With:

```bash
TARGET_CALL=4
```

the faulted sequence skips the update immediately before call 4:

```text
call 0: nonce++ -> 0
call 1: nonce++ -> 1
call 2: nonce++ -> 2
call 3: nonce++ -> 3
call 4: skip nonce++ -> 3
call 5: nonce++ -> 4
call 6: nonce++ -> 5
call 7: nonce++ -> 6
```

Thus:

```text
used_nonce_target     = 3
expected_nonce_target = 4
duplicate_call        = 3
```

The skipped update also shifts the suffix nonce sequence by one, so nonce
progression errors appear at calls 4, 5, 6, and 7:

```text
nonce_progress_errors = 4
```

---

## Runtime configuration

Baseline and attack use the same firmware binary.

The SimpleSerial `F` command configures the runtime mode.

Payload:

```text
byte 0 = fault_enable
         0 -> baseline
         1 -> attack

byte 1 = target_call

byte 2 = stale_nonce_arg
         kept for protocol compatibility;
         not used by the skip-update model

byte 3 = reserved
```

For the current skip-update model, the stale nonce is not directly supplied by
the host. It is determined naturally by the live `nonce_state`.

---

## SimpleSerial commands

The firmware supports:

```text
P -> P[1]      ping, returns 0x42
F -> F[8]      configure runtime fault mode
K -> K[1]      initialize kernel state
M -> M[1]      compatibility message upload
S -> S[1]      execute the update-and-sample kernel
H -> H[16]     status
Y -> Y[32]     DWT/HPC snapshot
```

### `H` status fields

```text
byte 0      init_ret
byte 1      kernel_ret
byte 2      check_ret
byte 3      semantic_valid
bytes 4-7   fault_skips
byte 8      fault_enable
byte 9      target_call
byte 10     stale_nonce_arg
byte 11     used_nonce_target
byte 12     defense_error
byte 13     nonce_progress_errors
byte 14     expected_nonce_target
byte 15     duplicate_call
```

`check_ret = 255` means the internal semantic check returned `-1`. This is
expected when the detector catches the attack.

### `Y` DWT/HPC fields

The historical field names in the host script still use `sample`, but after the
skip-update fix these values measure nonce-update primitives.

```text
word 0  available
word 1  anomaly
word 2  region_cycles
word 3  packed DWT event counters
        byte 0 = dwt_cpi
        byte 1 = dwt_exc
        byte 2 = dwt_lsu
        byte 3 = dwt_fold
word 4  target_update_cycles
word 5  update_cycles_min
word 6  update_cycles_max
word 7  update_cycles_sum
```

---

## Run baseline

```bash
cd ~/hpc-cw-defense/scripts/Number_Not_Used_Once
./run_base.sh
```

Expected status:

```text
fault_skips             = 0
fault_enable            = 0
target_call             = 4
used_nonce_target       = 4
expected_nonce_target   = 4
defense_error           = 0
nonce_progress_errors   = 0
duplicate_call          = 255
```

Typical DWT result:

```text
target_update_cycles    = 10
update_cycles_min       = 10
update_cycles_max       = 10
update_cycles_sum       = 80
```

Because the kernel performs 8 update operations:

```text
80 = 10 * 8
```

---

## Run attack

```bash
cd ~/hpc-cw-defense/scripts/Number_Not_Used_Once
TARGET_CALL=4 ./run_attack_nonce.sh
```

Expected status:

```text
fault_skips             = 1
fault_enable            = 1
target_call             = 4
used_nonce_target       = 3
expected_nonce_target   = 4
duplicate_call          = 3
defense_error           = 32
nonce_progress_errors   = 4
```

Typical DWT result:

```text
target_update_cycles    = 9
update_cycles_min       = 9
update_cycles_max       = 10
update_cycles_sum       = 79
```

The sum confirms that exactly one update primitive was faulted:

```text
79 = 10 * 7 + 9
```

---

## Interpretation of the current result

A representative baseline run:

```text
target_update_cycles = 10
update_cycles_sum    = 80
used_nonce_target    = 4
defense_error        = 0
```

A representative attack run:

```text
target_update_cycles = 9
update_cycles_sum    = 79
used_nonce_target    = 3
defense_error        = 32
duplicate_call       = 3
```

This shows that:

```text
1. The target operation is nonce++ itself.
2. The attack skips exactly one nonce update.
3. The sampler still runs normally after the skipped update.
4. The DWT target-update counter detects a cycle deviation.
5. The nonce-progression checker detects the semantic nonce reuse.
```

---

## Detector thresholds

In the current observed setup, the fault-free target update takes:

```text
target_update_cycles = 10
```

The skip-update target takes:

```text
target_update_cycles = 9
```

Therefore a calibrated detector can use:

```bash
NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN=10
NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX=10
```

The variable name still contains `SAMPLE_CYCLES` for compatibility with earlier
scripts, but it now refers to **target nonce-update cycles**.

Run baseline with DWT threshold enabled:

```bash
NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN=10 \
NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX=10 \
./run_base.sh
```

Expected:

```text
anomaly       = 0
defense_error = 0
```

Run attack with DWT threshold enabled:

```bash
NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN=10 \
NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX=10 \
TARGET_CALL=4 \
./run_attack_nonce.sh
```

Expected:

```text
target_update_cycles = 9
anomaly              = 8
defense_error        = 96
```

Bit meanings:

```text
0x08 = 8   = NNUO_HPC_ERR_TARGET_CYCLES_LOW
0x20 = 32  = NNUO_ERR_NONCE_PROGRESS
0x40 = 64  = NNUO_ERR_HW_COUNTER
96 = 32 | 64
```

---

## Repeated calibration

Run repeated baseline measurements:

```bash
TRIALS=20 ./run_base.sh
```

Run repeated attack measurements:

```bash
TRIALS=20 TARGET_CALL=4 ./run_attack_nonce.sh
```

Expected stable relationships:

```text
baseline:
  target_update_cycles = 10
  update_cycles_sum    = 80

attack:
  target_update_cycles = 9
  update_cycles_sum    = 79
  used_nonce_target    = 3
  duplicate_call       = 3
  nonce_progress_errors = 4
```

If the baseline target update is stable at 10 cycles across calibration trials:

```text
mu_R    = 10
sigma_R = 0
```

then for any finite confidence parameter `lambda`:

```text
tau_R^- = 10
tau_R^+ = 10
```

---

## Limitations

This experiment validates a source-level software simulation of a skipped
nonce-update instruction and the corresponding DWT/semantic detectors.

It should not be overclaimed as a direct physical fault-injection result against
full Dilithium signing. A physical clock-glitch, voltage-glitch, or EMFI
experiment should be recalibrated on the actual target and measured around the
real nonce-update instruction sequence.
