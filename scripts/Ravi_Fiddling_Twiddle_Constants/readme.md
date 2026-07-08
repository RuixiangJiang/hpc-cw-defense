# Ravi et al., “Fiddling the Twiddle Constants”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Ravi et al., **“Fiddling the Twiddle Constants”**.

The simulated fault is a **data corruption fault** on the twiddle information
used by an NTT butterfly.

It is **not** an NTT-layer skip and not a butterfly-loop skip.

The semantic model is:

```text
the target butterfly consumes an incorrect twiddle value
```

In the default experiment, the incorrect twiddle is zero:

```text
expected twiddle = 50838
used twiddle     = 0
```

The surrounding NTT layer still executes normally:

```text
normal prefix butterflies
one faulty target butterfly
normal suffix butterflies
```

---

## Important scope note

This firmware is an SRAM-safe NTT-layer semantic kernel.

It does not claim to be the full Dilithium NTT implementation from pqm4. Instead,
it isolates the fault object needed for the attack:

```text
twiddle pointer / twiddle load
↓
target NTT butterfly
↓
downstream NTT-layer state
```

This is intentional because the purpose of this experiment is to distinguish
twiddle-data corruption from control-flow removal.

The experiment should therefore be interpreted as:

```text
a controlled twiddle-corruption simulation for one target butterfly inside an
NTT-like layer
```

rather than a complete physical reproduction of the full Dilithium NTT routine.

---

## Files

```text
firmware/cw-dilithium-fiddling-twiddle/
├── Makefile
└── simpleserial-dilithium-fiddling.c

scripts/Ravi_Fiddling_Twiddle_Constants/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_fiddling_twiddle.py
```

The experiment does not modify the original pqm4 Dilithium source files.

---

## Fault models

The firmware supports three runtime modes:

```text
model = 0  none / baseline
model = 1  pointer-corruption
model = 2  value-corruption
```

The host script accepts:

```text
none
ptr
value
```

### Baseline

The target butterfly loads and consumes the correct twiddle:

```text
zeta = *normal_twiddle_pointer
```

### Pointer-corruption model

The twiddle pointer is redirected to a wrong address before the target butterfly
loads the twiddle:

```text
zeta = *wrong_twiddle_pointer
```

In the default attack configuration:

```text
WRONG_INDEX = 0
```

the wrong pointer resolves to a zero twiddle.

This models corruption of the pointer used by the NTT code to load twiddle
constants.

### Value-corruption model

The target butterfly first loads the normal twiddle, but the loaded value is
corrupted immediately before the butterfly consumes it:

```text
zeta = *normal_twiddle_pointer
zeta = FAULT_VALUE
```

In the default attack configuration:

```text
FAULT_VALUE = 0
```

the target butterfly consumes a zero twiddle.

This models corruption of the loaded twiddle value rather than corruption of the
pointer itself.

---

## NTT-like butterfly

The target computation uses a compact NTT-like butterfly:

```c
t = zeta * b;
a = a + t;
b = a_old - t;
```

In the firmware:

```c
static inline void fiddling_butterfly_unmeasured(int32_t *a,
                                                 int32_t *b,
                                                 int32_t zeta)
{
    int32_t x = *a;
    int32_t y = *b;
    int32_t t = fiddling_mul_mod(zeta, y);

    *a = fiddling_reduce_q((int64_t)x + (int64_t)t);
    *b = fiddling_reduce_q((int64_t)x - (int64_t)t);
}
```

The important property is that the butterfly itself still executes normally.
Only the twiddle data consumed by the butterfly is faulty.

---

## Prefix-target-suffix structure

The target is one butterfly inside an NTT layer.

The layer length is:

```text
FIDDLING_LAYER_LEN = 64
```

The default target butterfly is:

```text
TARGET_J = 17
```

The loop is split into:

```text
for j < TARGET_J:
    normal butterfly

j == TARGET_J:
    selected twiddle fault model

for j > TARGET_J:
    normal butterfly
```

This prevents accidentally modeling the attack as a skipped NTT layer or skipped
loop.

The structure is:

```c
for (j = 0; j < target; j++) {
    normal butterfly;
}

target butterfly with selected twiddle model;

for (j = target + 1; j < len; j++) {
    normal butterfly;
}
```

---

## No target-window pollution

The runtime model dispatch is outside the measured target primitive.

Dispatcher:

```c
static uint32_t fiddling_target_butterfly_apply(unsigned int model,
                                                int32_t *a,
                                                int32_t *b,
                                                const int32_t *normal_ptr,
                                                const int32_t *wrong_ptr,
                                                int32_t faulty_value)
{
    if (model == FIDDLING_MODEL_PTR) {
        return fiddling_butterfly_ptr_fault_measured(a, b, wrong_ptr);
    }

    if (model == FIDDLING_MODEL_VALUE) {
        return fiddling_butterfly_value_fault_measured(a, b, normal_ptr,
                                                       faulty_value);
    }

    return fiddling_butterfly_normal_measured(a, b, normal_ptr);
}
```

Each measured target primitive contains only the corresponding operation:

```text
normal target butterfly
target butterfly with redirected pointer
target butterfly with corrupted loaded value
```

The measured target primitive does not contain:

```c
if (attack) {
    corrupt twiddle;
}
```

Therefore the measured target window is not polluted by simulator-side attack
selection logic.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> pointer-corruption
            2 -> value-corruption

bytes 1-2   target butterfly index, little endian

bytes 3-4   normal twiddle index, little endian

bytes 5-6   wrong twiddle index, little endian

bytes 7-10  faulty value, little endian

bytes 11-15 reserved
```

Default values:

```text
TARGET_J      = 17
TWIDDLE_INDEX = 29
WRONG_INDEX   = 0
FAULT_VALUE   = 0
```

The normal twiddle is generated deterministically by the firmware:

```text
twiddles[i] = (i * 1753 + 1) mod Q
```

So:

```text
twiddles[29] = 50838
```

The default pointer-corruption and value-corruption attacks both make the target
butterfly consume:

```text
zeta = 0
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[24]     configure twiddle fault model
K -> K[1]      initialize polynomial and twiddle state
S -> S[1]      run the NTT-like layer
H -> H[32]     semantic status
T -> T[32]     target-butterfly status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
bytes 1-2   target_j
byte 3      semantic_valid

bytes 4-7   faults_applied

bytes 8-11  expected_twiddle
bytes 12-15 used_twiddle

bytes 16-19 output_digest
bytes 20-23 baseline_digest
bytes 24-27 output_diff

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

Important fields:

```text
expected_twiddle
    The twiddle that the target butterfly should consume in the baseline run.

used_twiddle
    The twiddle actually consumed by the target butterfly.

output_digest
    Digest of the final polynomial state after the tested layer.

baseline_digest
    Digest of a reference layer run with no twiddle fault.

output_diff
    output_digest XOR baseline_digest.

faults_applied
    0 in baseline and 1 in attack runs.
```

A successful zero-twiddle attack should show:

```text
expected_twiddle != 0
used_twiddle     = 0
output_diff      != 0
```

---

## `T` target-butterfly status fields

```text
bytes 0-3    target_before_a
bytes 4-7    target_before_b
bytes 8-11   target_after_a
bytes 12-15  target_after_b

bytes 16-19  twiddle_index
bytes 20-23  wrong_index
bytes 24-27  fault_value
bytes 28-31  layer_len
```

For the default target:

```text
target_before_a = 20910
target_before_b = 99566
```

If the target butterfly consumes `zeta = 0`, then:

```text
t  = zeta * b = 0
a' = a + t = a
b' = a - t = a
```

Therefore the expected target output is:

```text
target_after_a = 20910
target_after_b = 20910
```

---

## `Y` DWT/HPC fields

```text
word 0  available
word 1  anomaly
word 2  region_cycles
word 3  packed DWT event counters
        byte 0 = dwt_cpi
        byte 1 = dwt_exc
        byte 2 = dwt_lsu
        byte 3 = dwt_fold
word 4  target_cycles
word 5  cycles_min
word 6  cycles_max
word 7  cycles_sum
```

`target_cycles` is the measured cycle count of the target butterfly.

`cycles_min`, `cycles_max`, and `cycles_sum` are measured over all butterflies in
the layer.

Because the arithmetic uses data-dependent C operations such as modular
reduction, a few cycles of variation can appear even in the baseline.

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_ravi_fiddling_twiddle_impl.sh
```

If you already applied the initial script and need the fixed `used_twiddle`
reporting version, replace the firmware file with:

```bash
cp /mnt/data/simpleserial-dilithium-fiddling.c \
  ~/hpc-cw-defense/firmware/cw-dilithium-fiddling-twiddle/simpleserial-dilithium-fiddling.c
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Ravi_Fiddling_Twiddle_Constants
./run_base.sh
```

Run pointer-corruption attack:

```bash
MODEL=ptr TARGET_J=17 TWIDDLE_INDEX=29 WRONG_INDEX=0 ./run_attack.sh
```

Run value-corruption attack:

```bash
MODEL=value TARGET_J=17 TWIDDLE_INDEX=29 FAULT_VALUE=0 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL         = none
TARGET_J      = 17
TWIDDLE_INDEX = 29
```

Result:

```text
model                   : 0
model_name              : none
target_j                : 17
semantic_valid          : 1
faults_applied          : 0
expected_twiddle        : 50838
used_twiddle            : 50838
output_digest           : 2049670354
baseline_digest         : 2049670354
output_diff             : 0
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Target status:

```text
target_before_a         : 20910
target_before_b         : 99566
target_after_a          : 8365767
target_after_b          : 56470
twiddle_index           : 29
wrong_index             : 0
fault_value             : 0
layer_len               : 64
```

DWT/HPC status:

```text
available               : 3
anomaly                 : 0
region_cycles           : 26694
dwt_cpi                 : 128
dwt_exc                 : 0
dwt_lsu                 : 163
dwt_fold                : 128
target_cycles           : 360
cycles_min              : 356
cycles_max              : 360
cycles_sum              : 22910
```

Interpretation:

```text
expected_twiddle = used_twiddle = 50838
output_diff = 0
```

The target butterfly consumes the correct twiddle and the output matches the
reference layer.

The small baseline cycle range:

```text
cycles_min = 356
cycles_max = 360
```

is expected in this kernel because the arithmetic and reduction path can vary
slightly with data.

---

## Representative result: pointer-corruption attack

Configuration:

```text
MODEL         = ptr
TARGET_J      = 17
TWIDDLE_INDEX = 29
WRONG_INDEX   = 0
```

Result:

```text
model                   : 1
model_name              : ptr
target_j                : 17
semantic_valid          : 1
faults_applied          : 1
expected_twiddle        : 50838
used_twiddle            : 0
output_digest           : 2219749226
baseline_digest         : 2049670354
output_diff             : 4268086200
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Target status:

```text
target_before_a         : 20910
target_before_b         : 99566
target_after_a          : 20910
target_after_b          : 20910
twiddle_index           : 29
wrong_index             : 0
fault_value             : 0
layer_len               : 64
```

DWT/HPC status:

```text
available               : 3
anomaly                 : 0
region_cycles           : 26677
dwt_cpi                 : 118
dwt_exc                 : 0
dwt_lsu                 : 164
dwt_fold                : 128
target_cycles           : 340
cycles_min              : 340
cycles_max              : 360
cycles_sum              : 22890
```

Interpretation:

```text
expected_twiddle = 50838
used_twiddle     = 0
output_diff      != 0
```

The target butterfly consumes a zero twiddle because the pointer is redirected to
the wrong twiddle address.

The target output:

```text
target_after_a = 20910
target_after_b = 20910
```

matches the zero-twiddle butterfly equation.

---

## Representative result: value-corruption attack

Configuration:

```text
MODEL         = value
TARGET_J      = 17
TWIDDLE_INDEX = 29
FAULT_VALUE   = 0
```

Result:

```text
model                   : 2
model_name              : value
target_j                : 17
semantic_valid          : 1
faults_applied          : 1
expected_twiddle        : 50838
used_twiddle            : 0
output_digest           : 2219749226
baseline_digest         : 2049670354
output_diff             : 4268086200
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Target status:

```text
target_before_a         : 20910
target_before_b         : 99566
target_after_a          : 20910
target_after_b          : 20910
twiddle_index           : 29
wrong_index             : 0
fault_value             : 0
layer_len               : 64
```

DWT/HPC status:

```text
available               : 3
anomaly                 : 0
region_cycles           : 26679
dwt_cpi                 : 119
dwt_exc                 : 0
dwt_lsu                 : 164
dwt_fold                : 128
target_cycles           : 340
cycles_min              : 340
cycles_max              : 360
cycles_sum              : 22890
```

Interpretation:

```text
expected_twiddle = 50838
used_twiddle     = 0
output_diff      != 0
```

The target butterfly first loads the normal twiddle, but the loaded value is
replaced by zero immediately before the butterfly uses it.

Because both pointer-corruption and value-corruption are configured to produce
the same final consumed twiddle value, their semantic outputs match.

---

## Summary table

```text
Mode    Expected twiddle  Used twiddle  Faults  Output diff  Target cycles  Sum cycles
none    50838             50838         0       0            360            22910
ptr     50838             0             1       4268086200   340            22890
value   50838             0             1       4268086200   340            22890
```

The cycle difference is localized to the target butterfly:

```text
baseline cycles_sum - attack cycles_sum = 22910 - 22890 = 20
baseline target_cycles - attack target_cycles = 360 - 340 = 20
```

This confirms that only the target butterfly changed. The prefix and suffix
butterflies still executed normally.

---

## Detector interpretation

This attack is a twiddle-data corruption attack, not a control-flow skip.

In this semantic kernel, the zero-twiddle fault also produces a target-cycle
difference:

```text
baseline target_cycles = 360
attack   target_cycles = 340
```

However, this timing difference is implementation-dependent. It comes from the
arithmetic data path when `zeta = 0`, especially multiplication and modular
reduction. A more constant-time NTT arithmetic implementation may reduce or hide
this signal.

Therefore, a cycle-only detector should not be considered robust for this fault
model.

More appropriate defenses include:

```text
twiddle-table integrity checks
twiddle-pointer range checks
twiddle-pointer duplication
constant-location twiddle validation
redundant NTT computation
inverse-NTT / NTT consistency checks
range checks on NTT intermediate states
```

A strong detector should distinguish:

```text
control-flow anomaly
```

from:

```text
normal control flow with corrupted twiddle data
```

This experiment demonstrates the second case.

---

## Limitations

This is a software-level semantic simulation of the twiddle-pointer and
twiddle-load corruption described by the attack.

It validates:

```text
wrong twiddle consumed by target butterfly
NTT layer not skipped
prefix-target-suffix structure
changed NTT-layer output
DWT/HPC observability of the target arithmetic change
```

It is not a physical EMFI, clock-glitch, voltage-glitch, or Rowhammer
demonstration.

It is also not the full pqm4 Dilithium NTT implementation. A full implementation
would require hooking the actual target twiddle load inside the real NTT routine
while preserving the same semantic rule:

```text
corrupt twiddle data before butterfly consumption
do not skip the NTT layer
do not skip the butterfly loop
```
