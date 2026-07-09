# Krahmer et al., “Correction Fault Attacks on Randomized Dilithium”

This directory contains two ChipWhisperer/Cortex-M software fault-simulation
experiments for Krahmer et al., **“Correction Fault Attacks on Randomized
Dilithium”**:

```text
1. Skipping-correction variant
2. A-fault variant
```

Both experiments are implemented as SRAM-safe semantic kernels. They are not full
randomized Dilithium signing implementations. The goal is to isolate the fault
semantics and measure whether DWT/HPC-style counters can observe them under a
clean target-window design.

The final firmware directory is:

```text
firmware/cw-dilithium-krahmer
```

The host scripts are in:

```text
scripts/Krahmer_Correction_Fault_Attacks
```

---

## Final file layout

```text
firmware/cw-dilithium-krahmer/
├── Makefile
├── simpleserial-dilithium-krahmer.c
└── simpleserial-dilithium-krahmer-afault.c

scripts/Krahmer_Correction_Fault_Attacks/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
├── run_afault_base.sh
├── run_afault_attack.sh
├── test_krahmer_skipcorr.py
├── test_krahmer_afault.py
└── readme.md
```

The two firmware files correspond to:

```text
simpleserial-dilithium-krahmer.c
    Skipping-correction variant.

simpleserial-dilithium-krahmer-afault.c
    Materialized-A corruption variant.
```

---

# Part I — Skipping-Correction Variant

## Attack semantics

The skipping-correction attack removes one local correction operation in a
randomized Dilithium-style signing computation.

The semantic model is:

```text
normal:
    corrected = uncorrected + correction

faulted:
    corrected = uncorrected
```

The target coefficient therefore contains a structured local error:

```text
error = corrected_normal - corrected_faulted
      = correction
```

The coefficient loop itself is not skipped.

---

## Scope

This firmware is an SRAM-safe local-correction semantic kernel.

It does not claim to be a full randomized Dilithium signing implementation.
Instead, it isolates the local correction operation targeted by the
skipping-correction attack.

The attack logic being modeled is:

```text
normal prefix coefficients
one target coefficient where the correction term is omitted
normal suffix coefficients
```

The rest of the coefficient loop remains unchanged.

---

## Lightweight Dilithium-style correction

The final version avoids C's `% Q` operator.

An earlier draft used an `int64_t % Q` helper, which caused an artificial cycle
gap because 64-bit modulo is expensive on Cortex-M. That does not match the
style of Dilithium reference arithmetic.

The final version uses reference-Dilithium-style lightweight helpers:

```c
static inline int32_t krahmer_reduce32_refstyle(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * (int32_t)Q;

    return t;
}

static inline int32_t krahmer_caddq_refstyle(int32_t a)
{
    a += (a >> 31) & (int32_t)Q;
    return a;
}

static inline int32_t krahmer_freeze_refstyle(int32_t a)
{
    a = krahmer_reduce32_refstyle(a);
    a = krahmer_caddq_refstyle(a);
    return a;
}
```

The normal correction primitive is:

```c
corrected = krahmer_freeze_refstyle(uncorrected + correction);
*out = corrected;
```

The faulted correction primitive is:

```c
*out = uncorrected;
```

This better represents a lightweight local correction operation instead of an
artificially expensive modulo operation.

---

## Prefix-target-suffix structure

The target is one coefficient inside a correction loop.

The default target coefficient is:

```text
TARGET_COEFF = 17
```

The loop is split into:

```text
for i < TARGET_COEFF:
    normal correction

i == TARGET_COEFF:
    selected target correction primitive

for i > TARGET_COEFF:
    normal correction
```

This prevents the experiment from accidentally modeling a loop skip or phase
skip.

---

## No target-window pollution

Runtime dispatch is outside the measured correction primitive.

Dispatcher:

```c
static uint32_t krahmer_target_correction_apply(unsigned int model,
                                                int32_t uncorrected,
                                                int32_t correction,
                                                int32_t *out)
{
    if (model == KRAHMER_MODEL_SKIP) {
        return krahmer_correction_skip_measured(uncorrected, correction, out);
    }

    return krahmer_correction_normal_measured(uncorrected, correction, out);
}
```

The measured primitives themselves are separate:

```text
krahmer_correction_normal_measured(...)
krahmer_correction_skip_measured(...)
```

Therefore the measured target primitive does not contain:

```c
if (attack) {
    skip correction;
}
```

The target window contains either the normal correction primitive or the faulted
correction primitive, not simulator-side branch logic.

---

## Runtime configuration

The `F` command configures the skipping-correction experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> skip-correction

bytes 1-2   target coefficient index, little endian

bytes 3-6   message_tweak, little endian

bytes 7-15  reserved
```

Default values:

```text
TARGET_COEFF  = 17
MESSAGE_TWEAK = 0
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[16]     configure correction fault model
K -> K[1]      initialize synthetic coefficient state
S -> S[1]      run the correction loop
H -> H[32]     semantic status
D -> D[16]     digest status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
bytes 1-2   target_coeff
byte 3      semantic_valid

bytes 4-7   faults_applied

bytes 8-11  target_uncorrected
bytes 12-15 target_correction
bytes 16-19 target_expected
bytes 20-23 target_used
bytes 24-27 target_error

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

For a correct skipping-correction simulation:

```text
baseline:
    target_used  = target_expected
    target_error = 0

attack:
    target_used  = target_uncorrected
    target_error = target_correction
```

---

## `D` digest fields

```text
bytes 0-3    output_digest
bytes 4-7    reference_digest
bytes 8-11   output_diff
bytes 12-15  message_tweak
```

For baseline:

```text
output_diff = 0
```

For attack:

```text
output_diff != 0
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

---

## Build and run: skipping-correction

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Krahmer_Correction_Fault_Attacks
./run_base.sh
```

Run attack:

```bash
TARGET_COEFF=17 ./run_attack.sh
```

Other examples:

```bash
TARGET_COEFF=0 ./run_attack.sh
TARGET_COEFF=100 ./run_attack.sh
MESSAGE_TWEAK=1 TARGET_COEFF=17 ./run_attack.sh
```

---

## Representative result: skipping-correction baseline

Configuration:

```text
MODEL         = none
TARGET_COEFF  = 17
MESSAGE_TWEAK = 0
```

Semantic result:

```text
model                   : 0
model_name              : none
target_coeff            : 17
semantic_valid          : 1
faults_applied          : 0
target_uncorrected      : 20910
target_correction       : 131
target_expected         : 21041
target_used             : 21041
target_error            : 0
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Digest result:

```text
output_digest           : 2185840552
reference_digest        : 2185840552
output_diff             : 0
message_tweak           : 0
```

DWT/HPC result:

```text
available               : 3
anomaly                 : 0
region_cycles           : 14368
dwt_cpi                 : 241
dwt_exc                 : 0
dwt_lsu                 : 18
dwt_fold                : 0
target_cycles           : 10
cycles_min              : 10
cycles_max              : 10
cycles_sum              : 2560
```

Interpretation:

```text
target_used = target_expected = 21041
target_error = 0
output_diff = 0
```

The target coefficient is corrected normally.

---

## Representative result: skipping-correction attack

Configuration:

```text
MODEL         = skip
TARGET_COEFF  = 17
MESSAGE_TWEAK = 0
```

Semantic result:

```text
model                   : 1
model_name              : skip
target_coeff            : 17
semantic_valid          : 1
faults_applied          : 1
target_uncorrected      : 20910
target_correction       : 131
target_expected         : 21041
target_used             : 20910
target_error            : 131
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Digest result:

```text
output_digest           : 2890749955
reference_digest        : 2185840552
output_diff             : 772022187
message_tweak           : 0
```

DWT/HPC result:

```text
available               : 3
anomaly                 : 0
region_cycles           : 14363
dwt_cpi                 : 242
dwt_exc                 : 0
dwt_lsu                 : 18
dwt_fold                : 0
target_cycles           : 10
cycles_min              : 10
cycles_max              : 10
cycles_sum              : 2560
```

Interpretation:

```text
target_uncorrected = 20910
target_correction  = 131
target_expected    = 21041
target_used        = 20910
target_error       = 131
```

The target coefficient omits the correction term:

```text
faulted = uncorrected
        = 20910
```

The structured error equals the omitted correction term:

```text
target_error = target_expected - target_used
             = 21041 - 20910
             = 131
```

The digest changes:

```text
output_diff != 0
```

The cycle count does not change:

```text
baseline target_cycles = 10
attack   target_cycles = 10
```

---

## Summary: skipping-correction

```text
Mode      Faults  Uncorrected  Correction  Expected  Used   Error  Output diff  Target cycles
baseline  0       20910        131         21041     21041  0      0            10
attack    1       20910        131         21041     20910  131    772022187    10
```

The semantic difference is clear, but the measured target-cycle count is
identical under the lightweight correction implementation.

---

## Detector interpretation: skipping-correction

This variant is a local correction fault.

It does not skip the coefficient loop and does not remove the whole signing
phase. It only omits the local correction term for the target coefficient.

With the reference-style lightweight correction kernel, a cycle-only DWT/HPC
detector is weak:

```text
baseline target_cycles = 10
attack   target_cycles = 10
```

The semantic output changes, but the measured target-cycle count does not.

More appropriate defenses include:

```text
redundant correction computation
duplicate coefficient correction and compare
randomized-signature consistency checks
post-signing verification adapted to randomized signing
range and norm checks on corrected coefficients
structured-error detection in the corrected vector
```

---

# Part II — A-Fault Variant

## Attack semantics

The A-fault variant corrupts the signing-time matrix `A` or its expansion.

The final simulation follows the strict materialized-A corruption model:

```text
A is generated normally.
A is materialized in memory.
A is corrupted after materialization.
The signing-time computation consumes the corrupted A through the normal path.
```

The fault is a data corruption fault, not a control-flow skip.

---

## Scope

This firmware is an SRAM-safe semantic kernel for the A-fault variant.

It does not claim to be a full randomized Dilithium signing implementation.
Instead, it isolates the target data object:

```text
materialized signing-time matrix A
```

and the downstream computation that consumes it:

```text
normal matrix-vector consumption
```

The experiment deliberately avoids modeling the attack as:

```text
skipping A expansion
replacing A expansion with a cheaper primitive
skipping matrix multiplication
skipping the signing phase
```

---

## A-fault models

The firmware supports five runtime modes:

```text
model = 0  none / baseline
model = 1  entry fault
model = 2  block fault
model = 3  row fault
model = 4  column fault
```

The host script accepts:

```text
none
entry
block
row
col
```

### Baseline

`A` is generated normally and consumed normally:

```text
A_normal -> normal matrix-vector consumption
```

### Entry fault

One coefficient of one materialized block is corrupted:

```text
A[row][col][coeff] = fault_value
```

Example:

```text
A[0][0][17] : 1260973 -> 0
```

### Block fault

One materialized block is corrupted:

```text
A[row][col][:] = fault_value
```

Example:

```text
A[0][0][:] = 0
```

### Row fault

All materialized blocks in one row are corrupted:

```text
A[row][0][:] = fault_value
A[row][1][:] = fault_value
...
A[row][L-1][:] = fault_value
```

For Dilithium2:

```text
L = 4
```

so the row fault applies to 4 blocks.

### Column fault

All materialized blocks in one column are corrupted:

```text
A[0][col][:] = fault_value
A[1][col][:] = fault_value
...
A[K-1][col][:] = fault_value
```

For Dilithium2:

```text
K = 4
```

so the column fault applies to 4 blocks.

---

## Strict materialized-A simulation

The final version uses the strict materialized-A model.

The target experiment structure is:

```text
1. Generate/materialize A normally.

2. Record the expected target entry and expected block digest.

3. Corrupt materialized A according to the selected model.

4. Record the used target entry and used block digest.

5. Start trigger and DWT/HPC measurement.

6. Run normal matrix-vector consumption of the possibly corrupted A.

7. Stop DWT/HPC measurement and trigger.
```

The corruption happens before the measured target window.

The measured target window contains only:

```text
normal matrix-vector consumption
```

It does not contain:

```text
A generation
A corruption
fault-model dispatch
if attack then corrupt A
```

---

## Clean target window

The clean target-window structure is:

```text
normal materialize A
↓
corrupt materialized A, if enabled
↓
trigger_high()
DWT/HPC begin
normal matrix-vector consumption
DWT/HPC end
trigger_low()
```

The external ChipWhisperer trigger and DWT/HPC window both cover only the normal
consumption path.

The core structure is:

```c
krahmer_a_generate_matrix_materialized_normal();

krahmer_a_expected_entry = krahmer_A[row][col][coeff];
krahmer_a_expected_block_digest = krahmer_a_digest_normal_block(row, col);
krahmer_a_reference_digest = krahmer_a_compute_reference_digest();

krahmer_a_corrupt_materialized_A_unmeasured();

krahmer_a_used_entry = krahmer_A[row][col][coeff];
krahmer_a_used_block_digest = krahmer_a_digest_block(krahmer_A[row][col]);

trigger_high();
krahmer_a_hpc_region_begin();
start = krahmer_a_hpc_op_begin();

krahmer_a_consume_matrix_normal();

krahmer_a_hpc_target_cycles = krahmer_a_hpc_op_end_common(start);
krahmer_a_hpc_region_end();
trigger_low();
```

---

## Runtime configuration: A-fault

The `F` command configures the A-fault experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> entry
            2 -> block
            3 -> row
            4 -> col

byte 1      target row

byte 2      target column

bytes 3-4   target coefficient, little endian

bytes 5-8   fault_value, little endian

bytes 9-12  message_tweak, little endian

bytes 13-15 reserved
```

Default values:

```text
TARGET_ROW    = 0
TARGET_COL    = 0
TARGET_COEFF  = 17
FAULT_VALUE   = 0
MESSAGE_TWEAK = 0
```

For Dilithium2:

```text
K = 4
L = 4
N = 256
Q = 8380417
```

---

## SimpleSerial commands: A-fault

```text
P -> P[1]      ping, returns 0x42
F -> F[24]     configure A-fault model
K -> K[1]      initialize synthetic state
S -> S[1]      run materialized-A experiment
H -> H[32]     semantic status
D -> D[16]     digest status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields: A-fault

```text
byte 0      model
byte 1      target_row
byte 2      target_col
byte 3      semantic_valid

bytes 4-7   faults_applied

bytes 8-11  target_coeff

bytes 12-15 expected_entry
bytes 16-19 used_entry

bytes 20-23 expected_block_digest
bytes 24-27 used_block_digest

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

For a successful A-fault simulation:

```text
baseline:
    expected_entry == used_entry
    expected_block_digest == used_block_digest

attack:
    expected_block_digest != used_block_digest
```

For row and column faults, the displayed block digest is for the selected
`target_row, target_col` block.

---

## `D` digest fields: A-fault

```text
bytes 0-3    output_digest
bytes 4-7    reference_digest
bytes 8-11   output_diff
bytes 12-15  message_tweak
```

For baseline:

```text
output_diff = 0
```

For attacks:

```text
output_diff != 0
```

---

## `Y` DWT/HPC fields: A-fault

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

In the final materialized-A model, there is one measured target operation:

```text
normal matrix-vector consumption
```

Therefore:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

The expected result is that baseline and attack cycles are equal or nearly equal,
because the same normal consumption path executes in every mode.

---

## Build and run: A-fault

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Krahmer_Correction_Fault_Attacks
./run_afault_base.sh
```

Run entry fault:

```bash
MODEL=entry TARGET_ROW=0 TARGET_COL=0 TARGET_COEFF=17 FAULT_VALUE=0 ./run_afault_attack.sh
```

Run block fault:

```bash
MODEL=block TARGET_ROW=0 TARGET_COL=0 FAULT_VALUE=0 ./run_afault_attack.sh
```

Run row fault:

```bash
MODEL=row TARGET_ROW=0 FAULT_VALUE=0 ./run_afault_attack.sh
```

Run column fault:

```bash
MODEL=col TARGET_COL=0 FAULT_VALUE=0 ./run_afault_attack.sh
```

---

## Representative result: A-fault baseline

Configuration:

```text
MODEL        = none
TARGET_ROW   = 0
TARGET_COL   = 0
TARGET_COEFF = 17
FAULT_VALUE  = 0
```

Semantic result:

```text
model                   : 0
model_name              : none
target_row              : 0
target_col              : 0
semantic_valid          : 1
faults_applied          : 0
target_coeff            : 17
expected_entry          : 1260973
used_entry              : 1260973
expected_block_digest   : 3352514287
used_block_digest       : 3352514287
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Digest result:

```text
output_digest           : 2685163531
reference_digest        : 2685163531
output_diff             : 0
message_tweak           : 0
```

DWT/HPC result:

```text
available               : 3
anomaly                 : 0
region_cycles           : 41091
dwt_cpi                 : 11
dwt_exc                 : 0
dwt_lsu                 : 53
dwt_fold                : 2
target_cycles           : 41066
cycles_min              : 41066
cycles_max              : 41066
cycles_sum              : 41066
```

Interpretation:

```text
A[0][0][17] is unchanged.
The selected A block is unchanged.
The output matches the clean reference.
The normal matrix-consumption target window costs 41066 cycles.
```

---

## Representative result: A-fault entry attack

Configuration:

```text
MODEL        = entry
TARGET_ROW   = 0
TARGET_COL   = 0
TARGET_COEFF = 17
FAULT_VALUE  = 0
```

Semantic result:

```text
model                   : 1
model_name              : entry
target_row              : 0
target_col              : 0
semantic_valid          : 1
faults_applied          : 1
target_coeff            : 17
expected_entry          : 1260973
used_entry              : 0
expected_block_digest   : 3352514287
used_block_digest       : 4277323199
defense_error           : 0
hpc_anomaly_byte        : 0
entries                 : 1
exits                   : 1
```

Digest result:

```text
output_digest           : 3626322673
reference_digest        : 2685163531
output_diff             : 2015957754
message_tweak           : 0
```

DWT/HPC result:

```text
target_cycles           : 41066
cycles_min              : 41066
cycles_max              : 41066
cycles_sum              : 41066
```

Interpretation:

```text
A[0][0][17] changes from 1260973 to 0.
The target block digest changes.
The output digest changes.
The measured normal consumption cost is unchanged.
```

---

## Representative result: A-fault block attack

Configuration:

```text
MODEL        = block
TARGET_ROW   = 0
TARGET_COL   = 0
FAULT_VALUE  = 0
```

Semantic result:

```text
model                   : 2
model_name              : block
target_row              : 0
target_col              : 0
semantic_valid          : 1
faults_applied          : 1
target_coeff            : 17
expected_entry          : 1260973
used_entry              : 0
expected_block_digest   : 3352514287
used_block_digest       : 1299645893
```

Digest result:

```text
output_digest           : 2018536522
reference_digest        : 2685163531
output_diff             : 3629921345
```

DWT/HPC result:

```text
target_cycles           : 41066
cycles_min              : 41066
cycles_max              : 41066
cycles_sum              : 41066
```

Interpretation:

```text
The selected materialized A block is corrupted to a zero block.
The downstream output changes.
The normal matrix-consumption target window remains unchanged.
```

---

## Representative result: A-fault row attack

Configuration:

```text
MODEL       = row
TARGET_ROW  = 0
FAULT_VALUE = 0
```

Semantic result:

```text
model                   : 3
model_name              : row
target_row              : 0
target_col              : 0
semantic_valid          : 1
faults_applied          : 4
target_coeff            : 17
expected_entry          : 1260973
used_entry              : 0
expected_block_digest   : 3352514287
used_block_digest       : 1299645893
```

Digest result:

```text
output_digest           : 1576211275
reference_digest        : 2685163531
output_diff             : 4261366592
```

DWT/HPC result:

```text
target_cycles           : 41066
cycles_min              : 41066
cycles_max              : 41066
cycles_sum              : 41066
```

Interpretation:

```text
The target row contains L = 4 corrupted blocks.
The downstream output changes.
The normal matrix-consumption target window remains unchanged.
```

---

## Representative result: A-fault column attack

Configuration:

```text
MODEL       = col
TARGET_COL  = 0
FAULT_VALUE = 0
```

Semantic result:

```text
model                   : 4
model_name              : col
target_row              : 0
target_col              : 0
semantic_valid          : 1
faults_applied          : 4
target_coeff            : 17
expected_entry          : 1260973
used_entry              : 0
expected_block_digest   : 3352514287
used_block_digest       : 1299645893
```

Digest result:

```text
output_digest           : 3205767900
reference_digest        : 2685163531
output_diff             : 521698007
```

DWT/HPC result:

```text
target_cycles           : 41066
cycles_min              : 41066
cycles_max              : 41066
cycles_sum              : 41066
```

Interpretation:

```text
The target column contains K = 4 corrupted blocks.
The downstream output changes.
The normal matrix-consumption target window remains unchanged.
```

---

## Summary: A-fault

```text
Mode      Faults  Entry expected  Entry used  Block changed  Output diff   Target cycles
baseline  0       1260973         1260973     no             0             41066
entry     1       1260973         0           yes            2015957754    41066
block     1       1260973         0           yes            3629921345    41066
row       4       1260973         0           yes            4261366592    41066
col       4       1260973         0           yes            521698007     41066
```

The semantic output changes in all attack modes, but the measured target-window
cycle count stays unchanged.

---

## Detector interpretation: A-fault

This A-fault model is a data-corruption fault on materialized matrix `A`.

It does not alter the measured signing-time control flow.

Under the strict materialized-A model:

```text
baseline target_cycles = 41066
attack   target_cycles = 41066
```

Therefore, cycle-only DWT/HPC detection is weak for this variant.

The attack changes the data consumed by signing, not the sequence of instructions
in the signing-time consumption path.

More appropriate defenses include:

```text
A block digest or checksum before consumption
seed-to-A recomputation check
redundant A expansion and compare
row/column integrity checks
matrix-vector recomputation with comparison
consistency checks between A, randomness, and signature output
```

For entry faults, cycle-only detection is especially weak because the normal
consumption path is identical and only one data value changes.

For block, row, and column faults, cycle-only detection should also not be relied
on if the corruption occurs after materialization, because the same matrix-vector
code still runs.

---

# Combined detector conclusion

Both variants are semantically observable but weak for pure cycle-threshold
detection under the final clean-window implementations.

```text
Variant                 Semantic effect                         Cycle signal
skipping-correction     local correction term omitted            weak / none
A-fault                 materialized A data corrupted            weak / none
```

The common reason is:

```text
the target computation still follows the normal control flow
```

The attacks change data, not the measured instruction sequence.

Better detector directions include:

```text
redundant computation
local correction consistency check
A integrity check
seed-to-A recomputation check
post-signature consistency verification
range/norm checks on corrected values
structured-error detection
```

---

# Limitations

These are software-level semantic simulations.

They validate the intended attack semantics:

```text
skipping-correction:
    one target coefficient omits a local correction term

A-fault:
    A is materialized normally, corrupted in memory, and consumed normally
```

They are not physical EMFI, voltage-glitch, clock-glitch, or Rowhammer
demonstrations.

They are not full randomized Dilithium signing implementations.

A full implementation would require hooking the actual correction operation and
the actual materialized `A` or A-expansion path inside randomized Dilithium while
preserving the same semantic rules:

```text
do not skip the surrounding loop unless that is the actual attacked operation
do not skip the signing phase
do not add simulator-side branches inside the measured target primitive
```
