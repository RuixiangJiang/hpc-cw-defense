# Krahmer et al., “Correction Fault Attacks on Randomized Dilithium” — Skipping-Correction Variant

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Krahmer et al., **“Correction Fault Attacks on Randomized
Dilithium”**, focusing on the **skipping-correction variant**.

The simulated fault removes one local correction operation in a randomized
Dilithium-style signing computation.

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

## Important scope note

This firmware is an SRAM-safe local-correction semantic kernel.

It does not claim to be a full randomized Dilithium signing implementation.
Instead, it isolates the local correction operation targeted by the
skipping-correction attack.

The experiment should therefore be interpreted as:

```text
a controlled local-correction skip simulation inside a coefficient loop
```

rather than a full physical fault-injection reproduction of randomized
Dilithium.

The attack logic being modeled is:

```text
normal prefix coefficients
one target coefficient where the correction term is omitted
normal suffix coefficients
```

The rest of the coefficient loop remains unchanged.

---

## Files

```text
firmware/cw-dilithium-krahmer-skipcorr/
├── Makefile
└── simpleserial-dilithium-krahmer.c

scripts/Krahmer_Correction_Fault_Attacks/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_krahmer_skipcorr.py
```

Additional patch used to make the arithmetic closer to reference Dilithium style:

```text
patch_krahmer_refstyle_lightweight_correction.sh
simpleserial-dilithium-krahmer_refstyle.c
```

The final version should use the reference-style lightweight correction file.

---

## Why the correction is lightweight

An earlier draft of this simulation used a helper based on C's `% Q` operator.
That version produced a large cycle gap because `int64_t % Q` is expensive on
Cortex-M.

That was not a good model for Dilithium-style correction arithmetic.

The final version avoids C `% Q` and instead uses lightweight helpers shaped
after reference Dilithium's `reduce32`, `caddq`, and `freeze` style.

The implemented helpers are:

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

This better represents a local lightweight correction operation instead of an
artificially expensive C modulo operation.

---

## Fault model

The firmware supports two runtime models:

```text
model = 0  none / baseline
model = 1  skip-correction attack
```

The host script accepts:

```text
none
skip
```

### Baseline model

The target coefficient uses the normal correction primitive:

```text
corrected = uncorrected + correction
```

with lightweight Dilithium-style reduction.

### Skipping-correction model

The target coefficient uses the faulted primitive:

```text
corrected = uncorrected
```

The correction term is omitted only for the target coefficient.

The prefix and suffix coefficients still use the normal correction primitive.

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

In code, the structure is:

```c
for (i = 0; i < target; i++) {
    krahmer_correction_normal_measured(...);
}

krahmer_target_correction_apply(...);

for (i = target + 1; i < KRAHMER_NCOEFFS; i++) {
    krahmer_correction_normal_measured(...);
}
```

---

## No target-window pollution

The runtime model dispatch is outside the measured correction primitive.

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

The target window contains either the normal correction primitive or the
faulted correction primitive, not simulator-side branch logic.

---

## Runtime configuration

The `F` command configures the experiment.

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

The firmware generates deterministic synthetic coefficient data so that
baseline and attack runs are directly comparable.

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

Important fields:

```text
target_uncorrected
    Local value before correction.

target_correction
    Local correction term.

target_expected
    Correct baseline value after correction.

target_used
    Value actually produced by the selected target primitive.

target_error
    target_expected - target_used.

faults_applied
    0 in baseline and 1 in attack.
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

Important fields:

```text
output_digest
    Digest of the output after the tested correction loop.

reference_digest
    Digest of a reference correction loop with no fault.

output_diff
    output_digest XOR reference_digest.
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

`target_cycles` is the measured cycle count for the target correction primitive.

`cycles_min`, `cycles_max`, and `cycles_sum` are measured over all coefficients
in the correction loop.

With the reference-style lightweight correction, the baseline and attack target
cycle counts can be identical. This is expected and more realistic than the
earlier `% Q` version.

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_krahmer_skip_correction_impl.sh
```

Replace the initial implementation with the reference-style lightweight
correction version:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/patch_krahmer_refstyle_lightweight_correction.sh
```

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

## Representative result: baseline

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

---

## Summary table

```text
Mode      Faults  Uncorrected  Correction  Expected  Used   Error  Output diff  Target cycles
baseline  0       20910        131         21041     21041  0      0            10
attack    1       20910        131         21041     20910  131    772022187    10
```

The semantic difference is clear, but the cycle count is identical:

```text
baseline target_cycles = 10
attack   target_cycles = 10
```

This is the expected behavior for the reference-style lightweight correction
kernel.

---

## Detector interpretation

This attack is a local correction fault.

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

A robust detector should not rely only on cycle-count thresholds for this fault
model. It should validate the correction result or the downstream randomized
signature consistency.

---

## Limitations

This is a software-level semantic simulation of the skipping-correction variant.

It validates:

```text
normal prefix coefficients
one target coefficient with correction omitted
normal suffix coefficients
structured local error equal to the omitted correction term
changed output digest
weak cycle-level detectability under lightweight correction
```

It is not a physical fault-injection demonstration.

It is not a full randomized Dilithium signing implementation.

A full implementation would require hooking the actual correction operation in
the randomized Dilithium signing code while preserving the same semantic rule:

```text
omit only the target local correction term
do not skip the surrounding loop
do not skip the signing phase
```
