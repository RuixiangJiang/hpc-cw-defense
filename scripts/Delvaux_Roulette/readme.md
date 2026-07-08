# Delvaux, “Roulette”: masked-intermediate fault simulation

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Delvaux, **“Roulette”**.

Roulette is modeled as a family of faults on a masked intermediate in a
Kyber-like re-encryption / decoding pipeline. The common semantic effect is:

```text
a masked intermediate variable takes a faulty distribution,
and the following masked operations consume that faulty value.
```

This experiment implements four Roulette-style fault models:

```text
1. instruction-skip
2. set-to-constant
3. random fault
4. bit-flip
```

The target is inside a coefficient loop, so the firmware uses a
prefix-target-suffix structure:

```text
normal prefix coefficients
target coefficient with selected Roulette fault model
normal suffix coefficients
```

The target coefficient is selected at runtime.

---

## Important scope note

This firmware is an SRAM-safe masked-intermediate kernel.

It does **not** claim to be a full masked Kyber decapsulation implementation.
Instead, it isolates the semantic object needed for Roulette-style simulation:

```text
masked intermediate generation
fault injection on one target masked intermediate
downstream masked consumption of the faulty intermediate
```

This is intentional because full masked Kyber decapsulation is substantially
larger and is not available in the pqm4 Kyber512-90s implementation used here.

The experiment is therefore best interpreted as:

```text
a controlled masked-intermediate fault simulation for Roulette-style models
```

rather than a full reproduction of a complete masked Kyber implementation.

---

## Files

```text
firmware/cw-kyber51290s-roulette/
├── Makefile
└── simpleserial-kyber-roulette.c

scripts/Delvaux_Roulette/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_kyber_roulette.py
```

This experiment does not modify existing pqm4 source files.

---

## Fault models

The firmware supports five runtime modes:

```text
model = 0  none / baseline
model = 1  instruction-skip
model = 2  set-to-constant
model = 3  random fault
model = 4  bit-flip
```

The host script accepts the corresponding names:

```text
none
skip
const
random
bitflip
```

---

## Masked intermediate pipeline

Each coefficient has two masked shares:

```c
typedef struct {
    uint16_t s0;
    uint16_t s1;
} roulette_masked_u16;
```

The normal local masked operation computes the target intermediate:

```c
out->s0 = roulette_mask12(((unsigned int)in.s0 + 0x0123u) ^ 0x0041u);
out->s1 = roulette_mask12(((unsigned int)in.s1 + 0x0234u) ^ 0x0082u);
```

The downstream consumer then uses the resulting masked intermediate:

```c
digest = roulette_consume_masked_intermediate(state, coeff, digest);
```

The key point is that after the target intermediate is faulted, the rest of the
pipeline continues normally and consumes the faulty masked value.

---

## Prefix-target-suffix structure

The coefficient loop uses this structure:

```text
for coeff < target:
    normal masked operation
    normal downstream consumption

for coeff == target:
    selected Roulette fault model
    normal downstream consumption

for coeff > target:
    normal masked operation
    normal downstream consumption
```

In code, this is implemented by:

```c
for (coeff = 0; coeff < target; coeff++) {
    in = roulette_input_shares(coeff);
    (void)roulette_target_normal_measured(in, &state);
    digest = roulette_consume_masked_intermediate(state, coeff, digest);
}

in = roulette_input_shares(target);
roulette_masked_local_op_unmeasured(in, &expected);
roulette_hpc_target_op_cycles =
    roulette_target_apply_measured(roulette_fault_model, in, &state, &rng);

digest = roulette_consume_masked_intermediate(state, target, digest);

for (coeff = target + 1u; coeff < ROULETTE_NCOEFFS; coeff++) {
    in = roulette_input_shares(coeff);
    (void)roulette_target_normal_measured(in, &state);
    digest = roulette_consume_masked_intermediate(state, coeff, digest);
}
```

For Kyber:

```text
ROULETTE_NCOEFFS = KYBER_N = 256
```

---

## No target-window pollution

The runtime dispatcher is outside the measured target primitive.

Dispatcher:

```c
static uint32_t roulette_target_apply_measured(unsigned int model,
                                               roulette_masked_u16 in,
                                               roulette_masked_u16 *state,
                                               uint32_t *rng)
{
    if (model == ROULETTE_MODEL_SKIP) {
        return roulette_target_skip_measured(in, state);
    }

    if (model == ROULETTE_MODEL_CONST) {
        return roulette_target_const_measured(in, state, (uint16_t)roulette_const_value);
    }

    if (model == ROULETTE_MODEL_RANDOM) {
        return roulette_target_random_measured(in, state, rng);
    }

    if (model == ROULETTE_MODEL_BITFLIP) {
        return roulette_target_bitflip_measured(in, state, (uint16_t)roulette_bit_mask);
    }

    return roulette_target_normal_measured(in, state);
}
```

Each measured primitive contains only the selected operation.

Therefore the measured target window does not contain:

```c
if (attack) {
    fault target;
}
```

The measured operation is one of the following standalone primitives:

```text
normal local masked operation
skip local masked operation
set target intermediate to constant
replace target intermediate with random shares
apply normal operation and then bit-flip the selected share
```

---

## Implemented target primitives

### Baseline

The baseline executes the normal local masked operation:

```c
roulette_masked_local_op_unmeasured(in, out);
```

### Instruction-skip variant

The instruction-skip variant removes the target local masked operation. The
output object is deliberately left unchanged, so the downstream consumer receives
a stale or incomplete masked intermediate:

```c
__asm volatile("" : "+m"(*out) : : "memory");
```

Semantic effect:

```text
target intermediate = stale / incomplete value
```

### Set-to-constant variant

The set-to-constant variant replaces the target intermediate with a chosen
constant before downstream consumption:

```c
out->s0 = roulette_mask12(c);
out->s1 = 0u;
```

Semantic effect:

```text
target intermediate = constant
```

The constant is configured by:

```bash
CONST_VALUE=<value>
```

### Random-fault variant

The random-fault variant replaces the target intermediate with random shares
drawn from the experiment’s intended random-fault distribution:

```c
r0 = roulette_xorshift32(rng);
r1 = roulette_xorshift32(rng);
out->s0 = roulette_mask12(r0);
out->s1 = roulette_mask12(r1);
```

Semantic effect:

```text
target intermediate = random masked value
```

The random seed is configured by:

```bash
RAND_SEED=<seed>
```

### Bit-flip variant

The bit-flip variant first computes the target intermediate normally, then flips
the selected mask in share `s0`:

```c
roulette_masked_local_op_unmeasured(in, out);
out->s0 = roulette_mask12(((unsigned int)out->s0) ^ ((unsigned int)mask));
```

Semantic effect:

```text
target intermediate = normal intermediate with selected share bit(s) flipped
```

The bit mask is configured by:

```bash
BIT_MASK=<mask>
```

Because the bit flip is applied to one masked share, the unmasked value
difference is not necessarily equal to `BIT_MASK`.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
bytes 1-2   target coefficient, little endian
byte 3      reserved
bytes 4-5   constant value, little endian
bytes 6-7   bit mask, little endian
bytes 8-11  random seed, little endian
bytes 12-15 reserved
```

The response reports:

```text
byte 0      return code
byte 1      model
bytes 2-3   target coefficient
bytes 4-5   constant value
bytes 6-7   bit mask
bytes 8-11  random seed
bytes 12-13 number of coefficients
bytes 14-15 reserved
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[16]     configure fault model
K -> K[1]      initialize observation state
S -> S[1]      run masked-intermediate pipeline
H -> H[32]     semantic status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
bytes 1-2   target_coeff
byte 3      semantic_valid
bytes 4-7   faults_applied
bytes 8-11  target_expected_value
bytes 12-15 target_used_value
bytes 16-19 target_diff
bytes 20-23 output_digest
byte 24     defense_error
byte 25     hpc_anomaly_byte
byte 26     entries
byte 27     exits
byte 28     const_value_low
byte 29     bit_mask_low
bytes 30-31 reserved
```

Important fields:

```text
target_expected_value
    The unmasked value that the target intermediate should have in a normal run.

target_used_value
    The unmasked value actually consumed by the downstream pipeline.

target_diff
    target_expected_value XOR target_used_value.

output_digest
    A compact digest of the downstream pipeline output.

faults_applied
    Number of Roulette faults applied. It should be 0 in baseline and 1 in each
    attack run.

semantic_valid
    Set to 1 after a successful pipeline run.
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
word 4  target_op_cycles
word 5  op_cycles_min
word 6  op_cycles_max
word 7  op_cycles_sum
```

For a stable baseline with 256 coefficients and 11 cycles per local operation:

```text
op_cycles_sum = 11 * 256 = 2816
```

If only one target coefficient is faulted, the sum changes according to the
target primitive’s measured cost.

---

## Build and run

Install the experiment files from the repository root:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_delvaux_roulette_impl.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Delvaux_Roulette
./run_base.sh
```

Run attack variants:

```bash
MODEL=skip TARGET_COEFF=17 ./run_attack.sh

MODEL=const TARGET_COEFF=17 CONST_VALUE=0 ./run_attack.sh

MODEL=random TARGET_COEFF=17 RAND_SEED=0x12345678 ./run_attack.sh

MODEL=bitflip TARGET_COEFF=17 BIT_MASK=1 ./run_attack.sh
```

---

## Representative results

The following results were obtained with:

```text
TARGET_COEFF = 17
CONST_VALUE  = 0
BIT_MASK     = 1
RAND_SEED    = 0x12345678
```

### Baseline

```text
model                   : none
target_coeff            : 17
semantic_valid          : 1
faults_applied          : 0
target_expected_value   : 2843
target_used_value       : 2843
target_diff             : 0
output_digest           : 1802499307
target_op_cycles        : 11
op_cycles_min           : 11
op_cycles_max           : 11
op_cycles_sum           : 2816
```

The sum confirms that all 256 coefficients use the normal local masked operation:

```text
2816 = 11 * 256
```

### Instruction-skip

```text
model                   : skip
faults_applied          : 1
target_expected_value   : 2843
target_used_value       : 2030
target_diff             : 3317
output_digest           : 2838753870
target_op_cycles        : 8
op_cycles_min           : 8
op_cycles_max           : 11
op_cycles_sum           : 2813
```

Cycle relation:

```text
2813 = 11 * 255 + 8
```

This confirms that one target masked local operation was skipped while the
remaining 255 coefficients executed normally.

### Set-to-constant

```text
model                   : const
faults_applied          : 1
target_expected_value   : 2843
target_used_value       : 0
target_diff             : 2843
output_digest           : 1607175756
target_op_cycles        : 12
op_cycles_min           : 11
op_cycles_max           : 12
op_cycles_sum           : 2817
```

Cycle relation:

```text
2817 = 11 * 255 + 12
```

This confirms that only the target coefficient was replaced with the configured
constant.

### Random fault

```text
model                   : random
faults_applied          : 1
target_expected_value   : 2843
target_used_value       : 3912
target_diff             : 1107
output_digest           : 3202862930
target_op_cycles        : 32
op_cycles_min           : 11
op_cycles_max           : 32
op_cycles_sum           : 2837
```

Cycle relation:

```text
2837 = 11 * 255 + 32
```

The random-fault target window is longer because it generates two random shares.

### Bit-flip

```text
model                   : bitflip
faults_applied          : 1
target_expected_value   : 2843
target_used_value       : 2844
target_diff             : 7
output_digest           : 3879796128
target_op_cycles        : 11
op_cycles_min           : 11
op_cycles_max           : 11
op_cycles_sum           : 2816
```

Cycle relation:

```text
2816 = 11 * 256
```

The bit-flip changes the masked intermediate semantically but does not change
the local cycle count in this build.

The observed `target_diff` is:

```text
2843 XOR 2844 = 7
```

This is expected because the bit flip is applied to one masked share, while the
reported value is the unmasked sum of both shares.

---

## Summary table

```text
Mode      Expected  Used  Faults  Target cycles  Sum cycles
none      2843      2843  0       11             2816
skip      2843      2030  1       8              2813
const     2843      0     1       12             2817
random    2843      3912  1       32             2837
bitflip   2843      2844  1       11             2816
```

---

## Detector interpretation

Using the baseline target cycle count:

```text
baseline target_op_cycles = 11
```

a DWT cycle-threshold detector can identify:

```text
skip    : 8   -> low-cycle anomaly
const   : 12  -> high-cycle anomaly
random  : 32  -> high-cycle anomaly
```

The bit-flip variant is different:

```text
bitflip target_op_cycles = 11
baseline target_op_cycles = 11
```

So in this build, a pure target-cycle detector does not catch the bit-flip
variant. The semantic fields still show that the fault changed the target masked
intermediate and the downstream digest:

```text
target_used_value changes from 2843 to 2844
output_digest changes from 1802499307 to 3879796128
```

Therefore the detector conclusion should be:

```text
Instruction-skip, set-to-constant, and random-fault variants can be detected by
target-cycle deviations in this kernel. The bit-flip variant changes the masked
intermediate without necessarily changing the cycle count, so it requires
semantic redundancy, masked-domain consistency checks, duplicate computation, or
downstream consistency checks.
```

---

## Running with cycle thresholds

Baseline threshold calibration:

```bash
ROULETTE_HPC_TARGET_CYCLES_MIN=11 \
ROULETTE_HPC_TARGET_CYCLES_MAX=11 \
./run_base.sh
```

Expected:

```text
anomaly       = 0
defense_error = 0
```

Attack threshold checks:

```bash
ROULETTE_HPC_TARGET_CYCLES_MIN=11 \
ROULETTE_HPC_TARGET_CYCLES_MAX=11 \
MODEL=skip TARGET_COEFF=17 ./run_attack.sh
```

```bash
ROULETTE_HPC_TARGET_CYCLES_MIN=11 \
ROULETTE_HPC_TARGET_CYCLES_MAX=11 \
MODEL=const TARGET_COEFF=17 CONST_VALUE=0 ./run_attack.sh
```

```bash
ROULETTE_HPC_TARGET_CYCLES_MIN=11 \
ROULETTE_HPC_TARGET_CYCLES_MAX=11 \
MODEL=random TARGET_COEFF=17 RAND_SEED=0x12345678 ./run_attack.sh
```

```bash
ROULETTE_HPC_TARGET_CYCLES_MIN=11 \
ROULETTE_HPC_TARGET_CYCLES_MAX=11 \
MODEL=bitflip TARGET_COEFF=17 BIT_MASK=1 ./run_attack.sh
```

Expected:

```text
skip, const, random:
    anomaly is nonzero
    defense_error includes 0x40

bitflip:
    anomaly may remain 0
    semantic values still change
```

---

## Limitations

This is a software-level simulation of Roulette-style masked-intermediate
faults. It validates the semantic behavior and DWT/HPC observability of the
selected fault models in a controlled kernel.

It is not a full masked Kyber decapsulation implementation and should not be
described as a direct physical fault-injection demonstration. A physical
clock-glitch, voltage-glitch, or EMFI experiment would require a real masked
Kyber target, trigger calibration, and fault localization around the actual
masked intermediate operation.
