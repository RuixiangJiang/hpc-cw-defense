# Kundu et al., “Carry Your Fault”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Kundu et al., **“Carry Your Fault”**.

The simulated fault is a data-value fault on a carry bit or a masked A2B
intermediate.

The semantic change is:

```text
normal:
    run masked decoding / A2B normally
    produce carry or masked intermediate
    consume that carry/intermediate normally

faulted:
    run masked decoding / A2B normally until the target carry/intermediate is produced
    overwrite the produced carry/intermediate with a stuck-at value
    continue the original masked decoding / A2B computation normally
```

This is not an instruction skip.

---

## Important scope note

This firmware is an SRAM-safe semantic kernel.

It does not claim to be the full masked Dilithium implementation from the paper.
Instead, it isolates the relevant dataflow pattern:

```text
masked A2B / decoding computation
carry or intermediate generation
stuck-at data-value fault
normal continuation consuming the faulty value
```

The purpose is to evaluate whether a carry/intermediate stuck-at fault changes
the decoded output while preserving the original control flow.

---

## Files

```text
firmware/cw-dilithium-kundu-carry/
├── Makefile
└── simpleserial-dilithium-kundu-carry.c

scripts/Kundu_Carry_Your_Fault/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_kundu_carry_fault.py
```

---

## Fault model

The firmware supports five runtime modes:

```text
model = 0  none / baseline
model = 1  carry stuck-at-0
model = 2  carry stuck-at-1
model = 3  intermediate bit stuck-at-0
model = 4  intermediate bit stuck-at-1
```

The host script accepts:

```text
none
carry0
carry1
inter0
inter1
```

The default attack model is:

```text
MODEL = carry1
```

which means:

```text
target carry bit is forced to 1
```

Default target:

```text
TARGET_COEFF = 17
TARGET_BIT   = 7
```

---

## Computation model

The firmware models a small masked decoding / A2B-style computation over
16-bit words.

For each coefficient, two arithmetic shares are used:

```text
a0
a1
```

The normal decoding computes the Boolean representation of:

```text
a0 + a1 mod 2^16
```

by propagating carry bits.

For each bit position:

```text
sum  = ai XOR bi XOR carry
cout = majority(ai, bi, carry)
```

The full normal decoding is:

```c
for (bit = 0; bit < KUNDU_WORD_BITS; bit++) {
    ai = (a0 >> bit) & 1;
    bi = (a1 >> bit) & 1;

    sum  = ai ^ bi ^ carry;
    cout = (ai & bi) | (ai & carry) | (bi & carry);

    result |= sum << bit;
    carry = cout;
}
```

The attack targets either:

```text
the carry-out produced at TARGET_BIT
```

or:

```text
the partial Boolean intermediate bit at TARGET_BIT
```

---

## Correct simulation structure

The simulation follows the requested data-fault semantics:

```text
1. Run the masked decoding / A2B computation normally until the target
   carry/intermediate is produced.

2. Record the expected carry/intermediate.

3. Overwrite the selected carry/intermediate with the stuck-at value.

4. Run the original continuation normally.

5. Compare the final output with the clean reference.
```

The target coefficient is split as:

```text
normal prefix coefficients
target coefficient up to target intermediate
data-value fault on carry/intermediate
normal continuation of target coefficient
normal suffix coefficients
```

This is a data-value perturbation only.

The simulation does not skip:

```text
the A2B function
the target coefficient
the coefficient loop
the continuation logic
```

---

## Clean target-window design

The fault is applied outside the measured target window:

```c
kundu_a2b_prefix_until_target(..., &partial, &carry);

kundu_expected_partial = partial;
kundu_expected_carry = carry;

used_partial = partial;
used_carry = carry;

kundu_apply_data_fault_unmeasured(&used_partial, &used_carry);

trigger_high();
kundu_hpc_region_begin();
start = kundu_hpc_op_begin();

kundu_out[target] = kundu_a2b_finish_from_intermediate(...,
                                                       used_partial,
                                                       used_carry);

kundu_hpc_target_cycles = kundu_hpc_op_end_common(start);
kundu_hpc_region_end();
trigger_low();
```

The measured target window contains only:

```text
normal A2B continuation consuming the selected carry/intermediate
```

It does not contain:

```text
fault-model dispatch
if attack then corrupt
prefix computation
suffix coefficient loop
```

The same continuation primitive is used in baseline and attack.

Therefore, baseline and attack are expected to have the same target-window cycle
count unless the continuation implementation itself has data-dependent timing.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> carry0
            2 -> carry1
            3 -> inter0
            4 -> inter1

bytes 1-2   target coefficient index, little endian

byte 3      target bit index

bytes 4-7   message_tweak, little endian

bytes 8-15  reserved
```

Default values:

```text
MODEL         = none or carry1
TARGET_COEFF  = 17
TARGET_BIT    = 7
MESSAGE_TWEAK = 0
```

The configuration response reports:

```text
ret
model
target_coeff
target_bit
message_tweak
word_bits
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[20]     configure carry/intermediate fault model
K -> K[1]      initialize synthetic masked-decoding state
S -> S[1]      run masked-decoding experiment
H -> H[32]     semantic status
D -> D[16]     digest status
R -> R[16]     target detail status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_ref
byte 3      reserved

bytes 4-7   faults_applied

bytes 8-11  target_coeff
bytes 12-15 target_bit

bytes 16-19 expected_carry
bytes 20-23 used_carry

byte 24     expected_intermediate_bit
byte 25     used_intermediate_bit
byte 26     defense_error
byte 27     hpc_anomaly_byte
byte 28     entries
byte 29     exits
byte 30     reserved
byte 31     reserved
```

Important fields:

```text
expected_carry
    Carry produced by the normal computation at the target bit.

used_carry
    Carry consumed by the continuation after the stuck-at fault.

expected_intermediate_bit
    Target bit of the normal partial Boolean intermediate.

used_intermediate_bit
    Target bit of the partial Boolean intermediate after the stuck-at fault.

output_matches_ref
    1 if the final output digest matches the clean reference.

faults_applied
    0 in baseline and 1 in attack.
```

For a successful carry stuck-at fault:

```text
baseline:
    faults_applied = 0
    used_carry = expected_carry
    output_matches_ref = 1

attack:
    faults_applied = 1
    used_carry = stuck-at value
```

For a successful intermediate stuck-at fault:

```text
baseline:
    faults_applied = 0
    used_intermediate_bit = expected_intermediate_bit
    output_matches_ref = 1

attack:
    faults_applied = 1
    used_intermediate_bit = stuck-at value
```

If the stuck-at value happens to be equal to the naturally produced value, the
semantic output may remain unchanged for that target. In that case, choose a
different `TARGET_COEFF`, `TARGET_BIT`, or stuck-at model.

---

## `R` detail fields

```text
bytes 0-3    expected_target_value
bytes 4-7    used_target_value
bytes 8-11   expected_partial
bytes 12-15  used_partial
```

Important fields:

```text
expected_target_value
    Clean decoded target coefficient.

used_target_value
    Target coefficient after consuming the selected carry/intermediate.

expected_partial
    Partial Boolean value after normal prefix-to-target computation.

used_partial
    Partial Boolean value after the stuck-at intermediate fault.
```

For a semantically effective attack:

```text
used_target_value != expected_target_value
```

This is not guaranteed for every target/stuck-at combination. Some stuck-at
values may equal the natural value.

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
output_digest = reference_digest
output_diff   = 0
```

For an effective attack:

```text
output_digest != reference_digest
output_diff   != 0
```

If `output_diff = 0` under an attack model, the selected stuck-at value likely
matches the naturally produced value for that target or does not propagate to a
different final decoded word. Try another target coefficient or bit.

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

The measured target window is only the normal continuation primitive.

Therefore:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

and the expected behavior is:

```text
baseline target_cycles ≈ attack target_cycles
```

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_kundu_carry_your_fault_impl.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Kundu_Carry_Your_Fault
./run_base.sh
```

Run the default attack:

```bash
./run_attack.sh
```

The default attack is:

```text
MODEL=carry1
TARGET_COEFF=17
TARGET_BIT=7
```

Run other models:

```bash
MODEL=carry0 ./run_attack.sh
MODEL=carry1 ./run_attack.sh
MODEL=inter0 ./run_attack.sh
MODEL=inter1 ./run_attack.sh
```

Try different targets:

```bash
TARGET_COEFF=17 TARGET_BIT=7 MODEL=carry1 ./run_attack.sh
TARGET_COEFF=17 TARGET_BIT=8 MODEL=carry1 ./run_attack.sh
TARGET_COEFF=42 TARGET_BIT=5 MODEL=inter1 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL        = none
TARGET_COEFF = 17
TARGET_BIT   = 7
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 204
dwt_cpi                     : 7
dwt_exc                     : 0
dwt_lsu                     : 34
dwt_fold                    : 2
target_cycles               : 179
cycles_min                  : 179
cycles_max                  : 179
cycles_sum                  : 179
```

Interpretation:

```text
The target A2B continuation executes normally.
The continuation costs 179 cycles.
```

---

## Representative result: carry stuck-at-1 attack

Configuration:

```text
MODEL        = carry1
TARGET_COEFF = 17
TARGET_BIT   = 7
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 204
dwt_cpi                     : 7
dwt_exc                     : 0
dwt_lsu                     : 34
dwt_fold                    : 2
target_cycles               : 179
cycles_min                  : 179
cycles_max                  : 179
cycles_sum                  : 179
```

Interpretation:

```text
The target carry is overwritten before the measured window.
The same normal continuation primitive executes.
The continuation still costs 179 cycles.
```

This is the expected result for a data-value fault with a clean target window.

---

## Timing summary

```text
Mode      Target coeff  Target bit  Target window                 Target cycles
baseline  17            7           normal A2B continuation        179
carry1    17            7           normal A2B continuation        179
```

The cycle count is unchanged because the measured code path is unchanged.

---

## Detector interpretation

This attack is a data-value fault, not an instruction skip.

Under the clean-window implementation:

```text
baseline target_cycles = 179
attack   target_cycles = 179
```

This means a cycle-only DWT/HPC detector is weak for this model.

The correct detector should check the semantic integrity of the masked
conversion or decoding computation.

More appropriate defenses include:

```text
carry consistency checks
redundant A2B conversion and compare
masked-decoding recomputation
range checks on decoded values
share consistency checks
fault-resistant carry propagation
infective decoding checks
```

A DWT/HPC detector may still be useful for broader implementation faults such as
skipping whole loops or function calls, but it should not be expected to detect a
clean data-only stuck-at carry fault when the same continuation code executes.

---

## Why identical cycles are reasonable

The observed result:

```text
baseline target_cycles = 179
carry1   target_cycles = 179
```

is reasonable because:

```text
1. The carry/intermediate is produced normally before the target window.
2. The data-value overwrite happens before the target window.
3. The measured target window calls the same normal continuation function in
   both baseline and attack.
4. There is no branch inside the measured primitive that depends on the attack
   model.
5. The continuation is implemented with fixed loop bounds.
```

Therefore, the attack changes the data consumed by the continuation, not the
measured instruction sequence.

---

## Limitations

This is a software-level semantic simulation.

It validates:

```text
normal masked-decoding/A2B prefix
target carry/intermediate produced normally
stuck-at data-value overwrite
normal continuation consuming the faulty value
unchanged target-window cycle count
```

It is not a physical EMFI, voltage-glitch, clock-glitch, or laser fault
demonstration.

It is not a full masked Dilithium implementation.

A full implementation would hook the actual masked decoding or A2B conversion
logic while preserving the same semantic rule:

```text
do not skip instructions or functions
do not skip the surrounding loop
overwrite only the target carry/intermediate after it is produced
continue the original computation normally
do not add simulator-side branch logic inside the measured target window
```
