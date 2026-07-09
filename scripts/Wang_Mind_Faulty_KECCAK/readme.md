# Wang et al., “Mind the Faulty KECCAK”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Wang et al., **“Mind the Faulty KECCAK”**.

The simulated fault changes Keccak loop execution.

The core semantic change is:

```text
normal:
    execute the full Keccak loop

loop-abort fault:
    execute only a prefix of the Keccak loop

single-round skip fault:
    execute normal prefix rounds
    omit one target round
    execute normal suffix rounds
```

The surrounding Keccak call structure remains unchanged:

```text
init
absorb
target Keccak loop routine
squeeze / output handling
```

Only the loop execution inside the Keccak routine is faulted.

---

## Important scope note

This firmware is an SRAM-safe semantic kernel.

It does not implement full Keccak-f1600. Instead, it uses a compact
Keccak-like permutation stand-in with the same relevant structure:

```text
a fixed-round loop
a round body
state transformation
squeeze/output after the loop
```

The purpose is to isolate the attack semantics:

```text
Keccak loop executes fewer iterations
hash/seed output becomes different, repeated, or predictable
timing drops because loop work is skipped
```

This experiment should be interpreted as a controlled simulation of Keccak
loop-fault behavior, not as a full physical fault-injection reproduction.

---

## Files

```text
firmware/cw-dilithium-wang-faulty-keccak/
├── Makefile
└── simpleserial-dilithium-wang-keccak.c

scripts/Wang_Mind_Faulty_KECCAK/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_wang_faulty_keccak.py
```

---

## Fault models

The firmware supports three runtime modes:

```text
model = 0  none / baseline
model = 1  loop-abort
model = 2  single-round skip
```

The host script accepts:

```text
none
abort
skipround
```

### Baseline

The full Keccak-like loop executes:

```text
for round = 0 .. 23:
    execute round body
```

Therefore:

```text
used_rounds    = 24
skipped_rounds = 0
```

### Loop-abort model

The loop executes only a prefix of the original loop:

```text
for round = 0 .. stop_round - 1:
    execute round body
```

Default:

```text
STOP_ROUND = 8
```

Therefore:

```text
used_rounds    = 8
skipped_rounds = 16
```

This models a loop-abort fault where the Keccak loop terminates early.

### Single-round skip model

The loop executes the normal prefix, omits one target round body, and then
executes the normal suffix:

```text
for round = 0 .. skip_round - 1:
    execute round body

omit round = skip_round

for round = skip_round + 1 .. 23:
    execute round body
```

Default:

```text
SKIP_ROUND = 7
```

Therefore:

```text
used_rounds    = 23
skipped_rounds = 1
```

This models a single omitted Keccak loop body while preserving the surrounding
call structure.

---

## Correct simulation structure

The simulation follows the requested attack semantics.

The surrounding Keccak call structure is preserved:

```text
1. Initialize state.

2. Absorb input normally.

3. Select the Keccak routine outside the target window.

4. Trigger and measure only the selected Keccak loop routine.

5. Squeeze/output normally.
```

The selected routine is one of:

```text
normal full-loop routine
loop-abort routine
single-round-skip routine
```

The target window measures the skipped loop work directly.

It does not measure unrelated setup or output code.

---

## Clean target-window design

The target routine is selected before the trigger and DWT/HPC window:

```c
if (wang_model == WANG_MODEL_ABORT) {
    routine = wang_keccak_routine_abort;
    wang_used_rounds = wang_stop_round;
    wang_skipped_rounds = WANG_ROUNDS - wang_used_rounds;
    wang_faults_applied = 1u;
} else if (wang_model == WANG_MODEL_SKIPROUND) {
    routine = wang_keccak_routine_skipround;
    wang_used_rounds = WANG_ROUNDS - 1u;
    wang_skipped_rounds = 1u;
    wang_faults_applied = 1u;
} else {
    routine = wang_keccak_routine_normal;
    wang_used_rounds = WANG_ROUNDS;
    wang_skipped_rounds = 0u;
    wang_faults_applied = 0u;
}
```

The measured target window contains only the selected loop routine:

```c
trigger_high();
wang_hpc_region_begin();
start = wang_hpc_op_begin();

routine(wang_state);

wang_hpc_target_cycles = wang_hpc_op_end_common(start);
wang_hpc_region_end();
trigger_low();
```

The measured target window does not contain:

```text
fault-model dispatch
if attack then skip
input generation
state initialization
absorb
squeeze
output digest computation
```

This prevents target-window pollution.

---

## Why the observed timing difference is expected

The representative baseline result is:

```text
baseline target_cycles = 78075
```

The representative loop-abort result is:

```text
abort target_cycles = 26052
```

The default loop-abort configuration uses:

```text
WANG_ROUNDS = 24
STOP_ROUND  = 8
```

So the abort routine executes one third of the normal rounds:

```text
8 / 24 = 1/3
```

The measured cycle ratio is also about one third:

```text
26052 / 78075 ≈ 0.334
```

Therefore the result is reasonable.

It shows that the measured difference corresponds to skipped Keccak loop work,
not to unrelated setup or output handling.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> abort
            2 -> skipround

byte 1      stop_round

byte 2      skip_round

bytes 3-6   message_tweak, little endian

bytes 7-15  reserved
```

Default values:

```text
MODEL         = none or abort
STOP_ROUND    = 8
SKIP_ROUND    = 7
MESSAGE_TWEAK = 0
```

The configuration response reports:

```text
ret
model
stop_round
skip_round
message_tweak
rounds
input_bytes
output_bytes
input_digest
```

Default constants:

```text
WANG_ROUNDS      = 24
WANG_INPUT_BYTES = 96
WANG_OUTPUT_BYTES = 32
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[24]     configure faulty-Keccak model
K -> K[1]      initialize synthetic Keccak input/state
S -> S[1]      run faulty-Keccak experiment
H -> H[32]     semantic status
D -> D[16]     digest status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_clean
byte 3      output_matches_abort
byte 4      output_matches_skip
byte 5      stop_round
byte 6      skip_round
byte 7      reserved

bytes 8-11   faults_applied
bytes 12-15  expected_rounds
bytes 16-19  used_rounds
bytes 20-23  skipped_rounds
bytes 24-27  state_digest_after_absorb

byte 28       defense_error
byte 29       hpc_anomaly_byte
byte 30       entries
byte 31       exits
```

Important fields:

```text
expected_rounds
    Number of rounds in the clean Keccak-like routine.

used_rounds
    Number of round bodies executed by the selected routine.

skipped_rounds
    Number of omitted rounds.

output_matches_clean
    1 if the output matches the clean full-loop reference.

output_matches_abort
    1 if the output matches the loop-abort reference.

output_matches_skip
    1 if the output matches the single-round-skip reference.
```

For a correct baseline:

```text
faults_applied       = 0
used_rounds          = expected_rounds
skipped_rounds       = 0
output_matches_clean = 1
```

For a correct loop-abort attack:

```text
faults_applied       = 1
used_rounds          = stop_round
skipped_rounds       = expected_rounds - stop_round
output_matches_abort = 1
```

For a correct single-round skip attack:

```text
faults_applied       = 1
used_rounds          = expected_rounds - 1
skipped_rounds       = 1
output_matches_skip  = 1
```

---

## `D` digest fields

```text
bytes 0-3    output_digest
bytes 4-7    clean_digest
bytes 8-11   abort_digest
bytes 12-15  skip_digest
```

Important fields:

```text
output_digest
    Digest of the output generated by the selected routine.

clean_digest
    Digest of the clean full-loop reference.

abort_digest
    Digest of the loop-abort reference.

skip_digest
    Digest of the single-round-skip reference.
```

For baseline:

```text
output_digest = clean_digest
```

For loop-abort attack:

```text
output_digest = abort_digest
output_digest != clean_digest
```

For single-round skip attack:

```text
output_digest = skip_digest
output_digest != clean_digest
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

There is one measured target routine, so normally:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

The timing difference directly reflects the executed amount of Keccak loop work.

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_wang_faulty_keccak_impl.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Wang_Mind_Faulty_KECCAK
./run_base.sh
```

Run the default loop-abort attack:

```bash
./run_attack.sh
```

Equivalent explicit command:

```bash
MODEL=abort STOP_ROUND=8 ./run_attack.sh
```

Run single-round skip:

```bash
MODEL=skipround SKIP_ROUND=7 ./run_attack.sh
```

Try other abort points:

```bash
MODEL=abort STOP_ROUND=1 ./run_attack.sh
MODEL=abort STOP_ROUND=4 ./run_attack.sh
MODEL=abort STOP_ROUND=12 ./run_attack.sh
MODEL=abort STOP_ROUND=16 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL      = none
STOP_ROUND = 8
SKIP_ROUND = 7
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 78102
dwt_cpi                     : 13
dwt_exc                     : 0
dwt_lsu                     : 209
dwt_fold                    : 2
target_cycles               : 78075
cycles_min                  : 78075
cycles_max                  : 78075
cycles_sum                  : 78075
```

Interpretation:

```text
The clean Keccak-like routine executes all 24 rounds.
The measured full-loop target cost is 78075 cycles.
```

---

## Representative result: loop-abort attack

Configuration:

```text
MODEL      = abort
STOP_ROUND = 8
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 26079
dwt_cpi                     : 93
dwt_exc                     : 0
dwt_lsu                     : 180
dwt_fold                    : 3
target_cycles               : 26052
cycles_min                  : 26052
cycles_max                  : 26052
cycles_sum                  : 26052
```

Interpretation:

```text
The loop-abort routine executes only the first 8 rounds.
The remaining 16 rounds are skipped.
The target cost drops from 78075 cycles to 26052 cycles.
```

The timing ratio is:

```text
26052 / 78075 ≈ 0.334
```

which is close to:

```text
8 / 24 = 0.333
```

This is the expected timing behavior for a loop-abort model.

---

## Timing summary

```text
Mode      Rounds executed  Rounds skipped  Target cycles
baseline  24               0               78075
abort     8                16              26052
```

The observed cycle drop corresponds to skipped Keccak loop work.

---

## Detector interpretation

This attack is a T-type loop-execution fault.

Unlike a pure data-value fault, it changes the amount of loop body work executed
inside the measured Keccak routine.

The timing signal is strong:

```text
baseline target_cycles = 78075
abort   target_cycles = 26052
```

A cycle-threshold detector can detect this loop-abort case if the target window
is aligned with the Keccak loop routine.

Example logic:

```text
if target_cycles << expected_full_keccak_cycles:
    report shortened Keccak loop
```

More robust defenses include:

```text
round counters
redundant round-count verification
Keccak state consistency checks
duplicate Keccak computation and compare
absorbed/squeezed transcript checks
domain-separated hash transcript counters
control-flow integrity for permutation loop bounds
```

For the single-round skip model, the cycle gap is expected to be smaller than
loop-abort but still measurable if the round body is sufficiently expensive.

---

## Why this is not target-window pollution

The measured target window contains the selected Keccak routine only.

Dispatch happens before the window:

```text
routine = normal / abort / skipround
```

Then the window measures:

```text
routine(wang_state)
```

The window does not include:

```text
input setup
absorb
squeeze
digest comparison
host-side bookkeeping
fault-model dispatch
```

Therefore the observed timing gap corresponds to the skipped Keccak loop work
inside the attacked routine.

---

## Limitations

This is a software-level semantic simulation.

It validates:

```text
normal surrounding Keccak call structure
full-loop baseline
loop-abort prefix-only execution
single-round skip prefix-target-suffix execution
changed output digest
large timing drop for loop-abort
```

It is not a physical EMFI, voltage-glitch, clock-glitch, or laser fault
demonstration.

It is not a full Keccak-f1600 implementation.

A full implementation would hook the actual Keccak routine while preserving the
same semantic rule:

```text
for loop-abort:
    execute only the prefix of the original Keccak loop

for single-block/round skip:
    execute normal prefix
    omit the target loop body
    execute normal suffix

for both:
    keep the surrounding Keccak call structure unchanged
    do not add simulator-side branch logic inside the measured target window
```
