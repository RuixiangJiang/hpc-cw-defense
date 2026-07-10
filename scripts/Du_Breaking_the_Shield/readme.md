# Du et al., “Breaking the Shield”

This directory contains two ChipWhisperer/Cortex-M software fault-simulation
experiments for Du et al., **“Breaking the Shield”**:

```text
1. SHAKE256 absorb-loop attack
2. y-generation / polyz_unpack skipped-load attack
```

Both experiments are placed in one folder:

```text
firmware/cw-dilithium-du-breaking-shield
scripts/Du_Breaking_the_Shield
```

The two attacks have different semantics:

```text
SHAKE256 attack:
    loop-execution fault
    fewer SHAKE256 absorb blocks are processed

polyz_unpack attack:
    local skipped-load data fault
    one load result inside polyz_unpack is replaced by zero or by a prepared
    stale value
```

---

## File layout

```text
firmware/cw-dilithium-du-breaking-shield/
├── Makefile
├── simpleserial-du-shake256.c
└── simpleserial-du-polyz-unpack.c

scripts/Du_Breaking_the_Shield/
├── exp_env.sh
├── run_shake_base.sh
├── run_shake_attack.sh
├── run_polyz_base.sh
├── run_polyz_attack.sh
├── test_du_shake256_absorb.py
├── test_du_polyz_unpack.py
└── readme.md
```

The shared firmware Makefile selects the concrete experiment with:

```text
DU_SRC=simpleserial-du-shake256.c
DU_SRC=simpleserial-du-polyz-unpack.c
```

---

# Part I — SHAKE256 absorb-loop attack

## Semantics

The SHAKE256 attack skips or aborts an absorb loop.

Clean computation:

```text
initialize SHAKE state
absorb all intended blocks
finalize
squeeze output normally
```

Loop-abort fault:

```text
initialize SHAKE state
absorb only prefix blocks before the stopping point
finalize
squeeze output normally from the faulted state
```

Single-block skip fault:

```text
initialize SHAKE state
absorb normal prefix blocks
omit the target absorb block
absorb normal suffix blocks
finalize
squeeze output normally from the faulted state
```

The squeeze path still executes normally.

---

## SHAKE256 models

```text
model = 0  none / baseline
model = 1  loop-abort
model = 2  single-block skip
```

Host names:

```text
none
abort
skipblock
```

Default constants:

```text
DU_ABSORB_BLOCKS      = 8
DU_ABSORB_BLOCK_BYTES = 32
STOP_BLOCK            = 4
SKIP_BLOCK            = 3
```

Baseline:

```text
used_blocks    = 8
skipped_blocks = 0
```

Loop-abort with `STOP_BLOCK=4`:

```text
used_blocks    = 4
skipped_blocks = 4
```

Single-block skip with `SKIP_BLOCK=3`:

```text
used_blocks    = 7
skipped_blocks = 1
```

---

## SHAKE256 clean target window

The selected absorb-loop routine is chosen before the measured window:

```c
if (du_model == DU_MODEL_ABORT) {
    routine = du_shake_absorb_abort;
    du_used_blocks = du_stop_block;
    du_skipped_blocks = DU_ABSORB_BLOCKS - du_used_blocks;
    du_faults_applied = 1u;
} else if (du_model == DU_MODEL_SKIPBLOCK) {
    routine = du_shake_absorb_skipblock;
    du_used_blocks = DU_ABSORB_BLOCKS - 1u;
    du_skipped_blocks = 1u;
    du_faults_applied = 1u;
} else {
    routine = du_shake_absorb_normal;
    du_used_blocks = DU_ABSORB_BLOCKS;
    du_skipped_blocks = 0u;
    du_faults_applied = 0u;
}
```

The measured window contains only the selected absorb routine:

```c
trigger_high();
du_hpc_region_begin();
start = du_hpc_op_begin();

routine(du_state, du_input);

du_hpc_target_cycles = du_hpc_op_end_common(start);
du_hpc_region_end();
trigger_low();
```

The normal squeeze path runs after the target window:

```c
du_shake_finalize_squeeze_normal(du_state, du_output, DU_OUTPUT_BYTES);
```

The target window does not contain:

```text
fault-model dispatch
if attack then skip
finalize
squeeze
digest computation
host-side bookkeeping
```

This keeps the timing signal aligned with skipped absorb-loop work.

---

## Run SHAKE256 experiments

```bash
cd ~/hpc-cw-defense/scripts/Du_Breaking_the_Shield
./run_shake_base.sh
MODEL=abort STOP_BLOCK=4 ./run_shake_attack.sh
MODEL=skipblock SKIP_BLOCK=3 ./run_shake_attack.sh
```

Other examples:

```bash
MODEL=abort STOP_BLOCK=2 ./run_shake_attack.sh
MODEL=abort STOP_BLOCK=6 ./run_shake_attack.sh
MODEL=skipblock SKIP_BLOCK=0 ./run_shake_attack.sh
MODEL=skipblock SKIP_BLOCK=7 ./run_shake_attack.sh
```

---

## SHAKE256 `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_clean
byte 3      output_matches_abort
byte 4      output_matches_skip
byte 5      stop_block
byte 6      skip_block
byte 7      reserved

bytes 8-11   faults_applied
bytes 12-15  expected_blocks
bytes 16-19  used_blocks
bytes 20-23  skipped_blocks
bytes 24-27  state_digest_after_absorb

byte 28       defense_error
byte 29       hpc_anomaly_byte
byte 30       entries
byte 31       exits
```

Correct baseline:

```text
faults_applied       = 0
used_blocks          = 8
skipped_blocks       = 0
output_matches_clean = 1
```

Correct loop-abort attack:

```text
faults_applied       = 1
used_blocks          = STOP_BLOCK
skipped_blocks       = 8 - STOP_BLOCK
output_matches_abort = 1
```

Correct single-block skip attack:

```text
faults_applied      = 1
used_blocks         = 7
skipped_blocks      = 1
output_matches_skip = 1
```

---

## SHAKE256 `D` digest fields

```text
bytes 0-3    output_digest
bytes 4-7    clean_digest
bytes 8-11   abort_digest
bytes 12-15  skip_digest
```

Baseline:

```text
output_digest = clean_digest
```

Loop-abort:

```text
output_digest = abort_digest
output_digest != clean_digest
```

Single-block skip:

```text
output_digest = skip_digest
output_digest != clean_digest
```

---

## SHAKE256 result: baseline

Configuration:

```text
MODEL      = none
STOP_BLOCK = 4
SKIP_BLOCK = 3
```

Semantic result:

```text
model                       : 0
model_name                  : none
semantic_valid              : 1
output_matches_clean        : 1
output_matches_abort        : 0
output_matches_skip         : 0
stop_block                  : 4
skip_block                  : 3
faults_applied              : 0
expected_blocks             : 8
used_blocks                 : 8
skipped_blocks              : 0
state_digest_after_absorb   : 1227930189
```

Digest result:

```text
output_digest               : 923144022
clean_digest                : 923144022
abort_digest                : 4062619770
skip_digest                 : 939952897
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 26036
dwt_cpi                     : 37
dwt_exc                     : 0
dwt_lsu                     : 0
dwt_fold                    : 2
target_cycles               : 26008
cycles_min                  : 26008
cycles_max                  : 26008
cycles_sum                  : 26008
```

Interpretation:

```text
All 8 absorb blocks are processed.
The output matches the clean reference.
The measured full absorb-loop cost is 26008 cycles.
```

---

## SHAKE256 result: loop-abort

Configuration:

```text
MODEL      = abort
STOP_BLOCK = 4
```

Semantic result:

```text
model                       : 1
model_name                  : abort
semantic_valid              : 1
output_matches_clean        : 0
output_matches_abort        : 1
output_matches_skip         : 0
stop_block                  : 4
skip_block                  : 3
faults_applied              : 1
expected_blocks             : 8
used_blocks                 : 4
skipped_blocks              : 4
state_digest_after_absorb   : 3309249061
```

Digest result:

```text
output_digest               : 4062619770
clean_digest                : 923144022
abort_digest                : 4062619770
skip_digest                 : 939952897
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 13053
dwt_cpi                     : 149
dwt_exc                     : 0
dwt_lsu                     : 19
dwt_fold                    : 3
target_cycles               : 13025
cycles_min                  : 13025
cycles_max                  : 13025
cycles_sum                  : 13025
```

Interpretation:

```text
Only the first 4 absorb blocks are processed.
The remaining 4 absorb blocks are skipped.
The output matches the loop-abort reference.
The target cycles drop from 26008 to 13025.
```

The timing ratio is:

```text
13025 / 26008 ≈ 0.501
```

which matches the block ratio:

```text
4 / 8 = 0.5
```

---

## SHAKE256 result: single-block skip

Configuration:

```text
MODEL      = skipblock
SKIP_BLOCK = 3
```

Semantic result:

```text
model                       : 2
model_name                  : skipblock
semantic_valid              : 1
output_matches_clean        : 0
output_matches_abort        : 0
output_matches_skip         : 1
stop_block                  : 4
skip_block                  : 3
faults_applied              : 1
expected_blocks             : 8
used_blocks                 : 7
skipped_blocks              : 1
state_digest_after_absorb   : 3641812543
```

Digest result:

```text
output_digest               : 939952897
clean_digest                : 923144022
abort_digest                : 4062619770
skip_digest                 : 939952897
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 22804
dwt_cpi                     : 128
dwt_exc                     : 0
dwt_lsu                     : 138
dwt_fold                    : 3
target_cycles               : 22776
cycles_min                  : 22776
cycles_max                  : 22776
cycles_sum                  : 22776
```

Interpretation:

```text
Seven absorb blocks are processed.
One target block is omitted.
The output matches the single-block-skip reference.
The target cycles drop from 26008 to 22776.
```

The timing ratio is:

```text
22776 / 26008 ≈ 0.876
```

which is close to:

```text
7 / 8 = 0.875
```

---

## SHAKE256 timing summary

```text
Mode       Used blocks  Skipped blocks  Target cycles
baseline   8            0               26008
abort      4            4               13025
skipblock  7            1               22776
```

The timing reduction tracks the number of omitted absorb blocks.

This is a strong T-type evaluation case.

---

# Part II — y-generation / polyz_unpack skipped-load attack

## Semantics

The y-generation / `polyz_unpack` attack skips one load inside the unpacking
logic.

Clean computation:

```text
load all bytes needed for the target coefficient
reconstruct the coefficient normally
```

Faulted computation:

```text
load normally until the target load result should be produced
replace the target load result with zero or a prepared stale value
perform the remaining loads normally
reconstruct the coefficient normally
```

This is a local skipped-load data fault.

It is not a loop skip and not a full `polyz_unpack` skip.

---

## Fixed stale-value semantics

The stale model uses a prepared fixed stale value.

The stale byte is supplied at build time:

```text
-DDU_STALE_FIXED_BYTE=${STALE_BYTE}
```

Inside the measured target primitive, the stale replacement uses the compile-time
constant:

```c
DU_STALE_FIXED_BYTE
```

The target primitive does not read the runtime global `du_stale_byte`.

This models the stale value as already prepared before the target load result is
consumed, similar to a stale register or known stale data value.

Therefore the measured target window does not include extra runtime-global
memory access for the stale replacement.

---

## polyz_unpack models

```text
model = 0  none / baseline
model = 1  target load result becomes zero
model = 2  target load result becomes fixed stale byte
```

Host names:

```text
none
zero
stale
```

Default configuration:

```text
TARGET_COEFF = 17
TARGET_LOAD  = 1
STALE_BYTE   = 90
```

`TARGET_LOAD` selects the local byte-load result:

```text
0 -> first byte used by the target coefficient
1 -> second byte used by the target coefficient
2 -> third byte used by the target coefficient
```

---

## polyz_unpack clean target window

The unpacking loop is split into:

```text
normal prefix coefficients
one target coefficient
normal suffix coefficients
```

The target primitive is selected outside the measured window:

```c
target_fn = du_select_target_fn();
```

The measured window contains only one target coefficient unpack primitive:

```c
trigger_high();
du_hpc_region_begin();
start = du_hpc_op_begin();

du_out[target] = target_fn(du_packed, target);

du_hpc_target_cycles = du_hpc_op_end_common(start);
du_hpc_region_end();
trigger_low();
```

The measured window does not contain:

```text
fault-model dispatch
if attack then use zero/stale
runtime stale-byte global load
prefix coefficient loop
suffix coefficient loop
digest comparison
```

This models a local skipped load without changing the control flow of every
unpacking iteration.

---

## Run polyz_unpack experiments

```bash
cd ~/hpc-cw-defense/scripts/Du_Breaking_the_Shield
./run_polyz_base.sh

MODEL=zero TARGET_COEFF=17 TARGET_LOAD=1 ./run_polyz_attack.sh
MODEL=stale TARGET_COEFF=17 TARGET_LOAD=1 STALE_BYTE=90 ./run_polyz_attack.sh
```

Other examples:

```bash
MODEL=zero TARGET_COEFF=17 TARGET_LOAD=0 ./run_polyz_attack.sh
MODEL=zero TARGET_COEFF=17 TARGET_LOAD=2 ./run_polyz_attack.sh
MODEL=stale TARGET_COEFF=42 TARGET_LOAD=1 STALE_BYTE=0x5a ./run_polyz_attack.sh
```

Changing `STALE_BYTE` changes the compile-time fixed stale value and rebuilds the
firmware for that run.

---

## polyz_unpack `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_ref
byte 3      target_load

bytes 4-7   faults_applied
bytes 8-11  target_coeff
bytes 12-15 expected_coeff_u32
bytes 16-19 used_coeff_u32
bytes 20-23 expected_load_value
bytes 24-27 used_load_value

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

For a correct baseline:

```text
faults_applied      = 0
used_load_value     = expected_load_value
used_coeff          = expected_coeff
output_matches_ref  = 1
```

For a correct zero-load attack:

```text
faults_applied      = 1
used_load_value     = 0
used_coeff          != expected_coeff
output_matches_ref  = 0
```

For a correct stale-load attack:

```text
faults_applied      = 1
used_load_value     = STALE_BYTE
used_coeff          != expected_coeff
output_matches_ref  = 0
```

---

## polyz_unpack `R` detail fields

```text
bytes 0-3    target_group
bytes 4-7    coeff_in_group
bytes 8-11   expected_partial
bytes 12-15  used_partial
```

For `TARGET_COEFF = 17`:

```text
target_group   = 4
coeff_in_group = 1
```

---

## polyz_unpack `D` digest fields

```text
bytes 0-3    output_digest
bytes 4-7    reference_digest
bytes 8-11   output_diff
bytes 12-15  message_tweak
```

Baseline:

```text
output_digest = reference_digest
output_diff   = 0
```

Effective load fault:

```text
output_digest != reference_digest
output_diff   != 0
```

---

## polyz_unpack result: baseline

Configuration:

```text
MODEL        = none
TARGET_COEFF = 17
TARGET_LOAD  = 1
```

Semantic result:

```text
model                       : 0
model_name                  : none
semantic_valid              : 1
output_matches_ref          : 1
target_load                 : 1
faults_applied              : 0
target_coeff                : 17
expected_coeff_s32          : -65079
used_coeff_s32              : -65079
expected_load_value         : 248
used_load_value             : 248
```

Detail result:

```text
target_group                : 4
coeff_in_group              : 1
expected_partial            : 196151
used_partial                : 196151
```

Digest result:

```text
output_digest               : 2193911119
reference_digest            : 2193911119
output_diff                 : 0
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 60
dwt_cpi                     : 9
dwt_exc                     : 0
dwt_lsu                     : 21
dwt_fold                    : 2
target_cycles               : 33
cycles_min                  : 33
cycles_max                  : 33
cycles_sum                  : 33
```

Interpretation:

```text
The target load is normal.
The target coefficient is reconstructed normally.
The full unpacked output matches the reference.
```

---

## polyz_unpack result: zero-load attack

Configuration:

```text
MODEL        = zero
TARGET_COEFF = 17
TARGET_LOAD  = 1
```

Semantic result:

```text
model                       : 1
model_name                  : zero
semantic_valid              : 1
output_matches_ref          : 0
target_load                 : 1
faults_applied              : 1
target_coeff                : 17
expected_coeff_s32          : -65079
used_coeff_s32              : -49207
expected_load_value         : 248
used_load_value             : 0
```

Detail result:

```text
target_group                : 4
coeff_in_group              : 1
expected_partial            : 196151
used_partial                : 180279
```

Digest result:

```text
output_digest               : 1233617743
reference_digest            : 2193911119
output_diff                 : 3410226688
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 58
dwt_cpi                     : 9
dwt_exc                     : 0
dwt_lsu                     : 21
dwt_fold                    : 2
target_cycles               : 31
cycles_min                  : 31
cycles_max                  : 31
cycles_sum                  : 31
```

Interpretation:

```text
The selected load result changes from 248 to 0.
The reconstructed target coefficient changes from -65079 to -49207.
The full unpacked output digest changes.
```

---

## polyz_unpack result: fixed stale-load attack

Configuration:

```text
MODEL        = stale
TARGET_COEFF = 17
TARGET_LOAD  = 1
STALE_BYTE   = 90
```

Semantic result:

```text
model                       : 2
model_name                  : stale
semantic_valid              : 1
output_matches_ref          : 0
target_load                 : 1
faults_applied              : 1
target_coeff                : 17
expected_coeff_s32          : -65079
used_coeff_s32              : -54967
expected_load_value         : 248
used_load_value             : 90
```

Detail result:

```text
target_group                : 4
coeff_in_group              : 1
expected_partial            : 196151
used_partial                : 186039
```

Digest result:

```text
output_digest               : 1692335567
reference_digest            : 2193911119
output_diff                 : 3860500608
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 59
dwt_cpi                     : 9
dwt_exc                     : 0
dwt_lsu                     : 21
dwt_fold                    : 2
target_cycles               : 32
cycles_min                  : 32
cycles_max                  : 32
cycles_sum                  : 32
```

Interpretation:

```text
The selected load result changes from 248 to fixed stale value 90.
The reconstructed target coefficient changes from -65079 to -54967.
The full unpacked output digest changes.
The stale model no longer incurs an extra runtime-global-load overhead in the
target window.
```

---

## polyz_unpack timing summary

```text
Mode      Target load value  Target coefficient  Target cycles
baseline  248                -65079              33
zero      0                  -49207              31
stale     90                 -54967              32
```

The semantic data change is clear.

The target-cycle differences are small because only one local load/reconstruction
primitive is measured. After the fixed-stale patch, the stale case is aligned
with the zero case and no longer shows the previous compile-artifact overhead.

This attack should mainly be interpreted as a local data-value/load fault, not
as a large timing-skip case.

---

# Combined detector interpretation

The two attacks from this paper have different detector implications.

```text
Attack                         Fault type                 Cycle signal
SHAKE256 absorb-loop abort      loop-execution fault       strong
SHAKE256 single-block skip      local loop-body skip       moderate
polyz_unpack skipped load       local data/load fault      weak or small
```

For the SHAKE256 absorb-loop attack, the measured cycles scale with skipped
absorb work:

```text
baseline   8 blocks  -> 26008 cycles
abort      4 blocks  -> 13025 cycles
skipblock  7 blocks  -> 22776 cycles
```

A cycle-threshold DWT/HPC detector is suitable when the target window is aligned
with the absorb loop.

For the `polyz_unpack` attack, the attacker changes a local load result. The
control flow is mostly preserved and the measured primitive is small:

```text
baseline 33 cycles
zero     31 cycles
stale    32 cycles
```

Cycle-only detection is not robust for this local data fault.

More appropriate defenses for `polyz_unpack` include:

```text
redundant unpacking
packed input integrity checks
coefficient consistency checks
range checks on reconstructed y coefficients
duplicate y-generation and compare
signature consistency checks
```

More appropriate defenses for SHAKE256 loop faults include:

```text
absorbed-block counters
loop-bound verification
state transcript checks
duplicate SHAKE absorb and compare
control-flow integrity for absorb loops
absorbed-length checks before squeeze
```

---

## Limitations

These are software-level semantic simulations.

They validate:

```text
SHAKE256:
    shortened absorb loop
    prefix-target-suffix block skip
    normal squeeze from the faulted state
    timing reduction proportional to skipped absorb work

polyz_unpack:
    local load-result replacement
    fixed stale value prepared outside the target window
    normal reconstruction after the replacement
    normal prefix and suffix coefficients
    changed reconstructed y coefficient
```

They are not physical EMFI, voltage-glitch, clock-glitch, laser, or Rowhammer
demonstrations.

They are not full Dilithium signing implementations.

A full implementation would hook the real SHAKE256 absorb loop and the real
`polyz_unpack` code while preserving the same semantic rules:

```text
SHAKE256 attack:
    do not skip squeeze
    do not skip the whole caller
    shorten or skip only the target absorb-loop work

polyz_unpack attack:
    do not skip the whole unpacking loop
    do not alter every unpacking iteration
    replace only the target load result
    keep the remaining loads and reconstruction logic normal
    keep stale replacement prepared outside the measured target window
```
