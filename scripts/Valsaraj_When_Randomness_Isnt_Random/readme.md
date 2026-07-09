# Valsaraj et al., “When Randomness Isn’t Random”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Valsaraj et al., **“When Randomness Isn’t Random”**.

The simulated fault changes the seed input consumed by the sampler.

The core semantic change is:

```text
normal:
    derive the intended seed pointer
    form SHAKE input using the intended seed
    run SHAKE and sampling normally

faulted:
    derive or redirect the seed pointer incorrectly
    form SHAKE input using the wrong seed
    run SHAKE and sampling normally
```

The sampler is not skipped.

The SHAKE input formation and sampling routine still run normally, but they
consume the wrong seed input.

---

## Important scope note

This firmware is an SRAM-safe semantic kernel.

It does not claim to be a full Dilithium signing implementation. Instead, it
isolates the relevant dataflow:

```text
seed selection
seed pointer derivation
SHAKE input formation
sampling from selected seed
```

The purpose is to preserve the semantic distinction between:

```text
seed-selection fault
```

and:

```text
sampler execution fault
```

This experiment models the attack as a wrong-data-source fault. It is not a
sampler skip, SHAKE skip, or loop-abort attack.

---

## Files

```text
firmware/cw-dilithium-valsaraj-wrongseed/
├── Makefile
└── simpleserial-dilithium-valsaraj-wrongseed.c

scripts/Valsaraj_When_Randomness_Isnt_Random/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_valsaraj_wrong_seed.py
```

---

## Fault models

The firmware supports four runtime modes:

```text
model = 0  none / baseline
model = 1  pointer-offset skip
model = 2  wrong-domain fault
model = 3  pointer redirection
```

The host script accepts:

```text
none
offsetskip
wrongdomain
redirect
```

Default attack:

```text
MODEL = offsetskip
```

Default domains:

```text
INTENDED_DOMAIN = 2
WRONG_DOMAIN    = 1
```

---

## Attack semantics

### Baseline

The sampler consumes the intended domain seed:

```text
selected_seed = seed_pool[intended_domain]
SHAKE input formation runs normally
sampling runs normally
```

Default:

```text
intended_domain = 2
```

### Pointer-offset skip

The intended domain offset is not applied.

Instead of:

```text
seed_pool + intended_domain * SEED_BYTES
```

the faulted pointer derivation returns:

```text
seed_pool + 0
```

In the firmware:

```c
static const uint8_t *valsaraj_seedptr_offset_skip(unsigned int domain)
{
    (void)domain;
    return &valsaraj_seed_pool[0][0];
}
```

The sampler still runs normally on that selected seed pointer.

### Wrong-domain fault

The seed pointer is derived using a wrong domain index.

Instead of:

```text
seed_pool[intended_domain]
```

the selected seed is:

```text
seed_pool[wrong_domain]
```

In the firmware:

```c
static const uint8_t *valsaraj_seedptr_wrong_domain(unsigned int wrong_domain)
{
    if (wrong_domain >= VALSARAJ_NUM_DOMAINS) {
        wrong_domain = 0u;
    }

    return &valsaraj_seed_pool[wrong_domain][0];
}
```

The sampler still runs normally.

### Pointer redirection

The seed pointer is redirected to a known or attacker-controlled buffer:

```text
selected_seed = redirect_seed
```

In the firmware:

```c
static const uint8_t *valsaraj_seedptr_redirect(void)
{
    return &valsaraj_redirect_seed[0];
}
```

The sampler still runs normally on the redirected seed.

---

## Correct simulation structure

The simulation follows the requested attack semantics:

```text
1. Initialize seed pool normally.

2. Select the seed pointer.
   - baseline: intended domain seed
   - offsetskip: base seed pointer
   - wrongdomain: wrong domain seed
   - redirect: attacker-controlled seed buffer

3. Start trigger and DWT/HPC measurement.

4. Run the normal SHAKE input formation and sampling primitive using the
   selected seed pointer.

5. Stop DWT/HPC measurement.

6. Compare the output against clean, offsetskip, wrongdomain, and redirect
   references.
```

The key distinction is:

```text
the seed pointer changes before sampling
the sampler itself is unchanged
```

---

## Clean target-window design

Seed selection is outside the target window:

```c
if (valsaraj_model == VALSARAJ_MODEL_OFFSET_SKIP) {
    selected_seed = valsaraj_seedptr_offset_skip(valsaraj_intended_domain);
    valsaraj_used_domain = 0u;
    valsaraj_faults_applied = 1u;
} else if (valsaraj_model == VALSARAJ_MODEL_WRONG_DOMAIN) {
    selected_seed = valsaraj_seedptr_wrong_domain(valsaraj_wrong_domain);
    valsaraj_used_domain = valsaraj_wrong_domain;
    valsaraj_faults_applied = 1u;
} else if (valsaraj_model == VALSARAJ_MODEL_REDIRECT) {
    selected_seed = valsaraj_seedptr_redirect();
    valsaraj_used_domain = VALSARAJ_REDIRECT_DOMAIN_ID;
    valsaraj_faults_applied = 1u;
} else {
    selected_seed = valsaraj_seedptr_normal(valsaraj_intended_domain);
    valsaraj_used_domain = valsaraj_intended_domain;
    valsaraj_faults_applied = 0u;
}
```

The measured target window contains only the normal sampler primitive:

```c
trigger_high();
valsaraj_hpc_region_begin();
start = valsaraj_hpc_op_begin();

valsaraj_shake_and_sample_normal(selected_seed,
                                 valsaraj_intended_domain,
                                 valsaraj_sample_out);

valsaraj_hpc_target_cycles = valsaraj_hpc_op_end_common(start);
valsaraj_hpc_region_end();
trigger_low();
```

The measured target window does not contain:

```text
fault-model dispatch
if attack then use wrong seed
pointer derivation
seed-pool initialization
digest comparison
```

Therefore, baseline and attack should have the same target-window cycle count,
unless the sampler implementation itself has data-dependent timing.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> offsetskip
            2 -> wrongdomain
            3 -> redirect

byte 1      intended_domain

byte 2      wrong_domain

bytes 3-6   message_tweak, little endian

bytes 7-15  reserved
```

Default values:

```text
MODEL           = none or offsetskip
INTENDED_DOMAIN = 2
WRONG_DOMAIN    = 1
MESSAGE_TWEAK   = 0
```

The configuration response reports:

```text
ret
model
intended_domain
wrong_domain
message_tweak
num_domains
seed_bytes
output_coeffs
expected_seed_digest
```

Default constants:

```text
VALSARAJ_NUM_DOMAINS    = 4
VALSARAJ_SEED_BYTES     = 32
VALSARAJ_OUTPUT_COEFFS  = 256
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[24]     configure wrong-seed model
K -> K[1]      initialize synthetic seed pool
S -> S[1]      run sampler on selected seed
H -> H[32]     semantic status
D -> D[20]     digest status
R -> R[16]     redirect/domain detail status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_clean
byte 3      output_matches_offset
byte 4      output_matches_wrong
byte 5      output_matches_redirect
byte 6      expected_domain
byte 7      used_domain

bytes 8-11   faults_applied
bytes 12-15  expected_seed_digest
bytes 16-19  used_seed_digest
bytes 20-23  base_seed_digest
bytes 24-27  wrong_seed_digest

byte 28       defense_error
byte 29       hpc_anomaly_byte
byte 30       entries
byte 31       exits
```

Important fields:

```text
expected_domain
    The intended domain index.

used_domain
    The domain actually used by seed selection.
    For redirect mode, this is 255.

expected_seed_digest
    Digest of the intended seed.

used_seed_digest
    Digest of the seed actually consumed by the sampler.

base_seed_digest
    Digest of seed_pool[0], used by offsetskip.

wrong_seed_digest
    Digest of seed_pool[wrong_domain], used by wrongdomain.

output_matches_clean
    1 if the sampled output matches the clean intended-seed reference.

output_matches_offset
    1 if the sampled output matches the offsetskip reference.

output_matches_wrong
    1 if the sampled output matches the wrong-domain reference.

output_matches_redirect
    1 if the sampled output matches the redirected-seed reference.
```

For a correct baseline:

```text
faults_applied = 0
used_domain = expected_domain
used_seed_digest = expected_seed_digest
output_matches_clean = 1
```

For a correct offsetskip attack:

```text
faults_applied = 1
used_domain = 0
used_seed_digest = base_seed_digest
output_matches_offset = 1
```

For a correct wrongdomain attack:

```text
faults_applied = 1
used_domain = wrong_domain
used_seed_digest = wrong_seed_digest
output_matches_wrong = 1
```

For a correct redirect attack:

```text
faults_applied = 1
used_domain = 255
used_seed_digest = redirect_seed_digest
output_matches_redirect = 1
```

---

## `D` digest fields

```text
bytes 0-3    output_digest
bytes 4-7    clean_digest
bytes 8-11   offset_digest
bytes 12-15  wrong_digest
bytes 16-19  redirect_digest
```

For baseline:

```text
output_digest = clean_digest
```

For offsetskip:

```text
output_digest = offset_digest
output_digest != clean_digest
```

For wrongdomain:

```text
output_digest = wrong_digest
output_digest != clean_digest
```

For redirect:

```text
output_digest = redirect_digest
output_digest != clean_digest
```

---

## `R` detail fields

```text
bytes 0-3    redirect_seed_digest
bytes 4-7    message_tweak
bytes 8-11   intended_domain
bytes 12-15  wrong_domain
```

The redirect seed digest is used to verify pointer redirection mode.

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

There is one measured target sampler primitive, so normally:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

Since the same sampler primitive is executed in baseline and attack, the
expected timing behavior is:

```text
baseline target_cycles ≈ attack target_cycles
```

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_valsaraj_when_randomness_isnt_random_impl.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Valsaraj_When_Randomness_Isnt_Random
./run_base.sh
```

Run the default offsetskip attack:

```bash
./run_attack.sh
```

Equivalent explicit command:

```bash
MODEL=offsetskip ./run_attack.sh
```

Run other models:

```bash
MODEL=wrongdomain WRONG_DOMAIN=1 ./run_attack.sh
MODEL=redirect ./run_attack.sh
```

Try other domains:

```bash
INTENDED_DOMAIN=3 MODEL=offsetskip ./run_attack.sh
INTENDED_DOMAIN=3 MODEL=wrongdomain WRONG_DOMAIN=0 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL           = none
INTENDED_DOMAIN = 2
WRONG_DOMAIN    = 1
```

DWT/HPC result:

```text
available                     : 3
anomaly                       : 0
region_cycles                 : 324265
dwt_cpi                       : 101
dwt_exc                       : 0
dwt_lsu                       : 251
dwt_fold                      : 2
target_cycles                 : 324237
cycles_min                    : 324237
cycles_max                    : 324237
cycles_sum                    : 324237
```

Interpretation:

```text
The intended seed pointer is selected.
The normal SHAKE + sampling primitive runs on the intended seed.
The sampler target window costs 324237 cycles.
```

---

## Representative result: pointer-offset skip attack

Configuration:

```text
MODEL           = offsetskip
INTENDED_DOMAIN = 2
WRONG_DOMAIN    = 1
```

DWT/HPC result:

```text
available                     : 3
anomaly                       : 0
region_cycles                 : 324265
dwt_cpi                       : 101
dwt_exc                       : 0
dwt_lsu                       : 251
dwt_fold                      : 2
target_cycles                 : 324237
cycles_min                    : 324237
cycles_max                    : 324237
cycles_sum                    : 324237
```

Interpretation:

```text
The seed pointer is derived incorrectly.
The intended domain offset is skipped.
The sampler consumes seed_pool[0] instead of seed_pool[2].
The normal SHAKE + sampling primitive still runs.
The sampler target window still costs 324237 cycles.
```

This is the expected behavior for a wrong-seed data-source fault.

---

## Timing summary

```text
Mode        Intended domain  Used seed source      Target cycles
baseline    2                seed_pool[2]          324237
offsetskip  2                seed_pool[0]          324237
```

The target-window timing does not change because the sampler execution is the
same.

---

## Why this result is reasonable

The observed result:

```text
baseline   target_cycles = 324237
offsetskip target_cycles = 324237
```

is reasonable because:

```text
1. Seed selection happens before the measured target window.
2. The fault changes the seed pointer, not the sampler control flow.
3. The measured window calls the same normal SHAKE + sampling primitive in both
   baseline and attack.
4. The sampler loop bounds and operation sequence are unchanged.
5. The attack is a wrong-input / wrong-data-source fault, not a T-type skipped
   sampler.
```

Therefore, a pure cycle-threshold detector should not be expected to catch this
fault under the clean-window implementation.

---

## Detector interpretation

This attack is a seed-selection / data-source fault.

It is not a sampler skip.

Under the clean-window implementation:

```text
baseline target_cycles   = 324237
offsetskip target_cycles = 324237
```

Cycle-only DWT/HPC detection is weak for this model.

The semantic output changes because the sampler consumes the wrong seed, but the
measured instruction sequence remains the same.

More appropriate defenses include:

```text
seed pointer range checks
domain-index validation
domain-separated seed derivation checks
absorbed seed digest or checksum
redundant seed-pointer derivation
duplicate sampling from verified seed source
seed transcript binding
fault-resistant domain separation
```

A DWT/HPC detector can still detect related T-type attacks that skip the sampler
or shorten SHAKE, but it is not suitable as the only defense against a clean
wrong-seed pointer-selection fault.

---

## Limitations

This is a software-level semantic simulation.

It validates:

```text
normal seed-pool initialization
wrong seed-pointer derivation under fault
normal SHAKE input formation
normal sampling on the selected seed pointer
unchanged sampler target-window cycle count
```

It is not a physical EMFI, voltage-glitch, clock-glitch, Rowhammer, or laser
fault demonstration.

It is not a full Dilithium signing implementation.

A full implementation would hook the actual sampler seed derivation path while
preserving the same semantic rule:

```text
for pointer-offset skip:
    return the base seed pointer without applying the intended offset

for wrong-domain fault:
    derive the seed pointer using the wrong domain index

for pointer redirection:
    redirect the seed pointer to a known/attacker-controlled buffer

for all cases:
    run SHAKE input formation and sampling normally on the selected seed
    do not skip the sampler
    do not skip SHAKE
    do not add simulator-side branch logic inside the measured sampler window
```
