# Jendral, “A Single Trace Fault Injection Attack on Hedged CRYSTALS-Dilithium”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Jendral, **“A Single Trace Fault Injection Attack on Hedged
CRYSTALS-Dilithium”**.

The simulated fault is a skipped Keccak absorb call during signing-seed
generation.

The semantic change is:

```text
normal:
    absorb(prefix)
    absorb(target security-critical input)
    absorb(suffix)
    finalize / permute / squeeze

faulted:
    absorb(prefix)
    skip absorb(target security-critical input)
    absorb(suffix)
    finalize / permute / squeeze
```

The skipped absorb means part of the intended seed-generation input is not
absorbed into the Keccak state. The resulting signing seed matches the
“omit-target” reference rather than the clean reference.

---

## Important scope note

This firmware is an SRAM-safe semantic kernel.

It does not claim to be a full hedged CRYSTALS-Dilithium signing
implementation, and it does not implement the full Keccak-f1600 permutation.
Instead, it isolates the fault semantics:

```text
one security-critical absorb call is omitted
the remaining seed-generation steps still execute
the generated seed changes accordingly
```

The purpose is to evaluate both:

```text
semantic effect:
    whether the seed corresponds to the omitted-input computation

timing effect:
    whether skipping the absorb call creates a detectable T-type deviation
```

---

## Files

```text
firmware/cw-dilithium-jendral-seedabsorb/
├── Makefile
└── simpleserial-dilithium-jendral.c

scripts/Jendral_STFI_Hedged_Dilithium/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_jendral_skip_absorb.py
```

---

## Attack model

The firmware supports two runtime modes:

```text
model = 0  none / baseline
model = 1  skip target absorb
```

The host script accepts:

```text
none
skip
```

### Baseline

The target Keccak absorb call executes normally:

```text
absorb(prefix)
absorb(target)
absorb(suffix)
finalize / permute / squeeze
```

The produced seed should match the clean reference.

### Attack

The target Keccak absorb call is omitted:

```text
absorb(prefix)
skip absorb(target)
absorb(suffix)
finalize / permute / squeeze
```

The following seed-generation steps still execute normally.

The produced seed should match the omit-target reference.

---

## Clean target-window design

The target window is designed to avoid simulator-side pollution.

The target primitive is selected before the trigger and DWT/HPC window:

```c
if (jendral_model == JENDRAL_MODEL_SKIP_ABSORB) {
    target_fn = jendral_target_absorb_skipped;
    jendral_faults_applied = 1u;
    jendral_used_absorbed_target_bytes = 0u;
} else {
    target_fn = jendral_target_absorb_normal;
    jendral_faults_applied = 0u;
    jendral_used_absorbed_target_bytes = JENDRAL_TARGET_BYTES;
}
```

The measured target window contains only the selected primitive:

```c
trigger_high();
jendral_hpc_region_begin();
start = jendral_hpc_op_begin();

target_fn(jendral_state, jendral_target, JENDRAL_TARGET_BYTES);

jendral_hpc_target_cycles = jendral_hpc_op_end_common(start);
jendral_hpc_region_end();
trigger_low();
```

The measured target window does not contain:

```text
fault-model dispatch
if attack then skip
prefix absorb
suffix absorb
finalize
squeeze
```

Therefore:

```text
baseline target window:
    normal target absorb primitive

attack target window:
    skipped target absorb primitive
```

This matches the intended function-level perturbation:

```text
the target Keccak absorb call is omitted
```

---

## Remaining seed-generation steps still execute

After the target window, the firmware continues with the remaining
seed-generation steps:

```c
jendral_keccak_absorb_call(jendral_state, jendral_suffix, JENDRAL_SUFFIX_BYTES);
jendral_sponge_finalize_and_squeeze(jendral_state, jendral_seed, JENDRAL_SEED_BYTES);
```

This is important. The attack does not skip the whole seed-generation function.

It only skips the selected absorb call.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> skip

bytes 1-4   message_tweak, little endian

bytes 5-15  reserved
```

Default values:

```text
MODEL         = none or skip
MESSAGE_TWEAK = 0
```

The configuration response reports:

```text
ret
model
message_tweak
target_bytes
target_input_digest
```

In the default configuration:

```text
target_bytes = 32
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[16]     configure skipped-absorb model
K -> K[1]      initialize synthetic seed-generation input
S -> S[1]      run seed-generation experiment
H -> H[32]     semantic status
D -> D[16]     digest status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      seed_matches_clean
byte 3      seed_matches_omit

bytes 4-7   faults_applied

bytes 8-11  expected_absorbed_target_bytes
bytes 12-15 used_absorbed_target_bytes

bytes 16-19 target_input_digest
bytes 20-23 prefix_digest
bytes 24-27 suffix_digest

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

Important fields:

```text
expected_absorbed_target_bytes
    Number of target bytes that should be absorbed in the clean computation.

used_absorbed_target_bytes
    Number of target bytes actually absorbed by the selected target primitive.

seed_matches_clean
    1 if the generated seed matches the clean reference.

seed_matches_omit
    1 if the generated seed matches the reference where the target absorb is
    omitted.

faults_applied
    0 in baseline and 1 in attack.
```

For a correct skipped-absorb simulation:

```text
baseline:
    used_absorbed_target_bytes = expected_absorbed_target_bytes
    seed_matches_clean = 1
    seed_matches_omit  = 0

attack:
    used_absorbed_target_bytes = 0
    seed_matches_clean = 0
    seed_matches_omit  = 1
```

---

## `D` digest fields

```text
bytes 0-3    output_seed_digest
bytes 4-7    clean_seed_digest
bytes 8-11   omit_seed_digest
bytes 12-15  output_diff_clean
```

Important fields:

```text
output_seed_digest
    Digest of the seed generated by the selected model.

clean_seed_digest
    Digest of the seed generated by the clean reference computation.

omit_seed_digest
    Digest of the seed generated when the target absorb input is omitted.

output_diff_clean
    output_seed_digest XOR clean_seed_digest.
```

For baseline:

```text
output_seed_digest = clean_seed_digest
output_diff_clean  = 0
```

For attack:

```text
output_seed_digest = omit_seed_digest
output_diff_clean  != 0
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

In this experiment there is one measured target primitive, so normally:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

The skipped absorb is expected to create a strong timing deviation because the
normal target absorb call is omitted.

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_jendral_skip_absorb_impl.sh
```

If needed, apply the attack-runner fix so `run_attack.sh` defaults to `MODEL=skip`:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/patch_jendral_run_attack_model_skip.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Jendral_STFI_Hedged_Dilithium
./run_base.sh
```

Run attack:

```bash
./run_attack.sh
```

Equivalent explicit attack command:

```bash
MODEL=skip ./run_attack.sh
```

Other examples:

```bash
MESSAGE_TWEAK=1 ./run_base.sh
MESSAGE_TWEAK=1 MODEL=skip ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL         = none
MESSAGE_TWEAK = 0
```

Semantic result:

```text
model                         : 0
model_name                    : none
semantic_valid                : 1
seed_matches_clean            : 1
seed_matches_omit             : 0
faults_applied                : 0
expected_absorbed_target_bytes: 32
used_absorbed_target_bytes    : 32
target_input_digest           : 150943781
prefix_digest                 : 4106964325
suffix_digest                 : 248531173
defense_error                 : 0
hpc_anomaly_byte              : 0
entries                       : 1
exits                         : 1
```

Digest result:

```text
output_seed_digest            : 2322179139
clean_seed_digest             : 2322179139
omit_seed_digest              : 3418888909
output_diff_clean             : 0
```

DWT/HPC result:

```text
available                     : 3
anomaly                       : 0
region_cycles                 : 1897
dwt_cpi                       : 36
dwt_exc                       : 0
dwt_lsu                       : 12
dwt_fold                      : 2
target_cycles                 : 1870
cycles_min                    : 1870
cycles_max                    : 1870
cycles_sum                    : 1870
```

Interpretation:

```text
The target absorb executes normally.
All 32 target bytes are absorbed.
The generated seed matches the clean reference.
The generated seed does not match the omit-target reference.
The target absorb window costs 1870 cycles.
```

---

## Representative result: skipped-absorb attack

Configuration:

```text
MODEL         = skip
MESSAGE_TWEAK = 0
```

Semantic result:

```text
model                         : 1
model_name                    : skip
semantic_valid                : 1
seed_matches_clean            : 0
seed_matches_omit             : 1
faults_applied                : 1
expected_absorbed_target_bytes: 32
used_absorbed_target_bytes    : 0
target_input_digest           : 150943781
prefix_digest                 : 4106964325
suffix_digest                 : 248531173
defense_error                 : 0
hpc_anomaly_byte              : 0
entries                       : 1
exits                         : 1
```

Digest result:

```text
output_seed_digest            : 3418888909
clean_seed_digest             : 2322179139
omit_seed_digest              : 3418888909
output_diff_clean             : 1101119118
```

DWT/HPC result:

```text
available                     : 3
anomaly                       : 0
region_cycles                 : 41
dwt_cpi                       : 6
dwt_exc                       : 0
dwt_lsu                       : 21
dwt_fold                      : 2
target_cycles                 : 14
cycles_min                    : 14
cycles_max                    : 14
cycles_sum                    : 14
```

Interpretation:

```text
The target absorb call is skipped.
Zero target bytes are absorbed.
The generated seed does not match the clean reference.
The generated seed matches the omit-target reference.
The following seed-generation steps still execute.
```

The timing deviation is strong:

```text
baseline target_cycles = 1870
attack   target_cycles = 14
```

---

## Summary table

```text
Mode      Faults  Absorbed target bytes  Matches clean  Matches omit  Output diff clean  Target cycles
baseline  0       32                     yes            no            0                  1870
attack    1       0                      no             yes           1101119118         14
```

The semantic effect is clear, and the target-window timing deviation is large.

---

## Detector interpretation

This skipped-absorb model is both semantically successful and timing-visible.

Semantic effect:

```text
output_seed_digest = omit_seed_digest
output_seed_digest != clean_seed_digest
```

Timing effect:

```text
baseline target_cycles = 1870
attack   target_cycles = 14
```

Therefore, this is a strong T-type evaluation case for DWT/HPC-style detection.

A cycle-threshold detector can detect this specific skipped absorb call if the
target window is aligned with the security-critical absorb operation.

Example threshold logic:

```text
if target_cycles << expected_absorb_cycles:
    report skipped absorb
```

More robust defenses include:

```text
redundant absorb-call sequencing
absorbed-length accounting
domain-separated transcript counters
seed-generation transcript hash/checksum
duplicate seed generation and compare
post-signing consistency checks tied to the hedged seed inputs
```

The key point is that this fault changes the function-level execution of the
seed-generation transcript. Unlike pure data-corruption faults, the skipped
absorb call creates a measurable timing gap.

---

## Limitations

This is a software-level semantic simulation.

It validates:

```text
prefix absorb executes
target absorb call is omitted under attack
suffix absorb executes
finalize / permutation / squeeze execute
generated seed matches omit-target reference
target absorb timing drops strongly
```

It is not a physical EMFI, voltage-glitch, clock-glitch, or laser fault
demonstration.

It is not a full hedged Dilithium signing implementation.

It uses a Keccak-like sponge stand-in rather than a full Keccak-f1600
implementation, because the goal is to isolate the skipped-absorb semantics and
its DWT/HPC timing signature.

A full implementation would hook the actual signing-seed generation code while
preserving the same semantic rule:

```text
omit only the target Keccak absorb call
continue with the remaining permutation and squeeze steps
do not skip the whole seed-generation function
do not add simulator-side branch logic inside the target window
```
