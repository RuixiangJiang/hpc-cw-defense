# Wang et al., “Secret in OnePiece”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Wang et al., **“Secret in OnePiece”**.

The simulated fault targets a bitsliced masked decoder.

The core semantic change is:

```text
normal:
    insert one decoded bit into the destination word

faulted:
    skip the target bit assignment / OR operation
    leave the destination word unchanged
    continue the decoder normally
```

The target bit is therefore not inserted into the destination word. The
destination keeps its previous or stale value at that bit position.

---

## Important scope note

This firmware is an SRAM-safe semantic kernel.

It does not claim to be a full masked Dilithium decoder implementation from the
paper. Instead, it isolates the relevant dataflow:

```text
bitsliced source words
destination words
bit insertion / assignment
skipped bit insertion
normal prefix and suffix decoding
```

The purpose is to model the local skipped assignment / skipped OR operation in a
clean and measurable way.

---

## Files

```text
firmware/cw-dilithium-wang-onepiece/
├── Makefile
└── simpleserial-wang-onepiece.c

scripts/Wang_Secret_in_OnePiece/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
├── test_wang_onepiece_decoder.py
└── readme.md
```

---

## Fault model

The firmware supports two runtime modes:

```text
model = 0  none / baseline
model = 1  skipped bit insertion
```

The host script accepts:

```text
none
skip
```

Default target:

```text
TARGET_WORD  = 17
TARGET_BIT   = 5
PREVIOUS_BIT = 0
```

The default target is chosen so that the source bit differs from the stale
destination bit. This makes the skipped insertion visible.

---

## Decoder model

The synthetic decoder reconstructs an array of 16-bit destination words.

Constants:

```text
ONEPIECE_NWORDS      = 128
ONEPIECE_WORD_BITS   = 16
TOTAL_INSERTIONS     = 2048
```

The full decoding sequence is logically:

```text
for word in 0 .. 127:
    for bit in 0 .. 15:
        insert source bit into destination word
```

For a loop-internal target, the nested loop is flattened into a single linear
index:

```text
target_linear = target_word * 16 + target_bit
```

For the default target:

```text
target_word   = 17
target_bit    = 5
target_linear = 277
```

---

## Correct simulation structure

The decoder is split into three semantic regions:

```text
normal prefix insertions
one target insertion
normal suffix insertions
```

This avoids adding a target-check branch inside every loop iteration.

The baseline target primitive is:

```c
onepiece_insert_bit_normal(dst, bit, bitpos)
```

The attack target primitive is:

```c
onepiece_insert_bit_skip(dst, bit, bitpos)
```

The skipped primitive directly models a skipped assignment or skipped OR
operation:

```c
static uint16_t onepiece_insert_bit_skip(uint16_t dst,
                                         unsigned int bit,
                                         unsigned int bitpos)
{
    (void)bit;
    (void)bitpos;

    return dst;
}
```

So the destination word remains unchanged at the target insertion point.

---

## Clean target-window design

The target primitive is selected outside the trigger/DWT window:

```c
if (onepiece_model == ONEPIECE_MODEL_SKIP) {
    target_fn = onepiece_insert_bit_skip;
    onepiece_faults_applied = 1u;
} else {
    target_fn = onepiece_insert_bit_normal;
    onepiece_faults_applied = 0u;
}
```

The measured target window contains exactly one bit-insertion primitive:

```c
trigger_high();
onepiece_hpc_region_begin();
start = onepiece_hpc_op_begin();

used_word = target_fn(before, bit, target_bit);

onepiece_hpc_target_cycles = onepiece_hpc_op_end_common(start);
onepiece_hpc_region_end();
trigger_low();
```

The target window does not contain:

```text
fault-model dispatch
if attack then skip
target-check branch inside every loop iteration
prefix decoding
suffix decoding
digest comparison
host-side bookkeeping
```

This prevents target-window pollution.

---

## Runtime configuration

The `F` command configures the experiment.

Payload layout:

```text
byte 0      model
            0 -> none
            1 -> skip

bytes 1-2   target_word, little endian

byte 3      target_bit

byte 4      previous_bit
            stale destination bit before the target insertion

bytes 5-8   message_tweak, little endian

bytes 9-15  reserved
```

Default configuration:

```text
MODEL        = none or skip
TARGET_WORD  = 17
TARGET_BIT   = 5
PREVIOUS_BIT = 0
MESSAGE_TWEAK = 0
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[24]     configure decoder fault model
K -> K[1]      initialize synthetic decoder input/state
S -> S[1]      run bitsliced decoder experiment
H -> H[32]     semantic status
D -> D[16]     digest status
R -> R[16]     prefix/suffix detail status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      model
byte 1      semantic_valid
byte 2      output_matches_ref
byte 3      target_bit

bytes 4-7   faults_applied
bytes 8-11  target_word
bytes 12-15 target_linear
bytes 16-19 expected_word
bytes 20-23 used_word

byte 24     expected_bit
byte 25     used_bit
byte 26     stale_bit
byte 27     source_bit
byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     entries
byte 31     exits
```

Important fields:

```text
expected_word
    Destination word after the normal target insertion.

used_word
    Destination word after the selected target primitive.

expected_bit
    Target bit after normal insertion.

used_bit
    Target bit after the selected target primitive.

stale_bit
    Target bit in the destination word before the target insertion.

source_bit
    Source bit that should be inserted.
```

For a correct baseline:

```text
faults_applied     = 0
expected_word      = used_word
expected_bit       = used_bit
output_matches_ref = 1
```

For a correct skipped-insertion attack:

```text
faults_applied     = 1
used_word          = word_before_target
used_bit           = stale_bit
used_bit          != expected_bit
output_matches_ref = 0
```

---

## `R` detail fields

```text
bytes 0-3    prefix_count
bytes 4-7    suffix_count
bytes 8-11   total_insertions
bytes 12-15  word_before_target
```

For the default target:

```text
prefix_count     = 277
suffix_count     = 1770
total_insertions = 2048
```

The counts satisfy:

```text
prefix_count + 1 + suffix_count = total_insertions
```

This confirms the prefix-target-suffix structure.

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

For a semantically effective skipped insertion:

```text
output_digest != reference_digest
output_diff   != 0
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

Only one target insertion primitive is measured, so normally:

```text
target_cycles = cycles_min = cycles_max = cycles_sum
```

---

## Build and run

Install the experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_wang_secret_in_onepiece_impl.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Wang_Secret_in_OnePiece
./run_base.sh
```

Run default skipped-insertion attack:

```bash
./run_attack.sh
```

Equivalent explicit command:

```bash
MODEL=skip TARGET_WORD=17 TARGET_BIT=5 PREVIOUS_BIT=0 ./run_attack.sh
```

Try other targets:

```bash
TARGET_WORD=42 TARGET_BIT=7 PREVIOUS_BIT=1 ./run_attack.sh
TARGET_WORD=10 TARGET_BIT=3 PREVIOUS_BIT=0 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
MODEL        = none
TARGET_WORD  = 17
TARGET_BIT   = 5
PREVIOUS_BIT = 0
```

Semantic result:

```text
model                       : 0
model_name                  : none
semantic_valid              : 1
output_matches_ref          : 1
target_bit                  : 5
faults_applied              : 0
target_word                 : 17
target_linear               : 277
expected_word               : 38
used_word                   : 38
expected_bit                : 1
used_bit                    : 1
stale_bit                   : 0
source_bit                  : 1
```

Detail result:

```text
prefix_count                : 277
suffix_count                : 1770
total_insertions            : 2048
word_before_target          : 6
```

Digest result:

```text
output_digest               : 4292645210
reference_digest            : 4292645210
output_diff                 : 0
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 52
dwt_cpi                     : 7
dwt_exc                     : 0
dwt_lsu                     : 25
dwt_fold                    : 2
target_cycles               : 25
cycles_min                  : 25
cycles_max                  : 25
cycles_sum                  : 25
```

Interpretation:

```text
The target bit is inserted normally.
word_before_target = 6
normal insertion sets bit 5 to 1
used_word = expected_word = 38
```

---

## Representative result: skipped bit insertion

Configuration:

```text
MODEL        = skip
TARGET_WORD  = 17
TARGET_BIT   = 5
PREVIOUS_BIT = 0
```

Semantic result:

```text
model                       : 1
model_name                  : skip
semantic_valid              : 1
output_matches_ref          : 0
target_bit                  : 5
faults_applied              : 1
target_word                 : 17
target_linear               : 277
expected_word               : 38
used_word                   : 6
expected_bit                : 1
used_bit                    : 0
stale_bit                   : 0
source_bit                  : 1
```

Detail result:

```text
prefix_count                : 277
suffix_count                : 1770
total_insertions            : 2048
word_before_target          : 6
```

Digest result:

```text
output_digest               : 3819102202
reference_digest            : 4292645210
output_diff                 : 478039712
```

DWT/HPC result:

```text
available                   : 3
anomaly                     : 0
region_cycles               : 45
dwt_cpi                     : 7
dwt_exc                     : 0
dwt_lsu                     : 25
dwt_fold                    : 2
target_cycles               : 18
cycles_min                  : 18
cycles_max                  : 18
cycles_sum                  : 18
```

Interpretation:

```text
The target bit insertion is skipped.
The destination word remains unchanged at word_before_target = 6.
The target bit keeps stale_bit = 0 instead of being updated to 1.
The final decoded output digest changes.
```

---

## Timing summary

```text
Mode      expected_bit  used_bit  expected_word  used_word  target_cycles
baseline  1             1         38             38         25
skip      1             0         38             6          18
```

The attack saves only a small number of cycles because it skips one local
assignment/OR operation, not the full decoder loop.

This is the expected behavior for a local skipped bit insertion.

---

## Detector interpretation

This attack is a local decoder data-construction fault.

It is not a full decoder-loop skip.

The timing signal is local:

```text
baseline target_cycles = 25
skip     target_cycles = 18
```

A cycle-only DWT/HPC detector may detect this particular clean skipped insertion
if the target window is tightly aligned with the bit assignment / OR primitive.
However, the cycle difference is small and may be fragile across compiler
settings or target microarchitectures.

More robust defenses include:

```text
redundant bitsliced decoding
decoded-word consistency checks
bit-slice parity checks
masked decoder recomputation and compare
range or domain checks on decoded values
control-flow integrity for decoder assignment sequences
invariant checks on reconstructed destination words
```

---

## Why this is not target-window pollution

The target operation is loop-internal, but the implementation does not add:

```text
if current_index == target
```

inside every iteration.

Instead, it applies:

```text
normal prefix
one target primitive
normal suffix
```

The measured target window contains only:

```text
onepiece_insert_bit_normal(...)
```

or:

```text
onepiece_insert_bit_skip(...)
```

There is no dispatch, target-check branch, digest computation, prefix loop, or
suffix loop inside the measured target window.

Therefore the observed timing difference corresponds to the skipped assignment /
OR primitive itself.

---

## Limitations

This is a software-level semantic simulation.

It validates:

```text
normal prefix decoding
one target bit assignment / OR operation
skipped target assignment leaving destination unchanged
normal suffix decoding
changed decoded output
small local cycle reduction
```

It is not a physical EMFI, voltage-glitch, clock-glitch, or laser fault
demonstration.

It is not a full masked Dilithium decoder.

A full implementation would hook the actual bitsliced masked decoder while
preserving the same semantic rule:

```text
do not skip the whole decoder
do not add a target-check branch inside every loop iteration
flatten nested loop targets into a linear index if needed
split the decoder into normal prefix, one target operation, and normal suffix
fault only the target bit assignment / OR operation
let the destination word keep its previous or stale bit
```
