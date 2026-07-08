# Islam et al., “Signature Correction Attack on Dilithium Signature Scheme”

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Islam et al., **“Signature Correction Attack on Dilithium
Signature Scheme”**.

The simulated fault is a **data corruption fault** on the Dilithium secret-key
component `s1`.

It is **not** an instruction skip.

The semantic model is:

```text
s1' = s1 + Δs1
```

or, at the packed secret-key byte level used by this experiment:

```text
sk[s1_base + byte_offset] ^= bit_mask
```

The signing computation then consumes the already-corrupted in-memory secret
key, while the target-window control flow remains unchanged.

---

## Important scope note

On the CW308_STM32F3 / CWLITEARM target, full Dilithium2 key generation and full
Dilithium2 signing exceed the available stack/SRAM budget. The experiment
therefore uses an SRAM-safe semantic kernel by default.

The default firmware does **not** claim to execute a full Dilithium signature.

Instead, it implements the key semantic requirement of the Islam et al. attack:

```text
1. construct an in-memory packed Dilithium-style secret key;
2. flip one selected bit inside the packed s1 region before the target window;
3. run a target computation that consumes the already-corrupted s1 bytes;
4. restore the flipped secret-key bit after the target computation.
```

The experiment is therefore a controlled **s1 data-corruption simulation**, not a
full physical Rowhammer demonstration and not a full Dilithium signing
reproduction.

The attack logic itself is preserved:

```text
fault before signing/target computation
unchanged target-window control flow
secret-key bit restoration after signing/target computation
```

---

## Files

```text
firmware/cw-dilithium-islam-s1bitflip/
├── Makefile
└── simpleserial-dilithium-islam.c

scripts/Islam_Signature_Correction_Attack/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
└── test_dilithium_islam_s1_bitflip.py
```

Additional patch scripts used during bring-up:

```text
patch_islam_deterministic_sk.sh
force_patch_islam_sram_safe_cmd_sign.sh
```

The final working version uses:

```text
deterministic packed secret-key material
SRAM-safe s1-consumption kernel
```

---

## Secret-key layout

The pqm4 Dilithium2 secret key is packed as:

```text
rho || key || tr || s1 || s2 || t0
```

The packed `s1` region starts after three seed-sized fields:

```text
s1_base_offset = 3 * SEEDBYTES
               = 3 * 32
               = 96
```

For Dilithium2:

```text
L = 4
ETA = 2
POLYETA_PACKEDBYTES = 96
s1_bytes = L * POLYETA_PACKEDBYTES
         = 4 * 96
         = 384
```

So the attackable packed `s1` region is:

```text
sk[96 ... 479]
```

A runtime parameter selects the byte inside this region:

```text
abs_sk_offset = 96 + S1_BYTE_OFFSET
```

---

## Fault model

The runtime-configured fault is:

```text
sk[abs_sk_offset] ^= BIT_MASK
```

where:

```text
abs_sk_offset = 3 * SEEDBYTES + S1_BYTE_OFFSET
```

Example:

```text
S1_BYTE_OFFSET = 0
BIT_MASK       = 1
```

flips:

```text
sk[96] ^= 0x01
```

The fault is injected before the measured target computation starts.

After the target computation completes, the firmware restores the byte by
applying the same XOR again:

```text
sk[abs_sk_offset] ^= BIT_MASK
```

when:

```text
RESTORE_AFTER_SIGN = 1
```

---

## Target-window structure

The target-window structure is:

```text
apply s1 bit flip before target window
↓
trigger_high()
start DWT/HPC measurement
run target computation consuming sk.s1
end DWT/HPC measurement
trigger_low()
↓
restore s1 bit after target window
```

In code, the effective working structure is:

```c
islam_apply_s1_bitflip_before_signing();

trigger_high();
islam_hpc_sign_begin();

islam_sign_ret =
    islam_force_sram_safe_s1_kernel(islam_sig,
                                    &islam_sig_len,
                                    islam_msg,
                                    islam_msg_len,
                                    islam_sk);

islam_hpc_sign_end();
trigger_low();

islam_restore_s1_bit_after_signing();
```

The target computation contains no branch on `islam_fault_enable`.

Therefore the measured target window is not polluted by simulator logic such as:

```c
if (attack) {
    flip secret key bit;
}
```

The fault already exists in memory before the target computation starts.

---

## SRAM-safe s1-consumption kernel

The final working target kernel is:

```c
islam_force_sram_safe_s1_kernel(...)
```

It reads the packed `s1` region from the current in-memory secret key:

```c
const uint8_t *s1 = sk + ISLAM_S1_OFFSET;
```

and consumes all packed `s1` bytes:

```c
for (i = 0; i < ISLAM_S1_BYTES; i++) {
    uint32_t x = (uint32_t)s1[i];
    acc += x ^ (uint32_t)(i * 0x45d9f3bu);
    acc ^= acc << 13;
    acc ^= acc >> 17;
    acc ^= acc << 5;
    sig[i & 63u] ^= (uint8_t)(x ^ (acc >> ((i & 3u) * 8u)));
}
```

This is not a Dilithium signature algorithm. It is a compact target computation
whose purpose is to expose the dataflow effect of the pre-signing `s1` bit flip:

```text
baseline target reads original s1
attack target reads corrupted s1'
```

The important property is that the target computation is identical in baseline
and attack. Only the in-memory data differs.

---

## Why full keypair/signing were not used by default

The first implementation tried to execute:

```c
crypto_sign_keypair(...)
crypto_sign_signature(...)
```

on CW308_STM32F3.

Observed behavior:

```text
K->K no response
```

for the full keypair path, indicating stack/SRAM failure.

After replacing keypair with deterministic packed key material, the next failure
was:

```text
S->S no response
```

for the full signing path, indicating that full signing also exceeds the small
target’s memory budget.

Therefore the final default experiment uses:

```text
deterministic packed secret key
SRAM-safe target computation consuming sk.s1
```

This keeps the attack semantics but avoids changing `sign.c`, the signing loop,
or the `z`-generation code.

---

## Runtime configuration

The SimpleSerial `F` command configures the fault.

Payload layout:

```text
byte 0      fault_enable
            0 -> baseline
            1 -> attack

bytes 1-2   S1_BYTE_OFFSET, little endian

byte 3      BIT_MASK

byte 4      RESTORE_AFTER_SIGN
            0 -> do not restore corrupted secret-key byte
            1 -> restore after target computation

byte 5      VERIFY_AFTER_SIGN
            currently unused in SRAM-safe default path

bytes 6-15  reserved
```

The response reports:

```text
byte 0      return code
byte 1      fault_enable
bytes 2-3   normalized S1_BYTE_OFFSET
byte 4      BIT_MASK
byte 5      RESTORE_AFTER_SIGN
byte 6      VERIFY_AFTER_SIGN
byte 7      reserved
bytes 8-11  s1_base_offset
bytes 12-13 s1_bytes
bytes 14-15 reserved
```

Representative configuration response:

```text
fault_enable       = 0
s1_byte_offset     = 0
bit_mask           = 1
restore_after_sign = 1
s1_base_offset     = 96
s1_bytes           = 384
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[16]     configure s1 bit-flip model
K -> K[1]      construct deterministic packed secret key
M -> M[1]      upload message
S -> S[1]      run target computation
H -> H[32]     semantic status
Y -> Y[32]     DWT/HPC status
```

---

## `H` status fields

```text
byte 0      keypair_ret
byte 1      sign_ret
byte 2      verify_ret_u8
byte 3      semantic_valid

bytes 4-7   faults_applied

byte 8      fault_enable
bytes 9-10  s1_byte_offset
byte 11     bit_mask

bytes 12-15 abs_sk_offset

byte 16     byte_before
byte 17     byte_faulted
byte 18     byte_after
byte 19     restore_ok

bytes 20-23 sig_len
bytes 24-27 sig_digest

byte 28     defense_error
byte 29     hpc_anomaly_byte
byte 30     restore_after_sign
byte 31     verify_after_sign
```

Important fields:

```text
byte_before
    Secret-key byte before the fault is injected.

byte_faulted
    Secret-key byte consumed by the target computation.

byte_after
    Secret-key byte after post-computation restoration.

restore_ok
    1 means byte_after == byte_before.

sig_digest
    Digest of the produced target output. It changes when corrupted s1 is
    consumed.

faults_applied
    0 in baseline, 1 in attack.
```

---

## `Y` DWT/HPC fields

```text
word 0  available
word 1  anomaly
word 2  sign_region_cycles
word 3  packed DWT event counters
        byte 0 = dwt_cpi
        byte 1 = dwt_exc
        byte 2 = dwt_lsu
        byte 3 = dwt_fold
word 4  sign_cycles
word 5  reserved
word 6  reserved
word 7  reserved
```

Since the fault is a data fault injected before the target window, not a
control-flow fault inside the target computation, the baseline and attack cycle
counts are expected to be the same.

---

## Build and run

Install the initial experiment:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/apply_islam_signature_correction_impl.sh
```

Apply the deterministic secret-key patch:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/patch_islam_deterministic_sk.sh
```

Apply the SRAM-safe target-window patch:

```bash
cd ~/hpc-cw-defense
bash /mnt/data/force_patch_islam_sram_safe_cmd_sign.sh
```

Run baseline:

```bash
cd ~/hpc-cw-defense/scripts/Islam_Signature_Correction_Attack
./run_base.sh
```

Run attack:

```bash
S1_BYTE_OFFSET=0 BIT_MASK=1 ./run_attack.sh
```

Other examples:

```bash
S1_BYTE_OFFSET=10 BIT_MASK=1 ./run_attack.sh
S1_BYTE_OFFSET=10 BIT_MASK=4 ./run_attack.sh
S1_BYTE_OFFSET=100 BIT_MASK=0x80 ./run_attack.sh
```

---

## Representative result: baseline

Configuration:

```text
S1_BYTE_OFFSET = 0
BIT_MASK       = 1
RESTORE_AFTER_SIGN = 1
```

Baseline result:

```text
keypair_ret             : 0
sign_ret                : 0
verify_ret_u8           : 255
semantic_valid          : 1
faults_applied          : 0
fault_enable            : 0
s1_byte_offset          : 0
bit_mask                : 1
abs_sk_offset           : 96
byte_before             : 146
byte_faulted            : 146
byte_after              : 146
restore_ok              : 1
sig_len                 : 64
sig_digest              : 1577363675
defense_error           : 0
hpc_anomaly_byte        : 0
restore_after_sign      : 1
verify_after_sign       : 0
```

DWT/HPC result:

```text
available               : 3
anomaly                 : 0
sign_region_cycles      : 9708
dwt_cpi                 : 63
dwt_exc                 : 0
dwt_lsu                 : 35
dwt_fold                : 0
sign_cycles             : 9708
```

Interpretation:

```text
faults_applied = 0
byte_before = byte_faulted = byte_after = 146 = 0x92
sig_digest = 1577363675
```

No secret-key bit is changed in the baseline run.

---

## Representative result: attack

Attack result:

```text
keypair_ret             : 0
sign_ret                : 0
verify_ret_u8           : 255
semantic_valid          : 1
faults_applied          : 1
fault_enable            : 1
s1_byte_offset          : 0
bit_mask                : 1
abs_sk_offset           : 96
byte_before             : 146
byte_faulted            : 147
byte_after              : 146
restore_ok              : 1
sig_len                 : 64
sig_digest              : 2800202647
defense_error           : 0
hpc_anomaly_byte        : 0
restore_after_sign      : 1
verify_after_sign       : 0
```

DWT/HPC result:

```text
available               : 3
anomaly                 : 0
sign_region_cycles      : 9708
dwt_cpi                 : 63
dwt_exc                 : 0
dwt_lsu                 : 35
dwt_fold                : 0
sign_cycles             : 9708
```

The byte-level fault is correct:

```text
byte_before  = 146 = 0x92
bit_mask     = 1   = 0x01
byte_faulted = 147 = 0x93
byte_after   = 146 = 0x92
```

The restoration is correct:

```text
restore_ok = 1
```

The output changes:

```text
baseline sig_digest = 1577363675
attack   sig_digest = 2800202647
```

The cycle count does not change:

```text
baseline sign_cycles = 9708
attack   sign_cycles = 9708
```

This is expected because the attack changes data, not control flow.

---

## Summary table

```text
Mode      Faults  sk[96] before  sk[96] used  sk[96] after  Restore  Digest       Cycles
baseline  0       0x92           0x92         0x92          yes      1577363675  9708
attack    1       0x92           0x93         0x92          yes      2800202647  9708
```

---

## Detector interpretation

This attack is a secret-key data-corruption attack.

It does not skip an instruction and does not alter the target-window control
flow. Therefore, a pure cycle-based DWT/HPC detector is weak for this fault
model.

Observed:

```text
baseline sign_cycles = 9708
attack   sign_cycles = 9708
```

The semantic output changes, but the target-window timing does not.

Effective defenses should focus on secret-key integrity rather than only
instruction-count or cycle-count anomalies:

```text
secret-key checksum before signing
redundant encoding of s1
duplicate unpack/consume with consistency check
memory integrity check for sk.s1
ECC/parity-protected key storage
signature-level correction/consistency checks
```

For this experiment, a data-integrity detector would check the `s1` region before
the target computation starts:

```text
hash/checksum(sk[96 ... 479])
```

and compare it against a trusted reference.

---

## Limitations

This is a software-level simulation of Islam et al.’s Rowhammer-style secret-key
bit-flip model.

It validates the core semantic effect:

```text
s1 bit flip before signing
unchanged target-window control flow
changed target output
restored secret-key byte after signing
```

It is not a physical Rowhammer demonstration.

The default target computation is not full Dilithium signing. It is an
SRAM-safe target kernel that consumes the packed `s1` region so the data fault
can be observed on the CW308_STM32F3 target.

A full Dilithium reproduction requires a target with enough stack/SRAM to run:

```text
crypto_sign_keypair(...)
crypto_sign_signature(...)
```

with the same pre-signing packed `s1` bit-flip injection.
