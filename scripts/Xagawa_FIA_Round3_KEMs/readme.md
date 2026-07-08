# Xagawa et al.: Kyber decapsulation failure-handling `cmov` skip experiment

This directory contains a ChipWhisperer/Cortex-M software fault-simulation
experiment for Xagawa et al., **“Fault-Injection Attacks against NIST’s PQC
Round 3 KEM Candidates”**.

The experiment targets the failure-handling path in Kyber decapsulation. In a
correct decapsulation, when ciphertext verification fails, the implementation
must overwrite the candidate pre-key with fallback secret material before
deriving the final shared secret.

The simulated fault skips the call to the failure-handling `cmov` even when
`fail = 1`.

---

## Target code in Kyber decapsulation

In pqm4 Kyber512-90s, the relevant decapsulation code is:

```c
indcpa_dec(buf, ct, sk);

for (i = 0; i < KYBER_SYMBYTES; i++) {
    buf[KYBER_SYMBYTES + i] =
        sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
}

hash_g(kr, buf, 2 * KYBER_SYMBYTES);

fail = indcpa_enc_cmp(ct, buf, pk, kr + KYBER_SYMBYTES);

hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

cmov(kr,
     sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
     KYBER_SYMBYTES,
     fail);

kdf(ss, kr, 2 * KYBER_SYMBYTES);
```

The target operation is the `cmov(...)` call:

```c
cmov(kr,
     sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
     KYBER_SYMBYTES,
     fail);
```

When `fail = 1`, this call overwrites `kr[0:KYBER_SYMBYTES]` with the fallback
secret `z` stored at the end of the secret key.

The attack skips this call, so the candidate pre-key in `kr` remains unchanged
even though verification has failed.

---

## What `cmov` is in pqm4 Kyber

The name `cmov` may sound like a single CPU conditional-move instruction, but in
pqm4 Kyber it is a C function implementing a constant-time conditional copy:

```c
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b) {
    size_t i;

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}
```

For this target call:

```c
len = KYBER_SYMBYTES = 32
```

Therefore, skipping the call bypasses a full 32-byte constant-time copy loop,
not just a single hardware instruction.

This explains why the measured cycle gap can be large:

```text
baseline: execute the full 32-byte cmov function
attack:   skip the cmov call and execute only the no-op skip primitive
```

In the current measurement:

```text
baseline target_cmov_cycles = 134
attack   target_cmov_cycles = 8
```

The difference is mainly the cost of the 32-byte constant-time conditional copy
that is absent in the attack path.

---

## Experiment scope

This experiment uses real Kyber512-90s keypair, encapsulation, corrupted
ciphertext decapsulation, ciphertext verification, hash operations, and KDF.

The only simulated fault is the skipped failure-handling `cmov` call.

The following operations still execute normally:

```text
indcpa_dec
hash_g
indcpa_enc_cmp
hash_h
kdf
```

The attack changes only this final failure-handling operation:

```text
baseline:
    cmov(kr, fallback_z, KYBER_SYMBYTES, fail)

attack:
    skipped cmov call
```

This is a function-level control-flow perturbation, matching the attack model
where the call to `cmov` is skipped.

---

## Files

```text
scripts/Xagawa_FIA_Round3_KEMs/
├── exp_env.sh
├── run_base.sh
├── run_attack.sh
├── test_kyber_xagawa_failure.py
├── readme.md
└── patch_kyber51290s_xagawa_kem.py

firmware/cw-kyber51290s-xagawa-fail/
├── Makefile
└── simpleserial-kyber-xagawa.c

third_party/pqm4/crypto_kem/kyber512-90s/m4fspeed/
└── xagawa_failure_handling_fault.inc
```

---

## Required source patch

This experiment must hook the failure-handling `cmov` in:

```text
third_party/pqm4/crypto_kem/kyber512-90s/m4fspeed/kem.c
```

Run the patch script from the repository root:

```bash
cd ~/hpc-cw-defense
python3 scripts/Xagawa_FIA_Round3_KEMs/patch_kyber51290s_xagawa_kem.py
```

The patch adds:

```c
#ifndef PQM4_EXP_XAGAWA_FAILURE_HANDLING
#define PQM4_EXP_XAGAWA_FAILURE_HANDLING 0
#endif

#if PQM4_EXP_XAGAWA_FAILURE_HANDLING
#include "xagawa_failure_handling_fault.inc"
#endif
```

and replaces the original `cmov` call with:

```c
#if PQM4_EXP_XAGAWA_FAILURE_HANDLING
    xagawa_failure_handling_cmov_kr(kr,
                                    sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
                                    KYBER_SYMBYTES,
                                    fail);
#else
    cmov(kr,
         sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
         KYBER_SYMBYTES,
         fail);
#endif
```

The macro is enabled only by the experiment firmware Makefile:

```makefile
CFLAGS += -DPQM4_EXP_XAGAWA_FAILURE_HANDLING=1
```

So the original Kyber behavior is preserved for builds that do not enable this
experiment macro.

---

## No target-window pollution

The target measured window is the failure-handling primitive itself.

Normal measured primitive:

```c
__attribute__((noinline))
static uint32_t xagawa_cmov_normal_measured(unsigned char *r,
                                            const unsigned char *x,
                                            size_t len,
                                            unsigned char b)
{
    uint32_t start;
    uint32_t delta;

    start = xagawa_hpc_cmov_begin();

    cmov(r, x, len, b);

    delta = xagawa_hpc_cmov_end_common(start);
    return delta;
}
```

Faulted measured primitive:

```c
__attribute__((noinline))
static uint32_t xagawa_cmov_skip_measured(unsigned char *r,
                                          const unsigned char *x,
                                          size_t len,
                                          unsigned char b)
{
    uint32_t start;
    uint32_t delta;

    start = xagawa_hpc_cmov_begin();

    __asm volatile("" : : "r"(r), "r"(x), "r"(len), "r"(b) : "memory");

    delta = xagawa_hpc_cmov_end_common(start);
    xagawa_fault_skips++;

    return delta;
}
```

The branch that chooses between them is outside the measured primitive:

```c
if ((xagawa_fault_enable != 0u) && (fail != 0u)) {
    xagawa_hpc_target_cmov_cycles =
        xagawa_cmov_skip_measured(r, x, len, fail);
} else {
    xagawa_hpc_target_cmov_cycles =
        xagawa_cmov_normal_measured(r, x, len, fail);
}
```

Therefore the measured target window does not contain:

```c
if (attack) {
    skip cmov;
}
```

The measured window is either the normal `cmov` call or the skip-call primitive,
not the simulator dispatch logic.

---

## Runtime workflow

Each trial executes:

```text
1. Configure fault mode.
2. Generate Kyber keypair.
3. Encapsulate normally.
4. Copy the ciphertext and corrupt one byte.
5. Decapsulate the corrupted ciphertext.
6. Read semantic status and DWT/HPC counters.
```

The corrupted ciphertext is produced by:

```text
ct_bad = ct
ct_bad[CORRUPT_OFFSET] ^= CORRUPT_MASK
```

Default:

```text
CORRUPT_OFFSET = 0
CORRUPT_MASK   = 1
```

The corrupted ciphertext should make verification fail:

```text
fail = 1
```

---

## Runtime configuration

Baseline and attack use the same firmware binary.

The SimpleSerial `F` command configures runtime mode.

Payload:

```text
byte 0 = fault_enable
         0 -> baseline
         1 -> attack

byte 1 = corrupt_offset

byte 2 = corrupt_mask

byte 3 = reserved
```

---

## SimpleSerial commands

```text
P -> P[1]      ping, returns 0x42
F -> F[8]      configure runtime fault mode
K -> K[1]      generate Kyber keypair
E -> E[1]      encapsulate and construct corrupted ciphertext
D -> D[1]      decapsulate corrupted ciphertext
H -> H[16]     semantic status
Y -> Y[32]     DWT/HPC status
```

### `H` status fields

```text
byte 0      keypair_ret
byte 1      enc_ret
byte 2      dec_ret
byte 3      fail
bytes 4-7   fault_skips
byte 8      fault_enable
byte 9      corrupt_offset
byte 10     corrupt_mask
byte 11     ss_dec_eq_enc
byte 12     defense_error
byte 13     cmov_entries
byte 14     cmov_exits
byte 15     reserved
```

Important fields:

```text
fail
    1 means ciphertext verification failed.

fault_skips
    Number of skipped failure-handling cmov operations.

cmov_entries / cmov_exits
    The wrapper around the target cmov was entered and exited.

ss_dec_eq_enc
    Whether decapsulation output equals the encapsulation shared secret.
    For corrupted ciphertext, this is usually 0 even in the attack run,
    because the KDF input includes H(ct_bad), not H(ct).
```

### `Y` DWT/HPC fields

```text
word 0  available
word 1  anomaly
word 2  cmov_region_cycles
word 3  packed DWT event counters
        byte 0 = dwt_cpi
        byte 1 = dwt_exc
        byte 2 = dwt_lsu
        byte 3 = dwt_fold
word 4  target_cmov_cycles
word 5  cmov_cycles_min
word 6  cmov_cycles_max
word 7  cmov_cycles_sum
```

Since there is one target `cmov` per decapsulation, normally:

```text
target_cmov_cycles = cmov_cycles_sum
```

---

## Run baseline

```bash
cd ~/hpc-cw-defense/scripts/Xagawa_FIA_Round3_KEMs
./run_base.sh
```

Expected semantic status:

```text
fail          = 1
fault_skips   = 0
fault_enable  = 0
cmov_entries  = 1
cmov_exits    = 1
ss_dec_eq_enc = 0
defense_error = 0
```

Representative DWT/HPC result:

```text
cmov_region_cycles      = 185
target_cmov_cycles      = 134
cmov_cycles_min         = 134
cmov_cycles_max         = 134
cmov_cycles_sum         = 134
```

---

## Run attack

```bash
cd ~/hpc-cw-defense/scripts/Xagawa_FIA_Round3_KEMs
./run_attack.sh
```

Expected semantic status:

```text
fail          = 1
fault_skips   = 1
fault_enable  = 1
cmov_entries  = 1
cmov_exits    = 1
ss_dec_eq_enc = 0
defense_error = 0
```

Representative DWT/HPC result:

```text
cmov_region_cycles      = 60
target_cmov_cycles      = 8
cmov_cycles_min         = 8
cmov_cycles_max         = 8
cmov_cycles_sum         = 8
```

The large cycle difference is expected because the baseline executes the full
32-byte constant-time `cmov` loop, while the attack skips the call.

---

## Why `ss_dec_eq_enc = 0` is expected

The experiment compares:

```text
ss_enc = shared secret from encapsulation of original ciphertext ct
ss_dec = shared secret from decapsulation of corrupted ciphertext ct_bad
```

Even if the failure-handling `cmov` is skipped, Kyber decapsulation still uses:

```c
hash_h(kr + KYBER_SYMBYTES, ct_bad, KYBER_CIPHERTEXTBYTES);
kdf(ss_dec, kr, 2 * KYBER_SYMBYTES);
```

Therefore the KDF input contains `H(ct_bad)`, while encapsulation used the
original ciphertext `ct`. As a result:

```text
ss_dec_eq_enc = 0
```

does not mean the fault failed.

The relevant attack condition is instead:

```text
fail = 1
fault_skips = 1
```

together with a target-cycle reduction showing that the failure-handling `cmov`
call was skipped.

---

## Detector thresholds

In the current observed setup:

```text
baseline target_cmov_cycles = 134
attack   target_cmov_cycles = 8
```

A calibrated target-cycle detector can use:

```bash
XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN=134
XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX=134
```

Baseline with threshold:

```bash
XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN=134 \
XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX=134 \
./run_base.sh
```

Expected:

```text
anomaly       = 0
defense_error = 0
```

Attack with threshold:

```bash
XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN=134 \
XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX=134 \
./run_attack.sh
```

Expected:

```text
target_cmov_cycles = 8
anomaly            = 8
defense_error      = 64
```

Bit meanings:

```text
0x08 = XAGAWA_HPC_ERR_TARGET_CYCLES_LOW
0x40 = XAGAWA_ERR_HW_COUNTER
```

---

## Repeated calibration

Run repeated baseline trials:

```bash
TRIALS=20 ./run_base.sh
```

Run repeated attack trials:

```bash
TRIALS=20 ./run_attack.sh
```

Expected stable relationships:

```text
baseline:
  fail               = 1
  fault_skips        = 0
  target_cmov_cycles = 134

attack:
  fail               = 1
  fault_skips        = 1
  target_cmov_cycles = 8
```

If `target_cmov_cycles` is stable in baseline, use the measured baseline value
as both lower and upper threshold.

---

## Limitations

This experiment is a source-level software simulation of a skipped
failure-handling `cmov` call.

It validates the semantic effect and the DWT/HPC detector for the selected
control-flow perturbation, but it is not by itself a physical clock-glitch,
voltage-glitch, or EMFI demonstration.

A physical FI experiment should recalibrate the trigger point and cycle window
around the actual call site in the compiled binary.
