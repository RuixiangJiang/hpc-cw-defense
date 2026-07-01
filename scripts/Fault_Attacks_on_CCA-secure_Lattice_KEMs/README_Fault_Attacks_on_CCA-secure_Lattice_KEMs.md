# Fault Attacks on CCA-secure Lattice KEMs: Kyber512-90s Decoder-Skip Test Flow

This directory contains the scripts used to build and test the ChipWhisperer firmware for the Kyber512-90s decoder-skip experiment on `CWLITEARM` / `CW308_STM32F3`.

The current verified flow is:

```text
baseline firmware build -> flash -> SS2 communication -> K/E/T/C/D flow -> baseline correctness
attack firmware build   -> flash -> SS2 communication -> K/E/T/C/D flow -> decoder-skip hook observed
```

## 1. Hardware and software assumptions

Tested setup:

```text
Capture board : ChipWhisperer-Lite
Target        : CW308_STM32F3 / CWLITEARM
Protocol      : SimpleSerial2, SS_VER_2_1
Baudrate      : 230400
Target clock  : clkgen ~= 7.384615 MHz
ADC source    : clkgen_x4
Firmware app  : firmware/cw-kyber51290s-decoder-skip
Kyber impl    : third_party/pqm4/crypto_kem/kyber512-90s/m4fspeed
```

The test script configures the scope with the known-good settings, programs the target, resets it, and then runs the Kyber test flow.

## 2. Important files

From the repository root:

```text
firmware/cw-kyber51290s-decoder-skip/Makefile
firmware/cw-kyber51290s-decoder-skip/simpleserial-kyberprobe.c
scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py
```

The current Makefile intentionally follows the previously verified `Makefile.kyberprobe` style:

```text
- explicit ChipWhisperer target: CWLITEARM
- SimpleSerial2: SS_VER_2_1
- pqm4 Kyber512-90s m4fspeed implementation
- source discovery for Kyber implementation-local .c/.S/.s files
- VPATH + basenames only, not absolute paths in SRC/ASRC
- FPU flags enabled for pqm4 m4fspeed assembly
- clean rebuild required when switching baseline/attack macros
```

## 3. Firmware protocol

The firmware uses the previously verified uppercase command convention.

```text
P -> P[1]          ping, returns 0x42
K -> K[1]          keypair, returns ret
E -> E[33]         encaps, returns ret || ss_enc
T -> T[128]        read target-generated ciphertext chunk
C -> C[1]          upload ciphertext chunk
D -> S[33]         decaps, returns ret || ss_dec
H -> H[16]         status: return codes, ss_match, fault_skips, sizes
```

The test flow is:

```text
P  ping
K  generate keypair
E  encapsulate and obtain ss_enc
T  read ciphertext from target in 128-byte chunks
C  upload the same ciphertext back to target in 128-byte chunks
D  decapsulate and obtain ss_dec
H  read status, including hpc_cw_fault_skips
```

For Kyber512, the ciphertext length is 768 bytes, so `CT_CHUNK = 128` gives 6 chunks:

```text
offset 0, 128, 256, 384, 512, 640
```

## 4. Build baseline firmware

Always remove the object directory before switching between baseline and attack builds. The baseline/attack difference is controlled by preprocessor macros, so stale object files can silently produce the wrong firmware.

```bash
cd ~/hpc-cw-defense/firmware/cw-kyber51290s-decoder-skip

rm -rf objdir-CWLITEARM
rm -f *.elf *.hex *.map *.lss *.lst *.sym

make TARGET=cw-kyber51290s-decoder-skip-baseline \
     PLATFORM=CWLITEARM \
     SS_VER=SS_VER_2_1 \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="-DATTACK_DECODER_SKIP_QHALF=0" \
     cw-kyber51290s-decoder-skip-baseline-CWLITEARM.hex \
     2>&1 | tee build_baseline.log
```

Expected output artifact:

```text
firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-baseline-CWLITEARM.hex
```

## 5. Test baseline firmware

```bash
cd ~/hpc-cw-defense

python3 scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py \
  --hex firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-baseline-CWLITEARM.hex \
  --label baseline \
  --expected-fault-skips 0 \
  --expect-ss-match 1 \
  --verbose-packets
```

Expected result:

```text
P -> P valid, payload 42
K -> K valid, ret 00
E -> E valid, ret 00 plus 32-byte ss_enc
T ciphertext chunks valid
C ciphertext upload chunks valid
D -> S valid, ret 00 plus 32-byte ss_dec
H -> H valid
host_ss_match    : 1
target_ss_match  : 1
fault_skips      : 0
SUCCESS: all requested trials passed.
```

## 6. Build attack firmware

The attack firmware enables the software-simulated decoder skip in `poly_tomsg()` for one selected coefficient.

For coefficient 0:

```bash
cd ~/hpc-cw-defense/firmware/cw-kyber51290s-decoder-skip

rm -rf objdir-CWLITEARM
rm -f *.elf *.hex *.map *.lss *.lst *.sym

make TARGET=cw-kyber51290s-decoder-skip-attack-coeff0 \
     PLATFORM=CWLITEARM \
     SS_VER=SS_VER_2_1 \
     CRYPTO_TARGET=NONE \
     EXTRA_CFLAGS="-DATTACK_DECODER_SKIP_QHALF=1 -DATTACK_TARGET_COEFF=0" \
     cw-kyber51290s-decoder-skip-attack-coeff0-CWLITEARM.hex \
     2>&1 | tee build_attack_coeff0.log
```

Expected output artifact:

```text
firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-attack-coeff0-CWLITEARM.hex
```

## 7. Test attack firmware

```bash
cd ~/hpc-cw-defense

python3 scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/test_kyberprobe_upload_ct_dec.py \
  --hex firmware/cw-kyber51290s-decoder-skip/cw-kyber51290s-decoder-skip-attack-coeff0-CWLITEARM.hex \
  --label attack-coeff0 \
  --expected-fault-skips 1 \
  --verbose-packets
```

Expected result:

```text
P/K/E/T/C/D/H flow completes
fault_skips      : 1
SUCCESS: all requested trials passed.
```

Do not require `--expect-ss-match 0` for the attack firmware. A single selected-coefficient decoder skip is not guaranteed to change the final shared secret for every trial. The first-stage success criterion is that the hook is actually executed:

```text
fault_skips == 1
```

## 8. Notes from debugging

### SimpleSerial2 behavior

The working script uses the same style as the previously verified `test_upload_ct_dec.py`:

```python
target.simpleserial_write(cmd, payload)
target.simpleserial_read_witherrors(response_cmd, response_len, glitch_timeout=...)
```

Do not replace the `T` / `C` chunk transfer with a different wrapper unless needed. The verified 128-byte ciphertext chunk transfer works with the current script.

### Clean rebuilds are required

Baseline and attack use the same object directory but different macros. Always run:

```bash
rm -rf objdir-CWLITEARM
```

before rebuilding after changing `EXTRA_CFLAGS`.

### FPU is required

The pqm4 `m4fspeed` implementation uses Cortex-M4F VFP registers in assembly files such as NTT/INTT routines. The Makefile must compile these with FPU support:

```text
-mfpu=fpv4-sp-d16 -mfloat-abi=softfp
```

The firmware also enables the FPU at startup before executing Kyber code.

### Validated state

The current validated state is:

```text
baseline: pass, expected fault_skips = 0, expected ss_match = 1
attack  : pass, expected fault_skips = 1
```

This README records the first stable baseline/attack smoke-test flow after migrating from the earlier verified `simpleserial-kyber51290s` setup.
