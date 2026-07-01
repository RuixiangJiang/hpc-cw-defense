#include "hal.h"
#include "simpleserial.h"
#include "api.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef ATTACK_TARGET_COEFF
#define ATTACK_TARGET_COEFF 0
#endif

/*
 * ChipWhisperer Kyber512-90s probe firmware.
 *
 * Command protocol, SS_VER_2_1:
 *
 *   P -> P[1]          ping
 *   K -> K[1]          keypair, returns ret
 *   E -> E[33]         encaps, returns ret || ss_enc
 *   D -> S[33]         decaps, returns ret || ss_dec
 *   T -> T[n]          read ciphertext chunk
 *   C -> C[1]          upload ciphertext chunk
 *   H -> H[16]         status: ret codes, ss_match, fault_skips
 *
 * This intentionally follows the previously tested kyberprobe style:
 * - uppercase commands;
 * - command-specific response letters;
 * - chunked ciphertext read/upload;
 * - target-side KEM state stored in global buffers.
 */

#define SS_LEN 32
#define CT_CHUNK 128
#define PK_CHUNK 200
#define INDCPA_SK_CHUNK 128

#ifndef KYBER_SYMBYTES
#define KYBER_SYMBYTES 32
#endif

#ifndef KYBER_INDCPA_SECRETKEYBYTES
#define KYBER_INDCPA_SECRETKEYBYTES 768
#endif

#ifndef KYBERPROBE_BOOT_BANNER
#define KYBERPROBE_BOOT_BANNER 1
#endif

#ifndef PROBE_ENABLE_ENCAP_TRIGGER
#define PROBE_ENABLE_ENCAP_TRIGGER 0
#endif

#ifndef PROBE_ENABLE_KEYPAIR_TRIGGER
#define PROBE_ENABLE_KEYPAIR_TRIGGER 0
#endif

#ifdef CW_TRIGGER_DECAPS_FULL
#ifndef PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_ENABLE_DECAP_FULL_TRIGGER 1
#endif
#endif

#ifndef PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_ENABLE_DECAP_FULL_TRIGGER 0
#endif

#ifndef PROBE_ENABLE_FAULT_HANDLER_TRIGGER
#define PROBE_ENABLE_FAULT_HANDLER_TRIGGER 0
#endif

#if PROBE_ENABLE_ENCAP_TRIGGER
#define PROBE_ENCAP_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_ENCAP_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_ENCAP_TRIGGER_HIGH() do { } while (0)
#define PROBE_ENCAP_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_KEYPAIR_TRIGGER
#define PROBE_KEYPAIR_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_KEYPAIR_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_KEYPAIR_TRIGGER_HIGH() do { } while (0)
#define PROBE_KEYPAIR_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_DECAP_FULL_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_DECAP_FULL_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_DECAP_FULL_TRIGGER_HIGH() do { } while (0)
#define PROBE_DECAP_FULL_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_FAULT_HANDLER_TRIGGER
#define PROBE_FAULT_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_FAULT_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_FAULT_TRIGGER_HIGH() do { } while (0)
#define PROBE_FAULT_TRIGGER_LOW()  do { } while (0)
#endif

extern volatile unsigned int hpc_cw_decode_entries;
extern volatile unsigned int hpc_cw_decode_exits;
extern volatile unsigned int hpc_cw_decode_progress;
extern volatile unsigned int hpc_cw_decode_expected;
extern volatile unsigned int hpc_cw_decode_defense_error;
extern volatile unsigned int hpc_cw_decode_dup_checks;
extern volatile unsigned int hpc_cw_decode_dup_mismatches;
extern volatile unsigned int hpc_cw_decode_full_mismatches;
extern volatile unsigned int hpc_cw_decode_last_marker;
extern volatile unsigned int hpc_cw_decode_marker_count;

extern volatile unsigned int hpc_hw_available;
extern volatile unsigned int hpc_hw_ctrl;
extern volatile unsigned int hpc_hw_anomaly;

extern volatile unsigned int hpc_hw_decode_cycles;
extern volatile unsigned int hpc_hw_decode_cpi;
extern volatile unsigned int hpc_hw_decode_exc;
extern volatile unsigned int hpc_hw_decode_sleep;
extern volatile unsigned int hpc_hw_decode_lsu;
extern volatile unsigned int hpc_hw_decode_fold;

extern volatile unsigned int hpc_hw_coeff_cycles_sum;
extern volatile unsigned int hpc_hw_coeff_cycles_min;
extern volatile unsigned int hpc_hw_coeff_cycles_max;
extern volatile unsigned int hpc_hw_target_coeff_cycles;
extern volatile unsigned int hpc_hw_target_coeff_idx;

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];

static int last_keygen_ret = -1;
static int last_enc_ret = -1;
static int last_dec_ret = -1;

/*
 * If poly.c defines a strong hpc_cw_fault_skips, the linker uses that one.
 * If not, this weak fallback keeps this firmware linkable.
 */
__attribute__((weak)) volatile unsigned int hpc_cw_fault_skips = 0;

extern void indcpa_dec(unsigned char *m,
                       const unsigned char *c,
                       const unsigned char *sk);

int randombytes(uint8_t *buf, size_t len);

static void enable_fpu(void)
{
    volatile uint32_t *cpacr = (volatile uint32_t *)0xE000ED88U;

    /*
     * Enable CP10 and CP11 full access.
     * Required before executing pqm4 m4fspeed VFP-register assembly.
     */
    *cpacr |= (0xFU << 20);

    __asm volatile("dsb");
    __asm volatile("isb");
}

static void uart_puts(const char *s)
{
    while (*s) {
        putch(*s++);
    }
}

static void fault_puts(const char *s)
{
    while (*s) {
        putch(*s++);
    }
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_ping(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_ping(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1] = {0x42};
    simpleserial_put('P', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_keypair_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_keypair_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    PROBE_KEYPAIR_TRIGGER_HIGH();
    last_keygen_ret = crypto_kem_keypair(pk, sk);
    PROBE_KEYPAIR_TRIGGER_LOW();

    out[0] = (uint8_t)last_keygen_ret;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_encaps_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_encaps_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1 + CRYPTO_BYTES];

    PROBE_ENCAP_TRIGGER_HIGH();
    last_enc_ret = crypto_kem_enc(ct, ss_enc, pk);
    PROBE_ENCAP_TRIGGER_LOW();

    if (hpc_cw_decode_defense_error != 0u) {
        /*
        * Defense policy:
        *   - detect DecodeMessage tampering;
        *   - reject the decapsulation result;
        *   - prevent the manipulated shared secret from being used.
        */
        last_dec_ret = 0xFD;

        for (int i = 0; i < CRYPTO_BYTES; i++) {
            ss_dec[i] = 0;
        }
    }

    out[0] = (uint8_t)last_enc_ret;
    memcpy(out + 1, ss_enc, CRYPTO_BYTES);

    simpleserial_put('E', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_decaps_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_decaps_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1 + CRYPTO_BYTES];

    hpc_cw_fault_skips = 0;

    hpc_cw_decode_entries = 0;
    hpc_cw_decode_exits = 0;
    hpc_cw_decode_progress = 0;
    hpc_cw_decode_expected = 256;
    hpc_cw_decode_defense_error = 0;
    hpc_cw_decode_dup_checks = 0;
    hpc_cw_decode_dup_mismatches = 0;
    hpc_cw_decode_full_mismatches = 0;
    hpc_cw_decode_last_marker = 0;
    hpc_cw_decode_marker_count = 0;

    hpc_hw_anomaly = 0;
    hpc_hw_decode_cycles = 0;
    hpc_hw_decode_cpi = 0;
    hpc_hw_decode_exc = 0;
    hpc_hw_decode_sleep = 0;
    hpc_hw_decode_lsu = 0;
    hpc_hw_decode_fold = 0;
    hpc_hw_coeff_cycles_sum = 0;
    hpc_hw_coeff_cycles_min = 0xffffffffu;
    hpc_hw_coeff_cycles_max = 0;
    hpc_hw_target_coeff_cycles = 0;
    hpc_hw_target_coeff_idx = ATTACK_TARGET_COEFF;

    PROBE_DECAP_FULL_TRIGGER_HIGH();
    last_dec_ret = crypto_kem_dec(ss_dec, ct, sk);
    PROBE_DECAP_FULL_TRIGGER_LOW();

    out[0] = (uint8_t)last_dec_ret;
    memcpy(out + 1, ss_dec, CRYPTO_BYTES);

    /*
     * Keep the verified protocol behavior:
     * command D returns response command S.
     */
    simpleserial_put('S', sizeof(out), out);
    return 0x00;
}

static void put_u32le(uint8_t *out, unsigned int offset, unsigned int x)
{
    out[offset + 0] = (uint8_t)(x & 0xffu);
    out[offset + 1] = (uint8_t)((x >> 8) & 0xffu);
    out[offset + 2] = (uint8_t)((x >> 16) & 0xffu);
    out[offset + 3] = (uint8_t)((x >> 24) & 0xffu);
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_hpc_hw_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_hpc_hw_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[32];

    /*
     * Eight 32-bit words:
     *
     * word0: hpc_hw_available
     * word1: hpc_hw_anomaly
     * word2: DecodeMessage region cycles, DWT_CYCCNT
     * word3: packed event counters:
     *        byte0 CPICNT
     *        byte1 EXCCNT
     *        byte2 LSUCNT
     *        byte3 FOLDCNT
     * word4: target coefficient cycles
     * word5: min coefficient cycles
     * word6: max coefficient cycles
     * word7: sum coefficient cycles
     */
    put_u32le(out, 0,  hpc_hw_available);
    put_u32le(out, 4,  hpc_hw_anomaly);
    put_u32le(out, 8,  hpc_hw_decode_cycles);

    put_u32le(out, 12,
        (hpc_hw_decode_cpi & 0xffu)
        | ((hpc_hw_decode_exc & 0xffu) << 8)
        | ((hpc_hw_decode_lsu & 0xffu) << 16)
        | ((hpc_hw_decode_fold & 0xffu) << 24));

    put_u32le(out, 16, hpc_hw_target_coeff_cycles);
    put_u32le(out, 20, hpc_hw_coeff_cycles_min);
    put_u32le(out, 24, hpc_hw_coeff_cycles_max);
    put_u32le(out, 28, hpc_hw_coeff_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_pk(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_pk(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 3) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    uint8_t outlen = buf[2];

    if (offset >= CRYPTO_PUBLICKEYBYTES) {
        return 0x02;
    }

    if ((uint32_t)offset + (uint32_t)outlen > CRYPTO_PUBLICKEYBYTES) {
        return 0x03;
    }

    simpleserial_put('R', outlen, pk + offset);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_ct(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_ct(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 3) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    uint8_t outlen = buf[2];

    if (offset >= CRYPTO_CIPHERTEXTBYTES) {
        return 0x02;
    }

    if ((uint32_t)offset + (uint32_t)outlen > CRYPTO_CIPHERTEXTBYTES) {
        return 0x03;
    }

    simpleserial_put('T', outlen, ct + offset);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_load_ct(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_load_ct(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 2 + CT_CHUNK) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

    if ((uint32_t)offset + CT_CHUNK > CRYPTO_CIPHERTEXTBYTES) {
        return 0x02;
    }

    memcpy(ct + offset, buf + 2, CT_CHUNK);

    uint8_t out[1] = {0x00};
    simpleserial_put('C', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_rng_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_rng_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[17];
    int ret = randombytes(out + 1, 16);
    out[0] = (uint8_t)ret;

    simpleserial_put('N', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_debug_decode_msg(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_debug_decode_msg(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t m_dec[KYBER_SYMBYTES];

    /*
     * Debug-only:
     * directly run IND-CPA decryption on current ct and KEM sk.
     */
    indcpa_dec(m_dec, ct, sk);
    simpleserial_put('M', KYBER_SYMBYTES, m_dec);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_indcpa_sk_chunk(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_indcpa_sk_chunk(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len < 2) {
        uint8_t err = 0xff;
        simpleserial_put('Z', 1, &err);
        return 0x00;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

    if (offset >= KYBER_INDCPA_SECRETKEYBYTES) {
        uint8_t err = 0xfe;
        simpleserial_put('Z', 1, &err);
        return 0x00;
    }

    uint16_t remaining = KYBER_INDCPA_SECRETKEYBYTES - offset;
    uint8_t out_len = INDCPA_SK_CHUNK;

    if (remaining < INDCPA_SK_CHUNK) {
        out_len = (uint8_t)remaining;
    }

    simpleserial_put('Z', out_len, sk + offset);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[16];
    int ss_match = (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) == 0);

    out[0] = (uint8_t)(last_keygen_ret & 0xff);
    out[1] = (uint8_t)(last_enc_ret & 0xff);
    out[2] = (uint8_t)(last_dec_ret & 0xff);
    out[3] = (uint8_t)(ss_match ? 1 : 0);

    out[4] = (uint8_t)(hpc_cw_fault_skips & 0xff);
    out[5] = (uint8_t)((hpc_cw_fault_skips >> 8) & 0xff);
    out[6] = (uint8_t)((hpc_cw_fault_skips >> 16) & 0xff);
    out[7] = (uint8_t)((hpc_cw_fault_skips >> 24) & 0xff);

    out[8] = (uint8_t)(CRYPTO_BYTES & 0xff);
    out[9] = (uint8_t)(CRYPTO_CIPHERTEXTBYTES & 0xff);
    out[10] = (uint8_t)((CRYPTO_CIPHERTEXTBYTES >> 8) & 0xff);
    out[11] = (uint8_t)(CRYPTO_PUBLICKEYBYTES & 0xff);
    out[12] = (uint8_t)((CRYPTO_PUBLICKEYBYTES >> 8) & 0xff);

    out[13] = (uint8_t)(hpc_cw_decode_defense_error & 0xff);
    out[14] = (uint8_t)(hpc_cw_decode_dup_mismatches & 0xff);
    out[15] = (uint8_t)(hpc_cw_decode_full_mismatches & 0xff);

    simpleserial_put('H', sizeof(out), out);
    return 0x00;
}

void HardFault_Handler(void)
{
    fault_puts("rHARDFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}

void BusFault_Handler(void)
{
    fault_puts("rBUSFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}

void UsageFault_Handler(void)
{
    fault_puts("rUSAGEFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

#if KYBERPROBE_BOOT_BANNER
    uart_puts("rKYBERPROBE_A\n");
#endif

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss_enc, 0, sizeof(ss_enc));
    memset(ss_dec, 0, sizeof(ss_dec));

#if KYBERPROBE_BOOT_BANNER
    uart_puts("rKYBERPROBE_B\n");
#endif

    simpleserial_init();

    /*
     * Keep the known-good uppercase command convention.
     */
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('K', 0, cmd_keypair_probe);
    simpleserial_addcmd('R', 3, cmd_read_pk);
    simpleserial_addcmd('N', 0, cmd_rng_probe);
    simpleserial_addcmd('E', 0, cmd_encaps_probe);
    simpleserial_addcmd('D', 0, cmd_decaps_probe);
    simpleserial_addcmd('T', 3, cmd_read_ct);
    simpleserial_addcmd('C', 2 + CT_CHUNK, cmd_load_ct);
    simpleserial_addcmd('M', 0, cmd_debug_decode_msg);
    simpleserial_addcmd('Z', 3, cmd_read_indcpa_sk_chunk);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_hw_status);

#if KYBERPROBE_BOOT_BANNER
    uart_puts("rKYBERPROBE_C\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}