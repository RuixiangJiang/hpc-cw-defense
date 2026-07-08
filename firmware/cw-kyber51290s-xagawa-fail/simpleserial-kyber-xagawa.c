#include "hal.h"
#include "simpleserial.h"
#include "api.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define XAGAWA_DEFAULT_CORRUPT_OFFSET 0u
#define XAGAWA_DEFAULT_CORRUPT_MASK   0x01u

extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

__attribute__((weak)) volatile unsigned int xagawa_fault_enable = 0;
__attribute__((weak)) volatile unsigned int xagawa_fault_skips = 0;
__attribute__((weak)) volatile unsigned int xagawa_last_fail = 0;
__attribute__((weak)) volatile unsigned int xagawa_cmov_entries = 0;
__attribute__((weak)) volatile unsigned int xagawa_cmov_exits = 0;
__attribute__((weak)) volatile unsigned int xagawa_defense_error = 0;

__attribute__((weak)) volatile unsigned int xagawa_hpc_available = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_anomaly = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_cmov_region_cycles = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_cpi = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_exc = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_lsu = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_fold = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_cmov_cycles_sum = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_cmov_cycles_min = 0xffffffffu;
__attribute__((weak)) volatile unsigned int xagawa_hpc_cmov_cycles_max = 0;
__attribute__((weak)) volatile unsigned int xagawa_hpc_target_cmov_cycles = 0;

static unsigned char pk[CRYPTO_PUBLICKEYBYTES];
static unsigned char sk[CRYPTO_SECRETKEYBYTES];
static unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
static unsigned char ct_bad[CRYPTO_CIPHERTEXTBYTES];
static unsigned char ss_enc[CRYPTO_BYTES];
static unsigned char ss_dec[CRYPTO_BYTES];

static unsigned int corrupt_offset = XAGAWA_DEFAULT_CORRUPT_OFFSET;
static unsigned int corrupt_mask = XAGAWA_DEFAULT_CORRUPT_MASK;

static int last_keygen_ret = -1;
static int last_enc_ret = -1;
static int last_dec_ret = -1;
static unsigned int last_ss_match = 0;

static void enable_fpu(void)
{
    volatile uint32_t *cpacr = (volatile uint32_t *)0xE000ED88U;
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

static void put_u32le(uint8_t *out, unsigned int offset, unsigned int x)
{
    out[offset + 0] = (uint8_t)(x & 0xffu);
    out[offset + 1] = (uint8_t)((x >> 8) & 0xffu);
    out[offset + 2] = (uint8_t)((x >> 16) & 0xffu);
    out[offset + 3] = (uint8_t)((x >> 24) & 0xffu);
}

static void reset_xagawa_observation_state(void)
{
    xagawa_fault_skips = 0;
    xagawa_last_fail = 0;
    xagawa_cmov_entries = 0;
    xagawa_cmov_exits = 0;
    xagawa_defense_error = 0;

    xagawa_hpc_anomaly = 0;
    xagawa_hpc_cmov_region_cycles = 0;
    xagawa_hpc_cpi = 0;
    xagawa_hpc_exc = 0;
    xagawa_hpc_lsu = 0;
    xagawa_hpc_fold = 0;
    xagawa_hpc_cmov_cycles_sum = 0;
    xagawa_hpc_cmov_cycles_min = 0xffffffffu;
    xagawa_hpc_cmov_cycles_max = 0;
    xagawa_hpc_target_cmov_cycles = 0;
}

static void make_bad_ciphertext(void)
{
    unsigned int off = corrupt_offset;

    memcpy(ct_bad, ct, CRYPTO_CIPHERTEXTBYTES);

    if (off >= CRYPTO_CIPHERTEXTBYTES) {
        off = 0;
    }

    ct_bad[off] ^= (uint8_t)corrupt_mask;
}

static unsigned int ss_equal(void)
{
    unsigned int diff = 0;
    unsigned int i;

    for (i = 0; i < CRYPTO_BYTES; i++) {
        diff |= ((unsigned int)ss_enc[i]) ^ ((unsigned int)ss_dec[i]);
    }

    return (diff == 0u) ? 1u : 0u;
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
static uint8_t cmd_fault_config(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_fault_config(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    uint8_t out[8];

    if (len < 4) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    xagawa_fault_enable = buf[0] ? 1u : 0u;
    corrupt_offset = (unsigned int)buf[1];
    corrupt_mask = (unsigned int)buf[2];

    if (corrupt_mask == 0u) {
        corrupt_mask = XAGAWA_DEFAULT_CORRUPT_MASK;
    }

    out[0] = 0x00;
    out[1] = (uint8_t)xagawa_fault_enable;
    out[2] = (uint8_t)corrupt_offset;
    out[3] = (uint8_t)corrupt_mask;
    out[4] = (uint8_t)(CRYPTO_CIPHERTEXTBYTES & 0xffu);
    out[5] = (uint8_t)((CRYPTO_CIPHERTEXTBYTES >> 8) & 0xffu);
    out[6] = 0;
    out[7] = 0;

    simpleserial_put('F', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_keypair(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_keypair(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    last_keygen_ret = crypto_kem_keypair(pk, sk);

    out[0] = (uint8_t)last_keygen_ret;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_encaps(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_encaps(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    last_enc_ret = crypto_kem_enc(ct, ss_enc, pk);
    make_bad_ciphertext();

    out[0] = (uint8_t)last_enc_ret;
    simpleserial_put('E', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_decaps_bad(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_decaps_bad(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    reset_xagawa_observation_state();

    trigger_high();
    last_dec_ret = crypto_kem_dec(ss_dec, ct_bad, sk);
    trigger_low();

    last_ss_match = ss_equal();

    out[0] = (uint8_t)last_dec_ret;
    simpleserial_put('D', sizeof(out), out);
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

    out[0] = (uint8_t)last_keygen_ret;
    out[1] = (uint8_t)last_enc_ret;
    out[2] = (uint8_t)last_dec_ret;
    out[3] = (uint8_t)xagawa_last_fail;

    put_u32le(out, 4, xagawa_fault_skips);

    out[8] = (uint8_t)xagawa_fault_enable;
    out[9] = (uint8_t)corrupt_offset;
    out[10] = (uint8_t)corrupt_mask;
    out[11] = (uint8_t)last_ss_match;
    out[12] = (uint8_t)xagawa_defense_error;
    out[13] = (uint8_t)xagawa_cmov_entries;
    out[14] = (uint8_t)xagawa_cmov_exits;
    out[15] = 0;

    simpleserial_put('H', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_hpc_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_hpc_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[32];
    unsigned int packed =
        ((xagawa_hpc_cpi & 0xffu) << 0) |
        ((xagawa_hpc_exc & 0xffu) << 8) |
        ((xagawa_hpc_lsu & 0xffu) << 16) |
        ((xagawa_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0,  xagawa_hpc_available);
    put_u32le(out, 4,  xagawa_hpc_anomaly);
    put_u32le(out, 8,  xagawa_hpc_cmov_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, xagawa_hpc_target_cmov_cycles);
    put_u32le(out, 20, xagawa_hpc_cmov_cycles_min);
    put_u32le(out, 24, xagawa_hpc_cmov_cycles_max);
    put_u32le(out, 28, xagawa_hpc_cmov_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 4, cmd_fault_config);
    simpleserial_addcmd('K', 0, cmd_keypair);
    simpleserial_addcmd('E', 0, cmd_encaps);
    simpleserial_addcmd('D', 0, cmd_decaps_bad);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef XAGAWA_BOOT_BANNER
#define XAGAWA_BOOT_BANNER 1
#endif

#if XAGAWA_BOOT_BANNER
    uart_puts("XAGAWA_KYBER_FAILURE_HANDLING_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
