#include <stdint.h>
#include <string.h>

#include "hal.h"
#include "simpleserial.h"
#include "api.h"

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];

static int last_keygen_ret = -1;
static int last_enc_ret = -1;
static int last_dec_ret = -1;

extern volatile unsigned int hpc_cw_fault_skips;

static uint8_t cmd_ping(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

    uint8_t out[4] = { 'K', 'Y', 'B', 'R' };
    simpleserial_put('p', sizeof(out), out);
    return 0x00;
}

static uint8_t cmd_keygen(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

    trigger_high();
    last_keygen_ret = crypto_kem_keypair(pk, sk);
    trigger_low();

    simpleserial_put('k', 16, pk);
    return 0x00;
}

static uint8_t cmd_encaps(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

    trigger_high();
    last_enc_ret = crypto_kem_enc(ct, ss_enc, pk);
    trigger_low();

    simpleserial_put('e', CRYPTO_BYTES, ss_enc);
    return 0x00;
}

static uint8_t cmd_decaps(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

    hpc_cw_fault_skips = 0;

    trigger_high();
    last_dec_ret = crypto_kem_dec(ss_dec, ct, sk);
    trigger_low();

    simpleserial_put('d', CRYPTO_BYTES, ss_dec);
    return 0x00;
}

static uint8_t cmd_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

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

    for (int i = 8; i < 16; i++) {
        out[i] = 0;
    }

    simpleserial_put('s', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

    simpleserial_addcmd('p', 0, cmd_ping);
    simpleserial_addcmd('k', 0, cmd_keygen);
    simpleserial_addcmd('e', 0, cmd_encaps);
    simpleserial_addcmd('d', 0, cmd_decaps);
    simpleserial_addcmd('s', 0, cmd_status);

    while (1) {
        simpleserial_get();
    }

    return 0;
}
