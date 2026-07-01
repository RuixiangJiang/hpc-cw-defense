#include <stdint.h>

#include "hal.h"
#include "simpleserial.h"

static uint8_t cmd_ping(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data)
{
    (void)cmd;
    (void)scmd;
    (void)len;
    (void)data;

    uint8_t out[4] = { 'P', 'O', 'N', 'G' };
    simpleserial_put('r', 4, out);
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

    /*
     * Use a non-reserved test command with conventional 16-byte input.
     */
    simpleserial_addcmd('x', 16, cmd_ping);

    while (1) {
        simpleserial_get();
    }

    return 0;
}
