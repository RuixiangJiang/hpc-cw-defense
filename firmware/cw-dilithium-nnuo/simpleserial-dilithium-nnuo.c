#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

#include "ravi_nnuo_nonce_fault.inc"

#define NNUO_MSG_PAYLOAD_LEN 128u

static polyvecl nnuo_s1;
static polyveck nnuo_s2;

static int last_init_ret = -1;
static int last_kernel_ret = -1;
static int last_check_ret = -1;
static uint8_t last_semantic_valid = 0;

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

static void reset_outputs(void)
{
    memset(&nnuo_s1, 0, sizeof(nnuo_s1));
    memset(&nnuo_s2, 0, sizeof(nnuo_s2));
    memset(nnuo_used_nonces, 0xff, sizeof(nnuo_used_nonces));
}

static void reset_observation_state(void)
{
    nnuo_fault_skips = 0;

    nnuo_sampling_entries = 0;
    nnuo_sampling_exits = 0;
    nnuo_defense_error = 0;
    nnuo_nonce_progress_errors = 0;

    nnuo_used_nonce_target = 0;
    nnuo_expected_nonce_target = 0;
    nnuo_duplicate_call = 0xffu;

    nnuo_hpc_anomaly = 0;
    nnuo_hpc_sampling_region_cycles = 0;
    nnuo_hpc_cpi = 0;
    nnuo_hpc_exc = 0;
    nnuo_hpc_lsu = 0;
    nnuo_hpc_fold = 0;
    nnuo_hpc_sample_cycles_sum = 0;
    nnuo_hpc_sample_cycles_min = 0xffffffffu;
    nnuo_hpc_sample_cycles_max = 0;
    nnuo_hpc_target_sample_cycles = 0;
    nnuo_hpc_target_call = nnuo_fault_target_call;
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

    nnuo_fault_enable = buf[0] ? 1u : 0u;
    nnuo_fault_target_call = (unsigned int)buf[1];
    nnuo_fault_stale_nonce = (unsigned int)buf[2];

    if (nnuo_fault_target_call >= NNUO_TOTAL_CALLS) {
        nnuo_fault_enable = 0;
        nnuo_fault_target_call = L;
        nnuo_fault_stale_nonce = 0;
        out[0] = 0xfe;
    } else {
        out[0] = 0x00;
    }

    out[1] = (uint8_t)nnuo_fault_enable;
    out[2] = (uint8_t)nnuo_fault_target_call;
    out[3] = (uint8_t)nnuo_fault_stale_nonce;
    out[4] = (uint8_t)NNUO_TOTAL_CALLS;
    out[5] = (uint8_t)L;
    out[6] = (uint8_t)K;
    out[7] = 0;

    simpleserial_put('F', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_init_vectors(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_init_vectors(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    reset_outputs();
    reset_observation_state();

    last_init_ret = 0;
    last_kernel_ret = -1;
    last_check_ret = -1;
    last_semantic_valid = 0;

    out[0] = 0x00;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_message_compat(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_message_compat(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1] = {0x00};
    simpleserial_put('M', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_run_kernel(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_run_kernel(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    reset_outputs();
    reset_observation_state();

    trigger_high();
    nnuo_sampling_sequence_apply(&nnuo_s1, &nnuo_s2);
    trigger_low();

    last_check_ret = (nnuo_defense_error == 0u) ? 0 : -1;

    /*
     * This field means "the kernel executed and the observations are
     * well-formed", not "the defense accepted the execution".
     */
    last_semantic_valid = 1;
    last_kernel_ret = 0;

    out[0] = (uint8_t)last_kernel_ret;
    simpleserial_put('S', sizeof(out), out);
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

    out[0] = (uint8_t)last_init_ret;
    out[1] = (uint8_t)last_kernel_ret;
    out[2] = (uint8_t)last_check_ret;
    out[3] = last_semantic_valid;

    put_u32le(out, 4, nnuo_fault_skips);

    out[8] = (uint8_t)nnuo_fault_enable;
    out[9] = (uint8_t)nnuo_fault_target_call;
    out[10] = (uint8_t)nnuo_fault_stale_nonce;
    out[11] = (uint8_t)nnuo_used_nonce_target;
    out[12] = (uint8_t)nnuo_defense_error;
    out[13] = (uint8_t)nnuo_nonce_progress_errors;
    out[14] = (uint8_t)nnuo_expected_nonce_target;
    out[15] = (uint8_t)nnuo_duplicate_call;

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
        ((nnuo_hpc_cpi & 0xffu) << 0) |
        ((nnuo_hpc_exc & 0xffu) << 8) |
        ((nnuo_hpc_lsu & 0xffu) << 16) |
        ((nnuo_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0,  nnuo_hpc_available);
    put_u32le(out, 4,  nnuo_hpc_anomaly);
    put_u32le(out, 8,  nnuo_hpc_sampling_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, nnuo_hpc_target_sample_cycles);
    put_u32le(out, 20, nnuo_hpc_sample_cycles_min);
    put_u32le(out, 24, nnuo_hpc_sample_cycles_max);
    put_u32le(out, 28, nnuo_hpc_sample_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    reset_outputs();
    reset_observation_state();

    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 4, cmd_fault_config);
    simpleserial_addcmd('K', 0, cmd_init_vectors);
    simpleserial_addcmd('M', NNUO_MSG_PAYLOAD_LEN, cmd_message_compat);
    simpleserial_addcmd('S', 0, cmd_run_kernel);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef NNUO_BOOT_BANNER
#define NNUO_BOOT_BANNER 1
#endif

#if NNUO_BOOT_BANNER
    uart_puts("NNUO_DILITHIUM_SAMPLER_KERNEL_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
