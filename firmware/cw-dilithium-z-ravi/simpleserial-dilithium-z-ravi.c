#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*
 * Pull in the real z-generation fault primitive and DWT measurement logic.
 *
 * This standalone firmware does not call crypto_sign_keypair() or
 * crypto_sign_signature(), because the full Dilithium2/m4f signing stack is
 * too large for CWLITEARM/STM32F3. Instead, it initializes deterministic
 * vectors:
 *
 *     z = c*s1      stale/base contribution
 *     y = y         signing mask contribution
 *
 * and then executes:
 *
 *     ravi_z_generation_apply(&z, &y)
 *
 * This exercises the target semantic operation from Ravi et al.:
 *
 *     z = c*s1 + y
 */
#include "ravi_z_generation_fault.inc"

#ifndef RAVI_SIGN_DEFENSE_RET
#define RAVI_SIGN_DEFENSE_RET 0xFD
#endif

#define RAVI_Z_FAULT_NONE       0u
#define RAVI_Z_FAULT_SKIP_Y     1u
#define RAVI_Z_FAULT_SKIP_CS1   2u
#define RAVI_Z_FAULT_SKIP_STORE 3u

static polyvecl ravi_y;
static polyvecl ravi_z;
static polyvecl ravi_cs1_snapshot;
static polyvecl ravi_y_snapshot;

static int last_keygen_ret = -1;
static int last_sign_ret = -1;
static int last_verify_ret = -1;
static uint8_t last_signature_valid = 0;
static unsigned int last_bad_vec = 0xffu;
static unsigned int last_bad_coeff = 0xffu;

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

static int32_t deterministic_cs1(unsigned int v, unsigned int c)
{
    return (int32_t)(((v + 1u) * 1000u) + ((c * 17u) % 251u) - 125u);
}

static int32_t deterministic_y(unsigned int v, unsigned int c)
{
    return (int32_t)(100000u + ((v + 3u) * 2000u) + ((c * 29u) % 997u));
}

static void init_test_vectors(void)
{
    unsigned int v;
    unsigned int c;

    for (v = 0; v < L; v++) {
        for (c = 0; c < N; c++) {
            int32_t cs1 = deterministic_cs1(v, c);
            int32_t y = deterministic_y(v, c);

            ravi_cs1_snapshot.vec[v].coeffs[c] = cs1;
            ravi_y_snapshot.vec[v].coeffs[c] = y;

            /*
             * At the real sign.c hook point, z already contains c*s1 before
             * the final addition polyvecl_add(&z, &z, &y).
             */
            ravi_z.vec[v].coeffs[c] = cs1;
            ravi_y.vec[v].coeffs[c] = y;
        }
    }
}

static void reset_ravi_observation_state(void)
{
    ravi_z_fault_skips = 0;
    ravi_z_generation_entries = 0;
    ravi_z_generation_exits = 0;
    ravi_z_defense_error = 0;
    ravi_z_dup_mismatches = 0;

    ravi_hpc_anomaly = 0;
    ravi_hpc_z_region_cycles = 0;
    ravi_hpc_z_cpi = 0;
    ravi_hpc_z_exc = 0;
    ravi_hpc_z_lsu = 0;
    ravi_hpc_z_fold = 0;
    ravi_hpc_coeff_cycles_sum = 0;
    ravi_hpc_coeff_cycles_min = 0xffffffffu;
    ravi_hpc_coeff_cycles_max = 0;
    ravi_hpc_target_coeff_cycles = 0;
    ravi_hpc_target_vec = ravi_z_fault_target_vec;
    ravi_hpc_target_coeff = ravi_z_fault_target_coeff;

    last_bad_vec = 0xffu;
    last_bad_coeff = 0xffu;
}

static int check_z_semantics(void)
{
    unsigned int v;
    unsigned int c;
    unsigned int target_v = ravi_z_fault_target_vec;
    unsigned int target_c = ravi_z_fault_target_coeff;

    for (v = 0; v < L; v++) {
        for (c = 0; c < N; c++) {
            int32_t expected;

            expected = ravi_cs1_snapshot.vec[v].coeffs[c] +
                       ravi_y_snapshot.vec[v].coeffs[c];

            if ((ravi_z_fault_enable != 0u) &&
                (v == target_v) &&
                (c == target_c)) {
                if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_Y) {
                    expected = ravi_cs1_snapshot.vec[v].coeffs[c];
                } else if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_CS1) {
                    expected = ravi_y_snapshot.vec[v].coeffs[c];
                } else if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_STORE) {
                    expected = ravi_cs1_snapshot.vec[v].coeffs[c];
                }
            }

            if (ravi_z.vec[v].coeffs[c] != expected) {
                last_bad_vec = v;
                last_bad_coeff = c;
                return -1;
            }
        }
    }

    return 0;
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

    ravi_z_fault_enable = buf[0] ? 1u : 0u;
    ravi_z_fault_kind = (unsigned int)buf[1];
    ravi_z_fault_target_vec = (unsigned int)buf[2];
    ravi_z_fault_target_coeff = (unsigned int)buf[3];

    if ((ravi_z_fault_target_vec >= L) ||
        (ravi_z_fault_target_coeff >= N) ||
        (ravi_z_fault_kind > RAVI_Z_FAULT_SKIP_STORE)) {
        ravi_z_fault_enable = 0;
        ravi_z_fault_kind = RAVI_Z_FAULT_NONE;
        out[0] = 0xfe;
    } else {
        out[0] = 0x00;
    }

    out[1] = (uint8_t)ravi_z_fault_enable;
    out[2] = (uint8_t)ravi_z_fault_kind;
    out[3] = (uint8_t)ravi_z_fault_target_vec;
    out[4] = (uint8_t)ravi_z_fault_target_coeff;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;

    simpleserial_put('F', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_keypair_or_init(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_keypair_or_init(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    init_test_vectors();

    last_keygen_ret = 0;
    last_sign_ret = -1;
    last_verify_ret = -1;
    last_signature_valid = 0;

    out[0] = 0x00;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_message_chunk(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_message_chunk(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    /*
     * The z-generation kernel ignores the uploaded message, but keeps this
     * command for compatibility with the same host-side test script shape.
     */
    uint8_t out[1] = {0x00};
    simpleserial_put('M', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_sign_or_z_kernel(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_sign_or_z_kernel(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    reset_ravi_observation_state();

    /*
     * Re-initialize before every run so skip-store has a defined stale value
     * and repeated trials are independent.
     */
    init_test_vectors();

    trigger_high();
    ravi_z_generation_apply(&ravi_z, &ravi_y);
    trigger_low();

    if (check_z_semantics() == 0) {
        last_verify_ret = 0;
        last_signature_valid = 1;
        last_sign_ret = 0;
    } else {
        last_verify_ret = -1;
        last_signature_valid = 0;
        last_sign_ret = 0xee;
    }

    if (ravi_z_defense_error != 0u) {
        last_sign_ret = RAVI_SIGN_DEFENSE_RET;
    }

    out[0] = (uint8_t)last_sign_ret;
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

    out[0] = (uint8_t)last_keygen_ret;
    out[1] = (uint8_t)last_sign_ret;
    out[2] = (uint8_t)last_verify_ret;
    out[3] = last_signature_valid;
    put_u32le(out, 4, ravi_z_fault_skips);
    out[8] = (uint8_t)ravi_z_fault_enable;
    out[9] = (uint8_t)ravi_z_fault_kind;
    out[10] = (uint8_t)ravi_z_fault_target_vec;
    out[11] = (uint8_t)ravi_z_fault_target_coeff;
    out[12] = (uint8_t)ravi_z_defense_error;
    out[13] = (uint8_t)ravi_z_dup_mismatches;
    out[14] = (uint8_t)last_bad_vec;
    out[15] = (uint8_t)last_bad_coeff;

    simpleserial_put('H', sizeof(out), out);
    return 0x00;
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
    unsigned int packed =
        ((ravi_hpc_z_cpi & 0xffu) << 0) |
        ((ravi_hpc_z_exc & 0xffu) << 8) |
        ((ravi_hpc_z_lsu & 0xffu) << 16) |
        ((ravi_hpc_z_fold & 0xffu) << 24);

    put_u32le(out, 0,  ravi_hpc_available);
    put_u32le(out, 4,  ravi_hpc_anomaly);
    put_u32le(out, 8,  ravi_hpc_z_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, ravi_hpc_target_coeff_cycles);
    put_u32le(out, 20, ravi_hpc_coeff_cycles_min);
    put_u32le(out, 24, ravi_hpc_coeff_cycles_max);
    put_u32le(out, 28, ravi_hpc_coeff_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    init_test_vectors();

    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 4, cmd_fault_config);
    simpleserial_addcmd('K', 0, cmd_keypair_or_init);
    simpleserial_addcmd('M', 128, cmd_message_chunk);
    simpleserial_addcmd('S', 0, cmd_sign_or_z_kernel);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_hw_status);

#ifndef RAVI_BOOT_BANNER
#define RAVI_BOOT_BANNER 1
#endif

#if RAVI_BOOT_BANNER
    uart_puts("RAVI_DILITHIUM_Z_KERNEL_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}

