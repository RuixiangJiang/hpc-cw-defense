#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Delvaux, "Roulette"
 *
 * This firmware is a SRAM-safe masked-intermediate kernel for Roulette-style
 * software fault simulation. It does not claim to be a full masked Kyber
 * decapsulation implementation. The goal is to reproduce the common semantic
 * object of Roulette faults:
 *
 *   a masked intermediate in the re-encryption / decoding pipeline takes a
 *   faulty distribution, and the following masked operations consume it.
 *
 * Fault models:
 *   ROULETTE_MODEL_NONE    : normal baseline
 *   ROULETTE_MODEL_SKIP    : remove the target local masked operation
 *   ROULETTE_MODEL_CONST   : replace target intermediate by a constant
 *   ROULETTE_MODEL_RANDOM  : replace target intermediate by random value
 *   ROULETTE_MODEL_BITFLIP : flip selected bit mask in target intermediate
 *
 * Target-window rule:
 *   The switch selecting the fault model is outside the measured primitive.
 *   The measured target primitive contains only the corresponding local
 *   operation. There is no "if attack then fault" inside the target window.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef ROULETTE_HPC_TARGET_CYCLES_MIN
#define ROULETTE_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef ROULETTE_HPC_TARGET_CYCLES_MAX
#define ROULETTE_HPC_TARGET_CYCLES_MAX 0
#endif

#ifndef ROULETTE_NCOEFFS
#define ROULETTE_NCOEFFS KYBER_N
#endif

#define ROULETTE_MODEL_NONE    0u
#define ROULETTE_MODEL_SKIP    1u
#define ROULETTE_MODEL_CONST   2u
#define ROULETTE_MODEL_RANDOM  3u
#define ROULETTE_MODEL_BITFLIP 4u

#define ROULETTE_ERR_HW_COUNTER 0x40u

#define ROULETTE_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define ROULETTE_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

typedef struct {
    uint16_t s0;
    uint16_t s1;
} roulette_masked_u16;

volatile unsigned int roulette_fault_model = ROULETTE_MODEL_NONE;
volatile unsigned int roulette_target_coeff = 0;
volatile unsigned int roulette_const_value = 0;
volatile unsigned int roulette_bit_mask = 1;
volatile unsigned int roulette_rand_seed = 0x12345678u;

volatile unsigned int roulette_faults_applied = 0;
volatile unsigned int roulette_entries = 0;
volatile unsigned int roulette_exits = 0;
volatile unsigned int roulette_defense_error = 0;
volatile unsigned int roulette_semantic_valid = 0;

volatile unsigned int roulette_target_expected_value = 0;
volatile unsigned int roulette_target_used_value = 0;
volatile unsigned int roulette_target_diff = 0;
volatile unsigned int roulette_output_digest = 0;

volatile unsigned int roulette_hpc_available = 0;
volatile unsigned int roulette_hpc_anomaly = 0;
volatile unsigned int roulette_hpc_region_cycles = 0;
volatile unsigned int roulette_hpc_cpi = 0;
volatile unsigned int roulette_hpc_exc = 0;
volatile unsigned int roulette_hpc_lsu = 0;
volatile unsigned int roulette_hpc_fold = 0;
volatile unsigned int roulette_hpc_op_cycles_sum = 0;
volatile unsigned int roulette_hpc_op_cycles_min = 0xffffffffu;
volatile unsigned int roulette_hpc_op_cycles_max = 0;
volatile unsigned int roulette_hpc_target_op_cycles = 0;

#if HPC_HW_ENABLE

#define ROULETTE_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define ROULETTE_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define ROULETTE_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define ROULETTE_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define ROULETTE_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define ROULETTE_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define ROULETTE_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define ROULETTE_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define ROULETTE_HPC_DEMCR_TRCENA          (1u << 24)
#define ROULETTE_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define ROULETTE_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t roulette_hpc_region_start = 0;

static inline void roulette_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    ROULETTE_HPC_DEMCR |= ROULETTE_HPC_DEMCR_TRCENA;
    ctrl = ROULETTE_HPC_DWT_CTRL;

    if ((ctrl & ROULETTE_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        ROULETTE_HPC_DWT_CTRL |= ROULETTE_HPC_DWT_CTRL_CYCCNTENA;
        roulette_hpc_available |= 0x01u;
    }

    ROULETTE_HPC_DWT_CPICNT = 0;
    ROULETTE_HPC_DWT_EXCCNT = 0;
    ROULETTE_HPC_DWT_SLEEPCNT = 0;
    ROULETTE_HPC_DWT_LSUCNT = 0;
    ROULETTE_HPC_DWT_FOLDCNT = 0;
    roulette_hpc_available |= 0x02u;
}

static inline void roulette_hpc_region_begin(void)
{
    roulette_hpc_dwt_enable();

    roulette_hpc_anomaly = 0;
    roulette_hpc_region_cycles = 0;
    roulette_hpc_cpi = 0;
    roulette_hpc_exc = 0;
    roulette_hpc_lsu = 0;
    roulette_hpc_fold = 0;
    roulette_hpc_op_cycles_sum = 0;
    roulette_hpc_op_cycles_min = 0xffffffffu;
    roulette_hpc_op_cycles_max = 0;
    roulette_hpc_target_op_cycles = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    roulette_hpc_region_start = ROULETTE_HPC_DWT_CYCCNT;
}

static inline uint32_t roulette_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return ROULETTE_HPC_DWT_CYCCNT;
}

static inline uint32_t roulette_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((roulette_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = ROULETTE_HPC_DWT_CYCCNT - start;

    roulette_hpc_op_cycles_sum += delta;

    if (delta < roulette_hpc_op_cycles_min) {
        roulette_hpc_op_cycles_min = delta;
    }

    if (delta > roulette_hpc_op_cycles_max) {
        roulette_hpc_op_cycles_max = delta;
    }

    return delta;
}

static inline void roulette_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = ROULETTE_HPC_DWT_CYCCNT;
    roulette_hpc_region_cycles = end - roulette_hpc_region_start;

    roulette_hpc_cpi = ROULETTE_HPC_DWT_CPICNT & 0xffu;
    roulette_hpc_exc = ROULETTE_HPC_DWT_EXCCNT & 0xffu;
    roulette_hpc_lsu = ROULETTE_HPC_DWT_LSUCNT & 0xffu;
    roulette_hpc_fold = ROULETTE_HPC_DWT_FOLDCNT & 0xffu;

#if ROULETTE_HPC_TARGET_CYCLES_MIN > 0
    if (roulette_hpc_target_op_cycles < (unsigned int)ROULETTE_HPC_TARGET_CYCLES_MIN) {
        roulette_hpc_anomaly |= ROULETTE_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if ROULETTE_HPC_TARGET_CYCLES_MAX > 0
    if (roulette_hpc_target_op_cycles > (unsigned int)ROULETTE_HPC_TARGET_CYCLES_MAX) {
        roulette_hpc_anomaly |= ROULETTE_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (roulette_hpc_anomaly != 0u) {
        roulette_defense_error |= ROULETTE_ERR_HW_COUNTER;
    }
}

#else

static inline void roulette_hpc_region_begin(void)
{
    roulette_hpc_anomaly = 0;
    roulette_hpc_region_cycles = 0;
    roulette_hpc_op_cycles_sum = 0;
    roulette_hpc_op_cycles_min = 0xffffffffu;
    roulette_hpc_op_cycles_max = 0;
    roulette_hpc_target_op_cycles = 0;
}

static inline uint32_t roulette_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t roulette_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void roulette_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static inline uint16_t roulette_mask12(unsigned int x)
{
    return (uint16_t)(x & 0x0fffu);
}

static inline uint32_t roulette_xorshift32(uint32_t *state)
{
    uint32_t x = *state;

    if (x == 0u) {
        x = 0x6d2b79f5u;
    }

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    *state = x;
    return x;
}

static inline roulette_masked_u16 roulette_input_shares(unsigned int coeff)
{
    uint32_t x = 0x9e3779b9u ^ (coeff * 0x85ebca6bu);
    roulette_masked_u16 r;

    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;

    r.s0 = roulette_mask12(x);
    r.s1 = roulette_mask12((x >> 12) ^ (coeff * 0x31u) ^ 0x05a5u);

    return r;
}

/*
 * The local masked operation that represents a target intermediate in the
 * re-encryption / decoding pipeline. It is intentionally small and local:
 * Roulette variants perturb this intermediate, while the following masked
 * consume step remains unchanged.
 */
static inline void roulette_masked_local_op_unmeasured(roulette_masked_u16 in,
                                                       roulette_masked_u16 *out)
{
    out->s0 = roulette_mask12(((unsigned int)in.s0 + 0x0123u) ^ 0x0041u);
    out->s1 = roulette_mask12(((unsigned int)in.s1 + 0x0234u) ^ 0x0082u);
}

static inline uint16_t roulette_unmask(roulette_masked_u16 x)
{
    return roulette_mask12((unsigned int)x.s0 + (unsigned int)x.s1);
}

static inline uint32_t roulette_consume_masked_intermediate(roulette_masked_u16 x,
                                                            unsigned int coeff,
                                                            uint32_t digest)
{
    uint16_t v = roulette_unmask(x);
    uint32_t mix = ((uint32_t)v << (coeff & 7u)) ^ ((uint32_t)coeff * 0x45d9f3bu);

    /*
     * A Kyber-like downstream decoding/re-encryption consumer. The exact
     * cryptographic operation is not the point of this SRAM-safe kernel; the
     * point is that all following operations consume the masked intermediate
     * produced by the target step.
     */
    digest ^= mix + 0x9e3779b9u + (digest << 6) + (digest >> 2);

    if (v > (KYBER_Q / 2u)) {
        digest ^= 0x00010001u;
    } else {
        digest ^= 0x01000001u;
    }

    return digest;
}

__attribute__((noinline))
static uint32_t roulette_target_normal_measured(roulette_masked_u16 in,
                                                roulette_masked_u16 *out)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = roulette_hpc_op_begin();

    roulette_masked_local_op_unmeasured(in, out);

    __asm volatile("" ::: "memory");
    delta = roulette_hpc_op_end_common(start);

    return delta;
}

__attribute__((noinline))
static uint32_t roulette_target_skip_measured(roulette_masked_u16 in,
                                              roulette_masked_u16 *out)
{
    uint32_t start;
    uint32_t delta;

    (void)in;

    __asm volatile("" ::: "memory");
    start = roulette_hpc_op_begin();

    /*
     * Instruction-skip variant: remove the target local masked operation.
     * The output object is deliberately left unchanged, so the following
     * consumer sees a stale/incomplete masked intermediate.
     */
    __asm volatile("" : "+m"(*out) : : "memory");

    delta = roulette_hpc_op_end_common(start);

    roulette_faults_applied++;

    return delta;
}

__attribute__((noinline))
static uint32_t roulette_target_const_measured(roulette_masked_u16 in,
                                               roulette_masked_u16 *out,
                                               uint16_t c)
{
    uint32_t start;
    uint32_t delta;

    (void)in;

    __asm volatile("" ::: "memory");
    start = roulette_hpc_op_begin();

    out->s0 = roulette_mask12(c);
    out->s1 = 0u;

    __asm volatile("" ::: "memory");
    delta = roulette_hpc_op_end_common(start);

    roulette_faults_applied++;

    return delta;
}

__attribute__((noinline))
static uint32_t roulette_target_random_measured(roulette_masked_u16 in,
                                                roulette_masked_u16 *out,
                                                uint32_t *rng)
{
    uint32_t start;
    uint32_t delta;
    uint32_t r0;
    uint32_t r1;

    (void)in;

    __asm volatile("" ::: "memory");
    start = roulette_hpc_op_begin();

    r0 = roulette_xorshift32(rng);
    r1 = roulette_xorshift32(rng);
    out->s0 = roulette_mask12(r0);
    out->s1 = roulette_mask12(r1);

    __asm volatile("" ::: "memory");
    delta = roulette_hpc_op_end_common(start);

    roulette_faults_applied++;

    return delta;
}

__attribute__((noinline))
static uint32_t roulette_target_bitflip_measured(roulette_masked_u16 in,
                                                 roulette_masked_u16 *out,
                                                 uint16_t mask)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = roulette_hpc_op_begin();

    roulette_masked_local_op_unmeasured(in, out);
    out->s0 = roulette_mask12(((unsigned int)out->s0) ^ ((unsigned int)mask));

    __asm volatile("" ::: "memory");
    delta = roulette_hpc_op_end_common(start);

    roulette_faults_applied++;

    return delta;
}

/*
 * Dispatch is outside each measured primitive.
 */
__attribute__((noinline))
static uint32_t roulette_target_apply_measured(unsigned int model,
                                               roulette_masked_u16 in,
                                               roulette_masked_u16 *state,
                                               uint32_t *rng)
{
    if (model == ROULETTE_MODEL_SKIP) {
        return roulette_target_skip_measured(in, state);
    }

    if (model == ROULETTE_MODEL_CONST) {
        return roulette_target_const_measured(in, state, (uint16_t)roulette_const_value);
    }

    if (model == ROULETTE_MODEL_RANDOM) {
        return roulette_target_random_measured(in, state, rng);
    }

    if (model == ROULETTE_MODEL_BITFLIP) {
        return roulette_target_bitflip_measured(in, state, (uint16_t)roulette_bit_mask);
    }

    return roulette_target_normal_measured(in, state);
}

static void roulette_reset_observation_state(void)
{
    roulette_faults_applied = 0;
    roulette_entries = 0;
    roulette_exits = 0;
    roulette_defense_error = 0;
    roulette_semantic_valid = 0;

    roulette_target_expected_value = 0;
    roulette_target_used_value = 0;
    roulette_target_diff = 0;
    roulette_output_digest = 0;

    roulette_hpc_anomaly = 0;
    roulette_hpc_region_cycles = 0;
    roulette_hpc_cpi = 0;
    roulette_hpc_exc = 0;
    roulette_hpc_lsu = 0;
    roulette_hpc_fold = 0;
    roulette_hpc_op_cycles_sum = 0;
    roulette_hpc_op_cycles_min = 0xffffffffu;
    roulette_hpc_op_cycles_max = 0;
    roulette_hpc_target_op_cycles = 0;
}

__attribute__((noinline))
static void roulette_masked_pipeline_apply(void)
{
    unsigned int coeff;
    unsigned int target = roulette_target_coeff;
    roulette_masked_u16 in;
    roulette_masked_u16 state;
    roulette_masked_u16 expected;
    uint32_t rng = roulette_rand_seed;
    uint32_t digest = 0x524f554cu; /* "ROUL" */

    state.s0 = 0x0135u;
    state.s1 = 0x0246u;

    if (target >= ROULETTE_NCOEFFS) {
        target = 0;
    }

    roulette_entries++;

    roulette_hpc_region_begin();

    for (coeff = 0; coeff < target; coeff++) {
        in = roulette_input_shares(coeff);
        (void)roulette_target_normal_measured(in, &state);
        digest = roulette_consume_masked_intermediate(state, coeff, digest);
    }

    in = roulette_input_shares(target);
    roulette_masked_local_op_unmeasured(in, &expected);
    roulette_hpc_target_op_cycles =
        roulette_target_apply_measured(roulette_fault_model, in, &state, &rng);

    roulette_target_expected_value = (unsigned int)roulette_unmask(expected);
    roulette_target_used_value = (unsigned int)roulette_unmask(state);
    roulette_target_diff = roulette_target_expected_value ^ roulette_target_used_value;

    digest = roulette_consume_masked_intermediate(state, target, digest);

    for (coeff = target + 1u; coeff < ROULETTE_NCOEFFS; coeff++) {
        in = roulette_input_shares(coeff);
        (void)roulette_target_normal_measured(in, &state);
        digest = roulette_consume_masked_intermediate(state, coeff, digest);
    }

    roulette_hpc_region_end();

    roulette_rand_seed = rng;
    roulette_output_digest = digest;
    roulette_semantic_valid = 1;
    roulette_exits++;
}

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

    uint8_t out[16];
    unsigned int model;
    unsigned int target;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    target = ((unsigned int)buf[1]) | (((unsigned int)buf[2]) << 8);

    if (model > ROULETTE_MODEL_BITFLIP) {
        model = ROULETTE_MODEL_NONE;
    }

    if (target >= ROULETTE_NCOEFFS) {
        target = 0;
    }

    roulette_fault_model = model;
    roulette_target_coeff = target;
    roulette_const_value = ((unsigned int)buf[4]) | (((unsigned int)buf[5]) << 8);
    roulette_bit_mask = ((unsigned int)buf[6]) | (((unsigned int)buf[7]) << 8);
    roulette_rand_seed = ((unsigned int)buf[8]) |
                         (((unsigned int)buf[9]) << 8) |
                         (((unsigned int)buf[10]) << 16) |
                         (((unsigned int)buf[11]) << 24);

    if (roulette_bit_mask == 0u) {
        roulette_bit_mask = 1u;
    }

    if (roulette_rand_seed == 0u) {
        roulette_rand_seed = 0x12345678u;
    }

    memset(out, 0, sizeof(out));
    out[0] = 0x00;
    out[1] = (uint8_t)roulette_fault_model;
    out[2] = (uint8_t)(roulette_target_coeff & 0xffu);
    out[3] = (uint8_t)((roulette_target_coeff >> 8) & 0xffu);
    out[4] = (uint8_t)(roulette_const_value & 0xffu);
    out[5] = (uint8_t)((roulette_const_value >> 8) & 0xffu);
    out[6] = (uint8_t)(roulette_bit_mask & 0xffu);
    out[7] = (uint8_t)((roulette_bit_mask >> 8) & 0xffu);
    out[8] = (uint8_t)(roulette_rand_seed & 0xffu);
    out[9] = (uint8_t)((roulette_rand_seed >> 8) & 0xffu);
    out[10] = (uint8_t)((roulette_rand_seed >> 16) & 0xffu);
    out[11] = (uint8_t)((roulette_rand_seed >> 24) & 0xffu);
    out[12] = (uint8_t)(ROULETTE_NCOEFFS & 0xffu);
    out[13] = (uint8_t)((ROULETTE_NCOEFFS >> 8) & 0xffu);
    out[14] = 0;
    out[15] = 0;

    simpleserial_put('F', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_init(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_init(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    roulette_reset_observation_state();

    out[0] = 0x00;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_run(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_run(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    roulette_reset_observation_state();

    trigger_high();
    roulette_masked_pipeline_apply();
    trigger_low();

    out[0] = 0x00;
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

    uint8_t out[32];

    memset(out, 0, sizeof(out));

    out[0] = (uint8_t)roulette_fault_model;
    out[1] = (uint8_t)(roulette_target_coeff & 0xffu);
    out[2] = (uint8_t)((roulette_target_coeff >> 8) & 0xffu);
    out[3] = (uint8_t)roulette_semantic_valid;

    put_u32le(out, 4, roulette_faults_applied);
    put_u32le(out, 8, roulette_target_expected_value);
    put_u32le(out, 12, roulette_target_used_value);
    put_u32le(out, 16, roulette_target_diff);
    put_u32le(out, 20, roulette_output_digest);

    out[24] = (uint8_t)roulette_defense_error;
    out[25] = (uint8_t)roulette_hpc_anomaly;
    out[26] = (uint8_t)roulette_entries;
    out[27] = (uint8_t)roulette_exits;
    out[28] = (uint8_t)(roulette_const_value & 0xffu);
    out[29] = (uint8_t)(roulette_bit_mask & 0xffu);
    out[30] = 0;
    out[31] = 0;

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
        ((roulette_hpc_cpi & 0xffu) << 0) |
        ((roulette_hpc_exc & 0xffu) << 8) |
        ((roulette_hpc_lsu & 0xffu) << 16) |
        ((roulette_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0,  roulette_hpc_available);
    put_u32le(out, 4,  roulette_hpc_anomaly);
    put_u32le(out, 8,  roulette_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, roulette_hpc_target_op_cycles);
    put_u32le(out, 20, roulette_hpc_op_cycles_min);
    put_u32le(out, 24, roulette_hpc_op_cycles_max);
    put_u32le(out, 28, roulette_hpc_op_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    roulette_reset_observation_state();

    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_fault_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef ROULETTE_BOOT_BANNER
#define ROULETTE_BOOT_BANNER 1
#endif

#if ROULETTE_BOOT_BANNER
    uart_puts("DELVAUX_ROULETTE_MASKED_KERNEL_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
