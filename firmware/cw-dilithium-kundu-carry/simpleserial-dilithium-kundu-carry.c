#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Kundu et al., "Carry Your Fault"
 *
 * Semantic model:
 *
 *   This is not an instruction skip.  The A2B / masked-decoding computation
 *   runs normally until a selected carry bit or masked A2B intermediate is
 *   produced.  The selected data value is then overwritten with a stuck-at
 *   value.  The original computation then continues normally and consumes the
 *   faulty data.
 *
 * This firmware is an SRAM-safe semantic kernel.  It isolates a carry /
 * intermediate data-value fault in a masked decoding style A2B computation.
 *
 * Clean target-window design:
 *
 *   normal prefix masked-decoding coefficients
 *   normal target coefficient computation up to the target intermediate
 *   simulator-side data overwrite before trigger/DWT measurement
 *   trigger_high()
 *   DWT/HPC begin
 *   normal suffix computation of the target coefficient consumes faulty data
 *   DWT/HPC end
 *   trigger_low()
 *   normal suffix masked-decoding coefficients
 *
 * The measured target window contains the same normal continuation primitive
 * in baseline and attack.  It does not contain fault-model dispatch and it does
 * not contain "if attack then corrupt" logic.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef KUNDU_HPC_TARGET_CYCLES_MIN
#define KUNDU_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef KUNDU_HPC_TARGET_CYCLES_MAX
#define KUNDU_HPC_TARGET_CYCLES_MAX 0
#endif

#define KUNDU_MODEL_NONE       0u
#define KUNDU_MODEL_CARRY0     1u
#define KUNDU_MODEL_CARRY1     2u
#define KUNDU_MODEL_INTER0     3u
#define KUNDU_MODEL_INTER1     4u

#define KUNDU_ERR_HW_COUNTER 0x40u
#define KUNDU_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define KUNDU_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define KUNDU_NCOEFFS 256u
#define KUNDU_WORD_BITS 16u
#define KUNDU_WORD_MASK 0xffffu

static uint16_t kundu_a0[KUNDU_NCOEFFS];
static uint16_t kundu_a1[KUNDU_NCOEFFS];
static uint16_t kundu_out[KUNDU_NCOEFFS];
static uint16_t kundu_ref[KUNDU_NCOEFFS];

volatile unsigned int kundu_model = KUNDU_MODEL_NONE;
volatile unsigned int kundu_target_coeff = 17;
volatile unsigned int kundu_target_bit = 7;
volatile unsigned int kundu_message_tweak = 0;

volatile unsigned int kundu_faults_applied = 0;
volatile unsigned int kundu_entries = 0;
volatile unsigned int kundu_exits = 0;
volatile unsigned int kundu_semantic_valid = 0;
volatile unsigned int kundu_output_matches_ref = 0;
volatile unsigned int kundu_defense_error = 0;

volatile unsigned int kundu_expected_carry = 0;
volatile unsigned int kundu_used_carry = 0;
volatile unsigned int kundu_expected_intermediate_bit = 0;
volatile unsigned int kundu_used_intermediate_bit = 0;

volatile unsigned int kundu_expected_target_value = 0;
volatile unsigned int kundu_used_target_value = 0;
volatile unsigned int kundu_expected_partial = 0;
volatile unsigned int kundu_used_partial = 0;

volatile unsigned int kundu_output_digest = 0;
volatile unsigned int kundu_reference_digest = 0;
volatile unsigned int kundu_output_diff = 0;

volatile unsigned int kundu_hpc_available = 0;
volatile unsigned int kundu_hpc_anomaly = 0;
volatile unsigned int kundu_hpc_region_cycles = 0;
volatile unsigned int kundu_hpc_cpi = 0;
volatile unsigned int kundu_hpc_exc = 0;
volatile unsigned int kundu_hpc_lsu = 0;
volatile unsigned int kundu_hpc_fold = 0;
volatile unsigned int kundu_hpc_target_cycles = 0;
volatile unsigned int kundu_hpc_cycles_min = 0xffffffffu;
volatile unsigned int kundu_hpc_cycles_max = 0;
volatile unsigned int kundu_hpc_cycles_sum = 0;

#if HPC_HW_ENABLE

#define KUNDU_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define KUNDU_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define KUNDU_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define KUNDU_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define KUNDU_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define KUNDU_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define KUNDU_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define KUNDU_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define KUNDU_HPC_DEMCR_TRCENA          (1u << 24)
#define KUNDU_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define KUNDU_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t kundu_hpc_region_start = 0;

static inline void kundu_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    KUNDU_HPC_DEMCR |= KUNDU_HPC_DEMCR_TRCENA;
    ctrl = KUNDU_HPC_DWT_CTRL;

    if ((ctrl & KUNDU_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        KUNDU_HPC_DWT_CTRL |= KUNDU_HPC_DWT_CTRL_CYCCNTENA;
        kundu_hpc_available |= 0x01u;
    }

    KUNDU_HPC_DWT_CPICNT = 0;
    KUNDU_HPC_DWT_EXCCNT = 0;
    KUNDU_HPC_DWT_SLEEPCNT = 0;
    KUNDU_HPC_DWT_LSUCNT = 0;
    KUNDU_HPC_DWT_FOLDCNT = 0;
    kundu_hpc_available |= 0x02u;
}

static inline void kundu_hpc_region_begin(void)
{
    kundu_hpc_dwt_enable();

    kundu_hpc_anomaly = 0;
    kundu_hpc_region_cycles = 0;
    kundu_hpc_cpi = 0;
    kundu_hpc_exc = 0;
    kundu_hpc_lsu = 0;
    kundu_hpc_fold = 0;
    kundu_hpc_target_cycles = 0;
    kundu_hpc_cycles_min = 0xffffffffu;
    kundu_hpc_cycles_max = 0;
    kundu_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    kundu_hpc_region_start = KUNDU_HPC_DWT_CYCCNT;
}

static inline uint32_t kundu_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return KUNDU_HPC_DWT_CYCCNT;
}

static inline uint32_t kundu_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((kundu_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = KUNDU_HPC_DWT_CYCCNT - start;

    kundu_hpc_cycles_sum += delta;

    if (delta < kundu_hpc_cycles_min) {
        kundu_hpc_cycles_min = delta;
    }

    if (delta > kundu_hpc_cycles_max) {
        kundu_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void kundu_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = KUNDU_HPC_DWT_CYCCNT;
    kundu_hpc_region_cycles = end - kundu_hpc_region_start;

    kundu_hpc_cpi = KUNDU_HPC_DWT_CPICNT & 0xffu;
    kundu_hpc_exc = KUNDU_HPC_DWT_EXCCNT & 0xffu;
    kundu_hpc_lsu = KUNDU_HPC_DWT_LSUCNT & 0xffu;
    kundu_hpc_fold = KUNDU_HPC_DWT_FOLDCNT & 0xffu;

#if KUNDU_HPC_TARGET_CYCLES_MIN > 0
    if (kundu_hpc_target_cycles < (unsigned int)KUNDU_HPC_TARGET_CYCLES_MIN) {
        kundu_hpc_anomaly |= KUNDU_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if KUNDU_HPC_TARGET_CYCLES_MAX > 0
    if (kundu_hpc_target_cycles > (unsigned int)KUNDU_HPC_TARGET_CYCLES_MAX) {
        kundu_hpc_anomaly |= KUNDU_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (kundu_hpc_anomaly != 0u) {
        kundu_defense_error |= KUNDU_ERR_HW_COUNTER;
    }
}

#else

static inline void kundu_hpc_region_begin(void)
{
    kundu_hpc_anomaly = 0;
    kundu_hpc_region_cycles = 0;
    kundu_hpc_target_cycles = 0;
    kundu_hpc_cycles_min = 0xffffffffu;
    kundu_hpc_cycles_max = 0;
    kundu_hpc_cycles_sum = 0;
}

static inline uint32_t kundu_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t kundu_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void kundu_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static uint32_t kundu_fnv1a_words(const uint16_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < len; i++) {
        uint32_t x = (uint32_t)buf[i];

        h ^= x & 0xffu;
        h *= 0x01000193u;
        h ^= (x >> 8) & 0xffu;
        h *= 0x01000193u;
    }

    return h;
}

static uint16_t kundu_make_a0(unsigned int i)
{
    uint32_t x = 0x1357u + 73u * i + (kundu_message_tweak & 0xffffu);
    x ^= (kundu_message_tweak >> 16) & 0xffffu;
    return (uint16_t)(x & KUNDU_WORD_MASK);
}

static uint16_t kundu_make_a1(unsigned int i)
{
    uint32_t x = 0x2468u ^ (i * 0x031du) ^ ((kundu_message_tweak << 3) & 0xffffu);
    x += (kundu_message_tweak >> 5) & 0xffffu;
    return (uint16_t)(x & KUNDU_WORD_MASK);
}

static void kundu_init_inputs(void)
{
    unsigned int i;

    for (i = 0; i < KUNDU_NCOEFFS; i++) {
        kundu_a0[i] = kundu_make_a0(i);
        kundu_a1[i] = kundu_make_a1(i);
        kundu_out[i] = 0;
        kundu_ref[i] = 0;
    }
}

/*
 * Full normal A2B-style decoding of one word.
 *
 * The function computes the Boolean representation of a0 + a1 mod 2^16 by
 * explicitly propagating carry bits.  It is intentionally branchless with
 * respect to secret data.
 */
__attribute__((noinline))
static uint16_t kundu_a2b_decode_full_normal(uint16_t a0, uint16_t a1)
{
    unsigned int bit;
    unsigned int carry = 0;
    unsigned int result = 0;

    for (bit = 0; bit < KUNDU_WORD_BITS; bit++) {
        unsigned int ai = ((unsigned int)a0 >> bit) & 1u;
        unsigned int bi = ((unsigned int)a1 >> bit) & 1u;
        unsigned int sum = ai ^ bi ^ carry;
        unsigned int cout = (ai & bi) | (ai & carry) | (bi & carry);

        result |= sum << bit;
        carry = cout;
    }

    return (uint16_t)(result & KUNDU_WORD_MASK);
}

/*
 * Run the target coefficient normally until the target bit has been processed.
 * The produced carry-out and partial A2B intermediate are the attack target.
 */
__attribute__((noinline))
static void kundu_a2b_prefix_until_target(uint16_t a0,
                                          uint16_t a1,
                                          unsigned int target_bit,
                                          uint16_t *partial_out,
                                          unsigned int *carry_out)
{
    unsigned int bit;
    unsigned int carry = 0;
    unsigned int partial = 0;

    for (bit = 0; bit <= target_bit; bit++) {
        unsigned int ai = ((unsigned int)a0 >> bit) & 1u;
        unsigned int bi = ((unsigned int)a1 >> bit) & 1u;
        unsigned int sum = ai ^ bi ^ carry;
        unsigned int cout = (ai & bi) | (ai & carry) | (bi & carry);

        partial |= sum << bit;
        carry = cout;
    }

    *partial_out = (uint16_t)(partial & KUNDU_WORD_MASK);
    *carry_out = carry & 1u;
}

/*
 * Normal continuation after the target intermediate.
 *
 * This is the measured target primitive.  It is the same function in baseline
 * and attack.  Only its input data differs when the intermediate was faulted.
 */
__attribute__((noinline))
static uint16_t kundu_a2b_finish_from_intermediate(uint16_t a0,
                                                   uint16_t a1,
                                                   unsigned int next_bit,
                                                   uint16_t partial_in,
                                                   unsigned int carry_in)
{
    unsigned int bit;
    unsigned int carry = carry_in & 1u;
    unsigned int partial = (unsigned int)partial_in;

    for (bit = next_bit; bit < KUNDU_WORD_BITS; bit++) {
        unsigned int ai = ((unsigned int)a0 >> bit) & 1u;
        unsigned int bi = ((unsigned int)a1 >> bit) & 1u;
        unsigned int sum = ai ^ bi ^ carry;
        unsigned int cout = (ai & bi) | (ai & carry) | (bi & carry);

        partial &= ~(1u << bit);
        partial |= sum << bit;
        carry = cout;
    }

    return (uint16_t)(partial & KUNDU_WORD_MASK);
}

static void kundu_reset_observation_state(void)
{
    kundu_faults_applied = 0;
    kundu_entries = 0;
    kundu_exits = 0;
    kundu_semantic_valid = 0;
    kundu_output_matches_ref = 0;
    kundu_defense_error = 0;

    kundu_expected_carry = 0;
    kundu_used_carry = 0;
    kundu_expected_intermediate_bit = 0;
    kundu_used_intermediate_bit = 0;

    kundu_expected_target_value = 0;
    kundu_used_target_value = 0;
    kundu_expected_partial = 0;
    kundu_used_partial = 0;

    kundu_output_digest = 0;
    kundu_reference_digest = 0;
    kundu_output_diff = 0;

    kundu_hpc_anomaly = 0;
    kundu_hpc_region_cycles = 0;
    kundu_hpc_cpi = 0;
    kundu_hpc_exc = 0;
    kundu_hpc_lsu = 0;
    kundu_hpc_fold = 0;
    kundu_hpc_target_cycles = 0;
    kundu_hpc_cycles_min = 0xffffffffu;
    kundu_hpc_cycles_max = 0;
    kundu_hpc_cycles_sum = 0;
}

/*
 * Simulator-side data fault.  This function is deliberately called before the
 * external trigger and before DWT/HPC measurement starts.
 */
static void kundu_apply_data_fault_unmeasured(uint16_t *partial,
                                              unsigned int *carry)
{
    unsigned int tb = kundu_target_bit;

    if (kundu_model == KUNDU_MODEL_CARRY0) {
        *carry = 0u;
        kundu_faults_applied = 1u;
    } else if (kundu_model == KUNDU_MODEL_CARRY1) {
        *carry = 1u;
        kundu_faults_applied = 1u;
    } else if (kundu_model == KUNDU_MODEL_INTER0) {
        *partial = (uint16_t)(((unsigned int)(*partial)) & ~(1u << tb));
        kundu_faults_applied = 1u;
    } else if (kundu_model == KUNDU_MODEL_INTER1) {
        *partial = (uint16_t)(((unsigned int)(*partial)) | (1u << tb));
        kundu_faults_applied = 1u;
    } else {
        kundu_faults_applied = 0u;
    }
}

__attribute__((noinline))
static void kundu_run_masked_decoding_experiment(void)
{
    unsigned int i;
    unsigned int target = kundu_target_coeff;
    unsigned int bit = kundu_target_bit;
    uint16_t partial;
    uint16_t used_partial;
    unsigned int carry;
    unsigned int used_carry;
    uint32_t start;

    if (target >= KUNDU_NCOEFFS) {
        target = 0;
        kundu_target_coeff = 0;
    }

    if (bit >= KUNDU_WORD_BITS) {
        bit = 0;
        kundu_target_bit = 0;
    }

    kundu_entries++;

    /*
     * Reference output for comparison.
     */
    for (i = 0; i < KUNDU_NCOEFFS; i++) {
        kundu_ref[i] = kundu_a2b_decode_full_normal(kundu_a0[i], kundu_a1[i]);
    }

    kundu_reference_digest = kundu_fnv1a_words(kundu_ref, KUNDU_NCOEFFS);
    kundu_expected_target_value = kundu_ref[target];

    /*
     * Normal prefix coefficients.
     */
    for (i = 0; i < target; i++) {
        kundu_out[i] = kundu_a2b_decode_full_normal(kundu_a0[i], kundu_a1[i]);
    }

    /*
     * Target coefficient up to the produced target intermediate.
     */
    kundu_a2b_prefix_until_target(kundu_a0[target],
                                  kundu_a1[target],
                                  bit,
                                  &partial,
                                  &carry);

    kundu_expected_partial = partial;
    kundu_expected_carry = carry & 1u;
    kundu_expected_intermediate_bit = (((unsigned int)partial) >> bit) & 1u;

    used_partial = partial;
    used_carry = carry;

    /*
     * Data-value fault: overwrite carry/intermediate after it is produced.
     * This happens outside the target measurement window.
     */
    kundu_apply_data_fault_unmeasured(&used_partial, &used_carry);

    kundu_used_partial = used_partial;
    kundu_used_carry = used_carry & 1u;
    kundu_used_intermediate_bit = (((unsigned int)used_partial) >> bit) & 1u;

    /*
     * Clean target window: original continuation consumes the selected data.
     * Same function in baseline and attack.
     */
    trigger_high();
    kundu_hpc_region_begin();
    start = kundu_hpc_op_begin();

    kundu_out[target] = kundu_a2b_finish_from_intermediate(kundu_a0[target],
                                                           kundu_a1[target],
                                                           bit + 1u,
                                                           used_partial,
                                                           used_carry);

    kundu_hpc_target_cycles = kundu_hpc_op_end_common(start);
    kundu_hpc_region_end();
    trigger_low();

    kundu_used_target_value = kundu_out[target];

    /*
     * Normal suffix coefficients.
     */
    for (i = target + 1u; i < KUNDU_NCOEFFS; i++) {
        kundu_out[i] = kundu_a2b_decode_full_normal(kundu_a0[i], kundu_a1[i]);
    }

    kundu_output_digest = kundu_fnv1a_words(kundu_out, KUNDU_NCOEFFS);
    kundu_output_diff = kundu_output_digest ^ kundu_reference_digest;
    kundu_output_matches_ref = (kundu_output_digest == kundu_reference_digest) ? 1u : 0u;

    kundu_semantic_valid = 1u;
    kundu_exits++;
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
static uint8_t cmd_config(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_config(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    uint8_t out[20];
    unsigned int model;
    unsigned int target;
    unsigned int bit;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > KUNDU_MODEL_INTER1) {
        model = KUNDU_MODEL_NONE;
    }

    target = (unsigned int)buf[1] | (((unsigned int)buf[2]) << 8);
    if (target >= KUNDU_NCOEFFS) {
        target = 0;
    }

    bit = (unsigned int)buf[3];
    if (bit >= KUNDU_WORD_BITS) {
        bit = 0;
    }

    tweak = (unsigned int)buf[4] |
            (((unsigned int)buf[5]) << 8) |
            (((unsigned int)buf[6]) << 16) |
            (((unsigned int)buf[7]) << 24);

    kundu_model = model;
    kundu_target_coeff = target;
    kundu_target_bit = bit;
    kundu_message_tweak = tweak;

    kundu_init_inputs();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)kundu_model;
    put_u32le(out, 4, kundu_target_coeff);
    put_u32le(out, 8, kundu_target_bit);
    put_u32le(out, 12, kundu_message_tweak);
    put_u32le(out, 16, KUNDU_WORD_BITS);

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

    kundu_reset_observation_state();
    kundu_init_inputs();

    out[0] = 0;
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

    kundu_reset_observation_state();
    kundu_init_inputs();

    kundu_run_masked_decoding_experiment();

    out[0] = 0;
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

    out[0] = (uint8_t)kundu_model;
    out[1] = (uint8_t)kundu_semantic_valid;
    out[2] = (uint8_t)kundu_output_matches_ref;
    out[3] = 0;

    put_u32le(out, 4, kundu_faults_applied);
    put_u32le(out, 8, kundu_target_coeff);
    put_u32le(out, 12, kundu_target_bit);
    put_u32le(out, 16, kundu_expected_carry);
    put_u32le(out, 20, kundu_used_carry);

    out[24] = (uint8_t)kundu_expected_intermediate_bit;
    out[25] = (uint8_t)kundu_used_intermediate_bit;
    out[26] = (uint8_t)kundu_defense_error;
    out[27] = (uint8_t)kundu_hpc_anomaly;
    out[28] = (uint8_t)kundu_entries;
    out[29] = (uint8_t)kundu_exits;
    out[30] = 0;
    out[31] = 0;

    simpleserial_put('H', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_digest_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_digest_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[16];

    put_u32le(out, 0, kundu_output_digest);
    put_u32le(out, 4, kundu_reference_digest);
    put_u32le(out, 8, kundu_output_diff);
    put_u32le(out, 12, kundu_message_tweak);

    simpleserial_put('D', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_detail_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_detail_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[16];

    put_u32le(out, 0, kundu_expected_target_value);
    put_u32le(out, 4, kundu_used_target_value);
    put_u32le(out, 8, kundu_expected_partial);
    put_u32le(out, 12, kundu_used_partial);

    simpleserial_put('R', sizeof(out), out);
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
        ((kundu_hpc_cpi & 0xffu) << 0) |
        ((kundu_hpc_exc & 0xffu) << 8) |
        ((kundu_hpc_lsu & 0xffu) << 16) |
        ((kundu_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, kundu_hpc_available);
    put_u32le(out, 4, kundu_hpc_anomaly);
    put_u32le(out, 8, kundu_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, kundu_hpc_target_cycles);
    put_u32le(out, 20, kundu_hpc_cycles_min);
    put_u32le(out, 24, kundu_hpc_cycles_max);
    put_u32le(out, 28, kundu_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    kundu_reset_observation_state();
    kundu_init_inputs();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('R', 0, cmd_detail_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef KUNDU_BOOT_BANNER
#define KUNDU_BOOT_BANNER 1
#endif

#if KUNDU_BOOT_BANNER
    uart_puts("KUNDU_CARRY_FAULT_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
