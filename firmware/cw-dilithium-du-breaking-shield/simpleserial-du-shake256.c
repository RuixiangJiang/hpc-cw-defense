#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Du et al., "Breaking the Shield" -- SHAKE256 absorb-loop attack
 *
 * Semantic model:
 *
 *   The attack skips or aborts a SHAKE256 absorb loop.  The sponge state
 *   absorbs fewer input blocks than intended.  The output is then produced by
 *   the normal squeeze path from the faulted state.
 *
 * Models:
 *   0 = normal absorb loop
 *   1 = loop-abort: execute only prefix absorb iterations [0, stop_block)
 *   2 = single-block skip: execute normal prefix blocks, omit target block,
 *       execute normal suffix blocks
 *
 * Clean target window:
 *   state/input setup outside window
 *   routine selection outside window
 *   trigger/DWT window contains only selected absorb routine
 *   normal finalize/squeeze path after window
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef DU_HPC_TARGET_CYCLES_MIN
#define DU_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef DU_HPC_TARGET_CYCLES_MAX
#define DU_HPC_TARGET_CYCLES_MAX 0
#endif

#define DU_MODEL_NONE       0u
#define DU_MODEL_ABORT      1u
#define DU_MODEL_SKIPBLOCK  2u

#define DU_ERR_HW_COUNTER 0x40u
#define DU_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define DU_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define DU_STATE_WORDS 50u
#define DU_ABSORB_BLOCKS 8u
#define DU_ABSORB_BLOCK_BYTES 32u
#define DU_INPUT_BYTES (DU_ABSORB_BLOCKS * DU_ABSORB_BLOCK_BYTES)
#define DU_OUTPUT_BYTES 32u

static uint32_t du_state[DU_STATE_WORDS];
static uint8_t du_input[DU_INPUT_BYTES];
static uint8_t du_output[DU_OUTPUT_BYTES];

volatile unsigned int du_model = DU_MODEL_NONE;
volatile unsigned int du_stop_block = 4;
volatile unsigned int du_skip_block = 3;
volatile unsigned int du_message_tweak = 0;

volatile unsigned int du_faults_applied = 0;
volatile unsigned int du_entries = 0;
volatile unsigned int du_exits = 0;
volatile unsigned int du_semantic_valid = 0;
volatile unsigned int du_output_matches_clean = 0;
volatile unsigned int du_output_matches_abort = 0;
volatile unsigned int du_output_matches_skip = 0;
volatile unsigned int du_defense_error = 0;

volatile unsigned int du_expected_blocks = DU_ABSORB_BLOCKS;
volatile unsigned int du_used_blocks = DU_ABSORB_BLOCKS;
volatile unsigned int du_skipped_blocks = 0;
volatile unsigned int du_input_digest = 0;
volatile unsigned int du_state_digest_after_absorb = 0;

volatile unsigned int du_output_digest = 0;
volatile unsigned int du_clean_digest = 0;
volatile unsigned int du_abort_digest = 0;
volatile unsigned int du_skip_digest = 0;

volatile unsigned int du_hpc_available = 0;
volatile unsigned int du_hpc_anomaly = 0;
volatile unsigned int du_hpc_region_cycles = 0;
volatile unsigned int du_hpc_cpi = 0;
volatile unsigned int du_hpc_exc = 0;
volatile unsigned int du_hpc_lsu = 0;
volatile unsigned int du_hpc_fold = 0;
volatile unsigned int du_hpc_target_cycles = 0;
volatile unsigned int du_hpc_cycles_min = 0xffffffffu;
volatile unsigned int du_hpc_cycles_max = 0;
volatile unsigned int du_hpc_cycles_sum = 0;

typedef void (*du_shake_absorb_routine_fn)(uint32_t *state, const uint8_t *input);

#if HPC_HW_ENABLE
#define DU_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define DU_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define DU_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define DU_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define DU_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define DU_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define DU_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)
#define DU_HPC_DEMCR_TRCENA          (1u << 24)
#define DU_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define DU_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)
static uint32_t du_hpc_region_start = 0;

static inline void du_hpc_dwt_enable(void)
{
    uint32_t ctrl;
    DU_HPC_DEMCR |= DU_HPC_DEMCR_TRCENA;
    ctrl = DU_HPC_DWT_CTRL;
    if ((ctrl & DU_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        DU_HPC_DWT_CTRL |= DU_HPC_DWT_CTRL_CYCCNTENA;
        du_hpc_available |= 0x01u;
    }
    DU_HPC_DWT_CPICNT = 0;
    DU_HPC_DWT_EXCCNT = 0;
    DU_HPC_DWT_LSUCNT = 0;
    DU_HPC_DWT_FOLDCNT = 0;
    du_hpc_available |= 0x02u;
}

static inline void du_hpc_region_begin(void)
{
    du_hpc_dwt_enable();
    du_hpc_anomaly = 0;
    du_hpc_region_cycles = 0;
    du_hpc_cpi = 0;
    du_hpc_exc = 0;
    du_hpc_lsu = 0;
    du_hpc_fold = 0;
    du_hpc_target_cycles = 0;
    du_hpc_cycles_min = 0xffffffffu;
    du_hpc_cycles_max = 0;
    du_hpc_cycles_sum = 0;
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    du_hpc_region_start = DU_HPC_DWT_CYCCNT;
}

static inline uint32_t du_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return DU_HPC_DWT_CYCCNT;
}

static inline uint32_t du_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;
    if ((du_hpc_available & 0x01u) == 0u) {
        return 0;
    }
    __asm volatile("" ::: "memory");
    delta = DU_HPC_DWT_CYCCNT - start;
    du_hpc_cycles_sum += delta;
    if (delta < du_hpc_cycles_min) du_hpc_cycles_min = delta;
    if (delta > du_hpc_cycles_max) du_hpc_cycles_max = delta;
    return delta;
}

static inline void du_hpc_region_end(void)
{
    uint32_t end;
    __asm volatile("" ::: "memory");
    end = DU_HPC_DWT_CYCCNT;
    du_hpc_region_cycles = end - du_hpc_region_start;
    du_hpc_cpi = DU_HPC_DWT_CPICNT & 0xffu;
    du_hpc_exc = DU_HPC_DWT_EXCCNT & 0xffu;
    du_hpc_lsu = DU_HPC_DWT_LSUCNT & 0xffu;
    du_hpc_fold = DU_HPC_DWT_FOLDCNT & 0xffu;
#if DU_HPC_TARGET_CYCLES_MIN > 0
    if (du_hpc_target_cycles < (unsigned int)DU_HPC_TARGET_CYCLES_MIN) du_hpc_anomaly |= DU_HPC_ERR_TARGET_CYCLES_LOW;
#endif
#if DU_HPC_TARGET_CYCLES_MAX > 0
    if (du_hpc_target_cycles > (unsigned int)DU_HPC_TARGET_CYCLES_MAX) du_hpc_anomaly |= DU_HPC_ERR_TARGET_CYCLES_HIGH;
#endif
    if (du_hpc_anomaly != 0u) du_defense_error |= DU_ERR_HW_COUNTER;
}
#else
static inline void du_hpc_region_begin(void) { du_hpc_anomaly = 0; du_hpc_region_cycles = 0; du_hpc_target_cycles = 0; du_hpc_cycles_min = 0xffffffffu; du_hpc_cycles_max = 0; du_hpc_cycles_sum = 0; }
static inline uint32_t du_hpc_op_begin(void) { return 0; }
static inline uint32_t du_hpc_op_end_common(uint32_t start) { (void)start; return 0; }
static inline void du_hpc_region_end(void) { }
#endif

static uint32_t du_rotl32(uint32_t x, unsigned int r)
{
    return (x << r) | (x >> (32u - r));
}

static uint32_t du_fnv1a_bytes(const uint8_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;
    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }
    return h;
}

static uint32_t du_digest_words(const uint32_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;
    for (i = 0; i < len; i++) {
        uint32_t x = buf[i];
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }
    return h;
}

static void du_init_input(void)
{
    unsigned int i;
    uint32_t tweak = du_message_tweak;
    for (i = 0; i < DU_INPUT_BYTES; i++) {
        du_input[i] = (uint8_t)(0x5bu ^ (i * 17u) ^ ((tweak >> ((i & 3u) * 8u)) & 0xffu));
    }
    du_input_digest = du_fnv1a_bytes(du_input, DU_INPUT_BYTES);
}

static void du_shake_init(uint32_t *state)
{
    unsigned int i;
    for (i = 0; i < DU_STATE_WORDS; i++) {
        state[i] = 0x6a09e667u ^ (i * 0x01000193u);
    }
}

__attribute__((noinline))
static void du_shake_absorb_one_block(uint32_t *state, const uint8_t *block, unsigned int block_index)
{
    unsigned int i;
    for (i = 0; i < DU_ABSORB_BLOCK_BYTES; i++) {
        unsigned int word = ((i >> 2) + block_index * 3u) % DU_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;
        uint32_t x = ((uint32_t)block[i]) << shift;
        state[word] ^= x;
        state[(word + 17u) % DU_STATE_WORDS] += du_rotl32(x ^ (0x9e3779b9u + i + block_index), (i % 19u) + 1u);
        state[(word + 31u) % DU_STATE_WORDS] ^= du_rotl32(state[word] + 0x3c6ef372u, (i % 13u) + 3u);
    }

    for (i = 0; i < DU_STATE_WORDS; i++) {
        uint32_t a = state[i];
        uint32_t b = state[(i + 1u) % DU_STATE_WORDS];
        uint32_t c = state[(i + 13u) % DU_STATE_WORDS];
        state[i] = a ^ du_rotl32(b + c + block_index + i, (i % 23u) + 1u);
    }
}

__attribute__((noinline))
static void du_shake_absorb_normal(uint32_t *state, const uint8_t *input)
{
    unsigned int block;
    for (block = 0; block < DU_ABSORB_BLOCKS; block++) {
        du_shake_absorb_one_block(state, input + block * DU_ABSORB_BLOCK_BYTES, block);
    }
}

__attribute__((noinline))
static void du_shake_absorb_abort(uint32_t *state, const uint8_t *input)
{
    unsigned int block;
    unsigned int stop = du_stop_block;
    if (stop > DU_ABSORB_BLOCKS) stop = DU_ABSORB_BLOCKS;
    for (block = 0; block < stop; block++) {
        du_shake_absorb_one_block(state, input + block * DU_ABSORB_BLOCK_BYTES, block);
    }
}

__attribute__((noinline))
static void du_shake_absorb_skipblock(uint32_t *state, const uint8_t *input)
{
    unsigned int block;
    unsigned int skip = du_skip_block;
    if (skip >= DU_ABSORB_BLOCKS) skip = DU_ABSORB_BLOCKS - 1u;

    for (block = 0; block < skip; block++) {
        du_shake_absorb_one_block(state, input + block * DU_ABSORB_BLOCK_BYTES, block);
    }

    /*
     * Omit the target absorb-block body.
     */

    for (block = skip + 1u; block < DU_ABSORB_BLOCKS; block++) {
        du_shake_absorb_one_block(state, input + block * DU_ABSORB_BLOCK_BYTES, block);
    }
}

static void du_shake_finalize_squeeze_normal(uint32_t *state, uint8_t *output, unsigned int len)
{
    unsigned int i;
    state[0] ^= 0x1fu;
    state[DU_STATE_WORDS - 1u] ^= 0x80000000u;

    for (i = 0; i < DU_STATE_WORDS; i++) {
        state[i] ^= du_rotl32(state[(i + 7u) % DU_STATE_WORDS] + 0x7f4a7c15u + i, (i % 17u) + 1u);
    }

    for (i = 0; i < len; i++) {
        unsigned int word = (i >> 2) % DU_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;
        output[i] = (uint8_t)((state[word] >> shift) & 0xffu);
        state[(word + 9u) % DU_STATE_WORDS] ^= du_rotl32((uint32_t)output[i] + i, (i % 13u) + 1u);
    }
}

static uint32_t du_reference_digest_for_model(unsigned int model)
{
    uint32_t st[DU_STATE_WORDS];
    uint8_t out[DU_OUTPUT_BYTES];

    du_shake_init(st);

    if (model == DU_MODEL_ABORT) {
        du_shake_absorb_abort(st, du_input);
    } else if (model == DU_MODEL_SKIPBLOCK) {
        du_shake_absorb_skipblock(st, du_input);
    } else {
        du_shake_absorb_normal(st, du_input);
    }

    du_shake_finalize_squeeze_normal(st, out, DU_OUTPUT_BYTES);
    return du_fnv1a_bytes(out, DU_OUTPUT_BYTES) ^ du_digest_words(st, DU_STATE_WORDS);
}

static void du_reset_observation_state(void)
{
    du_faults_applied = 0;
    du_entries = 0;
    du_exits = 0;
    du_semantic_valid = 0;
    du_output_matches_clean = 0;
    du_output_matches_abort = 0;
    du_output_matches_skip = 0;
    du_defense_error = 0;
    du_expected_blocks = DU_ABSORB_BLOCKS;
    du_used_blocks = DU_ABSORB_BLOCKS;
    du_skipped_blocks = 0;
    du_state_digest_after_absorb = 0;
    du_output_digest = 0;
    du_clean_digest = 0;
    du_abort_digest = 0;
    du_skip_digest = 0;
    memset(du_state, 0, sizeof(du_state));
    memset(du_output, 0, sizeof(du_output));
    du_hpc_anomaly = 0;
    du_hpc_region_cycles = 0;
    du_hpc_cpi = 0;
    du_hpc_exc = 0;
    du_hpc_lsu = 0;
    du_hpc_fold = 0;
    du_hpc_target_cycles = 0;
    du_hpc_cycles_min = 0xffffffffu;
    du_hpc_cycles_max = 0;
    du_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void du_run_shake256_absorb_experiment(void)
{
    uint32_t start;
    du_shake_absorb_routine_fn routine;

    du_entries++;

    if (du_stop_block > DU_ABSORB_BLOCKS) du_stop_block = DU_ABSORB_BLOCKS;
    if (du_skip_block >= DU_ABSORB_BLOCKS) du_skip_block = DU_ABSORB_BLOCKS - 1u;

    du_clean_digest = du_reference_digest_for_model(DU_MODEL_NONE);
    du_abort_digest = du_reference_digest_for_model(DU_MODEL_ABORT);
    du_skip_digest = du_reference_digest_for_model(DU_MODEL_SKIPBLOCK);

    du_shake_init(du_state);

    /*
     * Select the absorb-loop routine outside the target window.
     */
    if (du_model == DU_MODEL_ABORT) {
        routine = du_shake_absorb_abort;
        du_used_blocks = du_stop_block;
        du_skipped_blocks = DU_ABSORB_BLOCKS - du_used_blocks;
        du_faults_applied = 1u;
    } else if (du_model == DU_MODEL_SKIPBLOCK) {
        routine = du_shake_absorb_skipblock;
        du_used_blocks = DU_ABSORB_BLOCKS - 1u;
        du_skipped_blocks = 1u;
        du_faults_applied = 1u;
    } else {
        routine = du_shake_absorb_normal;
        du_used_blocks = DU_ABSORB_BLOCKS;
        du_skipped_blocks = 0u;
        du_faults_applied = 0u;
    }

    trigger_high();
    du_hpc_region_begin();
    start = du_hpc_op_begin();

    routine(du_state, du_input);

    du_hpc_target_cycles = du_hpc_op_end_common(start);
    du_hpc_region_end();
    trigger_low();

    du_state_digest_after_absorb = du_digest_words(du_state, DU_STATE_WORDS);

    /*
     * Normal squeeze path from the clean or faulted state.
     */
    du_shake_finalize_squeeze_normal(du_state, du_output, DU_OUTPUT_BYTES);

    du_output_digest = du_fnv1a_bytes(du_output, DU_OUTPUT_BYTES) ^ du_digest_words(du_state, DU_STATE_WORDS);
    du_output_matches_clean = (du_output_digest == du_clean_digest) ? 1u : 0u;
    du_output_matches_abort = (du_output_digest == du_abort_digest) ? 1u : 0u;
    du_output_matches_skip = (du_output_digest == du_skip_digest) ? 1u : 0u;

    du_semantic_valid = 1u;
    du_exits++;
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
    while (*s) putch(*s++);
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
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
    (void)cmd; (void)scmd;
#endif
    uint8_t out[24];
    unsigned int model, stop_block, skip_block, tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > DU_MODEL_SKIPBLOCK) model = DU_MODEL_NONE;

    stop_block = (unsigned int)buf[1];
    if (stop_block > DU_ABSORB_BLOCKS) stop_block = DU_ABSORB_BLOCKS;

    skip_block = (unsigned int)buf[2];
    if (skip_block >= DU_ABSORB_BLOCKS) skip_block = DU_ABSORB_BLOCKS - 1u;

    tweak = (unsigned int)buf[3] |
            (((unsigned int)buf[4]) << 8) |
            (((unsigned int)buf[5]) << 16) |
            (((unsigned int)buf[6]) << 24);

    du_model = model;
    du_stop_block = stop_block;
    du_skip_block = skip_block;
    du_message_tweak = tweak;
    du_init_input();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)du_model;
    out[2] = (uint8_t)du_stop_block;
    out[3] = (uint8_t)du_skip_block;
    put_u32le(out, 4, du_message_tweak);
    put_u32le(out, 8, DU_ABSORB_BLOCKS);
    put_u32le(out, 12, DU_ABSORB_BLOCK_BYTES);
    put_u32le(out, 16, DU_OUTPUT_BYTES);
    put_u32le(out, 20, du_input_digest);

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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[1];
    du_reset_observation_state();
    du_init_input();
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[1];
    du_reset_observation_state();
    du_init_input();
    du_run_shake256_absorb_experiment();
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[32];
    memset(out, 0, sizeof(out));
    out[0] = (uint8_t)du_model;
    out[1] = (uint8_t)du_semantic_valid;
    out[2] = (uint8_t)du_output_matches_clean;
    out[3] = (uint8_t)du_output_matches_abort;
    out[4] = (uint8_t)du_output_matches_skip;
    out[5] = (uint8_t)du_stop_block;
    out[6] = (uint8_t)du_skip_block;
    put_u32le(out, 8, du_faults_applied);
    put_u32le(out, 12, du_expected_blocks);
    put_u32le(out, 16, du_used_blocks);
    put_u32le(out, 20, du_skipped_blocks);
    put_u32le(out, 24, du_state_digest_after_absorb);
    out[28] = (uint8_t)du_defense_error;
    out[29] = (uint8_t)du_hpc_anomaly;
    out[30] = (uint8_t)du_entries;
    out[31] = (uint8_t)du_exits;
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[16];
    put_u32le(out, 0, du_output_digest);
    put_u32le(out, 4, du_clean_digest);
    put_u32le(out, 8, du_abort_digest);
    put_u32le(out, 12, du_skip_digest);
    simpleserial_put('D', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_hpc_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_hpc_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[32];
    unsigned int packed = ((du_hpc_cpi & 0xffu) << 0) |
                          ((du_hpc_exc & 0xffu) << 8) |
                          ((du_hpc_lsu & 0xffu) << 16) |
                          ((du_hpc_fold & 0xffu) << 24);
    put_u32le(out, 0, du_hpc_available);
    put_u32le(out, 4, du_hpc_anomaly);
    put_u32le(out, 8, du_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, du_hpc_target_cycles);
    put_u32le(out, 20, du_hpc_cycles_min);
    put_u32le(out, 24, du_hpc_cycles_max);
    put_u32le(out, 28, du_hpc_cycles_sum);
    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();
    platform_init();
    init_uart();
    trigger_setup();
    du_reset_observation_state();
    du_init_input();
    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);
#ifndef DU_BOOT_BANNER
#define DU_BOOT_BANNER 1
#endif
#if DU_BOOT_BANNER
    uart_puts("DU_SHAKE256_ABSORB_READY\n");
#endif
    while (1) simpleserial_get();
    return 0;
}
