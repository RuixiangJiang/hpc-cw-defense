#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Wang et al., "Mind the Faulty KECCAK"
 *
 * Semantic model:
 *
 *   The attack changes Keccak loop execution.  A loop is aborted early or a
 *   selected loop body/block is omitted.  The surrounding Keccak call structure
 *   remains unchanged, so the observed timing difference corresponds to skipped
 *   loop work inside the Keccak routine itself.
 *
 * Models:
 *
 *   0 = normal Keccak-like permutation loop
 *   1 = loop-abort: execute only prefix rounds [0, stop_round)
 *   2 = single-round skip: execute normal prefix, omit target round, execute
 *       normal suffix
 *
 * This is an SRAM-safe semantic kernel.  It uses a compact Keccak-like
 * permutation stand-in instead of full Keccak-f1600.  The purpose is to isolate
 * loop-abort / loop-body-skip semantics and DWT/HPC timing effects without
 * changing the original attack model.
 *
 * Clean target-window design:
 *
 *   normal absorb / call setup
 *   select routine pointer outside target window
 *   trigger_high()
 *   DWT/HPC begin
 *   selected Keccak routine:
 *       normal full loop OR loop-abort routine OR single-round-skip routine
 *   DWT/HPC end
 *   trigger_low()
 *   normal squeeze / output handling
 *
 * The measured target window contains only the selected Keccak routine.  It
 * does not contain fault-model dispatch or "if attack then skip" logic.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef WANG_HPC_TARGET_CYCLES_MIN
#define WANG_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef WANG_HPC_TARGET_CYCLES_MAX
#define WANG_HPC_TARGET_CYCLES_MAX 0
#endif

#define WANG_MODEL_NONE       0u
#define WANG_MODEL_ABORT      1u
#define WANG_MODEL_SKIPROUND  2u

#define WANG_ERR_HW_COUNTER 0x40u
#define WANG_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define WANG_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define WANG_STATE_WORDS 50u
#define WANG_ROUNDS 24u
#define WANG_INPUT_BYTES 96u
#define WANG_OUTPUT_BYTES 32u

static uint32_t wang_state[WANG_STATE_WORDS];
static uint8_t wang_input[WANG_INPUT_BYTES];
static uint8_t wang_output[WANG_OUTPUT_BYTES];

volatile unsigned int wang_model = WANG_MODEL_NONE;
volatile unsigned int wang_stop_round = 8;
volatile unsigned int wang_skip_round = 7;
volatile unsigned int wang_message_tweak = 0;

volatile unsigned int wang_faults_applied = 0;
volatile unsigned int wang_entries = 0;
volatile unsigned int wang_exits = 0;
volatile unsigned int wang_semantic_valid = 0;
volatile unsigned int wang_output_matches_clean = 0;
volatile unsigned int wang_output_matches_abort = 0;
volatile unsigned int wang_output_matches_skip = 0;
volatile unsigned int wang_defense_error = 0;

volatile unsigned int wang_expected_rounds = WANG_ROUNDS;
volatile unsigned int wang_used_rounds = WANG_ROUNDS;
volatile unsigned int wang_skipped_rounds = 0;
volatile unsigned int wang_input_digest = 0;
volatile unsigned int wang_state_digest_after_absorb = 0;

volatile unsigned int wang_output_digest = 0;
volatile unsigned int wang_clean_digest = 0;
volatile unsigned int wang_abort_digest = 0;
volatile unsigned int wang_skip_digest = 0;

volatile unsigned int wang_hpc_available = 0;
volatile unsigned int wang_hpc_anomaly = 0;
volatile unsigned int wang_hpc_region_cycles = 0;
volatile unsigned int wang_hpc_cpi = 0;
volatile unsigned int wang_hpc_exc = 0;
volatile unsigned int wang_hpc_lsu = 0;
volatile unsigned int wang_hpc_fold = 0;
volatile unsigned int wang_hpc_target_cycles = 0;
volatile unsigned int wang_hpc_cycles_min = 0xffffffffu;
volatile unsigned int wang_hpc_cycles_max = 0;
volatile unsigned int wang_hpc_cycles_sum = 0;

typedef void (*wang_keccak_routine_fn)(uint32_t *state);

#if HPC_HW_ENABLE

#define WANG_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define WANG_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define WANG_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define WANG_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define WANG_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define WANG_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define WANG_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define WANG_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define WANG_HPC_DEMCR_TRCENA          (1u << 24)
#define WANG_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define WANG_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t wang_hpc_region_start = 0;

static inline void wang_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    WANG_HPC_DEMCR |= WANG_HPC_DEMCR_TRCENA;
    ctrl = WANG_HPC_DWT_CTRL;

    if ((ctrl & WANG_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        WANG_HPC_DWT_CTRL |= WANG_HPC_DWT_CTRL_CYCCNTENA;
        wang_hpc_available |= 0x01u;
    }

    WANG_HPC_DWT_CPICNT = 0;
    WANG_HPC_DWT_EXCCNT = 0;
    WANG_HPC_DWT_SLEEPCNT = 0;
    WANG_HPC_DWT_LSUCNT = 0;
    WANG_HPC_DWT_FOLDCNT = 0;
    wang_hpc_available |= 0x02u;
}

static inline void wang_hpc_region_begin(void)
{
    wang_hpc_dwt_enable();

    wang_hpc_anomaly = 0;
    wang_hpc_region_cycles = 0;
    wang_hpc_cpi = 0;
    wang_hpc_exc = 0;
    wang_hpc_lsu = 0;
    wang_hpc_fold = 0;
    wang_hpc_target_cycles = 0;
    wang_hpc_cycles_min = 0xffffffffu;
    wang_hpc_cycles_max = 0;
    wang_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    wang_hpc_region_start = WANG_HPC_DWT_CYCCNT;
}

static inline uint32_t wang_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return WANG_HPC_DWT_CYCCNT;
}

static inline uint32_t wang_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((wang_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = WANG_HPC_DWT_CYCCNT - start;

    wang_hpc_cycles_sum += delta;

    if (delta < wang_hpc_cycles_min) {
        wang_hpc_cycles_min = delta;
    }

    if (delta > wang_hpc_cycles_max) {
        wang_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void wang_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = WANG_HPC_DWT_CYCCNT;
    wang_hpc_region_cycles = end - wang_hpc_region_start;

    wang_hpc_cpi = WANG_HPC_DWT_CPICNT & 0xffu;
    wang_hpc_exc = WANG_HPC_DWT_EXCCNT & 0xffu;
    wang_hpc_lsu = WANG_HPC_DWT_LSUCNT & 0xffu;
    wang_hpc_fold = WANG_HPC_DWT_FOLDCNT & 0xffu;

#if WANG_HPC_TARGET_CYCLES_MIN > 0
    if (wang_hpc_target_cycles < (unsigned int)WANG_HPC_TARGET_CYCLES_MIN) {
        wang_hpc_anomaly |= WANG_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if WANG_HPC_TARGET_CYCLES_MAX > 0
    if (wang_hpc_target_cycles > (unsigned int)WANG_HPC_TARGET_CYCLES_MAX) {
        wang_hpc_anomaly |= WANG_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (wang_hpc_anomaly != 0u) {
        wang_defense_error |= WANG_ERR_HW_COUNTER;
    }
}

#else

static inline void wang_hpc_region_begin(void)
{
    wang_hpc_anomaly = 0;
    wang_hpc_region_cycles = 0;
    wang_hpc_target_cycles = 0;
    wang_hpc_cycles_min = 0xffffffffu;
    wang_hpc_cycles_max = 0;
    wang_hpc_cycles_sum = 0;
}

static inline uint32_t wang_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t wang_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void wang_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static uint32_t wang_rotl32(uint32_t x, unsigned int r)
{
    return (x << r) | (x >> (32u - r));
}

static uint32_t wang_fnv1a_bytes(const uint8_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }

    return h;
}

static uint32_t wang_digest_words(const uint32_t *buf, unsigned int len)
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

static void wang_init_input(void)
{
    unsigned int i;
    uint32_t tweak = wang_message_tweak;

    for (i = 0; i < WANG_INPUT_BYTES; i++) {
        wang_input[i] = (uint8_t)(0x42u ^ (i * 13u) ^
                                  ((tweak >> ((i & 3u) * 8u)) & 0xffu));
    }

    wang_input_digest = wang_fnv1a_bytes(wang_input, WANG_INPUT_BYTES);
}

static void wang_keccak_init(uint32_t *state)
{
    unsigned int i;

    for (i = 0; i < WANG_STATE_WORDS; i++) {
        state[i] = 0u;
    }
}

static void wang_keccak_absorb_unmeasured(uint32_t *state,
                                          const uint8_t *input,
                                          unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
        unsigned int word = (i >> 2) % WANG_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;
        uint32_t x = ((uint32_t)input[i]) << shift;

        state[word] ^= x;
        state[(word + 19u) % WANG_STATE_WORDS] +=
            wang_rotl32(x ^ (0x9e3779b9u + i), (i % 17u) + 1u);
    }
}

/*
 * One compact Keccak-like round stand-in.
 * This is the loop body whose execution count is faulted.
 */
__attribute__((noinline))
static void wang_keccak_round_body(uint32_t *state, unsigned int round)
{
    unsigned int i;
    uint32_t theta = 0x6a09e667u ^ (round * 0x01000193u);

    for (i = 0; i < WANG_STATE_WORDS; i++) {
        theta ^= wang_rotl32(state[i] + i + round, (i % 23u) + 1u);
    }

    for (i = 0; i < WANG_STATE_WORDS; i++) {
        uint32_t a = state[i];
        uint32_t b = state[(i + 1u) % WANG_STATE_WORDS];
        uint32_t c = state[(i + 13u) % WANG_STATE_WORDS];

        a ^= wang_rotl32(theta + b + (round << 8), (i % 19u) + 1u);
        a += wang_rotl32(c ^ (0x7f4a7c15u + round + i), (i % 11u) + 3u);
        a ^= (b & ~c);
        state[i] = a;
    }
}

/*
 * Normal Keccak-like routine: execute all rounds.
 */
__attribute__((noinline))
static void wang_keccak_routine_normal(uint32_t *state)
{
    unsigned int round;

    for (round = 0; round < WANG_ROUNDS; round++) {
        wang_keccak_round_body(state, round);
    }
}

/*
 * Loop-abort model: execute only the prefix of the original loop.
 * The surrounding Keccak call structure is unchanged.
 */
__attribute__((noinline))
static void wang_keccak_routine_abort(uint32_t *state)
{
    unsigned int round;
    unsigned int stop = wang_stop_round;

    if (stop > WANG_ROUNDS) {
        stop = WANG_ROUNDS;
    }

    for (round = 0; round < stop; round++) {
        wang_keccak_round_body(state, round);
    }
}

/*
 * Single-round skip model:
 * execute normal prefix rounds, omit the selected round body, then execute
 * normal suffix rounds.
 */
__attribute__((noinline))
static void wang_keccak_routine_skipround(uint32_t *state)
{
    unsigned int round;
    unsigned int skip = wang_skip_round;

    if (skip >= WANG_ROUNDS) {
        skip = WANG_ROUNDS - 1u;
    }

    for (round = 0; round < skip; round++) {
        wang_keccak_round_body(state, round);
    }

    /*
     * Omit target round body.
     */

    for (round = skip + 1u; round < WANG_ROUNDS; round++) {
        wang_keccak_round_body(state, round);
    }
}

static void wang_squeeze_unmeasured(uint32_t *state,
                                    uint8_t *output,
                                    unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
        unsigned int word = (i >> 2) % WANG_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;

        output[i] = (uint8_t)((state[word] >> shift) & 0xffu);
        state[(word + 7u) % WANG_STATE_WORDS] ^=
            wang_rotl32((uint32_t)output[i] + i, (i % 13u) + 1u);
    }
}

static uint32_t wang_reference_digest_for_model(unsigned int model)
{
    uint32_t st[WANG_STATE_WORDS];
    uint8_t out[WANG_OUTPUT_BYTES];

    wang_keccak_init(st);
    wang_keccak_absorb_unmeasured(st, wang_input, WANG_INPUT_BYTES);

    if (model == WANG_MODEL_ABORT) {
        wang_keccak_routine_abort(st);
    } else if (model == WANG_MODEL_SKIPROUND) {
        wang_keccak_routine_skipround(st);
    } else {
        wang_keccak_routine_normal(st);
    }

    wang_squeeze_unmeasured(st, out, WANG_OUTPUT_BYTES);

    return wang_fnv1a_bytes(out, WANG_OUTPUT_BYTES) ^
           wang_digest_words(st, WANG_STATE_WORDS);
}

static void wang_reset_observation_state(void)
{
    wang_faults_applied = 0;
    wang_entries = 0;
    wang_exits = 0;
    wang_semantic_valid = 0;
    wang_output_matches_clean = 0;
    wang_output_matches_abort = 0;
    wang_output_matches_skip = 0;
    wang_defense_error = 0;

    wang_expected_rounds = WANG_ROUNDS;
    wang_used_rounds = WANG_ROUNDS;
    wang_skipped_rounds = 0;
    wang_state_digest_after_absorb = 0;

    wang_output_digest = 0;
    wang_clean_digest = 0;
    wang_abort_digest = 0;
    wang_skip_digest = 0;

    memset(wang_state, 0, sizeof(wang_state));
    memset(wang_output, 0, sizeof(wang_output));

    wang_hpc_anomaly = 0;
    wang_hpc_region_cycles = 0;
    wang_hpc_cpi = 0;
    wang_hpc_exc = 0;
    wang_hpc_lsu = 0;
    wang_hpc_fold = 0;
    wang_hpc_target_cycles = 0;
    wang_hpc_cycles_min = 0xffffffffu;
    wang_hpc_cycles_max = 0;
    wang_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void wang_run_faulty_keccak_experiment(void)
{
    uint32_t start;
    wang_keccak_routine_fn routine;

    wang_entries++;

    if (wang_stop_round > WANG_ROUNDS) {
        wang_stop_round = WANG_ROUNDS;
    }

    if (wang_skip_round >= WANG_ROUNDS) {
        wang_skip_round = WANG_ROUNDS - 1u;
    }

    wang_clean_digest = wang_reference_digest_for_model(WANG_MODEL_NONE);
    wang_abort_digest = wang_reference_digest_for_model(WANG_MODEL_ABORT);
    wang_skip_digest = wang_reference_digest_for_model(WANG_MODEL_SKIPROUND);

    /*
     * Surrounding Keccak call structure: init + absorb happen normally and are
     * outside the measured loop-fault window.
     */
    wang_keccak_init(wang_state);
    wang_keccak_absorb_unmeasured(wang_state, wang_input, WANG_INPUT_BYTES);
    wang_state_digest_after_absorb = wang_digest_words(wang_state, WANG_STATE_WORDS);

    /*
     * Select the actual Keccak routine outside the target window.
     */
    if (wang_model == WANG_MODEL_ABORT) {
        routine = wang_keccak_routine_abort;
        wang_used_rounds = wang_stop_round;
        wang_skipped_rounds = WANG_ROUNDS - wang_used_rounds;
        wang_faults_applied = 1u;
    } else if (wang_model == WANG_MODEL_SKIPROUND) {
        routine = wang_keccak_routine_skipround;
        wang_used_rounds = WANG_ROUNDS - 1u;
        wang_skipped_rounds = 1u;
        wang_faults_applied = 1u;
    } else {
        routine = wang_keccak_routine_normal;
        wang_used_rounds = WANG_ROUNDS;
        wang_skipped_rounds = 0u;
        wang_faults_applied = 0u;
    }

    /*
     * Clean target window: only the selected Keccak loop routine.
     */
    trigger_high();
    wang_hpc_region_begin();
    start = wang_hpc_op_begin();

    routine(wang_state);

    wang_hpc_target_cycles = wang_hpc_op_end_common(start);
    wang_hpc_region_end();
    trigger_low();

    /*
     * Surrounding Keccak call structure continues normally.
     */
    wang_squeeze_unmeasured(wang_state, wang_output, WANG_OUTPUT_BYTES);

    wang_output_digest =
        wang_fnv1a_bytes(wang_output, WANG_OUTPUT_BYTES) ^
        wang_digest_words(wang_state, WANG_STATE_WORDS);

    wang_output_matches_clean = (wang_output_digest == wang_clean_digest) ? 1u : 0u;
    wang_output_matches_abort = (wang_output_digest == wang_abort_digest) ? 1u : 0u;
    wang_output_matches_skip = (wang_output_digest == wang_skip_digest) ? 1u : 0u;

    wang_semantic_valid = 1u;
    wang_exits++;
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

    uint8_t out[24];
    unsigned int model;
    unsigned int stop_round;
    unsigned int skip_round;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > WANG_MODEL_SKIPROUND) {
        model = WANG_MODEL_NONE;
    }

    stop_round = (unsigned int)buf[1];
    if (stop_round > WANG_ROUNDS) {
        stop_round = WANG_ROUNDS;
    }

    skip_round = (unsigned int)buf[2];
    if (skip_round >= WANG_ROUNDS) {
        skip_round = WANG_ROUNDS - 1u;
    }

    tweak = (unsigned int)buf[3] |
            (((unsigned int)buf[4]) << 8) |
            (((unsigned int)buf[5]) << 16) |
            (((unsigned int)buf[6]) << 24);

    wang_model = model;
    wang_stop_round = stop_round;
    wang_skip_round = skip_round;
    wang_message_tweak = tweak;

    wang_init_input();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)wang_model;
    out[2] = (uint8_t)wang_stop_round;
    out[3] = (uint8_t)wang_skip_round;
    put_u32le(out, 4, wang_message_tweak);
    put_u32le(out, 8, WANG_ROUNDS);
    put_u32le(out, 12, WANG_INPUT_BYTES);
    put_u32le(out, 16, WANG_OUTPUT_BYTES);
    put_u32le(out, 20, wang_input_digest);

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

    wang_reset_observation_state();
    wang_init_input();

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

    wang_reset_observation_state();
    wang_init_input();

    wang_run_faulty_keccak_experiment();

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

    out[0] = (uint8_t)wang_model;
    out[1] = (uint8_t)wang_semantic_valid;
    out[2] = (uint8_t)wang_output_matches_clean;
    out[3] = (uint8_t)wang_output_matches_abort;
    out[4] = (uint8_t)wang_output_matches_skip;
    out[5] = (uint8_t)wang_stop_round;
    out[6] = (uint8_t)wang_skip_round;
    out[7] = 0;

    put_u32le(out, 8, wang_faults_applied);
    put_u32le(out, 12, wang_expected_rounds);
    put_u32le(out, 16, wang_used_rounds);
    put_u32le(out, 20, wang_skipped_rounds);
    put_u32le(out, 24, wang_state_digest_after_absorb);

    out[28] = (uint8_t)wang_defense_error;
    out[29] = (uint8_t)wang_hpc_anomaly;
    out[30] = (uint8_t)wang_entries;
    out[31] = (uint8_t)wang_exits;

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

    put_u32le(out, 0, wang_output_digest);
    put_u32le(out, 4, wang_clean_digest);
    put_u32le(out, 8, wang_abort_digest);
    put_u32le(out, 12, wang_skip_digest);

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
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[32];
    unsigned int packed =
        ((wang_hpc_cpi & 0xffu) << 0) |
        ((wang_hpc_exc & 0xffu) << 8) |
        ((wang_hpc_lsu & 0xffu) << 16) |
        ((wang_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, wang_hpc_available);
    put_u32le(out, 4, wang_hpc_anomaly);
    put_u32le(out, 8, wang_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, wang_hpc_target_cycles);
    put_u32le(out, 20, wang_hpc_cycles_min);
    put_u32le(out, 24, wang_hpc_cycles_max);
    put_u32le(out, 28, wang_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    wang_reset_observation_state();
    wang_init_input();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef WANG_BOOT_BANNER
#define WANG_BOOT_BANNER 1
#endif

#if WANG_BOOT_BANNER
    uart_puts("WANG_FAULTY_KECCAK_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
