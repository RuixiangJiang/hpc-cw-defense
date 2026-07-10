#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Wang et al., "Secret in OnePiece"
 *
 * Semantic model:
 *
 *   The attack targets a bitsliced masked decoder.  A bit assignment or OR
 *   operation is skipped, so a target bit is not inserted into the destination
 *   word.  The decoder then proceeds with one missing/stale bit.
 *
 * Correct simulation structure:
 *
 *   normal prefix bit insertions
 *   one target insertion primitive:
 *      baseline: normal bit insertion
 *      attack:  skipped insertion; destination word is returned unchanged
 *   normal suffix bit insertions
 *
 * The target operation is loop-internal, but the simulation does not add a
 * target-check branch to every iteration.  The flattened bitsliced decoding
 * sequence is split into prefix, target, and suffix regions.
 *
 * Clean target-window design:
 *
 *   - target function pointer selected outside trigger/DWT window
 *   - target window contains only one target insertion primitive call
 *   - no fault-model dispatch inside the measured window
 *   - no "if attack then skip" inside the measured window
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef ONEPIECE_HPC_TARGET_CYCLES_MIN
#define ONEPIECE_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef ONEPIECE_HPC_TARGET_CYCLES_MAX
#define ONEPIECE_HPC_TARGET_CYCLES_MAX 0
#endif

#define ONEPIECE_MODEL_NONE 0u
#define ONEPIECE_MODEL_SKIP 1u

#define ONEPIECE_ERR_HW_COUNTER 0x40u
#define ONEPIECE_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define ONEPIECE_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define ONEPIECE_NWORDS 128u
#define ONEPIECE_WORD_BITS 16u
#define ONEPIECE_TOTAL_INSERTIONS (ONEPIECE_NWORDS * ONEPIECE_WORD_BITS)

static uint16_t onepiece_source_words[ONEPIECE_NWORDS];
static uint16_t onepiece_initial_dst[ONEPIECE_NWORDS];
static uint16_t onepiece_decoded[ONEPIECE_NWORDS];
static uint16_t onepiece_reference[ONEPIECE_NWORDS];

volatile unsigned int onepiece_model = ONEPIECE_MODEL_NONE;
volatile unsigned int onepiece_target_word = 17;
volatile unsigned int onepiece_target_bit = 5;
volatile unsigned int onepiece_previous_bit = 0;
volatile unsigned int onepiece_message_tweak = 0;

volatile unsigned int onepiece_faults_applied = 0;
volatile unsigned int onepiece_entries = 0;
volatile unsigned int onepiece_exits = 0;
volatile unsigned int onepiece_semantic_valid = 0;
volatile unsigned int onepiece_output_matches_ref = 0;
volatile unsigned int onepiece_defense_error = 0;

volatile unsigned int onepiece_target_linear = 0;
volatile unsigned int onepiece_source_bit = 0;
volatile unsigned int onepiece_expected_bit = 0;
volatile unsigned int onepiece_used_bit = 0;
volatile unsigned int onepiece_stale_bit = 0;

volatile unsigned int onepiece_expected_word = 0;
volatile unsigned int onepiece_used_word = 0;
volatile unsigned int onepiece_word_before_target = 0;

volatile unsigned int onepiece_prefix_count = 0;
volatile unsigned int onepiece_suffix_count = 0;
volatile unsigned int onepiece_input_digest = 0;
volatile unsigned int onepiece_output_digest = 0;
volatile unsigned int onepiece_reference_digest = 0;
volatile unsigned int onepiece_output_diff = 0;

volatile unsigned int onepiece_hpc_available = 0;
volatile unsigned int onepiece_hpc_anomaly = 0;
volatile unsigned int onepiece_hpc_region_cycles = 0;
volatile unsigned int onepiece_hpc_cpi = 0;
volatile unsigned int onepiece_hpc_exc = 0;
volatile unsigned int onepiece_hpc_lsu = 0;
volatile unsigned int onepiece_hpc_fold = 0;
volatile unsigned int onepiece_hpc_target_cycles = 0;
volatile unsigned int onepiece_hpc_cycles_min = 0xffffffffu;
volatile unsigned int onepiece_hpc_cycles_max = 0;
volatile unsigned int onepiece_hpc_cycles_sum = 0;

typedef uint16_t (*onepiece_insert_fn)(uint16_t dst, unsigned int bit, unsigned int bitpos);

#if HPC_HW_ENABLE

#define ONEPIECE_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define ONEPIECE_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define ONEPIECE_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define ONEPIECE_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define ONEPIECE_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define ONEPIECE_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define ONEPIECE_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define ONEPIECE_HPC_DEMCR_TRCENA          (1u << 24)
#define ONEPIECE_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define ONEPIECE_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t onepiece_hpc_region_start = 0;

static inline void onepiece_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    ONEPIECE_HPC_DEMCR |= ONEPIECE_HPC_DEMCR_TRCENA;
    ctrl = ONEPIECE_HPC_DWT_CTRL;

    if ((ctrl & ONEPIECE_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        ONEPIECE_HPC_DWT_CTRL |= ONEPIECE_HPC_DWT_CTRL_CYCCNTENA;
        onepiece_hpc_available |= 0x01u;
    }

    ONEPIECE_HPC_DWT_CPICNT = 0;
    ONEPIECE_HPC_DWT_EXCCNT = 0;
    ONEPIECE_HPC_DWT_LSUCNT = 0;
    ONEPIECE_HPC_DWT_FOLDCNT = 0;
    onepiece_hpc_available |= 0x02u;
}

static inline void onepiece_hpc_region_begin(void)
{
    onepiece_hpc_dwt_enable();

    onepiece_hpc_anomaly = 0;
    onepiece_hpc_region_cycles = 0;
    onepiece_hpc_cpi = 0;
    onepiece_hpc_exc = 0;
    onepiece_hpc_lsu = 0;
    onepiece_hpc_fold = 0;
    onepiece_hpc_target_cycles = 0;
    onepiece_hpc_cycles_min = 0xffffffffu;
    onepiece_hpc_cycles_max = 0;
    onepiece_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    onepiece_hpc_region_start = ONEPIECE_HPC_DWT_CYCCNT;
}

static inline uint32_t onepiece_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return ONEPIECE_HPC_DWT_CYCCNT;
}

static inline uint32_t onepiece_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((onepiece_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = ONEPIECE_HPC_DWT_CYCCNT - start;

    onepiece_hpc_cycles_sum += delta;

    if (delta < onepiece_hpc_cycles_min) {
        onepiece_hpc_cycles_min = delta;
    }

    if (delta > onepiece_hpc_cycles_max) {
        onepiece_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void onepiece_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = ONEPIECE_HPC_DWT_CYCCNT;
    onepiece_hpc_region_cycles = end - onepiece_hpc_region_start;

    onepiece_hpc_cpi = ONEPIECE_HPC_DWT_CPICNT & 0xffu;
    onepiece_hpc_exc = ONEPIECE_HPC_DWT_EXCCNT & 0xffu;
    onepiece_hpc_lsu = ONEPIECE_HPC_DWT_LSUCNT & 0xffu;
    onepiece_hpc_fold = ONEPIECE_HPC_DWT_FOLDCNT & 0xffu;

#if ONEPIECE_HPC_TARGET_CYCLES_MIN > 0
    if (onepiece_hpc_target_cycles < (unsigned int)ONEPIECE_HPC_TARGET_CYCLES_MIN) {
        onepiece_hpc_anomaly |= ONEPIECE_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if ONEPIECE_HPC_TARGET_CYCLES_MAX > 0
    if (onepiece_hpc_target_cycles > (unsigned int)ONEPIECE_HPC_TARGET_CYCLES_MAX) {
        onepiece_hpc_anomaly |= ONEPIECE_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (onepiece_hpc_anomaly != 0u) {
        onepiece_defense_error |= ONEPIECE_ERR_HW_COUNTER;
    }
}

#else

static inline void onepiece_hpc_region_begin(void)
{
    onepiece_hpc_anomaly = 0;
    onepiece_hpc_region_cycles = 0;
    onepiece_hpc_target_cycles = 0;
    onepiece_hpc_cycles_min = 0xffffffffu;
    onepiece_hpc_cycles_max = 0;
    onepiece_hpc_cycles_sum = 0;
}

static inline uint32_t onepiece_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t onepiece_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void onepiece_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static uint32_t onepiece_fnv1a_u16(const uint16_t *buf, unsigned int len)
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

static unsigned int onepiece_get_source_bit(unsigned int word, unsigned int bitpos)
{
    return ((unsigned int)(onepiece_source_words[word] >> bitpos)) & 1u;
}

/*
 * Normal bit assignment/insertion primitive.
 *
 * This models inserting one decoded bit into the destination word.
 */
__attribute__((noinline))
static uint16_t onepiece_insert_bit_normal(uint16_t dst,
                                           unsigned int bit,
                                           unsigned int bitpos)
{
    uint16_t mask = (uint16_t)(1u << bitpos);
    uint16_t b = (uint16_t)((bit & 1u) << bitpos);

    dst = (uint16_t)(dst & (uint16_t)(~mask));
    dst = (uint16_t)(dst | b);

    return dst;
}

/*
 * Faulted primitive.
 *
 * This directly models a skipped assignment or skipped OR operation: the
 * destination word is returned unchanged.  The target bit therefore retains its
 * previous/stale value at the target insertion point.
 */
__attribute__((noinline))
static uint16_t onepiece_insert_bit_skip(uint16_t dst,
                                         unsigned int bit,
                                         unsigned int bitpos)
{
    (void)bit;
    (void)bitpos;

    return dst;
}

static void onepiece_init_data(void)
{
    unsigned int i;
    uint32_t tweak = onepiece_message_tweak;
    uint16_t mask;

    if (onepiece_target_word >= ONEPIECE_NWORDS) {
        onepiece_target_word = 0u;
    }

    if (onepiece_target_bit >= ONEPIECE_WORD_BITS) {
        onepiece_target_bit = 0u;
    }

    onepiece_previous_bit &= 1u;

    for (i = 0; i < ONEPIECE_NWORDS; i++) {
        uint32_t x = 0xace1u ^ (i * 0x9e37u) ^
                     ((tweak >> ((i & 1u) * 16u)) & 0xffffu);
        onepiece_source_words[i] = (uint16_t)x;
        onepiece_initial_dst[i] = 0u;
    }

    /*
     * Prepare a target where the inserted bit differs from the previous/stale
     * destination bit.  This makes the local skipped insertion observable while
     * preserving the skipped-assignment semantics.
     */
    mask = (uint16_t)(1u << onepiece_target_bit);

    if (onepiece_previous_bit != 0u) {
        onepiece_initial_dst[onepiece_target_word] |= mask;
        onepiece_source_words[onepiece_target_word] =
            (uint16_t)(onepiece_source_words[onepiece_target_word] & (uint16_t)(~mask));
    } else {
        onepiece_initial_dst[onepiece_target_word] =
            (uint16_t)(onepiece_initial_dst[onepiece_target_word] & (uint16_t)(~mask));
        onepiece_source_words[onepiece_target_word] |= mask;
    }

    onepiece_input_digest =
        onepiece_fnv1a_u16(onepiece_source_words, ONEPIECE_NWORDS) ^
        onepiece_fnv1a_u16(onepiece_initial_dst, ONEPIECE_NWORDS);
}

static void onepiece_copy_initial(uint16_t *dst)
{
    unsigned int i;

    for (i = 0; i < ONEPIECE_NWORDS; i++) {
        dst[i] = onepiece_initial_dst[i];
    }
}

static void onepiece_decode_full_normal(uint16_t *dst)
{
    unsigned int idx;

    onepiece_copy_initial(dst);

    for (idx = 0; idx < ONEPIECE_TOTAL_INSERTIONS; idx++) {
        unsigned int word = idx / ONEPIECE_WORD_BITS;
        unsigned int bitpos = idx & (ONEPIECE_WORD_BITS - 1u);
        unsigned int bit = onepiece_get_source_bit(word, bitpos);

        dst[word] = onepiece_insert_bit_normal(dst[word], bit, bitpos);
    }
}

static void onepiece_decode_prefix(uint16_t *dst, unsigned int target_linear)
{
    unsigned int idx;

    for (idx = 0; idx < target_linear; idx++) {
        unsigned int word = idx / ONEPIECE_WORD_BITS;
        unsigned int bitpos = idx & (ONEPIECE_WORD_BITS - 1u);
        unsigned int bit = onepiece_get_source_bit(word, bitpos);

        dst[word] = onepiece_insert_bit_normal(dst[word], bit, bitpos);
    }
}

static void onepiece_decode_suffix(uint16_t *dst, unsigned int target_linear)
{
    unsigned int idx;

    for (idx = target_linear + 1u; idx < ONEPIECE_TOTAL_INSERTIONS; idx++) {
        unsigned int word = idx / ONEPIECE_WORD_BITS;
        unsigned int bitpos = idx & (ONEPIECE_WORD_BITS - 1u);
        unsigned int bit = onepiece_get_source_bit(word, bitpos);

        dst[word] = onepiece_insert_bit_normal(dst[word], bit, bitpos);
    }
}

static void onepiece_reset_observation_state(void)
{
    onepiece_faults_applied = 0;
    onepiece_entries = 0;
    onepiece_exits = 0;
    onepiece_semantic_valid = 0;
    onepiece_output_matches_ref = 0;
    onepiece_defense_error = 0;

    onepiece_target_linear = 0;
    onepiece_source_bit = 0;
    onepiece_expected_bit = 0;
    onepiece_used_bit = 0;
    onepiece_stale_bit = 0;

    onepiece_expected_word = 0;
    onepiece_used_word = 0;
    onepiece_word_before_target = 0;

    onepiece_prefix_count = 0;
    onepiece_suffix_count = 0;
    onepiece_output_digest = 0;
    onepiece_reference_digest = 0;
    onepiece_output_diff = 0;

    memset(onepiece_decoded, 0, sizeof(onepiece_decoded));
    memset(onepiece_reference, 0, sizeof(onepiece_reference));

    onepiece_hpc_anomaly = 0;
    onepiece_hpc_region_cycles = 0;
    onepiece_hpc_cpi = 0;
    onepiece_hpc_exc = 0;
    onepiece_hpc_lsu = 0;
    onepiece_hpc_fold = 0;
    onepiece_hpc_target_cycles = 0;
    onepiece_hpc_cycles_min = 0xffffffffu;
    onepiece_hpc_cycles_max = 0;
    onepiece_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void onepiece_run_decoder_experiment(void)
{
    uint32_t start;
    onepiece_insert_fn target_fn;
    unsigned int target_word;
    unsigned int target_bit;
    unsigned int target_linear;
    unsigned int bit;
    uint16_t before;
    uint16_t expected_word;
    uint16_t used_word;

    onepiece_entries++;

    if (onepiece_target_word >= ONEPIECE_NWORDS) {
        onepiece_target_word = 0u;
    }

    if (onepiece_target_bit >= ONEPIECE_WORD_BITS) {
        onepiece_target_bit = 0u;
    }

    target_word = onepiece_target_word;
    target_bit = onepiece_target_bit;
    target_linear = target_word * ONEPIECE_WORD_BITS + target_bit;

    onepiece_target_linear = target_linear;
    onepiece_prefix_count = target_linear;
    onepiece_suffix_count = ONEPIECE_TOTAL_INSERTIONS - target_linear - 1u;

    onepiece_decode_full_normal(onepiece_reference);
    onepiece_reference_digest =
        onepiece_fnv1a_u16(onepiece_reference, ONEPIECE_NWORDS);

    onepiece_copy_initial(onepiece_decoded);
    onepiece_decode_prefix(onepiece_decoded, target_linear);

    before = onepiece_decoded[target_word];
    bit = onepiece_get_source_bit(target_word, target_bit);

    onepiece_word_before_target = (unsigned int)before;
    onepiece_source_bit = bit;
    onepiece_stale_bit = (before >> target_bit) & 1u;

    expected_word = onepiece_insert_bit_normal(before, bit, target_bit);
    onepiece_expected_word = (unsigned int)expected_word;
    onepiece_expected_bit = (expected_word >> target_bit) & 1u;

    /*
     * Select normal or faulted target primitive outside the measured window.
     */
    if (onepiece_model == ONEPIECE_MODEL_SKIP) {
        target_fn = onepiece_insert_bit_skip;
        onepiece_faults_applied = 1u;
    } else {
        target_fn = onepiece_insert_bit_normal;
        onepiece_faults_applied = 0u;
    }

    /*
     * Clean target window: one target bit insertion primitive only.
     */
    trigger_high();
    onepiece_hpc_region_begin();
    start = onepiece_hpc_op_begin();

    used_word = target_fn(before, bit, target_bit);

    onepiece_hpc_target_cycles = onepiece_hpc_op_end_common(start);
    onepiece_hpc_region_end();
    trigger_low();

    onepiece_decoded[target_word] = used_word;
    onepiece_used_word = (unsigned int)used_word;
    onepiece_used_bit = (used_word >> target_bit) & 1u;

    onepiece_decode_suffix(onepiece_decoded, target_linear);

    onepiece_output_digest =
        onepiece_fnv1a_u16(onepiece_decoded, ONEPIECE_NWORDS);
    onepiece_output_diff = onepiece_output_digest ^ onepiece_reference_digest;
    onepiece_output_matches_ref =
        (onepiece_output_digest == onepiece_reference_digest) ? 1u : 0u;

    onepiece_semantic_valid = 1u;
    onepiece_exits++;
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
    unsigned int target_word;
    unsigned int target_bit;
    unsigned int previous_bit;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > ONEPIECE_MODEL_SKIP) {
        model = ONEPIECE_MODEL_NONE;
    }

    target_word = (unsigned int)buf[1] | (((unsigned int)buf[2]) << 8);
    if (target_word >= ONEPIECE_NWORDS) {
        target_word = 0u;
    }

    target_bit = (unsigned int)buf[3];
    if (target_bit >= ONEPIECE_WORD_BITS) {
        target_bit = 0u;
    }

    previous_bit = (unsigned int)buf[4] & 1u;

    tweak = (unsigned int)buf[5] |
            (((unsigned int)buf[6]) << 8) |
            (((unsigned int)buf[7]) << 16) |
            (((unsigned int)buf[8]) << 24);

    onepiece_model = model;
    onepiece_target_word = target_word;
    onepiece_target_bit = target_bit;
    onepiece_previous_bit = previous_bit;
    onepiece_message_tweak = tweak;

    onepiece_init_data();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)onepiece_model;
    out[2] = (uint8_t)onepiece_target_bit;
    out[3] = (uint8_t)onepiece_previous_bit;
    put_u32le(out, 4, onepiece_target_word);
    put_u32le(out, 8, onepiece_message_tweak);
    put_u32le(out, 12, ONEPIECE_NWORDS);
    put_u32le(out, 16, ONEPIECE_WORD_BITS);
    put_u32le(out, 20, onepiece_input_digest);

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

    onepiece_reset_observation_state();
    onepiece_init_data();

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

    onepiece_reset_observation_state();
    onepiece_init_data();

    onepiece_run_decoder_experiment();

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

    out[0] = (uint8_t)onepiece_model;
    out[1] = (uint8_t)onepiece_semantic_valid;
    out[2] = (uint8_t)onepiece_output_matches_ref;
    out[3] = (uint8_t)onepiece_target_bit;

    put_u32le(out, 4, onepiece_faults_applied);
    put_u32le(out, 8, onepiece_target_word);
    put_u32le(out, 12, onepiece_target_linear);
    put_u32le(out, 16, onepiece_expected_word);
    put_u32le(out, 20, onepiece_used_word);

    out[24] = (uint8_t)onepiece_expected_bit;
    out[25] = (uint8_t)onepiece_used_bit;
    out[26] = (uint8_t)onepiece_stale_bit;
    out[27] = (uint8_t)onepiece_source_bit;
    out[28] = (uint8_t)onepiece_defense_error;
    out[29] = (uint8_t)onepiece_hpc_anomaly;
    out[30] = (uint8_t)onepiece_entries;
    out[31] = (uint8_t)onepiece_exits;

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

    put_u32le(out, 0, onepiece_output_digest);
    put_u32le(out, 4, onepiece_reference_digest);
    put_u32le(out, 8, onepiece_output_diff);
    put_u32le(out, 12, onepiece_message_tweak);

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

    put_u32le(out, 0, onepiece_prefix_count);
    put_u32le(out, 4, onepiece_suffix_count);
    put_u32le(out, 8, ONEPIECE_TOTAL_INSERTIONS);
    put_u32le(out, 12, onepiece_word_before_target);

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
        ((onepiece_hpc_cpi & 0xffu) << 0) |
        ((onepiece_hpc_exc & 0xffu) << 8) |
        ((onepiece_hpc_lsu & 0xffu) << 16) |
        ((onepiece_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, onepiece_hpc_available);
    put_u32le(out, 4, onepiece_hpc_anomaly);
    put_u32le(out, 8, onepiece_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, onepiece_hpc_target_cycles);
    put_u32le(out, 20, onepiece_hpc_cycles_min);
    put_u32le(out, 24, onepiece_hpc_cycles_max);
    put_u32le(out, 28, onepiece_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    onepiece_reset_observation_state();
    onepiece_init_data();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('R', 0, cmd_detail_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef ONEPIECE_BOOT_BANNER
#define ONEPIECE_BOOT_BANNER 1
#endif

#if ONEPIECE_BOOT_BANNER
    uart_puts("WANG_ONEPIECE_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
