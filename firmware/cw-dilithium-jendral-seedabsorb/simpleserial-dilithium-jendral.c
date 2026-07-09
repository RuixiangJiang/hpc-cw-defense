#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Jendral, "A Single Trace Fault Injection Attack on Hedged CRYSTALS-Dilithium"
 *
 * Semantic model:
 *
 *   The signing-seed generation absorbs several intended input parts into a
 *   Keccak-like sponge.  The attack skips one security-critical Keccak absorb
 *   call.  The target input part is therefore not absorbed into the state, but
 *   the remaining steps, including subsequent absorb/finalize/permutation and
 *   squeeze steps, still execute normally.
 *
 * This firmware is an SRAM-safe semantic kernel.  It is not a full Dilithium
 * signing implementation and does not claim to implement the real Keccak-f1600
 * permutation.  The purpose is to isolate the skipped-absorb semantics and its
 * DWT/HPC timing signature under a clean target-window design.
 *
 * Clean target window:
 *
 *   normal prefix seed-generation steps
 *   select target primitive outside trigger/DWT window
 *   trigger_high()
 *   DWT/HPC begin
 *   either normal target absorb primitive OR skipped target absorb primitive
 *   DWT/HPC end
 *   trigger_low()
 *   normal following absorb/finalize/permutation/squeeze steps
 *
 * There is no "if attack then skip" branch inside the measured primitive.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef JENDRAL_HPC_TARGET_CYCLES_MIN
#define JENDRAL_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef JENDRAL_HPC_TARGET_CYCLES_MAX
#define JENDRAL_HPC_TARGET_CYCLES_MAX 0
#endif

#define JENDRAL_MODEL_NONE          0u
#define JENDRAL_MODEL_SKIP_ABSORB   1u

#define JENDRAL_ERR_HW_COUNTER 0x40u
#define JENDRAL_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define JENDRAL_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define JENDRAL_STATE_WORDS 50u
#define JENDRAL_PREFIX_BYTES 32u
#define JENDRAL_TARGET_BYTES 32u
#define JENDRAL_SUFFIX_BYTES 32u
#define JENDRAL_SEED_BYTES 32u

static uint32_t jendral_state[JENDRAL_STATE_WORDS];
static uint8_t jendral_prefix[JENDRAL_PREFIX_BYTES];
static uint8_t jendral_target[JENDRAL_TARGET_BYTES];
static uint8_t jendral_suffix[JENDRAL_SUFFIX_BYTES];
static uint8_t jendral_seed[JENDRAL_SEED_BYTES];

volatile unsigned int jendral_model = JENDRAL_MODEL_NONE;
volatile unsigned int jendral_message_tweak = 0;

volatile unsigned int jendral_faults_applied = 0;
volatile unsigned int jendral_entries = 0;
volatile unsigned int jendral_exits = 0;
volatile unsigned int jendral_semantic_valid = 0;
volatile unsigned int jendral_seed_matches_clean = 0;
volatile unsigned int jendral_seed_matches_omit = 0;
volatile unsigned int jendral_defense_error = 0;

volatile unsigned int jendral_expected_absorbed_target_bytes = JENDRAL_TARGET_BYTES;
volatile unsigned int jendral_used_absorbed_target_bytes = JENDRAL_TARGET_BYTES;

volatile unsigned int jendral_prefix_digest = 0;
volatile unsigned int jendral_target_digest = 0;
volatile unsigned int jendral_suffix_digest = 0;

volatile unsigned int jendral_output_seed_digest = 0;
volatile unsigned int jendral_clean_seed_digest = 0;
volatile unsigned int jendral_omit_seed_digest = 0;
volatile unsigned int jendral_output_diff_clean = 0;

volatile unsigned int jendral_hpc_available = 0;
volatile unsigned int jendral_hpc_anomaly = 0;
volatile unsigned int jendral_hpc_region_cycles = 0;
volatile unsigned int jendral_hpc_cpi = 0;
volatile unsigned int jendral_hpc_exc = 0;
volatile unsigned int jendral_hpc_lsu = 0;
volatile unsigned int jendral_hpc_fold = 0;
volatile unsigned int jendral_hpc_target_cycles = 0;
volatile unsigned int jendral_hpc_cycles_min = 0xffffffffu;
volatile unsigned int jendral_hpc_cycles_max = 0;
volatile unsigned int jendral_hpc_cycles_sum = 0;

typedef void (*jendral_target_absorb_fn)(uint32_t *state,
                                         const uint8_t *in,
                                         unsigned int inlen);

#if HPC_HW_ENABLE

#define JENDRAL_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define JENDRAL_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define JENDRAL_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define JENDRAL_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define JENDRAL_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define JENDRAL_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define JENDRAL_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define JENDRAL_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define JENDRAL_HPC_DEMCR_TRCENA          (1u << 24)
#define JENDRAL_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define JENDRAL_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t jendral_hpc_region_start = 0;

static inline void jendral_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    JENDRAL_HPC_DEMCR |= JENDRAL_HPC_DEMCR_TRCENA;
    ctrl = JENDRAL_HPC_DWT_CTRL;

    if ((ctrl & JENDRAL_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        JENDRAL_HPC_DWT_CTRL |= JENDRAL_HPC_DWT_CTRL_CYCCNTENA;
        jendral_hpc_available |= 0x01u;
    }

    JENDRAL_HPC_DWT_CPICNT = 0;
    JENDRAL_HPC_DWT_EXCCNT = 0;
    JENDRAL_HPC_DWT_SLEEPCNT = 0;
    JENDRAL_HPC_DWT_LSUCNT = 0;
    JENDRAL_HPC_DWT_FOLDCNT = 0;
    jendral_hpc_available |= 0x02u;
}

static inline void jendral_hpc_region_begin(void)
{
    jendral_hpc_dwt_enable();

    jendral_hpc_anomaly = 0;
    jendral_hpc_region_cycles = 0;
    jendral_hpc_cpi = 0;
    jendral_hpc_exc = 0;
    jendral_hpc_lsu = 0;
    jendral_hpc_fold = 0;
    jendral_hpc_target_cycles = 0;
    jendral_hpc_cycles_min = 0xffffffffu;
    jendral_hpc_cycles_max = 0;
    jendral_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    jendral_hpc_region_start = JENDRAL_HPC_DWT_CYCCNT;
}

static inline uint32_t jendral_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return JENDRAL_HPC_DWT_CYCCNT;
}

static inline uint32_t jendral_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((jendral_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = JENDRAL_HPC_DWT_CYCCNT - start;

    jendral_hpc_cycles_sum += delta;

    if (delta < jendral_hpc_cycles_min) {
        jendral_hpc_cycles_min = delta;
    }

    if (delta > jendral_hpc_cycles_max) {
        jendral_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void jendral_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = JENDRAL_HPC_DWT_CYCCNT;
    jendral_hpc_region_cycles = end - jendral_hpc_region_start;

    jendral_hpc_cpi = JENDRAL_HPC_DWT_CPICNT & 0xffu;
    jendral_hpc_exc = JENDRAL_HPC_DWT_EXCCNT & 0xffu;
    jendral_hpc_lsu = JENDRAL_HPC_DWT_LSUCNT & 0xffu;
    jendral_hpc_fold = JENDRAL_HPC_DWT_FOLDCNT & 0xffu;

#if JENDRAL_HPC_TARGET_CYCLES_MIN > 0
    if (jendral_hpc_target_cycles < (unsigned int)JENDRAL_HPC_TARGET_CYCLES_MIN) {
        jendral_hpc_anomaly |= JENDRAL_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if JENDRAL_HPC_TARGET_CYCLES_MAX > 0
    if (jendral_hpc_target_cycles > (unsigned int)JENDRAL_HPC_TARGET_CYCLES_MAX) {
        jendral_hpc_anomaly |= JENDRAL_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (jendral_hpc_anomaly != 0u) {
        jendral_defense_error |= JENDRAL_ERR_HW_COUNTER;
    }
}

#else

static inline void jendral_hpc_region_begin(void)
{
    jendral_hpc_anomaly = 0;
    jendral_hpc_region_cycles = 0;
    jendral_hpc_target_cycles = 0;
    jendral_hpc_cycles_min = 0xffffffffu;
    jendral_hpc_cycles_max = 0;
    jendral_hpc_cycles_sum = 0;
}

static inline uint32_t jendral_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t jendral_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void jendral_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static uint32_t jendral_rotl32(uint32_t x, unsigned int r)
{
    return (x << r) | (x >> (32u - r));
}

static uint32_t jendral_fnv1a(const uint8_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }

    return h;
}

static uint32_t jendral_digest_words(const uint32_t *buf, unsigned int len)
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

/*
 * Keccak-like permutation stand-in.
 * This is deliberately small and deterministic; it is used to ensure that
 * skipped absorb input affects the final seed digest.
 */
__attribute__((noinline))
static void jendral_keccak_permute_standin(uint32_t *state)
{
    unsigned int round;
    unsigned int i;

    for (round = 0; round < 12u; round++) {
        uint32_t carry = state[(round * 7u) % JENDRAL_STATE_WORDS] ^
                         (0x9e3779b9u + round * 0x1000193u);

        for (i = 0; i < JENDRAL_STATE_WORDS; i++) {
            uint32_t a = state[i];
            uint32_t b = state[(i + 1u) % JENDRAL_STATE_WORDS];
            uint32_t c = state[(i + 13u) % JENDRAL_STATE_WORDS];

            a ^= jendral_rotl32(b + carry + (uint32_t)i, (i % 23u) + 1u);
            a += jendral_rotl32(c ^ (0x7f4a7c15u + round), (i % 11u) + 3u);
            state[i] = a;
            carry ^= jendral_rotl32(a, (round % 7u) + 1u);
        }
    }
}

/*
 * Keccak absorb-call stand-in.
 *
 * This is the security-critical call targeted by the simulated fault.  In the
 * baseline it is called normally.  In the attack it is omitted by selecting a
 * separate skipped-absorb primitive outside the target window.
 */
__attribute__((noinline))
static void jendral_keccak_absorb_call(uint32_t *state,
                                       const uint8_t *in,
                                       unsigned int inlen)
{
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        unsigned int word = (i >> 2) % JENDRAL_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;
        uint32_t x = ((uint32_t)in[i]) << shift;

        state[word] ^= x;
        state[(word + 17u) % JENDRAL_STATE_WORDS] +=
            jendral_rotl32(x ^ (0x01000193u + i), (i % 19u) + 1u);
        state[(word + 31u) % JENDRAL_STATE_WORDS] ^=
            jendral_rotl32(state[word] + 0x6a09e667u, (i % 13u) + 3u);
    }
}

__attribute__((noinline))
static void jendral_target_absorb_normal(uint32_t *state,
                                         const uint8_t *in,
                                         unsigned int inlen)
{
    jendral_keccak_absorb_call(state, in, inlen);
}

__attribute__((noinline))
static void jendral_target_absorb_skipped(uint32_t *state,
                                          const uint8_t *in,
                                          unsigned int inlen)
{
    /*
     * Function-level perturbation: the intended absorb call is omitted.
     * Keep this primitive empty.  Do not add bookkeeping here; bookkeeping is
     * done before the trigger window.
     */
    (void)state;
    (void)in;
    (void)inlen;

    __asm volatile("" ::: "memory");
}

static void jendral_sponge_init(uint32_t *state)
{
    unsigned int i;

    for (i = 0; i < JENDRAL_STATE_WORDS; i++) {
        state[i] = 0u;
    }
}

static void jendral_sponge_finalize_and_squeeze(uint32_t *state,
                                                uint8_t *seed,
                                                unsigned int seedlen)
{
    unsigned int i;

    state[0] ^= 0x1fu;
    state[JENDRAL_STATE_WORDS - 1u] ^= 0x80000000u;

    jendral_keccak_permute_standin(state);

    for (i = 0; i < seedlen; i++) {
        unsigned int word = (i >> 2) % JENDRAL_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;

        if ((i != 0u) && ((i & 31u) == 0u)) {
            jendral_keccak_permute_standin(state);
        }

        seed[i] = (uint8_t)((state[word] >> shift) & 0xffu);
        state[(word + 9u) % JENDRAL_STATE_WORDS] ^=
            jendral_rotl32((uint32_t)seed[i] + i, (i % 17u) + 1u);
    }
}

static void jendral_init_inputs(void)
{
    unsigned int i;
    uint32_t tweak = jendral_message_tweak;

    for (i = 0; i < JENDRAL_PREFIX_BYTES; i++) {
        jendral_prefix[i] = (uint8_t)(0x30u ^ (i * 5u) ^ (tweak & 0xffu));
    }

    for (i = 0; i < JENDRAL_TARGET_BYTES; i++) {
        /*
         * This is the security-critical intended input whose absorb call is
         * skipped by the attack.
         */
        jendral_target[i] = (uint8_t)(0xa5u ^ (i * 7u) ^ ((tweak >> 8) & 0xffu));
    }

    for (i = 0; i < JENDRAL_SUFFIX_BYTES; i++) {
        jendral_suffix[i] = (uint8_t)(0x5au ^ (i * 11u) ^ ((tweak >> 16) & 0xffu));
    }

    jendral_prefix_digest = jendral_fnv1a(jendral_prefix, JENDRAL_PREFIX_BYTES);
    jendral_target_digest = jendral_fnv1a(jendral_target, JENDRAL_TARGET_BYTES);
    jendral_suffix_digest = jendral_fnv1a(jendral_suffix, JENDRAL_SUFFIX_BYTES);
}

static unsigned int jendral_seed_digest_from_mode(unsigned int omit_target)
{
    uint32_t st[JENDRAL_STATE_WORDS];
    uint8_t seed[JENDRAL_SEED_BYTES];

    jendral_sponge_init(st);

    jendral_keccak_absorb_call(st, jendral_prefix, JENDRAL_PREFIX_BYTES);

    if (!omit_target) {
        jendral_keccak_absorb_call(st, jendral_target, JENDRAL_TARGET_BYTES);
    }

    jendral_keccak_absorb_call(st, jendral_suffix, JENDRAL_SUFFIX_BYTES);
    jendral_sponge_finalize_and_squeeze(st, seed, JENDRAL_SEED_BYTES);

    return jendral_fnv1a(seed, JENDRAL_SEED_BYTES) ^ jendral_digest_words(st, JENDRAL_STATE_WORDS);
}

static void jendral_reset_observation_state(void)
{
    jendral_faults_applied = 0;
    jendral_entries = 0;
    jendral_exits = 0;
    jendral_semantic_valid = 0;
    jendral_seed_matches_clean = 0;
    jendral_seed_matches_omit = 0;
    jendral_defense_error = 0;

    jendral_expected_absorbed_target_bytes = JENDRAL_TARGET_BYTES;
    jendral_used_absorbed_target_bytes = JENDRAL_TARGET_BYTES;

    jendral_output_seed_digest = 0;
    jendral_clean_seed_digest = 0;
    jendral_omit_seed_digest = 0;
    jendral_output_diff_clean = 0;

    memset(jendral_state, 0, sizeof(jendral_state));
    memset(jendral_seed, 0, sizeof(jendral_seed));

    jendral_hpc_anomaly = 0;
    jendral_hpc_region_cycles = 0;
    jendral_hpc_cpi = 0;
    jendral_hpc_exc = 0;
    jendral_hpc_lsu = 0;
    jendral_hpc_fold = 0;
    jendral_hpc_target_cycles = 0;
    jendral_hpc_cycles_min = 0xffffffffu;
    jendral_hpc_cycles_max = 0;
    jendral_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void jendral_run_seed_generation(void)
{
    uint32_t start;
    jendral_target_absorb_fn target_fn;

    jendral_entries++;

    jendral_clean_seed_digest = jendral_seed_digest_from_mode(0u);
    jendral_omit_seed_digest = jendral_seed_digest_from_mode(1u);

    jendral_sponge_init(jendral_state);

    /*
     * Normal prefix seed-generation step.
     */
    jendral_keccak_absorb_call(jendral_state, jendral_prefix, JENDRAL_PREFIX_BYTES);

    /*
     * Select target primitive outside the trigger/DWT window.
     */
    if (jendral_model == JENDRAL_MODEL_SKIP_ABSORB) {
        target_fn = jendral_target_absorb_skipped;
        jendral_faults_applied = 1u;
        jendral_used_absorbed_target_bytes = 0u;
    } else {
        target_fn = jendral_target_absorb_normal;
        jendral_faults_applied = 0u;
        jendral_used_absorbed_target_bytes = JENDRAL_TARGET_BYTES;
    }

    /*
     * Clean target window: only the target absorb call or its omission.
     */
    trigger_high();
    jendral_hpc_region_begin();
    start = jendral_hpc_op_begin();

    target_fn(jendral_state, jendral_target, JENDRAL_TARGET_BYTES);

    jendral_hpc_target_cycles = jendral_hpc_op_end_common(start);
    jendral_hpc_region_end();
    trigger_low();

    /*
     * Remaining seed-generation steps still execute normally after the fault.
     */
    jendral_keccak_absorb_call(jendral_state, jendral_suffix, JENDRAL_SUFFIX_BYTES);
    jendral_sponge_finalize_and_squeeze(jendral_state, jendral_seed, JENDRAL_SEED_BYTES);

    jendral_output_seed_digest =
        jendral_fnv1a(jendral_seed, JENDRAL_SEED_BYTES) ^
        jendral_digest_words(jendral_state, JENDRAL_STATE_WORDS);

    jendral_output_diff_clean = jendral_output_seed_digest ^ jendral_clean_seed_digest;

    jendral_seed_matches_clean =
        (jendral_output_seed_digest == jendral_clean_seed_digest) ? 1u : 0u;
    jendral_seed_matches_omit =
        (jendral_output_seed_digest == jendral_omit_seed_digest) ? 1u : 0u;

    jendral_semantic_valid = 1u;
    jendral_exits++;
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

    uint8_t out[16];
    unsigned int model;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > JENDRAL_MODEL_SKIP_ABSORB) {
        model = JENDRAL_MODEL_NONE;
    }

    tweak = (unsigned int)buf[1] |
            (((unsigned int)buf[2]) << 8) |
            (((unsigned int)buf[3]) << 16) |
            (((unsigned int)buf[4]) << 24);

    jendral_model = model;
    jendral_message_tweak = tweak;

    jendral_init_inputs();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)jendral_model;
    put_u32le(out, 4, jendral_message_tweak);
    put_u32le(out, 8, JENDRAL_TARGET_BYTES);
    put_u32le(out, 12, jendral_target_digest);

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

    jendral_reset_observation_state();
    jendral_init_inputs();

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

    jendral_reset_observation_state();
    jendral_init_inputs();

    jendral_run_seed_generation();

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

    out[0] = (uint8_t)jendral_model;
    out[1] = (uint8_t)jendral_semantic_valid;
    out[2] = (uint8_t)jendral_seed_matches_clean;
    out[3] = (uint8_t)jendral_seed_matches_omit;

    put_u32le(out, 4, jendral_faults_applied);
    put_u32le(out, 8, jendral_expected_absorbed_target_bytes);
    put_u32le(out, 12, jendral_used_absorbed_target_bytes);
    put_u32le(out, 16, jendral_target_digest);
    put_u32le(out, 20, jendral_prefix_digest);
    put_u32le(out, 24, jendral_suffix_digest);

    out[28] = (uint8_t)jendral_defense_error;
    out[29] = (uint8_t)jendral_hpc_anomaly;
    out[30] = (uint8_t)jendral_entries;
    out[31] = (uint8_t)jendral_exits;

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

    put_u32le(out, 0, jendral_output_seed_digest);
    put_u32le(out, 4, jendral_clean_seed_digest);
    put_u32le(out, 8, jendral_omit_seed_digest);
    put_u32le(out, 12, jendral_output_diff_clean);

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
        ((jendral_hpc_cpi & 0xffu) << 0) |
        ((jendral_hpc_exc & 0xffu) << 8) |
        ((jendral_hpc_lsu & 0xffu) << 16) |
        ((jendral_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, jendral_hpc_available);
    put_u32le(out, 4, jendral_hpc_anomaly);
    put_u32le(out, 8, jendral_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, jendral_hpc_target_cycles);
    put_u32le(out, 20, jendral_hpc_cycles_min);
    put_u32le(out, 24, jendral_hpc_cycles_max);
    put_u32le(out, 28, jendral_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    jendral_reset_observation_state();
    jendral_init_inputs();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef JENDRAL_BOOT_BANNER
#define JENDRAL_BOOT_BANNER 1
#endif

#if JENDRAL_BOOT_BANNER
    uart_puts("JENDRAL_SKIP_ABSORB_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
