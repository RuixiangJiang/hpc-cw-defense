#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Valsaraj et al., "When Randomness Isn't Random"
 *
 * Semantic model:
 *
 *   The attack changes the seed input consumed by the sampler.
 *
 *   - pointer-offset skip:
 *       the seed pointer derivation returns the base seed pointer instead of
 *       applying the intended domain offset.
 *
 *   - wrong-domain fault:
 *       the seed pointer is derived using a wrong domain index.
 *
 *   - pointer redirection:
 *       the seed pointer is redirected to a known/constant/attacker-controlled
 *       buffer before SHAKE input formation.
 *
 *   The SHAKE input formation and sampling routine then run normally on the
 *   selected seed pointer.
 *
 * This is a data-source / pointer-selection fault.  It is not a sampler skip.
 *
 * Clean target-window design:
 *
 *   normal seed pool initialization
 *   select the seed pointer outside the trigger/DWT window
 *   trigger_high()
 *   DWT/HPC begin
 *   normal SHAKE-input formation and sampling on selected seed pointer
 *   DWT/HPC end
 *   trigger_low()
 *
 * The measured window contains the same normal sampler primitive in baseline
 * and attack.  It does not contain fault-model dispatch and it does not contain
 * "if attack then use wrong seed" logic.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef VALSARAJ_HPC_TARGET_CYCLES_MIN
#define VALSARAJ_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef VALSARAJ_HPC_TARGET_CYCLES_MAX
#define VALSARAJ_HPC_TARGET_CYCLES_MAX 0
#endif

#define VALSARAJ_MODEL_NONE        0u
#define VALSARAJ_MODEL_OFFSET_SKIP 1u
#define VALSARAJ_MODEL_WRONG_DOMAIN 2u
#define VALSARAJ_MODEL_REDIRECT    3u

#define VALSARAJ_ERR_HW_COUNTER 0x40u
#define VALSARAJ_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define VALSARAJ_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#define VALSARAJ_NUM_DOMAINS 4u
#define VALSARAJ_SEED_BYTES 32u
#define VALSARAJ_OUTPUT_COEFFS 256u
#define VALSARAJ_STATE_WORDS 50u
#define VALSARAJ_REDIRECT_DOMAIN_ID 255u

static uint8_t valsaraj_seed_pool[VALSARAJ_NUM_DOMAINS][VALSARAJ_SEED_BYTES];
static uint8_t valsaraj_redirect_seed[VALSARAJ_SEED_BYTES];
static uint16_t valsaraj_sample_out[VALSARAJ_OUTPUT_COEFFS];

volatile unsigned int valsaraj_model = VALSARAJ_MODEL_NONE;
volatile unsigned int valsaraj_intended_domain = 2;
volatile unsigned int valsaraj_wrong_domain = 1;
volatile unsigned int valsaraj_message_tweak = 0;

volatile unsigned int valsaraj_faults_applied = 0;
volatile unsigned int valsaraj_entries = 0;
volatile unsigned int valsaraj_exits = 0;
volatile unsigned int valsaraj_semantic_valid = 0;
volatile unsigned int valsaraj_output_matches_clean = 0;
volatile unsigned int valsaraj_output_matches_offset = 0;
volatile unsigned int valsaraj_output_matches_wrong = 0;
volatile unsigned int valsaraj_output_matches_redirect = 0;
volatile unsigned int valsaraj_defense_error = 0;

volatile unsigned int valsaraj_expected_domain = 2;
volatile unsigned int valsaraj_used_domain = 2;
volatile unsigned int valsaraj_expected_seed_digest = 0;
volatile unsigned int valsaraj_used_seed_digest = 0;
volatile unsigned int valsaraj_base_seed_digest = 0;
volatile unsigned int valsaraj_wrong_seed_digest = 0;
volatile unsigned int valsaraj_redirect_seed_digest = 0;

volatile unsigned int valsaraj_output_digest = 0;
volatile unsigned int valsaraj_clean_digest = 0;
volatile unsigned int valsaraj_offset_digest = 0;
volatile unsigned int valsaraj_wrong_digest = 0;
volatile unsigned int valsaraj_redirect_digest = 0;

volatile unsigned int valsaraj_hpc_available = 0;
volatile unsigned int valsaraj_hpc_anomaly = 0;
volatile unsigned int valsaraj_hpc_region_cycles = 0;
volatile unsigned int valsaraj_hpc_cpi = 0;
volatile unsigned int valsaraj_hpc_exc = 0;
volatile unsigned int valsaraj_hpc_lsu = 0;
volatile unsigned int valsaraj_hpc_fold = 0;
volatile unsigned int valsaraj_hpc_target_cycles = 0;
volatile unsigned int valsaraj_hpc_cycles_min = 0xffffffffu;
volatile unsigned int valsaraj_hpc_cycles_max = 0;
volatile unsigned int valsaraj_hpc_cycles_sum = 0;

#if HPC_HW_ENABLE

#define VALSARAJ_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define VALSARAJ_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define VALSARAJ_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define VALSARAJ_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define VALSARAJ_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define VALSARAJ_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define VALSARAJ_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define VALSARAJ_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define VALSARAJ_HPC_DEMCR_TRCENA          (1u << 24)
#define VALSARAJ_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define VALSARAJ_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t valsaraj_hpc_region_start = 0;

static inline void valsaraj_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    VALSARAJ_HPC_DEMCR |= VALSARAJ_HPC_DEMCR_TRCENA;
    ctrl = VALSARAJ_HPC_DWT_CTRL;

    if ((ctrl & VALSARAJ_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        VALSARAJ_HPC_DWT_CTRL |= VALSARAJ_HPC_DWT_CTRL_CYCCNTENA;
        valsaraj_hpc_available |= 0x01u;
    }

    VALSARAJ_HPC_DWT_CPICNT = 0;
    VALSARAJ_HPC_DWT_EXCCNT = 0;
    VALSARAJ_HPC_DWT_SLEEPCNT = 0;
    VALSARAJ_HPC_DWT_LSUCNT = 0;
    VALSARAJ_HPC_DWT_FOLDCNT = 0;
    valsaraj_hpc_available |= 0x02u;
}

static inline void valsaraj_hpc_region_begin(void)
{
    valsaraj_hpc_dwt_enable();

    valsaraj_hpc_anomaly = 0;
    valsaraj_hpc_region_cycles = 0;
    valsaraj_hpc_cpi = 0;
    valsaraj_hpc_exc = 0;
    valsaraj_hpc_lsu = 0;
    valsaraj_hpc_fold = 0;
    valsaraj_hpc_target_cycles = 0;
    valsaraj_hpc_cycles_min = 0xffffffffu;
    valsaraj_hpc_cycles_max = 0;
    valsaraj_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    valsaraj_hpc_region_start = VALSARAJ_HPC_DWT_CYCCNT;
}

static inline uint32_t valsaraj_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return VALSARAJ_HPC_DWT_CYCCNT;
}

static inline uint32_t valsaraj_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((valsaraj_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = VALSARAJ_HPC_DWT_CYCCNT - start;

    valsaraj_hpc_cycles_sum += delta;

    if (delta < valsaraj_hpc_cycles_min) {
        valsaraj_hpc_cycles_min = delta;
    }

    if (delta > valsaraj_hpc_cycles_max) {
        valsaraj_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void valsaraj_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = VALSARAJ_HPC_DWT_CYCCNT;
    valsaraj_hpc_region_cycles = end - valsaraj_hpc_region_start;

    valsaraj_hpc_cpi = VALSARAJ_HPC_DWT_CPICNT & 0xffu;
    valsaraj_hpc_exc = VALSARAJ_HPC_DWT_EXCCNT & 0xffu;
    valsaraj_hpc_lsu = VALSARAJ_HPC_DWT_LSUCNT & 0xffu;
    valsaraj_hpc_fold = VALSARAJ_HPC_DWT_FOLDCNT & 0xffu;

#if VALSARAJ_HPC_TARGET_CYCLES_MIN > 0
    if (valsaraj_hpc_target_cycles < (unsigned int)VALSARAJ_HPC_TARGET_CYCLES_MIN) {
        valsaraj_hpc_anomaly |= VALSARAJ_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if VALSARAJ_HPC_TARGET_CYCLES_MAX > 0
    if (valsaraj_hpc_target_cycles > (unsigned int)VALSARAJ_HPC_TARGET_CYCLES_MAX) {
        valsaraj_hpc_anomaly |= VALSARAJ_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (valsaraj_hpc_anomaly != 0u) {
        valsaraj_defense_error |= VALSARAJ_ERR_HW_COUNTER;
    }
}

#else

static inline void valsaraj_hpc_region_begin(void)
{
    valsaraj_hpc_anomaly = 0;
    valsaraj_hpc_region_cycles = 0;
    valsaraj_hpc_target_cycles = 0;
    valsaraj_hpc_cycles_min = 0xffffffffu;
    valsaraj_hpc_cycles_max = 0;
    valsaraj_hpc_cycles_sum = 0;
}

static inline uint32_t valsaraj_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t valsaraj_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void valsaraj_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static uint32_t valsaraj_rotl32(uint32_t x, unsigned int r)
{
    return (x << r) | (x >> (32u - r));
}

static uint32_t valsaraj_fnv1a_bytes(const uint8_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }

    return h;
}

static uint32_t valsaraj_fnv1a_coeffs(const uint16_t *buf, unsigned int len)
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

static void valsaraj_init_seed_pool(void)
{
    unsigned int d;
    unsigned int i;
    uint32_t tweak = valsaraj_message_tweak;

    for (d = 0; d < VALSARAJ_NUM_DOMAINS; d++) {
        for (i = 0; i < VALSARAJ_SEED_BYTES; i++) {
            valsaraj_seed_pool[d][i] =
                (uint8_t)(0x81u ^ (d * 0x31u) ^ (i * 0x07u) ^
                          ((tweak >> ((i & 3u) * 8u)) & 0xffu));
        }
    }

    for (i = 0; i < VALSARAJ_SEED_BYTES; i++) {
        /*
         * Known / attacker-controlled seed buffer.
         */
        valsaraj_redirect_seed[i] =
            (uint8_t)(0xc3u ^ (i * 0x11u) ^ ((tweak >> (((i + 1u) & 3u) * 8u)) & 0xffu));
    }

    valsaraj_base_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[0], VALSARAJ_SEED_BYTES);

    valsaraj_expected_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[valsaraj_intended_domain],
                             VALSARAJ_SEED_BYTES);

    valsaraj_wrong_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[valsaraj_wrong_domain],
                             VALSARAJ_SEED_BYTES);

    valsaraj_redirect_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_redirect_seed, VALSARAJ_SEED_BYTES);
}

/*
 * Seed pointer derivation primitives.
 *
 * These are not inside the sampler target window.  They model the attack's
 * seed-selection fault while preserving the semantic distinction between seed
 * selection and sampling.
 */
__attribute__((noinline))
static const uint8_t *valsaraj_seedptr_normal(unsigned int domain)
{
    if (domain >= VALSARAJ_NUM_DOMAINS) {
        domain = 0u;
    }

    return &valsaraj_seed_pool[domain][0];
}

__attribute__((noinline))
static const uint8_t *valsaraj_seedptr_offset_skip(unsigned int domain)
{
    (void)domain;

    /*
     * Pointer-offset skip: return base seed pointer without applying the
     * intended domain offset.
     */
    return &valsaraj_seed_pool[0][0];
}

__attribute__((noinline))
static const uint8_t *valsaraj_seedptr_wrong_domain(unsigned int wrong_domain)
{
    if (wrong_domain >= VALSARAJ_NUM_DOMAINS) {
        wrong_domain = 0u;
    }

    return &valsaraj_seed_pool[wrong_domain][0];
}

__attribute__((noinline))
static const uint8_t *valsaraj_seedptr_redirect(void)
{
    return &valsaraj_redirect_seed[0];
}

static void valsaraj_sponge_init(uint32_t *state)
{
    unsigned int i;

    for (i = 0; i < VALSARAJ_STATE_WORDS; i++) {
        state[i] = 0x6a09e667u ^ (i * 0x01000193u);
    }
}

static void valsaraj_sponge_absorb_seed(uint32_t *state,
                                        const uint8_t *seed,
                                        unsigned int sampler_domain)
{
    unsigned int i;

    /*
     * SHAKE input formation stand-in:
     *   seed || sampler_domain || fixed separators
     *
     * The sampler_domain remains the intended sampler context.  The fault
     * changes the seed pointer consumed by this routine.
     */
    for (i = 0; i < VALSARAJ_SEED_BYTES; i++) {
        unsigned int word = (i >> 2) % VALSARAJ_STATE_WORDS;
        unsigned int shift = (i & 3u) * 8u;
        uint32_t x = ((uint32_t)seed[i]) << shift;

        state[word] ^= x;
        state[(word + 17u) % VALSARAJ_STATE_WORDS] +=
            valsaraj_rotl32(x ^ (0x9e3779b9u + i), (i % 19u) + 1u);
    }

    state[3] ^= sampler_domain;
    state[7] ^= 0x1fu;
    state[VALSARAJ_STATE_WORDS - 1u] ^= 0x80000000u;
}

static void valsaraj_sponge_permute(uint32_t *state)
{
    unsigned int round;
    unsigned int i;

    for (round = 0; round < 12u; round++) {
        uint32_t theta = 0x7f4a7c15u ^ (round * 0x01000193u);

        for (i = 0; i < VALSARAJ_STATE_WORDS; i++) {
            theta ^= valsaraj_rotl32(state[i] + i + round, (i % 23u) + 1u);
        }

        for (i = 0; i < VALSARAJ_STATE_WORDS; i++) {
            uint32_t a = state[i];
            uint32_t b = state[(i + 1u) % VALSARAJ_STATE_WORDS];
            uint32_t c = state[(i + 13u) % VALSARAJ_STATE_WORDS];

            a ^= valsaraj_rotl32(theta + b + (round << 8), (i % 19u) + 1u);
            a += valsaraj_rotl32(c ^ (0x3c6ef372u + round + i), (i % 11u) + 3u);
            state[i] = a ^ (b & ~c);
        }
    }
}

/*
 * Normal SHAKE + sampling primitive.
 *
 * This is the measured target primitive.  It is the same function in baseline
 * and all attack modes.  Only the seed pointer input differs.
 */
__attribute__((noinline))
static void valsaraj_shake_and_sample_normal(const uint8_t *seed,
                                             unsigned int sampler_domain,
                                             uint16_t *out)
{
    unsigned int i;
    uint32_t state[VALSARAJ_STATE_WORDS];

    valsaraj_sponge_init(state);
    valsaraj_sponge_absorb_seed(state, seed, sampler_domain);
    valsaraj_sponge_permute(state);

    for (i = 0; i < VALSARAJ_OUTPUT_COEFFS; i++) {
        unsigned int w0 = (i * 7u) % VALSARAJ_STATE_WORDS;
        unsigned int w1 = (i * 13u + 5u) % VALSARAJ_STATE_WORDS;
        uint32_t x;

        if ((i != 0u) && ((i & 31u) == 0u)) {
            valsaraj_sponge_permute(state);
        }

        x = state[w0] ^ valsaraj_rotl32(state[w1] + i, (i % 17u) + 1u);
        out[i] = (uint16_t)(x & 0xffffu);

        state[(w0 + 3u) % VALSARAJ_STATE_WORDS] ^=
            valsaraj_rotl32(x + 0x1000193u + i, (i % 13u) + 1u);
    }
}

static uint32_t valsaraj_reference_digest_for_seed(const uint8_t *seed,
                                                   unsigned int sampler_domain)
{
    uint16_t tmp[VALSARAJ_OUTPUT_COEFFS];

    valsaraj_shake_and_sample_normal(seed, sampler_domain, tmp);
    return valsaraj_fnv1a_coeffs(tmp, VALSARAJ_OUTPUT_COEFFS);
}

static void valsaraj_reset_observation_state(void)
{
    valsaraj_faults_applied = 0;
    valsaraj_entries = 0;
    valsaraj_exits = 0;
    valsaraj_semantic_valid = 0;
    valsaraj_output_matches_clean = 0;
    valsaraj_output_matches_offset = 0;
    valsaraj_output_matches_wrong = 0;
    valsaraj_output_matches_redirect = 0;
    valsaraj_defense_error = 0;

    valsaraj_expected_domain = valsaraj_intended_domain;
    valsaraj_used_domain = valsaraj_intended_domain;

    valsaraj_used_seed_digest = 0;
    valsaraj_output_digest = 0;
    valsaraj_clean_digest = 0;
    valsaraj_offset_digest = 0;
    valsaraj_wrong_digest = 0;
    valsaraj_redirect_digest = 0;

    memset(valsaraj_sample_out, 0, sizeof(valsaraj_sample_out));

    valsaraj_hpc_anomaly = 0;
    valsaraj_hpc_region_cycles = 0;
    valsaraj_hpc_cpi = 0;
    valsaraj_hpc_exc = 0;
    valsaraj_hpc_lsu = 0;
    valsaraj_hpc_fold = 0;
    valsaraj_hpc_target_cycles = 0;
    valsaraj_hpc_cycles_min = 0xffffffffu;
    valsaraj_hpc_cycles_max = 0;
    valsaraj_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void valsaraj_run_wrong_seed_experiment(void)
{
    const uint8_t *selected_seed;
    uint32_t start;

    valsaraj_entries++;

    if (valsaraj_intended_domain >= VALSARAJ_NUM_DOMAINS) {
        valsaraj_intended_domain = 0u;
    }

    if (valsaraj_wrong_domain >= VALSARAJ_NUM_DOMAINS) {
        valsaraj_wrong_domain = 0u;
    }

    valsaraj_expected_domain = valsaraj_intended_domain;

    /*
     * Reference outputs for each semantic case.
     */
    valsaraj_clean_digest =
        valsaraj_reference_digest_for_seed(valsaraj_seed_pool[valsaraj_intended_domain],
                                           valsaraj_intended_domain);

    valsaraj_offset_digest =
        valsaraj_reference_digest_for_seed(valsaraj_seed_pool[0],
                                           valsaraj_intended_domain);

    valsaraj_wrong_digest =
        valsaraj_reference_digest_for_seed(valsaraj_seed_pool[valsaraj_wrong_domain],
                                           valsaraj_intended_domain);

    valsaraj_redirect_digest =
        valsaraj_reference_digest_for_seed(valsaraj_redirect_seed,
                                           valsaraj_intended_domain);

    /*
     * Seed selection happens before the target sampling window.
     */
    if (valsaraj_model == VALSARAJ_MODEL_OFFSET_SKIP) {
        selected_seed = valsaraj_seedptr_offset_skip(valsaraj_intended_domain);
        valsaraj_used_domain = 0u;
        valsaraj_faults_applied = 1u;
    } else if (valsaraj_model == VALSARAJ_MODEL_WRONG_DOMAIN) {
        selected_seed = valsaraj_seedptr_wrong_domain(valsaraj_wrong_domain);
        valsaraj_used_domain = valsaraj_wrong_domain;
        valsaraj_faults_applied = 1u;
    } else if (valsaraj_model == VALSARAJ_MODEL_REDIRECT) {
        selected_seed = valsaraj_seedptr_redirect();
        valsaraj_used_domain = VALSARAJ_REDIRECT_DOMAIN_ID;
        valsaraj_faults_applied = 1u;
    } else {
        selected_seed = valsaraj_seedptr_normal(valsaraj_intended_domain);
        valsaraj_used_domain = valsaraj_intended_domain;
        valsaraj_faults_applied = 0u;
    }

    valsaraj_expected_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[valsaraj_intended_domain],
                             VALSARAJ_SEED_BYTES);
    valsaraj_used_seed_digest =
        valsaraj_fnv1a_bytes(selected_seed, VALSARAJ_SEED_BYTES);
    valsaraj_base_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[0], VALSARAJ_SEED_BYTES);
    valsaraj_wrong_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_seed_pool[valsaraj_wrong_domain],
                             VALSARAJ_SEED_BYTES);
    valsaraj_redirect_seed_digest =
        valsaraj_fnv1a_bytes(valsaraj_redirect_seed, VALSARAJ_SEED_BYTES);

    /*
     * Clean target window: normal SHAKE input formation and sampling consumes
     * the selected seed pointer.  Same function in baseline and attack.
     */
    trigger_high();
    valsaraj_hpc_region_begin();
    start = valsaraj_hpc_op_begin();

    valsaraj_shake_and_sample_normal(selected_seed,
                                     valsaraj_intended_domain,
                                     valsaraj_sample_out);

    valsaraj_hpc_target_cycles = valsaraj_hpc_op_end_common(start);
    valsaraj_hpc_region_end();
    trigger_low();

    valsaraj_output_digest =
        valsaraj_fnv1a_coeffs(valsaraj_sample_out, VALSARAJ_OUTPUT_COEFFS);

    valsaraj_output_matches_clean =
        (valsaraj_output_digest == valsaraj_clean_digest) ? 1u : 0u;
    valsaraj_output_matches_offset =
        (valsaraj_output_digest == valsaraj_offset_digest) ? 1u : 0u;
    valsaraj_output_matches_wrong =
        (valsaraj_output_digest == valsaraj_wrong_digest) ? 1u : 0u;
    valsaraj_output_matches_redirect =
        (valsaraj_output_digest == valsaraj_redirect_digest) ? 1u : 0u;

    valsaraj_semantic_valid = 1u;
    valsaraj_exits++;
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
    unsigned int intended;
    unsigned int wrong;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > VALSARAJ_MODEL_REDIRECT) {
        model = VALSARAJ_MODEL_NONE;
    }

    intended = (unsigned int)buf[1];
    if (intended >= VALSARAJ_NUM_DOMAINS) {
        intended = 0u;
    }

    wrong = (unsigned int)buf[2];
    if (wrong >= VALSARAJ_NUM_DOMAINS) {
        wrong = 0u;
    }

    tweak = (unsigned int)buf[3] |
            (((unsigned int)buf[4]) << 8) |
            (((unsigned int)buf[5]) << 16) |
            (((unsigned int)buf[6]) << 24);

    valsaraj_model = model;
    valsaraj_intended_domain = intended;
    valsaraj_wrong_domain = wrong;
    valsaraj_message_tweak = tweak;

    valsaraj_init_seed_pool();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)valsaraj_model;
    out[2] = (uint8_t)valsaraj_intended_domain;
    out[3] = (uint8_t)valsaraj_wrong_domain;
    put_u32le(out, 4, valsaraj_message_tweak);
    put_u32le(out, 8, VALSARAJ_NUM_DOMAINS);
    put_u32le(out, 12, VALSARAJ_SEED_BYTES);
    put_u32le(out, 16, VALSARAJ_OUTPUT_COEFFS);
    put_u32le(out, 20, valsaraj_expected_seed_digest);

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

    valsaraj_reset_observation_state();
    valsaraj_init_seed_pool();

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

    valsaraj_reset_observation_state();
    valsaraj_init_seed_pool();

    valsaraj_run_wrong_seed_experiment();

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

    out[0] = (uint8_t)valsaraj_model;
    out[1] = (uint8_t)valsaraj_semantic_valid;
    out[2] = (uint8_t)valsaraj_output_matches_clean;
    out[3] = (uint8_t)valsaraj_output_matches_offset;
    out[4] = (uint8_t)valsaraj_output_matches_wrong;
    out[5] = (uint8_t)valsaraj_output_matches_redirect;
    out[6] = (uint8_t)valsaraj_expected_domain;
    out[7] = (uint8_t)valsaraj_used_domain;

    put_u32le(out, 8, valsaraj_faults_applied);
    put_u32le(out, 12, valsaraj_expected_seed_digest);
    put_u32le(out, 16, valsaraj_used_seed_digest);
    put_u32le(out, 20, valsaraj_base_seed_digest);
    put_u32le(out, 24, valsaraj_wrong_seed_digest);

    out[28] = (uint8_t)valsaraj_defense_error;
    out[29] = (uint8_t)valsaraj_hpc_anomaly;
    out[30] = (uint8_t)valsaraj_entries;
    out[31] = (uint8_t)valsaraj_exits;

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

    uint8_t out[20];

    put_u32le(out, 0, valsaraj_output_digest);
    put_u32le(out, 4, valsaraj_clean_digest);
    put_u32le(out, 8, valsaraj_offset_digest);
    put_u32le(out, 12, valsaraj_wrong_digest);
    put_u32le(out, 16, valsaraj_redirect_digest);

    simpleserial_put('D', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_redirect_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_redirect_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[16];

    put_u32le(out, 0, valsaraj_redirect_seed_digest);
    put_u32le(out, 4, valsaraj_message_tweak);
    put_u32le(out, 8, valsaraj_intended_domain);
    put_u32le(out, 12, valsaraj_wrong_domain);

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
        ((valsaraj_hpc_cpi & 0xffu) << 0) |
        ((valsaraj_hpc_exc & 0xffu) << 8) |
        ((valsaraj_hpc_lsu & 0xffu) << 16) |
        ((valsaraj_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, valsaraj_hpc_available);
    put_u32le(out, 4, valsaraj_hpc_anomaly);
    put_u32le(out, 8, valsaraj_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, valsaraj_hpc_target_cycles);
    put_u32le(out, 20, valsaraj_hpc_cycles_min);
    put_u32le(out, 24, valsaraj_hpc_cycles_max);
    put_u32le(out, 28, valsaraj_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    valsaraj_reset_observation_state();
    valsaraj_init_seed_pool();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('R', 0, cmd_redirect_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef VALSARAJ_BOOT_BANNER
#define VALSARAJ_BOOT_BANNER 1
#endif

#if VALSARAJ_BOOT_BANNER
    uart_puts("VALSARAJ_WRONG_SEED_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
