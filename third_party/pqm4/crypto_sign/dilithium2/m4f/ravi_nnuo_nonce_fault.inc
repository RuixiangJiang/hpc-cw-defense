#ifndef RAVI_NNUO_NONCE_FAULT_INC
#define RAVI_NNUO_NONCE_FAULT_INC

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*
 * Ravi et al., "Number Not Used Once"
 *
 * Correct semantic model for this kernel:
 *
 *   The target fault skips the nonce++ / domain-separation update itself.
 *   The sampler is not skipped and is not modified. It receives whatever
 *   nonce state remains after the update step.
 *
 * Measurement rule:
 *
 *   The measured target window is the nonce-update primitive, not the sampler.
 *   The attack path uses a separate noinline skip-update primitive, so there
 *   is no "if attack then skip nonce++" branch inside the measured window.
 *
 * Sequence:
 *
 *   nonce_state starts at 0xffff.
 *
 *   For each sampling call:
 *       measured update step:
 *           baseline: nonce_state++
 *           attack target: skip nonce_state++
 *       record used nonce
 *       run sampler normally with the current nonce_state
 *
 * For Dilithium2, the kernel executes L+K = 8 sampling calls. With
 * TARGET_CALL=4, skipping the update before call 4 makes call 4 reuse the
 * previous nonce 3 instead of the expected nonce 4. The suffix then continues
 * normal nonce++ operations from the stale state, which is what a real skipped
 * increment would do.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef NNUO_CHECK_NONCE_PROGRESS
#define NNUO_CHECK_NONCE_PROGRESS 1
#endif

#ifndef NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN
#define NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN 0
#endif

#ifndef NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX
#define NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX 0
#endif

#define NNUO_ERR_NONCE_PROGRESS 0x20u
#define NNUO_ERR_HW_COUNTER     0x40u

#define NNUO_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define NNUO_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

volatile unsigned int nnuo_fault_enable = 0;
volatile unsigned int nnuo_fault_target_call = L;
volatile unsigned int nnuo_fault_stale_nonce = 0; /* kept for protocol compatibility; not used in skip-update mode */
volatile unsigned int nnuo_fault_skips = 0;

volatile unsigned int nnuo_sampling_entries = 0;
volatile unsigned int nnuo_sampling_exits = 0;
volatile unsigned int nnuo_defense_error = 0;
volatile unsigned int nnuo_nonce_progress_errors = 0;

volatile unsigned int nnuo_used_nonce_target = 0;
volatile unsigned int nnuo_expected_nonce_target = 0;
volatile unsigned int nnuo_duplicate_call = 0xffu;

/*
 * DWT/HPC counters exposed through SimpleSerial Y.
 *
 * Historical variable names keep "sample" for compatibility with the existing
 * firmware response layout, but after this fix they measure nonce-update
 * primitives:
 *
 *   target_sample_cycles -> target update cycles
 *   sample_cycles_sum    -> sum of update cycles over L+K calls
 */
volatile unsigned int nnuo_hpc_available = 0;
volatile unsigned int nnuo_hpc_anomaly = 0;
volatile unsigned int nnuo_hpc_sampling_region_cycles = 0;
volatile unsigned int nnuo_hpc_cpi = 0;
volatile unsigned int nnuo_hpc_exc = 0;
volatile unsigned int nnuo_hpc_lsu = 0;
volatile unsigned int nnuo_hpc_fold = 0;
volatile unsigned int nnuo_hpc_sample_cycles_sum = 0;
volatile unsigned int nnuo_hpc_sample_cycles_min = 0xffffffffu;
volatile unsigned int nnuo_hpc_sample_cycles_max = 0;
volatile unsigned int nnuo_hpc_target_sample_cycles = 0;
volatile unsigned int nnuo_hpc_target_call = 0;

#define NNUO_TOTAL_CALLS ((unsigned int)(L + K))

static uint8_t nnuo_seed[32] = {
    0x4e, 0x4e, 0x55, 0x4f, 0x2d, 0x44, 0x69, 0x6c,
    0x69, 0x74, 0x68, 0x69, 0x75, 0x6d, 0x32, 0x2d,
    0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x2d,
    0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x21, 0x00
};

static uint8_t nnuo_used_nonces[NNUO_TOTAL_CALLS];

#if HPC_HW_ENABLE

#define NNUO_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define NNUO_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define NNUO_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define NNUO_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define NNUO_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define NNUO_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define NNUO_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define NNUO_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define NNUO_HPC_DEMCR_TRCENA          (1u << 24)
#define NNUO_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define NNUO_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t nnuo_hpc_region_start = 0;

static inline void nnuo_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    NNUO_HPC_DEMCR |= NNUO_HPC_DEMCR_TRCENA;
    ctrl = NNUO_HPC_DWT_CTRL;

    if ((ctrl & NNUO_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        NNUO_HPC_DWT_CTRL |= NNUO_HPC_DWT_CTRL_CYCCNTENA;
        nnuo_hpc_available |= 0x01u;
    }

    NNUO_HPC_DWT_CPICNT = 0;
    NNUO_HPC_DWT_EXCCNT = 0;
    NNUO_HPC_DWT_SLEEPCNT = 0;
    NNUO_HPC_DWT_LSUCNT = 0;
    NNUO_HPC_DWT_FOLDCNT = 0;
    nnuo_hpc_available |= 0x02u;
}

static inline void nnuo_hpc_region_begin(void)
{
    nnuo_hpc_dwt_enable();

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

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    nnuo_hpc_region_start = NNUO_HPC_DWT_CYCCNT;
}

static inline uint32_t nnuo_hpc_update_begin(void)
{
    __asm volatile("" ::: "memory");
    return NNUO_HPC_DWT_CYCCNT;
}

static inline uint32_t nnuo_hpc_update_end_common(uint32_t start)
{
    uint32_t delta;

    if ((nnuo_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = NNUO_HPC_DWT_CYCCNT - start;

    nnuo_hpc_sample_cycles_sum += delta;

    if (delta < nnuo_hpc_sample_cycles_min) {
        nnuo_hpc_sample_cycles_min = delta;
    }

    if (delta > nnuo_hpc_sample_cycles_max) {
        nnuo_hpc_sample_cycles_max = delta;
    }

    return delta;
}

static inline void nnuo_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = NNUO_HPC_DWT_CYCCNT;
    nnuo_hpc_sampling_region_cycles = end - nnuo_hpc_region_start;

    nnuo_hpc_cpi = NNUO_HPC_DWT_CPICNT & 0xffu;
    nnuo_hpc_exc = NNUO_HPC_DWT_EXCCNT & 0xffu;
    nnuo_hpc_lsu = NNUO_HPC_DWT_LSUCNT & 0xffu;
    nnuo_hpc_fold = NNUO_HPC_DWT_FOLDCNT & 0xffu;

#if NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN > 0
    if (nnuo_hpc_target_sample_cycles < (unsigned int)NNUO_HPC_TARGET_SAMPLE_CYCLES_MIN) {
        nnuo_hpc_anomaly |= NNUO_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX > 0
    if (nnuo_hpc_target_sample_cycles > (unsigned int)NNUO_HPC_TARGET_SAMPLE_CYCLES_MAX) {
        nnuo_hpc_anomaly |= NNUO_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (nnuo_hpc_anomaly != 0u) {
        nnuo_defense_error |= NNUO_ERR_HW_COUNTER;
    }
}

#else

static inline void nnuo_hpc_region_begin(void)
{
    nnuo_hpc_anomaly = 0;
    nnuo_hpc_sampling_region_cycles = 0;
    nnuo_hpc_sample_cycles_sum = 0;
    nnuo_hpc_sample_cycles_min = 0xffffffffu;
    nnuo_hpc_sample_cycles_max = 0;
    nnuo_hpc_target_sample_cycles = 0;
    nnuo_hpc_target_call = nnuo_fault_target_call;
}

static inline uint32_t nnuo_hpc_update_begin(void)
{
    return 0;
}

static inline uint32_t nnuo_hpc_update_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void nnuo_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static inline uint32_t nnuo_load_seed_word(unsigned int off)
{
    return ((uint32_t)nnuo_seed[(off + 0u) & 31u] << 0) |
           ((uint32_t)nnuo_seed[(off + 1u) & 31u] << 8) |
           ((uint32_t)nnuo_seed[(off + 2u) & 31u] << 16) |
           ((uint32_t)nnuo_seed[(off + 3u) & 31u] << 24);
}

/*
 * Deterministic SRAM-safe sampler stand-in.
 *
 * The sampler runs normally in both baseline and attack. It is intentionally
 * outside the target update measurement. The attack modifies the nonce state
 * that is passed into this sampler; it does not skip or modify the sampler.
 */
__attribute__((noinline))
static void nnuo_sampler_one(poly *out, uint16_t nonce)
{
    uint32_t x;
    unsigned int i;

    x = nnuo_load_seed_word((unsigned int)(nonce & 31u));
    x ^= ((uint32_t)nonce + 1u) * 0x9e3779b9u;
    x ^= 0x6d2b79f5u;

    for (i = 0; i < N; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x += 0x9e3779b9u + i;
        out->coeffs[i] = (int32_t)((int32_t)(x % 5u) - 2);
    }
}

/*
 * Normal measured nonce update:
 *
 *     nonce_state++
 */
__attribute__((noinline))
static uint32_t nnuo_nonce_update_normal_measured(uint16_t *nonce_state)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = nnuo_hpc_update_begin();

    *nonce_state = (uint16_t)(*nonce_state + 1u);

    __asm volatile("" ::: "memory");
    delta = nnuo_hpc_update_end_common(start);

    return delta;
}

/*
 * Faulted measured nonce update:
 *
 *     skip nonce_state++
 *
 * There is no branch or fault-kind switch in this measured window. The empty
 * asm with a memory clobber prevents the compiler from erasing the window
 * completely while keeping the semantic operation as "no update".
 */
__attribute__((noinline))
static uint32_t nnuo_nonce_update_skip_increment_measured(uint16_t *nonce_state)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = nnuo_hpc_update_begin();

    __asm volatile("" : "+m"(*nonce_state) : : "memory");

    delta = nnuo_hpc_update_end_common(start);

    nnuo_fault_skips++;

    return delta;
}

/*
 * Dispatch is outside the measured window.
 */
__attribute__((noinline))
static uint32_t nnuo_nonce_update_target_measured(uint16_t *nonce_state)
{
    if (nnuo_fault_enable != 0u) {
        return nnuo_nonce_update_skip_increment_measured(nonce_state);
    }

    return nnuo_nonce_update_normal_measured(nonce_state);
}

static inline poly *nnuo_output_poly(polyvecl *s1, polyveck *s2, unsigned int call)
{
    if (call < (unsigned int)L) {
        return &s1->vec[call];
    }

    return &s2->vec[call - (unsigned int)L];
}

static inline uint16_t nnuo_expected_nonce(unsigned int call)
{
    return (uint16_t)call;
}

static inline void nnuo_record_used_nonce(unsigned int call, uint16_t nonce)
{
    if (call < NNUO_TOTAL_CALLS) {
        nnuo_used_nonces[call] = (uint8_t)nonce;
    }
}

static void nnuo_check_nonce_progression(void)
{
#if NNUO_CHECK_NONCE_PROGRESS
    unsigned int call;

    nnuo_nonce_progress_errors = 0;
    nnuo_duplicate_call = 0xffu;

    for (call = 0; call < NNUO_TOTAL_CALLS; call++) {
        uint16_t expected = nnuo_expected_nonce(call);
        uint16_t used = (uint16_t)nnuo_used_nonces[call];

        if (used != expected) {
            nnuo_nonce_progress_errors++;
        }
    }

    nnuo_expected_nonce_target = (unsigned int)nnuo_expected_nonce(nnuo_fault_target_call);
    nnuo_used_nonce_target = (nnuo_fault_target_call < NNUO_TOTAL_CALLS) ?
                             (unsigned int)nnuo_used_nonces[nnuo_fault_target_call] :
                             0xffu;

    if (nnuo_fault_target_call < NNUO_TOTAL_CALLS) {
        for (call = 0; call < NNUO_TOTAL_CALLS; call++) {
            if (call == nnuo_fault_target_call) {
                continue;
            }

            if (nnuo_used_nonces[call] == nnuo_used_nonces[nnuo_fault_target_call]) {
                nnuo_duplicate_call = call;
                break;
            }
        }
    }

    if (nnuo_nonce_progress_errors != 0u) {
        nnuo_defense_error |= NNUO_ERR_NONCE_PROGRESS;
    }
#endif
}

/*
 * Prefix-target-suffix update-and-sample sequence.
 *
 * The target is the nonce++ update immediately before the target sampling
 * call. The sampler is called normally afterward with the resulting nonce
 * state.
 */
__attribute__((noinline))
static void nnuo_sampling_sequence_apply(polyvecl *s1, polyveck *s2)
{
    unsigned int call;
    unsigned int target = nnuo_fault_target_call;
    uint16_t nonce_state = 0xffffu;

    nnuo_sampling_entries++;

    nnuo_hpc_region_begin();

    if (target < NNUO_TOTAL_CALLS) {
        for (call = 0; call < target; call++) {
            (void)nnuo_nonce_update_normal_measured(&nonce_state);
            nnuo_record_used_nonce(call, nonce_state);
            nnuo_sampler_one(nnuo_output_poly(s1, s2, call), nonce_state);
        }

        nnuo_hpc_target_sample_cycles =
            nnuo_nonce_update_target_measured(&nonce_state);

        nnuo_record_used_nonce(target, nonce_state);
        nnuo_sampler_one(nnuo_output_poly(s1, s2, target), nonce_state);

        for (call = target + 1u; call < NNUO_TOTAL_CALLS; call++) {
            (void)nnuo_nonce_update_normal_measured(&nonce_state);
            nnuo_record_used_nonce(call, nonce_state);
            nnuo_sampler_one(nnuo_output_poly(s1, s2, call), nonce_state);
        }
    } else {
        for (call = 0; call < NNUO_TOTAL_CALLS; call++) {
            (void)nnuo_nonce_update_normal_measured(&nonce_state);
            nnuo_record_used_nonce(call, nonce_state);
            nnuo_sampler_one(nnuo_output_poly(s1, s2, call), nonce_state);
        }
    }

    nnuo_hpc_region_end();

    /*
     * Progression checking is after the sequence. It does not contaminate the
     * target nonce-update measured window.
     */
    nnuo_check_nonce_progression();

    nnuo_sampling_exits++;
}

#endif /* RAVI_NNUO_NONCE_FAULT_INC */

