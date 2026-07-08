#ifndef POLY_DECODE_HPC_INC
#define POLY_DECODE_HPC_INC

/*
 * Hardware-counter guarded DecodeMessage implementation for Kyber poly_tomsg().
 *
 * This file is intentionally included from poly.c at the original
 * poly_tomsg() location. It contains definitions, not just declarations.
 *
 * Main hardware counters used:
 *   - Cortex-M DWT_CYCCNT   : 32-bit cycle counter
 *   - Cortex-M DWT_CPICNT   : 8-bit CPI event counter
 *   - Cortex-M DWT_EXCCNT   : 8-bit exception overhead counter
 *   - Cortex-M DWT_LSUCNT   : 8-bit load/store event counter
 *   - Cortex-M DWT_FOLDCNT  : 8-bit folded instruction counter
 *
 * Detection policy:
 *   - build one firmware image containing both baseline and faulted decoders;
 *   - switch baseline/attack at runtime through hpc_cw_attack_enable;
 *   - build once with thresholds disabled to observe baseline/attack values;
 *   - then set HPC_HW_TARGET_COEFF_CYCLES_MIN / MAX or region thresholds.
 */

#ifndef ATTACK_DECODER_SKIP_QHALF
#define ATTACK_DECODER_SKIP_QHALF 0
#endif

#ifndef ATTACK_TARGET_COEFF
#define ATTACK_TARGET_COEFF 0
#endif

/*
 * Runtime attack control.
 *
 * To compare baseline and attack without changing the firmware binary,
 * compile both normal and faulted DecodeMessage primitives into the same
 * image and select the mode at runtime.
 *
 *   hpc_cw_attack_enable = 0: baseline mode
 *   hpc_cw_attack_enable = 1: attack mode
 *
 * ATTACK_TARGET_COEFF is still used as the default target coefficient, but
 * hpc_cw_attack_target_coeff may be changed by the SimpleSerial wrapper if
 * desired.
 */
#ifndef HPC_CW_ATTACK_ENABLE_DEFAULT
#define HPC_CW_ATTACK_ENABLE_DEFAULT 0
#endif

#ifndef DEFENSE_DUP_SELECTED
#define DEFENSE_DUP_SELECTED 1
#endif

#ifndef DEFENSE_REDUNDANT_FULL
#define DEFENSE_REDUNDANT_FULL 1
#endif

#ifndef DEFENSE_DUP_STRIDE
#define DEFENSE_DUP_STRIDE 32
#endif

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 1
#endif

#ifndef HPC_HW_REGION_CYCLES_MIN
#define HPC_HW_REGION_CYCLES_MIN 0u
#endif

#ifndef HPC_HW_REGION_CYCLES_MAX
#define HPC_HW_REGION_CYCLES_MAX 0u
#endif

#ifndef HPC_HW_TARGET_COEFF_CYCLES_MIN
#define HPC_HW_TARGET_COEFF_CYCLES_MIN 0u
#endif

#ifndef HPC_HW_TARGET_COEFF_CYCLES_MAX
#define HPC_HW_TARGET_COEFF_CYCLES_MAX 0u
#endif

#define HPC_CW_DECERR_DUP_MISMATCH       0x00000001u
#define HPC_CW_DECERR_FULL_MISMATCH      0x00000002u
#define HPC_CW_DECERR_PROGRESS_MISMATCH  0x00000004u
#define HPC_CW_DECERR_END_PROGRESS       0x00000008u
#define HPC_CW_DECERR_MARKER             0x00000010u
#define HPC_CW_DECERR_HW_COUNTER         0x00000040u

#define HPC_HW_ERR_DWT_UNAVAILABLE       0x00000001u
#define HPC_HW_ERR_REGION_CYCLES_LOW     0x00000002u
#define HPC_HW_ERR_REGION_CYCLES_HIGH    0x00000004u
#define HPC_HW_ERR_TARGET_CYCLES_LOW     0x00000008u
#define HPC_HW_ERR_TARGET_CYCLES_HIGH    0x00000010u

#define HPC_REG32(addr) (*(volatile uint32_t *)(addr))
#define HPC_REG8(addr)  (*(volatile uint8_t  *)(addr))

#define HPC_HW_DEMCR        HPC_REG32(0xE000EDFCu)
#define HPC_HW_DWT_CTRL     HPC_REG32(0xE0001000u)
#define HPC_HW_DWT_CYCCNT   HPC_REG32(0xE0001004u)
#define HPC_HW_DWT_CPICNT   HPC_REG8(0xE0001008u)
#define HPC_HW_DWT_EXCCNT   HPC_REG8(0xE000100Cu)
#define HPC_HW_DWT_SLEEPCNT HPC_REG8(0xE0001010u)
#define HPC_HW_DWT_LSUCNT   HPC_REG8(0xE0001014u)
#define HPC_HW_DWT_FOLDCNT  HPC_REG8(0xE0001018u)

#define HPC_HW_DEMCR_TRCENA         (1u << 24)
#define HPC_HW_DWT_CTRL_CYCCNTENA   (1u << 0)
#define HPC_HW_DWT_CTRL_CPIEVTENA   (1u << 17)
#define HPC_HW_DWT_CTRL_EXCEVTENA   (1u << 18)
#define HPC_HW_DWT_CTRL_SLEEPEVTENA (1u << 19)
#define HPC_HW_DWT_CTRL_LSUEVTENA   (1u << 20)
#define HPC_HW_DWT_CTRL_FOLDEVTENA  (1u << 21)
#define HPC_HW_DWT_CTRL_NOPRFCNT    (1u << 24)
#define HPC_HW_DWT_CTRL_NOCYCCNT    (1u << 25)

/* Existing attack/debug status. */
volatile unsigned int hpc_cw_fault_skips = 0;

/*
 * Runtime attack configuration.
 *
 * These variables allow baseline and attack trials to use the same firmware
 * binary. The host-side SimpleSerial wrapper should set hpc_cw_attack_enable
 * before decapsulation:
 *
 *   0 -> decode the target coefficient normally
 *   1 -> decode the target coefficient with the faulted primitive
 */
volatile unsigned int hpc_cw_attack_enable = HPC_CW_ATTACK_ENABLE_DEFAULT;
volatile unsigned int hpc_cw_attack_target_coeff = 0;

/* DecodeMessage software state, only for region/progress/status reporting. */
volatile unsigned int hpc_cw_decode_entries = 0;
volatile unsigned int hpc_cw_decode_exits = 0;
volatile unsigned int hpc_cw_decode_progress = 0;
volatile unsigned int hpc_cw_decode_expected = 256;
volatile unsigned int hpc_cw_decode_defense_error = 0;
volatile unsigned int hpc_cw_decode_dup_checks = 0;
volatile unsigned int hpc_cw_decode_dup_mismatches = 0;
volatile unsigned int hpc_cw_decode_full_mismatches = 0;
volatile unsigned int hpc_cw_decode_last_marker = 0;
volatile unsigned int hpc_cw_decode_marker_count = 0;

/* Real DWT hardware counter state. */
volatile unsigned int hpc_hw_available = 0;
volatile unsigned int hpc_hw_ctrl = 0;
volatile unsigned int hpc_hw_anomaly = 0;

volatile unsigned int hpc_hw_decode_cycles = 0;
volatile unsigned int hpc_hw_decode_cpi = 0;
volatile unsigned int hpc_hw_decode_exc = 0;
volatile unsigned int hpc_hw_decode_sleep = 0;
volatile unsigned int hpc_hw_decode_lsu = 0;
volatile unsigned int hpc_hw_decode_fold = 0;

volatile unsigned int hpc_hw_coeff_cycles_sum = 0;
volatile unsigned int hpc_hw_coeff_cycles_min = 0xffffffffu;
volatile unsigned int hpc_hw_coeff_cycles_max = 0;
volatile unsigned int hpc_hw_target_coeff_cycles = 0;
volatile unsigned int hpc_hw_target_coeff_idx = 0;

static unsigned int hpc_hw_start_cyccnt;
static uint8_t hpc_hw_start_cpicnt;
static uint8_t hpc_hw_start_exccnt;
static uint8_t hpc_hw_start_sleepcnt;
static uint8_t hpc_hw_start_lsucnt;
static uint8_t hpc_hw_start_foldcnt;

/*
 * Optional ITM marker. If ITM/SWO is not enabled, this only updates
 * volatile software marker variables and does not block.
 */
#define HPC_CW_ITM_STIM0_U8 HPC_REG8(0xE0000000u)
#define HPC_CW_ITM_TER      HPC_REG32(0xE0000E00u)
#define HPC_CW_ITM_TCR      HPC_REG32(0xE0000E80u)

static inline void hpc_cw_decode_marker(unsigned int marker)
{
    hpc_cw_decode_last_marker = marker;
    hpc_cw_decode_marker_count++;

    if ((HPC_CW_ITM_TCR & 1u) && (HPC_CW_ITM_TER & 1u)) {
        HPC_CW_ITM_STIM0_U8 = (uint8_t)marker;
    }
}

static inline unsigned int hpc_hw_delta8(uint8_t end, uint8_t start)
{
    return ((unsigned int)end - (unsigned int)start) & 0xffu;
}

static inline void hpc_hw_dwt_enable(void)
{
#if HPC_HW_ENABLE
    uint32_t ctrl;

    HPC_HW_DEMCR |= HPC_HW_DEMCR_TRCENA;

    ctrl = HPC_HW_DWT_CTRL;
    hpc_hw_ctrl = ctrl;
    hpc_hw_available = 0;

    if ((ctrl & HPC_HW_DWT_CTRL_NOCYCCNT) == 0u) {
        HPC_HW_DWT_CTRL |= HPC_HW_DWT_CTRL_CYCCNTENA;
        hpc_hw_available |= 0x01u;
    }

    if ((ctrl & HPC_HW_DWT_CTRL_NOPRFCNT) == 0u) {
        HPC_HW_DWT_CPICNT = 0;
        HPC_HW_DWT_EXCCNT = 0;
        HPC_HW_DWT_SLEEPCNT = 0;
        HPC_HW_DWT_LSUCNT = 0;
        HPC_HW_DWT_FOLDCNT = 0;

        HPC_HW_DWT_CTRL |=
            HPC_HW_DWT_CTRL_CPIEVTENA |
            HPC_HW_DWT_CTRL_EXCEVTENA |
            HPC_HW_DWT_CTRL_SLEEPEVTENA |
            HPC_HW_DWT_CTRL_LSUEVTENA |
            HPC_HW_DWT_CTRL_FOLDEVTENA;

        hpc_hw_available |= 0x02u;
    }

    __asm volatile("dsb");
    __asm volatile("isb");
#else
    hpc_hw_available = 0;
#endif
}

static inline void hpc_hw_region_begin(void)
{
#if HPC_HW_ENABLE
    hpc_hw_dwt_enable();

    hpc_hw_anomaly = 0;

    hpc_hw_decode_cycles = 0;
    hpc_hw_decode_cpi = 0;
    hpc_hw_decode_exc = 0;
    hpc_hw_decode_sleep = 0;
    hpc_hw_decode_lsu = 0;
    hpc_hw_decode_fold = 0;

    hpc_hw_coeff_cycles_sum = 0;
    hpc_hw_coeff_cycles_min = 0xffffffffu;
    hpc_hw_coeff_cycles_max = 0;
    hpc_hw_target_coeff_cycles = 0;
    hpc_hw_target_coeff_idx = hpc_cw_attack_target_coeff;

    if ((hpc_hw_available & 0x01u) == 0u) {
        hpc_hw_anomaly |= HPC_HW_ERR_DWT_UNAVAILABLE;
        return;
    }

    HPC_HW_DWT_CPICNT = 0;
    HPC_HW_DWT_EXCCNT = 0;
    HPC_HW_DWT_SLEEPCNT = 0;
    HPC_HW_DWT_LSUCNT = 0;
    HPC_HW_DWT_FOLDCNT = 0;

    __asm volatile("" ::: "memory");

    hpc_hw_start_cyccnt = HPC_HW_DWT_CYCCNT;
    hpc_hw_start_cpicnt = HPC_HW_DWT_CPICNT;
    hpc_hw_start_exccnt = HPC_HW_DWT_EXCCNT;
    hpc_hw_start_sleepcnt = HPC_HW_DWT_SLEEPCNT;
    hpc_hw_start_lsucnt = HPC_HW_DWT_LSUCNT;
    hpc_hw_start_foldcnt = HPC_HW_DWT_FOLDCNT;
#else
    hpc_hw_available = 0;
#endif
}

static inline void hpc_hw_region_end(void)
{
#if HPC_HW_ENABLE
    uint32_t end_cyccnt;
    uint8_t end_cpicnt;
    uint8_t end_exccnt;
    uint8_t end_sleepcnt;
    uint8_t end_lsucnt;
    uint8_t end_foldcnt;

    if ((hpc_hw_available & 0x01u) == 0u) {
        hpc_hw_anomaly |= HPC_HW_ERR_DWT_UNAVAILABLE;
        hpc_cw_decode_defense_error |= HPC_CW_DECERR_HW_COUNTER;
        return;
    }

    __asm volatile("" ::: "memory");

    end_cyccnt = HPC_HW_DWT_CYCCNT;
    end_cpicnt = HPC_HW_DWT_CPICNT;
    end_exccnt = HPC_HW_DWT_EXCCNT;
    end_sleepcnt = HPC_HW_DWT_SLEEPCNT;
    end_lsucnt = HPC_HW_DWT_LSUCNT;
    end_foldcnt = HPC_HW_DWT_FOLDCNT;

    hpc_hw_decode_cycles = end_cyccnt - hpc_hw_start_cyccnt;
    hpc_hw_decode_cpi = hpc_hw_delta8(end_cpicnt, hpc_hw_start_cpicnt);
    hpc_hw_decode_exc = hpc_hw_delta8(end_exccnt, hpc_hw_start_exccnt);
    hpc_hw_decode_sleep = hpc_hw_delta8(end_sleepcnt, hpc_hw_start_sleepcnt);
    hpc_hw_decode_lsu = hpc_hw_delta8(end_lsucnt, hpc_hw_start_lsucnt);
    hpc_hw_decode_fold = hpc_hw_delta8(end_foldcnt, hpc_hw_start_foldcnt);

#if HPC_HW_REGION_CYCLES_MIN
    if (hpc_hw_decode_cycles < HPC_HW_REGION_CYCLES_MIN) {
        hpc_hw_anomaly |= HPC_HW_ERR_REGION_CYCLES_LOW;
    }
#endif

#if HPC_HW_REGION_CYCLES_MAX
    if (hpc_hw_decode_cycles > HPC_HW_REGION_CYCLES_MAX) {
        hpc_hw_anomaly |= HPC_HW_ERR_REGION_CYCLES_HIGH;
    }
#endif

#if HPC_HW_TARGET_COEFF_CYCLES_MIN
    if (hpc_hw_target_coeff_cycles < HPC_HW_TARGET_COEFF_CYCLES_MIN) {
        hpc_hw_anomaly |= HPC_HW_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if HPC_HW_TARGET_COEFF_CYCLES_MAX
    if (hpc_hw_target_coeff_cycles > HPC_HW_TARGET_COEFF_CYCLES_MAX) {
        hpc_hw_anomaly |= HPC_HW_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (hpc_hw_anomaly != 0u) {
        hpc_cw_decode_defense_error |= HPC_CW_DECERR_HW_COUNTER;
    }
#endif
}

static inline uint32_t hpc_hw_coeff_begin(void)
{
#if HPC_HW_ENABLE
    __asm volatile("" ::: "memory");
    return HPC_HW_DWT_CYCCNT;
#else
    return 0;
#endif
}

/*
 * Common end-of-measurement helper for every coefficient.
 *
 * The target coefficient is no longer measured through a separate target-only
 * wrapper. This helper only computes and accumulates the delta. The caller
 * decides whether the returned delta should also be copied into
 * hpc_hw_target_coeff_cycles.
 */
static inline uint32_t hpc_hw_coeff_end_common(unsigned int coeff_idx,
                                               uint32_t start)
{
#if HPC_HW_ENABLE
    uint32_t delta;

    if ((hpc_hw_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = HPC_HW_DWT_CYCCNT - start;

    hpc_hw_coeff_cycles_sum += delta;

    if (delta < hpc_hw_coeff_cycles_min) {
        hpc_hw_coeff_cycles_min = delta;
    }

    if (delta > hpc_hw_coeff_cycles_max) {
        hpc_hw_coeff_cycles_max = delta;
    }

    (void)coeff_idx;
    return delta;
#else
    (void)coeff_idx;
    (void)start;
    return 0;
#endif
}

static inline void hpc_cw_decode_enter(void)
{
    hpc_cw_decode_entries++;
    hpc_cw_decode_progress = 0;
    hpc_cw_decode_expected = KYBER_SYMBYTES * 8u;
    hpc_cw_decode_marker(0xD1u);
}

static inline void hpc_cw_decode_coeff_progress(unsigned int coeff_idx)
{
    if (hpc_cw_decode_progress != coeff_idx) {
        hpc_cw_decode_defense_error |= HPC_CW_DECERR_PROGRESS_MISMATCH;
    }

    hpc_cw_decode_progress = coeff_idx + 1u;
}

static inline void hpc_cw_decode_exit(void)
{
    if (hpc_cw_decode_progress != hpc_cw_decode_expected) {
        hpc_cw_decode_defense_error |= HPC_CW_DECERR_END_PROGRESS;
    }

    hpc_cw_decode_exits++;
    hpc_cw_decode_marker(0xD2u);
}

/*
 * DecodeMessage coefficient primitives.
 *
 * Baseline and attack use the same firmware binary. The firmware contains
 * both primitives:
 *
 *   - hpc_cw_decode_round_normal():
 *       normal Kyber DecodeMessage rounding
 *
 *   - hpc_cw_decode_round_faulted_no_qhalf():
 *       faulted rounding with the (+ KYBER_Q / 2) term skipped
 *
 * Runtime mode selection chooses which primitive is used only for the selected
 * target coefficient. The target selection branch is outside the prefix/suffix
 * loops and outside the measured primitive window.
 */
__attribute__((noinline))
static uint16_t hpc_cw_decode_round_normal(int32_t x)
{
    return (uint16_t)((((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1);
}

__attribute__((noinline))
static uint16_t hpc_cw_decode_round_faulted_no_qhalf(int32_t x)
{
    return (uint16_t)(((x << 1) / KYBER_Q) & 1);
}

/*
 * Independent reference path. Used only for optional redundant decoding.
 */
__attribute__((noinline, optimize("O0")))
static uint16_t hpc_cw_decode_round_reference(int32_t x)
{
    volatile int32_t vx = x;
    volatile int32_t vq = KYBER_Q;
    volatile int32_t vh = KYBER_Q / 2;

    uint16_t r = (uint16_t)((((vx << 1) + vh) / vq) & 1);

    __asm volatile("" ::: "memory");
    return r;
}

static inline int hpc_cw_decode_should_duplicate(unsigned int coeff_idx)
{
#if DEFENSE_DUP_SELECTED
    if ((coeff_idx % DEFENSE_DUP_STRIDE) == 0u) {
        return 1;
    }
#else
    (void)coeff_idx;
#endif

    return 0;
}

static inline void hpc_cw_msg_or_bit(unsigned char msg[KYBER_SYMBYTES],
                                     unsigned int coeff_idx,
                                     uint16_t t)
{
    unsigned int byte_idx = coeff_idx >> 3;
    unsigned int bit_idx = coeff_idx & 7u;

    msg[byte_idx] |= (unsigned char)(t << bit_idx);
}

static inline void hpc_cw_decode_maybe_check_duplicate(uint16_t t,
                                                       int32_t x,
                                                       unsigned int coeff_idx,
                                                       int force_check)
{
#if DEFENSE_DUP_SELECTED
    if (force_check || hpc_cw_decode_should_duplicate(coeff_idx)) {
        uint16_t tref = hpc_cw_decode_round_reference(x);

        hpc_cw_decode_dup_checks++;

        if (t != tref) {
            hpc_cw_decode_dup_mismatches++;
            hpc_cw_decode_defense_error |= HPC_CW_DECERR_DUP_MISMATCH;
        }
    }
#else
    (void)t;
    (void)x;
    (void)coeff_idx;
    (void)force_check;
#endif
}

/*
 * Unified measured normal coefficient decode.
 *
 * Every normal coefficient, including the runtime-selected target coefficient
 * in baseline mode, goes through this exact same function body. This avoids
 * the previous target-only wrapper artifact where target_coeff_cycles could
 * be measured as only the counter-read overhead.
 */
__attribute__((noinline))
static uint32_t hpc_cw_decode_one_normal_measured(unsigned char msg[KYBER_SYMBYTES],
                                                  poly *a,
                                                  unsigned int coeff_idx,
                                                  int force_dup_check)
{
    uint16_t t;
    uint32_t coeff_cycle_start;
    uint32_t delta;

    __asm volatile("" ::: "memory");

    coeff_cycle_start = hpc_hw_coeff_begin();

    __asm volatile("" ::: "memory");

    t = hpc_cw_decode_round_normal(a->coeffs[coeff_idx]);

    __asm volatile("" ::: "memory");

    delta = hpc_hw_coeff_end_common(coeff_idx, coeff_cycle_start);

    hpc_cw_decode_maybe_check_duplicate(
        t,
        a->coeffs[coeff_idx],
        coeff_idx,
        force_dup_check
    );

    hpc_cw_msg_or_bit(msg, coeff_idx, t);
    hpc_cw_decode_coeff_progress(coeff_idx);

    return delta;
}

/*
 * Unified measured faulted target coefficient decode.
 *
 * Only the selected target coefficient in attack mode goes through this
 * function. The hpc_cw_fault_skips bookkeeping happens after the measured
 * primitive window.
 */
__attribute__((noinline))
static uint32_t hpc_cw_decode_one_faulted_measured(unsigned char msg[KYBER_SYMBYTES],
                                                   poly *a,
                                                   unsigned int coeff_idx,
                                                   int force_dup_check)
{
    uint16_t t;
    uint32_t coeff_cycle_start;
    uint32_t delta;

    __asm volatile("" ::: "memory");

    coeff_cycle_start = hpc_hw_coeff_begin();

    __asm volatile("" ::: "memory");

    t = hpc_cw_decode_round_faulted_no_qhalf(a->coeffs[coeff_idx]);

    __asm volatile("" ::: "memory");

    delta = hpc_hw_coeff_end_common(coeff_idx, coeff_cycle_start);

    /*
     * Keep the functional fault counter outside the measured primitive so
     * target_coeff_cycles measures the faulted DecodeMessage primitive rather
     * than the bookkeeping store.
     */
    hpc_cw_fault_skips++;

    hpc_cw_decode_maybe_check_duplicate(
        t,
        a->coeffs[coeff_idx],
        coeff_idx,
        force_dup_check
    );

    hpc_cw_msg_or_bit(msg, coeff_idx, t);
    hpc_cw_decode_coeff_progress(coeff_idx);

    return delta;
}

void poly_tomsg(unsigned char msg[KYBER_SYMBYTES], poly *a)
{
    unsigned int coeff_idx;
    unsigned int target_coeff = hpc_cw_attack_target_coeff;
    const unsigned int ncoeff = (unsigned int)(KYBER_SYMBYTES * 8u);
    int attack_enable;
    int i, j;

#if DEFENSE_REDUNDANT_FULL
    unsigned char msg_ref[KYBER_SYMBYTES];
#endif

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        msg[i] = 0;
    }

    attack_enable = (hpc_cw_attack_enable != 0u);

    hpc_cw_decode_enter();
    hpc_hw_region_begin();

    /*
     * Prefix-target-suffix DecodeMessage traversal.
     *
     * The target selection branch is outside the per-coefficient loops.
     * Therefore the normal loop body does not contain:
     *
     *     if (coeff_idx == hpc_cw_attack_target_coeff)
     *
     * Baseline and attack are selected at runtime using the same firmware
     * binary, but the measured target primitive itself contains no mode check.
     */
    if (target_coeff < ncoeff) {
        for (coeff_idx = 0; coeff_idx < target_coeff; coeff_idx++) {
            (void)hpc_cw_decode_one_normal_measured(msg, a, coeff_idx, 0);
        }

        if (attack_enable) {
            hpc_hw_target_coeff_cycles =
                hpc_cw_decode_one_faulted_measured(msg, a, target_coeff, 1);
        } else {
            hpc_hw_target_coeff_cycles =
                hpc_cw_decode_one_normal_measured(msg, a, target_coeff, 1);
        }

        for (coeff_idx = target_coeff + 1u; coeff_idx < ncoeff; coeff_idx++) {
            (void)hpc_cw_decode_one_normal_measured(msg, a, coeff_idx, 0);
        }
    } else {
        /*
         * Out-of-range target: no coefficient is faulted. This fallback keeps
         * the function safe if the runtime target coefficient is misconfigured.
         */
        for (coeff_idx = 0; coeff_idx < ncoeff; coeff_idx++) {
            (void)hpc_cw_decode_one_normal_measured(msg, a, coeff_idx, 0);
        }
    }

#if DEFENSE_REDUNDANT_FULL
    for (i = 0; i < KYBER_SYMBYTES; i++) {
        msg_ref[i] = 0;

        for (j = 0; j < 8; j++) {
            unsigned int ref_coeff_idx = (unsigned int)(8 * i + j);
            uint16_t tref = hpc_cw_decode_round_reference(a->coeffs[ref_coeff_idx]);

            msg_ref[i] |= (unsigned char)(tref << j);
        }
    }

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        if (msg[i] != msg_ref[i]) {
            hpc_cw_decode_full_mismatches++;
            hpc_cw_decode_defense_error |= HPC_CW_DECERR_FULL_MISMATCH;
        }
    }

    if (hpc_cw_decode_defense_error != 0u) {
        for (i = 0; i < KYBER_SYMBYTES; i++) {
            msg[i] = msg_ref[i];
        }
    }
#endif

    hpc_hw_region_end();
    hpc_cw_decode_exit();
}

#endif /* POLY_DECODE_HPC_INC */
