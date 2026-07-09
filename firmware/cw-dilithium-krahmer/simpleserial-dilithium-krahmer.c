#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Krahmer et al., "Correction Fault Attacks on Randomized Dilithium"
 * skipping-correction variant.
 *
 * This is an SRAM-safe local-correction semantic kernel.  Its arithmetic uses reference-Dilithium-style lightweight reduce32/caddq helpers, not C "% Q".
 *
 * The simulated fault is not an instruction skip of a loop or a signing phase.
 * It is a local correction skip:
 *
 *     normal:  corrected = uncorrected + correction
 *     fault:   corrected = uncorrected
 *
 * The surrounding coefficient loop remains unchanged.  If the target
 * correction is inside a coefficient loop, the loop is split as:
 *
 *     normal prefix coefficients
 *     one faulted target coefficient
 *     normal suffix coefficients
 *
 * Runtime dispatch is outside the measured target primitive, so the measured
 * correction primitive does not contain "if attack then skip correction".
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef KRAHMER_HPC_TARGET_CYCLES_MIN
#define KRAHMER_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef KRAHMER_HPC_TARGET_CYCLES_MAX
#define KRAHMER_HPC_TARGET_CYCLES_MAX 0
#endif

#ifndef KRAHMER_NCOEFFS
#define KRAHMER_NCOEFFS N
#endif

#define KRAHMER_MODEL_NONE 0u
#define KRAHMER_MODEL_SKIP 1u

#define KRAHMER_ERR_HW_COUNTER 0x40u
#define KRAHMER_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define KRAHMER_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

static int32_t krahmer_uncorrected[KRAHMER_NCOEFFS];
static int32_t krahmer_correction[KRAHMER_NCOEFFS];
static int32_t krahmer_output[KRAHMER_NCOEFFS];
static int32_t krahmer_reference[KRAHMER_NCOEFFS];

volatile unsigned int krahmer_fault_model = KRAHMER_MODEL_NONE;
volatile unsigned int krahmer_target_coeff = 17;
volatile unsigned int krahmer_message_tweak = 0;

volatile unsigned int krahmer_faults_applied = 0;
volatile unsigned int krahmer_entries = 0;
volatile unsigned int krahmer_exits = 0;
volatile unsigned int krahmer_semantic_valid = 0;
volatile unsigned int krahmer_defense_error = 0;

volatile int krahmer_target_uncorrected = 0;
volatile int krahmer_target_correction = 0;
volatile int krahmer_target_expected = 0;
volatile int krahmer_target_used = 0;
volatile int krahmer_target_error = 0;

volatile unsigned int krahmer_output_digest = 0;
volatile unsigned int krahmer_reference_digest = 0;
volatile unsigned int krahmer_output_diff = 0;

volatile unsigned int krahmer_hpc_available = 0;
volatile unsigned int krahmer_hpc_anomaly = 0;
volatile unsigned int krahmer_hpc_region_cycles = 0;
volatile unsigned int krahmer_hpc_cpi = 0;
volatile unsigned int krahmer_hpc_exc = 0;
volatile unsigned int krahmer_hpc_lsu = 0;
volatile unsigned int krahmer_hpc_fold = 0;
volatile unsigned int krahmer_hpc_target_cycles = 0;
volatile unsigned int krahmer_hpc_cycles_min = 0xffffffffu;
volatile unsigned int krahmer_hpc_cycles_max = 0;
volatile unsigned int krahmer_hpc_cycles_sum = 0;

#if HPC_HW_ENABLE

#define KRAHMER_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define KRAHMER_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define KRAHMER_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define KRAHMER_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define KRAHMER_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define KRAHMER_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define KRAHMER_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define KRAHMER_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define KRAHMER_HPC_DEMCR_TRCENA          (1u << 24)
#define KRAHMER_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define KRAHMER_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t krahmer_hpc_region_start = 0;

static inline void krahmer_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    KRAHMER_HPC_DEMCR |= KRAHMER_HPC_DEMCR_TRCENA;
    ctrl = KRAHMER_HPC_DWT_CTRL;

    if ((ctrl & KRAHMER_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        KRAHMER_HPC_DWT_CTRL |= KRAHMER_HPC_DWT_CTRL_CYCCNTENA;
        krahmer_hpc_available |= 0x01u;
    }

    KRAHMER_HPC_DWT_CPICNT = 0;
    KRAHMER_HPC_DWT_EXCCNT = 0;
    KRAHMER_HPC_DWT_SLEEPCNT = 0;
    KRAHMER_HPC_DWT_LSUCNT = 0;
    KRAHMER_HPC_DWT_FOLDCNT = 0;
    krahmer_hpc_available |= 0x02u;
}

static inline void krahmer_hpc_region_begin(void)
{
    krahmer_hpc_dwt_enable();

    krahmer_hpc_anomaly = 0;
    krahmer_hpc_region_cycles = 0;
    krahmer_hpc_cpi = 0;
    krahmer_hpc_exc = 0;
    krahmer_hpc_lsu = 0;
    krahmer_hpc_fold = 0;
    krahmer_hpc_target_cycles = 0;
    krahmer_hpc_cycles_min = 0xffffffffu;
    krahmer_hpc_cycles_max = 0;
    krahmer_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    krahmer_hpc_region_start = KRAHMER_HPC_DWT_CYCCNT;
}

static inline uint32_t krahmer_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return KRAHMER_HPC_DWT_CYCCNT;
}

static inline uint32_t krahmer_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((krahmer_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = KRAHMER_HPC_DWT_CYCCNT - start;

    krahmer_hpc_cycles_sum += delta;

    if (delta < krahmer_hpc_cycles_min) {
        krahmer_hpc_cycles_min = delta;
    }

    if (delta > krahmer_hpc_cycles_max) {
        krahmer_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void krahmer_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = KRAHMER_HPC_DWT_CYCCNT;
    krahmer_hpc_region_cycles = end - krahmer_hpc_region_start;

    krahmer_hpc_cpi = KRAHMER_HPC_DWT_CPICNT & 0xffu;
    krahmer_hpc_exc = KRAHMER_HPC_DWT_EXCCNT & 0xffu;
    krahmer_hpc_lsu = KRAHMER_HPC_DWT_LSUCNT & 0xffu;
    krahmer_hpc_fold = KRAHMER_HPC_DWT_FOLDCNT & 0xffu;

#if KRAHMER_HPC_TARGET_CYCLES_MIN > 0
    if (krahmer_hpc_target_cycles < (unsigned int)KRAHMER_HPC_TARGET_CYCLES_MIN) {
        krahmer_hpc_anomaly |= KRAHMER_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if KRAHMER_HPC_TARGET_CYCLES_MAX > 0
    if (krahmer_hpc_target_cycles > (unsigned int)KRAHMER_HPC_TARGET_CYCLES_MAX) {
        krahmer_hpc_anomaly |= KRAHMER_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (krahmer_hpc_anomaly != 0u) {
        krahmer_defense_error |= KRAHMER_ERR_HW_COUNTER;
    }
}

#else

static inline void krahmer_hpc_region_begin(void)
{
    krahmer_hpc_anomaly = 0;
    krahmer_hpc_region_cycles = 0;
    krahmer_hpc_target_cycles = 0;
    krahmer_hpc_cycles_min = 0xffffffffu;
    krahmer_hpc_cycles_max = 0;
    krahmer_hpc_cycles_sum = 0;
}

static inline uint32_t krahmer_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t krahmer_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void krahmer_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

/*
 * Reference-Dilithium-style lightweight reduction helpers.
 *
 * This deliberately avoids C's "% Q" operator.  The shape follows the
 * reference Dilithium reduce32/caddq/freeze style:
 *
 *   reduce32: bring an int32 close to the centered representative range;
 *   caddq:    conditionally add Q if the value is negative;
 *   freeze:   combine the two for a non-negative representative.
 *
 * This is much closer to the arithmetic style used by Dilithium reference code
 * than an int64_t modulo operation.
 */
static inline int32_t krahmer_reduce32_refstyle(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * (int32_t)Q;

    return t;
}

static inline int32_t krahmer_caddq_refstyle(int32_t a)
{
    a += (a >> 31) & (int32_t)Q;
    return a;
}

static inline int32_t krahmer_freeze_refstyle(int32_t a)
{
    a = krahmer_reduce32_refstyle(a);
    a = krahmer_caddq_refstyle(a);
    return a;
}

/*
 * Normal local correction primitive:
 *
 *     corrected = uncorrected + correction
 */
__attribute__((noinline))
static uint32_t krahmer_correction_normal_measured(int32_t uncorrected,
                                                   int32_t correction,
                                                   int32_t *out)
{
    uint32_t start;
    uint32_t delta;
    int32_t corrected;

    __asm volatile("" ::: "memory");
    start = krahmer_hpc_op_begin();

    corrected = krahmer_freeze_refstyle(uncorrected + correction);
    *out = corrected;

    __asm volatile("" ::: "memory");
    delta = krahmer_hpc_op_end_common(start);

    return delta;
}

/*
 * Faulted local correction primitive:
 *
 *     corrected = uncorrected
 *
 * The correction term is deliberately omitted.  The primitive directly returns
 * the uncorrected value, modeling a skipped local correction operation.
 */
__attribute__((noinline))
static uint32_t krahmer_correction_skip_measured(int32_t uncorrected,
                                                 int32_t correction,
                                                 int32_t *out)
{
    uint32_t start;
    uint32_t delta;

    (void)correction;

    __asm volatile("" ::: "memory");
    start = krahmer_hpc_op_begin();

    *out = uncorrected;

    __asm volatile("" ::: "memory");
    delta = krahmer_hpc_op_end_common(start);

    krahmer_faults_applied++;

    return delta;
}

/*
 * Runtime dispatch is outside the measured primitive.
 */
__attribute__((noinline))
static uint32_t krahmer_target_correction_apply(unsigned int model,
                                                int32_t uncorrected,
                                                int32_t correction,
                                                int32_t *out)
{
    if (model == KRAHMER_MODEL_SKIP) {
        return krahmer_correction_skip_measured(uncorrected, correction, out);
    }

    return krahmer_correction_normal_measured(uncorrected, correction, out);
}

static uint32_t krahmer_digest_vec(const int32_t *v)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < KRAHMER_NCOEFFS; i++) {
        uint32_t x = (uint32_t)v[i];
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }

    return h;
}

static void krahmer_reset_observation_state(void)
{
    krahmer_faults_applied = 0;
    krahmer_entries = 0;
    krahmer_exits = 0;
    krahmer_semantic_valid = 0;
    krahmer_defense_error = 0;

    krahmer_target_uncorrected = 0;
    krahmer_target_correction = 0;
    krahmer_target_expected = 0;
    krahmer_target_used = 0;
    krahmer_target_error = 0;

    krahmer_output_digest = 0;
    krahmer_reference_digest = 0;
    krahmer_output_diff = 0;

    krahmer_hpc_anomaly = 0;
    krahmer_hpc_region_cycles = 0;
    krahmer_hpc_cpi = 0;
    krahmer_hpc_exc = 0;
    krahmer_hpc_lsu = 0;
    krahmer_hpc_fold = 0;
    krahmer_hpc_target_cycles = 0;
    krahmer_hpc_cycles_min = 0xffffffffu;
    krahmer_hpc_cycles_max = 0;
    krahmer_hpc_cycles_sum = 0;
}

static void krahmer_init_data(void)
{
    unsigned int i;
    uint32_t tweak = krahmer_message_tweak;

    for (i = 0; i < KRAHMER_NCOEFFS; i++) {
        /*
         * Keep the synthetic values in a Dilithium coefficient-like range using
         * the same lightweight reduce32/caddq style.  Do not use "% Q" here:
         * the experiment should not accidentally measure a heavy C modulo.
         */
        krahmer_uncorrected[i] =
            krahmer_freeze_refstyle((int32_t)(17u + 1229u * i + 19u * tweak));

        /*
         * A structured local correction term.  It is intentionally
         * deterministic and small so that:
         *
         *   corrected = uncorrected + correction
         *
         * is the visible local correction relation.
         */
        krahmer_correction[i] =
            (int32_t)(3u + ((i * 37u + 11u + tweak) & 0xffu));

        krahmer_output[i] = 0;
        krahmer_reference[i] = 0;
    }
}

static void krahmer_run_reference(void)
{
    unsigned int i;

    for (i = 0; i < KRAHMER_NCOEFFS; i++) {
        krahmer_reference[i] =
            krahmer_freeze_refstyle(krahmer_uncorrected[i] +
                                    krahmer_correction[i]);
    }

    krahmer_reference_digest = krahmer_digest_vec(krahmer_reference);
}

__attribute__((noinline))
static void krahmer_run_correction_loop(void)
{
    unsigned int i;
    unsigned int target = krahmer_target_coeff;
    int32_t target_out = 0;

    if (target >= KRAHMER_NCOEFFS) {
        target = 0;
        krahmer_target_coeff = 0;
    }

    krahmer_entries++;

    krahmer_run_reference();

    krahmer_hpc_region_begin();

    /*
     * Normal prefix.
     */
    for (i = 0; i < target; i++) {
        (void)krahmer_correction_normal_measured(krahmer_uncorrected[i],
                                                 krahmer_correction[i],
                                                 &krahmer_output[i]);
    }

    /*
     * Target coefficient.
     */
    krahmer_target_uncorrected = krahmer_uncorrected[target];
    krahmer_target_correction = krahmer_correction[target];
    krahmer_target_expected = krahmer_reference[target];

    krahmer_hpc_target_cycles =
        krahmer_target_correction_apply(krahmer_fault_model,
                                        krahmer_uncorrected[target],
                                        krahmer_correction[target],
                                        &target_out);

    krahmer_output[target] = target_out;
    krahmer_target_used = target_out;

    /*
     * Normal suffix.
     */
    for (i = target + 1u; i < KRAHMER_NCOEFFS; i++) {
        (void)krahmer_correction_normal_measured(krahmer_uncorrected[i],
                                                 krahmer_correction[i],
                                                 &krahmer_output[i]);
    }

    krahmer_hpc_region_end();

    /*
     * Report the signed local error directly.  For the skipping-correction
     * attack this should equal the omitted correction term.
     */
    krahmer_target_error =
        (int)(krahmer_target_expected - krahmer_target_used);

    krahmer_output_digest = krahmer_digest_vec(krahmer_output);
    krahmer_output_diff = krahmer_output_digest ^ krahmer_reference_digest;

    krahmer_semantic_valid = 1;
    krahmer_exits++;
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
    unsigned int target;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > KRAHMER_MODEL_SKIP) {
        model = KRAHMER_MODEL_NONE;
    }

    target = ((unsigned int)buf[1]) | (((unsigned int)buf[2]) << 8);
    if (target >= KRAHMER_NCOEFFS) {
        target = 0;
    }

    tweak = (unsigned int)buf[3] |
            (((unsigned int)buf[4]) << 8) |
            (((unsigned int)buf[5]) << 16) |
            (((unsigned int)buf[6]) << 24);

    krahmer_fault_model = model;
    krahmer_target_coeff = target;
    krahmer_message_tweak = tweak;

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)krahmer_fault_model;
    out[2] = (uint8_t)(krahmer_target_coeff & 0xffu);
    out[3] = (uint8_t)((krahmer_target_coeff >> 8) & 0xffu);
    put_u32le(out, 4, krahmer_message_tweak);
    put_u32le(out, 8, KRAHMER_NCOEFFS);
    put_u32le(out, 12, (unsigned int)Q);

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

    krahmer_reset_observation_state();
    krahmer_init_data();

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

    krahmer_reset_observation_state();
    krahmer_init_data();

    trigger_high();
    krahmer_run_correction_loop();
    trigger_low();

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

    out[0] = (uint8_t)krahmer_fault_model;
    out[1] = (uint8_t)(krahmer_target_coeff & 0xffu);
    out[2] = (uint8_t)((krahmer_target_coeff >> 8) & 0xffu);
    out[3] = (uint8_t)krahmer_semantic_valid;

    put_u32le(out, 4, krahmer_faults_applied);
    put_u32le(out, 8, (unsigned int)krahmer_target_uncorrected);
    put_u32le(out, 12, (unsigned int)krahmer_target_correction);
    put_u32le(out, 16, (unsigned int)krahmer_target_expected);
    put_u32le(out, 20, (unsigned int)krahmer_target_used);
    put_u32le(out, 24, (unsigned int)krahmer_target_error);

    out[28] = (uint8_t)krahmer_defense_error;
    out[29] = (uint8_t)krahmer_hpc_anomaly;
    out[30] = (uint8_t)krahmer_entries;
    out[31] = (uint8_t)krahmer_exits;

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

    put_u32le(out, 0, krahmer_output_digest);
    put_u32le(out, 4, krahmer_reference_digest);
    put_u32le(out, 8, krahmer_output_diff);
    put_u32le(out, 12, krahmer_message_tweak);

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
        ((krahmer_hpc_cpi & 0xffu) << 0) |
        ((krahmer_hpc_exc & 0xffu) << 8) |
        ((krahmer_hpc_lsu & 0xffu) << 16) |
        ((krahmer_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, krahmer_hpc_available);
    put_u32le(out, 4, krahmer_hpc_anomaly);
    put_u32le(out, 8, krahmer_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, krahmer_hpc_target_cycles);
    put_u32le(out, 20, krahmer_hpc_cycles_min);
    put_u32le(out, 24, krahmer_hpc_cycles_max);
    put_u32le(out, 28, krahmer_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    krahmer_reset_observation_state();
    krahmer_init_data();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef KRAHMER_BOOT_BANNER
#define KRAHMER_BOOT_BANNER 1
#endif

#if KRAHMER_BOOT_BANNER
    uart_puts("KRAHMER_SKIP_CORRECTION_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}