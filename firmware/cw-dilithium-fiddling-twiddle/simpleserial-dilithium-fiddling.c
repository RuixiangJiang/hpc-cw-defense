#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Ravi et al., "Fiddling the Twiddle Constants"
 *
 * This firmware is an SRAM-safe NTT-layer semantic kernel.
 *
 * The attack is modeled as data corruption of the twiddle information consumed
 * by one butterfly.  The NTT layer and butterfly loop are not skipped.
 *
 * Fault models:
 *   0 = none
 *   1 = pointer-corruption:
 *       redirect the twiddle pointer to a wrong address before the target
 *       butterfly loads the twiddle.
 *   2 = value-corruption:
 *       perform the target twiddle load and then replace the loaded value
 *       immediately before the butterfly uses it.
 *
 * Target-window rule:
 *   Runtime dispatch is outside the measured target primitive.  The measured
 *   target primitive contains either:
 *
 *     - a normal butterfly consuming the normal twiddle pointer;
 *     - a normal butterfly consuming a redirected twiddle pointer;
 *     - a normal butterfly consuming a loaded-but-replaced twiddle value.
 *
 * The target window does not contain "if attack then fault".
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef FIDDLING_HPC_TARGET_CYCLES_MIN
#define FIDDLING_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef FIDDLING_HPC_TARGET_CYCLES_MAX
#define FIDDLING_HPC_TARGET_CYCLES_MAX 0
#endif

#ifndef FIDDLING_NCOEFFS
#define FIDDLING_NCOEFFS N
#endif

#ifndef FIDDLING_LAYER_LEN
#define FIDDLING_LAYER_LEN 64u
#endif

#define FIDDLING_MODEL_NONE      0u
#define FIDDLING_MODEL_PTR       1u
#define FIDDLING_MODEL_VALUE     2u

#define FIDDLING_ERR_HW_COUNTER 0x40u
#define FIDDLING_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define FIDDLING_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

static int32_t fiddling_poly[FIDDLING_NCOEFFS];
static int32_t fiddling_poly_baseline[FIDDLING_NCOEFFS];

static int32_t fiddling_twiddles[256];
static int32_t fiddling_wrong_twiddles[256];

static volatile int32_t fiddling_zero_twiddle = 0;

volatile unsigned int fiddling_fault_model = FIDDLING_MODEL_NONE;
volatile unsigned int fiddling_target_j = 17;
volatile unsigned int fiddling_twiddle_index = 29;
volatile unsigned int fiddling_wrong_index = 0;
volatile int fiddling_fault_value = 0;

volatile unsigned int fiddling_faults_applied = 0;
volatile unsigned int fiddling_entries = 0;
volatile unsigned int fiddling_exits = 0;
volatile unsigned int fiddling_semantic_valid = 0;
volatile unsigned int fiddling_defense_error = 0;

volatile int fiddling_expected_twiddle = 0;
volatile int fiddling_used_twiddle = 0;
volatile int fiddling_target_before_a = 0;
volatile int fiddling_target_before_b = 0;
volatile int fiddling_target_after_a = 0;
volatile int fiddling_target_after_b = 0;
volatile unsigned int fiddling_output_digest = 0;
volatile unsigned int fiddling_baseline_digest = 0;
volatile unsigned int fiddling_output_diff = 0;

volatile unsigned int fiddling_hpc_available = 0;
volatile unsigned int fiddling_hpc_anomaly = 0;
volatile unsigned int fiddling_hpc_region_cycles = 0;
volatile unsigned int fiddling_hpc_cpi = 0;
volatile unsigned int fiddling_hpc_exc = 0;
volatile unsigned int fiddling_hpc_lsu = 0;
volatile unsigned int fiddling_hpc_fold = 0;
volatile unsigned int fiddling_hpc_target_cycles = 0;
volatile unsigned int fiddling_hpc_cycles_min = 0xffffffffu;
volatile unsigned int fiddling_hpc_cycles_max = 0;
volatile unsigned int fiddling_hpc_cycles_sum = 0;

#if HPC_HW_ENABLE

#define FIDDLING_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define FIDDLING_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define FIDDLING_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define FIDDLING_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define FIDDLING_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define FIDDLING_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define FIDDLING_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define FIDDLING_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define FIDDLING_HPC_DEMCR_TRCENA          (1u << 24)
#define FIDDLING_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define FIDDLING_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t fiddling_hpc_region_start = 0;

static inline void fiddling_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    FIDDLING_HPC_DEMCR |= FIDDLING_HPC_DEMCR_TRCENA;
    ctrl = FIDDLING_HPC_DWT_CTRL;

    if ((ctrl & FIDDLING_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        FIDDLING_HPC_DWT_CTRL |= FIDDLING_HPC_DWT_CTRL_CYCCNTENA;
        fiddling_hpc_available |= 0x01u;
    }

    FIDDLING_HPC_DWT_CPICNT = 0;
    FIDDLING_HPC_DWT_EXCCNT = 0;
    FIDDLING_HPC_DWT_SLEEPCNT = 0;
    FIDDLING_HPC_DWT_LSUCNT = 0;
    FIDDLING_HPC_DWT_FOLDCNT = 0;
    fiddling_hpc_available |= 0x02u;
}

static inline void fiddling_hpc_region_begin(void)
{
    fiddling_hpc_dwt_enable();

    fiddling_hpc_anomaly = 0;
    fiddling_hpc_region_cycles = 0;
    fiddling_hpc_cpi = 0;
    fiddling_hpc_exc = 0;
    fiddling_hpc_lsu = 0;
    fiddling_hpc_fold = 0;
    fiddling_hpc_target_cycles = 0;
    fiddling_hpc_cycles_min = 0xffffffffu;
    fiddling_hpc_cycles_max = 0;
    fiddling_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    fiddling_hpc_region_start = FIDDLING_HPC_DWT_CYCCNT;
}

static inline uint32_t fiddling_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return FIDDLING_HPC_DWT_CYCCNT;
}

static inline uint32_t fiddling_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((fiddling_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = FIDDLING_HPC_DWT_CYCCNT - start;

    fiddling_hpc_cycles_sum += delta;

    if (delta < fiddling_hpc_cycles_min) {
        fiddling_hpc_cycles_min = delta;
    }

    if (delta > fiddling_hpc_cycles_max) {
        fiddling_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void fiddling_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = FIDDLING_HPC_DWT_CYCCNT;
    fiddling_hpc_region_cycles = end - fiddling_hpc_region_start;

    fiddling_hpc_cpi = FIDDLING_HPC_DWT_CPICNT & 0xffu;
    fiddling_hpc_exc = FIDDLING_HPC_DWT_EXCCNT & 0xffu;
    fiddling_hpc_lsu = FIDDLING_HPC_DWT_LSUCNT & 0xffu;
    fiddling_hpc_fold = FIDDLING_HPC_DWT_FOLDCNT & 0xffu;

#if FIDDLING_HPC_TARGET_CYCLES_MIN > 0
    if (fiddling_hpc_target_cycles < (unsigned int)FIDDLING_HPC_TARGET_CYCLES_MIN) {
        fiddling_hpc_anomaly |= FIDDLING_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if FIDDLING_HPC_TARGET_CYCLES_MAX > 0
    if (fiddling_hpc_target_cycles > (unsigned int)FIDDLING_HPC_TARGET_CYCLES_MAX) {
        fiddling_hpc_anomaly |= FIDDLING_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (fiddling_hpc_anomaly != 0u) {
        fiddling_defense_error |= FIDDLING_ERR_HW_COUNTER;
    }
}

#else

static inline void fiddling_hpc_region_begin(void)
{
    fiddling_hpc_anomaly = 0;
    fiddling_hpc_region_cycles = 0;
    fiddling_hpc_target_cycles = 0;
    fiddling_hpc_cycles_min = 0xffffffffu;
    fiddling_hpc_cycles_max = 0;
    fiddling_hpc_cycles_sum = 0;
}

static inline uint32_t fiddling_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t fiddling_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void fiddling_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static inline int32_t fiddling_reduce_q(int64_t x)
{
    int32_t r;

    x %= (int64_t)Q;
    if (x < 0) {
        x += (int64_t)Q;
    }

    r = (int32_t)x;
    return r;
}

static inline int32_t fiddling_mul_mod(int32_t a, int32_t b)
{
    return fiddling_reduce_q((int64_t)a * (int64_t)b);
}

/*
 * A compact NTT-like butterfly:
 *
 *   t = zeta * b
 *   b = a - t
 *   a = a + t
 *
 * The important property is that the twiddle value is consumed as data by an
 * otherwise normal butterfly.
 */
static inline void fiddling_butterfly_unmeasured(int32_t *a,
                                                 int32_t *b,
                                                 int32_t zeta)
{
    int32_t x = *a;
    int32_t y = *b;
    int32_t t = fiddling_mul_mod(zeta, y);

    *a = fiddling_reduce_q((int64_t)x + (int64_t)t);
    *b = fiddling_reduce_q((int64_t)x - (int64_t)t);
}

__attribute__((noinline))
static uint32_t fiddling_butterfly_normal_measured(int32_t *a,
                                                   int32_t *b,
                                                   const int32_t *tw_ptr)
{
    uint32_t start;
    uint32_t delta;
    int32_t zeta;

    __asm volatile("" ::: "memory");
    start = fiddling_hpc_op_begin();

    zeta = *tw_ptr;
    fiddling_butterfly_unmeasured(a, b, zeta);

    __asm volatile("" ::: "memory");
    delta = fiddling_hpc_op_end_common(start);

    fiddling_used_twiddle = zeta;

    return delta;
}

__attribute__((noinline))
static uint32_t fiddling_butterfly_ptr_fault_measured(int32_t *a,
                                                      int32_t *b,
                                                      const int32_t *wrong_ptr)
{
    uint32_t start;
    uint32_t delta;
    int32_t zeta;

    __asm volatile("" ::: "memory");
    start = fiddling_hpc_op_begin();

    /*
     * Pointer-corruption model:
     * the pointer has already been redirected before this primitive consumes it.
     * The butterfly still executes normally using the loaded wrong twiddle.
     */
    zeta = *wrong_ptr;
    fiddling_butterfly_unmeasured(a, b, zeta);

    __asm volatile("" ::: "memory");
    delta = fiddling_hpc_op_end_common(start);

    fiddling_used_twiddle = zeta;
    fiddling_faults_applied++;

    return delta;
}

__attribute__((noinline))
static uint32_t fiddling_butterfly_value_fault_measured(int32_t *a,
                                                        int32_t *b,
                                                        const int32_t *tw_ptr,
                                                        int32_t faulty_value)
{
    uint32_t start;
    uint32_t delta;
    int32_t zeta;

    __asm volatile("" ::: "memory");
    start = fiddling_hpc_op_begin();

    /*
     * Value-corruption model:
     * load the twiddle, then replace the loaded value immediately before the
     * butterfly consumes it.  The butterfly still executes normally.
     */
    zeta = *tw_ptr;
    zeta = faulty_value;
    fiddling_butterfly_unmeasured(a, b, zeta);

    __asm volatile("" ::: "memory");
    delta = fiddling_hpc_op_end_common(start);

    fiddling_used_twiddle = zeta;
    fiddling_faults_applied++;

    return delta;
}

/*
 * Dispatch is outside the measured target primitive.
 */
__attribute__((noinline))
static uint32_t fiddling_target_butterfly_apply(unsigned int model,
                                                int32_t *a,
                                                int32_t *b,
                                                const int32_t *normal_ptr,
                                                const int32_t *wrong_ptr,
                                                int32_t faulty_value)
{
    if (model == FIDDLING_MODEL_PTR) {
        return fiddling_butterfly_ptr_fault_measured(a, b, wrong_ptr);
    }

    if (model == FIDDLING_MODEL_VALUE) {
        return fiddling_butterfly_value_fault_measured(a, b, normal_ptr, faulty_value);
    }

    return fiddling_butterfly_normal_measured(a, b, normal_ptr);
}

static void fiddling_reset_observation_state(void)
{
    fiddling_faults_applied = 0;
    fiddling_entries = 0;
    fiddling_exits = 0;
    fiddling_semantic_valid = 0;
    fiddling_defense_error = 0;

    fiddling_expected_twiddle = 0;
    fiddling_used_twiddle = 0;
    fiddling_target_before_a = 0;
    fiddling_target_before_b = 0;
    fiddling_target_after_a = 0;
    fiddling_target_after_b = 0;
    fiddling_output_digest = 0;
    fiddling_baseline_digest = 0;
    fiddling_output_diff = 0;

    fiddling_hpc_anomaly = 0;
    fiddling_hpc_region_cycles = 0;
    fiddling_hpc_cpi = 0;
    fiddling_hpc_exc = 0;
    fiddling_hpc_lsu = 0;
    fiddling_hpc_fold = 0;
    fiddling_hpc_target_cycles = 0;
    fiddling_hpc_cycles_min = 0xffffffffu;
    fiddling_hpc_cycles_max = 0;
    fiddling_hpc_cycles_sum = 0;
}

static void fiddling_init_data(void)
{
    unsigned int i;

    for (i = 0; i < FIDDLING_NCOEFFS; i++) {
        fiddling_poly[i] = (int32_t)((i * 1229u + 17u) % Q);
        fiddling_poly_baseline[i] = fiddling_poly[i];
    }

    for (i = 0; i < 256u; i++) {
        fiddling_twiddles[i] = (int32_t)((i * 1753u + 1u) % Q);
        fiddling_wrong_twiddles[i] = (int32_t)((i * 0u) % Q);
    }

    fiddling_wrong_twiddles[0] = 0;
    fiddling_zero_twiddle = 0;
}

static uint32_t fiddling_digest_poly(const int32_t *a)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < FIDDLING_NCOEFFS; i++) {
        uint32_t x = (uint32_t)a[i];
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }

    return h;
}

static uint32_t fiddling_run_reference_layer(void)
{
    unsigned int j;
    unsigned int len = FIDDLING_LAYER_LEN;
    unsigned int base = 0;
    unsigned int twidx = fiddling_twiddle_index & 0xffu;
    const int32_t *normal_ptr = &fiddling_twiddles[twidx];

    for (j = 0; j < len; j++) {
        fiddling_butterfly_unmeasured(&fiddling_poly_baseline[base + j],
                                      &fiddling_poly_baseline[base + j + len],
                                      *normal_ptr);
    }

    return fiddling_digest_poly(fiddling_poly_baseline);
}

__attribute__((noinline))
static void fiddling_run_target_layer(void)
{
    unsigned int j;
    unsigned int len = FIDDLING_LAYER_LEN;
    unsigned int base = 0;
    unsigned int target = fiddling_target_j;
    unsigned int twidx = fiddling_twiddle_index & 0xffu;
    unsigned int wrongidx = fiddling_wrong_index & 0xffu;
    const int32_t *normal_ptr = &fiddling_twiddles[twidx];
    const int32_t *wrong_ptr;
    int32_t faulty_value = (int32_t)fiddling_fault_value;
    int32_t target_used_twiddle_snapshot = 0;

    if (target >= len) {
        target = 0;
        fiddling_target_j = 0;
    }

    /*
     * Pointer-corruption model default: redirect to a zero twiddle address.
     * wrong_index selects a wrong table entry; wrong_index=0 is zero.
     */
    if (wrongidx == 0u) {
        wrong_ptr = (const int32_t *)&fiddling_zero_twiddle;
    } else {
        wrong_ptr = &fiddling_wrong_twiddles[wrongidx];
    }

    fiddling_entries++;

    fiddling_expected_twiddle = *normal_ptr;

    fiddling_hpc_region_begin();

    for (j = 0; j < target; j++) {
        (void)fiddling_butterfly_normal_measured(&fiddling_poly[base + j],
                                                 &fiddling_poly[base + j + len],
                                                 normal_ptr);
    }

    fiddling_target_before_a = fiddling_poly[base + target];
    fiddling_target_before_b = fiddling_poly[base + target + len];

    fiddling_hpc_target_cycles =
        fiddling_target_butterfly_apply(fiddling_fault_model,
                                        &fiddling_poly[base + target],
                                        &fiddling_poly[base + target + len],
                                        normal_ptr,
                                        wrong_ptr,
                                        faulty_value);

    /*
     * Preserve the twiddle consumed by the target butterfly.
     *
     * Normal prefix/suffix butterflies also call measured primitives, so their
     * bookkeeping would otherwise overwrite fiddling_used_twiddle.  The H
     * status should report the target butterfly's consumed twiddle, not the
     * last suffix butterfly's twiddle.
     */
    target_used_twiddle_snapshot = fiddling_used_twiddle;

    fiddling_target_after_a = fiddling_poly[base + target];
    fiddling_target_after_b = fiddling_poly[base + target + len];

    for (j = target + 1u; j < len; j++) {
        (void)fiddling_butterfly_normal_measured(&fiddling_poly[base + j],
                                                 &fiddling_poly[base + j + len],
                                                 normal_ptr);
    }

    fiddling_used_twiddle = target_used_twiddle_snapshot;

    fiddling_hpc_region_end();

    fiddling_output_digest = fiddling_digest_poly(fiddling_poly);
    fiddling_baseline_digest = fiddling_run_reference_layer();
    fiddling_output_diff = fiddling_output_digest ^ fiddling_baseline_digest;

    fiddling_semantic_valid = 1;
    fiddling_exits++;
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
    unsigned int target;
    unsigned int twidx;
    unsigned int wrongidx;
    int32_t fval;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > FIDDLING_MODEL_VALUE) {
        model = FIDDLING_MODEL_NONE;
    }

    target = ((unsigned int)buf[1]) | (((unsigned int)buf[2]) << 8);
    if (target >= FIDDLING_LAYER_LEN) {
        target = 0;
    }

    twidx = ((unsigned int)buf[3]) | (((unsigned int)buf[4]) << 8);
    twidx &= 0xffu;

    wrongidx = ((unsigned int)buf[5]) | (((unsigned int)buf[6]) << 8);
    wrongidx &= 0xffu;

    fval = (int32_t)((uint32_t)buf[7] |
                    ((uint32_t)buf[8] << 8) |
                    ((uint32_t)buf[9] << 16) |
                    ((uint32_t)buf[10] << 24));

    fiddling_fault_model = model;
    fiddling_target_j = target;
    fiddling_twiddle_index = twidx;
    fiddling_wrong_index = wrongidx;
    fiddling_fault_value = fval;

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)fiddling_fault_model;
    out[2] = (uint8_t)(fiddling_target_j & 0xffu);
    out[3] = (uint8_t)((fiddling_target_j >> 8) & 0xffu);
    out[4] = (uint8_t)(fiddling_twiddle_index & 0xffu);
    out[5] = (uint8_t)((fiddling_twiddle_index >> 8) & 0xffu);
    out[6] = (uint8_t)(fiddling_wrong_index & 0xffu);
    out[7] = (uint8_t)((fiddling_wrong_index >> 8) & 0xffu);
    put_u32le(out, 8, (unsigned int)fiddling_fault_value);
    put_u32le(out, 12, FIDDLING_LAYER_LEN);
    put_u32le(out, 16, FIDDLING_NCOEFFS);
    put_u32le(out, 20, (unsigned int)Q);

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

    fiddling_reset_observation_state();
    fiddling_init_data();

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

    fiddling_reset_observation_state();
    fiddling_init_data();

    trigger_high();
    fiddling_run_target_layer();
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

    out[0] = (uint8_t)fiddling_fault_model;
    out[1] = (uint8_t)(fiddling_target_j & 0xffu);
    out[2] = (uint8_t)((fiddling_target_j >> 8) & 0xffu);
    out[3] = (uint8_t)fiddling_semantic_valid;

    put_u32le(out, 4, fiddling_faults_applied);
    put_u32le(out, 8, (unsigned int)fiddling_expected_twiddle);
    put_u32le(out, 12, (unsigned int)fiddling_used_twiddle);
    put_u32le(out, 16, fiddling_output_digest);
    put_u32le(out, 20, fiddling_baseline_digest);
    put_u32le(out, 24, fiddling_output_diff);

    out[28] = (uint8_t)fiddling_defense_error;
    out[29] = (uint8_t)fiddling_hpc_anomaly;
    out[30] = (uint8_t)fiddling_entries;
    out[31] = (uint8_t)fiddling_exits;

    simpleserial_put('H', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_target_status(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_target_status(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[32];

    put_u32le(out, 0, (unsigned int)fiddling_target_before_a);
    put_u32le(out, 4, (unsigned int)fiddling_target_before_b);
    put_u32le(out, 8, (unsigned int)fiddling_target_after_a);
    put_u32le(out, 12, (unsigned int)fiddling_target_after_b);
    put_u32le(out, 16, fiddling_twiddle_index);
    put_u32le(out, 20, fiddling_wrong_index);
    put_u32le(out, 24, (unsigned int)fiddling_fault_value);
    put_u32le(out, 28, FIDDLING_LAYER_LEN);

    simpleserial_put('T', sizeof(out), out);
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
        ((fiddling_hpc_cpi & 0xffu) << 0) |
        ((fiddling_hpc_exc & 0xffu) << 8) |
        ((fiddling_hpc_lsu & 0xffu) << 16) |
        ((fiddling_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, fiddling_hpc_available);
    put_u32le(out, 4, fiddling_hpc_anomaly);
    put_u32le(out, 8, fiddling_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, fiddling_hpc_target_cycles);
    put_u32le(out, 20, fiddling_hpc_cycles_min);
    put_u32le(out, 24, fiddling_hpc_cycles_max);
    put_u32le(out, 28, fiddling_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    fiddling_reset_observation_state();
    fiddling_init_data();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('T', 0, cmd_target_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef FIDDLING_BOOT_BANNER
#define FIDDLING_BOOT_BANNER 1
#endif

#if FIDDLING_BOOT_BANNER
    uart_puts("RAVI_FIDDLING_TWIDDLE_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}