#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Krahmer et al., "Correction Fault Attacks on Randomized Dilithium"
 * A-fault variant.
 *
 * Strict materialized-A data-corruption model.
 *
 * This version models:
 *
 *   1. Generate/materialize A normally.
 *   2. Corrupt the selected A entry/block/row/column after materialization.
 *   3. Run the normal signing-time matrix-vector consumption on the possibly
 *      corrupted A.
 *
 * The target signing computation is the matrix-vector consumption.  The
 * simulator-side memory corruption happens before trigger_high() and before
 * DWT/HPC measurement starts.  Therefore the measured target window contains
 * the same normal consumption path in baseline and attack.
 *
 * This version deliberately does NOT replace the A-expansion primitive with a
 * cheaper constant-block generator.  Therefore a block fault should not look
 * artificially cheaper merely because expansion was skipped.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef KRAHMER_A_HPC_TARGET_CYCLES_MIN
#define KRAHMER_A_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef KRAHMER_A_HPC_TARGET_CYCLES_MAX
#define KRAHMER_A_HPC_TARGET_CYCLES_MAX 0
#endif

#define KRAHMER_A_MODEL_NONE      0u
#define KRAHMER_A_MODEL_ELEMENT   1u
#define KRAHMER_A_MODEL_BLOCK     2u
#define KRAHMER_A_MODEL_ROW       3u
#define KRAHMER_A_MODEL_COL       4u

#define KRAHMER_A_ERR_HW_COUNTER 0x40u
#define KRAHMER_A_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define KRAHMER_A_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

static int32_t krahmer_A[K][L][N];
static int32_t krahmer_s[L][N];
static int32_t krahmer_out[K][N];

volatile unsigned int krahmer_a_fault_model = KRAHMER_A_MODEL_NONE;
volatile unsigned int krahmer_a_target_row = 0;
volatile unsigned int krahmer_a_target_col = 0;
volatile unsigned int krahmer_a_target_coeff = 17;
volatile int32_t krahmer_a_fault_value = 0;
volatile unsigned int krahmer_a_message_tweak = 0;

volatile unsigned int krahmer_a_faults_applied = 0;
volatile unsigned int krahmer_a_entries = 0;
volatile unsigned int krahmer_a_exits = 0;
volatile unsigned int krahmer_a_semantic_valid = 0;
volatile unsigned int krahmer_a_defense_error = 0;

volatile int32_t krahmer_a_expected_entry = 0;
volatile int32_t krahmer_a_used_entry = 0;
volatile unsigned int krahmer_a_expected_block_digest = 0;
volatile unsigned int krahmer_a_used_block_digest = 0;

volatile unsigned int krahmer_a_output_digest = 0;
volatile unsigned int krahmer_a_reference_digest = 0;
volatile unsigned int krahmer_a_output_diff = 0;

volatile unsigned int krahmer_a_hpc_available = 0;
volatile unsigned int krahmer_a_hpc_anomaly = 0;
volatile unsigned int krahmer_a_hpc_region_cycles = 0;
volatile unsigned int krahmer_a_hpc_cpi = 0;
volatile unsigned int krahmer_a_hpc_exc = 0;
volatile unsigned int krahmer_a_hpc_lsu = 0;
volatile unsigned int krahmer_a_hpc_fold = 0;
volatile unsigned int krahmer_a_hpc_target_cycles = 0;
volatile unsigned int krahmer_a_hpc_cycles_min = 0xffffffffu;
volatile unsigned int krahmer_a_hpc_cycles_max = 0;
volatile unsigned int krahmer_a_hpc_cycles_sum = 0;

#if HPC_HW_ENABLE

#define KRAHMER_A_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define KRAHMER_A_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define KRAHMER_A_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define KRAHMER_A_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define KRAHMER_A_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define KRAHMER_A_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define KRAHMER_A_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define KRAHMER_A_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define KRAHMER_A_HPC_DEMCR_TRCENA          (1u << 24)
#define KRAHMER_A_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define KRAHMER_A_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t krahmer_a_hpc_region_start = 0;

static inline void krahmer_a_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    KRAHMER_A_HPC_DEMCR |= KRAHMER_A_HPC_DEMCR_TRCENA;
    ctrl = KRAHMER_A_HPC_DWT_CTRL;

    if ((ctrl & KRAHMER_A_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        KRAHMER_A_HPC_DWT_CTRL |= KRAHMER_A_HPC_DWT_CTRL_CYCCNTENA;
        krahmer_a_hpc_available |= 0x01u;
    }

    KRAHMER_A_HPC_DWT_CPICNT = 0;
    KRAHMER_A_HPC_DWT_EXCCNT = 0;
    KRAHMER_A_HPC_DWT_SLEEPCNT = 0;
    KRAHMER_A_HPC_DWT_LSUCNT = 0;
    KRAHMER_A_HPC_DWT_FOLDCNT = 0;
    krahmer_a_hpc_available |= 0x02u;
}

static inline void krahmer_a_hpc_region_begin(void)
{
    krahmer_a_hpc_dwt_enable();

    krahmer_a_hpc_anomaly = 0;
    krahmer_a_hpc_region_cycles = 0;
    krahmer_a_hpc_cpi = 0;
    krahmer_a_hpc_exc = 0;
    krahmer_a_hpc_lsu = 0;
    krahmer_a_hpc_fold = 0;
    krahmer_a_hpc_target_cycles = 0;
    krahmer_a_hpc_cycles_min = 0xffffffffu;
    krahmer_a_hpc_cycles_max = 0;
    krahmer_a_hpc_cycles_sum = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    krahmer_a_hpc_region_start = KRAHMER_A_HPC_DWT_CYCCNT;
}

static inline uint32_t krahmer_a_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return KRAHMER_A_HPC_DWT_CYCCNT;
}

static inline uint32_t krahmer_a_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;

    if ((krahmer_a_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = KRAHMER_A_HPC_DWT_CYCCNT - start;

    krahmer_a_hpc_cycles_sum += delta;

    if (delta < krahmer_a_hpc_cycles_min) {
        krahmer_a_hpc_cycles_min = delta;
    }

    if (delta > krahmer_a_hpc_cycles_max) {
        krahmer_a_hpc_cycles_max = delta;
    }

    return delta;
}

static inline void krahmer_a_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = KRAHMER_A_HPC_DWT_CYCCNT;
    krahmer_a_hpc_region_cycles = end - krahmer_a_hpc_region_start;

    krahmer_a_hpc_cpi = KRAHMER_A_HPC_DWT_CPICNT & 0xffu;
    krahmer_a_hpc_exc = KRAHMER_A_HPC_DWT_EXCCNT & 0xffu;
    krahmer_a_hpc_lsu = KRAHMER_A_HPC_DWT_LSUCNT & 0xffu;
    krahmer_a_hpc_fold = KRAHMER_A_HPC_DWT_FOLDCNT & 0xffu;

#if KRAHMER_A_HPC_TARGET_CYCLES_MIN > 0
    if (krahmer_a_hpc_target_cycles < (unsigned int)KRAHMER_A_HPC_TARGET_CYCLES_MIN) {
        krahmer_a_hpc_anomaly |= KRAHMER_A_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if KRAHMER_A_HPC_TARGET_CYCLES_MAX > 0
    if (krahmer_a_hpc_target_cycles > (unsigned int)KRAHMER_A_HPC_TARGET_CYCLES_MAX) {
        krahmer_a_hpc_anomaly |= KRAHMER_A_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (krahmer_a_hpc_anomaly != 0u) {
        krahmer_a_defense_error |= KRAHMER_A_ERR_HW_COUNTER;
    }
}

#else

static inline void krahmer_a_hpc_region_begin(void)
{
    krahmer_a_hpc_anomaly = 0;
    krahmer_a_hpc_region_cycles = 0;
    krahmer_a_hpc_target_cycles = 0;
    krahmer_a_hpc_cycles_min = 0xffffffffu;
    krahmer_a_hpc_cycles_max = 0;
    krahmer_a_hpc_cycles_sum = 0;
}

static inline uint32_t krahmer_a_hpc_op_begin(void)
{
    return 0;
}

static inline uint32_t krahmer_a_hpc_op_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void krahmer_a_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

/*
 * Reference-Dilithium-style lightweight reduction helpers.
 * Avoid C "% Q" so the experiment does not accidentally benchmark heavy modulo.
 */
static inline int32_t krahmer_a_reduce32_refstyle(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * (int32_t)Q;

    return t;
}

static inline int32_t krahmer_a_caddq_refstyle(int32_t a)
{
    a += (a >> 31) & (int32_t)Q;
    return a;
}

static inline int32_t krahmer_a_freeze_refstyle(int32_t a)
{
    a = krahmer_a_reduce32_refstyle(a);
    a = krahmer_a_caddq_refstyle(a);
    return a;
}

static uint32_t krahmer_a_xorshift32(uint32_t x)
{
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

static int32_t krahmer_a_expand_coeff(unsigned int row,
                                      unsigned int col,
                                      unsigned int coeff)
{
    uint32_t x;

    /*
     * Deterministic SRAM-safe stand-in for A expansion.
     * This models the data object A without the SHAKE stack/SRAM cost.
     */
    x = 0x6a09e667u;
    x ^= (row + 1u) * 0x9e3779b9u;
    x ^= (col + 1u) * 0x85ebca6bu;
    x ^= (coeff + 1u) * 0xc2b2ae35u;
    x ^= krahmer_a_message_tweak * 0x27d4eb2du;
    x = krahmer_a_xorshift32(x);

    return krahmer_a_freeze_refstyle((int32_t)(x & 0x007fffffu));
}

static uint32_t krahmer_a_digest_block(const int32_t *block)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < N; i++) {
        uint32_t x = (uint32_t)block[i];
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }

    return h;
}

static uint32_t krahmer_a_digest_normal_block(unsigned int row,
                                              unsigned int col)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (i = 0; i < N; i++) {
        uint32_t x = (uint32_t)krahmer_a_expand_coeff(row, col, i);
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }

    return h;
}

static void krahmer_a_generate_matrix_materialized_normal(void)
{
    unsigned int r;
    unsigned int c;
    unsigned int i;

    for (r = 0; r < K; r++) {
        for (c = 0; c < L; c++) {
            for (i = 0; i < N; i++) {
                krahmer_A[r][c][i] = krahmer_a_expand_coeff(r, c, i);
            }
        }
    }
}

static void krahmer_a_init_vectors(void)
{
    unsigned int j;
    unsigned int i;

    for (j = 0; j < L; j++) {
        for (i = 0; i < N; i++) {
            int32_t v = (int32_t)(((j + 1u) * 3u + i + krahmer_a_message_tweak) & 3u);
            krahmer_s[j][i] = v - 1;
        }
    }

    memset(krahmer_A, 0, sizeof(krahmer_A));
    memset(krahmer_out, 0, sizeof(krahmer_out));
}

static void krahmer_a_reset_observation_state(void)
{
    krahmer_a_faults_applied = 0;
    krahmer_a_entries = 0;
    krahmer_a_exits = 0;
    krahmer_a_semantic_valid = 0;
    krahmer_a_defense_error = 0;

    krahmer_a_expected_entry = 0;
    krahmer_a_used_entry = 0;
    krahmer_a_expected_block_digest = 0;
    krahmer_a_used_block_digest = 0;

    krahmer_a_output_digest = 0;
    krahmer_a_reference_digest = 0;
    krahmer_a_output_diff = 0;

    krahmer_a_hpc_anomaly = 0;
    krahmer_a_hpc_region_cycles = 0;
    krahmer_a_hpc_cpi = 0;
    krahmer_a_hpc_exc = 0;
    krahmer_a_hpc_lsu = 0;
    krahmer_a_hpc_fold = 0;
    krahmer_a_hpc_target_cycles = 0;
    krahmer_a_hpc_cycles_min = 0xffffffffu;
    krahmer_a_hpc_cycles_max = 0;
    krahmer_a_hpc_cycles_sum = 0;
}

static uint32_t krahmer_a_digest_output(const int32_t out[K][N])
{
    unsigned int r;
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (r = 0; r < K; r++) {
        for (i = 0; i < N; i++) {
            uint32_t x = (uint32_t)out[r][i];
            h ^= x;
            h *= 0x01000193u;
            h ^= x >> 16;
            h *= 0x01000193u;
        }
    }

    return h;
}

/*
 * Normal signing-time consumption of A.
 * The same function is used in baseline and attack.
 */
__attribute__((noinline))
static void krahmer_a_consume_matrix_normal(void)
{
    unsigned int r;
    unsigned int c;
    unsigned int i;

    for (r = 0; r < K; r++) {
        for (i = 0; i < N; i++) {
            int32_t acc = 0;
            for (c = 0; c < L; c++) {
                acc += krahmer_A[r][c][i] * krahmer_s[c][i];
            }
            krahmer_out[r][i] = krahmer_a_freeze_refstyle(acc);
        }
    }

    krahmer_a_output_digest = krahmer_a_digest_output(krahmer_out);
}

static uint32_t krahmer_a_compute_reference_digest(void)
{
    unsigned int r;
    unsigned int c;
    unsigned int i;
    uint32_t h = 0x811c9dc5u;

    for (r = 0; r < K; r++) {
        for (i = 0; i < N; i++) {
            int32_t acc = 0;
            for (c = 0; c < L; c++) {
                int32_t a = krahmer_a_expand_coeff(r, c, i);
                acc += a * krahmer_s[c][i];
            }
            {
                uint32_t x = (uint32_t)krahmer_a_freeze_refstyle(acc);
                h ^= x;
                h *= 0x01000193u;
                h ^= x >> 16;
                h *= 0x01000193u;
            }
        }
    }

    return h;
}

/*
 * Simulator-side materialized-A corruption.
 *
 * This function is intentionally called before trigger_high() and before DWT
 * measurement starts.  It models an external memory/data corruption fault in
 * materialized A, not a cheaper algorithmic replacement for A expansion.
 */
static void krahmer_a_corrupt_materialized_A_unmeasured(void)
{
    unsigned int r;
    unsigned int c;
    unsigned int i;
    unsigned int row = krahmer_a_target_row;
    unsigned int col = krahmer_a_target_col;
    unsigned int coeff = krahmer_a_target_coeff;
    int32_t fv = krahmer_a_fault_value;

    if (row >= K) {
        row = 0;
        krahmer_a_target_row = 0;
    }

    if (col >= L) {
        col = 0;
        krahmer_a_target_col = 0;
    }

    if (coeff >= N) {
        coeff = 0;
        krahmer_a_target_coeff = 0;
    }

    if (krahmer_a_fault_model == KRAHMER_A_MODEL_ELEMENT) {
        krahmer_A[row][col][coeff] = fv;
        krahmer_a_faults_applied = 1;
    } else if (krahmer_a_fault_model == KRAHMER_A_MODEL_BLOCK) {
        for (i = 0; i < N; i++) {
            krahmer_A[row][col][i] = fv;
        }
        krahmer_a_faults_applied = 1;
    } else if (krahmer_a_fault_model == KRAHMER_A_MODEL_ROW) {
        for (c = 0; c < L; c++) {
            for (i = 0; i < N; i++) {
                krahmer_A[row][c][i] = fv;
            }
        }
        krahmer_a_faults_applied = L;
    } else if (krahmer_a_fault_model == KRAHMER_A_MODEL_COL) {
        for (r = 0; r < K; r++) {
            for (i = 0; i < N; i++) {
                krahmer_A[r][col][i] = fv;
            }
        }
        krahmer_a_faults_applied = K;
    }
}

__attribute__((noinline))
static void krahmer_a_run_materialized_A_experiment(void)
{
    uint32_t start;
    unsigned int row = krahmer_a_target_row;
    unsigned int col = krahmer_a_target_col;
    unsigned int coeff = krahmer_a_target_coeff;

    if (row >= K) {
        row = 0;
        krahmer_a_target_row = 0;
    }

    if (col >= L) {
        col = 0;
        krahmer_a_target_col = 0;
    }

    if (coeff >= N) {
        coeff = 0;
        krahmer_a_target_coeff = 0;
    }

    krahmer_a_entries++;

    /*
     * Step 1: materialize A normally.
     */
    krahmer_a_generate_matrix_materialized_normal();

    krahmer_a_expected_entry = krahmer_A[row][col][coeff];
    krahmer_a_expected_block_digest = krahmer_a_digest_normal_block(row, col);
    krahmer_a_reference_digest = krahmer_a_compute_reference_digest();

    /*
     * Step 2: corrupt materialized A before the measured signing computation.
     */
    krahmer_a_corrupt_materialized_A_unmeasured();

    krahmer_a_used_entry = krahmer_A[row][col][coeff];
    krahmer_a_used_block_digest = krahmer_a_digest_block(krahmer_A[row][col]);

    /*
     * Step 3: normal signing-time consumption of the possibly faulty A.
     *
     * This is the only target window for both the external ChipWhisperer
     * trigger and DWT/HPC measurement.  A materialization and simulator-side
     * corruption have already happened before trigger_high().
     */
    trigger_high();
    krahmer_a_hpc_region_begin();
    start = krahmer_a_hpc_op_begin();

    krahmer_a_consume_matrix_normal();

    krahmer_a_hpc_target_cycles = krahmer_a_hpc_op_end_common(start);
    krahmer_a_hpc_region_end();
    trigger_low();

    krahmer_a_output_diff = krahmer_a_output_digest ^ krahmer_a_reference_digest;

    krahmer_a_semantic_valid = 1;
    krahmer_a_exits++;
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
    unsigned int row;
    unsigned int col;
    unsigned int coeff;
    int32_t fval;
    unsigned int tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > KRAHMER_A_MODEL_COL) {
        model = KRAHMER_A_MODEL_NONE;
    }

    row = (unsigned int)buf[1];
    col = (unsigned int)buf[2];

    if (row >= K) {
        row = 0;
    }

    if (col >= L) {
        col = 0;
    }

    coeff = ((unsigned int)buf[3]) | (((unsigned int)buf[4]) << 8);
    if (coeff >= N) {
        coeff = 0;
    }

    fval = (int32_t)((uint32_t)buf[5] |
                     ((uint32_t)buf[6] << 8) |
                     ((uint32_t)buf[7] << 16) |
                     ((uint32_t)buf[8] << 24));

    tweak = (unsigned int)buf[9] |
            (((unsigned int)buf[10]) << 8) |
            (((unsigned int)buf[11]) << 16) |
            (((unsigned int)buf[12]) << 24);

    krahmer_a_fault_model = model;
    krahmer_a_target_row = row;
    krahmer_a_target_col = col;
    krahmer_a_target_coeff = coeff;
    krahmer_a_fault_value = fval;
    krahmer_a_message_tweak = tweak;

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)krahmer_a_fault_model;
    out[2] = (uint8_t)krahmer_a_target_row;
    out[3] = (uint8_t)krahmer_a_target_col;
    out[4] = (uint8_t)(krahmer_a_target_coeff & 0xffu);
    out[5] = (uint8_t)((krahmer_a_target_coeff >> 8) & 0xffu);
    put_u32le(out, 6, (unsigned int)krahmer_a_fault_value);
    put_u32le(out, 10, krahmer_a_message_tweak);
    out[14] = (uint8_t)K;
    out[15] = (uint8_t)L;
    put_u32le(out, 16, N);
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

    krahmer_a_reset_observation_state();
    krahmer_a_init_vectors();

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

    krahmer_a_reset_observation_state();
    krahmer_a_init_vectors();

    krahmer_a_run_materialized_A_experiment();

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

    out[0] = (uint8_t)krahmer_a_fault_model;
    out[1] = (uint8_t)krahmer_a_target_row;
    out[2] = (uint8_t)krahmer_a_target_col;
    out[3] = (uint8_t)krahmer_a_semantic_valid;

    put_u32le(out, 4, krahmer_a_faults_applied);
    put_u32le(out, 8, krahmer_a_target_coeff);
    put_u32le(out, 12, (unsigned int)krahmer_a_expected_entry);
    put_u32le(out, 16, (unsigned int)krahmer_a_used_entry);
    put_u32le(out, 20, krahmer_a_expected_block_digest);
    put_u32le(out, 24, krahmer_a_used_block_digest);

    out[28] = (uint8_t)krahmer_a_defense_error;
    out[29] = (uint8_t)krahmer_a_hpc_anomaly;
    out[30] = (uint8_t)krahmer_a_entries;
    out[31] = (uint8_t)krahmer_a_exits;

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

    put_u32le(out, 0, krahmer_a_output_digest);
    put_u32le(out, 4, krahmer_a_reference_digest);
    put_u32le(out, 8, krahmer_a_output_diff);
    put_u32le(out, 12, krahmer_a_message_tweak);

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
        ((krahmer_a_hpc_cpi & 0xffu) << 0) |
        ((krahmer_a_hpc_exc & 0xffu) << 8) |
        ((krahmer_a_hpc_lsu & 0xffu) << 16) |
        ((krahmer_a_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0, krahmer_a_hpc_available);
    put_u32le(out, 4, krahmer_a_hpc_anomaly);
    put_u32le(out, 8, krahmer_a_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, krahmer_a_hpc_target_cycles);
    put_u32le(out, 20, krahmer_a_hpc_cycles_min);
    put_u32le(out, 24, krahmer_a_hpc_cycles_max);
    put_u32le(out, 28, krahmer_a_hpc_cycles_sum);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    krahmer_a_reset_observation_state();
    krahmer_a_init_vectors();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef KRAHMER_A_BOOT_BANNER
#define KRAHMER_A_BOOT_BANNER 1
#endif

#if KRAHMER_A_BOOT_BANNER
    uart_puts("KRAHMER_A_MATERIALIZED_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
