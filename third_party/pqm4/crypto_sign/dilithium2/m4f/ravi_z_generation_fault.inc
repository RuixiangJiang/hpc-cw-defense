#ifndef RAVI_Z_GENERATION_FAULT_INC
#define RAVI_Z_GENERATION_FAULT_INC

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*
 * Ravi et al., "Exploiting Determinism in Lattice-based Signatures"
 *
 * This include file replaces only the final z-generation addition:
 *
 *     z = c*s1 + y
 *
 * At the hook point in sign.c, z already contains the c*s1 contribution
 * produced by polyvecl_small_basemul_invntt(...). The normal primitive
 * therefore stores:
 *
 *     z[v][i] = z[v][i] + y[v][i]
 *
 * The source-level fault simulation modifies exactly one target coefficient.
 *
 * Important implementation rule:
 *
 *   Do not put fault-kind selection inside the measured coefficient window.
 *
 * The target coefficient dispatch chooses one noinline fault primitive before
 * entering the measured window. Therefore the measured target window contains
 * only the semantic primitive, not a switch/case used by the simulator.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef RAVI_HPC_TARGET_COEFF_CYCLES_MIN
#define RAVI_HPC_TARGET_COEFF_CYCLES_MIN 0
#endif

#ifndef RAVI_HPC_TARGET_COEFF_CYCLES_MAX
#define RAVI_HPC_TARGET_COEFF_CYCLES_MAX 0
#endif

#define RAVI_Z_FAULT_NONE       0u
#define RAVI_Z_FAULT_SKIP_Y     1u
#define RAVI_Z_FAULT_SKIP_CS1   2u
#define RAVI_Z_FAULT_SKIP_STORE 3u

#define RAVI_Z_ERR_HW_COUNTER   0x40u

#define RAVI_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define RAVI_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

/* Runtime fault configuration. Set through SimpleSerial command F. */
volatile unsigned int ravi_z_fault_enable = 0;
volatile unsigned int ravi_z_fault_kind = RAVI_Z_FAULT_NONE;
volatile unsigned int ravi_z_fault_target_vec = 0;
volatile unsigned int ravi_z_fault_target_coeff = 0;
volatile unsigned int ravi_z_fault_skips = 0;

/* Region/status counters. */
volatile unsigned int ravi_z_generation_entries = 0;
volatile unsigned int ravi_z_generation_exits = 0;
volatile unsigned int ravi_z_defense_error = 0;
volatile unsigned int ravi_z_dup_mismatches = 0;

/* DWT/HPC counters exposed through SimpleSerial Y. */
volatile unsigned int ravi_hpc_available = 0;
volatile unsigned int ravi_hpc_anomaly = 0;
volatile unsigned int ravi_hpc_z_region_cycles = 0;
volatile unsigned int ravi_hpc_z_cpi = 0;
volatile unsigned int ravi_hpc_z_exc = 0;
volatile unsigned int ravi_hpc_z_lsu = 0;
volatile unsigned int ravi_hpc_z_fold = 0;
volatile unsigned int ravi_hpc_coeff_cycles_sum = 0;
volatile unsigned int ravi_hpc_coeff_cycles_min = 0xffffffffu;
volatile unsigned int ravi_hpc_coeff_cycles_max = 0;
volatile unsigned int ravi_hpc_target_coeff_cycles = 0;
volatile unsigned int ravi_hpc_target_vec = 0;
volatile unsigned int ravi_hpc_target_coeff = 0;

#if HPC_HW_ENABLE

#define RAVI_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define RAVI_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define RAVI_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define RAVI_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define RAVI_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define RAVI_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define RAVI_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define RAVI_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define RAVI_HPC_DEMCR_TRCENA          (1u << 24)
#define RAVI_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define RAVI_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t ravi_hpc_z_region_start = 0;

static inline void ravi_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    RAVI_HPC_DEMCR |= RAVI_HPC_DEMCR_TRCENA;
    ctrl = RAVI_HPC_DWT_CTRL;

    if ((ctrl & RAVI_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        RAVI_HPC_DWT_CTRL |= RAVI_HPC_DWT_CTRL_CYCCNTENA;
        ravi_hpc_available |= 0x01u;
    }

    RAVI_HPC_DWT_CPICNT = 0;
    RAVI_HPC_DWT_EXCCNT = 0;
    RAVI_HPC_DWT_SLEEPCNT = 0;
    RAVI_HPC_DWT_LSUCNT = 0;
    RAVI_HPC_DWT_FOLDCNT = 0;
    ravi_hpc_available |= 0x02u;
}

static inline void ravi_hpc_region_begin(void)
{
    ravi_hpc_dwt_enable();

    ravi_hpc_anomaly = 0;
    ravi_hpc_z_region_cycles = 0;
    ravi_hpc_z_cpi = 0;
    ravi_hpc_z_exc = 0;
    ravi_hpc_z_lsu = 0;
    ravi_hpc_z_fold = 0;
    ravi_hpc_coeff_cycles_sum = 0;
    ravi_hpc_coeff_cycles_min = 0xffffffffu;
    ravi_hpc_coeff_cycles_max = 0;
    ravi_hpc_target_coeff_cycles = 0;
    ravi_hpc_target_vec = ravi_z_fault_target_vec;
    ravi_hpc_target_coeff = ravi_z_fault_target_coeff;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    ravi_hpc_z_region_start = RAVI_HPC_DWT_CYCCNT;
}

static inline uint32_t ravi_hpc_coeff_begin(void)
{
    __asm volatile("" ::: "memory");
    return RAVI_HPC_DWT_CYCCNT;
}

static inline uint32_t ravi_hpc_coeff_end_common(uint32_t start)
{
    uint32_t delta;

    if ((ravi_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = RAVI_HPC_DWT_CYCCNT - start;

    ravi_hpc_coeff_cycles_sum += delta;

    if (delta < ravi_hpc_coeff_cycles_min) {
        ravi_hpc_coeff_cycles_min = delta;
    }

    if (delta > ravi_hpc_coeff_cycles_max) {
        ravi_hpc_coeff_cycles_max = delta;
    }

    return delta;
}

static inline void ravi_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = RAVI_HPC_DWT_CYCCNT;
    ravi_hpc_z_region_cycles = end - ravi_hpc_z_region_start;

    ravi_hpc_z_cpi = RAVI_HPC_DWT_CPICNT & 0xffu;
    ravi_hpc_z_exc = RAVI_HPC_DWT_EXCCNT & 0xffu;
    ravi_hpc_z_lsu = RAVI_HPC_DWT_LSUCNT & 0xffu;
    ravi_hpc_z_fold = RAVI_HPC_DWT_FOLDCNT & 0xffu;

#if RAVI_HPC_TARGET_COEFF_CYCLES_MIN > 0
    if (ravi_hpc_target_coeff_cycles < (unsigned int)RAVI_HPC_TARGET_COEFF_CYCLES_MIN) {
        ravi_hpc_anomaly |= RAVI_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if RAVI_HPC_TARGET_COEFF_CYCLES_MAX > 0
    if (ravi_hpc_target_coeff_cycles > (unsigned int)RAVI_HPC_TARGET_COEFF_CYCLES_MAX) {
        ravi_hpc_anomaly |= RAVI_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (ravi_hpc_anomaly != 0u) {
        ravi_z_defense_error |= RAVI_Z_ERR_HW_COUNTER;
    }
}

#else

static inline void ravi_hpc_region_begin(void)
{
    ravi_hpc_anomaly = 0;
    ravi_hpc_z_region_cycles = 0;
    ravi_hpc_coeff_cycles_sum = 0;
    ravi_hpc_coeff_cycles_min = 0xffffffffu;
    ravi_hpc_coeff_cycles_max = 0;
    ravi_hpc_target_coeff_cycles = 0;
    ravi_hpc_target_vec = ravi_z_fault_target_vec;
    ravi_hpc_target_coeff = ravi_z_fault_target_coeff;
}

static inline uint32_t ravi_hpc_coeff_begin(void)
{
    return 0;
}

static inline uint32_t ravi_hpc_coeff_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void ravi_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

static inline unsigned int ravi_z_total_coeffs(void)
{
    return (unsigned int)(L * N);
}

static inline unsigned int ravi_z_flat_index(unsigned int vec, unsigned int coeff)
{
    return vec * (unsigned int)N + coeff;
}

static inline unsigned int ravi_z_vec_from_flat(unsigned int flat)
{
    return flat / (unsigned int)N;
}

static inline unsigned int ravi_z_coeff_from_flat(unsigned int flat)
{
    return flat - ravi_z_vec_from_flat(flat) * (unsigned int)N;
}

/*
 * Normal semantic primitive:
 *
 *     z[v][c] = cs1[v][c] + y[v][c]
 *
 * At this point z[v][c] contains cs1[v][c].
 */
__attribute__((noinline))
static uint32_t ravi_z_one_normal_measured(polyvecl *z,
                                           const polyvecl *y,
                                           unsigned int flat)
{
    unsigned int v = ravi_z_vec_from_flat(flat);
    unsigned int c = ravi_z_coeff_from_flat(flat);
    int32_t cs1_value;
    int32_t y_value;
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = ravi_hpc_coeff_begin();

    cs1_value = z->vec[v].coeffs[c];
    y_value = y->vec[v].coeffs[c];
    z->vec[v].coeffs[c] = cs1_value + y_value;

    __asm volatile("" ::: "memory");
    delta = ravi_hpc_coeff_end_common(start);

    return delta;
}

/*
 * Fault kind 1: skip-y.
 *
 * Semantics:
 *     released z coefficient contains only c*s1.
 *
 * Because z already contains c*s1 at the hook point, writing cs1_value back is
 * sufficient and keeps the primitive separate from skip-store. The volatile
 * pointer prevents the compiler from deleting the same-value store.
 */
__attribute__((noinline))
static uint32_t ravi_z_one_fault_skip_y_measured(polyvecl *z,
                                                 const polyvecl *y,
                                                 unsigned int flat)
{
    unsigned int v = ravi_z_vec_from_flat(flat);
    unsigned int c = ravi_z_coeff_from_flat(flat);
    volatile int32_t *z_coeff = (volatile int32_t *)&z->vec[v].coeffs[c];
    int32_t cs1_value;
    uint32_t start;
    uint32_t delta;

    (void)y;

    __asm volatile("" ::: "memory");
    start = ravi_hpc_coeff_begin();

    cs1_value = *z_coeff;
    *z_coeff = cs1_value;

    __asm volatile("" ::: "memory");
    delta = ravi_hpc_coeff_end_common(start);

    ravi_z_fault_skips++;

    return delta;
}

/*
 * Fault kind 2: skip-cs1.
 *
 * Semantics:
 *     released z coefficient contains only y.
 */
__attribute__((noinline))
static uint32_t ravi_z_one_fault_skip_cs1_measured(polyvecl *z,
                                                   const polyvecl *y,
                                                   unsigned int flat)
{
    unsigned int v = ravi_z_vec_from_flat(flat);
    unsigned int c = ravi_z_coeff_from_flat(flat);
    int32_t y_value;
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = ravi_hpc_coeff_begin();

    y_value = y->vec[v].coeffs[c];
    z->vec[v].coeffs[c] = y_value;

    __asm volatile("" ::: "memory");
    delta = ravi_hpc_coeff_end_common(start);

    ravi_z_fault_skips++;

    return delta;
}

/*
 * Fault kind 3: skip-store.
 *
 * Semantics:
 *     target coefficient of z remains unchanged from its previous value.
 *
 * The arithmetic result is kept alive in a register using an inline-assembly
 * input operand, but the result is not stored back to z.
 */
__attribute__((noinline))
static uint32_t ravi_z_one_fault_skip_store_measured(polyvecl *z,
                                                     const polyvecl *y,
                                                     unsigned int flat)
{
    unsigned int v = ravi_z_vec_from_flat(flat);
    unsigned int c = ravi_z_coeff_from_flat(flat);
    int32_t cs1_value;
    int32_t y_value;
    int32_t tmp;
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = ravi_hpc_coeff_begin();

    cs1_value = z->vec[v].coeffs[c];
    y_value = y->vec[v].coeffs[c];
    tmp = cs1_value + y_value;

    /*
     * Keep the local computation alive, but intentionally skip the store to
     * z->vec[v].coeffs[c].
     */
    __asm volatile("" : : "r"(tmp) : "memory");

    delta = ravi_hpc_coeff_end_common(start);

    ravi_z_fault_skips++;

    return delta;
}

/*
 * The fault-kind dispatch happens here, outside the measured primitive window.
 */
__attribute__((noinline))
static uint32_t ravi_z_one_target_measured(polyvecl *z,
                                           const polyvecl *y,
                                           unsigned int target_flat)
{
    if ((ravi_z_fault_enable == 0u) ||
        (ravi_z_fault_kind == RAVI_Z_FAULT_NONE)) {
        return ravi_z_one_normal_measured(z, y, target_flat);
    }

    if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_Y) {
        return ravi_z_one_fault_skip_y_measured(z, y, target_flat);
    }

    if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_CS1) {
        return ravi_z_one_fault_skip_cs1_measured(z, y, target_flat);
    }

    if (ravi_z_fault_kind == RAVI_Z_FAULT_SKIP_STORE) {
        return ravi_z_one_fault_skip_store_measured(z, y, target_flat);
    }

    return ravi_z_one_normal_measured(z, y, target_flat);
}

/*
 * Replacement for:
 *
 *     polyvecl_add(&z, &z, &y);
 *
 * At entry:
 *     z = c*s1
 *     y = signing mask vector
 *
 * At exit:
 *     z = c*s1 + y, except for the selected target coefficient when
 *     ravi_z_fault_enable != 0.
 */
__attribute__((noinline))
static void ravi_z_generation_apply(polyvecl *z, const polyvecl *y)
{
    unsigned int flat;
    unsigned int target_flat;
    unsigned int total = ravi_z_total_coeffs();

    ravi_z_generation_entries++;

    target_flat = ravi_z_flat_index(ravi_z_fault_target_vec,
                                    ravi_z_fault_target_coeff);

    ravi_hpc_region_begin();

    if (target_flat < total) {
        for (flat = 0; flat < target_flat; flat++) {
            (void)ravi_z_one_normal_measured(z, y, flat);
        }

        ravi_hpc_target_coeff_cycles =
            ravi_z_one_target_measured(z, y, target_flat);

        for (flat = target_flat + 1u; flat < total; flat++) {
            (void)ravi_z_one_normal_measured(z, y, flat);
        }
    } else {
        for (flat = 0; flat < total; flat++) {
            (void)ravi_z_one_normal_measured(z, y, flat);
        }
    }

    ravi_hpc_region_end();
    ravi_z_generation_exits++;
}

#endif /* RAVI_Z_GENERATION_FAULT_INC */
