#ifndef XAGAWA_FAILURE_HANDLING_FAULT_INC
#define XAGAWA_FAILURE_HANDLING_FAULT_INC

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "verify.h"

/*
 * Xagawa et al., "Fault-Injection Attacks against NIST's PQC Round 3
 * KEM Candidates"
 *
 * Semantic target:
 *
 *   Kyber decapsulation computes:
 *
 *     indcpa_dec(...)
 *     hash_g(...)
 *     fail = indcpa_enc_cmp(...)
 *     hash_h(...)
 *     cmov(kr, fallback_z, KYBER_SYMBYTES, fail)
 *     kdf(ss, kr, ...)
 *
 * On verification failure, cmov overwrites the pre-key with the secret
 * fallback z. The simulated fault skips this final failure-handling cmov.
 *
 * Correct simulation rule:
 *
 *   - ciphertext verification still executes normally;
 *   - good-key derivation still executes normally;
 *   - fallback material is still available in the secret key;
 *   - hash_h and kdf still execute normally;
 *   - only the final conditional move / fallback overwrite is absent.
 *
 * Measurement rule:
 *
 *   The measured target window is only the failure-handling cmov primitive.
 *   The attack selection branch is outside the measured primitive. Therefore
 *   there is no "if attack then skip cmov" statement inside the target window.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN
#define XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN 0
#endif

#ifndef XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX
#define XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX 0
#endif

#define XAGAWA_ERR_HW_COUNTER 0x40u

#define XAGAWA_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define XAGAWA_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

volatile unsigned int xagawa_fault_enable = 0;
volatile unsigned int xagawa_fault_skips = 0;
volatile unsigned int xagawa_last_fail = 0;
volatile unsigned int xagawa_cmov_entries = 0;
volatile unsigned int xagawa_cmov_exits = 0;
volatile unsigned int xagawa_defense_error = 0;

volatile unsigned int xagawa_hpc_available = 0;
volatile unsigned int xagawa_hpc_anomaly = 0;
volatile unsigned int xagawa_hpc_cmov_region_cycles = 0;
volatile unsigned int xagawa_hpc_cpi = 0;
volatile unsigned int xagawa_hpc_exc = 0;
volatile unsigned int xagawa_hpc_lsu = 0;
volatile unsigned int xagawa_hpc_fold = 0;
volatile unsigned int xagawa_hpc_cmov_cycles_sum = 0;
volatile unsigned int xagawa_hpc_cmov_cycles_min = 0xffffffffu;
volatile unsigned int xagawa_hpc_cmov_cycles_max = 0;
volatile unsigned int xagawa_hpc_target_cmov_cycles = 0;

#if HPC_HW_ENABLE

#define XAGAWA_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define XAGAWA_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define XAGAWA_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define XAGAWA_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define XAGAWA_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define XAGAWA_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define XAGAWA_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define XAGAWA_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define XAGAWA_HPC_DEMCR_TRCENA          (1u << 24)
#define XAGAWA_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define XAGAWA_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t xagawa_hpc_region_start = 0;

static inline void xagawa_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    XAGAWA_HPC_DEMCR |= XAGAWA_HPC_DEMCR_TRCENA;
    ctrl = XAGAWA_HPC_DWT_CTRL;

    if ((ctrl & XAGAWA_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        XAGAWA_HPC_DWT_CTRL |= XAGAWA_HPC_DWT_CTRL_CYCCNTENA;
        xagawa_hpc_available |= 0x01u;
    }

    XAGAWA_HPC_DWT_CPICNT = 0;
    XAGAWA_HPC_DWT_EXCCNT = 0;
    XAGAWA_HPC_DWT_SLEEPCNT = 0;
    XAGAWA_HPC_DWT_LSUCNT = 0;
    XAGAWA_HPC_DWT_FOLDCNT = 0;
    xagawa_hpc_available |= 0x02u;
}

static inline void xagawa_hpc_region_begin(void)
{
    xagawa_hpc_dwt_enable();

    xagawa_hpc_anomaly = 0;
    xagawa_hpc_cmov_region_cycles = 0;
    xagawa_hpc_cpi = 0;
    xagawa_hpc_exc = 0;
    xagawa_hpc_lsu = 0;
    xagawa_hpc_fold = 0;
    xagawa_hpc_cmov_cycles_sum = 0;
    xagawa_hpc_cmov_cycles_min = 0xffffffffu;
    xagawa_hpc_cmov_cycles_max = 0;
    xagawa_hpc_target_cmov_cycles = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    xagawa_hpc_region_start = XAGAWA_HPC_DWT_CYCCNT;
}

static inline uint32_t xagawa_hpc_cmov_begin(void)
{
    __asm volatile("" ::: "memory");
    return XAGAWA_HPC_DWT_CYCCNT;
}

static inline uint32_t xagawa_hpc_cmov_end_common(uint32_t start)
{
    uint32_t delta;

    if ((xagawa_hpc_available & 0x01u) == 0u) {
        return 0;
    }

    __asm volatile("" ::: "memory");

    delta = XAGAWA_HPC_DWT_CYCCNT - start;

    xagawa_hpc_cmov_cycles_sum += delta;

    if (delta < xagawa_hpc_cmov_cycles_min) {
        xagawa_hpc_cmov_cycles_min = delta;
    }

    if (delta > xagawa_hpc_cmov_cycles_max) {
        xagawa_hpc_cmov_cycles_max = delta;
    }

    return delta;
}

static inline void xagawa_hpc_region_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = XAGAWA_HPC_DWT_CYCCNT;
    xagawa_hpc_cmov_region_cycles = end - xagawa_hpc_region_start;

    xagawa_hpc_cpi = XAGAWA_HPC_DWT_CPICNT & 0xffu;
    xagawa_hpc_exc = XAGAWA_HPC_DWT_EXCCNT & 0xffu;
    xagawa_hpc_lsu = XAGAWA_HPC_DWT_LSUCNT & 0xffu;
    xagawa_hpc_fold = XAGAWA_HPC_DWT_FOLDCNT & 0xffu;

#if XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN > 0
    if (xagawa_hpc_target_cmov_cycles < (unsigned int)XAGAWA_HPC_TARGET_CMOV_CYCLES_MIN) {
        xagawa_hpc_anomaly |= XAGAWA_HPC_ERR_TARGET_CYCLES_LOW;
    }
#endif

#if XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX > 0
    if (xagawa_hpc_target_cmov_cycles > (unsigned int)XAGAWA_HPC_TARGET_CMOV_CYCLES_MAX) {
        xagawa_hpc_anomaly |= XAGAWA_HPC_ERR_TARGET_CYCLES_HIGH;
    }
#endif

    if (xagawa_hpc_anomaly != 0u) {
        xagawa_defense_error |= XAGAWA_ERR_HW_COUNTER;
    }
}

#else

static inline void xagawa_hpc_region_begin(void)
{
    xagawa_hpc_anomaly = 0;
    xagawa_hpc_cmov_region_cycles = 0;
    xagawa_hpc_cmov_cycles_sum = 0;
    xagawa_hpc_cmov_cycles_min = 0xffffffffu;
    xagawa_hpc_cmov_cycles_max = 0;
    xagawa_hpc_target_cmov_cycles = 0;
}

static inline uint32_t xagawa_hpc_cmov_begin(void)
{
    return 0;
}

static inline uint32_t xagawa_hpc_cmov_end_common(uint32_t start)
{
    (void)start;
    return 0;
}

static inline void xagawa_hpc_region_end(void)
{
}

#endif /* HPC_HW_ENABLE */

__attribute__((noinline))
static uint32_t xagawa_cmov_normal_measured(unsigned char *r,
                                            const unsigned char *x,
                                            size_t len,
                                            unsigned char b)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = xagawa_hpc_cmov_begin();

    cmov(r, x, len, b);

    __asm volatile("" ::: "memory");
    delta = xagawa_hpc_cmov_end_common(start);

    return delta;
}

__attribute__((noinline))
static uint32_t xagawa_cmov_skip_measured(unsigned char *r,
                                          const unsigned char *x,
                                          size_t len,
                                          unsigned char b)
{
    uint32_t start;
    uint32_t delta;

    __asm volatile("" ::: "memory");
    start = xagawa_hpc_cmov_begin();

    __asm volatile("" : : "r"(r), "r"(x), "r"(len), "r"(b) : "memory");

    delta = xagawa_hpc_cmov_end_common(start);

    xagawa_fault_skips++;

    return delta;
}

__attribute__((noinline))
static void xagawa_failure_handling_cmov_kr(unsigned char *r,
                                            const unsigned char *x,
                                            size_t len,
                                            unsigned char fail)
{
    xagawa_cmov_entries++;
    xagawa_last_fail = (unsigned int)fail;

    xagawa_hpc_region_begin();

    if ((xagawa_fault_enable != 0u) && (fail != 0u)) {
        xagawa_hpc_target_cmov_cycles =
            xagawa_cmov_skip_measured(r, x, len, fail);
    } else {
        xagawa_hpc_target_cmov_cycles =
            xagawa_cmov_normal_measured(r, x, len, fail);
    }

    xagawa_hpc_region_end();

    xagawa_cmov_exits++;
}

#endif /* XAGAWA_FAILURE_HANDLING_FAULT_INC */
