#include "hal.h"
#include "simpleserial.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Du et al., "Breaking the Shield" -- y-generation / polyz_unpack attack
 *
 * Semantic model:
 *
 *   The attack skips a load inside polyz_unpack.  The target load result is
 *   replaced by a stale or known value, while the remaining loads and
 *   coefficient reconstruction steps execute normally.
 *
 * Models:
 *   0 = normal polyz_unpack target coefficient
 *   1 = skipped load result becomes known zero
 *   2 = skipped load result becomes configured stale byte
 *
 * Clean target window:
 *   normal prefix coefficients
 *   select target coefficient primitive outside target window
 *   trigger_high()
 *   DWT/HPC begin
 *   normal target coefficient unpack OR faulted target coefficient unpack
 *   DWT/HPC end
 *   trigger_low()
 *   normal suffix coefficients
 *
 * The measured window does not contain fault-model dispatch or "if attack"
 * logic.  This models a local skipped load without changing the control flow
 * of every unpacking iteration.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef DU_HPC_TARGET_CYCLES_MIN
#define DU_HPC_TARGET_CYCLES_MIN 0
#endif

#ifndef DU_HPC_TARGET_CYCLES_MAX
#define DU_HPC_TARGET_CYCLES_MAX 0
#endif

/*
 * Fixed stale replacement value used inside the target primitive.
 *
 * This is intentionally a compile-time constant, supplied by the host build
 * script through -DDU_STALE_FIXED_BYTE=<value>.  The target primitive does not
 * read the runtime global du_stale_byte, so the measured window models a stale
 * load result that has already been prepared before the faulted load is
 * consumed.
 */
#ifndef DU_STALE_FIXED_BYTE
#define DU_STALE_FIXED_BYTE 90u
#endif

#define DU_MODEL_NONE   0u
#define DU_MODEL_ZERO   1u
#define DU_MODEL_STALE  2u

#define DU_ERR_HW_COUNTER 0x40u
#define DU_HPC_ERR_TARGET_CYCLES_LOW  0x08u
#define DU_HPC_ERR_TARGET_CYCLES_HIGH 0x10u

#ifndef POLYZ_PACKEDBYTES
#define POLYZ_PACKEDBYTES 576
#endif

#define DU_NCOEFFS 256u
#define DU_PACKED_BYTES POLYZ_PACKEDBYTES

static uint8_t du_packed[DU_PACKED_BYTES];
static int32_t du_out[DU_NCOEFFS];
static int32_t du_ref[DU_NCOEFFS];

volatile unsigned int du_model = DU_MODEL_NONE;
volatile unsigned int du_target_coeff = 17;
volatile unsigned int du_target_load = 1;
volatile unsigned int du_stale_byte = 0x5au;
volatile unsigned int du_message_tweak = 0;

volatile unsigned int du_faults_applied = 0;
volatile unsigned int du_entries = 0;
volatile unsigned int du_exits = 0;
volatile unsigned int du_semantic_valid = 0;
volatile unsigned int du_output_matches_ref = 0;
volatile unsigned int du_defense_error = 0;

volatile unsigned int du_expected_load_value = 0;
volatile unsigned int du_used_load_value = 0;
volatile unsigned int du_target_group = 0;
volatile unsigned int du_coeff_in_group = 0;

volatile uint32_t du_expected_coeff_u32 = 0;
volatile uint32_t du_used_coeff_u32 = 0;
volatile uint32_t du_expected_partial = 0;
volatile uint32_t du_used_partial = 0;

volatile unsigned int du_packed_digest = 0;
volatile unsigned int du_output_digest = 0;
volatile unsigned int du_reference_digest = 0;
volatile unsigned int du_output_diff = 0;

volatile unsigned int du_hpc_available = 0;
volatile unsigned int du_hpc_anomaly = 0;
volatile unsigned int du_hpc_region_cycles = 0;
volatile unsigned int du_hpc_cpi = 0;
volatile unsigned int du_hpc_exc = 0;
volatile unsigned int du_hpc_lsu = 0;
volatile unsigned int du_hpc_fold = 0;
volatile unsigned int du_hpc_target_cycles = 0;
volatile unsigned int du_hpc_cycles_min = 0xffffffffu;
volatile unsigned int du_hpc_cycles_max = 0;
volatile unsigned int du_hpc_cycles_sum = 0;

typedef int32_t (*du_polyz_target_fn)(const uint8_t *a, unsigned int coeff);

#if HPC_HW_ENABLE
#define DU_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define DU_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define DU_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define DU_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define DU_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define DU_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define DU_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)
#define DU_HPC_DEMCR_TRCENA          (1u << 24)
#define DU_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define DU_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)
static uint32_t du_hpc_region_start = 0;
static inline void du_hpc_dwt_enable(void)
{
    uint32_t ctrl;
    DU_HPC_DEMCR |= DU_HPC_DEMCR_TRCENA;
    ctrl = DU_HPC_DWT_CTRL;
    if ((ctrl & DU_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        DU_HPC_DWT_CTRL |= DU_HPC_DWT_CTRL_CYCCNTENA;
        du_hpc_available |= 0x01u;
    }
    DU_HPC_DWT_CPICNT = 0;
    DU_HPC_DWT_EXCCNT = 0;
    DU_HPC_DWT_LSUCNT = 0;
    DU_HPC_DWT_FOLDCNT = 0;
    du_hpc_available |= 0x02u;
}
static inline void du_hpc_region_begin(void)
{
    du_hpc_dwt_enable();
    du_hpc_anomaly = 0;
    du_hpc_region_cycles = 0;
    du_hpc_cpi = 0;
    du_hpc_exc = 0;
    du_hpc_lsu = 0;
    du_hpc_fold = 0;
    du_hpc_target_cycles = 0;
    du_hpc_cycles_min = 0xffffffffu;
    du_hpc_cycles_max = 0;
    du_hpc_cycles_sum = 0;
    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");
    du_hpc_region_start = DU_HPC_DWT_CYCCNT;
}
static inline uint32_t du_hpc_op_begin(void)
{
    __asm volatile("" ::: "memory");
    return DU_HPC_DWT_CYCCNT;
}
static inline uint32_t du_hpc_op_end_common(uint32_t start)
{
    uint32_t delta;
    if ((du_hpc_available & 0x01u) == 0u) return 0;
    __asm volatile("" ::: "memory");
    delta = DU_HPC_DWT_CYCCNT - start;
    du_hpc_cycles_sum += delta;
    if (delta < du_hpc_cycles_min) du_hpc_cycles_min = delta;
    if (delta > du_hpc_cycles_max) du_hpc_cycles_max = delta;
    return delta;
}
static inline void du_hpc_region_end(void)
{
    uint32_t end;
    __asm volatile("" ::: "memory");
    end = DU_HPC_DWT_CYCCNT;
    du_hpc_region_cycles = end - du_hpc_region_start;
    du_hpc_cpi = DU_HPC_DWT_CPICNT & 0xffu;
    du_hpc_exc = DU_HPC_DWT_EXCCNT & 0xffu;
    du_hpc_lsu = DU_HPC_DWT_LSUCNT & 0xffu;
    du_hpc_fold = DU_HPC_DWT_FOLDCNT & 0xffu;
#if DU_HPC_TARGET_CYCLES_MIN > 0
    if (du_hpc_target_cycles < (unsigned int)DU_HPC_TARGET_CYCLES_MIN) du_hpc_anomaly |= DU_HPC_ERR_TARGET_CYCLES_LOW;
#endif
#if DU_HPC_TARGET_CYCLES_MAX > 0
    if (du_hpc_target_cycles > (unsigned int)DU_HPC_TARGET_CYCLES_MAX) du_hpc_anomaly |= DU_HPC_ERR_TARGET_CYCLES_HIGH;
#endif
    if (du_hpc_anomaly != 0u) du_defense_error |= DU_ERR_HW_COUNTER;
}
#else
static inline void du_hpc_region_begin(void) { du_hpc_anomaly = 0; du_hpc_region_cycles = 0; du_hpc_target_cycles = 0; du_hpc_cycles_min = 0xffffffffu; du_hpc_cycles_max = 0; du_hpc_cycles_sum = 0; }
static inline uint32_t du_hpc_op_begin(void) { return 0; }
static inline uint32_t du_hpc_op_end_common(uint32_t start) { (void)start; return 0; }
static inline void du_hpc_region_end(void) { }
#endif

static uint32_t du_fnv1a_bytes(const uint8_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;
    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }
    return h;
}

static uint32_t du_fnv1a_coeffs(const int32_t *buf, unsigned int len)
{
    unsigned int i;
    uint32_t h = 0x811c9dc5u;
    for (i = 0; i < len; i++) {
        uint32_t x = (uint32_t)buf[i];
        h ^= x;
        h *= 0x01000193u;
        h ^= x >> 16;
        h *= 0x01000193u;
    }
    return h;
}

static void du_init_packed(void)
{
    unsigned int i;
    uint32_t tweak = du_message_tweak;
    for (i = 0; i < DU_PACKED_BYTES; i++) {
        du_packed[i] = (uint8_t)(0x93u ^ (i * 29u) ^ ((tweak >> ((i & 3u) * 8u)) & 0xffu));
    }
    du_packed_digest = du_fnv1a_bytes(du_packed, DU_PACKED_BYTES);
}

static void du_get_coeff_bytes(const uint8_t *a, unsigned int coeff,
                               uint8_t *b0, uint8_t *b1, uint8_t *b2)
{
    unsigned int group = coeff >> 2;
    unsigned int pos = coeff & 3u;
    const uint8_t *p = a + 9u * group;

    if (pos == 0u) {
        *b0 = p[0]; *b1 = p[1]; *b2 = p[2];
    } else if (pos == 1u) {
        *b0 = p[2]; *b1 = p[3]; *b2 = p[4];
    } else if (pos == 2u) {
        *b0 = p[4]; *b1 = p[5]; *b2 = p[6];
    } else {
        *b0 = p[6]; *b1 = p[7]; *b2 = p[8];
    }
}

static uint32_t du_decode_raw_from_bytes(unsigned int pos, uint8_t b0, uint8_t b1, uint8_t b2)
{
    uint32_t t;
    if (pos == 0u) {
        t = (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16);
    } else if (pos == 1u) {
        t = ((uint32_t)b0 >> 2) | ((uint32_t)b1 << 6) | ((uint32_t)b2 << 14);
    } else if (pos == 2u) {
        t = ((uint32_t)b0 >> 4) | ((uint32_t)b1 << 4) | ((uint32_t)b2 << 12);
    } else {
        t = ((uint32_t)b0 >> 6) | ((uint32_t)b1 << 2) | ((uint32_t)b2 << 10);
    }
    return t & 0x3ffffu;
}

static int32_t du_polyz_finish(uint32_t raw)
{
    return (int32_t)GAMMA1 - (int32_t)raw;
}

__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_normal(const uint8_t *a, unsigned int coeff)
{
    uint8_t b0, b1, b2;
    uint32_t raw;
    du_get_coeff_bytes(a, coeff, &b0, &b1, &b2);
    raw = du_decode_raw_from_bytes(coeff & 3u, b0, b1, b2);
    return du_polyz_finish(raw);
}

static int32_t du_polyz_unpack_coeff_with_load_value(const uint8_t *a,
                                                     unsigned int coeff,
                                                     unsigned int load_index,
                                                     uint8_t replacement)
{
    uint8_t b0, b1, b2;
    uint32_t raw;

    du_get_coeff_bytes(a, coeff, &b0, &b1, &b2);

    if (load_index == 0u) {
        b0 = replacement;
    } else if (load_index == 1u) {
        b1 = replacement;
    } else {
        b2 = replacement;
    }

    raw = du_decode_raw_from_bytes(coeff & 3u, b0, b1, b2);
    return du_polyz_finish(raw);
}

__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_zero_l0(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 0u, 0u);
}
__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_zero_l1(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 1u, 0u);
}
__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_zero_l2(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 2u, 0u);
}
__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_stale_l0(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 0u, (uint8_t)DU_STALE_FIXED_BYTE);
}
__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_stale_l1(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 1u, (uint8_t)DU_STALE_FIXED_BYTE);
}
__attribute__((noinline))
static int32_t du_polyz_unpack_coeff_stale_l2(const uint8_t *a, unsigned int coeff)
{
    return du_polyz_unpack_coeff_with_load_value(a, coeff, 2u, (uint8_t)DU_STALE_FIXED_BYTE);
}

static du_polyz_target_fn du_select_target_fn(void)
{
    unsigned int load = du_target_load;
    if (load > 2u) load = 2u;

    if (du_model == DU_MODEL_ZERO) {
        if (load == 0u) return du_polyz_unpack_coeff_zero_l0;
        if (load == 1u) return du_polyz_unpack_coeff_zero_l1;
        return du_polyz_unpack_coeff_zero_l2;
    }

    if (du_model == DU_MODEL_STALE) {
        if (load == 0u) return du_polyz_unpack_coeff_stale_l0;
        if (load == 1u) return du_polyz_unpack_coeff_stale_l1;
        return du_polyz_unpack_coeff_stale_l2;
    }

    return du_polyz_unpack_coeff_normal;
}

static uint8_t du_expected_load_byte(const uint8_t *a, unsigned int coeff, unsigned int load)
{
    uint8_t b0, b1, b2;
    du_get_coeff_bytes(a, coeff, &b0, &b1, &b2);
    if (load == 0u) return b0;
    if (load == 1u) return b1;
    return b2;
}

static uint32_t du_raw_partial_for_coeff_value(int32_t z)
{
    return ((uint32_t)((int32_t)GAMMA1 - z)) & 0x3ffffu;
}

static void du_reset_observation_state(void)
{
    du_faults_applied = 0;
    du_entries = 0;
    du_exits = 0;
    du_semantic_valid = 0;
    du_output_matches_ref = 0;
    du_defense_error = 0;
    du_expected_load_value = 0;
    du_used_load_value = 0;
    du_target_group = 0;
    du_coeff_in_group = 0;
    du_expected_coeff_u32 = 0;
    du_used_coeff_u32 = 0;
    du_expected_partial = 0;
    du_used_partial = 0;
    du_output_digest = 0;
    du_reference_digest = 0;
    du_output_diff = 0;
    memset(du_out, 0, sizeof(du_out));
    memset(du_ref, 0, sizeof(du_ref));
    du_hpc_anomaly = 0;
    du_hpc_region_cycles = 0;
    du_hpc_cpi = 0;
    du_hpc_exc = 0;
    du_hpc_lsu = 0;
    du_hpc_fold = 0;
    du_hpc_target_cycles = 0;
    du_hpc_cycles_min = 0xffffffffu;
    du_hpc_cycles_max = 0;
    du_hpc_cycles_sum = 0;
}

__attribute__((noinline))
static void du_run_polyz_unpack_experiment(void)
{
    unsigned int i;
    unsigned int target = du_target_coeff;
    unsigned int load = du_target_load;
    uint32_t start;
    du_polyz_target_fn target_fn;

    if (target >= DU_NCOEFFS) {
        target = 0u;
        du_target_coeff = 0u;
    }
    if (load > 2u) {
        load = 2u;
        du_target_load = 2u;
    }

    du_entries++;

    for (i = 0; i < DU_NCOEFFS; i++) {
        du_ref[i] = du_polyz_unpack_coeff_normal(du_packed, i);
    }
    du_reference_digest = du_fnv1a_coeffs(du_ref, DU_NCOEFFS);

    for (i = 0; i < target; i++) {
        du_out[i] = du_polyz_unpack_coeff_normal(du_packed, i);
    }

    /*
     * Select target primitive outside the measured window.
     */
    target_fn = du_select_target_fn();

    if (du_model == DU_MODEL_ZERO) {
        du_faults_applied = 1u;
        du_used_load_value = 0u;
    } else if (du_model == DU_MODEL_STALE) {
        du_faults_applied = 1u;
        du_used_load_value = ((unsigned int)DU_STALE_FIXED_BYTE) & 0xffu;
    } else {
        du_faults_applied = 0u;
        du_used_load_value = du_expected_load_byte(du_packed, target, load);
    }

    du_expected_load_value = du_expected_load_byte(du_packed, target, load);
    du_target_group = target >> 2;
    du_coeff_in_group = target & 3u;

    trigger_high();
    du_hpc_region_begin();
    start = du_hpc_op_begin();

    du_out[target] = target_fn(du_packed, target);

    du_hpc_target_cycles = du_hpc_op_end_common(start);
    du_hpc_region_end();
    trigger_low();

    for (i = target + 1u; i < DU_NCOEFFS; i++) {
        du_out[i] = du_polyz_unpack_coeff_normal(du_packed, i);
    }

    du_expected_coeff_u32 = (uint32_t)du_ref[target];
    du_used_coeff_u32 = (uint32_t)du_out[target];
    du_expected_partial = du_raw_partial_for_coeff_value(du_ref[target]);
    du_used_partial = du_raw_partial_for_coeff_value(du_out[target]);

    du_output_digest = du_fnv1a_coeffs(du_out, DU_NCOEFFS);
    du_output_diff = du_output_digest ^ du_reference_digest;
    du_output_matches_ref = (du_output_digest == du_reference_digest) ? 1u : 0u;
    du_semantic_valid = 1u;
    du_exits++;
}

static void enable_fpu(void)
{
    volatile uint32_t *cpacr = (volatile uint32_t *)0xE000ED88U;
    *cpacr |= (0xFU << 20);
    __asm volatile("dsb");
    __asm volatile("isb");
}
static void uart_puts(const char *s) { while (*s) putch(*s++); }
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
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
    (void)cmd; (void)scmd;
#endif
    uint8_t out[24];
    unsigned int model, coeff, load, stale, tweak;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xffu;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    model = (unsigned int)buf[0];
    if (model > DU_MODEL_STALE) model = DU_MODEL_NONE;

    coeff = (unsigned int)buf[1] | (((unsigned int)buf[2]) << 8);
    if (coeff >= DU_NCOEFFS) coeff = 0u;

    load = (unsigned int)buf[3];
    if (load > 2u) load = 2u;

    stale = (unsigned int)buf[4];

    tweak = (unsigned int)buf[5] |
            (((unsigned int)buf[6]) << 8) |
            (((unsigned int)buf[7]) << 16) |
            (((unsigned int)buf[8]) << 24);

    du_model = model;
    du_target_coeff = coeff;
    du_target_load = load;
    du_stale_byte = stale & 0xffu;
    du_message_tweak = tweak;
    du_init_packed();

    memset(out, 0, sizeof(out));
    out[0] = 0;
    out[1] = (uint8_t)du_model;
    put_u32le(out, 4, du_target_coeff);
    put_u32le(out, 8, du_target_load);
    put_u32le(out, 12, du_stale_byte);
    put_u32le(out, 16, du_message_tweak);
    put_u32le(out, 20, du_packed_digest);
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[1];
    du_reset_observation_state();
    du_init_packed();
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[1];
    du_reset_observation_state();
    du_init_packed();
    du_run_polyz_unpack_experiment();
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[32];
    memset(out, 0, sizeof(out));
    out[0] = (uint8_t)du_model;
    out[1] = (uint8_t)du_semantic_valid;
    out[2] = (uint8_t)du_output_matches_ref;
    out[3] = (uint8_t)du_target_load;
    put_u32le(out, 4, du_faults_applied);
    put_u32le(out, 8, du_target_coeff);
    put_u32le(out, 12, du_expected_coeff_u32);
    put_u32le(out, 16, du_used_coeff_u32);
    put_u32le(out, 20, du_expected_load_value);
    put_u32le(out, 24, du_used_load_value);
    out[28] = (uint8_t)du_defense_error;
    out[29] = (uint8_t)du_hpc_anomaly;
    out[30] = (uint8_t)du_entries;
    out[31] = (uint8_t)du_exits;
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[16];
    put_u32le(out, 0, du_output_digest);
    put_u32le(out, 4, du_reference_digest);
    put_u32le(out, 8, du_output_diff);
    put_u32le(out, 12, du_message_tweak);
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[16];
    put_u32le(out, 0, du_target_group);
    put_u32le(out, 4, du_coeff_in_group);
    put_u32le(out, 8, du_expected_partial);
    put_u32le(out, 12, du_used_partial);
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
    (void)cmd; (void)scmd;
#endif
    (void)len; (void)buf;
    uint8_t out[32];
    unsigned int packed = ((du_hpc_cpi & 0xffu) << 0) |
                          ((du_hpc_exc & 0xffu) << 8) |
                          ((du_hpc_lsu & 0xffu) << 16) |
                          ((du_hpc_fold & 0xffu) << 24);
    put_u32le(out, 0, du_hpc_available);
    put_u32le(out, 4, du_hpc_anomaly);
    put_u32le(out, 8, du_hpc_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, du_hpc_target_cycles);
    put_u32le(out, 20, du_hpc_cycles_min);
    put_u32le(out, 24, du_hpc_cycles_max);
    put_u32le(out, 28, du_hpc_cycles_sum);
    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();
    platform_init();
    init_uart();
    trigger_setup();
    du_reset_observation_state();
    du_init_packed();
    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_config);
    simpleserial_addcmd('K', 0, cmd_init);
    simpleserial_addcmd('S', 0, cmd_run);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('D', 0, cmd_digest_status);
    simpleserial_addcmd('R', 0, cmd_detail_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);
#ifndef DU_BOOT_BANNER
#define DU_BOOT_BANNER 1
#endif
#if DU_BOOT_BANNER
    uart_puts("DU_POLYZ_UNPACK_READY\n");
#endif
    while (1) simpleserial_get();
    return 0;
}
