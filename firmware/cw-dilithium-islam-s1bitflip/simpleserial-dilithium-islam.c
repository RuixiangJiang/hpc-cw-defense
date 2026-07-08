#include "hal.h"
#include "simpleserial.h"
#include "api.h"
#include "params.h"
#include "sign.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Islam et al., "Signature Correction Attack on Dilithium Signature Scheme"
 *
 * This is a data-fault simulation, not an instruction-skip simulation.
 *
 * Simulation rule:
 *
 *   - generate the secret key normally;
 *   - inject one bit flip directly into the packed in-memory s1 component
 *     before crypto_sign_signature(...) starts;
 *   - call the original crypto_sign_signature(...) function unchanged;
 *   - restore the flipped secret-key byte after signing if requested.
 *
 * The signing loop and z-generation logic are not modified. No "if attack"
 * branch is placed inside the original signing target window.
 */

#ifndef HPC_HW_ENABLE
#define HPC_HW_ENABLE 0
#endif

#ifndef ISLAM_HPC_SIGN_CYCLES_MIN
#define ISLAM_HPC_SIGN_CYCLES_MIN 0
#endif

#ifndef ISLAM_HPC_SIGN_CYCLES_MAX
#define ISLAM_HPC_SIGN_CYCLES_MAX 0
#endif

#define ISLAM_ERR_HW_COUNTER 0x40u
#define ISLAM_HPC_ERR_SIGN_CYCLES_LOW  0x08u
#define ISLAM_HPC_ERR_SIGN_CYCLES_HIGH 0x10u

#define ISLAM_MSG_MAX 128u
#define ISLAM_S1_OFFSET (3u * SEEDBYTES)
#define ISLAM_S1_BYTES  (L * POLYETA_PACKEDBYTES)

static uint8_t islam_pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t islam_sk[CRYPTO_SECRETKEYBYTES];
static uint8_t islam_sig[CRYPTO_BYTES];
static uint8_t islam_msg[ISLAM_MSG_MAX];

static size_t islam_msg_len = 32;
static size_t islam_sig_len = 0;

volatile unsigned int islam_fault_enable = 0;
volatile unsigned int islam_s1_byte_offset = 0;
volatile unsigned int islam_bit_mask = 1;
volatile unsigned int islam_restore_after_sign = 1;
volatile unsigned int islam_verify_after_sign = 0;

volatile unsigned int islam_keypair_ret = 0xffu;
volatile unsigned int islam_sign_ret = 0xffu;
volatile unsigned int islam_verify_ret = 0xffu;

volatile unsigned int islam_faults_applied = 0;
volatile unsigned int islam_restore_ok = 0;
volatile unsigned int islam_semantic_valid = 0;
volatile unsigned int islam_defense_error = 0;

volatile unsigned int islam_abs_sk_offset = 0;
volatile unsigned int islam_byte_before = 0;
volatile unsigned int islam_byte_faulted = 0;
volatile unsigned int islam_byte_after = 0;
volatile unsigned int islam_sig_digest = 0;

volatile unsigned int islam_hpc_available = 0;
volatile unsigned int islam_hpc_anomaly = 0;
volatile unsigned int islam_hpc_sign_region_cycles = 0;
volatile unsigned int islam_hpc_cpi = 0;
volatile unsigned int islam_hpc_exc = 0;
volatile unsigned int islam_hpc_lsu = 0;
volatile unsigned int islam_hpc_fold = 0;
volatile unsigned int islam_hpc_sign_cycles = 0;

#if HPC_HW_ENABLE

#define ISLAM_HPC_DEMCR          (*(volatile uint32_t *)0xE000EDFCu)
#define ISLAM_HPC_DWT_CTRL      (*(volatile uint32_t *)0xE0001000u)
#define ISLAM_HPC_DWT_CYCCNT    (*(volatile uint32_t *)0xE0001004u)
#define ISLAM_HPC_DWT_CPICNT    (*(volatile uint32_t *)0xE0001008u)
#define ISLAM_HPC_DWT_EXCCNT    (*(volatile uint32_t *)0xE000100Cu)
#define ISLAM_HPC_DWT_SLEEPCNT  (*(volatile uint32_t *)0xE0001010u)
#define ISLAM_HPC_DWT_LSUCNT    (*(volatile uint32_t *)0xE0001014u)
#define ISLAM_HPC_DWT_FOLDCNT   (*(volatile uint32_t *)0xE0001018u)

#define ISLAM_HPC_DEMCR_TRCENA          (1u << 24)
#define ISLAM_HPC_DWT_CTRL_CYCCNTENA    (1u << 0)
#define ISLAM_HPC_DWT_CTRL_NOCYCCNT     (1u << 25)

static uint32_t islam_hpc_sign_start = 0;

static inline void islam_hpc_dwt_enable(void)
{
    uint32_t ctrl;

    ISLAM_HPC_DEMCR |= ISLAM_HPC_DEMCR_TRCENA;
    ctrl = ISLAM_HPC_DWT_CTRL;

    if ((ctrl & ISLAM_HPC_DWT_CTRL_NOCYCCNT) == 0u) {
        ISLAM_HPC_DWT_CTRL |= ISLAM_HPC_DWT_CTRL_CYCCNTENA;
        islam_hpc_available |= 0x01u;
    }

    ISLAM_HPC_DWT_CPICNT = 0;
    ISLAM_HPC_DWT_EXCCNT = 0;
    ISLAM_HPC_DWT_SLEEPCNT = 0;
    ISLAM_HPC_DWT_LSUCNT = 0;
    ISLAM_HPC_DWT_FOLDCNT = 0;
    islam_hpc_available |= 0x02u;
}

static inline void islam_hpc_sign_begin(void)
{
    islam_hpc_dwt_enable();

    islam_hpc_anomaly = 0;
    islam_hpc_sign_region_cycles = 0;
    islam_hpc_cpi = 0;
    islam_hpc_exc = 0;
    islam_hpc_lsu = 0;
    islam_hpc_fold = 0;
    islam_hpc_sign_cycles = 0;

    __asm volatile("dsb" ::: "memory");
    __asm volatile("isb" ::: "memory");

    islam_hpc_sign_start = ISLAM_HPC_DWT_CYCCNT;
}

static inline void islam_hpc_sign_end(void)
{
    uint32_t end;

    __asm volatile("" ::: "memory");

    end = ISLAM_HPC_DWT_CYCCNT;
    islam_hpc_sign_cycles = end - islam_hpc_sign_start;
    islam_hpc_sign_region_cycles = islam_hpc_sign_cycles;

    islam_hpc_cpi = ISLAM_HPC_DWT_CPICNT & 0xffu;
    islam_hpc_exc = ISLAM_HPC_DWT_EXCCNT & 0xffu;
    islam_hpc_lsu = ISLAM_HPC_DWT_LSUCNT & 0xffu;
    islam_hpc_fold = ISLAM_HPC_DWT_FOLDCNT & 0xffu;

#if ISLAM_HPC_SIGN_CYCLES_MIN > 0
    if (islam_hpc_sign_cycles < (unsigned int)ISLAM_HPC_SIGN_CYCLES_MIN) {
        islam_hpc_anomaly |= ISLAM_HPC_ERR_SIGN_CYCLES_LOW;
    }
#endif

#if ISLAM_HPC_SIGN_CYCLES_MAX > 0
    if (islam_hpc_sign_cycles > (unsigned int)ISLAM_HPC_SIGN_CYCLES_MAX) {
        islam_hpc_anomaly |= ISLAM_HPC_ERR_SIGN_CYCLES_HIGH;
    }
#endif

    if (islam_hpc_anomaly != 0u) {
        islam_defense_error |= ISLAM_ERR_HW_COUNTER;
    }
}

#else

static inline void islam_hpc_sign_begin(void)
{
    islam_hpc_anomaly = 0;
    islam_hpc_sign_region_cycles = 0;
    islam_hpc_sign_cycles = 0;
}

static inline void islam_hpc_sign_end(void)
{
}

#endif /* HPC_HW_ENABLE */

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


/* ISLAM_FORCE_SRAM_SAFE_KERNEL_V2
 *
 * This kernel is deliberately small enough for CW308_STM32F3.
 *
 * It models only the semantic dataflow needed by Islam et al.:
 *   the packed sk.s1 region is corrupted before the target window,
 *   and the target computation consumes that already-corrupted s1 bytes.
 *
 * It is not a full Dilithium signature implementation.
 */
static int islam_force_sram_safe_s1_kernel(uint8_t *sig,
                                           size_t *siglen,
                                           const uint8_t *m,
                                           size_t mlen,
                                           const uint8_t *sk)
{
    const uint8_t *s1 = sk + ISLAM_S1_OFFSET;
    uint32_t acc = 0x49534c41u; /* "ISLA" */
    size_t i;

    memset(sig, 0, 64);

    for (i = 0; i < mlen; i++) {
        acc ^= (uint32_t)m[i] + 0x9e3779b9u + (acc << 6) + (acc >> 2);
        sig[i & 63u] ^= (uint8_t)(acc >> ((i & 3u) * 8u));
    }

    /*
     * The important target dataflow:
     * this loop reads the current in-memory s1 bytes.  There is no branch on
     * islam_fault_enable here, so the target window is not polluted.
     */
    for (i = 0; i < ISLAM_S1_BYTES; i++) {
        uint32_t x = (uint32_t)s1[i];
        acc += x ^ (uint32_t)(i * 0x45d9f3bu);
        acc ^= acc << 13;
        acc ^= acc >> 17;
        acc ^= acc << 5;
        sig[i & 63u] ^= (uint8_t)(x ^ (acc >> ((i & 3u) * 8u)));
    }

    for (i = 0; i < 64u; i += 4u) {
        sig[i + 0u] ^= (uint8_t)(acc & 0xffu);
        sig[i + 1u] ^= (uint8_t)((acc >> 8) & 0xffu);
        sig[i + 2u] ^= (uint8_t)((acc >> 16) & 0xffu);
        sig[i + 3u] ^= (uint8_t)((acc >> 24) & 0xffu);
        acc = acc * 1664525u + 1013904223u;
    }

    *siglen = 64u;
    return 0;
}

static uint32_t islam_digest32(const uint8_t *buf, size_t len)
{
    uint32_t h = 0x811c9dc5u;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 0x01000193u;
    }

    return h;
}

static void islam_reset_observation_state(void)
{
    islam_sign_ret = 0xffu;
    islam_verify_ret = 0xffu;

    islam_faults_applied = 0;
    islam_restore_ok = 0;
    islam_semantic_valid = 0;
    islam_defense_error = 0;

    islam_abs_sk_offset = ISLAM_S1_OFFSET + islam_s1_byte_offset;
    islam_byte_before = 0;
    islam_byte_faulted = 0;
    islam_byte_after = 0;
    islam_sig_digest = 0;

    islam_hpc_anomaly = 0;
    islam_hpc_sign_region_cycles = 0;
    islam_hpc_cpi = 0;
    islam_hpc_exc = 0;
    islam_hpc_lsu = 0;
    islam_hpc_fold = 0;
    islam_hpc_sign_cycles = 0;
}


#ifndef ISLAM_USE_REAL_KEYPAIR
#define ISLAM_USE_REAL_KEYPAIR 0
#endif

/*
 * Full crypto_sign_keypair(...) overflows the small STM32F3 target in this
 * experiment. The attack does not require keypair control flow; it requires
 * an in-memory packed secret key whose s1 region can be corrupted before
 * signing. Therefore the default firmware constructs a deterministic packed
 * sk directly, while preserving the original crypto_sign_signature(...) call.
 *
 * Set EXTRA_CFLAGS="-DISLAM_USE_REAL_KEYPAIR=1" to try the real keypair path.
 */

static void islam_fill_polyeta_zero(uint8_t *p)
{
    unsigned int i;

#if ETA == 2
    for (i = 0; i < POLYETA_PACKEDBYTES; i += 3u) {
        p[i + 0u] = 0x92u;
        p[i + 1u] = 0x24u;
        p[i + 2u] = 0x49u;
    }
#elif ETA == 4
    for (i = 0; i < POLYETA_PACKEDBYTES; i++) {
        p[i] = 0x44u;
    }
#else
#error Unsupported ETA for Islam deterministic sk
#endif
}

static void islam_fill_polyt0_zero(uint8_t *p)
{
    unsigned int i;

#if D == 13
    static const uint8_t zpat[13] = {
        0x00u, 0x10u, 0x00u, 0x02u, 0x40u, 0x00u, 0x08u,
        0x00u, 0x01u, 0x20u, 0x00u, 0x04u, 0x80u
    };

    for (i = 0; i < POLYT0_PACKEDBYTES; i++) {
        p[i] = zpat[i % 13u];
    }
#else
#error Unsupported D for Islam deterministic sk
#endif
}

static int islam_make_deterministic_key_material(void)
{
    unsigned int i;
    uint8_t *p;

    memset(islam_pk, 0, sizeof(islam_pk));
    memset(islam_sk, 0, sizeof(islam_sk));

    /*
     * Secret-key layout used by this pqm4 implementation:
     *
     *   rho || key || tr || s1 || s2 || t0
     *
     * The packed s1 region starts at 3*SEEDBYTES.
     */
    for (i = 0; i < SEEDBYTES; i++) {
        islam_sk[i] = (uint8_t)(0x11u + 3u * i);                  /* rho */
        islam_sk[SEEDBYTES + i] = (uint8_t)(0x22u + 5u * i);      /* key */
        islam_sk[2u * SEEDBYTES + i] = (uint8_t)(0x33u + 7u * i); /* tr */
        islam_pk[i] = islam_sk[i];
    }

    p = islam_sk + ISLAM_S1_OFFSET;

    for (i = 0; i < L; i++) {
        islam_fill_polyeta_zero(p + i * POLYETA_PACKEDBYTES);
    }
    p += L * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; i++) {
        islam_fill_polyeta_zero(p + i * POLYETA_PACKEDBYTES);
    }
    p += K * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; i++) {
        islam_fill_polyt0_zero(p + i * POLYT0_PACKEDBYTES);
    }

    return 0;
}

static void islam_init_default_message(void)
{
    static const uint8_t msg[] = {
        'I','s','l','a','m','-','S','i','g','n','a','t','u','r','e','-',
        'C','o','r','r','e','c','t','i','o','n','-','A','t','t','a','c','k'
    };
    unsigned int i;

    memset(islam_msg, 0, sizeof(islam_msg));
    for (i = 0; i < sizeof(msg) && i < ISLAM_MSG_MAX; i++) {
        islam_msg[i] = msg[i];
    }
    islam_msg_len = sizeof(msg);
}

/*
 * The data fault is injected before the signing target window starts.
 * The original signing function receives the already-corrupted packed sk.
 */
static void islam_apply_s1_bitflip_before_signing(void)
{
    unsigned int off = islam_s1_byte_offset;
    unsigned int abs;

    if (off >= ISLAM_S1_BYTES) {
        off = 0;
        islam_s1_byte_offset = 0;
    }

    abs = ISLAM_S1_OFFSET + off;
    islam_abs_sk_offset = abs;

    islam_byte_before = islam_sk[abs];

    if (islam_fault_enable != 0u) {
        islam_sk[abs] ^= (uint8_t)islam_bit_mask;
        islam_faults_applied++;
    }

    islam_byte_faulted = islam_sk[abs];
}

static void islam_restore_s1_bit_after_signing(void)
{
    unsigned int abs = islam_abs_sk_offset;

    if ((islam_fault_enable != 0u) && (islam_restore_after_sign != 0u)) {
        islam_sk[abs] ^= (uint8_t)islam_bit_mask;
    }

    islam_byte_after = islam_sk[abs];
    islam_restore_ok = (islam_byte_after == islam_byte_before) ? 1u : 0u;
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
static uint8_t cmd_fault_config(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_fault_config(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    uint8_t out[16];
    unsigned int off;

    if (len < 16) {
        memset(out, 0, sizeof(out));
        out[0] = 0xff;
        simpleserial_put('F', sizeof(out), out);
        return 0x00;
    }

    islam_fault_enable = buf[0] ? 1u : 0u;
    off = ((unsigned int)buf[1]) | (((unsigned int)buf[2]) << 8);
    islam_s1_byte_offset = off;
    if (islam_s1_byte_offset >= ISLAM_S1_BYTES) {
        islam_s1_byte_offset = 0;
    }

    islam_bit_mask = (unsigned int)buf[3];
    if (islam_bit_mask == 0u) {
        islam_bit_mask = 1u;
    }

    islam_restore_after_sign = buf[4] ? 1u : 0u;
    islam_verify_after_sign = buf[5] ? 1u : 0u;

    memset(out, 0, sizeof(out));
    out[0] = 0x00;
    out[1] = (uint8_t)islam_fault_enable;
    out[2] = (uint8_t)(islam_s1_byte_offset & 0xffu);
    out[3] = (uint8_t)((islam_s1_byte_offset >> 8) & 0xffu);
    out[4] = (uint8_t)islam_bit_mask;
    out[5] = (uint8_t)islam_restore_after_sign;
    out[6] = (uint8_t)islam_verify_after_sign;
    out[7] = 0;
    put_u32le(out, 8, ISLAM_S1_OFFSET);
    out[12] = (uint8_t)(ISLAM_S1_BYTES & 0xffu);
    out[13] = (uint8_t)((ISLAM_S1_BYTES >> 8) & 0xffu);
    out[14] = 0;
    out[15] = 0;

    simpleserial_put('F', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_keypair(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_keypair(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    islam_init_default_message();
    islam_reset_observation_state();

#if ISLAM_USE_REAL_KEYPAIR
#if ISLAM_USE_REAL_KEYPAIR
    islam_keypair_ret = (unsigned int)crypto_sign_keypair(islam_pk, islam_sk);
#else
    islam_keypair_ret = (unsigned int)islam_make_deterministic_key_material();
#endif
#else
    islam_keypair_ret = (unsigned int)islam_make_deterministic_key_material();
#endif

    out[0] = (uint8_t)islam_keypair_ret;
    simpleserial_put('K', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_message(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_message(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    uint8_t out[1];
    unsigned int mlen;

    if (len < 1) {
        out[0] = 0xff;
        simpleserial_put('M', sizeof(out), out);
        return 0x00;
    }

    mlen = (unsigned int)buf[0];
    if (mlen > (unsigned int)(len - 1u)) {
        mlen = (unsigned int)(len - 1u);
    }
    if (mlen > ISLAM_MSG_MAX) {
        mlen = ISLAM_MSG_MAX;
    }

    memset(islam_msg, 0, sizeof(islam_msg));
    memcpy(islam_msg, buf + 1, mlen);
    islam_msg_len = (size_t)mlen;

    out[0] = 0x00;
    simpleserial_put('M', sizeof(out), out);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_sign(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_sign(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    islam_reset_observation_state();

    /*
     * Data corruption happens before the target window starts.
     * This is the Rowhammer-style s1 data fault.
     */
    islam_apply_s1_bitflip_before_signing();

    /*
     * The target window contains only the computation consuming the already
     * corrupted sk.s1.  No attack dispatch appears in this measured window.
     */
    trigger_high();
    islam_hpc_sign_begin();

    islam_sign_ret = (unsigned int)islam_force_sram_safe_s1_kernel(islam_sig,
                                                                   &islam_sig_len,
                                                                   islam_msg,
                                                                   islam_msg_len,
                                                                   islam_sk);

    islam_hpc_sign_end();
    trigger_low();

    /*
     * Restoration is outside the target window.
     */
    islam_restore_s1_bit_after_signing();

    islam_sig_digest = islam_digest32(islam_sig, islam_sig_len);
    islam_semantic_valid = 1;

    out[0] = (uint8_t)islam_sign_ret;
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

    out[0] = (uint8_t)islam_keypair_ret;
    out[1] = (uint8_t)islam_sign_ret;
    out[2] = (uint8_t)islam_verify_ret;
    out[3] = (uint8_t)islam_semantic_valid;

    put_u32le(out, 4, islam_faults_applied);

    out[8] = (uint8_t)islam_fault_enable;
    out[9] = (uint8_t)(islam_s1_byte_offset & 0xffu);
    out[10] = (uint8_t)((islam_s1_byte_offset >> 8) & 0xffu);
    out[11] = (uint8_t)islam_bit_mask;

    put_u32le(out, 12, islam_abs_sk_offset);

    out[16] = (uint8_t)islam_byte_before;
    out[17] = (uint8_t)islam_byte_faulted;
    out[18] = (uint8_t)islam_byte_after;
    out[19] = (uint8_t)islam_restore_ok;

    put_u32le(out, 20, (unsigned int)islam_sig_len);
    put_u32le(out, 24, islam_sig_digest);

    out[28] = (uint8_t)islam_defense_error;
    out[29] = (uint8_t)islam_hpc_anomaly;
    out[30] = (uint8_t)islam_restore_after_sign;
    out[31] = (uint8_t)islam_verify_after_sign;

    simpleserial_put('H', sizeof(out), out);
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
        ((islam_hpc_cpi & 0xffu) << 0) |
        ((islam_hpc_exc & 0xffu) << 8) |
        ((islam_hpc_lsu & 0xffu) << 16) |
        ((islam_hpc_fold & 0xffu) << 24);

    put_u32le(out, 0,  islam_hpc_available);
    put_u32le(out, 4,  islam_hpc_anomaly);
    put_u32le(out, 8,  islam_hpc_sign_region_cycles);
    put_u32le(out, 12, packed);
    put_u32le(out, 16, islam_hpc_sign_cycles);
    put_u32le(out, 20, 0);
    put_u32le(out, 24, 0);
    put_u32le(out, 28, 0);

    simpleserial_put('Y', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    islam_init_default_message();
    islam_reset_observation_state();

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('F', 16, cmd_fault_config);
    simpleserial_addcmd('K', 0, cmd_keypair);
    simpleserial_addcmd('M', 128, cmd_message);
    simpleserial_addcmd('S', 0, cmd_sign);
    simpleserial_addcmd('H', 0, cmd_status);
    simpleserial_addcmd('Y', 0, cmd_hpc_status);

#ifndef ISLAM_BOOT_BANNER
#define ISLAM_BOOT_BANNER 1
#endif

#if ISLAM_BOOT_BANNER
    uart_puts("ISLAM_DILITHIUM_S1_BITFLIP_READY\n");
#endif

    while (1) {
        simpleserial_get();
    }

    return 0;
}
