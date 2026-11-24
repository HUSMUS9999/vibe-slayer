#ifndef VS_CRYPTO_CORE_H
#define VS_CRYPTO_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define VS_HAVE_X86_SIMD 1
#else
#define VS_HAVE_X86_SIMD 0
#endif

#if defined(__GNUC__) || defined(__clang__)
#define VS_ALWAYS_INLINE static inline __attribute__((always_inline))
#define VS_USED_ALIGNED __attribute__((used, aligned(16)))
#if defined(VS_FREESTANDING)
#define VS_TARGET_FN(feat) __attribute__((target(feat), no_stack_protector, noinline, unused))
#else
#define VS_TARGET_FN(feat) __attribute__((target(feat), noinline, unused))
#endif
#else
#define VS_ALWAYS_INLINE static inline
#define VS_USED_ALIGNED
#define VS_TARGET_FN(feat)
#endif

VS_ALWAYS_INLINE uint32_t vs_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

VS_ALWAYS_INLINE uint32_t vs_load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

VS_ALWAYS_INLINE uint64_t vs_core_load64_le(const uint8_t *p) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint64_t v;
    __builtin_memcpy(&v, p, 8);
    return v;
#else
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
#endif
}

VS_ALWAYS_INLINE void vs_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
}

VS_ALWAYS_INLINE void vs_core_store64_le(uint8_t *p, uint64_t v) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    __builtin_memcpy(p, &v, 8);
#else
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (i * 8)) & 0xffU);
#endif
}

VS_ALWAYS_INLINE void vs_store32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xffU);
    p[1] = (uint8_t)((v >> 16) & 0xffU);
    p[2] = (uint8_t)((v >> 8) & 0xffU);
    p[3] = (uint8_t)(v & 0xffU);
}

VS_ALWAYS_INLINE void vs_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0U) return;
#if defined(__GNUC__) || defined(__clang__)
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    while (len--) {
        *vp++ = 0U;
    }
#endif
}

#if VS_HAVE_X86_SIMD
VS_ALWAYS_INLINE void vs_cpuid(
    uint32_t leaf, uint32_t subleaf,
    uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx
) {
    __asm__ __volatile__(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf)
    );
}

VS_ALWAYS_INLINE uint64_t vs_xgetbv0(void) {
    uint32_t eax = 0, edx = 0;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0U));
    return ((uint64_t)edx << 32) | eax;
}

static inline int vs_has_shani(void) {
    static int cached = -1;
    int c = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (c >= 0) return c;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    vs_cpuid(0U, 0U, &eax, &ebx, &ecx, &edx);
    if (eax < 7U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1U << 9)) == 0U || (ecx & (1U << 19)) == 0U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(7U, 0U, &eax, &ebx, &ecx, &edx);
    c = ((ebx & (1U << 29)) != 0U) ? 1 : 0;
    __atomic_store_n(&cached, c, __ATOMIC_RELAXED);
    return c;
}

static inline int vs_has_avx2(void) {
    static int cached = -1;
    int c = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (c >= 0) return c;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    vs_cpuid(0U, 0U, &eax, &ebx, &ecx, &edx);
    if (eax < 7U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1U << 27)) == 0U || (ecx & (1U << 28)) == 0U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    if ((vs_xgetbv0() & 0x6ULL) != 0x6ULL) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(7U, 0U, &eax, &ebx, &ecx, &edx);
    c = ((ebx & (1U << 5)) != 0U) ? 1 : 0;
    __atomic_store_n(&cached, c, __ATOMIC_RELAXED);
    return c;
}

static inline int vs_has_avx512f(void) {
    static int cached = -1;
    int c = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (c >= 0) return c;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    vs_cpuid(0U, 0U, &eax, &ebx, &ecx, &edx);
    if (eax < 7U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1U << 27)) == 0U || (ecx & (1U << 28)) == 0U) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    if ((vs_xgetbv0() & 0xe6ULL) != 0xe6ULL) { __atomic_store_n(&cached, 0, __ATOMIC_RELAXED); return 0; }
    vs_cpuid(7U, 0U, &eax, &ebx, &ecx, &edx);
    c = ((ebx & (1U << 16)) != 0U) ? 1 : 0;
    __atomic_store_n(&cached, c, __ATOMIC_RELAXED);
    return c;
}
#endif

/* ---- FIPS 180-4 SHA-256 + HMAC-SHA256 + HKDF-SHA256 ---- */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
} vs_sha256_ctx;

VS_USED_ALIGNED static const uint32_t VS_SHA256_K[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

VS_ALWAYS_INLINE uint32_t vs_rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void vs_sha256_transform(vs_sha256_ctx *ctx, const uint8_t *data) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = vs_rotr32(w[i - 15], 7) ^ vs_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = vs_rotr32(w[i - 2], 17) ^ vs_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = vs_rotr32(e, 6) ^ vs_rotr32(e, 11) ^ vs_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + VS_SHA256_K[i] + w[i];
        uint32_t S0 = vs_rotr32(a, 2) ^ vs_rotr32(a, 13) ^ vs_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
    vs_secure_zero(w, sizeof(w));
    a = b = c = d = e = f = g = h = 0;
}

#if VS_HAVE_X86_SIMD
VS_TARGET_FN("sha,sse4.1,ssse3")
static void vs_sha256_blocks_shani(uint32_t state[8], const uint8_t *data, size_t nblocks) {
    __m128i abef = _mm_set_epi32((int)state[0], (int)state[1], (int)state[4], (int)state[5]);
    __m128i cdgh = _mm_set_epi32((int)state[2], (int)state[3], (int)state[6], (int)state[7]);
    const __m128i bswap_mask = _mm_set_epi32(
        (int)0x0c0d0e0fU, (int)0x08090a0bU, (int)0x04050607U, (int)0x00010203U
    );

#define VS_SHANI_STEP(m_cur, m_next, m_prev, k_off) do { \
    __m128i _m = _mm_add_epi32((m_cur), _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + (k_off)))); \
    cdgh = _mm_sha256rnds2_epu32(cdgh, abef, _m); \
    __m128i _t = _mm_alignr_epi8((m_cur), (m_prev), 4); \
    (m_next) = _mm_add_epi32((m_next), _t); \
    (m_next) = _mm_sha256msg2_epu32((m_next), (m_cur)); \
    _m = _mm_shuffle_epi32(_m, 0x0E); \
    abef = _mm_sha256rnds2_epu32(abef, cdgh, _m); \
    (m_prev) = _mm_sha256msg1_epu32((m_prev), (m_cur)); \
} while (0)

    for (size_t b = 0; b < nblocks; b++, data += 64) {
        const __m128i abef_save = abef;
        const __m128i cdgh_save = cdgh;

        __m128i msg0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(data + 0)), bswap_mask);
        __m128i msg = _mm_add_epi32(msg0, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 0)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        __m128i msg1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(data + 16)), bswap_mask);
        msg = _mm_add_epi32(msg1, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 4)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        __m128i msg2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(data + 32)), bswap_mask);
        msg = _mm_add_epi32(msg2, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 8)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        __m128i msg3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(data + 48)), bswap_mask);
        msg = _mm_add_epi32(msg3, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 12)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        __m128i tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        VS_SHANI_STEP(msg0, msg1, msg3, 16);
        VS_SHANI_STEP(msg1, msg2, msg0, 20);
        VS_SHANI_STEP(msg2, msg3, msg1, 24);
        VS_SHANI_STEP(msg3, msg0, msg2, 28);
        VS_SHANI_STEP(msg0, msg1, msg3, 32);
        VS_SHANI_STEP(msg1, msg2, msg0, 36);
        VS_SHANI_STEP(msg2, msg3, msg1, 40);
        VS_SHANI_STEP(msg3, msg0, msg2, 44);
        VS_SHANI_STEP(msg0, msg1, msg3, 48);
        VS_SHANI_STEP(msg1, msg2, msg0, 52);

        msg = _mm_add_epi32(msg2, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 56)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        msg = _mm_add_epi32(msg3, _mm_loadu_si128((const __m128i *)(const void *)(VS_SHA256_K + 60)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);
    }
#undef VS_SHANI_STEP

    uint32_t out_abef[4], out_cdgh[4];
    _mm_storeu_si128((__m128i *)(void *)out_abef, abef);
    _mm_storeu_si128((__m128i *)(void *)out_cdgh, cdgh);
    state[0] = out_abef[3];
    state[1] = out_abef[2];
    state[2] = out_cdgh[3];
    state[3] = out_cdgh[2];
    state[4] = out_abef[1];
    state[5] = out_abef[0];
    state[6] = out_cdgh[1];
    state[7] = out_cdgh[0];
}
#endif

static void vs_sha256_init(vs_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

static void vs_sha256_update(vs_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) return;
    size_t i = 0;
    if (ctx->buflen > 0) {
        while (i < len && ctx->buflen < 64) {
            ctx->buf[ctx->buflen++] = data[i++];
        }
        if (ctx->buflen == 64) {
            vs_sha256_transform(ctx, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
    size_t rem_full = (len - i) / 64U;
    if (rem_full > 0U) {
#if VS_HAVE_X86_SIMD
        if (vs_has_shani()) {
            vs_sha256_blocks_shani(ctx->state, data + i, rem_full);
            ctx->bitlen += (uint64_t)rem_full * 512ULL;
            i += rem_full * 64U;
        } else
#endif
        {
            while ((len - i) >= 64U) {
                vs_sha256_transform(ctx, data + i);
                ctx->bitlen += 512;
                i += 64;
            }
        }
    }
    while (i < len) {
        ctx->buf[ctx->buflen++] = data[i++];
    }
}

static void vs_sha256_final(vs_sha256_ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->buflen;
    ctx->bitlen += (uint64_t)i * 8ULL;
    ctx->buf[i++] = 0x80U;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        vs_sha256_transform(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    for (int j = 0; j < 8; j++) {
        ctx->buf[63 - j] = (uint8_t)((ctx->bitlen >> (j * 8)) & 0xffU);
    }
    vs_sha256_transform(ctx, ctx->buf);
    for (int j = 0; j < 8; j++) {
        vs_store32_be(out + j * 4, ctx->state[j]);
    }
    vs_secure_zero(ctx, sizeof(*ctx));
}

static void vs_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    vs_sha256_ctx ctx;
    vs_sha256_init(&ctx);
    vs_sha256_update(&ctx, data, len);
    vs_sha256_final(&ctx, out);
}

static void vs_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]
) {
    uint8_t kpad[64];
    memset(kpad, 0, sizeof(kpad));
    if (key_len > 64) {
        vs_sha256(key, key_len, kpad);
    } else if (key && key_len > 0) {
        memcpy(kpad, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kpad[i] ^ 0x36U;
        opad[i] = kpad[i] ^ 0x5cU;
    }
    uint8_t inner[32];
    vs_sha256_ctx ctx;
    vs_sha256_init(&ctx);
    vs_sha256_update(&ctx, ipad, 64);
    vs_sha256_update(&ctx, msg, msg_len);
    vs_sha256_final(&ctx, inner);

    vs_sha256_init(&ctx);
    vs_sha256_update(&ctx, opad, 64);
    vs_sha256_update(&ctx, inner, 32);
    vs_sha256_final(&ctx, out);

    vs_secure_zero(kpad, sizeof(kpad));
    vs_secure_zero(ipad, sizeof(ipad));
    vs_secure_zero(opad, sizeof(opad));
    vs_secure_zero(inner, sizeof(inner));
}

static inline void vs_hkdf_sha256_32(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t out_okm[32]
) {
    uint8_t prk[32];
    vs_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (i < 32 ? prk[i] : 0) ^ 0x36U;
        opad[i] = (i < 32 ? prk[i] : 0) ^ 0x5cU;
    }
    uint8_t one = 0x01U;
    uint8_t inner[32];
    vs_sha256_ctx ctx;
    vs_sha256_init(&ctx);
    vs_sha256_update(&ctx, ipad, 64);
    vs_sha256_update(&ctx, info, info_len);
    vs_sha256_update(&ctx, &one, 1);
    vs_sha256_final(&ctx, inner);

    vs_sha256_init(&ctx);
    vs_sha256_update(&ctx, opad, 64);
    vs_sha256_update(&ctx, inner, 32);
    vs_sha256_final(&ctx, out_okm);

    vs_secure_zero(prk, sizeof(prk));
    vs_secure_zero(ipad, sizeof(ipad));
    vs_secure_zero(opad, sizeof(opad));
    vs_secure_zero(inner, sizeof(inner));
}

/* ---- RFC 8439 ChaCha20 + Poly1305 AEAD ---- */
#define VS_QR(a, b, c, d) do { \
    a += b; d ^= a; d = vs_rotl32(d, 16); \
    c += d; b ^= c; b = vs_rotl32(b, 12); \
    a += b; d ^= a; d = vs_rotl32(d, 8);  \
    c += d; b ^= c; b = vs_rotl32(b, 7);  \
} while (0)

static void vs_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        vs_load32_le(key + 0),  vs_load32_le(key + 4),
        vs_load32_le(key + 8),  vs_load32_le(key + 12),
        vs_load32_le(key + 16), vs_load32_le(key + 20),
        vs_load32_le(key + 24), vs_load32_le(key + 28),
        counter,
        vs_load32_le(nonce + 0), vs_load32_le(nonce + 4), vs_load32_le(nonce + 8)
    };
    uint32_t x[16];
    memcpy(x, s, sizeof(s));
    for (int i = 0; i < 10; i++) {
        VS_QR(x[0], x[4], x[8],  x[12]);
        VS_QR(x[1], x[5], x[9],  x[13]);
        VS_QR(x[2], x[6], x[10], x[14]);
        VS_QR(x[3], x[7], x[11], x[15]);
        VS_QR(x[0], x[5], x[10], x[15]);
        VS_QR(x[1], x[6], x[11], x[12]);
        VS_QR(x[2], x[7], x[8],  x[13]);
        VS_QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++) {
        vs_store32_le(out + i * 4, x[i] + s[i]);
    }
    vs_secure_zero(x, sizeof(x));
    vs_secure_zero(s, sizeof(s));
}

#if VS_HAVE_X86_SIMD
VS_TARGET_FN("avx2")
static void vs_chacha20_blocks8_avx2(
    const uint8_t key[32], uint32_t ctr, const uint8_t nonce[12],
    const uint8_t *in, uint8_t *out, size_t n8
) {
    const __m256i c0 = _mm256_set1_epi32((int)0x61707865U);
    const __m256i c1 = _mm256_set1_epi32((int)0x3320646eU);
    const __m256i c2 = _mm256_set1_epi32((int)0x79622d32U);
    const __m256i c3 = _mm256_set1_epi32((int)0x6b206574U);
    const __m256i k0 = _mm256_set1_epi32((int)vs_load32_le(key + 0));
    const __m256i k1 = _mm256_set1_epi32((int)vs_load32_le(key + 4));
    const __m256i k2 = _mm256_set1_epi32((int)vs_load32_le(key + 8));
    const __m256i k3 = _mm256_set1_epi32((int)vs_load32_le(key + 12));
    const __m256i k4 = _mm256_set1_epi32((int)vs_load32_le(key + 16));
    const __m256i k5 = _mm256_set1_epi32((int)vs_load32_le(key + 20));
    const __m256i k6 = _mm256_set1_epi32((int)vs_load32_le(key + 24));
    const __m256i k7 = _mm256_set1_epi32((int)vs_load32_le(key + 28));
    const __m256i n0 = _mm256_set1_epi32((int)vs_load32_le(nonce + 0));
    const __m256i n1 = _mm256_set1_epi32((int)vs_load32_le(nonce + 4));
    const __m256i n2 = _mm256_set1_epi32((int)vs_load32_le(nonce + 8));
    const __m256i rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2
    );
    const __m256i rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3
    );
    const __m256i ctr_step = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);

#define VS_QR_AVX2(a, b, c, d) do { \
    a = _mm256_add_epi32(a, b); \
    d = _mm256_shuffle_epi8(_mm256_xor_si256(d, a), rot16); \
    c = _mm256_add_epi32(c, d); \
    { __m256i _t = _mm256_xor_si256(b, c); b = _mm256_or_si256(_mm256_slli_epi32(_t, 12), _mm256_srli_epi32(_t, 20)); } \
    a = _mm256_add_epi32(a, b); \
    d = _mm256_shuffle_epi8(_mm256_xor_si256(d, a), rot8); \
    c = _mm256_add_epi32(c, d); \
    { __m256i _t = _mm256_xor_si256(b, c); b = _mm256_or_si256(_mm256_slli_epi32(_t, 7), _mm256_srli_epi32(_t, 25)); } \
} while (0)

#define VS_XOR_GROUP_AVX2(r0, r1, r2, r3, s0, s1, s2, s3, off) do { \
    __m256i _x0 = _mm256_add_epi32(r0, s0); \
    __m256i _x1 = _mm256_add_epi32(r1, s1); \
    __m256i _x2 = _mm256_add_epi32(r2, s2); \
    __m256i _x3 = _mm256_add_epi32(r3, s3); \
    __m256i _t0 = _mm256_unpacklo_epi32(_x0, _x1); \
    __m256i _t1 = _mm256_unpackhi_epi32(_x0, _x1); \
    __m256i _t2 = _mm256_unpacklo_epi32(_x2, _x3); \
    __m256i _t3 = _mm256_unpackhi_epi32(_x2, _x3); \
    __m256i _q0 = _mm256_unpacklo_epi64(_t0, _t2); \
    __m256i _q1 = _mm256_unpackhi_epi64(_t0, _t2); \
    __m256i _q2 = _mm256_unpacklo_epi64(_t1, _t3); \
    __m256i _q3 = _mm256_unpackhi_epi64(_t1, _t3); \
    _mm_storeu_si128((__m128i *)(void *)(out + 0 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 0 * 64 + (off))), _mm256_castsi256_si128(_q0))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 1 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 1 * 64 + (off))), _mm256_castsi256_si128(_q1))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 2 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 2 * 64 + (off))), _mm256_castsi256_si128(_q2))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 3 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 3 * 64 + (off))), _mm256_castsi256_si128(_q3))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 4 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 4 * 64 + (off))), _mm256_extracti128_si256(_q0, 1))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 5 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 5 * 64 + (off))), _mm256_extracti128_si256(_q1, 1))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 6 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 6 * 64 + (off))), _mm256_extracti128_si256(_q2, 1))); \
    _mm_storeu_si128((__m128i *)(void *)(out + 7 * 64 + (off)), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(in + 7 * 64 + (off))), _mm256_extracti128_si256(_q3, 1))); \
} while (0)

    for (size_t i = 0; i < n8; i++) {
        const __m256i s12 = _mm256_add_epi32(_mm256_set1_epi32((int)ctr), ctr_step);
        __m256i x0 = c0, x1 = c1, x2 = c2, x3 = c3;
        __m256i x4 = k0, x5 = k1, x6 = k2, x7 = k3;
        __m256i x8 = k4, x9 = k5, x10 = k6, x11 = k7;
        __m256i x12 = s12, x13 = n0, x14 = n1, x15 = n2;
        for (int r = 0; r < 10; r++) {
            VS_QR_AVX2(x0, x4, x8, x12);
            VS_QR_AVX2(x1, x5, x9, x13);
            VS_QR_AVX2(x2, x6, x10, x14);
            VS_QR_AVX2(x3, x7, x11, x15);
            VS_QR_AVX2(x0, x5, x10, x15);
            VS_QR_AVX2(x1, x6, x11, x12);
            VS_QR_AVX2(x2, x7, x8, x13);
            VS_QR_AVX2(x3, x4, x9, x14);
        }
        VS_XOR_GROUP_AVX2(x0, x1, x2, x3, c0, c1, c2, c3, 0);
        VS_XOR_GROUP_AVX2(x4, x5, x6, x7, k0, k1, k2, k3, 16);
        VS_XOR_GROUP_AVX2(x8, x9, x10, x11, k4, k5, k6, k7, 32);
        VS_XOR_GROUP_AVX2(x12, x13, x14, x15, s12, n0, n1, n2, 48);
        in += 512;
        out += 512;
        ctr += 8U;
    }
#undef VS_QR_AVX2
#undef VS_XOR_GROUP_AVX2
    _mm256_zeroupper();
}

VS_TARGET_FN("avx512f")
static void vs_chacha20_blocks16_avx512(
    const uint8_t key[32], uint32_t ctr, const uint8_t nonce[12],
    const uint8_t *in, uint8_t *out, size_t n16
) {
    const __m512i c0 = _mm512_set1_epi32((int)0x61707865U);
    const __m512i c1 = _mm512_set1_epi32((int)0x3320646eU);
    const __m512i c2 = _mm512_set1_epi32((int)0x79622d32U);
    const __m512i c3 = _mm512_set1_epi32((int)0x6b206574U);
    const __m512i k0 = _mm512_set1_epi32((int)vs_load32_le(key + 0));
    const __m512i k1 = _mm512_set1_epi32((int)vs_load32_le(key + 4));
    const __m512i k2 = _mm512_set1_epi32((int)vs_load32_le(key + 8));
    const __m512i k3 = _mm512_set1_epi32((int)vs_load32_le(key + 12));
    const __m512i k4 = _mm512_set1_epi32((int)vs_load32_le(key + 16));
    const __m512i k5 = _mm512_set1_epi32((int)vs_load32_le(key + 20));
    const __m512i k6 = _mm512_set1_epi32((int)vs_load32_le(key + 24));
    const __m512i k7 = _mm512_set1_epi32((int)vs_load32_le(key + 28));
    const __m512i n0 = _mm512_set1_epi32((int)vs_load32_le(nonce + 0));
    const __m512i n1 = _mm512_set1_epi32((int)vs_load32_le(nonce + 4));
    const __m512i n2 = _mm512_set1_epi32((int)vs_load32_le(nonce + 8));

#define VS_QR_AVX512(a, b, c, d) do { \
    a = _mm512_add_epi32(a, b); \
    d = _mm512_rol_epi32(_mm512_xor_si512(d, a), 16); \
    c = _mm512_add_epi32(c, d); \
    b = _mm512_rol_epi32(_mm512_xor_si512(b, c), 12); \
    a = _mm512_add_epi32(a, b); \
    d = _mm512_rol_epi32(_mm512_xor_si512(d, a), 8); \
    c = _mm512_add_epi32(c, d); \
    b = _mm512_rol_epi32(_mm512_xor_si512(b, c), 7); \
} while (0)

#define VS_TRANSPOSE_GROUP_AVX512(r0, r1, r2, r3, s0, s1, s2, s3, q0, q1, q2, q3) \
    __m512i q0, q1, q2, q3; \
    do { \
        __m512i _x0 = _mm512_add_epi32(r0, s0); \
        __m512i _x1 = _mm512_add_epi32(r1, s1); \
        __m512i _x2 = _mm512_add_epi32(r2, s2); \
        __m512i _x3 = _mm512_add_epi32(r3, s3); \
        __m512i _t0 = _mm512_unpacklo_epi32(_x0, _x1); \
        __m512i _t1 = _mm512_unpackhi_epi32(_x0, _x1); \
        __m512i _t2 = _mm512_unpacklo_epi32(_x2, _x3); \
        __m512i _t3 = _mm512_unpackhi_epi32(_x2, _x3); \
        q0 = _mm512_unpacklo_epi64(_t0, _t2); \
        q1 = _mm512_unpackhi_epi64(_t0, _t2); \
        q2 = _mm512_unpacklo_epi64(_t1, _t3); \
        q3 = _mm512_unpackhi_epi64(_t1, _t3); \
    } while (0)

#define VS_STORE_COL_AVX512(g0, g1, g2, g3, col) do { \
    __m512i _u0 = _mm512_shuffle_i32x4(g0, g1, 0x44); \
    __m512i _u1 = _mm512_shuffle_i32x4(g0, g1, 0xEE); \
    __m512i _u2 = _mm512_shuffle_i32x4(g2, g3, 0x44); \
    __m512i _u3 = _mm512_shuffle_i32x4(g2, g3, 0xEE); \
    __m512i _b0  = _mm512_shuffle_i32x4(_u0, _u2, 0x88); \
    __m512i _b4  = _mm512_shuffle_i32x4(_u0, _u2, 0xDD); \
    __m512i _b8  = _mm512_shuffle_i32x4(_u1, _u3, 0x88); \
    __m512i _b12 = _mm512_shuffle_i32x4(_u1, _u3, 0xDD); \
    _mm512_storeu_si512((void *)(out + ((col) +  0) * 64), _mm512_xor_si512(_mm512_loadu_si512((const void *)(in + ((col) +  0) * 64)), _b0)); \
    _mm512_storeu_si512((void *)(out + ((col) +  4) * 64), _mm512_xor_si512(_mm512_loadu_si512((const void *)(in + ((col) +  4) * 64)), _b4)); \
    _mm512_storeu_si512((void *)(out + ((col) +  8) * 64), _mm512_xor_si512(_mm512_loadu_si512((const void *)(in + ((col) +  8) * 64)), _b8)); \
    _mm512_storeu_si512((void *)(out + ((col) + 12) * 64), _mm512_xor_si512(_mm512_loadu_si512((const void *)(in + ((col) + 12) * 64)), _b12)); \
} while (0)

    const __m512i ctr_inc = _mm512_set_epi32(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const __m512i ctr_step = _mm512_set1_epi32(16);
    __m512i s12 = _mm512_add_epi32(_mm512_set1_epi32((int)ctr), ctr_inc);
    for (size_t i = 0; i < n16; i++) {
        __m512i x0 = c0, x1 = c1, x2 = c2, x3 = c3;
        __m512i x4 = k0, x5 = k1, x6 = k2, x7 = k3;
        __m512i x8 = k4, x9 = k5, x10 = k6, x11 = k7;
        __m512i x12 = s12, x13 = n0, x14 = n1, x15 = n2;
        for (int r = 0; r < 10; r++) {
            VS_QR_AVX512(x0, x4, x8, x12);
            VS_QR_AVX512(x1, x5, x9, x13);
            VS_QR_AVX512(x2, x6, x10, x14);
            VS_QR_AVX512(x3, x7, x11, x15);
            VS_QR_AVX512(x0, x5, x10, x15);
            VS_QR_AVX512(x1, x6, x11, x12);
            VS_QR_AVX512(x2, x7, x8, x13);
            VS_QR_AVX512(x3, x4, x9, x14);
        }
        VS_TRANSPOSE_GROUP_AVX512(x0, x1, x2, x3, c0, c1, c2, c3, g0q0, g0q1, g0q2, g0q3);
        VS_TRANSPOSE_GROUP_AVX512(x4, x5, x6, x7, k0, k1, k2, k3, g1q0, g1q1, g1q2, g1q3);
        VS_TRANSPOSE_GROUP_AVX512(x8, x9, x10, x11, k4, k5, k6, k7, g2q0, g2q1, g2q2, g2q3);
        VS_TRANSPOSE_GROUP_AVX512(x12, x13, x14, x15, s12, n0, n1, n2, g3q0, g3q1, g3q2, g3q3);
        VS_STORE_COL_AVX512(g0q0, g1q0, g2q0, g3q0, 0);
        VS_STORE_COL_AVX512(g0q1, g1q1, g2q1, g3q1, 1);
        VS_STORE_COL_AVX512(g0q2, g1q2, g2q2, g3q2, 2);
        VS_STORE_COL_AVX512(g0q3, g1q3, g2q3, g3q3, 3);
        in += 1024;
        out += 1024;
        s12 = _mm512_add_epi32(s12, ctr_step);
    }
#undef VS_QR_AVX512
#undef VS_TRANSPOSE_GROUP_AVX512
#undef VS_STORE_COL_AVX512
    _mm256_zeroupper();
}
#endif

static void vs_chacha20_xor(
    const uint8_t key[32], uint32_t initial_counter, const uint8_t nonce[12],
    const uint8_t *in, uint8_t *out, size_t len
) {
    uint32_t ctr = initial_counter;
    size_t off = 0;
#if VS_HAVE_X86_SIMD
    if (len >= 1024U && vs_has_avx512f()) {
        size_t n16 = len / 1024U;
        vs_chacha20_blocks16_avx512(key, ctr, nonce, in, out, n16);
        off = n16 * 1024U;
        ctr += (uint32_t)(n16 * 16U);
    }
    if ((len - off) >= 512U && vs_has_avx2()) {
        size_t n8 = (len - off) / 512U;
        vs_chacha20_blocks8_avx2(key, ctr, nonce, in + off, out + off, n8);
        off += n8 * 512U;
        ctr += (uint32_t)(n8 * 8U);
    }
#endif
    uint8_t block[64];
    while (off < len) {
        vs_chacha20_block(key, ctr++, nonce, block);
        size_t rem = len - off;
        if (rem >= 64U) {
            for (int w = 0; w < 8; w++) {
                uint64_t x = vs_core_load64_le(in + off + (size_t)w * 8U) ^
                             vs_core_load64_le(block + (size_t)w * 8U);
                vs_core_store64_le(out + off + (size_t)w * 8U, x);
            }
            off += 64U;
        } else {
            for (size_t i = 0; i < rem; i++) {
                out[off + i] = in[off + i] ^ block[i];
            }
            off += rem;
        }
    }
    vs_secure_zero(block, sizeof(block));
}

#if defined(__SIZEOF_INT128__)
__extension__ typedef unsigned __int128 vs_u128;

typedef struct {
    uint64_t r[3];
    uint64_t h[3];
    uint64_t pad[2];
} vs_poly1305_state;

static void vs_poly1305_init(vs_poly1305_state *st, const uint8_t key[32]) {
    uint64_t t0 = vs_core_load64_le(key + 0) & 0x0ffffffc0fffffffULL;
    uint64_t t1 = vs_core_load64_le(key + 8) & 0x0ffffffc0ffffffcULL;
    st->r[0] = t0 & 0x0fffffffffffULL;
    st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0x0fffffffffffULL;
    st->r[2] = (t1 >> 24) & 0x03ffffffffffULL;
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->pad[0] = vs_core_load64_le(key + 16);
    st->pad[1] = vs_core_load64_le(key + 24);
}

static inline void vs_poly1305_mul_limbs(const uint64_t a[3], const uint64_t b[3], uint64_t out[3]) {
    const uint64_t r0 = b[0], r1 = b[1], r2 = b[2];
    const uint64_t s1 = r1 * 20ULL, s2 = r2 * 20ULL;
    vs_u128 d0 = (vs_u128)a[0] * r0 + (vs_u128)a[1] * s2 + (vs_u128)a[2] * s1;
    vs_u128 d1 = (vs_u128)a[0] * r1 + (vs_u128)a[1] * r0 + (vs_u128)a[2] * s2;
    vs_u128 d2 = (vs_u128)a[0] * r2 + (vs_u128)a[1] * r1 + (vs_u128)a[2] * r0;
    uint64_t c = (uint64_t)(d0 >> 44);
    uint64_t h0 = (uint64_t)d0 & 0x0fffffffffffULL;
    d1 += c;
    c = (uint64_t)(d1 >> 44);
    uint64_t h1 = (uint64_t)d1 & 0x0fffffffffffULL;
    d2 += c;
    c = (uint64_t)(d2 >> 42);
    uint64_t h2 = (uint64_t)d2 & 0x03ffffffffffULL;
    h0 += c * 5ULL;
    c = h0 >> 44; h0 &= 0x0fffffffffffULL; h1 += c;
    c = h1 >> 44; h1 &= 0x0fffffffffffULL; h2 += c;
    c = h2 >> 42; h2 &= 0x03ffffffffffULL; h0 += c * 5ULL;
    c = h0 >> 44; h0 &= 0x0fffffffffffULL; h1 += c;
    out[0] = h0;
    out[1] = h1;
    out[2] = h2;
}

#if VS_HAVE_X86_SIMD
static inline void vs_poly1305_limbs44_to_26(
    uint64_t v0, uint64_t v1, uint64_t v2, uint64_t x[5]
) {
    const uint64_t m44 = 0xfffffffffffULL;
    const uint64_t m42 = 0x3ffffffffffULL;
    uint64_t cy = v0 >> 44;
    v0 &= m44;
    v1 += cy;
    cy = v1 >> 44;
    v1 &= m44;
    v2 += cy;
    cy = v2 >> 42;
    v2 &= m42;
    v0 += cy * 5ULL;
    cy = v0 >> 44;
    v0 &= m44;
    v1 += cy;
    x[0] = v0 & 0x3ffffffULL;
    x[1] = (v0 >> 26) | ((v1 & 0xffULL) << 18);
    x[2] = (v1 >> 8) & 0x3ffffffULL;
    x[3] = (v1 >> 34) | ((v2 & 0xffffULL) << 10);
    x[4] = v2 >> 16;
}

VS_TARGET_FN("avx2")
static void vs_poly1305_blocks_avx2(vs_poly1305_state *st, const uint8_t *m, size_t aligned64) {
    uint64_t r2k[3], r3k[3], r4k[3];
    vs_poly1305_mul_limbs(st->r, st->r, r2k);
    vs_poly1305_mul_limbs(r2k, st->r, r3k);
    vs_poly1305_mul_limbs(r2k, r2k, r4k);

    uint64_t h26[5], r1_26[5], r2_26[5], r3_26[5], r4_26[5];
    vs_poly1305_limbs44_to_26(st->h[0], st->h[1], st->h[2], h26);
    vs_poly1305_limbs44_to_26(st->r[0], st->r[1], st->r[2], r1_26);
    vs_poly1305_limbs44_to_26(r2k[0], r2k[1], r2k[2], r2_26);
    vs_poly1305_limbs44_to_26(r3k[0], r3k[1], r3k[2], r3_26);
    vs_poly1305_limbs44_to_26(r4k[0], r4k[1], r4k[2], r4_26);

    const __m256i mask26 = _mm256_set1_epi64x(0x3ffffffLL);
    const __m256i hibit24 = _mm256_set1_epi64x((long long)(1ULL << 24));

    const __m256i r4_0 = _mm256_set1_epi64x((long long)r4_26[0]);
    const __m256i r4_1 = _mm256_set1_epi64x((long long)r4_26[1]);
    const __m256i r4_2 = _mm256_set1_epi64x((long long)r4_26[2]);
    const __m256i r4_3 = _mm256_set1_epi64x((long long)r4_26[3]);
    const __m256i r4_4 = _mm256_set1_epi64x((long long)r4_26[4]);
    const __m256i s4_1 = _mm256_set1_epi64x((long long)(r4_26[1] * 5ULL));
    const __m256i s4_2 = _mm256_set1_epi64x((long long)(r4_26[2] * 5ULL));
    const __m256i s4_3 = _mm256_set1_epi64x((long long)(r4_26[3] * 5ULL));
    const __m256i s4_4 = _mm256_set1_epi64x((long long)(r4_26[4] * 5ULL));

    #define VS_POLY_LOAD4(ptr, M0, M1, M2, M3, M4)                                                    \
        do {                                                                                          \
            __m256i v0_ = _mm256_loadu_si256((const __m256i *)((ptr) + 0));                           \
            __m256i v1_ = _mm256_loadu_si256((const __m256i *)((ptr) + 32));                          \
            __m256i lo_ = _mm256_permute4x64_epi64(_mm256_unpacklo_epi64(v0_, v1_), 0xD8);            \
            __m256i hi_ = _mm256_permute4x64_epi64(_mm256_unpackhi_epi64(v0_, v1_), 0xD8);            \
            (M0) = _mm256_and_si256(lo_, mask26);                                                     \
            (M1) = _mm256_and_si256(_mm256_srli_epi64(lo_, 26), mask26);                              \
            (M2) = _mm256_and_si256(                                                                  \
                _mm256_or_si256(_mm256_srli_epi64(lo_, 52), _mm256_slli_epi64(hi_, 12)), mask26);     \
            (M3) = _mm256_and_si256(_mm256_srli_epi64(hi_, 14), mask26);                              \
            (M4) = _mm256_or_si256(_mm256_srli_epi64(hi_, 40), hibit24);                              \
        } while (0)

    #define VS_POLY_MUL5(A0, A1, A2, A3, A4, R0, R1, R2, R3, R4, S1, S2, S3, S4, D0, D1, D2, D3, D4) \
        do {                                                                                          \
            (D0) = _mm256_add_epi64(                                                                  \
                _mm256_add_epi64(_mm256_mul_epu32((A0), (R0)), _mm256_mul_epu32((A1), (S4))),         \
                _mm256_add_epi64(                                                                     \
                    _mm256_mul_epu32((A2), (S3)),                                                     \
                    _mm256_add_epi64(_mm256_mul_epu32((A3), (S2)), _mm256_mul_epu32((A4), (S1))))); \
            (D1) = _mm256_add_epi64(                                                                  \
                _mm256_add_epi64(_mm256_mul_epu32((A0), (R1)), _mm256_mul_epu32((A1), (R0))),         \
                _mm256_add_epi64(                                                                     \
                    _mm256_mul_epu32((A2), (S4)),                                                     \
                    _mm256_add_epi64(_mm256_mul_epu32((A3), (S3)), _mm256_mul_epu32((A4), (S2))))); \
            (D2) = _mm256_add_epi64(                                                                  \
                _mm256_add_epi64(_mm256_mul_epu32((A0), (R2)), _mm256_mul_epu32((A1), (R1))),         \
                _mm256_add_epi64(                                                                     \
                    _mm256_mul_epu32((A2), (R0)),                                                     \
                    _mm256_add_epi64(_mm256_mul_epu32((A3), (S4)), _mm256_mul_epu32((A4), (S3))))); \
            (D3) = _mm256_add_epi64(                                                                  \
                _mm256_add_epi64(_mm256_mul_epu32((A0), (R3)), _mm256_mul_epu32((A1), (R2))),         \
                _mm256_add_epi64(                                                                     \
                    _mm256_mul_epu32((A2), (R1)),                                                     \
                    _mm256_add_epi64(_mm256_mul_epu32((A3), (R0)), _mm256_mul_epu32((A4), (S4))))); \
            (D4) = _mm256_add_epi64(                                                                  \
                _mm256_add_epi64(_mm256_mul_epu32((A0), (R4)), _mm256_mul_epu32((A1), (R3))),         \
                _mm256_add_epi64(                                                                     \
                    _mm256_mul_epu32((A2), (R2)),                                                     \
                    _mm256_add_epi64(_mm256_mul_epu32((A3), (R1)), _mm256_mul_epu32((A4), (R0))))); \
        } while (0)

    __m256i a0, a1, a2, a3, a4;
    VS_POLY_LOAD4(m, a0, a1, a2, a3, a4);
    a0 = _mm256_add_epi64(a0, _mm256_set_epi64x(0, 0, 0, (long long)h26[0]));
    a1 = _mm256_add_epi64(a1, _mm256_set_epi64x(0, 0, 0, (long long)h26[1]));
    a2 = _mm256_add_epi64(a2, _mm256_set_epi64x(0, 0, 0, (long long)h26[2]));
    a3 = _mm256_add_epi64(a3, _mm256_set_epi64x(0, 0, 0, (long long)h26[3]));
    a4 = _mm256_add_epi64(a4, _mm256_set_epi64x(0, 0, 0, (long long)h26[4]));

    size_t off = 64U;
    while (off < aligned64) {
        __m256i d0, d1, d2, d3, d4;
        VS_POLY_MUL5(
            a0, a1, a2, a3, a4,
            r4_0, r4_1, r4_2, r4_3, r4_4,
            s4_1, s4_2, s4_3, s4_4,
            d0, d1, d2, d3, d4
        );

        __m256i m0, m1, m2, m3, m4;
        VS_POLY_LOAD4(m + off, m0, m1, m2, m3, m4);

        __m256i cy = _mm256_srli_epi64(d0, 26);
        a0 = _mm256_and_si256(d0, mask26);
        d1 = _mm256_add_epi64(d1, cy);
        cy = _mm256_srli_epi64(d1, 26);
        a1 = _mm256_and_si256(d1, mask26);
        d2 = _mm256_add_epi64(d2, cy);
        cy = _mm256_srli_epi64(d2, 26);
        a2 = _mm256_and_si256(d2, mask26);
        d3 = _mm256_add_epi64(d3, cy);
        cy = _mm256_srli_epi64(d3, 26);
        a3 = _mm256_and_si256(d3, mask26);
        d4 = _mm256_add_epi64(d4, cy);
        cy = _mm256_srli_epi64(d4, 26);
        a4 = _mm256_and_si256(d4, mask26);
        a0 = _mm256_add_epi64(a0, _mm256_add_epi64(cy, _mm256_slli_epi64(cy, 2)));
        cy = _mm256_srli_epi64(a0, 26);
        a0 = _mm256_and_si256(a0, mask26);
        a1 = _mm256_add_epi64(a1, cy);

        a0 = _mm256_add_epi64(a0, m0);
        a1 = _mm256_add_epi64(a1, m1);
        a2 = _mm256_add_epi64(a2, m2);
        a3 = _mm256_add_epi64(a3, m3);
        a4 = _mm256_add_epi64(a4, m4);
        off += 64U;
    }

    const __m256i rf0 = _mm256_set_epi64x((long long)r1_26[0], (long long)r2_26[0], (long long)r3_26[0], (long long)r4_26[0]);
    const __m256i rf1 = _mm256_set_epi64x((long long)r1_26[1], (long long)r2_26[1], (long long)r3_26[1], (long long)r4_26[1]);
    const __m256i rf2 = _mm256_set_epi64x((long long)r1_26[2], (long long)r2_26[2], (long long)r3_26[2], (long long)r4_26[2]);
    const __m256i rf3 = _mm256_set_epi64x((long long)r1_26[3], (long long)r2_26[3], (long long)r3_26[3], (long long)r4_26[3]);
    const __m256i rf4 = _mm256_set_epi64x((long long)r1_26[4], (long long)r2_26[4], (long long)r3_26[4], (long long)r4_26[4]);
    const __m256i sf1 = _mm256_add_epi64(rf1, _mm256_slli_epi64(rf1, 2));
    const __m256i sf2 = _mm256_add_epi64(rf2, _mm256_slli_epi64(rf2, 2));
    const __m256i sf3 = _mm256_add_epi64(rf3, _mm256_slli_epi64(rf3, 2));
    const __m256i sf4 = _mm256_add_epi64(rf4, _mm256_slli_epi64(rf4, 2));

    __m256i fd0, fd1, fd2, fd3, fd4;
    VS_POLY_MUL5(
        a0, a1, a2, a3, a4,
        rf0, rf1, rf2, rf3, rf4,
        sf1, sf2, sf3, sf4,
        fd0, fd1, fd2, fd3, fd4
    );

    #undef VS_POLY_LOAD4
    #undef VS_POLY_MUL5

    #define VS_POLY_HSUM64(vec, out_u64)                                                       \
        do {                                                                                   \
            __m256i p1_ = _mm256_add_epi64((vec), _mm256_permute4x64_epi64((vec), 0x4E));      \
            __m256i p2_ = _mm256_add_epi64(p1_, _mm256_permute4x64_epi64(p1_, 0x01));          \
            (out_u64) = (uint64_t)_mm256_extract_epi64(p2_, 0);                                \
        } while (0)

    uint64_t u0, u1, u2, u3, u4;
    VS_POLY_HSUM64(fd0, u0);
    VS_POLY_HSUM64(fd1, u1);
    VS_POLY_HSUM64(fd2, u2);
    VS_POLY_HSUM64(fd3, u3);
    VS_POLY_HSUM64(fd4, u4);
    #undef VS_POLY_HSUM64

    _mm256_zeroupper();

    uint64_t cy;
    cy = u0 >> 26; u0 &= 0x3ffffffULL; u1 += cy;
    cy = u1 >> 26; u1 &= 0x3ffffffULL; u2 += cy;
    cy = u2 >> 26; u2 &= 0x3ffffffULL; u3 += cy;
    cy = u3 >> 26; u3 &= 0x3ffffffULL; u4 += cy;
    cy = u4 >> 26; u4 &= 0x3ffffffULL; u0 += cy * 5ULL;
    cy = u0 >> 26; u0 &= 0x3ffffffULL; u1 += cy;

    cy = u1 >> 26; u1 &= 0x3ffffffULL; u2 += cy;
    cy = u2 >> 26; u2 &= 0x3ffffffULL; u3 += cy;
    cy = u3 >> 26; u3 &= 0x3ffffffULL; u4 += cy;
    cy = u4 >> 26; u4 &= 0x3ffffffULL; u0 += cy * 5ULL;
    cy = u0 >> 26; u0 &= 0x3ffffffULL; u1 += cy;

    st->h[0] = u0 | ((u1 & 0x3ffffULL) << 26);
    st->h[1] = (u1 >> 18) | (u2 << 8) | ((u3 & 0x3ffULL) << 34);
    st->h[2] = (u3 >> 10) | (u4 << 16);
}
#endif

static void vs_poly1305_blocks(vs_poly1305_state *st, const uint8_t *m, size_t bytes, uint32_t hibit_flag) {
    const uint64_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2];
    const uint64_t s1 = r1 * 20ULL, s2 = r2 * 20ULL;
    const uint64_t hibit = (hibit_flag != 0U) ? (1ULL << 40) : 0ULL;
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];

#if VS_HAVE_X86_SIMD
    if (bytes >= 64U && hibit_flag != 0U && vs_has_avx2()) {
        const size_t aligned64 = bytes & ~(size_t)63U;
        vs_poly1305_blocks_avx2(st, m, aligned64);
        m += aligned64;
        bytes -= aligned64;
        h0 = st->h[0];
        h1 = st->h[1];
        h2 = st->h[2];
    }
#endif

    if (bytes >= 64U && hibit_flag != 0U) {
        uint64_t r2k[3], r3k[3], r4k[3];
        vs_poly1305_mul_limbs(st->r, st->r, r2k);
        vs_poly1305_mul_limbs(r2k, st->r, r3k);
        vs_poly1305_mul_limbs(r2k, r2k, r4k);
        const uint64_t r20 = r2k[0], r21 = r2k[1], r22 = r2k[2], s21 = r21 * 20ULL, s22 = r22 * 20ULL;
        const uint64_t r30 = r3k[0], r31 = r3k[1], r32 = r3k[2], s31 = r31 * 20ULL, s32 = r32 * 20ULL;
        const uint64_t r40 = r4k[0], r41 = r4k[1], r42 = r4k[2], s41 = r41 * 20ULL, s42 = r42 * 20ULL;

        while (bytes >= 64U) {
            uint64_t a0 = vs_core_load64_le(m + 0),  a1 = vs_core_load64_le(m + 8);
            uint64_t b0 = vs_core_load64_le(m + 16), b1 = vs_core_load64_le(m + 24);
            uint64_t c0 = vs_core_load64_le(m + 32), c1 = vs_core_load64_le(m + 40);
            uint64_t e0 = vs_core_load64_le(m + 48), e1 = vs_core_load64_le(m + 56);

            uint64_t f0 = h0 + (a0 & 0x0fffffffffffULL);
            uint64_t f1 = h1 + (((a0 >> 44) | (a1 << 20)) & 0x0fffffffffffULL);
            uint64_t f2 = h2 + ((a1 >> 24) | hibit);

            uint64_t m10 = b0 & 0x0fffffffffffULL;
            uint64_t m11 = ((b0 >> 44) | (b1 << 20)) & 0x0fffffffffffULL;
            uint64_t m12 = (b1 >> 24) | hibit;

            uint64_t m20 = c0 & 0x0fffffffffffULL;
            uint64_t m21 = ((c0 >> 44) | (c1 << 20)) & 0x0fffffffffffULL;
            uint64_t m22 = (c1 >> 24) | hibit;

            uint64_t m30 = e0 & 0x0fffffffffffULL;
            uint64_t m31 = ((e0 >> 44) | (e1 << 20)) & 0x0fffffffffffULL;
            uint64_t m32 = (e1 >> 24) | hibit;

            vs_u128 d0 = (vs_u128)f0 * r40  + (vs_u128)f1 * s42  + (vs_u128)f2 * s41
                       + (vs_u128)m10 * r30 + (vs_u128)m11 * s32 + (vs_u128)m12 * s31
                       + (vs_u128)m20 * r20 + (vs_u128)m21 * s22 + (vs_u128)m22 * s21
                       + (vs_u128)m30 * r0  + (vs_u128)m31 * s2  + (vs_u128)m32 * s1;
            vs_u128 d1 = (vs_u128)f0 * r41  + (vs_u128)f1 * r40  + (vs_u128)f2 * s42
                       + (vs_u128)m10 * r31 + (vs_u128)m11 * r30 + (vs_u128)m12 * s32
                       + (vs_u128)m20 * r21 + (vs_u128)m21 * r20 + (vs_u128)m22 * s22
                       + (vs_u128)m30 * r1  + (vs_u128)m31 * r0  + (vs_u128)m32 * s2;
            vs_u128 d2 = (vs_u128)f0 * r42  + (vs_u128)f1 * r41  + (vs_u128)f2 * r40
                       + (vs_u128)m10 * r32 + (vs_u128)m11 * r31 + (vs_u128)m12 * r30
                       + (vs_u128)m20 * r22 + (vs_u128)m21 * r21 + (vs_u128)m22 * r20
                       + (vs_u128)m30 * r2  + (vs_u128)m31 * r1  + (vs_u128)m32 * r0;

            uint64_t cy = (uint64_t)(d0 >> 44);
            h0 = (uint64_t)d0 & 0x0fffffffffffULL;
            d1 += cy;
            cy = (uint64_t)(d1 >> 44);
            h1 = (uint64_t)d1 & 0x0fffffffffffULL;
            d2 += cy;
            cy = (uint64_t)(d2 >> 42);
            h2 = (uint64_t)d2 & 0x03ffffffffffULL;
            h0 += cy * 5ULL;
            cy = h0 >> 44;
            h0 &= 0x0fffffffffffULL;
            h1 += cy;

            m += 64;
            bytes -= 64;
        }
    }

    while (bytes >= 16U) {
        uint64_t u0 = vs_core_load64_le(m + 0);
        uint64_t u1 = vs_core_load64_le(m + 8);
        uint64_t f0 = h0 + (u0 & 0x0fffffffffffULL);
        uint64_t f1 = h1 + (((u0 >> 44) | (u1 << 20)) & 0x0fffffffffffULL);
        uint64_t f2 = h2 + ((u1 >> 24) | hibit);

        vs_u128 d0 = (vs_u128)f0 * r0 + (vs_u128)f1 * s2 + (vs_u128)f2 * s1;
        vs_u128 d1 = (vs_u128)f0 * r1 + (vs_u128)f1 * r0 + (vs_u128)f2 * s2;
        vs_u128 d2 = (vs_u128)f0 * r2 + (vs_u128)f1 * r1 + (vs_u128)f2 * r0;

        uint64_t c = (uint64_t)(d0 >> 44);
        h0 = (uint64_t)d0 & 0x0fffffffffffULL;
        d1 += c;
        c = (uint64_t)(d1 >> 44);
        h1 = (uint64_t)d1 & 0x0fffffffffffULL;
        d2 += c;
        c = (uint64_t)(d2 >> 42);
        h2 = (uint64_t)d2 & 0x03ffffffffffULL;
        h0 += c * 5ULL;
        c = h0 >> 44;
        h0 &= 0x0fffffffffffULL;
        h1 += c;

        m += 16;
        bytes -= 16;
    }
    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
}

static void vs_poly1305_feed_padded(vs_poly1305_state *st, const uint8_t *data, size_t len) {
    size_t full = len & ~(size_t)15U;
    if (full > 0U) {
        vs_poly1305_blocks(st, data, full, 1U);
    }
    size_t rem = len & 15U;
    if (rem > 0U) {
        uint8_t blk[16];
        memset(blk, 0, 16);
        for (size_t i = 0U; i < rem; i++) {
            blk[i] = data[full + i];
        }
        vs_poly1305_blocks(st, blk, 16, 1U);
        vs_secure_zero(blk, sizeof(blk));
    }
}

static void vs_poly1305_finish(vs_poly1305_state *st, uint8_t mac[16]) {
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint64_t c = h1 >> 44; h1 &= 0x0fffffffffffULL; h2 += c;
    c = h2 >> 42; h2 &= 0x03ffffffffffULL; h0 += c * 5ULL;
    c = h0 >> 44; h0 &= 0x0fffffffffffULL; h1 += c;
    c = h1 >> 44; h1 &= 0x0fffffffffffULL; h2 += c;

    uint64_t g0 = h0 + 5ULL; c = g0 >> 44; g0 &= 0x0fffffffffffULL;
    uint64_t g1 = h1 + c;   c = g1 >> 44; g1 &= 0x0fffffffffffULL;
    uint64_t g2 = h2 + c - (1ULL << 42);

    uint64_t mask = (g2 >> 63) - 1ULL;
    uint64_t nmask = ~mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);

    uint64_t f0 = h0 | (h1 << 44);
    uint64_t f1 = (h1 >> 20) | (h2 << 24);
    vs_u128 s0 = (vs_u128)f0 + st->pad[0];
    vs_u128 s1 = (vs_u128)f1 + st->pad[1] + (s0 >> 64);
    vs_core_store64_le(mac + 0, (uint64_t)s0);
    vs_core_store64_le(mac + 8, (uint64_t)s1);
    vs_secure_zero(st, sizeof(*st));
}
#else
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
} vs_poly1305_state;

static void vs_poly1305_init(vs_poly1305_state *st, const uint8_t key[32]) {
    st->r[0] = (vs_load32_le(key + 0)) & 0x3ffffffU;
    st->r[1] = (vs_load32_le(key + 3) >> 2) & 0x3ffff03U;
    st->r[2] = (vs_load32_le(key + 6) >> 4) & 0x3ffc0ffU;
    st->r[3] = (vs_load32_le(key + 9) >> 6) & 0x3f03fffU;
    st->r[4] = (vs_load32_le(key + 12) >> 8) & 0x00fffffU;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    for (int i = 0; i < 4; i++) st->pad[i] = vs_load32_le(key + 16 + i * 4);
}

static void vs_poly1305_blocks(vs_poly1305_state *st, const uint8_t *m, size_t bytes, uint32_t hibit_flag) {
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5U, s2 = r2 * 5U, s3 = r3 * 5U, s4 = r4 * 5U;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t hibit = (hibit_flag != 0U) ? (1U << 24) : 0U;

    while (bytes >= 16) {
        h0 += (vs_load32_le(m + 0)) & 0x3ffffffU;
        h1 += (vs_load32_le(m + 3) >> 2) & 0x3ffffffU;
        h2 += (vs_load32_le(m + 6) >> 4) & 0x3ffffffU;
        h3 += (vs_load32_le(m + 9) >> 6) & 0x3ffffffU;
        h4 += (vs_load32_le(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffU; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffU; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffU; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffU; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffU; h0 += c * 5U;
        c = h0 >> 26; h0 &= 0x3ffffffU; h1 += c;

        m += 16;
        bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void vs_poly1305_feed_padded(vs_poly1305_state *st, const uint8_t *data, size_t len) {
    size_t full = len & ~(size_t)15U;
    if (full > 0) {
        vs_poly1305_blocks(st, data, full, 1U);
    }
    size_t rem = len - full;
    if (rem > 0) {
        uint8_t blk[16];
        memset(blk, 0, 16);
        memcpy(blk, data + full, rem);
        vs_poly1305_blocks(st, blk, 16, 1U);
        vs_secure_zero(blk, sizeof(blk));
    }
}

static void vs_poly1305_finish(vs_poly1305_state *st, uint8_t mac[16]) {
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffffU; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffU; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffU; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffU; h0 += c * 5U;
    c = h0 >> 26; h0 &= 0x3ffffffU; h1 += c;

    uint32_t g0 = h0 + 5U; c = g0 >> 26; g0 &= 0x3ffffffU;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffU;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffU;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffU;
    uint32_t g4 = h4 + c - (1U << 26);

    uint32_t mask = (g4 >> 31) - 1U;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f;
    f = (uint64_t)(h0 | (h1 << 26)) + st->pad[0];               vs_store32_le(mac + 0,  (uint32_t)f);
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + st->pad[1] + (f >> 32); vs_store32_le(mac + 4,  (uint32_t)f);
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + st->pad[2] + (f >> 32); vs_store32_le(mac + 8,  (uint32_t)f);
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + st->pad[3] + (f >> 32);  vs_store32_le(mac + 12, (uint32_t)f);
    vs_secure_zero(st, sizeof(*st));
}
#endif

static inline int vs_chacha20_poly1305_verify(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    const uint8_t tag[16]
) {
    if (!key || !nonce || !tag) return -1;
    if (aad_len > 0U && !aad) return -1;
    if (ct_len > 0U && !ct) return -1;
    if (ct_len > 0U && (uint64_t)((ct_len - 1U) / 64U) >= (uint64_t)(UINT32_MAX - 1U)) return -1;

    uint8_t otk[64];
    vs_chacha20_block(key, 0, nonce, otk);

    vs_poly1305_state st;
    vs_poly1305_init(&st, otk);
    vs_poly1305_feed_padded(&st, aad, aad_len);
    vs_poly1305_feed_padded(&st, ct, ct_len);

    uint8_t lens[16];
    vs_core_store64_le(lens + 0, (uint64_t)aad_len);
    vs_core_store64_le(lens + 8, (uint64_t)ct_len);
    vs_poly1305_blocks(&st, lens, 16, 1U);

    uint8_t computed[16];
    vs_poly1305_finish(&st, computed);
    vs_secure_zero(otk, sizeof(otk));

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (uint8_t)(computed[i] ^ tag[i]);
    }
    vs_secure_zero(computed, sizeof(computed));
    return (diff == 0U) ? 0 : -1;
}

static inline int vs_chacha20_poly1305_open(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t *plain_out
) {
    if (ct_len > 0U && !plain_out) return -1;
    if (vs_chacha20_poly1305_verify(key, nonce, aad, aad_len, ct, ct_len, tag) != 0) {
        return -1;
    }
    vs_chacha20_xor(key, 1, nonce, ct, plain_out, ct_len);
    return 0;
}

static inline int vs_hex_decode(const char *hex, uint8_t *out, size_t max_bytes) {
    size_t len = strlen(hex);
    if ((len & 1U) != 0 || (len / 2U) > max_bytes) return -1;
    for (size_t i = 0; i < len / 2U; i++) {
        uint8_t v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i * 2 + j];
            uint8_t nib;
            if (c >= '0' && c <= '9') nib = (uint8_t)(c - '0');
            else if (c >= 'a' && c <= 'f') nib = (uint8_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') nib = (uint8_t)(c - 'A' + 10);
            else return -1;
            v = (uint8_t)((v << 4) | nib);
        }
        out[i] = v;
    }
    return (int)(len / 2U);
}

static inline void vs_hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = H[(in[i] >> 4) & 0x0fU];
        out[i * 2 + 1] = H[in[i] & 0x0fU];
    }
    out[len * 2] = '\0';
}

#endif
