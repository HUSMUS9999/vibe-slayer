#ifndef VIBESLAYER_SDK_H
#define VIBESLAYER_SDK_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define VS_API __declspec(dllexport)
#elif defined(__GNUC__)
#define VS_API __attribute__((visibility("default")))
#else
#define VS_API
#endif

#define VS_ERR_AUTH (-1)

#ifdef __cplusplus
extern "C" {
#endif

VS_API int vs_harden_process(void);

/*
 * Legacy VSPK2 buffer unseal (kept for wire compatibility).
 * Returns >= 0 (plaintext bytes written) or VS_ERR_AUTH (-1) on any auth/bounds failure.
 */
VS_API int vs_unseal_vspk2(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
);

VS_API int vs_unseal_vspk2_for_asset(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *expected_asset_id,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
);

/*
 * Legacy VSPK3 v1 buffer unseal with unified opaque VS_ERR_AUTH (-1) on any failure
 * (eliminates CMT-4 vs AEAD vs padding error oracles).
 */
VS_API int vs_unseal_vspk3(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *asset_id,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
);

/*
 * 64-bit streaming VSPK3 v2 ChaCha20-Poly1305 + Bellare-Hoang Ctx/UtC CMT-4 file unseal.
 * Uses constant ~132 KiB RAM with NO 2 GiB INT_MAX cap (supports multi-terabyte files),
 * bit-for-bit wire-compatible with Rust `vs-vault::seal_vspk3_v2_stream(..., AeadAlg::ChaCha20Poly1305)`.
 * Returns plaintext byte count (>= 0) on success, or VS_ERR_AUTH (-1) on any error.
 */
VS_API int64_t vs_unseal_vspk3_v2_chacha20_file(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *asset_id,
    const char *expected_context,
    const char *in_path,
    const char *out_path
);

#ifdef __cplusplus
}
#endif

#endif
