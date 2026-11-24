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

#ifdef __cplusplus
extern "C" {
#endif

VS_API int vs_harden_process(void);

/*
 * Unseals a `VSPK2` binary container produced by Rust, Go, Python, or C.
 * Returns >= 0 (plaintext byte length written to `plain_out`) on success,
 * or negative error code (`-1` header/args, `-2` domain/context denied, `-3` Poly1305 MAC failed).
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

/*
 * Unseals a `VSPK2` container while also binding & verifying `expected_asset_id`.
 * Returns >= 0 on success, or negative error code (`-1` header/args, `-2` policy/asset mismatch, `-3` MAC failed).
 */
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
 * Unseals a headerless key-committing `VSPK3` container produced by Rust or Go.
 * Verifies CMT-4 HMAC commitment in constant time before ChaCha20-Poly1305 AEAD
 * and unframes the 1024-byte pad-then-encrypt inner buffer.
 * Returns >= 0 (plaintext byte length written to `plain_out`) on success,
 * or negative error code (`-1` args/bounds, `-3` Poly1305/length fail, `-4` CMT-4 fail).
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

#ifdef __cplusplus
}
#endif

#endif
