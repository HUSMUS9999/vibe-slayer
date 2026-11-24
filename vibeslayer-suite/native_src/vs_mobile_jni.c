#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#endif
#include "vs_crypto_core.h"

#if defined(__GNUC__)
#define VS_EXPORT __attribute__((visibility("default")))
#else
#define VS_EXPORT
#endif

/*
 * Mobile Native Shared Library (`libvsmobile.so`):
 * Binds ChaCha20-Poly1305 VSPK asset unsealing via HKDF-SHA256 to:
 *   (leaseBaseKey32, packageName, runtimeApkSigningCertSha256Hex, assetId)
 * Repackaging an APK changes the APK signing certificate SHA-256 -> HKDF produces
 * an unrelated 256-bit key -> RFC 8439 Poly1305 MAC fails (-2).
 */
VS_EXPORT int vs_mobile_harden_process(void) {
#ifdef __linux__
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#else
    return 0;
#endif
}

VS_EXPORT int vs_mobile_unseal_asset(
    const uint8_t *lease_root_key32,
    const char *package_name,
    const char *runtime_apk_cert_sha256_hex,
    const char *asset_id,
    const uint8_t *nonce12,
    const uint8_t *tag16,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plain_out
) {
    if (!lease_root_key32 || !package_name || !runtime_apk_cert_sha256_hex ||
        !asset_id || !nonce12 || !tag16 || (!ciphertext && ciphertext_len > 0) || !plain_out) {
        return -1;
    }

    char info[512];
    int info_len = snprintf(
        info, sizeof(info),
        "VS_MOBILE_V1|%s|%s|%s",
        package_name, runtime_apk_cert_sha256_hex, asset_id
    );
    if (info_len <= 0 || (size_t)info_len >= sizeof(info)) {
        return -1;
    }

    uint8_t derived_key[32];
    vs_hkdf_sha256_32(
        lease_root_key32, 32,
        (const uint8_t *)asset_id, strlen(asset_id),
        (const uint8_t *)info, (size_t)info_len,
        derived_key
    );

    int rc = vs_chacha20_poly1305_open(
        derived_key,
        nonce12,
        (const uint8_t *)info, (size_t)info_len,
        ciphertext, ciphertext_len,
        tag16,
        plain_out
    );

    vs_secure_zero(derived_key, sizeof(derived_key));
    vs_secure_zero(info, sizeof(info));
    return (rc == 0) ? 0 : -2;
}
