#ifdef __linux__
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/prctl.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vs_crypto_core.h"

/*
 * Desktop Out-of-Process Native Enclave Sidecar (`vs_desktop_enclave` / `.exe`):
 * - Hardens itself with PR_SET_DUMPABLE=0 and MADV_DONTDUMP on Linux so Electron/Tauri
 *   renderer DevTools (Ctrl+Shift+I) and non-root ptrace/core dumps never access master rules.
 * - Accepts boot frame on line 1:
 *     <keyHex32> <nonceHex12> <tagHex16> <aadStr> <cipherHex>
 *   Unseals the enclave pricing config in protected memory, extracts `enterpriseUnitUsd`,
 *   and responds to IPC requests `<op> <seats>` without ever emitting `masterSalt`.
 */
int main(void) {
    int dumpable = -1;
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
#else
    dumpable = 0;
#endif

    char line[16384];
    if (!fgets(line, sizeof(line), stdin)) {
        vs_secure_zero(line, sizeof(line));
        return 1;
    }
    char key_hex[128], nonce_hex[64], tag_hex[64], aad[256], ct_hex[8192];
    if (sscanf(line, "%127s %63s %63s %255s %8191s", key_hex, nonce_hex, tag_hex, aad, ct_hex) != 5) {
        vs_secure_zero(line, sizeof(line));
        vs_secure_zero(key_hex, sizeof(key_hex));
        vs_secure_zero(nonce_hex, sizeof(nonce_hex));
        vs_secure_zero(tag_hex, sizeof(tag_hex));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(ct_hex, sizeof(ct_hex));
        printf("{\"ok\":false,\"code\":\"BAD_BOOT_FRAME\"}\n");
        fflush(stdout);
        return 2;
    }
    vs_secure_zero(line, sizeof(line));

    uint8_t key[32], nonce[12], tag[16];
    int hex_ok = (
        vs_hex_decode(key_hex, key, 32) == 32 &&
        vs_hex_decode(nonce_hex, nonce, 12) == 12 &&
        vs_hex_decode(tag_hex, tag, 16) == 16
    );
    vs_secure_zero(key_hex, sizeof(key_hex));
    vs_secure_zero(nonce_hex, sizeof(nonce_hex));
    vs_secure_zero(tag_hex, sizeof(tag_hex));
    if (!hex_ok) {
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(ct_hex, sizeof(ct_hex));
        printf("{\"ok\":false,\"code\":\"BAD_BOOT_HEX\"}\n");
        fflush(stdout);
        return 2;
    }

    size_t ct_hex_len = strlen(ct_hex);
    size_t ct_len = ct_hex_len / 2U;
    size_t alloc_len = 4096U;
    if ((ct_hex_len & 1U) != 0 || ct_len >= alloc_len) {
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(ct_hex, sizeof(ct_hex));
        printf("{\"ok\":false,\"code\":\"BAD_CT_BOUNDS\"}\n");
        fflush(stdout);
        return 2;
    }

    uint8_t *ct = (uint8_t *)malloc(ct_len + 1U);
    if (!ct) {
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(ct_hex, sizeof(ct_hex));
        return 3;
    }
    if (vs_hex_decode(ct_hex, ct, ct_len) != (int)ct_len) {
        free(ct);
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        vs_secure_zero(ct_hex, sizeof(ct_hex));
        printf("{\"ok\":false,\"code\":\"BAD_CT_HEX\"}\n");
        fflush(stdout);
        return 2;
    }
    vs_secure_zero(ct_hex, sizeof(ct_hex));

#ifdef __linux__
    uint8_t *secret_page = (uint8_t *)mmap(NULL, alloc_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secret_page == MAP_FAILED) {
        vs_secure_zero(ct, ct_len + 1U);
        free(ct);
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        return 3;
    }
    (void)mlock(secret_page, alloc_len);
#ifdef MADV_DONTDUMP
    madvise(secret_page, alloc_len, MADV_DONTDUMP);
#endif
#else
    uint8_t *secret_page = (uint8_t *)malloc(alloc_len);
    if (!secret_page) {
        vs_secure_zero(ct, ct_len + 1U);
        free(ct);
        vs_secure_zero(key, sizeof(key));
        vs_secure_zero(aad, sizeof(aad));
        return 3;
    }
#endif

    int rc = vs_chacha20_poly1305_open(
        key, nonce,
        (const uint8_t *)aad, strlen(aad),
        ct, ct_len, tag, secret_page
    );
    vs_secure_zero(key, sizeof(key));
    vs_secure_zero(aad, sizeof(aad));
    vs_secure_zero(ct, ct_len + 1U);
    free(ct);

    if (rc != 0) {
        vs_secure_zero(secret_page, alloc_len);
#ifdef __linux__
        (void)munlock(secret_page, alloc_len);
        munmap(secret_page, alloc_len);
#else
        free(secret_page);
#endif
        printf("{\"ok\":false,\"code\":\"ENCLAVE_AEAD_AUTH_FAILED\"}\n");
        fflush(stdout);
        return 3;
    }
    secret_page[ct_len] = '\0';

    /* Parse enterpriseUnitUsd integer inside enclave memory; never emit masterSalt */
    int unit_usd = 0;
    const char *p = strstr((const char *)secret_page, "\"enterpriseUnitUsd\":");
    if (p) {
        unit_usd = atoi(p + strlen("\"enterpriseUnitUsd\":"));
    }

    printf("{\"ok\":true,\"ready\":true,\"enclaveDumpable\":%d}\n", dumpable);
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin)) {
        char op[128];
        int seats = 0;
        if (strncmp(line, "SHUTDOWN", 8) == 0) {
            break;
        }
        if (sscanf(line, "%127s %d", op, &seats) == 2) {
            if (strcmp(op, "compute-license-quote") == 0 && seats >= 1 && seats <= 100000) {
                long total = (long)seats * (long)unit_usd;
                printf("{\"ok\":true,\"totalUsd\":%ld,\"enclaveDumpable\":%d}\n", total, dumpable);
            } else {
                printf("{\"ok\":false,\"code\":\"UNSUPPORTED_IPC_OP\"}\n");
            }
            fflush(stdout);
        } else {
            printf("{\"ok\":false,\"code\":\"BAD_IPC_FRAME\"}\n");
            fflush(stdout);
        }
    }

    vs_secure_zero(line, sizeof(line));
    vs_secure_zero(secret_page, alloc_len);
#ifdef __linux__
    (void)munlock(secret_page, alloc_len);
    munmap(secret_page, alloc_len);
#else
    free(secret_page);
#endif
    return 0;
}
