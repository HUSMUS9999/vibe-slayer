#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vs_crypto_core.h"

typedef int (*vs_mobile_harden_fn)(void);
typedef int (*vs_mobile_unseal_fn)(
    const uint8_t *lease_root_key32,
    const char *package_name,
    const char *runtime_apk_cert_sha256_hex,
    const char *asset_id,
    const uint8_t *nonce12,
    const uint8_t *tag16,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plain_out
);

static int read_stdin_field(char *buf, size_t cap) {
    if (!fgets(buf, (int)cap, stdin)) {
        return -1;
    }
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    return 0;
}

static void *load_sibling_mobile_so(void) {
    char exe_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n > 0) {
        exe_path[n] = '\0';
        char *slash = strrchr(exe_path, '/');
        if (slash != NULL) {
            char so_path[PATH_MAX];
            *slash = '\0';
            int w = snprintf(so_path, sizeof(so_path), "%s/libvsmobile.so", exe_path);
            if (w > 0 && (size_t)w < sizeof(so_path)) {
                void *h = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
                if (h != NULL) {
                    return h;
                }
            }
        }
    }
    return NULL;
}

/*
 * Thin CLI harness dynamically loading sibling `libvsmobile.so` without DT_RUNPATH.
 * Supports:
 *   vs_mobile_runner --stdin
 *     (7 lines: leaseKeyHex, pkgName, apkCertHex, assetId, nonceHex, tagHex, cipherHex)
 *   vs_mobile_runner <leaseKeyHex> <pkgName> <apkCertHex> <assetId> <nonceHex> <tagHex> <cipherHex>
 */
int main(int argc, char **argv) {
    void *so = load_sibling_mobile_so();
    if (!so) {
        fprintf(stderr, "MOBILE_SO_LOAD_FAILED\n");
        return 1;
    }
    vs_mobile_harden_fn p_harden = (vs_mobile_harden_fn)dlsym(so, "vs_mobile_harden_process");
    vs_mobile_unseal_fn p_unseal = (vs_mobile_unseal_fn)dlsym(so, "vs_mobile_unseal_asset");
    if (!p_harden || !p_unseal) {
        dlclose(so);
        fprintf(stderr, "MOBILE_SO_SYMBOL_MISSING\n");
        return 1;
    }
    p_harden();

    int stdin_mode = (argc == 2 && strcmp(argv[1], "--stdin") == 0);
    if (!stdin_mode && argc != 8) {
        dlclose(so);
        fprintf(stderr, "BAD_ARGS\n");
        return 1;
    }

    char *in_key = NULL;
    char *in_pkg = NULL;
    char *in_cert = NULL;
    char *in_asset = NULL;
    char *in_nonce = NULL;
    char *in_tag = NULL;
    char *in_ct = NULL;
    char *stdin_buf = NULL;

    if (stdin_mode) {
        const size_t ct_buf_cap = 1024U * 1024U;
        stdin_buf = (char *)malloc(2048U * 6U + ct_buf_cap);
        if (!stdin_buf) {
            dlclose(so);
            return 1;
        }
        in_key = stdin_buf;
        in_pkg = in_key + 256;
        in_cert = in_pkg + 512;
        in_asset = in_cert + 256;
        in_nonce = in_asset + 512;
        in_tag = in_nonce + 128;
        in_ct = in_tag + 128;
        if (read_stdin_field(in_key, 256) != 0 ||
            read_stdin_field(in_pkg, 512) != 0 ||
            read_stdin_field(in_cert, 256) != 0 ||
            read_stdin_field(in_asset, 512) != 0 ||
            read_stdin_field(in_nonce, 128) != 0 ||
            read_stdin_field(in_tag, 128) != 0 ||
            read_stdin_field(in_ct, ct_buf_cap) != 0) {
            vs_secure_zero(stdin_buf, 2048U * 6U + ct_buf_cap);
            free(stdin_buf);
            dlclose(so);
            fprintf(stderr, "BAD_STDIN_FRAME\n");
            return 1;
        }
    } else {
        in_key = argv[1];
        in_pkg = argv[2];
        in_cert = argv[3];
        in_asset = argv[4];
        in_nonce = argv[5];
        in_tag = argv[6];
        in_ct = argv[7];
    }

    uint8_t key32[32], nonce12[12], tag16[16];
    int dec_ok = (
        vs_hex_decode(in_key, key32, 32) == 32 &&
        vs_hex_decode(in_nonce, nonce12, 12) == 12 &&
        vs_hex_decode(in_tag, tag16, 16) == 16
    );
    vs_secure_zero(in_key, strlen(in_key));
    if (!dec_ok) {
        vs_secure_zero(key32, sizeof(key32));
        if (stdin_buf) {
            vs_secure_zero(stdin_buf, 2048U * 6U + 1024U * 1024U);
            free(stdin_buf);
        }
        dlclose(so);
        fprintf(stderr, "BAD_HEX\n");
        return 1;
    }

    size_t ct_hex_len = strlen(in_ct);
    size_t ct_len = ct_hex_len / 2U;
    uint8_t *ct = (uint8_t *)malloc(ct_len ? ct_len : 1U);
    uint8_t *pt = (uint8_t *)malloc(ct_len ? ct_len : 1U);
    if (!ct || !pt) {
        free(ct);
        free(pt);
        vs_secure_zero(key32, sizeof(key32));
        if (stdin_buf) {
            vs_secure_zero(stdin_buf, 2048U * 6U + 1024U * 1024U);
            free(stdin_buf);
        }
        dlclose(so);
        return 1;
    }

    int ct_rc = (ct_len > 0) ? vs_hex_decode(in_ct, ct, ct_len) : 0;
    if (!stdin_mode) {
        vs_secure_zero(in_ct, ct_hex_len);
    }
    if (ct_rc != (int)ct_len) {
        vs_secure_zero(key32, sizeof(key32));
        free(ct);
        free(pt);
        if (stdin_buf) {
            vs_secure_zero(stdin_buf, 2048U * 6U + 1024U * 1024U);
            free(stdin_buf);
        }
        dlclose(so);
        return 1;
    }

    int rc = p_unseal(
        key32, in_pkg, in_cert, in_asset,
        nonce12, tag16, ct, ct_len, pt
    );
    vs_secure_zero(key32, sizeof(key32));
    if (stdin_buf) {
        vs_secure_zero(stdin_buf, 2048U * 6U + 1024U * 1024U);
        free(stdin_buf);
    }

    if (rc != 0) {
        vs_secure_zero(pt, ct_len);
        free(ct);
        free(pt);
        dlclose(so);
        fprintf(stderr, "MOBILE_AUTH_TAG_FAILED\n");
        return 2;
    }

    char *out_hex = (char *)malloc(ct_len * 2U + 1U);
    if (!out_hex) {
        vs_secure_zero(pt, ct_len);
        free(ct);
        free(pt);
        dlclose(so);
        return 1;
    }
    vs_hex_encode(pt, ct_len, out_hex);
    printf("%s\n", out_hex);

    vs_secure_zero(out_hex, ct_len * 2U + 1U);
    vs_secure_zero(pt, ct_len);
    free(out_hex);
    free(ct);
    free(pt);
    dlclose(so);
    return 0;
}
