#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/prctl.h>
#elif !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vibeslayer.h"
#include "../../vibeslayer-suite/native_src/vs_crypto_core.h"

#define VS_V2_PREFIX_LEN 64U
#define VS_V2_CHUNK_PLAIN 65536U
#define VS_V2_PAD_QUANTUM 1024U
#define VS_V2_TRAILER_LEN 48U
#define VS_V2_INTERMEDIATE_REC (VS_V2_CHUNK_PLAIN + VS_V2_TRAILER_LEN)
#define VS_V2_MIN_FINAL_REC (VS_V2_PAD_QUANTUM + VS_V2_TRAILER_LEN)
#define VS_V2_MAX_FINAL_REC ((((4U + VS_V2_CHUNK_PLAIN + VS_V2_PAD_QUANTUM - 1U) / VS_V2_PAD_QUANTUM) * VS_V2_PAD_QUANTUM) + VS_V2_TRAILER_LEN)
#define VS_V2_MIN_TWO_CHUNKS (VS_V2_INTERMEDIATE_REC + VS_V2_MIN_FINAL_REC)
#define VS_V2_MAX_CHACHA_CHUNKS ((UINT64_C(1) << 46) - UINT64_C(1))

static void vs_store64_be(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static uint8_t vs_ct_diff32(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t d = 0U;
    for (size_t i = 0U; i < 32U; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d;
}

static size_t vs_fread_full(FILE *f, uint8_t *buf, size_t want) {
    size_t got = 0U;
    while (got < want) {
        size_t n = fread(buf + got, 1U, want - got, f);
        if (n == 0U) {
            break;
        }
        got += n;
    }
    return got;
}

#if !defined(_WIN32)
static int vs_write_all_fd(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0U;
    while (off < len) {
        ssize_t nw = write(fd, buf + off, len - off);
        if (nw < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)nw;
    }
    return 0;
}
#endif

VS_API int vs_harden_process(void) {
#ifdef __linux__
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#else
    return 0;
#endif
}

static int vs_unseal_vspk2_internal(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *expected_asset_id,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
) {
    if (!master_key32 || !expected_domain || !expected_context || !vspk_bytes || vspk_len < 40U) {
        return VS_ERR_AUTH;
    }
    if (memcmp(vspk_bytes, "VSPK2", 5U) != 0 || vspk_bytes[5] != 1U) {
        return VS_ERR_AUTH;
    }

    uint16_t dlen = (uint16_t)vspk_bytes[6] | ((uint16_t)vspk_bytes[7] << 8);
    uint16_t alen = (uint16_t)vspk_bytes[8] | ((uint16_t)vspk_bytes[9] << 8);
    uint16_t clen = (uint16_t)vspk_bytes[10] | ((uint16_t)vspk_bytes[11] << 8);
    size_t hdr_end = 40U + (size_t)dlen + (size_t)alen + (size_t)clen;
    if (vspk_len < hdr_end || dlen > 128U || alen > 128U || clen > 256U) {
        return VS_ERR_AUTH;
    }

    size_t ct_len = vspk_len - hdr_end;
    if (ct_len > (size_t)INT_MAX || plain_cap < ct_len || (!plain_out && ct_len > 0U)) {
        return VS_ERR_AUTH;
    }

    const uint8_t *dom_ptr = vspk_bytes + 40U;
    const uint8_t *aid_ptr = dom_ptr + dlen;
    const uint8_t *ctx_ptr = aid_ptr + alen;
    if (memchr(dom_ptr, '\0', dlen) != NULL ||
        memchr(aid_ptr, '\0', alen) != NULL ||
        memchr(ctx_ptr, '\0', clen) != NULL) {
        return VS_ERR_AUTH;
    }

    char domain[129], asset_id[129], context[257];
    memcpy(domain, dom_ptr, dlen); domain[dlen] = '\0';
    memcpy(asset_id, aid_ptr, alen); asset_id[alen] = '\0';
    memcpy(context, ctx_ptr, clen); context[clen] = '\0';

    if (strcmp(domain, expected_domain) != 0 ||
        strcmp(context, expected_context) != 0 ||
        (expected_asset_id != NULL && strcmp(asset_id, expected_asset_id) != 0)) {
        vs_secure_zero(domain, sizeof(domain));
        vs_secure_zero(asset_id, sizeof(asset_id));
        vs_secure_zero(context, sizeof(context));
        return VS_ERR_AUTH;
    }

    char info[600];
    int info_len = snprintf(info, sizeof(info), "VSPK2_V1|%s|%s|%s", domain, asset_id, context);
    if (info_len <= 0 || (size_t)info_len >= sizeof(info)) {
        vs_secure_zero(domain, sizeof(domain));
        vs_secure_zero(asset_id, sizeof(asset_id));
        vs_secure_zero(context, sizeof(context));
        return VS_ERR_AUTH;
    }

    uint8_t key32[32];
    vs_hkdf_sha256_32(
        master_key32, 32U,
        (const uint8_t *)asset_id, alen,
        (const uint8_t *)info, (size_t)info_len,
        key32
    );

    const uint8_t *nonce = vspk_bytes + 12U;
    const uint8_t *tag = vspk_bytes + 24U;
    const uint8_t *ct = vspk_bytes + hdr_end;

    int rc = vs_chacha20_poly1305_open(
        key32, nonce,
        (const uint8_t *)info, (size_t)info_len,
        ct, ct_len, tag, plain_out
    );
    vs_secure_zero(key32, sizeof(key32));
    vs_secure_zero(domain, sizeof(domain));
    vs_secure_zero(asset_id, sizeof(asset_id));
    vs_secure_zero(context, sizeof(context));
    vs_secure_zero(info, sizeof(info));
    if (rc != 0) {
        return VS_ERR_AUTH;
    }
    return (int)ct_len;
}

VS_API int vs_unseal_vspk2(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
) {
    return vs_unseal_vspk2_internal(
        master_key32, expected_domain, NULL, expected_context, vspk_bytes, vspk_len, plain_out, plain_cap
    );
}

VS_API int vs_unseal_vspk2_for_asset(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *expected_asset_id,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
) {
    if (!expected_asset_id) {
        return VS_ERR_AUTH;
    }
    return vs_unseal_vspk2_internal(
        master_key32, expected_domain, expected_asset_id, expected_context, vspk_bytes, vspk_len, plain_out, plain_cap
    );
}

VS_API int vs_unseal_vspk3(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *asset_id,
    const char *expected_context,
    const uint8_t *vspk_bytes,
    size_t vspk_len,
    uint8_t *plain_out,
    size_t plain_cap
) {
    const size_t prefix_len = 92U;
    const size_t pad_quantum = 1024U;
    if (!master_key32 || !expected_domain || !asset_id || !expected_context || !vspk_bytes) {
        return VS_ERR_AUTH;
    }
    if (vspk_len < prefix_len + pad_quantum) {
        return VS_ERR_AUTH;
    }
    size_t ct_len = vspk_len - prefix_len;
    if ((ct_len % pad_quantum) != 0U || ct_len > (size_t)INT_MAX) {
        return VS_ERR_AUTH;
    }

    size_t dlen = strlen(expected_domain);
    size_t alen = strlen(asset_id);
    size_t clen = strlen(expected_context);
    if (dlen > 4096U || alen > 4096U || clen > 4096U) {
        return VS_ERR_AUTH;
    }

    size_t info_len = 10U + 12U + dlen + alen + clen;
    size_t cmt_msg_len = 12U + info_len;
    size_t aad_len = 76U + info_len;
    size_t sub_info_len = info_len + 4U;
    size_t meta_len = info_len + sub_info_len + cmt_msg_len + aad_len;

    uint8_t stack_scratch[2048];
    uint8_t *heap_scratch = NULL;
    uint8_t *scratch = stack_scratch;
    if (meta_len > sizeof(stack_scratch)) {
        heap_scratch = (uint8_t *)malloc(meta_len);
        if (!heap_scratch) {
            return VS_ERR_AUTH;
        }
        scratch = heap_scratch;
    }
    uint8_t *info = scratch;
    uint8_t *sub_info = info + info_len;
    uint8_t *cmt_msg = sub_info + sub_info_len;
    uint8_t *aad = cmt_msg + cmt_msg_len;

    size_t p = 0U;
    memcpy(info + p, "VSPK3_CMT4", 10U); p += 10U;
    vs_store32_le(info + p, (uint32_t)dlen); p += 4U;
    if (dlen > 0U) { memcpy(info + p, expected_domain, dlen); p += dlen; }
    vs_store32_le(info + p, (uint32_t)alen); p += 4U;
    if (alen > 0U) { memcpy(info + p, asset_id, alen); p += alen; }
    vs_store32_le(info + p, (uint32_t)clen); p += 4U;
    if (clen > 0U) { memcpy(info + p, expected_context, clen); p += clen; }

    const uint8_t *salt = vspk_bytes + 0U;
    const uint8_t *nonce = vspk_bytes + 32U;
    const uint8_t *cmt4 = vspk_bytes + 44U;
    const uint8_t *tag = vspk_bytes + 76U;
    const uint8_t *ct = vspk_bytes + 92U;

    uint8_t enc_key[32], cmt_key[32], expected_cmt[32];
    memcpy(sub_info, info, info_len);
    memcpy(sub_info + info_len, "|ENC", 4U);
    vs_hkdf_sha256_32(master_key32, 32U, salt, 32U, sub_info, sub_info_len, enc_key);

    memcpy(sub_info + info_len, "|CMT", 4U);
    vs_hkdf_sha256_32(master_key32, 32U, salt, 32U, sub_info, sub_info_len, cmt_key);

    memcpy(cmt_msg, nonce, 12U);
    memcpy(cmt_msg + 12U, info, info_len);
    vs_hmac_sha256(cmt_key, 32U, cmt_msg, cmt_msg_len, expected_cmt);
    vs_secure_zero(cmt_key, sizeof(cmt_key));

    uint8_t diff = vs_ct_diff32(expected_cmt, cmt4);
    vs_secure_zero(expected_cmt, sizeof(expected_cmt));

    if (diff != 0U) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(scratch, meta_len);
        free(heap_scratch);
        return VS_ERR_AUTH;
    }

    memcpy(aad + 0U, salt, 32U);
    memcpy(aad + 32U, nonce, 12U);
    memcpy(aad + 44U, cmt4, 32U);
    memcpy(aad + 76U, info, info_len);

    uint8_t *inner = (uint8_t *)malloc(ct_len);
    if (!inner) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(scratch, meta_len);
        free(heap_scratch);
        return VS_ERR_AUTH;
    }

    int rc = vs_chacha20_poly1305_open(enc_key, nonce, aad, aad_len, ct, ct_len, tag, inner);
    vs_secure_zero(enc_key, sizeof(enc_key));
    vs_secure_zero(scratch, meta_len);
    free(heap_scratch);
    if (rc != 0) {
        vs_secure_zero(inner, ct_len);
        free(inner);
        return VS_ERR_AUTH;
    }

    uint32_t plain_len = vs_load32_le(inner);
    if (plain_len > (uint32_t)(ct_len - 4U) || (size_t)plain_len > plain_cap ||
        (plain_len > 0U && !plain_out)) {
        vs_secure_zero(inner, ct_len);
        free(inner);
        return VS_ERR_AUTH;
    }
    uint8_t pad_or = 0U;
    for (size_t i = 4U + (size_t)plain_len; i < ct_len; i++) {
        pad_or |= inner[i];
    }
    if (pad_or != 0U) {
        vs_secure_zero(inner, ct_len);
        free(inner);
        return VS_ERR_AUTH;
    }
    if (plain_len > 0U) {
        memcpy(plain_out, inner + 4U, (size_t)plain_len);
    }
    vs_secure_zero(inner, ct_len);
    free(inner);
    return (int)plain_len;
}

VS_API int64_t vs_unseal_vspk3_v2_chacha20_file(
    const uint8_t master_key32[32],
    const char *expected_domain,
    const char *asset_id,
    const char *expected_context,
    const char *in_path,
    const char *out_path
) {
    if (!master_key32 || !expected_domain || !asset_id || !expected_context || !in_path || !out_path) {
        return VS_ERR_AUTH;
    }
    size_t dlen = strlen(expected_domain);
    size_t alen = strlen(asset_id);
    size_t clen = strlen(expected_context);
    if (dlen > 4096U || alen > 4096U || clen > 4096U) {
        return VS_ERR_AUTH;
    }

    FILE *fin = fopen(in_path, "rb");
    if (!fin) {
        return VS_ERR_AUTH;
    }
    uint8_t prefix[VS_V2_PREFIX_LEN];
    if (vs_fread_full(fin, prefix, VS_V2_PREFIX_LEN) != VS_V2_PREFIX_LEN || ferror(fin)) {
        fclose(fin);
        return VS_ERR_AUTH;
    }
    const uint8_t *salt = prefix;
    const uint8_t *hdr_cmt = prefix + 32U;

    const char *tag_str = "VSPK3_V2_STREAM";
    const size_t tag_len = 15U;
    const char *alg_tag = "|CHACHA20P1305";
    const size_t alg_len = 14U;

    size_t info_len = tag_len + 12U + dlen + alen + clen;
    size_t sub_len = info_len + alg_len + 4U;
    size_t hdr_msg_len = 13U + 32U + alg_len + info_len;
    size_t ctx_msg_len = 13U + 32U + 12U + 8U + 1U + info_len + 16U;
    size_t aad_len = 64U + 9U + info_len;
    size_t meta_total = info_len + sub_len + hdr_msg_len + ctx_msg_len + aad_len;

    uint8_t *meta = (uint8_t *)malloc(meta_total);
    uint8_t *window = (uint8_t *)malloc(VS_V2_MIN_TWO_CHUNKS);
    uint8_t *plain_buf = (uint8_t *)malloc(VS_V2_MAX_FINAL_REC);
    if (!meta || !window || !plain_buf) {
        free(meta);
        free(window);
        free(plain_buf);
        fclose(fin);
        return VS_ERR_AUTH;
    }

    uint8_t *info = meta;
    uint8_t *sub_info = info + info_len;
    uint8_t *hdr_msg = sub_info + sub_len;
    uint8_t *ctx_msg = hdr_msg + hdr_msg_len;
    uint8_t *aad = ctx_msg + ctx_msg_len;

    size_t p = 0U;
    memcpy(info + p, tag_str, tag_len); p += tag_len;
    vs_store32_le(info + p, (uint32_t)dlen); p += 4U;
    if (dlen > 0U) { memcpy(info + p, expected_domain, dlen); p += dlen; }
    vs_store32_le(info + p, (uint32_t)alen); p += 4U;
    if (alen > 0U) { memcpy(info + p, asset_id, alen); p += alen; }
    vs_store32_le(info + p, (uint32_t)clen); p += 4U;
    if (clen > 0U) { memcpy(info + p, expected_context, clen); p += clen; }

    uint8_t enc_key[32], cmt_key[32], expected_hdr[32];
    memcpy(sub_info, info, info_len);
    memcpy(sub_info + info_len, alg_tag, alg_len);
    memcpy(sub_info + info_len + alg_len, "|ENC", 4U);
    vs_hkdf_sha256_32(master_key32, 32U, salt, 32U, sub_info, sub_len, enc_key);

    memcpy(sub_info + info_len + alg_len, "|CMT", 4U);
    vs_hkdf_sha256_32(master_key32, 32U, salt, 32U, sub_info, sub_len, cmt_key);

    p = 0U;
    memcpy(hdr_msg + p, "VSPK3_V2_HDR|", 13U); p += 13U;
    memcpy(hdr_msg + p, salt, 32U); p += 32U;
    memcpy(hdr_msg + p, alg_tag, alg_len); p += alg_len;
    memcpy(hdr_msg + p, info, info_len);
    vs_hmac_sha256(cmt_key, 32U, hdr_msg, hdr_msg_len, expected_hdr);

    if (vs_ct_diff32(expected_hdr, hdr_cmt) != 0U) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(cmt_key, sizeof(cmt_key));
        vs_secure_zero(expected_hdr, sizeof(expected_hdr));
        vs_secure_zero(meta, meta_total);
        free(meta);
        free(window);
        free(plain_buf);
        fclose(fin);
        return VS_ERR_AUTH;
    }

    /* Atomic 0600 sibling temp file (no process-global umask race) — never truncates out_path on auth failure. */
    size_t out_len = strlen(out_path);
    char *tmp_path = (char *)malloc(out_len + 48U);
    if (!tmp_path) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(cmt_key, sizeof(cmt_key));
        vs_secure_zero(expected_hdr, sizeof(expected_hdr));
        vs_secure_zero(meta, meta_total);
        free(meta);
        free(window);
        free(plain_buf);
        fclose(fin);
        return VS_ERR_AUTH;
    }
#if !defined(_WIN32)
    snprintf(tmp_path, out_len + 48U, "%s.vstmpXXXXXX", out_path);
    int out_fd = mkstemp(tmp_path);
    if (out_fd >= 0 && fchmod(out_fd, (mode_t)0600) != 0) {
        close(out_fd);
        unlink(tmp_path);
        out_fd = -1;
    }
    if (out_fd < 0) {
        free(tmp_path);
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(cmt_key, sizeof(cmt_key));
        vs_secure_zero(expected_hdr, sizeof(expected_hdr));
        vs_secure_zero(meta, meta_total);
        free(meta);
        free(window);
        free(plain_buf);
        fclose(fin);
        return VS_ERR_AUTH;
    }
#else
    HANDLE out_h = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0U; attempt < 16U; attempt++) {
        unsigned long long tick = (unsigned long long)GetTickCount64() ^ ((unsigned long long)attempt * 0x9E3779B97F4A7C15ULL);
        snprintf(tmp_path, out_len + 48U, "%s.vstmp.%lu.%llx", out_path, (unsigned long)GetCurrentProcessId(), tick);
        out_h = CreateFileA(
            tmp_path,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY,
            NULL
        );
        if (out_h != INVALID_HANDLE_VALUE) break;
    }
    if (out_h == INVALID_HANDLE_VALUE) {
        free(tmp_path);
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(cmt_key, sizeof(cmt_key));
        vs_secure_zero(expected_hdr, sizeof(expected_hdr));
        vs_secure_zero(meta, meta_total);
        free(meta);
        free(window);
        free(plain_buf);
        fclose(fin);
        return VS_ERR_AUTH;
    }
#endif

    size_t buffered = 0U;
    uint64_t chunk_index = 0U;
    int64_t total_plain = 0;
    int ok = 1;

    for (;;) {
        if (buffered < VS_V2_MIN_TWO_CHUNKS) {
            buffered += vs_fread_full(fin, window + buffered, VS_V2_MIN_TWO_CHUNKS - buffered);
            if (ferror(fin)) {
                ok = 0;
                break;
            }
        }
        if (buffered < VS_V2_MIN_FINAL_REC ||
            (buffered > VS_V2_MAX_FINAL_REC && buffered < VS_V2_MIN_TWO_CHUNKS)) {
            ok = 0;
            break;
        }

        int is_final = (buffered <= VS_V2_MAX_FINAL_REC) ? 1 : 0;
        if ((!is_final && chunk_index >= VS_V2_MAX_CHACHA_CHUNKS) ||
            (is_final && chunk_index > VS_V2_MAX_CHACHA_CHUNKS)) {
            ok = 0;
            break;
        }
        size_t ct_len = is_final ? (buffered - VS_V2_TRAILER_LEN) : VS_V2_CHUNK_PLAIN;
        if (is_final && (ct_len < VS_V2_PAD_QUANTUM || (ct_len % VS_V2_PAD_QUANTUM) != 0U)) {
            ok = 0;
            break;
        }

        const uint8_t *ct = window;
        const uint8_t *tag = window + ct_len;
        const uint8_t *ctx_cmt = window + ct_len + 16U;

        uint8_t nonce[12];
        memset(nonce, 0, sizeof(nonce));
        nonce[3] = (uint8_t)is_final;
        vs_store64_be(nonce + 4U, chunk_index);

        uint8_t idx_be[8];
        vs_store64_be(idx_be, chunk_index);
        uint8_t flag_b = (uint8_t)is_final;

        p = 0U;
        memcpy(ctx_msg + p, "VSPK3_V2_CTX|", 13U); p += 13U;
        memcpy(ctx_msg + p, salt, 32U); p += 32U;
        memcpy(ctx_msg + p, nonce, 12U); p += 12U;
        memcpy(ctx_msg + p, idx_be, 8U); p += 8U;
        ctx_msg[p++] = flag_b;
        memcpy(ctx_msg + p, info, info_len); p += info_len;
        memcpy(ctx_msg + p, tag, 16U);

        uint8_t expected_ctx[32];
        vs_hmac_sha256(cmt_key, 32U, ctx_msg, ctx_msg_len, expected_ctx);
        if (vs_ct_diff32(expected_ctx, ctx_cmt) != 0U) {
            vs_secure_zero(expected_ctx, sizeof(expected_ctx));
            ok = 0;
            break;
        }
        vs_secure_zero(expected_ctx, sizeof(expected_ctx));

        p = 0U;
        memcpy(aad + p, salt, 32U); p += 32U;
        memcpy(aad + p, hdr_cmt, 32U); p += 32U;
        memcpy(aad + p, idx_be, 8U); p += 8U;
        aad[p++] = flag_b;
        memcpy(aad + p, info, info_len);

        if (vs_chacha20_poly1305_open(enc_key, nonce, aad, aad_len, ct, ct_len, tag, plain_buf) != 0) {
            ok = 0;
            break;
        }

        if (!is_final) {
            if (total_plain > INT64_MAX - (int64_t)VS_V2_CHUNK_PLAIN) {
                ok = 0;
                break;
            }
#if !defined(_WIN32)
            if (vs_write_all_fd(out_fd, plain_buf, VS_V2_CHUNK_PLAIN) != 0) {
                ok = 0;
                break;
            }
#else
            {
                size_t off = 0U;
                while (off < VS_V2_CHUNK_PLAIN) {
                    DWORD written = 0U;
                    if (!WriteFile(out_h, plain_buf + off, (DWORD)(VS_V2_CHUNK_PLAIN - off), &written, NULL) || written == 0U) {
                        ok = 0;
                        break;
                    }
                    off += (size_t)written;
                }
                if (!ok) break;
            }
#endif
            total_plain += (int64_t)VS_V2_CHUNK_PLAIN;
            size_t remain = buffered - VS_V2_INTERMEDIATE_REC;
            memmove(window, window + VS_V2_INTERMEDIATE_REC, remain);
            buffered = remain;
            chunk_index++;
        } else {
            if (ct_len < 4U) {
                ok = 0;
                break;
            }
            uint32_t rem_len = vs_load32_le(plain_buf);
            if (rem_len > VS_V2_CHUNK_PLAIN || (size_t)rem_len + 4U > ct_len) {
                ok = 0;
                break;
            }
            uint8_t pad_or = 0U;
            for (size_t i = 4U + (size_t)rem_len; i < ct_len; i++) {
                pad_or |= plain_buf[i];
            }
            if (pad_or != 0U || total_plain > INT64_MAX - (int64_t)rem_len) {
                ok = 0;
                break;
            }
            if (rem_len > 0U) {
#if !defined(_WIN32)
                if (vs_write_all_fd(out_fd, plain_buf + 4U, (size_t)rem_len) != 0) {
                    ok = 0;
                    break;
                }
#else
                {
                    size_t off = 0U;
                    while (off < (size_t)rem_len) {
                        DWORD written = 0U;
                        if (!WriteFile(out_h, plain_buf + 4U + off, (DWORD)((size_t)rem_len - off), &written, NULL) || written == 0U) {
                            ok = 0;
                            break;
                        }
                        off += (size_t)written;
                    }
                    if (!ok) break;
                }
#endif
            }
            total_plain += (int64_t)rem_len;
            break;
        }
    }

    fclose(fin);
#if !defined(_WIN32)
    if (ok) {
        if (fsync(out_fd) != 0) ok = 0;
    }
    if (close(out_fd) != 0) ok = 0;
    if (ok) {
        if (rename(tmp_path, out_path) != 0) ok = 0;
    }
    if (!ok) {
        unlink(tmp_path);
    }
    free(tmp_path);
#else
    if (ok) {
        if (!FlushFileBuffers(out_h)) ok = 0;
    }
    if (!CloseHandle(out_h)) ok = 0;
    if (ok) {
        if (!MoveFileExA(tmp_path, out_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) ok = 0;
    }
    if (!ok) {
        DeleteFileA(tmp_path);
    }
    free(tmp_path);
#endif
    vs_secure_zero(enc_key, sizeof(enc_key));
    vs_secure_zero(cmt_key, sizeof(cmt_key));
    vs_secure_zero(expected_hdr, sizeof(expected_hdr));
    vs_secure_zero(meta, meta_total);
    vs_secure_zero(window, VS_V2_MIN_TWO_CHUNKS);
    vs_secure_zero(plain_buf, VS_V2_MAX_FINAL_REC);
    free(meta);
    free(window);
    free(plain_buf);
    return ok ? total_plain : VS_ERR_AUTH;
}
