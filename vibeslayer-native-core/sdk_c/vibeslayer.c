#ifdef __linux__
#define _GNU_SOURCE
#include <sys/prctl.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vibeslayer.h"
#include "../../vibeslayer-suite/native_src/vs_crypto_core.h"

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
    if (!master_key32 || !expected_domain || !expected_context || !vspk_bytes || vspk_len < 40) {
        return -1;
    }
    if (memcmp(vspk_bytes, "VSPK2", 5) != 0 || vspk_bytes[5] != 1) {
        return -1;
    }

    uint16_t dlen = (uint16_t)vspk_bytes[6] | ((uint16_t)vspk_bytes[7] << 8);
    uint16_t alen = (uint16_t)vspk_bytes[8] | ((uint16_t)vspk_bytes[9] << 8);
    uint16_t clen = (uint16_t)vspk_bytes[10] | ((uint16_t)vspk_bytes[11] << 8);
    size_t hdr_end = 40U + (size_t)dlen + (size_t)alen + (size_t)clen;
    if (vspk_len < hdr_end || dlen > 128 || alen > 128 || clen > 256) {
        return -1;
    }

    size_t ct_len = vspk_len - hdr_end;
    if (ct_len > (size_t)INT_MAX || plain_cap < ct_len || (!plain_out && ct_len > 0)) {
        return -1;
    }

    const uint8_t *dom_ptr = vspk_bytes + 40;
    const uint8_t *aid_ptr = dom_ptr + dlen;
    const uint8_t *ctx_ptr = aid_ptr + alen;
    if (memchr(dom_ptr, '\0', dlen) != NULL ||
        memchr(aid_ptr, '\0', alen) != NULL ||
        memchr(ctx_ptr, '\0', clen) != NULL) {
        return -1;
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
        return -2;
    }

    char info[600];
    int info_len = snprintf(info, sizeof(info), "VSPK2_V1|%s|%s|%s", domain, asset_id, context);
    if (info_len <= 0 || (size_t)info_len >= sizeof(info)) {
        vs_secure_zero(domain, sizeof(domain));
        vs_secure_zero(asset_id, sizeof(asset_id));
        vs_secure_zero(context, sizeof(context));
        return -1;
    }

    uint8_t key32[32];
    vs_hkdf_sha256_32(
        master_key32, 32,
        (const uint8_t *)asset_id, alen,
        (const uint8_t *)info, (size_t)info_len,
        key32
    );

    const uint8_t *nonce = vspk_bytes + 12;
    const uint8_t *tag = vspk_bytes + 24;
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
        return -3;
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
        return -1;
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
        return -1;
    }
    if (vspk_len < prefix_len + pad_quantum) {
        return -1;
    }
    size_t ct_len = vspk_len - prefix_len;
    if ((ct_len % pad_quantum) != 0U || ct_len > (size_t)INT_MAX) {
        return -1;
    }

    size_t dlen = strlen(expected_domain);
    size_t alen = strlen(asset_id);
    size_t clen = strlen(expected_context);
    if (dlen > 4096U || alen > 4096U || clen > 4096U) {
        return -1;
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
            return -1;
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

    uint8_t diff = 0U;
    for (size_t i = 0U; i < 32U; i++) {
        diff |= (uint8_t)(expected_cmt[i] ^ cmt4[i]);
    }
    vs_secure_zero(expected_cmt, sizeof(expected_cmt));

    if (diff != 0U) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        vs_secure_zero(scratch, meta_len);
        free(heap_scratch);
        return -4;
    }

    memcpy(aad + 0U, salt, 32U);
    memcpy(aad + 32U, nonce, 12U);
    memcpy(aad + 44U, cmt4, 32U);
    memcpy(aad + 76U, info, info_len);

    int rc = vs_chacha20_poly1305_verify(enc_key, nonce, aad, aad_len, ct, ct_len, tag);
    vs_secure_zero(scratch, meta_len);
    free(heap_scratch);
    if (rc != 0) {
        vs_secure_zero(enc_key, sizeof(enc_key));
        return -3;
    }

    /* Authenticated: read block 1 on stack and decrypt directly into plain_out. */
    uint8_t blk1[64];
    vs_chacha20_block(enc_key, 1U, nonce, blk1);
    uint32_t plain_len = vs_load32_le(ct) ^ vs_load32_le(blk1);
    if (plain_len > (uint32_t)(ct_len - 4U) || (size_t)plain_len > plain_cap ||
        (plain_len > 0U && !plain_out)) {
        vs_secure_zero(blk1, sizeof(blk1));
        vs_secure_zero(enc_key, sizeof(enc_key));
        return -3;
    }

    size_t first_n = ((size_t)plain_len < 60U) ? (size_t)plain_len : 60U;
    for (size_t i = 0U; i < first_n; i++) {
        plain_out[i] = ct[4U + i] ^ blk1[4U + i];
    }
    vs_secure_zero(blk1, sizeof(blk1));
    if ((size_t)plain_len > first_n) {
        vs_chacha20_xor(
            enc_key, 2U, nonce,
            ct + 64U, plain_out + first_n,
            (size_t)plain_len - first_n
        );
    }
    vs_secure_zero(enc_key, sizeof(enc_key));
    return (int)plain_len;
}
