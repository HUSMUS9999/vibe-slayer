#define _GNU_SOURCE
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include "vs_crypto_core.h"

extern const Elf64_Ehdr __ehdr_start;

typedef struct __attribute__((packed)) {
    uint8_t magic[8];       /* "VSBLB001" */
    uint32_t cipher_len;
    uint8_t nonce[12];
    uint8_t tag[16];
    char asset_id[64];
    uint8_t ciphertext[4096];
} vs_embedded_blob_t;

/*
 * Placed in read-only non-executable `.vsblob` section so build-time sealing
 * writes ciphertext/nonce/tag without altering a single byte of the RX code segment!
 */
__attribute__((section(".vsblob"), used, aligned(16)))
static const volatile vs_embedded_blob_t VS_SEALED_BLOB = {
    .magic = { 'V', 'S', 'B', 'L', 'B', '0', '0', '1' },
    .cipher_len = 0
};

__attribute__((constructor(101)))
static void vs_early_init_lock(void) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static int compute_live_rx_sha256(uint8_t out_hash[32]) {
    const Elf64_Ehdr *eh = &__ehdr_start;
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)eh + eh->e_phoff);
    uintptr_t first_vaddr = 0;
    int have_first = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            first_vaddr = (uintptr_t)ph[i].p_vaddr;
            have_first = 1;
            break;
        }
    }
    if (!have_first) return -1;
    uintptr_t load_bias = (uintptr_t)eh - first_vaddr;

    vs_sha256_ctx ctx;
    vs_sha256_init(&ctx);
    int found = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X) != 0) {
            vs_sha256_update(&ctx, (const uint8_t *)(load_bias + (uintptr_t)ph[i].p_vaddr), (size_t)ph[i].p_filesz);
            found = 1;
        }
    }
    if (!found) return -1;
    vs_sha256_final(&ctx, out_hash);
    return 0;
}

/* Padding function inside .text so tests can flip 1 instruction byte safely without crashing ELF init */
__attribute__((noinline, used))
int vs_hot_kernel_compute(const uint8_t *unsealed_cfg, size_t len) {
    uint32_t acc = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        acc ^= unsealed_cfg[i];
        acc *= 16777619U;
    }
    return (int)(acc & 0x7fffffffU);
}

int main(int argc, char **argv) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);

    if (argc < 2) {
        fprintf(stderr, "MISSING_NATIVE_LEASE\n");
        return 2;
    }

    uint8_t lease_key[32];
    size_t arg1_len = strlen(argv[1]);
    int dec_rc = vs_hex_decode(argv[1], lease_key, 32);
    vs_secure_zero(argv[1], arg1_len);
    if (dec_rc != 32) {
        vs_secure_zero(lease_key, sizeof(lease_key));
        fprintf(stderr, "MALFORMED_NATIVE_LEASE\n");
        return 2;
    }

    uint8_t rx_hash[32];
    if (compute_live_rx_sha256(rx_hash) != 0) {
        vs_secure_zero(lease_key, sizeof(lease_key));
        return 3;
    }
    char rx_hex[65];
    vs_hex_encode(rx_hash, 32, rx_hex);

    vs_embedded_blob_t snap;
    memcpy(&snap, (const void *)&VS_SEALED_BLOB, sizeof(snap));
    snap.asset_id[sizeof(snap.asset_id) - 1U] = '\0';
    if (snap.cipher_len == 0 || snap.cipher_len > sizeof(snap.ciphertext)) {
        vs_secure_zero(&snap, sizeof(snap));
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        vs_secure_zero(rx_hex, sizeof(rx_hex));
        vs_secure_zero(lease_key, sizeof(lease_key));
        return 3;
    }

    char info[192];
    int info_len = snprintf(info, sizeof(info), "VS_NATIVE_ELF_V1|%s|%s", snap.asset_id, rx_hex);
    if (info_len <= 0 || (size_t)info_len >= sizeof(info)) {
        vs_secure_zero(info, sizeof(info));
        vs_secure_zero(&snap, sizeof(snap));
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        vs_secure_zero(rx_hex, sizeof(rx_hex));
        vs_secure_zero(lease_key, sizeof(lease_key));
        return 3;
    }

    uint8_t content_key[32];
    vs_hkdf_sha256_32(
        lease_key, 32,
        (const uint8_t *)snap.asset_id, strlen(snap.asset_id),
        (const uint8_t *)info, (size_t)info_len,
        content_key
    );
    vs_secure_zero(lease_key, sizeof(lease_key));

    uint8_t *page = (uint8_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        vs_secure_zero(content_key, sizeof(content_key));
        vs_secure_zero(info, sizeof(info));
        vs_secure_zero(&snap, sizeof(snap));
        vs_secure_zero(rx_hash, sizeof(rx_hash));
        vs_secure_zero(rx_hex, sizeof(rx_hex));
        return 4;
    }
    (void)mlock(page, 4096);
#ifdef MADV_DONTDUMP
    madvise(page, 4096, MADV_DONTDUMP);
#endif

    int rc = vs_chacha20_poly1305_open(
        content_key,
        snap.nonce,
        (const uint8_t *)info, (size_t)info_len,
        snap.ciphertext, snap.cipher_len,
        snap.tag,
        page
    );
    vs_secure_zero(content_key, sizeof(content_key));
    vs_secure_zero(info, sizeof(info));
    vs_secure_zero(rx_hash, sizeof(rx_hash));
    vs_secure_zero(rx_hex, sizeof(rx_hex));

    if (rc != 0) {
        vs_secure_zero(&snap, sizeof(snap));
        vs_secure_zero(page, 4096);
        (void)munlock(page, 4096);
        munmap(page, 4096);
        fprintf(stderr, "NATIVE_AEAD_OR_CODE_INTEGRITY_FAILED\n");
        return 3;
    }

    int kernel_tag = vs_hot_kernel_compute(page, snap.cipher_len);
    uint8_t payload_sha[32];
    vs_sha256(page, snap.cipher_len, payload_sha);
    char payload_sha_hex[65];
    vs_hex_encode(payload_sha, 32, payload_sha_hex);

    printf(
        "{\"ok\":true,\"dumpable\":%d,\"kernelTag\":%d,\"payloadSha256\":\"%s\"}\n",
        dumpable, kernel_tag, payload_sha_hex
    );

    vs_secure_zero(payload_sha, sizeof(payload_sha));
    vs_secure_zero(payload_sha_hex, sizeof(payload_sha_hex));
    vs_secure_zero(&snap, sizeof(snap));
    vs_secure_zero(page, 4096);
    (void)munlock(page, 4096);
    munmap(page, 4096);
    return 0;
}
