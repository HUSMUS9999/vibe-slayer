#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vibeslayer.h"
#include "../../vibeslayer-suite/native_src/vs_crypto_core.h"

int main(int argc, char **argv) {
    int use_vspk3 = 0;
    int arg_off = 0;
    if (argc == 7 && strcmp(argv[1], "--vspk3") == 0) {
        use_vspk3 = 1;
        arg_off = 1;
    } else if (argc != 6) {
        fprintf(stderr, "Usage: test_c_sdk [--vspk3] <masterKeyHex> <domain> <assetId> <context> <vspkPath>\n");
        return 1;
    }
    vs_harden_process();

    uint8_t mk[32];
    if (vs_hex_decode(argv[1 + arg_off], mk, 32) != 32) {
        vs_secure_zero(mk, sizeof(mk));
        return 1;
    }

    FILE *f = fopen(argv[5 + arg_off], "rb");
    if (!f) {
        vs_secure_zero(mk, sizeof(mk));
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        vs_secure_zero(mk, sizeof(mk));
        return 1;
    }

    uint8_t *in_buf = (uint8_t *)malloc((size_t)sz);
    uint8_t *out_buf = (uint8_t *)malloc((size_t)sz);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        fclose(f);
        vs_secure_zero(mk, sizeof(mk));
        return 1;
    }
    if (fread(in_buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(in_buf);
        free(out_buf);
        fclose(f);
        vs_secure_zero(mk, sizeof(mk));
        return 1;
    }
    fclose(f);

    int plain_len;
    if (use_vspk3) {
        plain_len = vs_unseal_vspk3(
            mk, argv[2 + arg_off], argv[3 + arg_off], argv[4 + arg_off],
            in_buf, (size_t)sz, out_buf, (size_t)sz
        );
    } else {
        plain_len = vs_unseal_vspk2_for_asset(
            mk, argv[2 + arg_off], argv[3 + arg_off], argv[4 + arg_off],
            in_buf, (size_t)sz, out_buf, (size_t)sz
        );
    }
    vs_secure_zero(mk, sizeof(mk));
    if (plain_len < 0) {
        vs_secure_zero(out_buf, (size_t)sz);
        free(in_buf);
        free(out_buf);
        return 2;
    }

    if (plain_len > 0) {
        fwrite(out_buf, 1, (size_t)plain_len, stdout);
    }
    vs_secure_zero(out_buf, (size_t)sz);
    free(in_buf);
    free(out_buf);
    return 0;
}
