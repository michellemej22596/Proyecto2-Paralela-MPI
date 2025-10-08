#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h> 

static void set_odd_parity(unsigned char *k, int len) {
    for (int i = 0; i < len; ++i) {
        unsigned char b = k[i];
        int ones = __builtin_popcount((unsigned int)(b & 0xFE));
        if ((ones % 2) == 0)
            k[i] = (b & 0xFE) | 0x01;
        else
            k[i] = (b & 0xFE);
    }
}

static void make_des_key_from_56(uint64_t key56, unsigned char out[8]) {
    uint64_t tmp = key56;
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) {
        tmp <<= 1;
        k |= ((tmp & ((uint64_t)0xFE << (i * 8))));
    }
    for (int i = 0; i < 8; ++i)
        out[i] = (unsigned char)((k >> (i * 8)) & 0xFF);
    set_odd_parity(out, 8);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <plaintext.txt> <key56_decimal> -o <cipher.bin> [-p]\n", argv[0]);
        return 1;
    }

    /* Cargar provider legacy para habilitar DES-ECB (si aplica) */
    OSSL_PROVIDER *prov = NULL;
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    prov = OSSL_PROVIDER_load(NULL, "legacy");
    if (!prov) {
        fprintf(stderr, "Warning: no se pudo cargar provider 'legacy'\n");
    }
#endif

    char *infile = argv[1];
    uint64_t key56 = strtoull(argv[2], NULL, 0);
    char *outfile = "cipher.bin";
    int padding = 0;

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            outfile = argv[++i];
        else if (strcmp(argv[i], "-p") == 0)
            padding = 1;
    }

    FILE *fin = fopen(infile, "rb");
    if (!fin) {
        perror("fopen infile");
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long len = ftell(fin);
    rewind(fin);

    if (len <= 0) {
        fprintf(stderr, "Archivo de entrada vacío.\n");
        fclose(fin);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    unsigned char *plain = malloc((size_t)len);
    if (!plain) {
        perror("malloc");
        fclose(fin);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    /* Leer y verificar lectura completa */
    size_t got = fread(plain, 1, (size_t)len, fin);
    if (got != (size_t)len) {
        if (feof(fin)) {
            fprintf(stderr, "Advertencia: EOF inesperado (leídos %zu de %ld bytes)\n", got, len);
        } else if (ferror(fin)) {
            perror("fread");
        } else {
            fprintf(stderr, "Lectura incompleta: %zu/%ld\n", got, len);
        }
        /* ajustar len a los bytes realmente leídos */
        len = (long)got;
    }
    fclose(fin);

    unsigned char keybytes[8];
    make_des_key_from_56(key56, keybytes);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: no se pudo crear contexto EVP.\n");
        free(plain);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, keybytes, NULL) != 1) {
        fprintf(stderr, "Error en EncryptInit.\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, padding ? 1 : 0);

    unsigned char *cipher = malloc((size_t)len + 16);
    if (!cipher) {
        perror("malloc cipher");
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    int outlen1 = 0, outlen2 = 0;

    if (EVP_EncryptUpdate(ctx, cipher, &outlen1, plain, (int)len) != 1) {
        fprintf(stderr, "Error en EncryptUpdate.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(cipher);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    if (EVP_EncryptFinal_ex(ctx, cipher + outlen1, &outlen2) != 1) {
        /* si padding está desactivado y el tamaño no es múltiplo del bloque, puede fallar */
        fprintf(stderr, "Advertencia: EncryptFinal_ex retornó error (padding desactivado o bloque parcial)\n");
        ERR_print_errors_fp(stderr);
        /* podemos seguir usando lo que haya en outlen1; outlen2 se queda en 0 o no válido */
        outlen2 = 0;
    }

    int total = outlen1 + outlen2;

    FILE *fout = fopen(outfile, "wb");
    if (!fout) {
        perror("fopen outfile");
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(cipher);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    if (fwrite(cipher, 1, (size_t)total, fout) != (size_t)total) {
        perror("fwrite");
    }
    fclose(fout);

    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(cipher);

#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (prov) OSSL_PROVIDER_unload(prov);
#endif

    printf("Generado %s (bytes: %d) con key56=%llu (0x%llx), padding=%d\n",
           outfile, total, (unsigned long long)key56, (unsigned long long)key56, padding);

    return 0;
}
