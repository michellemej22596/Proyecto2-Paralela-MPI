#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>
#endif

#define KEYSPACE_BITS_DEFAULT 56ULL
#define MAX_CIPHER_BYTES (1<<20) /* 1 MB */
#define CHUNK_SIZE 1024

/* ---------- parity/key ---------- */
static void set_odd_parity(unsigned char *k, int len) {
    for (int i = 0; i < len; ++i) {
        unsigned char b = k[i];
        int ones = __builtin_popcount((unsigned int)(b & 0xFE));
        if ((ones % 2) == 0) k[i] = (b & 0xFE) | 0x01;
        else k[i] = (b & 0xFE);
    }
}

static void make_des_key_from_56(uint64_t key56, unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)((key56 >> (8*i)) & 0xFFULL);
    set_odd_parity(out, 8);
}

/* ---------- EVP encrypt/decrypt helpers ---------- */
/* marcar como unused para evitar warning cuando no se compile TEST_TRYKEY */
static int __attribute__((unused)) des_encrypt_buffer_evpbased(uint64_t key56, const unsigned char *in, size_t len, unsigned char *out, int padding_enabled) {
    unsigned char keybytes[8];
    make_des_key_from_56(key56, keybytes);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, keybytes, NULL)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx, padding_enabled ? 1 : 0);

    int outlen = 0, tmplen = 0;
    if (1 != EVP_EncryptUpdate(ctx, out, &outlen, in, (int)len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, out + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

static int des_decrypt_buffer_evpbased(uint64_t key56, const unsigned char *in, unsigned char *out, size_t len, int padding_enabled) {
    unsigned char keybytes[8];
    make_des_key_from_56(key56, keybytes);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, keybytes, NULL)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx, padding_enabled ? 1 : 0);

    int outlen = 0, tmplen = 0;
    if (1 != EVP_DecryptUpdate(ctx, out, &outlen, in, (int)len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if (1 != EVP_DecryptFinal_ex(ctx, out + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

/* ---------- try_key (defensiva) ---------- */
static int try_key(uint64_t key56, const unsigned char *cipher, size_t cipher_len, const char *keyword, int padding_enabled, unsigned char *out_plain) {
    if(!cipher || cipher_len==0 || !keyword) return 0;
    unsigned char *plain = malloc(cipher_len + 64);
    if(!plain) return 0;
    memset(plain, 0, cipher_len + 64);
    int dec = des_decrypt_buffer_evpbased(key56, cipher, plain, cipher_len, padding_enabled);
    if(dec <= 0){ free(plain); return 0; }
    plain[dec] = '\0';
    int ok = (strstr((char*)plain, keyword) != NULL);
    if(ok && out_plain) { memcpy(out_plain, plain, dec); out_plain[dec] = '\0'; }
    free(plain);
    return ok;
}

/* ---------- usage ---------- */
static void usage(const char *p) {
    fprintf(stderr,
        "Uso: %s -f <cipher_file> -k <keyword> [-p] [-s] [--test-bits N] [--trials N]\n"
        " -f <cipher_file>  archivo binario con ciphertext\n"
        " -k <keyword>      palabra a buscar\n"
        " -p                activar padding\n"
        " -s                modo secuencial (solo rank 0)\n", p);
}

/* ---------- main ---------- */
int main(int argc, char *argv[]) {
    int rank=0, size=1;
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    OSSL_PROVIDER *legacy_prov = NULL;
#endif

    MPI_Init(&argc,&argv);
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);

    /* --- Inicialización OpenSSL y carga de provider legacy si aplica --- */
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    /* OpenSSL 3.x */
    OPENSSL_init_crypto(0, NULL);
    legacy_prov = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_prov) {
        if (rank == 0) fprintf(stderr, "[OPENSSL] No se pudo cargar provider 'legacy'.\n");
        ERR_print_errors_fp(stderr);
    }
#elif (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L)
    /* OpenSSL 1.1.x */
    OpenSSL_add_all_algorithms();
#else
    /* OpenSSL <1.1 */
    OpenSSL_add_all_algorithms();
#endif
    /* --------------------------------------------------------------- */

#ifdef TEST_TRYKEY
    if(rank == 0){
        printf("[TEST] Ejecutando prueba unitaria de tryKey...\n");
        const char *keyword = "frase_clave";
        const char *mensaje = "Este es un mensaje de prueba con la frase_clave incluida.";
        uint64_t test_key = 5;
        size_t msg_len = strlen(mensaje);

        unsigned char cipher[256];
        unsigned char plain[256];

        int clen = des_encrypt_buffer_evpbased(test_key, (const unsigned char*)mensaje, msg_len, cipher, 1);
        if(clen < 0){
            fprintf(stderr, "[TEST] Error cifrando mensaje\n");
            ERR_print_errors_fp(stderr);
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L)
            EVP_cleanup();
#endif
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
            if (legacy_prov) OSSL_PROVIDER_unload(legacy_prov);
#endif
            MPI_Finalize();
            return 1;
        }

        int ok = try_key(test_key, cipher, (size_t)clen, keyword, 1, plain);
        if(ok){
            printf("[TEST] tryKey detectó la clave %llu correctamente.\n", (unsigned long long)test_key);
            printf("[TEST] Plaintext recuperado: %s\n", plain);
        } else {
            printf("[TEST] tryKey falló en la detección.\n");
        }
    }
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_cleanup();
#endif
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (legacy_prov) OSSL_PROVIDER_unload(legacy_prov);
#endif
    MPI_Finalize();
    return 0;
#endif

    char *filename=NULL, *keyword=NULL;
    int padding_enabled = 0;
    int sequential_mode = 0;
    int test_bits = (int)KEYSPACE_BITS_DEFAULT;
    int trials = 1;

    /* parse args simple */
    for (int i=1;i<argc;++i) {
        if (strcmp(argv[i],"-f")==0 && i+1<argc) filename=argv[++i];
        else if (strcmp(argv[i],"-k")==0 && i+1<argc) keyword=argv[++i];
        else if (strcmp(argv[i],"-p")==0) padding_enabled=1;
        else if (strcmp(argv[i],"-s")==0) sequential_mode=1;
        else if (strcmp(argv[i],"--test-bits")==0 && i+1<argc) test_bits = atoi(argv[++i]);
        else if (strcmp(argv[i],"--trials")==0 && i+1<argc) trials = atoi(argv[++i]);
        else { usage(argv[0]); MPI_Finalize(); return 1; }
    }
    if(!filename || !keyword) { usage(argv[0]); MPI_Finalize(); return 1; }

    unsigned char *cipher = malloc(MAX_CIPHER_BYTES);
    if(!cipher){ fprintf(stderr,"malloc fail\n"); MPI_Finalize(); return 1; }
    FILE *fin = fopen(filename,"rb");
    if(!fin){ perror("fopen"); free(cipher); MPI_Finalize(); return 1; }
    size_t cipher_len = fread(cipher,1,MAX_CIPHER_BYTES,fin);
    fclose(fin);
    if(cipher_len==0){ fprintf(stderr,"Archivo vacio o ilegible\n"); free(cipher); MPI_Finalize(); return 1; }

    uint64_t upper = (test_bits >= 64) ? UINT64_MAX : (1ULL << (uint64_t)test_bits);

    for(int trial=0; trial<trials; ++trial){
        MPI_Barrier(MPI_COMM_WORLD);
        double t0 = MPI_Wtime();

        uint64_t local_found = 0;
        uint64_t global_found = 0;

        if(sequential_mode && rank==0){
            for(uint64_t k=0;k<upper;++k){
                if(try_key(k, cipher, cipher_len, keyword, padding_enabled, NULL)){
                    local_found = k; break;
                }
            }
        } else if(!sequential_mode){
            /* prefer round-robin intercalado por balance */
            uint64_t checked = 0;
            for(uint64_t k = (uint64_t)rank; k < upper; k += (uint64_t)size){
                if(try_key(k, cipher, cipher_len, keyword, padding_enabled, NULL)){
                    local_found = k; break;
                }
                ++checked;
                if((checked % CHUNK_SIZE) == 0){
                    MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
                    if(global_found) break;
                }
            }
        }

        /* final reduction to know any found */
        MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
        double t1 = MPI_Wtime();

        if(rank==0){
            if(global_found){
                unsigned char *plain = malloc(cipher_len+1);
                if(plain){
                    int dec = des_decrypt_buffer_evpbased(global_found, cipher, plain, cipher_len, padding_enabled);
                    if(dec > 0){
                        plain[dec]=0;
                        printf("[ROOT] Ensayo %d: Llave encontrada: %" PRIu64 "\nTexto:\n%s\n", trial+1, (uint64_t)global_found, plain);
                    } else {
                        printf("[ROOT] Ensayo %d: Llave encontrada: %" PRIu64 " pero fallo decrypt\n", trial+1, (uint64_t)global_found);
                    }
                    free(plain);
                }
            } else {
                printf("[ROOT] Ensayo %d: No encontrada. (Tiempo: %.6f s)\n", trial+1, t1 - t0);
            }
            printf("[ROOT] Tiempo wallclock ensayo %d: %.6f s\n", trial+1, t1 - t0);
        }
        MPI_Barrier(MPI_COMM_WORLD);
    } /* trials */

    free(cipher);

    /* --- Limpieza OpenSSL para versiones antiguas (1.0.x) --- */
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_cleanup();
#endif
#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (legacy_prov) OSSL_PROVIDER_unload(legacy_prov);
#endif
    /* ------------------------------------------------------- */

    MPI_Finalize();
    return 0;
}
