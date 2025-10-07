/* bruteforce.c
   Versión corregida para OpenSSL 3 (carga providers),
   EVP-based DES-ECB, --test-bits, --partition, --create-cipher, MPI Irecv/Send.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#define DES_KEYSPACE_BITS_DEFAULT 56

/* ---------------------- helpers: file IO ---------------------- */

static unsigned char *read_binary_file(const char *path, size_t *out_len){
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END) != 0){ fclose(f); return NULL; }
    long len = ftell(f);
    if(len < 0){ fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)len);
    if(!buf){ fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if(r != (size_t)len){ free(buf); return NULL; }
    *out_len = (size_t)len;
    return buf;
}

static int write_binary_file(const char *path, const unsigned char *buf, size_t len){
    FILE *f = fopen(path, "wb");
    if(!f) return -1;
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    return (w == len) ? 0 : -1;
}

/* ---------------------- parity / key build ---------------------- */

/* Force odd parity on a single byte (lowest bit is parity bit) */
static void set_odd_parity_byte(unsigned char *b) {
    unsigned char v = *b & 0xFE; /* clear LSB (parity bit) for counting */
    int ones = __builtin_popcount((unsigned int)v);
    if ((ones & 1) == 0) /* even ones -> set parity bit to 1 to get odd total */
        *b = v | 0x01;
    else
        *b = v & 0xFE;
}

/* Convert low 56 bits of key56 into 8 bytes; then force odd parity on each byte.
   NOTE: simple byte-wise mapping (LSB first). */
static void uint64_to_des_key(uint64_t key56, unsigned char out[8]) {
    for(int i = 0; i < 8; ++i){
        out[i] = (unsigned char)((key56 >> (8 * i)) & 0xFFULL);
    }
    for(int i = 0; i < 8; ++i) set_odd_parity_byte(&out[i]);
}

/* ---------------------- EVP encrypt/decrypt wrappers ---------------------- */

/* Encrypt 'in' of length len into outbuf using DES-ECB and key derived from key56.
   If padding_enabled==0 then no padding (len must be multiple of 8).
   Returns number of output bytes on success, -1 on failure. */
static int encrypt_with_key_evpbased(uint64_t key56, const unsigned char *in, size_t len, unsigned char *outbuf, int padding_enabled){
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = EVP_des_ecb();
    unsigned char key[8];
    uint64_to_des_key(key56, key);

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return -1;
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if(!padding_enabled) EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen = 0, tmplen = 0;
    if(1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, in, (int)len)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if(1 != EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

/* Decrypt 'in' of length len into outbuf. outbuf must have room for len+1.
   Returns number of output bytes on success, -1 on failure. */
static int decrypt_with_key_evpbased(uint64_t key56, const unsigned char *in, size_t len, unsigned char *outbuf, int padding_enabled){
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = EVP_des_ecb();
    unsigned char key[8];
    uint64_to_des_key(key56, key);

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return -1;
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if(!padding_enabled) EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen = 0, tmplen = 0;
    if(1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, in, (int)len)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    if(1 != EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)){
        /* Final can fail if padding is wrong - signal error */
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

/* ---------------------- create cipher helper ---------------------- */

/* Create cipher file from plaintext file 'infile' using key (uint64 decimal).
   padding_enabled: if true, apply PKCS-like padding via EVP.
   Returns 0 on success, -1 on error. */
static int create_cipher_file(const char *infile, uint64_t key, const char *out_path, int padding_enabled){
    size_t plain_len = 0;
    unsigned char *plain = read_binary_file(infile, &plain_len);
    if(!plain) { fprintf(stderr, "create_cipher_file: no pude leer %s\n", infile); return -1; }

    /* If padding is disabled, pad to multiple of 8 with zeros */
    if(padding_enabled){
        unsigned char *outbuf = (unsigned char *)malloc(plain_len + 64);
        if(!outbuf){ free(plain); fprintf(stderr, "create_cipher_file: malloc failed\n"); return -1; }
        int outlen = encrypt_with_key_evpbased(key, plain, plain_len, outbuf, 1);
        if(outlen < 0){ free(plain); free(outbuf); fprintf(stderr, "create_cipher_file: encrypt error\n"); return -1; }
        int rc = write_binary_file(out_path, outbuf, (size_t)outlen);
        free(plain); free(outbuf);
        return rc;
    } else {
        size_t padded_len = ((plain_len + 7) / 8) * 8;
        unsigned char *tmp = (unsigned char *)calloc(1, padded_len);
        if(!tmp){ free(plain); return -1; }
        memcpy(tmp, plain, plain_len);
        unsigned char *outbuf = (unsigned char *)malloc(padded_len + 64);
        if(!outbuf){ free(tmp); free(plain); return -1; }
        int outlen = encrypt_with_key_evpbased(key, tmp, padded_len, outbuf, 0);
        if(outlen < 0){ free(tmp); free(plain); free(outbuf); return -1; }
        int rc = write_binary_file(out_path, outbuf, (size_t)outlen);
        free(tmp); free(plain); free(outbuf);
        return rc;
    }
}

/* ---------------------- tryKey: decrypt buffer and search keyword ---------------------- */
/* If decryption yields a plaintext containing keyword, return 1 and optionally copy plaintext into out_plain (must have room).
   Otherwise return 0. */
static int tryKey(uint64_t key56, const unsigned char *cipher, size_t cipher_len, const char *keyword, int padding_enabled, unsigned char *out_plain){
    unsigned char *tmp = (unsigned char *)malloc(cipher_len + 64);
    if(!tmp) return 0;
    int dec_len = decrypt_with_key_evpbased(key56, cipher, cipher_len, tmp, padding_enabled);
    if(dec_len <= 0){
        free(tmp); return 0;
    }
    if((size_t)dec_len >= cipher_len + 63) tmp[cipher_len + 63] = '\0';
    else tmp[dec_len] = '\0';
    int found = 0;
    if(keyword && strstr((char *)tmp, keyword) != NULL) found = 1;
    if(found && out_plain){
        memcpy(out_plain, tmp, dec_len);
        out_plain[dec_len] = '\0';
    }
    free(tmp);
    return found;
}

/* ---------------------- usage ---------------------- */
static void print_usage(const char *prog){
    printf("Uso:\n");
    printf("  Compilar: mpicc -O2 -Wall -std=c11 bruteforce.c -o bruteforce -lcrypto\n\n");
    printf("  Crear cipher: %s --create-cipher <plain.txt> <key_decimal> <out.bin> [--padding]\n", prog);
    printf("  Buscar llave (paralelo por defecto): mpirun -np <N> %s <cipher.bin> <keyword> [--test-bits N] [--partition=block|roundrobin] [-p]\n", prog);
    printf("  Buscar llave (secuencial): %s --mode=sequential <cipher.bin> <keyword> [--test-bits N] [-p]\n", prog);
    printf("\nNota: --test-bits N reduce el espacio de búsqueda a 2^N (para pruebas rápidas).\n");
}

/* ---------------------- main ---------------------- */

int main(int argc, char *argv[]){
    if(argc < 2){
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Load providers for OpenSSL 3 to ensure legacy ciphers (DES) are available */
#ifdef OPENSSL_VERSION_NUMBER
    /* Try to load default + legacy providers; ignore failures (but print if rank 0 later) */
    OSSL_PROVIDER *pdef = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *pleg = OSSL_PROVIDER_load(NULL, "legacy");
    (void)pdef; (void)pleg;
#endif

    MPI_Init(&argc, &argv);
    int Nprocs = 1, rank = 0;
    MPI_Comm_size(MPI_COMM_WORLD, &Nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* Handle create-cipher path quickly */
    if(strcmp(argv[1], "--create-cipher") == 0){
        if(argc < 5){
            if(rank==0) fprintf(stderr, "Uso: %s --create-cipher <plain.txt> <key_decimal> <out.bin> [--padding]\n", argv[0]);
            MPI_Finalize(); return EXIT_FAILURE;
        }
        const char *plain = argv[2];
        uint64_t key = (uint64_t)strtoull(argv[3], NULL, 10);
        const char *out = argv[4];
        int padding = 0;
        if(argc >= 6 && strcmp(argv[5], "--padding") == 0) padding = 1;
        if(rank == 0){
            if(create_cipher_file(plain, key, out, padding) == 0){
                printf("Generado %s con key=%" PRIu64 "\n", out, key);
            } else {
                fprintf(stderr, "Error generando %s\n", out);
            }
        }
        MPI_Finalize(); return EXIT_SUCCESS;
    }

    /* detect mode */
    int sequential_mode = 0;
    int argi = 1;
    if(strcmp(argv[argi], "--mode=sequential") == 0){
        sequential_mode = 1;
        argi++;
    }

    /* Remaining args: cipher_path keyword [--test-bits N] [-p] [--partition=...] */
    if(argc - argi < 2){
        if(rank==0) print_usage(argv[0]);
        MPI_Finalize(); return EXIT_FAILURE;
    }
    const char *cipher_path = argv[argi++];
    const char *keyword = argv[argi++];

    /* parse optional --test-bits or env var */
    int test_bits = DES_KEYSPACE_BITS_DEFAULT;
    char *env_tb = getenv("TEST_KEYSPACE_BITS");
    if(env_tb){
        int tb = atoi(env_tb);
        if(tb >= 1 && tb <= DES_KEYSPACE_BITS_DEFAULT) test_bits = tb;
    }
    /* parse argv for flags */
    int padding_enabled = 0;
    int use_roundrobin = 0;
    for(int i = argi; i < argc; ++i){
        if(strcmp(argv[i], "--test-bits") == 0 && i + 1 < argc){
            int tb = atoi(argv[++i]);
            if(tb >= 1 && tb <= DES_KEYSPACE_BITS_DEFAULT) test_bits = tb;
            else if(rank == 0) fprintf(stderr, "--test-bits debe estar entre 1 y %d\n", DES_KEYSPACE_BITS_DEFAULT);
        } else if(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--padding") == 0){
            padding_enabled = 1;
        } else if(strncmp(argv[i], "--partition=", 12) == 0){
            const char *val = argv[i] + 12;
            if(strcmp(val, "roundrobin") == 0) use_roundrobin = 1;
            else if(strcmp(val, "block") == 0) use_roundrobin = 0;
            else if(rank == 0) fprintf(stderr, "Unknown --partition value '%s' (using block)\n", val);
        } else {
            if(rank == 0) fprintf(stderr, "Warning: argumento desconocido '%s' (ignorando)\n", argv[i]);
        }
    }

    uint64_t keyspace_bits = (uint64_t)test_bits;
    uint64_t upper = (keyspace_bits >= 64) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << keyspace_bits);

    /* read cipher */
    size_t ciphlen = 0;
    unsigned char *cipher = read_binary_file(cipher_path, &ciphlen);
    if(!cipher){
        if(rank==0) fprintf(stderr, "Error leyendo archivo ciphertext: %s\n", cipher_path);
        MPI_Finalize(); return EXIT_FAILURE;
    }

    /* Prepare non-blocking receive for 'found' key (unsigned long long) */
    uint64_t found = 0;
    MPI_Request req;
    MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    double t0 = MPI_Wtime();

    if(sequential_mode && rank == 0){
        if(rank == 0) printf("[SEQUENTIAL] keyspace 2^%d = %" PRIu64 " claves\n", test_bits, upper);
        unsigned char *plain = (unsigned char *)malloc(ciphlen + 128);
        for(uint64_t k = 0; k < upper; ++k){
            if(tryKey(k, cipher, ciphlen, keyword, padding_enabled, plain)){
                found = k;
                printf("Llave encontrada: 0x%016" PRIx64 " (%" PRIu64 ")\nTexto:\n%s\n", (uint64_t)found, (uint64_t)found, (char *)plain);
                break;
            }
            if((k & 0xFFFFFFULL) == 0){
                /* allow cancel check */
                MPI_Test(&req, NULL, MPI_STATUS_IGNORE);
            }
        }
        free(plain);
    } else if(!sequential_mode){
        if(rank == 0){
            printf("[ROOT] Ejecutando paralelo con %d procesos, keyspace 2^%d (upper=%" PRIu64 ")\n", Nprocs, test_bits, upper);
            if(use_roundrobin) printf("[ROOT] particionado: round-robin\n");
            else printf("[ROOT] particionado: block\n");
        }

        if(use_roundrobin){
            uint64_t iter = 0;
            int flag = 0;
            unsigned char *plain = (unsigned char *)malloc(ciphlen + 128);
            for(uint64_t k = (uint64_t)rank; k < upper; k += (uint64_t)Nprocs){
                if((iter++ & 0xFFFF) == 0){
                    MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                    if(flag && found != 0) break;
                }
                if(tryKey(k, cipher, ciphlen, keyword, padding_enabled, plain)){
                    found = k;
                    for(int p = 0; p < Nprocs; ++p) MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, MPI_COMM_WORLD);
                    break;
                }
            }
            free(plain);
        } else {
            uint64_t per_proc = (upper / (uint64_t)Nprocs);
            if(per_proc == 0) per_proc = 1;
            uint64_t mylower = per_proc * (uint64_t)rank;
            uint64_t myupper = (rank == Nprocs - 1) ? (upper - 1) : (per_proc * (uint64_t)(rank + 1) - 1);
            uint64_t iter = 0;
            int flag = 0;
            unsigned char *plain = (unsigned char *)malloc(ciphlen + 128);
            for(uint64_t k = mylower; k <= myupper; ++k){
                if((iter++ & 0xFFFF) == 0){
                    MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                    if(flag && found != 0) break;
                }
                if(tryKey(k, cipher, ciphlen, keyword, padding_enabled, plain)){
                    found = k;
                    for(int p = 0; p < Nprocs; ++p) MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, MPI_COMM_WORLD);
                    break;
                }
            }
            free(plain);
        }
    } else {
        /* sequential_mode && rank != 0 : wait for possible found */
    }

    double t1 = MPI_Wtime();
    double elapsed = t1 - t0;

    if(rank == 0){
        MPI_Wait(&req, MPI_STATUS_IGNORE);
        if(found != 0){
            unsigned char *plain = (unsigned char *)malloc(ciphlen + 256);
            if(plain){
                int dec_len = decrypt_with_key_evpbased(found, cipher, ciphlen, plain, padding_enabled);
                if(dec_len > 0){
                    plain[dec_len] = '\0';
                    printf("[ROOT] Llave: 0x%016" PRIx64 " (%" PRIu64 ")\n", (uint64_t)found, (uint64_t)found);
                    printf("[ROOT] Texto (parcial o completo):\n%s\n", (char *)plain);
                    printf("[ROOT] Tiempo wallclock: %.6f s\n", elapsed);
                } else {
                    printf("[ROOT] Llave encontrada pero no pude descifrar con EVP (padding?).\n");
                }
                free(plain);
            }
        } else {
            printf("[ROOT] No se encontró la llave (keyword/cipher tal vez incorrectos)\n");
            printf("[ROOT] Tiempo wallclock: %.6f s\n", elapsed);
        }
    } else {
        MPI_Wait(&req, MPI_STATUS_IGNORE);
        printf("rank %d: tiempo local: %.6f s\n", rank, elapsed);
    }

    free(cipher);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
