#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <errno.h>
#include <unistd.h>

/* ---------- Config ---------- */
#define DES_KEYSPACE_BITS_DEFAULT 56
#define MAX_PLAIN_LEN (1<<20) /* 1 MB safe guard */

/* ---------- Helpers: file IO ---------- */
static unsigned char *read_binary_file(const char *path, size_t *out_len){
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END) != 0){ fclose(f); return NULL; }
    long len = ftell(f);
    if(len < 0){ fclose(f); return NULL; }
    rewind(f);
    if((size_t)len > MAX_PLAIN_LEN){ fclose(f); return NULL; }
    unsigned char *buf = malloc((size_t)len + 1);
    if(!buf){ fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if(r != (size_t)len){ free(buf); return NULL; }
    buf[len] = '\0';
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

/* ---------- Parity / key build ---------- */
/* Force odd parity on a single byte (LSB parity bit) */
static void set_odd_parity_byte(unsigned char *b) {
    unsigned char v = *b & 0xFE;
    int ones = __builtin_popcount((unsigned int)v);
    if ((ones & 1) == 0) *b = v | 0x01;
    else *b = v & 0xFE;
}

/* Convert low 56 bits of key56 into 8 bytes, then set odd parity */
static void uint64_to_des_key(uint64_t key56, unsigned char out[8]) {
    /* Simple byte-wise mapping LSB-first (consistent con muchas implementaciones) */
    for(int i = 0; i < 8; ++i){
        out[i] = (unsigned char)((key56 >> (8 * i)) & 0xFFULL);
    }
    for(int i = 0; i < 8; ++i) set_odd_parity_byte(&out[i]);
}

/* ---------- EVP wrappers (DES-ECB) ---------- */
/* encrypt_with_key_evpbased: retorna bytes escritos o -1 en error */
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

/* decrypt_with_key_evpbased: retorna bytes descifrados o -1 */
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
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

/* ---------- create cipher helper ---------- */
static int create_cipher_file(const char *infile, uint64_t key, const char *out_path, int padding_enabled){
    size_t plain_len = 0;
    unsigned char *plain = read_binary_file(infile, &plain_len);
    if(!plain){ fprintf(stderr, "create_cipher_file: no pude leer %s\n", infile); return -1; }

    if(!padding_enabled){
        size_t padded_len = ((plain_len + 7) / 8) * 8;
        unsigned char *tmp = calloc(1, padded_len);
        if(!tmp){ free(plain); return -1; }
        memcpy(tmp, plain, plain_len);
        unsigned char *outbuf = malloc(padded_len + 64);
        if(!outbuf){ free(tmp); free(plain); return -1; }
        int outlen = encrypt_with_key_evpbased(key, tmp, padded_len, outbuf, 0);
        if(outlen < 0){ free(tmp); free(plain); free(outbuf); return -1; }
        int rc = write_binary_file(out_path, outbuf, (size_t)outlen);
        free(tmp); free(plain); free(outbuf);
        return rc;
    } else {
        unsigned char *outbuf = malloc(plain_len + 64);
        if(!outbuf){ free(plain); return -1; }
        int outlen = encrypt_with_key_evpbased(key, plain, plain_len, outbuf, 1);
        if(outlen < 0){ free(plain); free(outbuf); return -1; }
        int rc = write_binary_file(out_path, outbuf, (size_t)outlen);
        free(plain); free(outbuf);
        return rc;
    }
}

/* ---------- tryKey: decrypt buffer and search keyword ---------- */
/**
 * tryKey - intenta descifrar 'cipher' con clave key56 y busca 'keyword'.
 * @key56: clave en forma de 56 bits en uint64.
 * @cipher: buffer del ciphertext.
 * @cipher_len: longitud del ciphertext en bytes.
 * @keyword: palabra/substring que se busca (no nulo).
 * @padding_enabled: 1 si se habilita padding en EVP, 0 si no.
 * @out_plain: buffer opcional para copiar el texto plano (debe tener room).
 *
 * Retorna: 1 si la keyword fue encontrada, 0 en caso contrario.
 *
 * Nota: función defensiva (valida parámetros y maneja errores de EVP).
 */
static int tryKey(uint64_t key56, const unsigned char *cipher, size_t cipher_len, const char *keyword, int padding_enabled, unsigned char *out_plain){
    if(!cipher || cipher_len == 0 || !keyword) return 0;
    unsigned char *tmp = malloc(cipher_len + 64);
    if(!tmp) return 0;
    int dec_len = decrypt_with_key_evpbased(key56, cipher, cipher_len, tmp, padding_enabled);
    if(dec_len <= 0){ free(tmp); return 0; }
    if((size_t)dec_len >= cipher_len + 63) tmp[cipher_len + 63] = '\0';
    else tmp[dec_len] = '\0';
    int found = (strstr((char *)tmp, keyword) != NULL) ? 1 : 0;
    if(found && out_plain){
        memcpy(out_plain, tmp, dec_len);
        out_plain[dec_len] = '\0';
    }
    free(tmp);
    return found;
}

/* ---------- usage ---------- */
static void print_usage(const char *prog){
    printf("Uso:\n");
    printf("  Compilar: mpicc -O2 -Wall -std=c11 bruteforce.c -o bruteforce -lcrypto\n\n");
    printf("  Crear cipher: %s --create-cipher <plain.txt> <key_decimal> <out.bin> [--padding]\n", prog);
    printf("  Buscar llave (paralelo con MPI): mpirun -np <N> %s <cipher.bin> <keyword> [--test-bits N] [--partition=block|roundrobin] [-p] [--trials N]\n", prog);
    printf("  Buscar llave (secuencial): %s --mode=sequential <cipher.bin> <keyword> [--test-bits N] [-p] [--trials N]\n", prog);
    printf("\nNota: --test-bits N reduce el espacio de búsqueda a 2^N (útil para pruebas rápidas).\n");
    printf("      --partition=roundrobin usa particionado intercalado (mejor balance).\n");
}

/* ---------- main ---------- */
int main(int argc, char *argv[]){
    if(argc < 2){ print_usage(argv[0]); return EXIT_FAILURE; }

    /* Load OpenSSL providers for legacy DES if available */
#ifdef OPENSSL_VERSION_NUMBER
    /* ignore return, but try to load */
    OSSL_PROVIDER *pdef = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *pleg = OSSL_PROVIDER_load(NULL, "legacy");
    (void)pdef; (void)pleg;
#endif

    /* Inicializamos MPI para permitir ejecuciones con mpirun (aunque secuencial se ejecute en rank 0) */
    MPI_Init(&argc, &argv);
    int Nprocs = 1, rank = 0;
    MPI_Comm_size(MPI_COMM_WORLD, &Nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* Rápido path: crear cipher */
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

    /* Detect mode */
    int sequential_mode = 0;
    int argi = 1;
    if(strncmp(argv[argi], "--mode=", 7) == 0){
        if(strcmp(argv[argi], "--mode=sequential") == 0){
            sequential_mode = 1; argi++;
        }
    }

    if(argc - argi < 2){
        if(rank==0) print_usage(argv[0]);
        MPI_Finalize(); return EXIT_FAILURE;
    }

    const char *cipher_path = argv[argi++];
    const char *keyword = argv[argi++];

    /* Opcionales: --test-bits N, -p/--padding, --partition=, --trials N */
    int test_bits = DES_KEYSPACE_BITS_DEFAULT;
    int padding_enabled = 0;
    int use_roundrobin = 0;
    int trials = 1;
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
        } else if(strcmp(argv[i], "--trials") == 0 && i + 1 < argc){
            trials = atoi(argv[++i]);
            if(trials < 1) trials = 1;
        } else {
            if(rank == 0) fprintf(stderr, "Warning: argumento desconocido '%s' (ignorando)\n", argv[i]);
        }
    }

    uint64_t keyspace_bits = (uint64_t)test_bits;
    uint64_t upper = (keyspace_bits >= 64) ? UINT64_MAX : (1ULL << keyspace_bits);

    /* read cipher */
    size_t ciphlen = 0;
    unsigned char *cipher = read_binary_file(cipher_path, &ciphlen);
    if(!cipher){
        if(rank==0) fprintf(stderr, "Error leyendo archivo ciphertext: %s\n", cipher_path);
        MPI_Finalize(); return EXIT_FAILURE;
    }

    /* Prepare non-blocking receive for 'found' key */
    uint64_t found = 0;
    MPI_Request req;
    MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    /* If sequential_mode and rank==0 do sequential trials; otherwise parallel trials across processes */
    double total_elapsed = 0.0;
    uint64_t final_found = 0;

    for(int t = 0; t < trials; ++t){
        MPI_Barrier(MPI_COMM_WORLD);
        double t0 = MPI_Wtime();

        if(sequential_mode && rank == 0){
            if(rank == 0) printf("[SEQUENTIAL] ensayo %d/%d: keyspace 2^%d = %" PRIu64 " claves\n", t+1, trials, test_bits, upper);
            unsigned char *plain = malloc(ciphlen + 128);
            found = 0;
            for(uint64_t k = 0; k < upper; ++k){
                if(tryKey(k, cipher, ciphlen, keyword, padding_enabled, plain)){
                    found = k;
                    break;
                }
                if((k & 0xFFFFFFULL) == 0){
                    /* allow cancel check */
                    int flag = 0;
                    MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                    if(flag && found != 0) break;
                }
            }
            free(plain);
        } else if(!sequential_mode){
            /* Pararell search: support block or roundrobin (intercalado). */
            if(rank == 0){
                printf("[ROOT] ensayo %d/%d paralelo con %d procesos, keyspace 2^%d (upper=%" PRIu64 ")\n", t+1, trials, Nprocs, test_bits, upper);
                printf("[ROOT] partition: %s\n", use_roundrobin ? "roundrobin (intercalado)" : "block");
            }

            if(use_roundrobin){
                uint64_t iter = 0;
                int flag = 0;
                unsigned char *plain = malloc(ciphlen + 128);
                for(uint64_t k = (uint64_t)rank; k < upper; k += (uint64_t)Nprocs){
                    if((iter++ & 0xFFFF) == 0){
                        MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                        if(flag && found != 0) break;
                    }
                    if(tryKey(k, cipher, ciphlen, keyword, padding_enabled, plain)){
                        found = k;
                        /* notify all ranks */
                        for(int p = 0; p < Nprocs; ++p) MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, MPI_COMM_WORLD);
                        break;
                    }
                }
                free(plain);
            } else {
                /* block partition */
                uint64_t per_proc = (upper / (uint64_t)Nprocs);
                if(per_proc == 0) per_proc = 1;
                uint64_t mylower = per_proc * (uint64_t)rank;
                uint64_t myupper = (rank == Nprocs - 1) ? (upper - 1) : (per_proc * (uint64_t)(rank + 1) - 1);
                uint64_t iter = 0;
                int flag = 0;
                unsigned char *plain = malloc(ciphlen + 128);
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
            /* sequential_mode && rank != 0 : nothing to do, just wait for notifications */
        }

        double t1 = MPI_Wtime();
        double elapsed = t1 - t0;
        total_elapsed += elapsed;

        /* root awaits found message (if any) */
        if(rank == 0){
            MPI_Wait(&req, MPI_STATUS_IGNORE);
            if(found != 0){
                unsigned char *plain = malloc(ciphlen + 256);
                if(plain){
                    int dec_len = decrypt_with_key_evpbased(found, cipher, ciphlen, plain, padding_enabled);
                    if(dec_len > 0){
                        plain[dec_len] = '\0';
                        printf("[ROOT] Llave: 0x%016" PRIx64 " (%" PRIu64 ")\n", (uint64_t)found, (uint64_t)found);
                        printf("[ROOT] Texto (parcial o completo):\n%s\n", (char *)plain);
                        printf("[ROOT] Tiempo wallclock (ensayo %d): %.6f s\n", t+1, elapsed);
                    } else {
                        printf("[ROOT] Llave encontrada pero no pude descifrar con EVP (padding?).\n");
                    }
                    free(plain);
                }
            } else {
                printf("[ROOT] No se encontró la llave (ensayo %d). Tiempo: %.6f s\n", t+1, elapsed);
            }
            /* Reset non-blocking receive for next trial */
            if(t+1 < trials){
                found = 0;
                MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);
            }
        } else {
            /* non-root ranks ensure they wait for any final found before continuing to next trial */
            MPI_Wait(&req, MPI_STATUS_IGNORE);
            if(t+1 < trials){
                found = 0;
                MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);
            }
        }
        /* small sync between trials */
        MPI_Barrier(MPI_COMM_WORLD);
    } /* end trials */

    if(rank == 0){
        double avg = total_elapsed / (double)trials;
        printf("[ROOT] Tiempo promedio sobre %d ensayos: %.6f s\n", trials, avg);
    }

    free(cipher);
    MPI_Finalize();
    return EXIT_SUCCESS;
}

/* ---------- Bloque de pruebas unitarias para tryKey ----------
   Compilar con: mpicc -DTEST_TRYKEY bruteforce.c -lcrypto -o test_trykey
   Ejecutar: ./test_trykey --create-cipher ... o ./test_trykey --mode=sequential ...
*/
#ifdef TEST_TRYKEY
/* Si el binario se compila con -DTEST_TRYKEY ejecutará pruebas simples */
int main_test_trykey(int argc, char *argv[]){
    (void)argc; (void)argv;
    const char *plaintext = "Mensaje de prueba con la palabra SECRETO dentro.";
    const char *keyword = "SECRETO";
    uint64_t key = 123456ULL;

    /* cifrar en memoria usando encrypt_with_key_evpbased */
    size_t plain_len = strlen(plaintext);
    unsigned char *outbuf = malloc(plain_len + 64);
    if(!outbuf){ fprintf(stderr, "malloc fail\n"); return 1; }
    int outlen = encrypt_with_key_evpbased(key, (unsigned char*)plaintext, plain_len, outbuf, 1);
    if(outlen <= 0){ fprintf(stderr, "encrypt failed\n"); free(outbuf); return 1; }

    /* probar tryKey con clave correcta */
    unsigned char plainrec[1024];
    int ok = tryKey(key, outbuf, (size_t)outlen, keyword, 1, plainrec);
    if(ok){
        printf("tryKey detectó la palabra con la clave correcta. Texto recuperado:\n%s\n", plainrec);
    } else {
        printf("tryKey NO detectó la palabra con la clave correcta\n");
    }
    /* probar con clave incorrecta */
    ok = tryKey(key+1, outbuf, (size_t)outlen, keyword, 1, plainrec);
    if(!ok) printf("tryKey correctamente rechazó clave incorrecta\n");
    else printf("tryKey erroneamente aceptó clave incorrecta\n");

    free(outbuf);
    return 0;
}

int main(int argc, char *argv[]){ return main_test_trykey(argc, argv); }
#endif
