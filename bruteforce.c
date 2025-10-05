/* bruteforce.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mpi.h>
#include <openssl/des.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>

#define DES_KEYSPACE_BITS_DEFAULT 56

static void die(const char *msg){
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

uint64_t parse_uint64(const char *s){
    if(!s) return 0;
    char *end = NULL;
    uint64_t v = 0;
    if(strlen(s) > 2 && s[0] == '0' && (s[1]=='x' || s[1]=='X')){
        errno = 0;
        v = strtoull(s, &end, 16);
    } else {
        errno = 0;
        v = strtoull(s, &end, 10);
    }
    if(errno != 0 || end == s){
        fprintf(stderr, "Error parsing number: %s\n", s);
        return 0;
    }
    return v;
}

unsigned char *read_binary_file(const char *path, size_t *out_len){
    struct stat st;
    if(stat(path, &st) != 0) return NULL;
    size_t fsize = (size_t)st.st_size;
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    unsigned char *buf = (unsigned char *)malloc(fsize);
    if(!buf){
        fclose(f);
        return NULL;
    }
    size_t r = fread(buf, 1, fsize, f);
    fclose(f);
    if(r != fsize){
        free(buf);
        return NULL;
    }
    *out_len = fsize;
    return buf;
}

int write_binary_file(const char *path, const unsigned char *buf, size_t len){
    FILE *f = fopen(path, "wb");
    if(!f) return -1;
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    return (w == len) ? 0 : -1;
}

/* DES helpers */
void long_to_des_cblock(uint64_t key, DES_cblock *out_block){
    for(int i = 0; i < 8; ++i){
        (*out_block)[7 - i] = (unsigned char)(key & 0xFF);
        key >>= 8;
    }
    DES_set_odd_parity(out_block);
}

void decrypt_with_key(uint64_t key, const unsigned char *ciph, size_t len, unsigned char *outbuf){
    DES_cblock kblock;
    DES_key_schedule ks;
    long_to_des_cblock(key, &kblock);
    DES_set_key_unchecked(&kblock, &ks);

    for(size_t i = 0; i < len; i += 8){
        DES_cblock inblock, outblock;
        memcpy(inblock, ciph + i, 8);
        DES_ecb_encrypt((const_DES_cblock *)inblock, &outblock, &ks, DES_DECRYPT);
        memcpy(outbuf + i, outblock, 8);
    }
}

void encrypt_with_key(uint64_t key, const unsigned char *plain, size_t len, unsigned char *outbuf){
    DES_cblock kblock;
    DES_key_schedule ks;
    long_to_des_cblock(key, &kblock);
    DES_set_key_unchecked(&kblock, &ks);

    for(size_t i = 0; i < len; i += 8){
        DES_cblock inblock, outblock;
        memcpy(inblock, plain + i, 8);
        DES_ecb_encrypt((const_DES_cblock *)inblock, &outblock, &ks, DES_ENCRYPT);
        memcpy(outbuf + i, outblock, 8);
    }
}

int tryKey(uint64_t key, const unsigned char *cipher, size_t len, const char *keyword){
    unsigned char *temp = (unsigned char *)malloc(len + 1);
    if(!temp) return 0;
    decrypt_with_key(key, cipher, len, temp);
    temp[len] = '\0';
    int found = (strstr((char *)temp, keyword) != NULL);
    free(temp);
    return found;
}

/* create cipher file */
int create_cipher_file(const char *plain_path, const char *out_path, uint64_t key){
    struct stat st;
    if(stat(plain_path, &st) != 0){
        fprintf(stderr, "create_cipher_file: no se puede stat %s\n", plain_path);
        return -1;
    }
    size_t plain_len = (size_t)st.st_size;
    unsigned char *plain = read_binary_file(plain_path, &plain_len);
    if(!plain){
        fprintf(stderr, "create_cipher_file: no se pudo leer %s\n", plain_path);
        return -1;
    }

    size_t padded_len = plain_len;
    if(padded_len % 8 != 0) padded_len = ((padded_len / 8) + 1) * 8;
    unsigned char *padded = (unsigned char *)calloc(1, padded_len);
    if(!padded){
        free(plain);
        fprintf(stderr, "create_cipher_file: malloc failed\n");
        return -1;
    }
    memcpy(padded, plain, plain_len);
    free(plain);

    unsigned char *outbuf = (unsigned char *)malloc(padded_len);
    if(!outbuf){
        free(padded);
        fprintf(stderr, "create_cipher_file: malloc failed\n");
        return -1;
    }

    encrypt_with_key(key, padded, padded_len, outbuf);
    int rc = write_binary_file(out_path, outbuf, padded_len);

    free(padded);
    free(outbuf);
    return rc;
}

void print_usage(const char *prog){
    printf("Uso:\n");
    printf("  Compilar: mpicc bruteforce.c -o bruteforce -lcrypto\n\n");
    printf("  Crear cipher: %s --create-cipher <plain.txt> <key> <out.bin>\n", prog);
    printf("  Buscar llave (paralelo por defecto): mpirun -np <N> %s <cipher.bin> <keyword> [--test-bits N]\n", prog);
    printf("  Buscar llave (secuencial): %s --mode=sequential <cipher.bin> <keyword> [--test-bits N]\n", prog);
    printf("\nNota: --test-bits N reduce el espacio de búsqueda a 2^N (para pruebas rápidas).\n");
}

/* main */
int main(int argc, char *argv[]){
    if(argc < 2){
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* create-cipher mode (no MPI init needed) */
    if(argc >= 5 && strcmp(argv[1], "--create-cipher") == 0){
        const char *plain_path = argv[2];
        const char *key_s = argv[3];
        const char *out_path = argv[4];
        uint64_t key = parse_uint64(key_s);
        if(create_cipher_file(plain_path, out_path, key) != 0){
            fprintf(stderr, "Error creando cipher file.\n");
            return EXIT_FAILURE;
        }
        printf("Cipher creado: %s (key=0x%016" PRIx64 ")\n", out_path, key);
        return EXIT_SUCCESS;
    }

    MPI_Init(&argc, &argv);
    int Nprocs = 1, rank = 0;
    MPI_Comm_size(MPI_COMM_WORLD, &Nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* detect mode */
    int sequential_mode = 0;
    int argi = 1;
    if(strcmp(argv[argi], "--mode=sequential") == 0){
        sequential_mode = 1;
        argi++;
    }

    /* Remaining args: cipher_path keyword [--test-bits N] */
    if(argc - argi < 2){
        if(rank==0) print_usage(argv[0]);
        MPI_Finalize();
        return EXIT_FAILURE;
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
    if(argi < argc && strcmp(argv[argi], "--test-bits") == 0){
        if(argi + 1 < argc){
            int tb = atoi(argv[argi+1]);
            if(tb >= 1 && tb <= DES_KEYSPACE_BITS_DEFAULT) test_bits = tb;
            argi += 2;
        } else {
            if(rank==0) fprintf(stderr, "--test-bits requiere un valor\n");
            MPI_Finalize();
            return EXIT_FAILURE;
        }
    }

    uint64_t keyspace_bits = (uint64_t)test_bits;
    uint64_t upper = (keyspace_bits >= 64) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << keyspace_bits);

    /* read cipher */
    size_t ciphlen = 0;
    unsigned char *cipher = read_binary_file(cipher_path, &ciphlen);
    if(!cipher){
        if(rank==0) fprintf(stderr, "Error leyendo archivo ciphertext: %s\n", cipher_path);
        MPI_Finalize();
        return EXIT_FAILURE;
    }
    size_t padded_len = ciphlen;
    if(padded_len % 8 != 0) padded_len = ((padded_len / 8) + 1) * 8;
    if(padded_len != ciphlen){
        unsigned char *tmp = (unsigned char *)calloc(1, padded_len);
        if(!tmp){ free(cipher); MPI_Finalize(); return EXIT_FAILURE; }
        memcpy(tmp, cipher, ciphlen);
        free(cipher);
        cipher = tmp;
    }

    uint64_t found = 0;
    MPI_Request req;
    MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);
    double t0 = MPI_Wtime();

    if(sequential_mode && rank == 0){
        if(rank==0) printf("[SEQUENTIAL] keyspace 2^%d = %" PRIu64 " claves\n", test_bits, upper);
        for(uint64_t k = 0; k < upper; ++k){
            if(tryKey(k, cipher, padded_len, keyword)){
                found = k;
                for(int p = 0; p < Nprocs; ++p) MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, MPI_COMM_WORLD);
                break;
            }
            if((k & 0xFFFFFFULL) == 0){
                int flag = 0;
                MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                if(flag && found != 0) break;
            }
        }
    } else if(!sequential_mode){
        uint64_t per_proc = (upper / (uint64_t)Nprocs);
        if(per_proc == 0) per_proc = 1;
        uint64_t mylower = per_proc * (uint64_t)rank;
        uint64_t myupper = (rank == Nprocs - 1) ? (upper - 1) : (per_proc * (uint64_t)(rank + 1) - 1);
        uint64_t iter = 0;
        int flag = 0;
        for(uint64_t k = mylower; k <= myupper; ++k){
            if((iter++ & 0xFFFF) == 0){
                MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
                if(flag && found != 0) break;
            }
            if(tryKey(k, cipher, padded_len, keyword)){
                found = k;
                for(int p = 0; p < Nprocs; ++p) MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, MPI_COMM_WORLD);
                break;
            }
        }
    } else {
        /* sequential_mode && rank != 0: esperar */
    }

    double t1 = MPI_Wtime();
    double elapsed = t1 - t0;

    if(rank == 0){
        MPI_Wait(&req, MPI_STATUS_IGNORE);
        if(found != 0){
            unsigned char *plain = (unsigned char *)malloc(padded_len + 1);
            if(plain){
                decrypt_with_key(found, cipher, padded_len, plain);
                plain[padded_len]='\0';
                printf("Llave encontrada: 0x%016" PRIx64 " (%" PRIu64 ")\n", found, found);
                printf("Texto descifrado (muestra):\n%s\n", (char*)plain);
                free(plain);
            } else {
                printf("Llave encontrada: 0x%016" PRIx64 "\n", found);
            }
        } else {
            printf("No se encontró la llave (found==0)\n");
        }
    } else {
        MPI_Wait(&req, MPI_STATUS_IGNORE);
    }

    if(!sequential_mode){
        uint64_t per_proc = (upper / (uint64_t)Nprocs);
        if(per_proc == 0) per_proc = 1;
        uint64_t mylower = per_proc * (uint64_t)rank;
        uint64_t myupper = (rank == Nprocs - 1) ? (upper - 1) : (per_proc * (uint64_t)(rank + 1) - 1);
        printf("rank %d: rango [%" PRIu64 " .. %" PRIu64 "], tiempo local: %.6f s\n",
               rank, mylower, myupper, elapsed);
    } else if(sequential_mode && rank==0){
        printf("[SEQUENTIAL] tiempo total: %.6f s\n", elapsed);
    }

    free(cipher);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
