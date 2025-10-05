/* bruteforce.c
   Uso:
     mpicc bruteforce.c -o bruteforce -lcrypto
     mpirun -np <N> ./bruteforce <cipher_file> <keyword>

   Ejemplo:
     mpirun -np 4 ./bruteforce cipher.bin " the "

   Notas:
   - Requiere OpenSSL headers/libs (libssl-dev / libcrypto)
   - El archivo cipher_file debe contener el ciphertext en binario (longitud en bytes).
   - El programa asume DES ECB por bloques de 8 bytes; si el archivo no es múltiplo de 8, se
     hace padding con ceros para poder descifrar (para este ejercicio está bien).
   - Espacio de búsqueda de claves: 2^56 (descrito como upper = 1ULL << 56).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mpi.h>
#include <openssl/des.h>
#include <sys/stat.h>

#define DES_KEYSPACE_BITS 56
#define DES_KEYSPACE (1ULL << DES_KEYSPACE_BITS)

static void die(const char *msg){
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

/* Convierte una "key" (uint64_t) a DES_cblock (8 bytes). Rellena bytes LSB->MSB.
   Luego ajusta paridad impar requerida por DES. */
void long_to_des_cblock(uint64_t key, DES_cblock *out_block){
    for(int i = 0; i < 8; ++i){
        // llenamos de byte más significativo a menos significativo
        (*out_block)[7 - i] = key & 0xFF;
        key >>= 8;
    }
    DES_set_odd_parity(out_block);
}

/* Decrypt: descifra `len` bytes de `ciph` (múltiplo de 8) con DES-ECB usando la clave `key`.
   Resultado en outbuf (debe tener al menos `len` bytes). */
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

/* Encrypt: cifra `len` bytes de `plain` con DES-ECB usando la clave `key`. */
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

/* tryKey: prueba si con `key` el ciphertext descifrado contiene la `keyword`.
   Retorna 1 si encuentra la keyword, 0 si no. */
int tryKey(uint64_t key, const unsigned char *cipher, size_t len, const char *keyword){
    unsigned char *temp = (unsigned char *)malloc(len + 1);
    if(!temp) return 0;
    decrypt_with_key(key, cipher, len, temp);
    temp[len] = '\0'; // asumimos texto ASCII (para búsqueda substring)
    int found = (strstr((char *)temp, keyword) != NULL);
    free(temp);
    return found;
}

/* lee archivo binario en buffer; devuelve tamaño en out_len y buffer dinámico (free luego) */
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

int main(int argc, char *argv[]){
    MPI_Init(&argc, &argv);

    int Nprocs, rank;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &Nprocs);
    MPI_Comm_rank(comm, &rank);

    if(argc < 3){
        if(rank == 0){
            fprintf(stderr, "Uso: %s <cipher_file> <keyword>\n", argv[0]);
            fprintf(stderr, "Ejemplo: mpirun -np 4 %s cipher.bin \" the \"\n", argv[0]);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    const char *cipher_path = argv[1];
    const char *keyword = argv[2];

    /* Leer ciphertext */
    size_t ciphlen;
    unsigned char *cipher = read_binary_file(cipher_path, &ciphlen);
    if(!cipher){
        if(rank==0) fprintf(stderr, "Error leyendo archivo: %s\n", cipher_path);
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    /* Padding a múltiplo de 8 bytes (DES block size) si es necesario */
    size_t padded_len = ciphlen;
    if(padded_len % 8 != 0){
        padded_len = ((padded_len / 8) + 1) * 8;
        unsigned char *newbuf = (unsigned char *)calloc(1, padded_len);
        if(!newbuf){
            free(cipher);
            if(rank==0) fprintf(stderr, "Error reservando memoria para padding.\n");
            MPI_Finalize();
            return EXIT_FAILURE;
        }
        memcpy(newbuf, cipher, ciphlen);
        free(cipher);
        cipher = newbuf;
    }

    /* Pre-post non-blocking receive para la llave encontrada por cualquier proceso */
    uint64_t found = 0; // 0 significa no encontrado
    MPI_Request req;
    MPI_Irecv(&found, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    /* Definir rango para cada proceso (división simple equitativa) */
    uint64_t upper = DES_KEYSPACE; // 2^56
    uint64_t per_proc = upper / (uint64_t)Nprocs;
    uint64_t mylower = per_proc * (uint64_t)rank;
    uint64_t myupper = (rank == Nprocs - 1) ? (upper - 1) : (per_proc * (uint64_t)(rank + 1) - 1);

    double t0 = MPI_Wtime();

    /* Búsqueda: iterar localmente mientras nadie haya encontrado (found == 0). Se revisa MPI_Test periódicamente. */
    int flag = 0;
    uint64_t report_interval = 1000000ULL; // cada cuántas iteraciones chequear MPI_Test (ajustable)
    uint64_t iter = 0;
    for(uint64_t k = mylower; k <= myupper; ++k){
        /* Checar si ya se recibió la llave desde otro proceso */
        if((iter++ & 0xFFFF) == 0){ // cada cierto número de iteraciones, chequear más barato con máscara
            MPI_Test(&req, &flag, MPI_STATUS_IGNORE);
            if(flag && found != 0){
                break; // otro proceso encontró la llave
            }
        }

        /* Probar la clave k */
        if(tryKey(k, cipher, padded_len, keyword)){
            found = k;
            /* Enviar la llave encontrada a todos los procesos (incluido a sí mismo por consistencia) */
            for(int p = 0; p < Nprocs; ++p){
                MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, p, 0, comm);
            }
            break;
        }
    }

    double t1 = MPI_Wtime();
    double elapsed = t1 - t0;

    /* Asegurarse de que rank 0 tenga la llave en 'found' (esperar si no) */
    if(rank == 0){
        // si el recv no completó aún, esperar
        MPI_Wait(&req, MPI_STATUS_IGNORE);
        if(found != 0){
            unsigned char *plain = (unsigned char *)malloc(padded_len + 1);
            if(plain){
                decrypt_with_key(found, cipher, padded_len, plain);
                plain[padded_len] = '\0';
                printf("Llave encontrada: 0x%016llx (decimal %llu)\n", (unsigned long long)found, (unsigned long long)found);
                printf("Texto descifrado (primeros %zu bytes mostrados):\n%s\n", padded_len, (char *)plain);
                free(plain);
            } else {
                printf("Llave encontrada: 0x%016llx (decimal %llu)\n", (unsigned long long)found, (unsigned long long)found);
                printf("(No se pudo mostrar el texto descifrado por falta de memoria)\n");
            }
        } else {
            printf("No se encontró la llave (rank 0). (found == 0)\n");
        }
    } else {
        /* Los demás procesos deberían asegurarse de que su request termine para liberar recursos */
        MPI_Wait(&req, MPI_STATUS_IGNORE);
    }

    /* Cada proceso imprime su tiempo (útil para medir speedup) */
    printf("rank %d: rango [%llu .. %llu], tiempo local: %.6f s\n", rank,
           (unsigned long long)mylower, (unsigned long long)myupper, elapsed);

    free(cipher);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
