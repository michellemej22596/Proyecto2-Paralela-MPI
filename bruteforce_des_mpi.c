/* bruteforce_mpi_patched.c
   Versión mínima parcheada de bruteforce_mpi.c que añade --test-bits N
   y mantiene flags -f, -k, -p, -s. Compilar con:
     mpicc -O2 -Wall -o bruteforce_mpi_patched bruteforce_mpi_patched.c -lcrypto
*/
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

/* tryKey reusa buffer plainbuf en vez de malloc/free */
int tryKey_withbuf(uint64_t key, const unsigned char *cipher, size_t len, const char *keyword, unsigned char *plainbuf){
    decrypt_with_key(key, cipher, len, plainbuf);
    plainbuf[len] = '\0';
    int found = (strstr((char *)plainbuf, keyword) != NULL);
    return found;
}

void print_usage(const char *p) {
    fprintf(stderr,
        "Uso: %s -f <cipher_file> -k <keyword> [-p] [-s] [--test-bits N] [--partition=block|roundrobin]\n"
        " -f <cipher_file>  archivo binario con ciphertext\n"
        " -k <keyword>      palabra a buscar en descifrado\n"
        " -p                activar padding en DES-EVP (PKCS#5/7)\n"
        " -s                modo secuencial (no distribuido)\n"
        " --test-bits N     reducir espacio de búsqueda a 2^N (para pruebas)\n"
        " --partition=...   partition strategy (block or roundrobin)\n", p);
}

int main(int argc, char *argv[]){
    int rank=0, size=1;
    char *filename=NULL, *keyword=NULL;
    int padding_enabled = 0;
    int sequential_mode = 0;
    int test_bits = DES_KEYSPACE_BITS_DEFAULT;
    int use_roundrobin = 0;

    for (int i=1;i<argc;++i) {
        if (strcmp(argv[i],"-f")==0 && i+1<argc) filename=argv[++i];
        else if (strcmp(argv[i],"-k")==0 && i+1<argc) keyword=argv[++i];
        else if (strcmp(argv[i],"-p")==0) padding_enabled=1;
        else if (strcmp(argv[i],"-s")==0) sequential_mode=1;
        else if (strcmp(argv[i],"--test-bits")==0 && i+1<argc) {
            test_bits = atoi(argv[++i]);
            if (test_bits < 1 || test_bits > DES_KEYSPACE_BITS_DEFAULT) {
                fprintf(stderr, "--test-bits debe estar entre 1 y %d\n", DES_KEYSPACE_BITS_DEFAULT);
                return 1;
            }
        }
        else if (strncmp(argv[i],"--partition=",11)==0) {
            if (strcmp(argv[i]+11,"roundrobin")==0) use_roundrobin=1;
        }
        else { print_usage(argv[0]); return 1; }
    }
    if (!filename || !keyword) { print_usage(argv[0]); return 1; }

    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    cipher = read_binary_file(filename, &cipher_len);
    if (!cipher) { fprintf(stderr,"Error leyendo %s\n", filename); return 1; }

    /* padding to multiple of 8 */
    size_t padded_len = cipher_len;
    if (padded_len % 8 != 0) {
        size_t newlen = ((padded_len/8)+1)*8;
        unsigned char *tmp = calloc(1, newlen);
        if (!tmp) { free(cipher); fprintf(stderr,"malloc fail\n"); return 1; }
        memcpy(tmp, cipher, cipher_len);
        free(cipher);
        cipher = tmp;
        padded_len = newlen;
    }

    MPI_Init(&argc,&argv);
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);

    uint64_t upper = (test_bits >= 64) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << (uint64_t)test_bits);

    uint64_t local_found = 0;
    uint64_t global_found = 0;

    unsigned char *plainbuf = malloc(padded_len + 1);
    if (!plainbuf) { if(rank==0) fprintf(stderr,"malloc plainbuf fail\n"); MPI_Finalize(); free(cipher); return 1; }
    memset(plainbuf,0,padded_len+1);

    double t0 = MPI_Wtime();

    if (sequential_mode && rank==0) {
        for (uint64_t k=0;k<upper;++k) {
            if (tryKey_withbuf(k, cipher, padded_len, keyword, plainbuf)) { local_found = k; break; }
            if ((k & 0xFFFFFFULL)==0) { MPI_Barrier(MPI_COMM_WORLD); } // light sync so others can quit if needed
        }
    } else {
        if (use_roundrobin) {
            for (uint64_t k = (uint64_t)rank; k < upper; k += (uint64_t)size) {
                if (local_found) break;
                if (tryKey_withbuf(k, cipher, padded_len, keyword, plainbuf)) { local_found = k; break; }
                // occasionally check global_found
                if ((k & 0xFFFFF) == 0) {
                    MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
                    if (global_found) break;
                }
            }
        } else {
            uint64_t per = upper / (uint64_t)size;
            if (per==0) per = 1;
            uint64_t lo = per * (uint64_t)rank;
            uint64_t hi_ex = (rank==size-1) ? upper : per * (uint64_t)(rank+1);
            uint64_t checked = 0;
            for (uint64_t k=lo; k<hi_ex; ++k) {
                if (local_found) break;
                if (tryKey_withbuf(k, cipher, padded_len, keyword, plainbuf)) { local_found = k; break; }
                ++checked;
                if ((checked % 100000) == 0) {
                    MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
                    if (global_found) break;
                }
            }
        }
    }

    MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
    double t1 = MPI_Wtime();

    if (rank==0) {
        if (global_found) {
            decrypt_with_key(global_found, cipher, padded_len, plainbuf);
            plainbuf[padded_len] = '\0';
            printf("[ROOT] Llave: 0x%016" PRIx64 " (%" PRIu64 ")\n", (uint64_t)global_found, (uint64_t)global_found);
            printf("[ROOT] Texto:\n%s\n", (char*)plainbuf);
        } else {
            printf("[ROOT] No se encontró la llave (keyword/cipher tal vez incorrectos)\n");
        }
        printf("[ROOT] Tiempo wallclock: %.6f s\n", t1 - t0);
    }

    free(plainbuf);
    free(cipher);
    MPI_Finalize();
    return 0;
}
