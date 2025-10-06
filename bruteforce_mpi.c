#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <stdint.h>

#define KEYSPACE_BITS 56ULL
#define KEYSPACE ((1ULL << KEYSPACE_BITS))
#define MAX_CIPHER_BYTES 8192
#define CHUNK_SIZE 1024  // número de claves entre sincronizaciones colectivas

static void set_odd_parity(unsigned char *k, int len) {
    for (int i = 0; i < len; ++i) {
        unsigned char b = k[i];
        int ones = __builtin_popcount((unsigned int)(b & 0xFE));
        if ((ones % 2) == 0) k[i] = (b & 0xFE) | 0x01;
        else k[i] = (b & 0xFE) | 0x00;
    }
}

static void make_des_key_from_56(uint64_t key56, unsigned char out[8]) {
    uint64_t tmp = key56;
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) {
        tmp <<= 1;
        k |= ((tmp & ((uint64_t)0xFE << (i*8))));
    }
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)((k >> (i*8)) & 0xFF);
    set_odd_parity(out, 8);
}

static void des_decrypt_buffer_evpbased(uint64_t key56, unsigned char *in, unsigned char *out, size_t len, int padding_enabled) {
    unsigned char keybytes[8];
    make_des_key_from_56(key56, keybytes);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, keybytes, NULL)) {
        EVP_CIPHER_CTX_free(ctx); return;
    }
    EVP_CIPHER_CTX_set_padding(ctx, padding_enabled ? 1 : 0);

    size_t blocks = len / 8;
    int outlen = 0;
    // decrypt full blocks
    for (size_t i = 0; i < blocks; ++i) {
        int outl = 0;
        if (1 != EVP_DecryptUpdate(ctx, out + i*8, &outl, in + i*8, 8)) {
            EVP_CIPHER_CTX_free(ctx); return;
        }
    }
    // final
    if (1 != EVP_DecryptFinal_ex(ctx, out + blocks*8, &outlen)) {
        // if padding disabled and exact blocks, final may "fail" — ignore
    }
    EVP_CIPHER_CTX_free(ctx);
    size_t rem = len % 8;
    if (rem) memcpy(out + blocks*8, in + blocks*8, rem);
}

static int try_key(uint64_t key56, unsigned char *cipher, size_t cipher_len, const char *keyword, int padding_enabled) {
    unsigned char *plain = malloc(cipher_len + 1);
    if (!plain) return 0;
    memset(plain, 0, cipher_len + 1);
    des_decrypt_buffer_evpbased(key56, cipher, plain, cipher_len, padding_enabled);
    plain[cipher_len] = '\0';
    int ok = (strstr((char*)plain, keyword) != NULL);
    free(plain);
    return ok;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Uso: %s -f <cipher_file> -k <keyword> [-p] [-s]\n"
        " -f <cipher_file>  archivo binario con ciphertext\n"
        " -k <keyword>      palabra a buscar en descifrado\n"
        " -p                activar padding en DES-EVP (PKCS#5/7)\n"
        " -s                modo secuencial (no distribuido)\n", p);
}

int main(int argc, char *argv[]) {
    int rank=0, size=1;
    char *filename=NULL, *keyword=NULL;
    int padding_enabled = 0;
    int sequential_mode = 0;
    for (int i=1;i<argc;++i) {
        if (strcmp(argv[i],"-f")==0 && i+1<argc) filename=argv[++i];
        else if (strcmp(argv[i],"-k")==0 && i+1<argc) keyword=argv[++i];
        else if (strcmp(argv[i],"-p")==0) padding_enabled=1;
        else if (strcmp(argv[i],"-s")==0) sequential_mode=1;
        else { usage(argv[0]); return 1; }
    }
    if (!filename || !keyword) { usage(argv[0]); return 1; }

    unsigned char *cipher = malloc(MAX_CIPHER_BYTES);
    if (!cipher) { fprintf(stderr,"Mem alloc fail\n"); return 1; }
    FILE *fin = fopen(filename,"rb");
    if (!fin) { perror("fopen"); free(cipher); return 1; }
    size_t cipher_len = fread(cipher,1,MAX_CIPHER_BYTES,fin);
    fclose(fin);
    if (cipher_len==0) { fprintf(stderr,"Archivo vacio o ilegible\n"); free(cipher); return 1; }

    MPI_Init(&argc,&argv);
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);

    if (sequential_mode) {
        if (rank==0) {
            double t0 = MPI_Wtime();
            uint64_t found=0;
            for (uint64_t k=0;k<KEYSPACE;++k) {
                if (try_key(k,cipher,cipher_len,keyword,padding_enabled)) { found=k; break; }
            }
            double t1 = MPI_Wtime();
            if (found) {
                unsigned char *plain = malloc(cipher_len+1);
                des_decrypt_buffer_evpbased(found,cipher,plain,cipher_len,padding_enabled);
                plain[cipher_len]=0;
                printf("Llave encontrada: %llu\nTexto:\n%s\nTiempo: %.6f s\n",(unsigned long long)found,plain,t1-t0);
                free(plain);
            } else printf("No encontrada. Tiempo: %.6f s\n", t1-t0);
        }
        MPI_Finalize(); free(cipher); return 0;
    }

    uint64_t upper = KEYSPACE;
    uint64_t chunk = upper / (uint64_t)size;
    uint64_t lower = chunk * (uint64_t)rank;
    uint64_t upper_excl = (rank==size-1) ? upper : chunk * (uint64_t)(rank+1);

    uint64_t local_found = 0;
    uint64_t global_found = 0;

    double t0 = MPI_Wtime();
    uint64_t checked = 0;
    for (uint64_t k = lower; k < upper_excl; ++k) {
        if (local_found || global_found) break;
        if (try_key(k, cipher, cipher_len, keyword, padding_enabled)) {
            local_found = k;
        }
        ++checked;
        if ((checked % CHUNK_SIZE) == 0) {
            // collective sync: get max across ranks. if any found, global_found > 0
            MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
            if (global_found) break;
        }
    }
    // final collective to propagate last finds
    MPI_Allreduce(&local_found, &global_found, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);
    double t1 = MPI_Wtime();

    if (rank==0) {
        uint64_t final_found = global_found;
        if (final_found) {
            unsigned char *plain = malloc(cipher_len+1);
            des_decrypt_buffer_evpbased(final_found,cipher,plain,cipher_len,padding_enabled);
            plain[cipher_len]=0;
            printf("[ROOT] Llave: %llu\n[ROOT] Texto:\n%s\n", (unsigned long long)final_found, plain);
            free(plain);
        } else {
            printf("[ROOT] No se encontró la llave (keyword/cipher tal vez incorrectos)\n");
        }
        printf("[ROOT] Tiempo wallclock: %.6f s\n", t1 - t0);
    }

    MPI_Finalize();
    free(cipher);
    return 0;
}
