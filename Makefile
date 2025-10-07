# Makefile para Proyecto2 
MPICC = mpicc
CC = gcc
CFLAGS = -O2 -Wall
LDLIBS = -lcrypto

# Ejecutables 
BRUTE_EXE = bruteforce_mpi
BRUTE_SRC = bruteforce_mpi.c

MAKE_CIPHER_EXE = cipher_gen
MAKE_CIPHER_SRC = cipher_gen.c

# Scripts
BITACORA_SCRIPT = make_test_cipher.sh
RUN_SPEEDUP_SCRIPT = run_speedup.sh

.PHONY: all help build_cipher build_brute createcipher run_tests bitacora run_speedup clean

all: $(BRUTE_EXE) $(MAKE_CIPHER_EXE)

help:
	@echo "Targets disponibles:"
	@echo "  make / make all        -> compila bruteforce_mpi y cipher_gen"
	@echo "  make createcipher      -> genera cipher.bin desde mensaje.txt con key 0x5 (padding ON)"
	@echo "  make run_tests         -> prueba rápida (mpirun -np 2) con --test-bits 20"
	@echo "  make bitacora          -> ejecuta $(BITACORA_SCRIPT) si existe (genera bitacora.csv)"
	@echo "  make run_speedup       -> ejecuta $(RUN_SPEEDUP_SCRIPT) si existe (genera results_speedup.csv)"
	@echo "  make clean             -> limpia binarios y resultados"

# Compilar brute-force con mpicc
$(BRUTE_EXE): $(BRUTE_SRC)
	$(MPICC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Compilar el generador de cipher 
$(MAKE_CIPHER_EXE): $(MAKE_CIPHER_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Crear cipher.bin desde mensaje.txt con key por defecto 
createcipher: $(MAKE_CIPHER_EXE)
	@if [ ! -f mensaje.txt ]; then echo "mensaje.txt no existe. Crea mensaje.txt y vuelve a intentar."; exit 1; fi
	@echo "Creando cipher.bin desde mensaje.txt con key 0x5 (padding ON)..."
	./$(MAKE_CIPHER_EXE) mensaje.txt 0x5 -o cipher.bin -p

# Ejecutar una prueba rápida (2 procesos) con espacio reducido (--test-bits)
run_tests: $(BRUTE_EXE)
	@echo "Ejecutando prueba rápida (p=2) con --test-bits 20..."
	mpirun -np 2 ./$(BRUTE_EXE) -f cipher.bin -k "frase_clave" --test-bits 20

# Ejecutar script de bitácora 
bitacora:
	@if [ -x $(BITACORA_SCRIPT) ]; then ./$(BITACORA_SCRIPT) 10 6 20; else echo "No se encontró $(BITACORA_SCRIPT) o no es ejecutable."; fi

# Ejecutar script de speedup
run_speedup:
	@if [ -x $(RUN_SPEEDUP_SCRIPT) ]; then ./$(RUN_SPEEDUP_SCRIPT) cipher.bin "frase_clave" 8 ./$(BRUTE_EXE); else echo "No se encontró $(RUN_SPEEDUP_SCRIPT) o no es ejecutable."; fi

clean:
	-rm -f $(BRUTE_EXE) $(MAKE_CIPHER_EXE) cipher.bin results_speedup.csv bitacora.csv
