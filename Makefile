# Compiladores y flags
MPICC   = mpicc
CC      = gcc
CFLAGS  = -O2 -Wall -std=c11
LDLIBS  = -lcrypto

# Ejecutables principales
BRUTE_EXE       = bruteforce_mpi
BRUTE_SRC       = bruteforce_mpi.c

BRUTE_TEST_EXE  = bruteforce_mpi_test
BRUTE_TEST_SRC  = bruteforce_mpi.c  # mismo código pero compilado con TEST_TRYKEY

CIPHER_EXE      = cipher_gen
CIPHER_SRC      = cipher_gen.c      # (puedes omitir si usas --create-cipher del bruteforce.c unificado)

# Archivos de datos
PLAIN_FILE      = mensaje.txt
CIPHER_FILE     = cipher.bin
TEST_KEY        = 5                # clave por defecto para pruebas

# Scripts auxiliares
BITACORA_SCRIPT    = make_test_cipher.sh
RUN_SPEEDUP_SCRIPT = run_speedup.sh

# ================================

.PHONY: all help brute cipher tests unit_tests createcipher run_tests bitacora run_speedup clean

all: brute cipher

help:
	@echo "Targets disponibles:"
	@echo "  make all             -> compila $(BRUTE_EXE) y $(CIPHER_EXE)"
	@echo "  make brute           -> compila el ejecutable de fuerza bruta MPI"
	@echo "  make cipher          -> compila el generador de cifrados"
	@echo "  make createcipher    -> genera $(CIPHER_FILE) desde $(PLAIN_FILE) con key=$(TEST_KEY)"
	@echo "  make run_tests       -> prueba rápida con mpirun -np 2 y --test-bits 20"
	@echo "  make unit_tests      -> compila y ejecuta pruebas unitarias de tryKey"
	@echo "  make bitacora        -> ejecuta el script de bitácora (si existe)"
	@echo "  make run_speedup     -> ejecuta el script de medición de speedup (si existe)"
	@echo "  make clean           -> limpia binarios y salidas intermedias"

# ================================
# Compilación
# ================================

brute: $(BRUTE_EXE)

$(BRUTE_EXE): $(BRUTE_SRC)
	@echo "Compilando $@ ..."
	$(MPICC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Compilar versión con TEST_TRYKEY activado
unit_tests: $(BRUTE_TEST_EXE)
	@echo "Ejecutando pruebas unitarias de tryKey..."
	./$(BRUTE_TEST_EXE)

$(BRUTE_TEST_EXE): $(BRUTE_TEST_SRC)
	@echo "Compilando $@ (modo test)..."
	$(MPICC) $(CFLAGS) -DTEST_TRYKEY -o $@ $< $(LDLIBS)

cipher: $(CIPHER_EXE)

$(CIPHER_EXE): $(CIPHER_SRC)
	@echo "🔨 Compilando $@ ..."
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# ================================
# Tareas de prueba y bitácora
# ================================

createcipher: $(CIPHER_EXE)
	@if [ ! -f $(PLAIN_FILE) ]; then \
		echo " $(PLAIN_FILE) no existe. Crea un archivo de texto de prueba primero."; \
		exit 1; \
	fi
	@echo "Creando $(CIPHER_FILE) desde $(PLAIN_FILE) con key=$(TEST_KEY) (padding ON)..."
	./$(CIPHER_EXE) $(PLAIN_FILE) $(TEST_KEY) -o $(CIPHER_FILE) -p
	@echo "✅ Cipher generado: $(CIPHER_FILE)"

run_tests: $(BRUTE_EXE)
	@if [ ! -f $(CIPHER_FILE) ]; then \
		echo "No se encontró $(CIPHER_FILE). Ejecuta 'make createcipher' primero."; \
		exit 1; \
	fi
	@echo "Ejecutando prueba rápida (2 procesos) con --test-bits 20..."
	mpirun -np 2 ./$(BRUTE_EXE) -f $(CIPHER_FILE) -k "frase_clave" --test-bits 20 -p

bitacora:
	@if [ -x $(BITACORA_SCRIPT) ]; then \
		echo "Ejecutando $(BITACORA_SCRIPT)..."; \
		./$(BITACORA_SCRIPT) 10 6 20; \
	else \
		echo "No se encontró $(BITACORA_SCRIPT) o no es ejecutable."; \
	fi

run_speedup:
	@if [ -x $(RUN_SPEEDUP_SCRIPT) ]; then \
		echo "📈 Ejecutando $(RUN_SPEEDUP_SCRIPT)..."; \
		./$(RUN_SPEEDUP_SCRIPT) $(CIPHER_FILE) "frase_clave" 8 ./$(BRUTE_EXE); \
	else \
		echo "No se encontró $(RUN_SPEEDUP_SCRIPT) o no es ejecutable."; \
	fi

clean:
	@echo "Limpiando..."
	-rm -f $(BRUTE_EXE) $(BRUTE_TEST_EXE) $(CIPHER_EXE) $(CIPHER_FILE) results_speedup.csv bitacora.csv
