#!/usr/bin/env bash
# make_test_cipher.sh
# Genera plain.txt con la palabra clave " the " y crea cipher.bin con llave pequeña,
# luego ejecuta várias corridas en paralelo para crear bitacora.csv
# Uso: ./make_test_cipher.sh [TRIALS] [MAX_PROCS] [TEST_BITS]
TRIALS=${1:-10}
MAX_PROCS=${2:-6}   # se probarán procesos 2,4,6,... hasta MAX_PROCS (ajusta)
TEST_BITS=${3:-20}  # espacio 2^TEST_BITS para pruebas rápidas (ej. 20)
CIPHER=./cipher.bin
PLAIN=./plain.txt
KEY=0x0000000000000005  # llave pequeña para pruebas
PROG=./bruteforce
CSV=bitacora.csv

if [ ! -x "$PROG" ]; then
  echo "No encuentro $PROG - compila primero: mpicc bruteforce.c -o bruteforce -lcrypto"
  exit 1
fi

# crear plain.txt (tiene la palabra clave " the ")
cat > $PLAIN <<EOF
This is a short test file.
It contains the secret phrase: the quick brown fox.
Use this file to test brute-force DES program.
EOF

echo "Creando cipher con key $KEY..."
$PROG --create-cipher $PLAIN $KEY $CIPHER
if [ $? -ne 0 ]; then echo "Error creando cipher"; exit 1; fi

echo "test_bits,$TEST_BITS" > $CSV
echo "procs,trial,elapsed_seconds,found_key" >> $CSV

for PROCS in $(seq 2 2 $MAX_PROCS); do
  echo "=== Ejecutando con $PROCS procesos (TRIALS=$TRIALS) ==="
  for T in $(seq 1 $TRIALS); do
    # correr en paralelo y capturar tiempo. Usamos --test-bits para reducir keyspace
    # Redirigimos stdout/err a temp y parseamos tiempo real por rank 0 echoado al final
    OUT=$(mpirun -np $PROCS $PROG $CIPHER " the " --test-bits $TEST_BITS 2>&1)
    # Extraer la línea con "[SEQUENTIAL]" o "rank X: rango" para tiempo; buscamos la última aparición de "tiempo local" o "tiempo total"
    # Esto es simple: buscamos "tiempo" en la salida
    ELAPSED=$(echo "$OUT" | grep -oE "tiempo (total|local): [0-9]+\.[0-9]+" | tail -n1 | grep -oE "[0-9]+\.[0-9]+")
    # Si no se encontró por el patrón anterior, tratamos de buscar "tiempo" en cualquier línea
    if [ -z "$ELAPSED" ]; then
      # fallback: buscar línea que contiene "rank 0" y extraer número al final (poco robusto)
      ELAPSED=$(echo "$OUT" | grep -oE "[0-9]+\.[0-9]+ s" | head -n1 | grep -oE "[0-9]+\.[0-9]+")
    fi
    # Extraer found key si existe
    FOUND=$(echo "$OUT" | grep -oE "Llave encontrada: 0x[0-9a-fA-F]+" | head -n1 | awk '{print $3}')
    ELAPSED=${ELAPSED:-0}
    FOUND=${FOUND:-NA}
    echo "$PROCS,$T,$ELAPSED,$FOUND" >> $CSV
    echo "Trial $T procs $PROCS => elapsed=$ELAPSED found=$FOUND"
  done
done

echo "Bitácora guardada en $CSV"
