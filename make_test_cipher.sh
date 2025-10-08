#!/usr/bin/env bash
set -euo pipefail

N=${1:-5}              # Número de pruebas (default 5)
NP=${2:-4}             # Número de procesos MPI (default 4)
TBITS=${3:-20}         # Tamaño reducido del keyspace (2^TBITS)

CIPHER="cipher.bin"
PLAIN="mensaje.txt"
KEYWORD="frase_clave"
KEY=5
BINARY="./bruteforce_mpi"
OUTFILE="bitacora.csv"
TMP_LOG="tmp_bitacora_log.txt"

# Verificar y generar plaintext si falta
if [ ! -f "$PLAIN" ]; then
    echo "No se encontró $PLAIN. Creando archivo de prueba..."
    echo "Este es un mensaje de prueba con la ${KEYWORD} incrustada." > "$PLAIN"
fi

# Generar cipher si no existe
if [ ! -f "$CIPHER" ]; then
    if [ ! -x "./cipher_gen" ]; then
        echo "ERROR: no se encontró el generador cipher_gen. Compila primero."
        exit 1
    fi
    echo "Generando $CIPHER con clave $KEY..."
    ./cipher_gen "$PLAIN" $KEY -o "$CIPHER" -p
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: no se encontró el ejecutable $BINARY. Compila primero (make all)."
    exit 1
fi

echo "prueba,procesos,test_bits,tiempo_seg" > "$OUTFILE"
echo "Ejecutando $N pruebas con $NP procesos y 2^$TBITS claves..."

for i in $(seq 1 $N); do
    echo "Prueba #$i..."
    # Ejecutar y capturar salida completa
    mpirun --oversubscribe -np "$NP" "$BINARY" -f "$CIPHER" -k "$KEYWORD" --test-bits "$TBITS" -p 2>&1 | tee "$TMP_LOG"

    TIME=$(grep -iE 'tiempo.*wallclock|wallclock|Elapsed|Tiempo' "$TMP_LOG" | \
           head -n1 | \
           grep -oE '[0-9]+\.[0-9]+' || true)

    if [ -z "$TIME" ]; then
        TIME=$(grep -oE '[0-9]+\.[0-9]+' "$TMP_LOG" | head -n1 || true)
    fi

    if [ -z "$TIME" ]; then
        echo "WARNING: No se pudo extraer tiempo decimal para la prueba #$i. Revisa $TMP_LOG"
        TIME="ERROR"
    fi
    # -----------------------------------------------------------------------

    echo "$i,$NP,$TBITS,$TIME" >> "$OUTFILE"
done

rm -f "$TMP_LOG"
echo "Bitácora generada: $OUTFILE"
