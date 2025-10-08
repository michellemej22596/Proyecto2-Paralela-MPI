#!/usr/bin/env bash
set -euo pipefail

CIPHER=${1:-cipher.bin}
KEYWORD=${2:-frase_clave}
MAXP=${3:-8}
EXEC=${4:-./bruteforce_mpi}
TBITS=${5:-24}

OUTFILE="results_speedup.csv"
TMP_LOG="tmp_speed_log.txt"

if [ ! -x "$EXEC" ]; then
    echo "ERROR: ejecutable no encontrado o no ejecutable: $EXEC"
    exit 1
fi
if [ ! -f "$CIPHER" ]; then
    echo "ERROR: archivo cipher no encontrado: $CIPHER"
    exit 1
fi

echo "nprocs,tiempo_sec,speedup" > "$OUTFILE"
echo "Midiendo speedup hasta $MAXP procesos (2^$TBITS claves) ..."

# Caso secuencial: lanzar con mpirun -np 1
echo "Ejecutando caso secuencial base (1 proceso)..."
mpirun --oversubscribe -np 1 "$EXEC" -f "$CIPHER" -k "$KEYWORD" --test-bits "$TBITS" -p 2>&1 | tee "$TMP_LOG"

# Extraer primer número decimal (robusto)
SEQ_TIME=$(grep -iE 'tiempo.*wallclock|wallclock|Elapsed|Tiempo' "$TMP_LOG" | head -n1 | grep -oE '[0-9]+\.[0-9]+' || true)
if [ -z "$SEQ_TIME" ]; then
    SEQ_TIME=$(grep -oE '[0-9]+\.[0-9]+' "$TMP_LOG" | head -n1 || true)
fi

# Fallback si no se captura SEQ_TIME
if [ -z "$SEQ_TIME" ] || [ "$SEQ_TIME" = "0" ]; then
    echo "WARNING: No se capturó un tiempo válido para 1 proceso. Usando fallback 0.000001 para evitar división por cero."
    SEQ_TIME="0.000001"
fi

echo "1,${SEQ_TIME},1.0" >> "$OUTFILE"

# Pruebas con distintos números de procesos
for np in $(seq 2 1 "$MAXP"); do
    echo "Ejecutando con $np procesos..."
    mpirun --oversubscribe -np "$np" "$EXEC" -f "$CIPHER" -k "$KEYWORD" --test-bits "$TBITS" -p 2>&1 | tee "$TMP_LOG"

    # Extraer tiempo decimal
    TIME=$(grep -iE 'tiempo.*wallclock|wallclock|Elapsed|Tiempo' "$TMP_LOG" | head -n1 | grep -oE '[0-9]+\.[0-9]+' || true)
    if [ -z "$TIME" ]; then
        TIME=$(grep -oE '[0-9]+\.[0-9]+' "$TMP_LOG" | head -n1 || true)
    fi

    if [ -z "$TIME" ] || [ "$TIME" = "0" ]; then
        echo "$np,ERROR,ERROR" >> "$OUTFILE"
        echo "Warning: no se pudo extraer tiempo válido para np=$np (revisa la salida)"
        continue
    fi

    SPEEDUP=$(awk -v t1="$SEQ_TIME" -v tp="$TIME" 'BEGIN{
        t1f = (t1=="" ? 0 : t1) + 0;
        tpf = (tp=="" ? 0 : tp) + 0;
        if(t1f <= 0 || tpf <= 0){ print "NaN"; exit }
        printf "%.6f", t1f / tpf
    }')

    echo "$np,$TIME,$SPEEDUP" >> "$OUTFILE"
done

rm -f "$TMP_LOG"
echo "Resultados guardados en $OUTFILE"
