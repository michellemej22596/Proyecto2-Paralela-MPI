#!/usr/bin/env bash
CIPHER=${1:-cipher.bin}
KEYWORD=${2:-frase_clave}
MAXP=${3:-8}
EXEC=${4:-./bruteforce_mpi}
TBITS=${TEST_KEYSPACE_BITS:-24}

OUTFILE="results_speedup.csv"
echo "nprocs,tiempo_seg,speedup" > "$OUTFILE"

echo "Midiendo speedup hasta $MAXP procesos (2^$TBITS claves)..."

# Tiempo secuencial base
echo "Ejecutando caso secuencial base..."
SEQ_TIME=$($EXEC -s -f "$CIPHER" -k "$KEYWORD" --test-bits $TBITS -p \
    | grep "Tiempo" | awk '{print $3}')
echo "1,$SEQ_TIME,1.0" >> "$OUTFILE"

# Pruebas con distintos números de procesos
for np in $(seq 2 $MAXP); do
    echo "Ejecutando con $np procesos..."
    TIME=$(mpirun -np $np $EXEC -f "$CIPHER" -k "$KEYWORD" --test-bits $TBITS -p \
        | grep "Tiempo wallclock" | awk '{print $4}')
    if [ -z "$TIME" ]; then
        echo "$np,ERROR,ERROR" >> "$OUTFILE"
    else
        SPEEDUP=$(awk -v t1="$SEQ_TIME" -v tp="$TIME" 'BEGIN {printf "%.3f", t1/tp}')
        echo "$np,$TIME,$SPEEDUP" >> "$OUTFILE"
    fi
done

echo "Resultados guardados en $OUTFILE"
