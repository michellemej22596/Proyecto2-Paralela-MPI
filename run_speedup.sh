#!/usr/bin/env bash
CIPHER=${1:-cipher.bin}
KEYWORD=${2:-" the "}
MAXP=${3:-8}
OUT=results_speedup.csv
echo "procs,elapsed_s" > $OUT

for p in 1 2 4 8 16; do
  if [ $p -gt $MAXP ]; then break; fi
  echo "Running with $p procs..."
  # ejecutar y capturar tiempo que imprime el root al final "Tiempo wallclock"
  TMP=$(mpirun -np $p ./bruteforce_mpi -f "$CIPHER" -k "$KEYWORD" 2>&1)
  # buscar line with 'Tiempo' or 'wallclock'
  # intenta varias formas
  TIME=$(echo "$TMP" | grep -Eo "Tiempo wallclock: [0-9]+\.[0-9]+" | awk -F': ' '{print $2}' | head -n1)
  if [ -z "$TIME" ]; then
    TIME=$(echo "$TMP" | grep -Eo "Tiempo: [0-9]+\.[0-9]+" | awk -F': ' '{print $2}' | head -n1)
  fi
  if [ -z "$TIME" ]; then
    # intentar última línea numérica: tiempo aproximado
    TIME=$(echo "$TMP" | tail -n3 | grep -Eo "[0-9]+\.[0-9]+" | tail -n1)
  fi
  if [ -z "$TIME" ]; then TIME="NA"; fi
  echo "$p,$TIME" >> $OUT
done

echo "Resultados guardados en $OUT"
