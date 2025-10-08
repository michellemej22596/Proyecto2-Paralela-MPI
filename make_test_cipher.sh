#!/usr/bin/env bash
N=${1:-5}              # Número de pruebas (default 5)
NP=${2:-4}             # Número de procesos MPI (default 4)
TBITS=${3:-20}         # Tamaño reducido del keyspace (2^TBITS)

CIPHER="cipher.bin"
PLAIN="mensaje.txt"
KEYWORD="frase_clave"
KEY=5

# Verificar archivos base
if [ ! -f "$PLAIN" ]; then
    echo "No se encontró $PLAIN. Creando archivo de prueba..."
    echo "Este es un mensaje de prueba con la ${KEYWORD} incrustada." > "$PLAIN"
fi

# Generar cipher si no existe
if [ ! -f "$CIPHER" ]; then
    echo "Generando $CIPHER con clave $KEY..."
    ./cipher_gen "$PLAIN" $KEY -o "$CIPHER" -p
fi

# Archivo CSV de salida
OUTFILE="bitacora.csv"
echo "prueba,procesos,test_bits,tiempo_seg" > "$OUTFILE"

echo "Ejecutando $N pruebas con $NP procesos y 2^$TBITS claves..."

for i in $(seq 1 $N); do
    echo "Prueba #$i..."
    # Ejecutar y extraer tiempo desde la salida
    TIME=$(mpirun -np $NP ./bruteforce_mpi -f "$CIPHER" -k "$KEYWORD" --test-bits $TBITS -p \
        | grep "Tiempo wallclock" | awk '{print $4}')
    if [ -z "$TIME" ]; then TIME="ERROR"; fi
    echo "$i,$NP,$TBITS,$TIME" >> "$OUTFILE"
done

echo "Bitácora generada: $OUTFILE"
