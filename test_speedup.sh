#!/bin/bash

# Script para automatizar pruebas de speedup
# Uso: ./test_speedup.sh <cipher_file> <keyword> <max_processes>

if [ $# -lt 3 ]; then
    echo "Uso: $0 <cipher_file> <keyword> <max_processes>"
    echo "Ejemplo: $0 cipher.bin SECRETO 8"
    exit 1
fi

CIPHER_FILE=$1
KEYWORD=$2
MAX_PROCS=$3
PROGRAM="./bruteforce_mpi"
ITERATIONS=3

# Verificar que el programa existe
if [ ! -f "$PROGRAM" ]; then
    echo "Error: $PROGRAM no existe. Compilar primero con 'make bruteforce_mpi'"
    exit 1
fi

# Verificar que el archivo cifrado existe
if [ ! -f "$CIPHER_FILE" ]; then
    echo "Error: $CIPHER_FILE no existe"
    exit 1
fi

echo "=========================================="
echo "Pruebas de Speedup - Brute Force DES MPI"
echo "=========================================="
echo "Archivo cifrado: $CIPHER_FILE"
echo "Palabra clave: $KEYWORD"
echo "Procesos máximos: $MAX_PROCS"
echo "Iteraciones por configuración: $ITERATIONS"
echo ""

# Crear archivo de resultados
RESULTS_FILE="resultados_$(date +%Y%m%d_%H%M%S).txt"
echo "Resultados guardados en: $RESULTS_FILE"
echo ""

# Escribir encabezado en archivo de resultados
{
    echo "Pruebas de Speedup - $(date)"
    echo "Archivo: $CIPHER_FILE"
    echo "Keyword: $KEYWORD"
    echo "=========================================="
    echo ""
} > "$RESULTS_FILE"

# Función para ejecutar y medir tiempo
run_test() {
    local procs=$1
    local iter=$2
    
    echo "  Iteración $iter..."
    
    if [ $procs -eq 1 ]; then
        # Modo secuencial
        TIME_OUTPUT=$( { time $PROGRAM -f "$CIPHER_FILE" -k "$KEYWORD" -s > /dev/null 2>&1; } 2>&1 )
    else
        # Modo paralelo
        TIME_OUTPUT=$( { time mpirun -np $procs $PROGRAM -f "$CIPHER_FILE" -k "$KEYWORD" > /dev/null 2>&1; } 2>&1 )
    fi
    
    # Extraer tiempo real (puede variar según el sistema)
    REAL_TIME=$(echo "$TIME_OUTPUT" | grep real | awk '{print $2}')
    echo "    Tiempo: $REAL_TIME"
    
    echo "$REAL_TIME" >> temp_times_${procs}.txt
}

# Prueba secuencial (baseline)
echo "=========================================="
echo "Prueba Secuencial (Baseline)"
echo "=========================================="
{
    echo "SECUENCIAL (1 proceso)"
    echo "----------------------"
} >> "$RESULTS_FILE"

for i in $(seq 1 $ITERATIONS); do
    run_test 1 $i
done

# Calcular promedio secuencial
echo "" >> "$RESULTS_FILE"
cat temp_times_1.txt >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Pruebas paralelas
for procs in $(seq 2 2 $MAX_PROCS); do
    echo ""
    echo "=========================================="
    echo "Prueba con $procs procesos"
    echo "=========================================="
    
    {
        echo ""
        echo "CON $procs PROCESOS"
        echo "-------------------"
    } >> "$RESULTS_FILE"
    
    for i in $(seq 1 $ITERATIONS); do
        run_test $procs $i
    done
    
    echo "" >> "$RESULTS_FILE"
    cat temp_times_${procs}.txt >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
done

# Limpiar archivos temporales
rm -f temp_times_*.txt

echo ""
echo "=========================================="
echo "Pruebas completadas"
echo "=========================================="S
echo "Resultados guardados en: $RESULTS_FILE"
echo ""
echo "Para calcular speedup y eficiencia, usar las fórmulas:"
echo "  Speedup = T_secuencial / T_paralelo"
echo "  Eficiencia = Speedup / num_procesos"
