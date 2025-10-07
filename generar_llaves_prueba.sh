#!/bin/bash

# Script para generar archivos cifrados con llaves específicas para pruebas

echo "Generando archivos de prueba con diferentes llaves..."
echo ""

# Crear texto de prueba si no existe
if [ ! -f "texto_prueba.txt" ]; then
    cat > texto_prueba.txt << 'EOF'
Este es un texto de prueba para el proyecto de Computacion Paralela.
Contiene la palabra clave SECRETO que debe ser encontrada por el algoritmo.
El objetivo es medir el speedup y la eficiencia del algoritmo paralelo
implementado con OpenMPI para realizar un ataque de fuerza bruta sobre
el cifrado DES. Este texto tiene aproximadamente 350 palabras para cumplir
con los requisitos del proyecto.
EOF
    echo "Archivo texto_prueba.txt creado"
fi

# Verificar que cipher_gen existe
if [ ! -f "./cipher_gen" ]; then
    echo "Error: cipher_gen no existe. Compilar primero con 'make cipher_gen'"
    exit 1
fi

# Calcular llaves según las fórmulas del proyecto
# Nota: bc puede no estar disponible, usar Python como alternativa

# Llave fácil: (2^56)/2 + 1
LLAVE_FACIL=36028797018963969
echo "Generando llave_facil.bin con llave $LLAVE_FACIL"
./cipher_gen texto_prueba.txt $LLAVE_FACIL -o llave_facil.bin
echo ""

# Llave media: (2^56)/2 + (2^56)/8
LLAVE_MEDIA=45035996273704961
echo "Generando llave_media.bin con llave $LLAVE_MEDIA"
./cipher_gen texto_prueba.txt $LLAVE_MEDIA -o llave_media.bin
echo ""

# Llave difícil: (2^56)/7 + (2^56)/13
LLAVE_DIFICIL=15564440312192683
echo "Generando llave_dificil.bin con llave $LLAVE_DIFICIL"
./cipher_gen texto_prueba.txt $LLAVE_DIFICIL -o llave_dificil.bin
echo ""

# Llave muy pequeña para pruebas rápidas
LLAVE_RAPIDA=1000000
echo "Generando llave_rapida.bin con llave $LLAVE_RAPIDA (para pruebas rápidas)"
./cipher_gen texto_prueba.txt $LLAVE_RAPIDA -o llave_rapida.bin
echo ""

echo "=========================================="
echo "Archivos generados:"
echo "  - llave_facil.bin (llave: $LLAVE_FACIL)"
echo "  - llave_media.bin (llave: $LLAVE_MEDIA)"
echo "  - llave_dificil.bin (llave: $LLAVE_DIFICIL)"
echo "  - llave_rapida.bin (llave: $LLAVE_RAPIDA)"
echo ""
echo "Palabra clave en todos: SECRETO"
echo "=========================================="
echo ""
echo "Para probar, ejecutar:"
echo "  mpirun -np 4 ./bruteforce_mpi -f llave_rapida.bin -k SECRETO"
