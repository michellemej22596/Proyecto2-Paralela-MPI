#!/bin/bash

# Script para preparar la entrega del foro
# Genera el archivo cifrado con una llave específica

echo "=========================================="
echo "Preparando entrega para el foro de Canvas"
echo "=========================================="
echo ""

# Verificar que existe el archivo de texto
if [ ! -f "texto_para_cifrar.txt" ]; then
    echo "❌ Error: No se encuentra texto_para_cifrar.txt"
    exit 1
fi

# Verificar que existe cipher_gen
if [ ! -f "./cipher_gen" ]; then
    echo "⚠️  cipher_gen no encontrado. Compilando..."
    make cipher_gen
fi

# Generar una llave aleatoria pero documentada
# Puedes cambiar este valor por cualquier número de 56 bits
LLAVE="0x1A2B3C4D5E6F7A"  # Ejemplo de llave en hexadecimal

echo "📝 Archivo de entrada: texto_para_cifrar.txt"
echo "🔑 Llave utilizada: $LLAVE"
echo "🎯 Palabra clave: PALABRA_CLAVE_XYLOPHONE_2025_PROYECTO_MPI"
echo ""

# Cifrar el archivo
echo "🔐 Cifrando archivo..."
./cipher_gen texto_para_cifrar.txt mi_texto_cifrado.bin "$LLAVE"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ ¡Archivo cifrado exitosamente!"
    echo ""
    echo "=========================================="
    echo "INFORMACIÓN PARA PUBLICAR EN EL FORO:"
    echo "=========================================="
    echo ""
    echo "📎 Archivo a subir: mi_texto_cifrado.bin"
    echo ""
    echo "📋 Mensaje para el foro:"
    echo "---"
    echo "Equipo: 9"
    echo "Palabra clave: PALABRA_CLAVE_XYLOPHONE_2025_PROYECTO_MPI"
    echo "Tamaño del texto: ~350 palabras"
    echo "Algoritmo: DES con OpenSSL EVP"
    echo "---"
    echo ""
    echo "⚠️  IMPORTANTE: Guarda la llave $LLAVE en un lugar seguro"
    echo "   (la necesitarás para verificar que otros equipos la encuentren)"
    echo ""
else
    echo "❌ Error al cifrar el archivo"
    exit 1
fi
