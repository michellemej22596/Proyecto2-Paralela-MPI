# Proyecto 2 - Brute Force DES con MPI

Proyecto de Computación Paralela y Distribuida - Universidad del Valle de Guatemala

## Descripción

Este proyecto implementa un ataque de fuerza bruta para encontrar la llave privada usada para cifrar un texto con el algoritmo DES (Data Encryption Standard). Utiliza OpenMPI para paralelizar la búsqueda en el espacio de claves de 56 bits.

## Requisitos del Sistema

- **Compilador**: GCC con soporte para C11
- **OpenMPI**: versión 4.0 o superior
- **OpenSSL**: versión 3.0 o superior (con proveedor legacy para DES)
- **Sistema Operativo**: Linux (Ubuntu, Debian, etc.)

### Instalación de Dependencias (Ubuntu/Debian)

\`\`\`bash
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install libopenmpi-dev openmpi-bin
sudo apt-get install libssl-dev
\`\`\`

## Compilación

El proyecto incluye un Makefile para facilitar la compilación:

\`\`\`bash
# Compilar todos los programas
make all

# Compilar solo el generador de cifrados
make cipher_gen

# Compilar versión secuencial
make bruteforce

# Compilar versión paralela con MPI
make bruteforce_mpi

# Compilar versión alternativa con DES
make bruteforce_des_mpi

# Limpiar archivos compilados
make clean
\`\`\`

## Uso

### 1. Generar un Archivo Cifrado

Primero, crea un archivo de texto plano (por ejemplo, `texto.txt`) con el contenido que deseas cifrar:

\`\`\`bash
echo "Este es un texto de prueba con la palabra clave SECRETO para buscar" > texto.txt
\`\`\`

Luego, cifra el archivo usando una llave de 56 bits:

\`\`\`bash
./cipher_gen texto.txt 123456789 -o mi_cifrado.bin
\`\`\`

**Parámetros:**
- `texto.txt`: archivo de entrada (texto plano)
- `123456789`: llave de 56 bits en formato decimal
- `-o mi_cifrado.bin`: archivo de salida (opcional, por defecto `cipher.bin`)
- `-p`: activar padding PKCS#5/7 (opcional)

**Ejemplos de llaves para pruebas:**
\`\`\`bash
# Llave fácil (proceso 2 de 4 la encuentra rápido)
./cipher_gen texto.txt 18014398509481985 -o facil.bin

# Llave media
./cipher_gen texto.txt 27021597764222977 -o media.bin

# Llave difícil
./cipher_gen texto.txt 15564440312192683 -o dificil.bin
\`\`\`

### 2. Buscar la Llave (Modo Secuencial)

Para probar el algoritmo en modo secuencial (sin paralelización):

\`\`\`bash
./bruteforce_mpi -f mi_cifrado.bin -k SECRETO -s
\`\`\`

**Parámetros:**
- `-f <archivo>`: archivo binario con el texto cifrado
- `-k <palabra>`: palabra clave a buscar en el texto descifrado
- `-s`: modo secuencial (opcional)
- `-p`: activar padding si se usó al cifrar (opcional)

### 3. Buscar la Llave (Modo Paralelo con MPI)

Para ejecutar con múltiples procesos MPI:

\`\`\`bash
# Con 4 procesos
mpirun -np 4 ./bruteforce_mpi -f mi_cifrado.bin -k SECRETO

# Con 8 procesos
mpirun -np 8 ./bruteforce_mpi -f mi_cifrado.bin -k SECRETO

# Con padding activado
mpirun -np 4 ./bruteforce_mpi -f mi_cifrado.bin -k SECRETO -p
\`\`\`

**Parámetros de mpirun:**
- `-np N`: número de procesos a utilizar
- `--hostfile hosts.txt`: archivo con lista de hosts para cluster (opcional)

### 4. Versión con Estrategia Round-Robin

El programa `bruteforce_des_mpi` incluye una estrategia de particionamiento round-robin para mejorar la consistencia del speedup:

\`\`\`bash
# Modo block partition (por defecto)
mpirun -np 4 ./bruteforce_des_mpi -f mi_cifrado.bin -k SECRETO

# Modo round-robin
mpirun -np 4 ./bruteforce_des_mpi -f mi_cifrado.bin -k SECRETO --partition=roundrobin

# Pruebas rápidas con espacio reducido (solo primeros N bits)
mpirun -np 4 ./bruteforce_des_mpi -f mi_cifrado.bin -k SECRETO --test-bits 24
\`\`\`

## Estructura del Proyecto

\`\`\`
.
├── Makefile                    # Archivo de compilación
├── README.md                   # Este archivo
├── DOCUMENTACION.md            # Documentación técnica detallada
├── MEDICIONES.md               # Plantilla para bitácora de mediciones
├── bruteforce.c                # Versión secuencial base
├── bruteforce_mpi.c            # Versión paralela con MPI (simple)
├── bruteforce_des_mpi.c        # Versión paralela optimizada
├── cipher_gen.c                # Generador de archivos cifrados
├── test_speedup.sh             # Script para pruebas automatizadas
├── cipher.bin                  # Archivo cifrado de ejemplo
└── cipher_test.bin             # Archivo cifrado de prueba
\`\`\`

## Ejemplos de Uso Completo

### Ejemplo 1: Prueba Rápida

\`\`\`bash
# 1. Crear texto
echo "Hola mundo con palabra CLAVE secreta" > test.txt

# 2. Cifrar con llave pequeña
./cipher_gen test.txt 1000 -o test.bin

# 3. Buscar con 4 procesos
mpirun -np 4 ./bruteforce_mpi -f test.bin -k CLAVE
\`\`\`

### Ejemplo 2: Medición de Speedup

\`\`\`bash
# Crear archivo de prueba
echo "Texto largo para pruebas de speedup con KEYWORD importante" > speedup.txt

# Cifrar con llave conocida
./cipher_gen speedup.txt 50000000 -o speedup.bin

# Medir tiempo secuencial
time ./bruteforce_mpi -f speedup.bin -k KEYWORD -s

# Medir con 2 procesos
time mpirun -np 2 ./bruteforce_mpi -f speedup.bin -k KEYWORD

# Medir con 4 procesos
time mpirun -np 4 ./bruteforce_mpi -f speedup.bin -k KEYWORD

# Medir con 8 procesos
time mpirun -np 8 ./bruteforce_mpi -f speedup.bin -k KEYWORD
\`\`\`

### Ejemplo 3: Cluster Multi-Máquina

\`\`\`bash
# 1. Crear archivo hosts.txt con las IPs de las máquinas
cat > hosts.txt << EOF
192.168.1.10 slots=4
192.168.1.11 slots=4
192.168.1.12 slots=4
EOF

# 2. Ejecutar en el cluster
mpirun --hostfile hosts.txt -np 12 ./bruteforce_mpi -f cipher.bin -k PALABRA
\`\`\`

## Solución de Problemas

### Error: "DES not available"
Asegúrate de que OpenSSL 3 esté instalado con el proveedor legacy:
\`\`\`bash
openssl list -providers
\`\`\`

### Error: "mpirun: command not found"
Instala OpenMPI:
\`\`\`bash
sudo apt-get install openmpi-bin libopenmpi-dev
\`\`\`

### El programa no encuentra la llave
- Verifica que la palabra clave esté correctamente escrita
- Asegúrate de usar `-p` si cifraste con padding
- Confirma que el archivo cifrado no esté corrupto

## Autores

Silvia Illescas, Isabella Miralles, Michelle Mejia

## Licencia

Proyecto académico - Universidad del Valle de Guatemala
