# Documentación Técnica - Brute Force DES con MPI

## 1. Algoritmo DES (Data Encryption Standard)

### ¿Qué es DES?

DES es un algoritmo de cifrado simétrico de bloques desarrollado por IBM en los años 70 y adoptado como estándar por el gobierno de EE.UU. en 1977. Utiliza una llave de 56 bits efectivos (64 bits con paridad) para cifrar bloques de 64 bits (8 bytes).

### Características Principales

- **Tipo**: Cifrado simétrico de bloques
- **Tamaño de bloque**: 64 bits (8 bytes)
- **Tamaño de llave**: 56 bits efectivos + 8 bits de paridad = 64 bits totales
- **Modo usado**: ECB (Electronic Codebook)
- **Espacio de búsqueda**: 2^56 = 72,057,594,037,927,936 llaves posibles

### Pasos del Algoritmo DES

#### Cifrado:

1. **Permutación Inicial (IP)**: El bloque de 64 bits se permuta según una tabla fija
2. **Expansión de la Llave**: La llave de 56 bits se expande a 16 subllaves de 48 bits cada una
3. **16 Rondas Feistel**: 
   - División del bloque en mitades izquierda (L) y derecha (R)
   - Función F aplicada a R con la subllave correspondiente
   - XOR del resultado con L
   - Intercambio de mitades
4. **Permutación Final (FP)**: Inversa de la permutación inicial
5. **Salida**: Bloque cifrado de 64 bits

#### Descifrado:

El proceso es idéntico al cifrado, pero usando las subllaves en orden inverso (de la 16 a la 1).

### Diagrama de Flujo DES

\`\`\`
┌─────────────────────────────────────────────────────────────┐
│                    ALGORITMO DES                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Texto Plano     │
                    │    (64 bits)     │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Permutación     │
                    │    Inicial (IP)  │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Dividir en L₀R₀ │
                    │   (32 bits c/u)  │
                    └──────────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
         ┌──────────┐              ┌──────────────┐
         │ Llave    │              │  16 Rondas   │
         │ (56 bits)│──────────────▶  Feistel     │
         └──────────┘              │              │
                                   │  Lᵢ = Rᵢ₋₁   │
                                   │  Rᵢ = Lᵢ₋₁⊕F │
                                   └──────────────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │ Intercambio  │
                                   │   Final      │
                                   └──────────────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │ Permutación  │
                                   │  Final (FP)  │
                                   └──────────────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │ Texto Cifrado│
                                   │  (64 bits)   │
                                   └──────────────┘
\`\`\`

## 2. Explicación de Rutinas Principales

### 2.1 Función `encrypt(key, *text, len)`

**Propósito**: Cifrar un buffer de texto usando DES con una llave de 56 bits.

**Diagrama de Flujo**:
\`\`\`
┌─────────────────────┐
│  encrypt(key, text) │
└─────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Convertir key56 a       │
│ formato DES (8 bytes)   │
│ + paridad impar         │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Crear contexto EVP      │
│ EVP_CIPHER_CTX_new()    │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Inicializar cifrado     │
│ EVP_EncryptInit_ex()    │
│ con EVP_des_ecb()       │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Configurar padding      │
│ EVP_CIPHER_CTX_set_pad()│
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Para cada bloque de 8   │
│ bytes del texto:        │
│ EVP_EncryptUpdate()     │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Finalizar cifrado       │
│ EVP_EncryptFinal_ex()   │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Liberar contexto        │
│ EVP_CIPHER_CTX_free()   │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Retornar texto cifrado  │
└─────────────────────────┘
\`\`\`

**Entradas**:
- `key`: Llave de 56 bits (uint64_t)
- `text`: Puntero al buffer de texto plano
- `len`: Longitud del texto en bytes

**Salidas**:
- Buffer `text` modificado con el texto cifrado

### 2.2 Función `decrypt(key, *cipher, len)`

**Propósito**: Descifrar un buffer cifrado usando DES con una llave de 56 bits.

**Diagrama de Flujo**:
\`\`\`
┌─────────────────────┐
│ decrypt(key, cipher)│
└─────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Convertir key56 a       │
│ formato DES (8 bytes)   │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Crear contexto EVP      │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Inicializar descifrado  │
│ EVP_DecryptInit_ex()    │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Para cada bloque:       │
│ EVP_DecryptUpdate()     │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ EVP_DecryptFinal_ex()   │
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Retornar texto plano    │
└─────────────────────────┘
\`\`\`

**Entradas**:
- `key`: Llave de 56 bits
- `cipher`: Puntero al buffer cifrado
- `len`: Longitud del buffer

**Salidas**:
- Buffer con el texto descifrado

### 2.3 Función `tryKey(key, *cipher, len, *keyword)`

**Propósito**: Probar si una llave descifra correctamente el texto buscando una palabra clave.

**Diagrama de Flujo**:
\`\`\`
┌──────────────────────┐
│ tryKey(key, cipher,  │
│    keyword)          │
└──────────────────────┘
          │
          ▼
┌──────────────────────┐
│ Reservar memoria para│
│ texto plano          │
│ malloc(cipher_len+1) │
└──────────────────────┘
          │
          ▼
┌──────────────────────┐
│ Descifrar con la     │
│ llave proporcionada  │
│ decrypt(key, ...)    │
└──────────────────────┘
          │
          ▼
┌──────────────────────┐
│ Agregar terminador   │
│ nulo '\0'            │
└──────────────────────┘
          │
          ▼
┌──────────────────────┐
│ Buscar keyword en    │
│ texto descifrado     │
│ strstr(plain,keyword)│
└──────────────────────┘
          │
          ▼
┌──────────────────────┐
│ ¿Encontrada?         │
└──────────────────────┘
     │           │
     │ Sí        │ No
     ▼           ▼
┌────────┐  ┌────────┐
│return 1│  │return 0│
└────────┘  └────────┘
\`\`\`

**Entradas**:
- `key`: Llave a probar
- `cipher`: Buffer cifrado
- `len`: Longitud del buffer
- `keyword`: Palabra clave a buscar

**Salidas**:
- `1` si la palabra fue encontrada (llave correcta)
- `0` si no se encontró

### 2.4 Función `memcpy(dest, src, n)`

**Propósito**: Copiar `n` bytes desde `src` a `dest`.

**Uso en el proyecto**: Se usa para copiar bytes residuales (no múltiplos de 8) que no forman un bloque completo de DES.

**Diagrama**:
\`\`\`
Memoria Origen:     [A][B][C][D][E][F][G][H]
                     │  │  │  │  │  │  │  │
                     └──┼──┼──┼──┼──┼──┼──┘
                        ▼  ▼  ▼  ▼  ▼  ▼  ▼
Memoria Destino:    [A][B][C][D][E][F][G][H]
\`\`\`

### 2.5 Función `strstr(haystack, needle)`

**Propósito**: Buscar la primera ocurrencia de la subcadena `needle` en la cadena `haystack`.

**Uso en el proyecto**: Verificar si el texto descifrado contiene la palabra clave.

**Diagrama**:
\`\`\`
haystack: "Este es un texto con PALABRA secreta"
                              ^^^^^^^^
                              needle: "PALABRA"
                              
Retorna: puntero a la 'P' de PALABRA
\`\`\`

## 3. Primitivas MPI

### 3.1 `MPI_Send`

**Propósito**: Enviar un mensaje de forma bloqueante a otro proceso.

**Sintaxis**:
\`\`\`c
int MPI_Send(void *buf, int count, MPI_Datatype datatype, 
             int dest, int tag, MPI_Comm comm)
\`\`\`

**Parámetros**:
- `buf`: Buffer con los datos a enviar
- `count`: Número de elementos
- `datatype`: Tipo de dato (MPI_INT, MPI_UNSIGNED_LONG_LONG, etc.)
- `dest`: Rank del proceso destino
- `tag`: Etiqueta del mensaje
- `comm`: Comunicador (usualmente MPI_COMM_WORLD)

**Flujo de Comunicación**:
\`\`\`
Proceso 0                    Proceso 1
    │                            │
    │  MPI_Send(data, 1, ...)   │
    ├───────────────────────────▶│
    │         [BLOQUEADO]        │
    │                            │ MPI_Recv(...)
    │                            │ [Recibe datos]
    │      [DESBLOQUEADO]        │
    │                            │
    ▼                            ▼
\`\`\`

### 3.2 `MPI_Irecv`

**Propósito**: Iniciar una recepción no bloqueante (asíncrona).

**Sintaxis**:
\`\`\`c
int MPI_Irecv(void *buf, int count, MPI_Datatype datatype,
              int source, int tag, MPI_Comm comm, MPI_Request *request)
\`\`\`

**Parámetros adicionales**:
- `request`: Handle para verificar el estado de la operación

**Flujo de Comunicación**:
\`\`\`
Proceso 0                    Proceso 1
    │                            │
    │                            │ MPI_Irecv(&found, ...)
    │                            │ [NO BLOQUEADO]
    │                            │ [Continúa trabajando]
    │                            │
    │  MPI_Send(found, ...)     │
    ├───────────────────────────▶│
    │                            │ [Mensaje en cola]
    │                            │
    │                            │ MPI_Wait(&request, ...)
    │                            │ [Espera completar]
    │                            │ [Recibe datos]
    ▼                            ▼
\`\`\`

### 3.3 `MPI_Wait`

**Propósito**: Esperar a que una operación no bloqueante se complete.

**Sintaxis**:
\`\`\`c
int MPI_Wait(MPI_Request *request, MPI_Status *status)
\`\`\`

**Uso típico**:
\`\`\`c
MPI_Request req;
MPI_Irecv(buffer, count, MPI_INT, source, tag, comm, &req);

// Hacer otro trabajo mientras se recibe...
do_other_work();

// Ahora necesitamos los datos, esperamos
MPI_Wait(&req, MPI_STATUS_IGNORE);
// Ahora buffer contiene los datos recibidos
\`\`\`

### 3.4 `MPI_Allreduce`

**Propósito**: Operación colectiva que combina valores de todos los procesos y distribuye el resultado a todos.

**Sintaxis**:
\`\`\`c
int MPI_Allreduce(void *sendbuf, void *recvbuf, int count,
                  MPI_Datatype datatype, MPI_Op op, MPI_Comm comm)
\`\`\`

**Flujo de Comunicación (MPI_MAX con 4 procesos)**:
\`\`\`
Antes:
P0: local_found = 0
P1: local_found = 0
P2: local_found = 12345  ← Encontró la llave
P3: local_found = 0

MPI_Allreduce(&local_found, &global_found, 1, 
              MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD)

Después:
P0: global_found = 12345
P1: global_found = 12345
P2: global_found = 12345
P3: global_found = 12345
\`\`\`

## 4. Estrategias de Particionamiento

### 4.1 Block Partition (Por Bloques)

Divide el espacio de búsqueda en bloques contiguos:

\`\`\`
Espacio total: [0 ─────────────────────── 2^56]

Con 4 procesos:
P0: [0 ──────── 2^54]
P1: [2^54 ───── 2^55]
P2: [2^55 ───── 3×2^54]
P3: [3×2^54 ─── 2^56]
\`\`\`

**Ventaja**: Simple de implementar
**Desventaja**: Speedup inconsistente según posición de la llave

### 4.2 Round-Robin (Cíclico)

Asigna llaves de forma intercalada:

\`\`\`
P0: 0, 4, 8, 12, 16, 20, ...
P1: 1, 5, 9, 13, 17, 21, ...
P2: 2, 6, 10, 14, 18, 22, ...
P3: 3, 7, 11, 15, 19, 23, ...
\`\`\`

**Ventaja**: Speedup más consistente
**Desventaja**: Más saltos en memoria (peor localidad)

## 5. Análisis de Speedup

### Fórmula de Speedup

$$S_p = \frac{T_{\text{secuencial}}}{T_{\text{paralelo}}}$$

### Fórmula de Eficiencia

$$E_p = \frac{S_p}{p} = \frac{T_{\text{secuencial}}}{p \times T_{\text{paralelo}}}$$

Donde:
- $$S_p$$ = Speedup con p procesos
- $$E_p$$ = Eficiencia con p procesos
- $$p$$ = Número de procesos
- $$T$$ = Tiempo de ejecución

### Speedup Ideal vs Real

**Ideal**: $$S_p = p$$ (speedup lineal)
**Real**: $$S_p < p$$ debido a overhead de comunicación y sincronización
