# Documentación Técnica del Código Fuente
## Implementación del Algoritmo de Cifrado Polimórfico OTP para IoT
**Asignatura:** DSS101 — Diseño de Sistemas de Seguridad en Redes de Datos  
**Universidad Don Bosco** · Facultad de Ingeniería · Escuela de Electrónica  
**Basado en:** *"Cryptography model to secure IoT device endpoints, based on polymorphic cipher OTP"*  
C. Bran, D. Flores, C. Hernández — IIIE, UDB, 2019

---

## Índice
1. [Estructura del proyecto](#1-estructura-del-proyecto)
2. [cipher.py — Motor criptográfico](#2-cipherpy--motor-criptográfico)
3. [client.py — Dispositivo IoT transmisor](#3-clientpy--dispositivo-iot-transmisor)
4. [server.py — Receptor / Servidor](#4-serverpy--receptor--servidor)
5. [Tabla de correspondencia: Código ↔ Paper](#5-tabla-de-correspondencia-código--paper)

---

## 1. Estructura del proyecto

```
cipher.py   →  Motor criptográfico (caja criptográfica)
client.py   →  Nodo IoT transmisor (cliente TCP)
server.py   →  Nodo IoT receptor  (servidor TCP)
```

Los tres archivos juntos implementan el protocolo completo de comunicación segura entre dos puntos finales IoT descrito en la **Sección II y III** del paper. El flujo general es:

```
Cliente                          Servidor
   |                                |
   |──── FCM (semillas P,Q,S,N) ───>|  ambos generan la misma tabla de llaves
   |──── RM  (datos cifrados)  ────>|  servidor descifra con su tabla
   |──── RM  (datos cifrados)  ────>|
   |──── KUM (nuevas semillas) ────>|  ambos regeneran la tabla
   |──── RM  (datos cifrados)  ────>|
   |──── LCM (cierre sesión)   ────>|  servidor borra la tabla
```

---

## 2. `cipher.py` — Motor Criptográfico

Implementa la clase `CifradoPolimorfico`, que es la *cryptographic box* descrita en el paper. Cubre las **Secciones II y III** completas.

### 2.1 Constructor `__init__`

| Atributo | Descripción | Referencia |
|---|---|---|
| `MASK_64` | Máscara `0xFFFFFFFFFFFFFFFF`. Confina todas las operaciones al espacio de 64 bits. | Actividad req. (a): llaves de 64 bits |
| `keys` | Lista que representa la *key table* (K1…Kn). | Paper Sec. III-A |
| `last_psn` | Último PSN usado. Sirve de puntero para extraer el siguiente PSN. | Paper Sec. III-B |
| `current_key_index` | Índice de la llave activa. Implementa OTP: una llave por mensaje. | Paper Sec. II (OTP) |

---

### 2.2 Funciones base de generación de llaves

> Paper Sec. III-A: *"functions as light as possible will be used so that the time to generate the tables is fast enough in case of key exhaustion"*

| Función | Implementación | Rol en el algoritmo |
|---|---|---|
| `fs(x, y)` | `x ^ y` | **Scrambled**: mezcla el primo P con la semilla S → produce la llave embrión P0 |
| `fg(x, y)` | `(x * y) & MASK_64` | **Generación**: combina P0 con Q para obtener la llave Kn de la tabla |
| `fm(x, y)` | `(x + y) & MASK_64` | **Mutación**: altera la semilla S junto con Q → genera la nueva semilla S0 |

---

### 2.3 `generate_keys(P, Q, S, N)` — Algoritmo Fig. 3 del paper

Implementa el diagrama de flujo de la **Figura 3** del paper. Genera pares de llaves hasta alcanzar N:

```
P0 = fs(P, S)      → llave embrión
K1 = fg(P0, Q)     → primera llave del par → se agrega a la tabla
S0 = fm(S, Q)      → mutación de la semilla
Q0 = fs(Q, S0)     → embrión para segunda llave
K2 = fg(Q0, P0)    → segunda llave del par → se agrega a la tabla
S1 = fm(S0, P0)    → semilla para el siguiente ciclo
P, Q, S = P0, Q0, S1  → los primos y la semilla evolucionan
```

> *"The seed value mutates with each key computation so the sub-index increases by one. On the other hand the sub-indexes of each prime change with the two-key generation."* — Paper Sec. III-A

---

### 2.4 Funciones reversibles `fr1`, `fr2`, `fr3`

> Paper Sec. III-B y Refs. [15][16]: *"reversible functions [...] applied to the message to encrypt it"*

La elección de estas tres funciones es libre (requisito c de la actividad). El grupo propone:

| Función | Cifrado | Descifrado | Nota |
|---|---|---|---|
| `fr1` | `M ^ K` | `C ^ K` | XOR directa. Autorecíproca. |
| `fr2` | `(M + K) & MASK_64` | `(C - K) & MASK_64` | Suma/resta modular 64 bits. |
| `fr3` | `M ^ ((K >> 3) & MASK_64)` | `C ^ ((K >> 3) & MASK_64)` | XOR con la llave desplazada 3 bits. |

---

### 2.5 Tabla polimórfica — `get_function_sequence` / `get_reverse_sequence`

El **PSN** (nibble de 4 bits → valores 0..15) indexa esta tabla y determina **qué funciones** se aplican y **en qué orden**. Esto es el corazón del polimorfismo: el mismo dato cifrado con la misma llave produce resultados distintos si el PSN cambia.

> *"The order of application of the reversible functions is determined by the PSN which is dependent on the data to be protected [...] which makes the process non-deterministic."* — Paper Sec. III-B

La tabla de descifrado aplica siempre el **orden inverso** de las funciones inversas (propiedad de composición reversible).

| PSN | Secuencia cifrado | Secuencia descifrado |
|---|---|---|
| 0 | `fr1` | `fr1_rev` |
| 3 | `fr1 → fr2` | `fr2_rev → fr1_rev` |
| 9 | `fr1 → fr2 → fr3` | `fr3_rev → fr2_rev → fr1_rev` |
| 15 | `fr1 → fr2 → fr1` | `fr1_rev → fr2_rev → fr1_rev` |

*(16 combinaciones totales para PSN 0..15)*

---

### 2.6 `extract_psn(payload, pointer)`

Extrae un nibble (4 bits) del payload en la posición indicada por `pointer`:

```python
shift = (pointer % 16) * 4
PSN   = (payload >> shift) & 0xF
```

El PSN anterior (`last_psn`) actúa como puntero para extraer el PSN del siguiente mensaje, haciendo el proceso no determinístico y dependiente del dato transportado.

> *"PSN can be taken from any part of the message and is used as a pointer for the application of the reversible functions and for the PSN of the next message."* — Paper Sec. II

---

### 2.7 `encrypt(payload, key_index)` — Figura 4 del paper

```
1. Si es el primer mensaje → PSN desde posición 0 del payload
   Si no → PSN desde la posición last_psn del payload
2. Seleccionar llave Kn = keys[current_key_index]
3. Obtener secuencia de funciones para ese PSN
4. Aplicar funciones en cadena: result = fr_n(...fr2(fr1(payload, K), K)..., K)
5. Guardar last_psn para el próximo mensaje
6. Retornar (texto_cifrado, psn_usado)
```

---

### 2.8 `decrypt(cipher, key_index, psn)`

```
1. Seleccionar la misma llave Kn (índice sincronizado con el emisor)
2. Obtener secuencia INVERSA de funciones para el PSN recibido
3. Aplicar funciones inversas en cadena sobre el texto cifrado
4. Retornar el mensaje original
```

> *"The receiver takes the message from which it extracts the PSN for the selection of functions, applies them in reverse using its own calculated key for decryption."* — Paper Sec. III-B

---

### 2.9 `generar_semillas_random()`

Genera P, Q (primos distintos de una lista predefinida) y S (XOR entre timestamp en ms y bits aleatorios de 32 bits), emulando el uso de parámetros físicos del hardware IoT.

> *"a pseudo-random process is used using physical parameters of the IoT core, which can be temperature, program counter state or physical line state."* — Paper Sec. III-A

---

## 3. `client.py` — Dispositivo IoT Transmisor

Simula un nodo IoT cliente que implementa el protocolo completo de cuatro fases.

### Fase 1 — FCM: First Contact Message

- Genera semillas aleatorias P, Q, S, N.
- Construye su tabla de llaves localmente.
- Envía `{"Type": "FCM", "Payload": {P, Q, S, N}, "PSN": "NA"}`.
- El servidor recibe las semillas y genera la misma tabla → **sincronización**.

> *"First Contact Message (FCM): the message sent the first time when the peers have not established a key table for encryption so they exchange identifiers and seeds for key construction."* — Paper Sec. II

### Fase 2 — RM: Regular Messages (con KUM automático)

Para cada lectura de sensor:
1. **Verifica llaves disponibles**: si `current_key_index >= len(keys)` → dispara KUM automático con nuevas semillas.
2. **Divide el mensaje** en bloques de 8 bytes (64 bits), relleno de ceros si es necesario.
3. **Cifra cada bloque** con `encrypt()` → obtiene `(cipher_val, psn_val)`.
4. **Construye el paquete RM**: lista de bloques con su PSN individual.
5. **Incrementa `current_key_index`** → OTP: la llave se consume.

### KUM — Key Update Message (dentro de Fase 2)

- Se dispara cuando las llaves se agotan.
- Genera nuevas semillas y reconstruye la tabla.
- Envía `{"Type": "KUM", "Payload": {P_new, Q_new, S_new, N_new}, "PSN": "NA"}`.

> *"Key update message (KUM): used to change the key table of the pairs and can be triggered by any of the nodes which implies, a reconstruction of the tables with new seed parameters."* — Paper Sec. II

### Fase 3 — LCM: Last Contact Message

- Envía `{"Type": "LCM", "Payload": "NA", "PSN": "NA"}`.
- El servidor borrará su tabla al recibirlo.

---

## 4. `server.py` — Receptor / Servidor

Escucha en puerto 5000 y despacha cada paquete según su campo `Type`.

### Caso FCM
Recibe P, Q, S, N y llama a `generate_keys()` con esos parámetros. La tabla generada es idéntica a la del cliente → sincronización sin transmitir las llaves directamente.

### Caso RM
Para cada bloque del payload:
- Convierte `bloque_hex` a entero de 64 bits.
- Llama a `decrypt(cipher_int, llave_actual, psn_usado)`.
- Convierte el entero descifrado a bytes UTF-8 y elimina relleno `\x00`.
- Incrementa `current_key_index` (OTP sincronizado con el cliente).

### Caso KUM
Idéntico al FCM: regenera la tabla con los nuevos parámetros y reinicia el índice.

### Caso LCM
```python
node_server.keys = []       # Destruye la tabla de llaves
node_server.last_psn = None # Resetea el estado PSN
```
> *"Last Contact Message (LCM): used to release the peer-to-peer communication, thereby deleting the key tables and the peer identifier."* — Paper Sec. II

---

## 5. Tabla de correspondencia: Código ↔ Paper

| Elemento del paper | Sección | Implementación en el código |
|---|---|---|
| Funciones base `fs`, `fg`, `fm` | Sec. III-A, Fig. 3 | `cipher.py`: `fs()`, `fg()`, `fm()` |
| Algoritmo generación de tabla de llaves | Sec. III-A, Fig. 3 | `cipher.py`: `generate_keys()` |
| Llaves de 64 bits | Sec. III-A / Actividad (a) | `cipher.py`: `MASK_64` + `generate_keys()` |
| Funciones reversibles `fr()` | Sec. III-B, Fig. 4, Refs. [15][16] | `cipher.py`: `fr1`, `fr2`, `fr3` y sus inversas |
| Tabla polimórfica PSN → funciones | Sec. III-B | `cipher.py`: `get_function_sequence()` + `get_reverse_sequence()` |
| Extracción del PSN del payload | Sec. II, Sec. III-B | `cipher.py`: `extract_psn()` |
| Mecanismo de cifrado completo | Sec. III-B, Fig. 4 | `cipher.py`: `encrypt()` |
| Mecanismo de descifrado completo | Sec. III-B | `cipher.py`: `decrypt()` |
| Semillas pseudo-aleatorias (P, Q, S) | Sec. III-A | `cipher.py`: `generar_semillas_random()` |
| Encapsulamiento ID + Type + Payload + PSN | Sec. II, Fig. 2 | `client.py` + `server.py` (diccionario JSON) |
| FCM — First Contact Message | Sec. II | `client.py`: `paquete_fcm` / `server.py`: caso FCM |
| RM — Regular Message cifrado | Sec. II | `client.py`: `paquete_rm` / `server.py`: caso RM |
| KUM — Key Update Message | Sec. II | `client.py`: KUM automático / `server.py`: caso KUM |
| LCM — Last Contact Message | Sec. II | `client.py`: `paquete_lcm` / `server.py`: caso LCM |
| Rotación de llaves OTP (una por mensaje) | Sec. II (OTP) | `client.py` + `server.py`: `current_key_index++` |
| Sincronización por semillas (sin transmitir llaves) | Sec. III-A, Sec. IV-B | `server.py`: `generate_keys()` con mismos P, Q, S, N |
| Destrucción de llaves al cerrar sesión | Sec. II (LCM) | `server.py`: `keys = []` en caso LCM |
| Modelo cliente-servidor TCP/IP | Sec. IV-B | `client.py` + `server.py`: sockets Python |