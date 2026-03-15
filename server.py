# =============================================================================
# server.py — Receptor / Servidor (nodo receptor del par IoT)
#
# Implementa el receptor en el modelo cliente-servidor descrito en la
# Sección IV-B del paper:
#   "Cryptography model to secure IoT device endpoints,
#    based on polymorphic cipher OTP"
#   C. Bran, D. Flores, C. Hernández — Universidad Don Bosco, 2019
#
# Paper Sec. IV-B: "Each node working on client-server model [...] the server
# only can decrypt with success the encrypted messages when the server is
# synchronized correctly with the respected client."
#
# Corresponde al modo "server-receiver" de la Tabla III del paper (consumo
# de memoria flash en ESP8266 con cifrado habilitado: 303 685 Bytes, 65 %).
# =============================================================================

import socket
import json
from cipher import CifradoPolimorfico

# =============================================================================
# AUXILIAR — Visualización del encapsulamiento de mensajes entrantes
#
# Imprime los cuatro campos del encapsulamiento definido en la Figura 2
# del paper: ID, Type, Payload y PSN.
# Paper Sec. II, Fig. 2: "A simple encapsulation structure is proposed to
# manage the pairs of communication nodes and the exchange of keys [...] 
# 4 fields: node ID, message type and the effective payload which leaves
# a nibble for handling the mutation sequence to be applied for message
# encryption."
# =============================================================================

def imprimir_caja_roja(titulo, paquete):
    print(f"\n{'='*40}")
    print(f"[{titulo}]")
    print(f"ID:      {paquete.get('ID')}")       # Identificador del nodo origen
    print(f"Type:    {paquete.get('Type')}")     # Tipo de mensaje: FCM/RM/KUM/LCM
    print(f"Payload: {paquete.get('Payload')}") # Semillas o bloques cifrados
    print(f"PSN:     {paquete.get('PSN')}")      # Polymorphic Sequence Nibble
    print(f"{'='*40}")


# =============================================================================
# FUNCIÓN PRINCIPAL — Bucle de recepción y procesado de paquetes
# =============================================================================

def run_server():
    # Instancia la caja criptográfica del nodo servidor.
    # Comparte la misma clase CifradoPolimorfico que el cliente; la
    # sincronización se logra regenerando la tabla con los mismos parámetros
    # semilla (P, Q, S, N) recibidos en el FCM o KUM.
    node_server = CifradoPolimorfico()
    node_server.current_key_index = 0
    
    # ── Levanta el socket TCP en el puerto 5000 ────────────────────────────
    # Paper Sec. IV-B: modelo cliente-servidor sobre WiFi TCP/IP con ESP8266.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Servidor en espera en el puerto 5000...")

    conn, addr = server_socket.accept()

    # Buffer acumulativo: los paquetes JSON se delimitan con "\n".
    # Permite reconstruir mensajes aunque lleguen fragmentados por TCP.
    buffer = ""
    
    while True:
        data = conn.recv(4096)
        if not data:
            break
            
        buffer += data.decode('utf-8')
        
        # Procesa cada línea completa del buffer (un paquete por línea).
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip():
                continue
            
            # Deserializa el paquete JSON al diccionario Python.
            paquete = json.loads(line)
            tipo = paquete.get('Type')
            
            imprimir_caja_roja("PAQUETE ENTRANTE", paquete)

            # =================================================================
            # CASO FCM — First Contact Message
            #
            # El servidor recibe los parámetros semilla P, Q, S, N y regenera
            # localmente la misma tabla de llaves que tiene el cliente.
            # NO se transmiten las llaves directamente; ambos lados ejecutan
            # el mismo algoritmo determinístico con los mismos parámetros.
            #
            # Paper Sec. III-A: "Three parameters are exchanged between the
            # pairs to start the process: two prime numbers P and Q, one for
            # each IoT pair, and a seed S defined by the node that initiates
            # the first message."
            #
            # Paper Sec. IV-B: "The pair keys exchanged in this process are
            # S, P, and Q. Once the exchange is successful the client and
            # server are synchronized."
            # =================================================================

            if tipo == 'FCM':
                datos = paquete.get('Payload')

                # Regenera la tabla de llaves con los parámetros recibidos.
                # Después de esta llamada, node_server.keys es idéntica a
                # la tabla del cliente → sincronización completa.
                node_server.generate_keys(datos['P'], datos['Q'], datos['S'], datos['N'])
                node_server.current_key_index = 0 
                print(f"--> FCM Procesado. Llaves inicializadas: {len(node_server.keys)}")
                
                # Visualiza la tabla para verificar la sincronización.
                # Requisito (b) de la actividad: evaluar calidad de generación.
                node_server.print_key_table("FCM: Tablas de llaves sincronizadas (Servidor)", datos['P'], datos['Q'], datos['S'], datos['N'])

            # =================================================================
            # CASO RM — Regular Message (mensaje cifrado)
            #
            # El servidor descifra cada bloque del payload usando la llave
            # en el índice sincronizado y el PSN enviado por el cliente.
            #
            # Paper Sec. II: "Regular Messages (RM) it represents a normal
            # encrypted message once the peers have constructed the key tables
            # and cipher strategy."
            #
            # Paper Sec. III-B: "The receiver takes the message from which it
            # extracts the PSN for the selection of functions, applies them in
            # reverse using its own calculated key for decryption."
            # =================================================================

            elif tipo == 'RM':
                bloques = paquete.get('Payload')
                texto_ensamblado = ""
                llave_actual = node_server.current_key_index
                
                for item in bloques:
                    # Convierte el bloque cifrado de hexadecimal a entero de 64 bits.
                    cipher_int = int(item['bloque_hex'], 16)

                    # Recupera el PSN que el cliente usó para cifrar este bloque.
                    # El PSN viene en el campo "psn_usado" de cada bloque del payload.
                    psn_usado = item['psn_usado']
                    
                    # ── Descifrado del bloque ──────────────────────────────
                    # Aplica las funciones inversas en orden inverso sobre el
                    # texto cifrado para recuperar el entero de 64 bits original.
                    # Paper Fig. 4 (proceso inverso): aplicar fr_rev() en orden
                    # inverso al orden de cifrado.
                    plain_num = node_server.decrypt(cipher_int, llave_actual, psn_usado)
                    
                    # Convierte el entero de 64 bits de vuelta a bytes UTF-8
                    # y elimina el relleno de ceros añadido en el cliente.
                    try:
                        fragmento = plain_num.to_bytes(8, byteorder='big').decode('utf-8').replace('\x00', '')
                        texto_ensamblado += fragmento
                    except UnicodeDecodeError:
                        texto_ensamblado += "[?]"
                        
                print(f"--> TEXTO DESCIFRADO (Llave {llave_actual}): '{texto_ensamblado}'")

                # Avanza al siguiente índice de llave (OTP: sincronizado con el cliente).
                # Paper: la llave Kn se consume con cada mensaje RM y no se reutiliza.
                node_server.current_key_index += 1 

            # =================================================================
            # CASO KUM — Key Update Message
            #
            # Funciona igual que el FCM: el servidor regenera la tabla de llaves
            # con los nuevos parámetros semilla recibidos y reinicia el índice.
            # Puede ser disparado por cualquiera de los dos nodos.
            #
            # Paper Sec. II: "Key update message (KUM) it is used to change the
            # key table of the pairs and can be triggered by any of the nodes
            # which implies, a reconstruction of the tables with new seed
            # parameters."
            # =================================================================

            elif tipo == 'KUM':
                datos = paquete.get('Payload')

                # Reemplaza la tabla de llaves existente por una nueva,
                # generada con los parámetros frescos enviados por el cliente.
                node_server.generate_keys(datos['P'], datos['Q'], datos['S'], datos['N'])
                node_server.current_key_index = 0 
                print(f"--> KUM Procesado. Tablas de llaves renovadas: {len(node_server.keys)}")
                
                node_server.print_key_table("KUM: Tablas de llaves actualizadas (Servidor)", datos['P'], datos['Q'], datos['S'], datos['N'])

            # =================================================================
            # CASO LCM — Last Contact Message
            #
            # Destruye la tabla de llaves y resetea el estado criptográfico.
            # Implementa el concepto OTP de expiración de llaves: al cerrar
            # la sesión, todo el material criptográfico es eliminado.
            #
            # Paper Sec. II: "Last Contact Message (LCM) it is used to release
            # the peer-to-peer communication, thereby deleting the key tables
            # and the peer identifier."
            # =================================================================

            elif tipo == 'LCM':
                # Borra la tabla de llaves en memoria.
                node_server.keys = []
                # Resetea el último PSN: la sesión ha terminado.
                node_server.last_psn = None
                print("--> Tablas de llaves borradas. Conexión liberada.")
                
                # Visualiza el estado final para confirmar el borrado.
                node_server.print_key_table("LCM: Estado final de la memoria")

    conn.close()

if __name__ == "__main__":
    run_server()