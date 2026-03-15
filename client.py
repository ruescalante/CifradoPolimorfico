# =============================================================================
# client.py — Dispositivo IoT transmisor (nodo cliente)
#
# Simula un dispositivo IoT actuando como cliente en el modelo cliente-servidor
# descrito en la Sección IV-B del paper:
#   "Real Nodes Implementation — The test bench was implemented using wireless
#    connection through WiFi for each node. Each node working on client-server
#    model. Being the client who always trigger the communication process."
#
# Implementa el flujo completo del protocolo de intercambio de mensajes
# definido en la Sección II del paper:
#   FCM → RM (con KUM automático si se agotan llaves) → LCM
# =============================================================================

import socket
import json
import time
import random
from cipher import CifradoPolimorfico

# =============================================================================
# AUXILIAR — Visualización del encapsulamiento de mensajes
#
# Imprime en consola los cuatro campos del encapsulamiento definido en
# la Figura 2 del paper: ID, Type, Payload y PSN.
# Paper Sec. II, Fig. 2: "A simple encapsulation structure is proposed to
# manage the pairs of communication nodes and the exchange of keys."
# =============================================================================

def imprimir_caja_roja(titulo, paquete):
    print(f"\n{'='*40}")
    print(f"[{titulo}]")
    print(f"ID:      {paquete.get('ID')}")       # Identificador del nodo origen
    print(f"Type:    {paquete.get('Type')}")     # Tipo de mensaje: FCM/RM/KUM/LCM
    print(f"Payload: {paquete.get('Payload')}") # Cuerpo del mensaje (semillas o datos cifrados)
    print(f"PSN:     {paquete.get('PSN')}")      # Polymorphic Sequence Nibble
    print(f"{'='*40}")


# =============================================================================
# AUXILIAR — Envío de paquete por socket TCP
#
# Serializa el diccionario Python a JSON y lo envía al servidor.
# El salto de línea "\n" actúa como delimitador de paquete para que
# el servidor pueda reconstruir el mensaje desde el buffer.
# =============================================================================

def send_msg(sock, paquete):
    imprimir_caja_roja("ENVIANDO PAQUETE", paquete)
    data = json.dumps(paquete) + "\n"
    sock.sendall(data.encode('utf-8'))
    # Pausa entre mensajes para simular la cadencia de un nodo IoT real.
    time.sleep(1.5)


# =============================================================================
# FUNCIÓN PRINCIPAL — Flujo del protocolo completo
#
# Paper Sec. IV-B: "the client starts the first contact aiming to exchange
# the generated keys with the server [...] Once the exchange is successful
# the client and server are synchronized."
# =============================================================================

def run_client():
    # Instancia la caja criptográfica del nodo cliente.
    # Paper Sec. III: "The proposed model is described in three main functions:
    # the first is the key table generation mechanism, the second is the
    # encryption mechanism and the third is the key table update."
    node_client = CifradoPolimorfico()
    node_client.current_key_index = 0
    
    # ── ID del nodo ───────────────────────────────────────────────────────────
    # Paper Sec. II: "The node ID identifies the origin of the initial message
    # and is used to differentiate the key tables. It is randomly initialized
    # according to the number of available bits which are limited by the
    # processor resources and the non-volatile memory of the IoT."
    mi_id = f"ID00001"
    print(f"Iniciando dispositivo IoT con ID: {mi_id}")

    # Establece la conexión TCP con el servidor (puerto 5000).
    # Paper Sec. IV-B: "Each node working on client-server model."
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('localhost', 5000))
    except ConnectionRefusedError:
        print("Error: Primero ejecutar Server.py")
        return

    # =========================================================================
    # FASE 1 — FCM: First Contact Message
    #
    # Primer mensaje del protocolo. El cliente aún no tiene tabla de llaves
    # en el servidor, por lo que envía los parámetros semilla P, Q, S, N
    # para que ambos nodos generen la misma tabla de forma independiente.
    #
    # Paper Sec. II: "First Contact Message (FCM) it is the message sent the
    # first time when the peers have not established a key table for encryption
    # so they exchange identifiers and seeds for key construction."
    #
    # Paper Sec. IV-B: "the client starts the first contact aiming to exchange
    # the generated keys with the server. The pair keys exchanged in this
    # process are S, P, and Q."
    # =========================================================================

    # Genera semillas pseudo-aleatorias (emula parámetros físicos del IoT).
    # Paper Sec. III-A: "a pseudo-random process is used using physical
    # parameters of the IoT core."
    P, Q, S, N = node_client.generar_semillas_random(num_keys=2)

    # Construye la tabla de llaves local con las semillas generadas.
    node_client.generate_keys(P, Q, S, N)
    node_client.current_key_index = 0

    # Muestra la tabla para verificar la generación de llaves.
    # Cubre el requisito (b) de la actividad: "Evaluar la calidad de la
    # generación de llaves de cifrado en cada punto final."
    node_client.print_key_table("FCM: Llaves iniciales en el Cliente", P, Q, S, N)
    
    # El PSN se envía como "NA" porque no hay datos cifrados en el FCM;
    # aún no existe una tabla de llaves activa entre los pares.
    paquete_fcm = {"ID": mi_id, "Type": "FCM", "Payload": {"P": P, "Q": Q, "S": S, "N": N}, "PSN": "NA"}
    send_msg(client_socket, paquete_fcm)


    # =========================================================================
    # FASE 2 — RM: Regular Messages (con KUM automático)
    #
    # El cliente cifra lecturas de sensor y las envía como mensajes RM.
    # Cada RM usa una llave diferente de la tabla (OTP: una llave por mensaje).
    # Si se agotan las llaves, se dispara automáticamente un KUM.
    #
    # Paper Sec. II: "Regular Messages (RM) it represents a normal encrypted
    # message once the peers have constructed the key tables and cipher strategy."
    # =========================================================================

    lecturas_sensor = [
        "Sensor: 25C",
        "Sensor: 26C",
        "Sensor: 28C", 
        "Sensor: 24C"
    ]

    for lectura in lecturas_sensor:

        # ── KUM: Key Update Message (disparo automático) ───────────────────
        # Si el índice supera el tamaño de la tabla, las llaves se agotaron.
        # Se genera una nueva tabla con semillas frescas y se notifica al servidor.
        # Paper Sec. II: "Key update message (KUM) it is used to change the key
        # table of the pairs and can be triggered by any of the nodes which
        # implies, a reconstruction of the tables with new seed parameters."
        if node_client.current_key_index >= len(node_client.keys):
            print("\n[!] Alerta: Llaves agotadas. Disparando KUM automático...")

            # Genera nuevas semillas y reconstruye la tabla de llaves.
            P_new, Q_new, S_new, N_new = node_client.generar_semillas_random(num_keys=2)
            node_client.generate_keys(P_new, Q_new, S_new, N_new)
            node_client.current_key_index = 0 
            
            node_client.print_key_table("KUM: Llaves rotadas en el Cliente", P_new, Q_new, S_new, N_new)
            
            # Envía el KUM al servidor con los nuevos parámetros semilla.
            # El PSN es "NA" porque el KUM no lleva datos cifrados.
            paquete_kum = {"ID": mi_id, "Type": "KUM", "Payload": {"P": P_new, "Q": Q_new, "S": S_new, "N": N_new}, "PSN": "NA"}
            send_msg(client_socket, paquete_kum)

        llave_actual = node_client.current_key_index
        print(f"\n--> Cifrando '{lectura}' con la llave OTP índice: {llave_actual}")
        
        # ── Preparación del mensaje: división en bloques de 64 bits ───────
        # Paper Sec. III-B: "The process starts by dividing the message into
        # parts so that its number is an integer for a proper selection of
        # the PSN, to ensure this the most significant part of the message
        # is filled with zeros."
        bytes_mensaje = lectura.encode('utf-8')
        bloques_cifrados = []
        ultimo_psn = "NA"
        
        for i in range(0, len(bytes_mensaje), 8):
            # Toma fragmentos de 8 bytes (64 bits), alineado al tamaño de la llave.
            fragmento = bytes_mensaje[i:i+8]

            # Convierte los bytes a un entero de 64 bits (big-endian).
            # Los bytes faltantes se rellenan implícitamente con ceros al
            # usar int.from_bytes sobre un fragmento menor a 8 bytes.
            entero_64bits = int.from_bytes(fragmento, byteorder='big')
            
            # ── Cifrado del bloque ─────────────────────────────────────────
            # Llama al mecanismo de cifrado polimórfico (Fig. 4 del paper).
            # Retorna el bloque cifrado y el PSN que se usó para cifrarlo.
            # El PSN debe incluirse en el paquete para que el servidor descifre.
            cipher_val, psn_val = node_client.encrypt(entero_64bits, key_index=llave_actual)
            bloques_cifrados.append({"bloque_hex": hex(cipher_val), "psn_usado": psn_val})
            ultimo_psn = psn_val 
            
        # ── Construcción del paquete RM ────────────────────────────────────
        # El Payload contiene la lista de bloques cifrados.
        # El PSN del último bloque se envía en el campo PSN del encapsulamiento,
        # siguiendo la Figura 2 del paper (campo PSN de 4 bits).
        paquete_rm = {"ID": mi_id, "Type": "RM", "Payload": bloques_cifrados, "PSN": ultimo_psn}
        send_msg(client_socket, paquete_rm)
        
        # Avanza al siguiente índice de llave (OTP: una llave por mensaje).
        # Implementa el concepto de que las llaves se "consumen" y no se reusan.
        node_client.current_key_index += 1


    # =========================================================================
    # FASE 3 — LCM: Last Contact Message
    #
    # Cierra la sesión de comunicación. El servidor borrará su tabla de llaves
    # y el identificador del par al recibir este mensaje.
    #
    # Paper Sec. II: "Last Contact Message (LCM) it is used to release the
    # peer-to-peer communication, thereby deleting the key tables and the
    # peer identifier."
    # =========================================================================

    # Payload y PSN son "NA" porque el LCM no transporta datos.
    paquete_lcm = {"ID": mi_id, "Type": "LCM", "Payload": "NA", "PSN": "NA"}
    send_msg(client_socket, paquete_lcm)
    client_socket.close()
    print("\nComunicación liberada.")

if __name__ == "__main__":
    run_client()