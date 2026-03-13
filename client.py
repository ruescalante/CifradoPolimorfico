import socket
import json
import time
import random
from cipher import CifradoPolimorfico

def imprimir_caja_roja(titulo, paquete):
    print(f"\n{'='*40}")
    print(f"[{titulo}]")
    print(f"ID:      {paquete.get('ID')}")
    print(f"Type:    {paquete.get('Type')}")
    print(f"Payload: {paquete.get('Payload')}")
    print(f"PSN:     {paquete.get('PSN')}")
    print(f"{'='*40}")

def send_msg(sock, paquete):
    imprimir_caja_roja("ENVIANDO PAQUETE", paquete)
    data = json.dumps(paquete) + "\n"
    sock.sendall(data.encode('utf-8'))
    time.sleep(1.5)

def run_client():
    node_client = CifradoPolimorfico()
    node_client.current_key_index = 0
    
    mi_id = f"ID00001"
    print(f"Iniciando dispositivo IoT con ID: {mi_id}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('localhost', 5000))
    except ConnectionRefusedError:
        print("Error: Primero ejecutar Server.py")
        return

    # 1. FCM Inicial 
    P, Q, S, N = node_client.generar_semillas_random(num_keys=2) 
    node_client.generate_keys(P, Q, S, N)
    node_client.current_key_index = 0

    # Llamada agregada para visualizar la tabla inicial
    node_client.print_key_table("FCM: Llaves iniciales en el Cliente", P, Q, S, N)
    
    paquete_fcm = {"ID": mi_id, "Type": "FCM", "Payload": {"P": P, "Q": Q, "S": S, "N": N}, "PSN": "NA"}
    send_msg(client_socket, paquete_fcm)


    #2. RM y KUM dinámico
    
    lecturas_sensor = [
        "Sensor: 25C",
        "Sensor: 26C",
        "Sensor: 28C", 
        "Sensor: 24C"
    ]

    for lectura in lecturas_sensor:
        if node_client.current_key_index >= len(node_client.keys):
            print("\n[!] Alerta: Llaves agotadas. Disparando KUM automático...")
            P_new, Q_new, S_new, N_new = node_client.generar_semillas_random(num_keys=2)
            node_client.generate_keys(P_new, Q_new, S_new, N_new)
            node_client.current_key_index = 0 
            
            # Ver nueva tabla e llaves
            node_client.print_key_table("KUM: Llaves rotadas en el Cliente", P_new, Q_new, S_new, N_new)
            
            paquete_kum = {"ID": mi_id, "Type": "KUM", "Payload": {"P": P_new, "Q": Q_new, "S": S_new, "N": N_new}, "PSN": "NA"}
            send_msg(client_socket, paquete_kum)

        llave_actual = node_client.current_key_index
        print(f"\n--> Cifrando '{lectura}' con la llave OTP índice: {llave_actual}")
        
        bytes_mensaje = lectura.encode('utf-8')
        bloques_cifrados = []
        ultimo_psn = "NA"
        
        for i in range(0, len(bytes_mensaje), 8):
            fragmento = bytes_mensaje[i:i+8]
            entero_64bits = int.from_bytes(fragmento, byteorder='big')
            
            cipher_val, psn_val = node_client.encrypt(entero_64bits, key_index=llave_actual)
            bloques_cifrados.append({"bloque_hex": hex(cipher_val), "psn_usado": psn_val})
            ultimo_psn = psn_val 
            
        paquete_rm = {"ID": mi_id, "Type": "RM", "Payload": bloques_cifrados, "PSN": ultimo_psn}
        send_msg(client_socket, paquete_rm)
        
        node_client.current_key_index += 1

    # 3. LCM Final
    paquete_lcm = {"ID": mi_id, "Type": "LCM", "Payload": "NA", "PSN": "NA"}
    send_msg(client_socket, paquete_lcm)
    client_socket.close()
    print("\nComunicación liberada.")

if __name__ == "__main__":
    run_client()