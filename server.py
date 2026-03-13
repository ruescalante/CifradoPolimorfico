import socket
import json
from cipher import CifradoPolimorfico

def imprimir_caja_roja(titulo, paquete):
    print(f"\n{'='*40}")
    print(f"[{titulo}]")
    print(f"ID:      {paquete.get('ID')}")
    print(f"Type:    {paquete.get('Type')}")
    print(f"Payload: {paquete.get('Payload')}")
    print(f"PSN:     {paquete.get('PSN')}")
    print(f"{'='*40}")

#Levantar sockets
def run_server():
    node_server = CifradoPolimorfico()
    node_server.current_key_index = 0
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Servidor en espera en el puerto 5000...")

    conn, addr = server_socket.accept()
    buffer = ""
    
    while True:
        data = conn.recv(4096)
        if not data:
            break
            
        buffer += data.decode('utf-8')
        
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip(): continue
            
            paquete = json.loads(line)
            tipo = paquete.get('Type')
            
            imprimir_caja_roja("PAQUETE ENTRANTE", paquete)

            if tipo == 'FCM':
                datos = paquete.get('Payload')
                node_server.generate_keys(datos['P'], datos['Q'], datos['S'], datos['N'])
                node_server.current_key_index = 0 
                print(f"--> FCM Procesado. Llaves inicializadas: {len(node_server.keys)}")
                
                #Visualizacion del FCM en el servidor
                node_server.print_key_table("FCM: Tablas de llaves sincronizadas (Servidor)", datos['P'], datos['Q'], datos['S'], datos['N'])
                
            elif tipo == 'RM':
                bloques = paquete.get('Payload')
                texto_ensamblado = ""
                llave_actual = node_server.current_key_index
                
                for item in bloques:
                    cipher_int = int(item['bloque_hex'], 16)
                    psn_usado = item['psn_usado']
                    
                    plain_num = node_server.decrypt(cipher_int, llave_actual, psn_usado)
                    
                    try:
                        fragmento = plain_num.to_bytes(8, byteorder='big').decode('utf-8').replace('\x00', '')
                        texto_ensamblado += fragmento
                    except UnicodeDecodeError:
                        texto_ensamblado += "[?]"
                        
                print(f"--> TEXTO DESCIFRADO (Llave {llave_actual}): '{texto_ensamblado}'")
                node_server.current_key_index += 1 
                
            elif tipo == 'KUM':
                datos = paquete.get('Payload')
                node_server.generate_keys(datos['P'], datos['Q'], datos['S'], datos['N'])
                node_server.current_key_index = 0 
                print(f"--> KUM Procesado. Tablas de llaves renovadas: {len(node_server.keys)}")
                
                #Visualizacion del KUM en el servidor
                node_server.print_key_table("KUM: Tablas de llaves actualizadas (Servidor)", datos['P'], datos['Q'], datos['S'], datos['N'])
                
            elif tipo == 'LCM':
                node_server.keys = []
                node_server.last_psn = None
                print("--> Tablas de llaves borradas. Conexión liberada.")
                
                #Visualizacion final para ver borrado
                node_server.print_key_table("LCM: Estado final de la memoria")

    conn.close()

if __name__ == "__main__":
    run_server()