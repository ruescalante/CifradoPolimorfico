import random
import time

class CifradoPolimorfico:
    
    def __init__(self):
        self.MASK_64 = 0xFFFFFFFFFFFFFFFF
        self.keys = []
        self.last_psn = None
        self.current_key_index = 0
        
    #Funciones base
    def fs(self, x, y):
        return x ^ y

    def fg(self, x, y):
        return (x * y) & self.MASK_64

    def fm(self, x, y):
        return (x + y) & self.MASK_64

    #Generacion de llaves
    def generate_keys(self, P, Q, S, N):

        self.keys = []
        self.current_key_index = 0
        while len(self.keys) < N:

            P0 = self.fs(P, S)
            K1 = self.fg(P0, Q)
            self.keys.append(K1)

            if len(self.keys) == N:
                break

            S0 = self.fm(S, Q)

            Q0 = self.fs(Q, S0)
            K2 = self.fg(Q0, P0)
            self.keys.append(K2)

            S1 = self.fm(S0, P0)

            P, Q, S = P0, Q0, S1

    #Funciones reversibles
    def fr1(self, M, K):
        return M ^ K

    def fr1_rev(self, C, K):
        return C ^ K

    def fr2(self, M, K):
        return (M + K) & self.MASK_64

    def fr2_rev(self, C, K):
        return (C - K) & self.MASK_64

    def fr3(self, M, K):
        return M ^ ((K >> 3) & self.MASK_64)

    def fr3_rev(self, C, K):
        return C ^ ((K >> 3) & self.MASK_64)

   #Tabla polimorfica 16
    def get_function_sequence(self, psn):
        secuencias = {
            0:  [self.fr1],
            1:  [self.fr2],
            2:  [self.fr3],
            3:  [self.fr1, self.fr2],
            4:  [self.fr2, self.fr1],
            5:  [self.fr1, self.fr3],
            6:  [self.fr3, self.fr1],
            7:  [self.fr2, self.fr3],
            8:  [self.fr3, self.fr2],
            9:  [self.fr1, self.fr2, self.fr3],
            10: [self.fr1, self.fr3, self.fr2],
            11: [self.fr2, self.fr1, self.fr3],
            12: [self.fr2, self.fr3, self.fr1],
            13: [self.fr3, self.fr1, self.fr2],
            14: [self.fr3, self.fr2, self.fr1],
            15: [self.fr1, self.fr2, self.fr1]
        }
        return secuencias[psn]

    def get_reverse_sequence(self, psn):
        secuencias_reversibles = {

            0:  [self.fr1_rev],
            1:  [self.fr2_rev],
            2:  [self.fr3_rev],
            3:  [self.fr2_rev, self.fr1_rev],
            4:  [self.fr1_rev, self.fr2_rev],
            5:  [self.fr3_rev, self.fr1_rev],
            6:  [self.fr1_rev, self.fr3_rev],
            7:  [self.fr3_rev, self.fr2_rev],
            8:  [self.fr2_rev, self.fr3_rev],
            9:  [self.fr3_rev, self.fr2_rev, self.fr1_rev],
            10: [self.fr2_rev, self.fr3_rev, self.fr1_rev],
            11: [self.fr3_rev, self.fr1_rev, self.fr2_rev],
            12: [self.fr1_rev, self.fr3_rev, self.fr2_rev],
            13: [self.fr2_rev, self.fr1_rev, self.fr3_rev],
            14: [self.fr1_rev, self.fr2_rev, self.fr3_rev],
            15: [self.fr1_rev, self.fr2_rev, self.fr1_rev]
        }
        return secuencias_reversibles[psn]

    #Extraer PSN
    def extract_psn(self, payload, pointer):

        shift = (pointer % 16) * 4
        return (payload >> shift) & 0xF

   #Cifrado
    def encrypt(self, payload, key_index):

        if self.last_psn is None:
            psn = self.extract_psn(payload, 0)
        else:
            psn = self.extract_psn(payload, self.last_psn)

        key = self.keys[self.current_key_index]

        funcs = self.get_function_sequence(psn)

        result = payload

        for f in funcs:
            result = f(result, key)

        self.last_psn = psn

        return result, psn

    #Descifrado
    def decrypt(self, cipher, key_index, psn):

        key = self.keys[self.current_key_index]

        funcs = self.get_reverse_sequence(psn)

        result = cipher

        for f in funcs:
            result = f(result, key)

        self.last_psn = psn

        return result

    #Visualizar tabla de llaves
    def print_key_table(self, title="Tabla de Llaves", P=None, Q=None, S=None, N=None):
        print(f"\n{title}")
        
        if P is not None:
            print(f"Semillas Recibidas/Usadas -> P: {P} | Q: {Q} | S: {S} | N: {N}")
            
        print("+" + "-"*8 + "+" + "-"*20 + "+")
        print("| Índice | Valor (Hexadecimal)  |")
        print("+" + "-"*8 + "+" + "-"*20 + "+")
        
        if not self.keys:
            print("| (Tabla vacía)                 |")
        else:
            for i, key in enumerate(self.keys):
                print(f"| K{i+1:<5} | {hex(key):<18} |")
                
        print("+" + "-"*8 + "+" + "-"*20 + "+\n")
        
      #Crear semillas aleatoriamente.
    def generar_semillas_random(self, num_keys=10):
        primos_disponibles = [104729, 1299709, 324161, 49979687, 15485863, 32452843, 86028121]
        
        P = random.choice(primos_disponibles)
        Q = random.choice([p for p in primos_disponibles if p != P])
        
        ruido_termico = random.getrandbits(32)
        tiempo_ms = int(time.time() * 1000)
    
        S = tiempo_ms ^ ruido_termico
        N = num_keys
        
        return P, Q, S, N