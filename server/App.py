import socket
import json
from phe import paillier

class Server:
# Server creates private and public key for client
    def __init__(self):
        self.__public_key, self.__private_key = paillier.generate_paillier_keypair() # wait this doesn't make sense why are we the ones creating the keys
    
# Server awaits on TCP connection with client
    def app(self):
        HOST = "127.0.0.1"  #localhost
        PORT = 5000

        server_socket = socket.socket()
        server_socket.bind((HOST, PORT))
        
        server_socket.listen(5)
        conn, address = server_socket.accept()
        print(f"Connection with client {address} established")
        client_keys = (self.__public_key, self.__private_key)
        data = conn.recv(1024)
        if data:
            # Server receives encrypted result and computes on encrypted results
            print (data.decode('utf-8'))
        # Server sends client both keys
        conn.sendall(str(self.__public_key).encode('utf-8'))
        conn.close()
            
    def deserialise_data(serialised_data):
        # data is sent serialised
        data_dict = json.loads(serialised_data)
        pk = data_dict['public_key']
        public_key = paillier.PaillierPublicKey(g = int(pk['g']), n = int(pk['n']))
        encrypted_data = [
            paillier.EncryptedNumber(public_key, int(x[0]), int(x[1]))
            for x in data_dict['values']
        ]
        return encrypted_data
    
    def compute_average(encrypted_data):
        encrypted_vals = [x[0] for x in encrypted_data]
        encrypted_sum = 0
        num_vals = 0
        for x in encrypted_vals:
            encrypted_sum = encrypted_sum + x
            num_vals += 1
            
        # holy fuck there isn't a division function in this library
        pk = [k[0] for k in encrypted_data]
        n_squared = pk[0] * pk[0]
        inverse_n = paillier.invert(num_vals)
        encrypted_avg = paillier.powmod(encrypted_sum, inverse_n, n_squared)
        return encrypted_avg
        
if __name__ == '__main__':
    Server().app()