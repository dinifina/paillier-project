import socket
import json
import sys
sys.path.append("library")
sys.path.append("server/library")
from library.phe import paillier
from library import rsa

class Server:
# Server creates private and public key for client
    def __init__(self):
        self.__public_key, self.__private_key = paillier.generate_paillier_keypair() #TEMPORARY
        
# Server awaits on TCP connection with client
    def app(self):
        def signature_check(part1, part2, rsaPubkey):
            crypto = rsa.decrypt(part1, rsaPubkey)
            if crypto == part2:
                return True
            else:
                return False
            
        def case_User(pkey):
            #Get public RSA_key
            conn.sendall(b'RSA_Key')
            data = conn.recv(1024)
            rsaPubkey = rsa.PublicKey._load_pkcs1_pem(data)
            #Send Paillier public key
            conn.sendall(str(pkey).encode('utf-8')) #sending public key modulus n, so that user can regenerate pk
            #Receive encrypted data & Signature Check
            part1 = conn.recv(1024)
            tamperCheck = False
            if part1:
                part2 = conn.recv(1024)
                if part2 != part1:
                    tamperCheck = signature_check(part1, part2, rsaPubkey)
            #Check integrity & Store Data
            if tamperCheck:
                with open("encrypted_database.json", "r+") as f:
                    existingData = f.read()
                    f.seek(0)
                    #### TO DO #### ----ARDINI
                    #read data, and replace with new
                conn.sendall("Complete")
            else:
                conn.sendall("Incomplete: Tampered Message")

        HOST = "127.0.0.1"  #localhost
        PORT = 5000
        server_socket = socket.socket()
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        conn, address = server_socket.accept()
        
        with conn:
            print(f"Connection with client {address} established")
            data = conn.recv(1024)
            if data:
                match data:
                    case b"User":
                        case_User(self.__public_key.n)
                    case b"Client":
                        print("")
                        #check if the client is actually the client
                    case _:
                        print("Invalid")
                        conn.sendall(b'Invalid Request: Please send "User" or "Client"')
                        #Invalid and close the connection
                        
               
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