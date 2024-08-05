import socket
import json
import sys
import random
sys.path.append("library")
sys.path.append("server/library")
from library.phe import paillier
from library import rsa

class Server:
# Server creates private and public key for client
    def __init__(self):
        self.paillier_pubkn = 5499136237975420695393439280924762080225967562564308602239849883158250310983372123162989130396254458438631748212967783894989302879375435592775673910348240184354459871871116800618524089144252178705602144126561016959141705703738236101636521128253175727947718399905721873949646692013441357312228822770301140969488141647673414428705578889775616708452035585169773466788164149174390703607635824536765428354449297424816213964656371546720653179958532249902282227569438946068450777793589452287357839015650498471033830272590627214558291316154084664164530238238697674696512666998900066914006971820130766972041851178603561958739892148951976664561099358232607691455132111202586202039288204727598186878891931891269500968632152794103062361433333116785330013149884220980957988535629066705883120300328633216959830696020218233263810465718921251342667031157068402519580277875780865804757447693643234947607815483393750021057173250173555764909071
        self.paillier_pubk = paillier.PaillierPublicKey(self.paillier_pubkn)
        self.HOST = "127.0.0.1"  #localhost
        self.PORT = 5001
        
# Server awaits on TCP connection with client
    def app(self):
        def signature_check(eSal, sig, rsaPubkey):
            print("Verifying signature")
            crypto = rsa.verify(eSal, sig, rsaPubkey)
            if crypto == 'SHA-256':
                return True
            else:
                return False
            
        def case_User():
            #Get public RSA_key
            conn.sendall(b'RSA_Key')
            data = conn.recv(2048)
            rsaPubkey = rsa.PublicKey._load_pkcs1_pem(data)
            #Send Paillier public key
            conn.sendall(str(self.paillier_pubkn).encode('utf-8')) #sending public key modulus n, so that user can regenerate pk
            #Receive encrypted data & Signature Check
            sig = conn.recv(2048)
            print(f"Signature received")
            tamperCheck = False
            if sig:
                eSal = conn.recv(2048)
                tamperCheck = signature_check(eSal, sig, rsaPubkey)
            #Check integrity & Store Data
            if tamperCheck:
                print("Passed tamper check")
                # with open("encrypted_database.json", "r+") as f:
                #     existingData = f.read()
                #     f.seek(0)
                #     #### TO DO #### ----ARDINI
                #     #do what you need to do for the database of enc_salaries
                conn.sendall(b"Complete")
            else:
                conn.sendall(b"Incomplete: Tampered Message")

        def case_Client():
            #generate a number with 2048 bits
            upper_rand = random.getrandbits(2048)
            lower = random.randint(1, upper_rand)
            ans = upper_rand - lower
            gen_r = random.randint(1,self.paillier_pubk.get_random_lt_n()) % self.paillier_pubk.max_int
            #ans is upper - lower
            #encrypt all
            upper_enc = self.paillier_pubk.encrypt(upper_rand)
            lower_enc = self.paillier_pubk.encrypt(lower)
            ans_enc = self.paillier_pubk.encrypt(ans, r_value=gen_r)
            r_enc = self.paillier_pubk.encrypt(gen_r)
            #send to client for ZKP
            conn.sendall(str(upper_enc.ciphertext()).encode('utf-8')) 
            conn.sendall(str(lower_enc.ciphertext()).encode('utf-8'))
            conn.sendall(str(r_enc.ciphertext()).encode('utf-8'))
            #response
            clientAns = conn.recv(2048).decode('utf-8')
            if (int(clientAns) == ans_enc.ciphertext(be_secure=False)):
                # with open("encrypted_database.json", "r+") as f:
                #     existingData = f.read()
                #     f.seek(0)
                    # ### TO DO #### ----ARDINI
                    # do what you need to do for the database of enc_salaries
                enc_salaries = 10000
                conn.sendall(str(enc_salaries).encode('utf-8'))
                print("Sent details to Client")
            else:
                print("Client answer is incorrect")
                conn.sendall(b"Answer is incorrect")
        
        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.HOST, self.PORT))
        server_socket.listen(5)
        conn, address = server_socket.accept()
        with conn:
            print(f"Connection with client {address} established")
            data = conn.recv(2048)
            if data:
                match data:
                    case b"User":
                        case_User()
                    case b"Client":
                        case_Client()
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
        encrypted_avg = encrypted_sum/num_vals
        return encrypted_avg
        
if __name__ == '__main__':
    Server().app()