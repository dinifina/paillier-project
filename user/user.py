import socket
import sys
sys.path.append("library")
sys.path.append("user/library")
from library import rsa
from library.phe import paillier
import time

class user:
    def __init__(self):
        (self.pubkey, self.privkey) = rsa.newkeys(2048)
        self.HOST = "127.0.0.1"  # The server's hostname or IP address
        self.PORT = 5000  # The port used by the server
        self.salary = 10000
    
    def app(self):
        def send_sigMsg(rsaSign, encryptedSal):
            s.sendall(rsaSign)
            s.sendall(encryptedSal)
            
        def serverResponse(data):
            match data:
                case b'RSA_Key':
                    s.sendall(self.pubkey.save_pkcs1(format='PEM'))
                    #Get Paillier pubkey Modulus
                    data = s.recv(1024).decode('utf-8')
                    if data:
                        paillierPubk = paillier.PaillierPublicKey(int(data))
                        #Encrypt salary
                        encryptedSal = str(paillierPubk.encrypt(self.salary).ciphertext()).encode('utf-8')
                        #Encrypted msg with private key
                        rsaSign = rsa.encrypt(encryptedSal, self.privkey)
                        return rsaSign, encryptedSal
                    else:
                        return None, None
                case _:
                    print("Invalid data")
                    return None, None
                    
        message = b'User'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            while True:
                try:
                    s.connect((self.HOST, self.PORT))
                    break
                except Exception as e:
                    print("retrying: ", e)
                    time.sleep(1)
            print("Connected to Server")
            s.sendall(message)
            #Server response
            data = s.recv(1024)
            if data:
                rsaSign, encryptedSal = serverResponse(data)
                if (rsaSign != None and encryptedSal != None):
                    send_sigMsg(rsaSign, encryptedSal)
                    data = s.recv(1024).decode('utf-8')
                    if data:
                        match data:
                            case 'Complete':
                                print("Your Salary has been uploaded securely")
                            case _:
                                print(data)
            else:
                s.close()
                
if __name__ == '__main__': 
    user().app()
    