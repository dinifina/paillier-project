import socket
import sys
sys.path.append("library")
sys.path.append("user/library")
from library import rsa
import time

class user:
    
    def __init__(self):
        (self.pubkey, self.privkey) = rsa.newkeys(2048)
        self.HOST = "127.0.0.1"  # The server's hostname or IP address
        self.PORT = 5000  # The port used by the server
    
    def app(self):
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
            data = s.recv(1024)
            if data:
                s.sendall(self.pubkey.save_pkcs1(format='PEM'))
                print(f"Received {data!r}")
            s.close()
        

if __name__ == '__main__': 
    user().app()
    