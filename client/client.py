import socket
import sys
sys.path.append("library")
sys.path.append("client/library")
from library import rsa

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 5000  # The port used by the server

if __name__ == '__main__': 
    (pubkey, privkey) = rsa.newkeys(1024)
    message = b'my top secret'
    crypto = rsa.encrypt(message,privkey)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(pubkey.save_pkcs1(format='PEM'))
        data = s.recv(1024)
        print(f"Received {data!r}")
        s.close()
        