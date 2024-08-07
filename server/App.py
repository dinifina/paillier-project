import socket
import json
import sys
import random
sys.path.append("library")
sys.path.append("server/library")
from library.phe import paillier
from library import rsa
from library.phe.util import invert

class Server:
# Server creates private and public key for client
    def __init__(self):
        self.paillier_pubkn = 5499136237975420695393439280924762080225967562564308602239849883158250310983372123162989130396254458438631748212967783894989302879375435592775673910348240184354459871871116800618524089144252178705602144126561016959141705703738236101636521128253175727947718399905721873949646692013441357312228822770301140969488141647673414428705578889775616708452035585169773466788164149174390703607635824536765428354449297424816213964656371546720653179958532249902282227569438946068450777793589452287357839015650498471033830272590627214558291316154084664164530238238697674696512666998900066914006971820130766972041851178603561958739892148951976664561099358232607691455132111202586202039288204727598186878891931891269500968632152794103062361433333116785330013149884220980957988535629066705883120300328633216959830696020218233263810465718921251342667031157068402519580277875780865804757447693643234947607815483393750021057173250173555764909071
        self.paillier_pubk = paillier.PaillierPublicKey(self.paillier_pubkn)
        self.HOST = "127.0.0.1"  #localhost
        self.PORT = 5001
        self.paillier_privp = 2291292959459873742182383900054479391339700075384482340707171597222637753428982942135876616674834980588956082914497983323609878055163913673083122014066981864854387257287366450869841777395703056864869916769392211298707889663660821824217424226969315077124558206593513725965392398588623991580206534578545358867501948813058379147845661872322134245769526192727427523249551211627263771242588677795763761064959606188877489985097399439441995501723152754101529672052876749
        self.paillier_privq = 2400014461385911788918503599704110282044406274459797245917989349468276415689997733503592043325745636623418256635614566120119952917822250676012612171375454338574831876060764665075250733280368089240160444323280177594304415506597977681769227587578451397160601317154226273302655586540225313998942177689678449257293801038700828359986151157739904272740583626898333810052151020550143223563935819013949241180528087184915193853237170566101070478538812000228092104563279179
        self.paillier_pubkn = 5499136237975420695393439280924762080225967562564308602239849883158250310983372123162989130396254458438631748212967783894989302879375435592775673910348240184354459871871116800618524089144252178705602144126561016959141705703738236101636521128253175727947718399905721873949646692013441357312228822770301140969488141647673414428705578889775616708452035585169773466788164149174390703607635824536765428354449297424816213964656371546720653179958532249902282227569438946068450777793589452287357839015650498471033830272590627214558291316154084664164530238238697674696512666998900066914006971820130766972041851178603561958739892148951976664561099358232607691455132111202586202039288204727598186878891931891269500968632152794103062361433333116785330013149884220980957988535629066705883120300328633216959830696020218233263810465718921251342667031157068402519580277875780865804757447693643234947607815483393750021057173250173555764909071
        self.paillier_privk = paillier.PaillierPrivateKey(self.paillier_pubk,self.paillier_privp, self.paillier_privq)

        
# Server awaits on TCP connection with client
    def app(self):
        def signature_check(message, sig, rsaPubkey):
            print("Verifying signature")
            crypto = rsa.verify(message, sig, rsaPubkey)
            if crypto == 'SHA-256':
                return True
            else:
                return False
            
        def compute_average(data):
            values = [paillier.EncryptedNumber(self.paillier_pubk, x) for x in data['salaries']]
            encrypted_sum = self.paillier_pubk.encrypt(0)
            num_values = data['num']
            for x in values:
                encrypted_sum = encrypted_sum._add_encrypted(x)
            encrypted_avg = encrypted_sum.__truediv__(num_values)    
            return encrypted_avg

        def case_User():
            #Get public RSA_key
            conn.sendall(b'RSA_Key')
            data = conn.recv(2048)
            rsaPubkey = rsa.PublicKey._load_pkcs1_pem(data)
            #Send Paillier public key modulus
            conn.sendall(str(self.paillier_pubkn).encode('utf-8')) #sending public key modulus n, so that user can regenerate pk
            #Receive encrypted data & Signature Check
            sig = conn.recv(2048)
            print(f"Signature received")
            tamperCheck = False
            if sig:
                message = conn.recv(2048)
                print(f"Authentication in progress")
                tamperCheck = signature_check(message, sig, rsaPubkey)
            #Check integrity & Store Data
            if tamperCheck:
                print("Passed tamper check")
                with open("encrypted_database.json", "r+") as f:
                    jsonData = f.read()
                    f.seek(0)
                    # save encrypted val to db
                    data = json.loads(jsonData)
                    encryptedSal = int(message.decode('utf-8'))
                    salaryKey = 'salaries'
                    numPeopleKey = 'num'
                    if salaryKey and numPeopleKey in data:
                        data[salaryKey].append(encryptedSal)
                        data[numPeopleKey] += 1
                    json.dump(data, f)
                    print("Successfully computed")
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
                with open("encrypted_database.json", "r+") as f:
                    # read encrypted number
                    file_content = f.read()
                    data = json.loads(file_content)
                    
                average = compute_average(data)
                temp = str(average.ciphertext()).encode('utf-8')
                expo = str(average.exponent).encode('utf-8')
                conn.sendall(temp)
                conn.sendall(expo)
                #conn.sendall(temp)
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

        
if __name__ == '__main__':
    Server().app()