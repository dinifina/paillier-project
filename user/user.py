import socket
import sys
import json
sys.path.append("library")
sys.path.append("user/library")
from library import rsa
from library.phe import paillier
import time

class user:
    def __init__(self):
        ############### BOTH CLIENT & USER HAS ACCESS TO THESE
        self.HOST = "127.0.0.1"  # The server's hostname or IP address
        self.PORT = 5001  # The port used by the server
        self.salary = 22051
        ############### ONLY USER HAS ACCESS TO THIS
        (self.pubkey, self.privkey) = rsa.newkeys(2047)
        ############### ONLY CLIENT HAS ACCESS TO THIS (KEY GENERATED FROM PHE.PAILLIER)
        self.paillier_privp = 2291292959459873742182383900054479391339700075384482340707171597222637753428982942135876616674834980588956082914497983323609878055163913673083122014066981864854387257287366450869841777395703056864869916769392211298707889663660821824217424226969315077124558206593513725965392398588623991580206534578545358867501948813058379147845661872322134245769526192727427523249551211627263771242588677795763761064959606188877489985097399439441995501723152754101529672052876749
        self.paillier_privq = 2400014461385911788918503599704110282044406274459797245917989349468276415689997733503592043325745636623418256635614566120119952917822250676012612171375454338574831876060764665075250733280368089240160444323280177594304415506597977681769227587578451397160601317154226273302655586540225313998942177689678449257293801038700828359986151157739904272740583626898333810052151020550143223563935819013949241180528087184915193853237170566101070478538812000228092104563279179
        self.paillier_pubkn = 5499136237975420695393439280924762080225967562564308602239849883158250310983372123162989130396254458438631748212967783894989302879375435592775673910348240184354459871871116800618524089144252178705602144126561016959141705703738236101636521128253175727947718399905721873949646692013441357312228822770301140969488141647673414428705578889775616708452035585169773466788164149174390703607635824536765428354449297424816213964656371546720653179958532249902282227569438946068450777793589452287357839015650498471033830272590627214558291316154084664164530238238697674696512666998900066914006971820130766972041851178603561958739892148951976664561099358232607691455132111202586202039288204727598186878891931891269500968632152794103062361433333116785330013149884220980957988535629066705883120300328633216959830696020218233263810465718921251342667031157068402519580277875780865804757447693643234947607815483393750021057173250173555764909071
        ############### Paillier keys
        self.paillier_pubk = paillier.PaillierPublicKey(self.paillier_pubkn)
        self.paillier_privk = paillier.PaillierPrivateKey(self.paillier_pubk,self.paillier_privp, self.paillier_privq)
        self.public_g = self.paillier_pubk.g
        
    def app(self):
        def send_sigMsg(rsaSign, sal):
            print("Sending your signature")
            s.sendall(rsaSign)
            print(f"Signature Sent")
            print(f"Sending encrypted salary")
            s.sendall(sal)
        
        def RSA_sign(msg):
            skey = self.privkey
            result = rsa.sign(msg, skey, 'SHA-256')
            return result

        def serverResponse_user(data):
            match data:
                case b'RSA_Key':
                    s.sendall(self.pubkey.save_pkcs1(format='PEM'))
                    #Get Paillier pubkey Modulus
                    data = s.recv(2048).decode('utf-8')
                    if data:
                        # Encrypted msg with private key
                        encryptedSal = str(self.paillier_pubk.encrypt(self.salary).ciphertext(be_secure=False)).encode('utf-8')
                        rsaSign = RSA_sign(encryptedSal)
                        return rsaSign, encryptedSal
                    else:
                        return None, None
                case _:
                    print("Invalid data")
                    return None, None
        
        def serverResponse_client(upper, lower, r_enc):
            upper_enc = paillier.EncryptedNumber(self.paillier_pubk, int(upper))
            lower_enc = paillier.EncryptedNumber(self.paillier_pubk, int(lower))
            rval_enc = paillier.EncryptedNumber(self.paillier_pubk, int(r_enc))
            upper_dec = self.paillier_privk.decrypt(upper_enc)
            lower_dec = self.paillier_privk.decrypt(lower_enc)
            rval = self.paillier_privk.decrypt(rval_enc)
            ans = upper_dec-lower_dec
            ans_enc = str(self.paillier_pubk.encrypt(ans, r_value=rval).ciphertext(be_secure=False)).encode('utf-8')
            s.sendall(ans_enc)
            response = s.recv(2024).decode("utf-8")
            #decode response
            enc_num = paillier.EncryptedNumber(self.paillier_pubk, int(response))
            avg = self.paillier_privk.decrypt(enc_num)
            print(f"Average: {avg}")
            
        
        def getUserType():       
            while True:
                try:
                    choice = int(input("'1' for User \n'2' for Client\n"))
                    assert 0 < choice < 3
                except ValueError:
                    print("Incorrect input, please enter numbers '1' or '2'")
                except AssertionError:
                    print("Incorrect input, please enter numbers '1' or '2'")
                else:
                    break
                
            if choice == 1:
                return (b'User')
            else:  
                return (b'Client')

        message = getUserType()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while True:
                try:
                    s.connect((self.HOST, self.PORT))
                    break
                except Exception as e:
                    print("retrying: ", e)
                    time.sleep(1)
            print("Connected to Server")
            #Server response
            if message == b'User':
                # Sends 'user'
                s.sendall(message)
                # Receive 
                data = s.recv(2048)
                if data:
                    rsaSign, encryptedSal = serverResponse_user(data)
                    if (rsaSign != None and encryptedSal != None):
                        send_sigMsg(rsaSign, encryptedSal)
                        data = s.recv(2048).decode('utf-8')
                        if data:
                            match data:
                                case 'Complete':
                                    print("Your salary has been uploaded securely")
                                case _:
                                    print(data)
                else:
                    s.close()
            else:
                #If not access as user, you are accessing as client
                s.sendall(message)
                upper = s.recv(2048).decode('utf-8')
                lower = s.recv(2048).decode('utf-8')
                r_enc = s.recv(2048).decode('utf-8')
                if upper and lower and r_enc:
                    serverResponse_client(upper, lower, r_enc)
                else:
                    s.close()
                
if __name__ == '__main__': 
    user().app()
    