import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib


def AESencrypt(plaintext, key):
    k = hashlib.sha256(KEY).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext,key

def outputFile(key, ciphertext, newfilename):
  with open(newfilename, "wb") as fc:
    fc.write(ciphertext)
  with open("key.enc", "wb") as fk:
    fk.write(key)
  print('[+] Output encrypted file: %s' % newfilename)
  print('[+] Output key file: key.enc')

  
try:
    content = open(sys.argv[1], "rb").read()
    
except:
    print("File argument needed! %s <C# binary file>" % sys.argv[0])
    sys.exit()

print('[+] File to be encrypted: %s' % sys.argv[1])
KEYString = input("Enter AES Key: ")
KEY = bytes(KEYString, 'utf-8')
ciphertext, key = AESencrypt(content, KEY)
filename = sys.argv[1].split(".");
newfilename = '-'.join(filename[0][i:i+1] for i in range(0, len(filename[0]), 1)) + ".enc"
outputFile(KEY,ciphertext,newfilename)
