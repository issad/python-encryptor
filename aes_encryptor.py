from cryptography.fernet import Fernet
import base64
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def key_generator(password):
    password=password.encode()
    salt=os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=10000,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def read_key_file(key_file):
    file = open(key_file,"rb")
    key = file.read()
    file.close()
    return key

def encrypt_file(input_file,password):
    key=key_generator(password)
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    output_file = input_file+"_encrypted"
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    key_file = input_file+"_key"    
    with open(key_file, 'wb') as f:
        f.write(key)

def decrypt_file(encrypted_file,key_file):
    key=read_key_file(key_file)
    with open(encrypted_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)
    output_file = encrypted_file+"_decrypted"
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    f.close()

#input_file=sys.argv[1]
#password=sys.argv[2]
#encrypt_file(input_file,password)

encrypted_file=sys.argv[1]
key_file=sys.argv[2]
decrypt_file(encrypted_file,key_file)

