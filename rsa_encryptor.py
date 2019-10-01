from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend())
    public_key = private_key.public_key() 
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
    with open('private_key.pem', 'wb') as f:
        f.write(pem)
    f.close()
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('public_key.pem', 'wb') as f:
        f.write(pem)
    f.close()

def get_keys():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
    key_file.close()
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())
    key_file.close()
    return private_key, public_key

def encrypt_file(file_to_encrypt,public_key_file):
    f=open(file_to_encrypt, 'rb')
    message = f.read()
    f.close()
#    print(message)
    f=open(public_key_file, 'rb')
    public_key = serialization.load_pem_public_key(f.read(),backend=default_backend())
    f.close()
#    print(public_key)
    encrypted = public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    encrypted_file=file_to_encrypt+"_RSA_encrypted"
    f = open(encrypted_file, 'wb')
    f.write(encrypted)
    f.close()

def decrypt_file(file_to_decrypt,private_key_file):
    f=open(file_to_decrypt, 'rb')
    encrypted_message=f.read()
    f.close()
    f=open(private_key_file,'rb')
    private_key = serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
    f.close()
    decrypted_message = private_key.decrypt(encrypted_message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    decrypted_file=file_to_decrypt+"_RSA_decrypted"
    f=open(decrypted_file, 'wb')
    f.write(decrypted_message)
    f.close()

file_to_decrypt=sys.argv[1]
private_key_file=sys.argv[2]
decrypt_file(file_to_decrypt,private_key_file)
#file_to_encrypt=sys.argv[1]
#public_key_file=sys.argv[2]
#print(file_to_encrypt,public_key_file)
#encrypt_file(file_to_encrypt,public_key_file)
