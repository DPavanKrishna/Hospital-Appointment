import os, json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

#LOAD RSA KEYS 
with open("public_key.pem", "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

with open("private_key.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# AES KEY GENERATION 
def generate_aes_key():
    return os.urandom(32)  # AES-256

#AES ENCRYPT
def aes_encrypt(data: dict, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    plaintext = json.dumps(data).encode()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(iv).decode()
    )

#AES DECRYPT
def aes_decrypt(ciphertext_b64, iv_b64, key):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB(base64.b64decode(iv_b64)),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(base64.b64decode(ciphertext_b64)) + decryptor.finalize()
    return json.loads(plaintext.decode())

#RSA ENCRYPT AES KEY(securely encrypts an AES secret key using RSA public-key cryptography.)
def rsa_encrypt_key(aes_key: bytes):
    encrypted_key = PUBLIC_KEY.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

#RSA DECRYPT AES KEY(securely dencrypts an AES secret key using RSA private-key cryptography)
def rsa_decrypt_key(encrypted_key_b64):
    encrypted_key = base64.b64decode(encrypted_key_b64)
    return PRIVATE_KEY.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
