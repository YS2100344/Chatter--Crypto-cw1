import os
import socket
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Logging setup
logging.basicConfig(filename='client-logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

SERVER_ADDRESS = ('127.0.0.1', 8888)
PBKDF2_ITERATIONS = 100000

# RSA key generation for client
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
client_public_key = client_private_key.public_key()
logging.info("Client RSA keys generated.")

# Load server public key
with open("server_public_key.pem", "rb") as key_file:
    server_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
logging.info("Server public key loaded.")

# AES session key generation
aes_key = os.urandom(32)  # 256-bit AES key
logging.info(f"Generated AES Key (client): {aes_key.hex()}")

# Encrypt AES key with server's public RSA key
encrypted_aes_key = server_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
)
logging.info("AES key encrypted with server's public RSA key.")

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(SERVER_ADDRESS)
logging.info("Connected to server.")

# Send encrypted AES key
client_socket.sendall(encrypted_aes_key)

logging.info("Encrypted AES key sent to server.")

# Authentication Functions
def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS, backend=default_backend())
    hashed_password = urlsafe_b64encode(salt + kdf.derive(password.encode()))
    return hashed_password.decode()

def authenticate(username, password):
    client_socket.sendall(f"LOGIN:{username}:{password}".encode())
    response = client_socket.recv(1024).decode()
    if response == "LOGIN_SUCCESS":
        logging.info(f"User '{username}' Login was successful")
        print("Login successful!")
        return True
    elif response == "INVALID_PASSWORD":
        logging.warning(f"User '{username}' login failed due to incorrect password.")
        print("Incorrect password. Please try again.")
        return False
    elif response == "USER_NOT_FOUND":
        logging.warning(f"User '{username}' login failed. Username does not exist.")
        print("Username not found. Please register first.")
        return False


def register(username, password):
    hashed_password = hash_password(password)
    client_socket.sendall(f"REGISTER:{username}:{hashed_password}".encode())
    response = client_socket.recv(1024).decode()
    if response == "REGISTER_SUCCESS":
        logging.info(f"User '{username}' registered successfully.")
        return True
    else:
        logging.error(f"User '{username}' registration failed.")
        return False

# Initial prompt
username = input("Enter username: ")
password = input("Enter password: ")

action = input("Do you want to register or login? (r/l): ")
if action.lower() == 'r':
    if not register(username, password):
        client_socket.close()
        exit()
elif action.lower() == 'l':
    if not authenticate(username, password):
        client_socket.close()
        exit()

# encrypts messages
def encrypt_message(message):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

# allows user to send multiple msgs
try:
    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        nonce, encrypted_message, tag = encrypt_message(message)
        client_socket.sendall(nonce + tag + encrypted_message)
        logging.info(f"Encrypted Message (client): {encrypted_message.hex()}")
finally:
    client_socket.close()
    logging.info("Connection closed.")
