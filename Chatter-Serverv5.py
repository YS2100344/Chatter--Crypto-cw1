import os
import socket
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Logging setup
logging.basicConfig(filename='server-logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

PBKDF2_ITERATIONS = 100000
USERS_FILE = "users.txt"

# RSA key generation for server
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
server_public_key = server_private_key.public_key()
logging.info("Server RSA keys generated.")

# Save server public key
with open("server_public_key.pem", "wb") as key_file:
    key_file.write(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
logging.info("Server RSA Public Key saved to server_public_key.pem.")

# Server socket 
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 8888))
server_socket.listen(5)
print("Chatter Server is now activelylistening on 127.0.0.1:8888 ")
logging.info("Chatter Server is currently listening on 127.0.0.1:8888")


# Authentication Functions
def save_user(username, hashed_password):
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}:{hashed_password}\n")
    logging.info(f"User '{username}' registered successfully.")

def verify_user(username, password):
    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                stored_username, stored_hashed = line.strip().split(":")
                if stored_username == username:
                    salt = urlsafe_b64decode(stored_hashed.encode())[:16]
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS, backend=default_backend())
                    hashed_password = urlsafe_b64encode(salt + kdf.derive(password.encode()))
                    return hashed_password.decode() == stored_hashed
    except FileNotFoundError:
        logging.error("User file not found.")
    return False

def handle_client(client_socket):
    try:
        # Receive encrypted AES key using RSA private key
        encrypted_aes_key = client_socket.recv(256)
        aes_key = server_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        )
        logging.info(f"Decrypted AES Key (server): {aes_key.hex()}")

        # Authentication process
        auth_data = client_socket.recv(1024).decode()
        command, username, password = auth_data.split(":", 2)

        if command == "REGISTER":
            save_user(username, password)
            client_socket.sendall(b"REGISTER_SUCCESS")

        elif command == "LOGIN":
            if verify_user(username, password):
                client_socket.sendall(b"LOGIN_SUCCESS")
                logging.info(f"User '{username}' logged in successfully.")
            else:
                client_socket.sendall(b"LOGIN_FAILURE")
                
                logging.warning(f"Failed login attempt for user '{username}'")
                return

        # Chat loop: Receive multiple messages
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            nonce, tag, ciphertext = data[:12], data[12:28], data[28:]

            # Decrypt the message
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            logging.info(f"Decrypted Message: {decrypted_message.decode()}")
            print(f"Received message from '{username}': {decrypted_message.decode()}")

    except Exception as e:
        logging.error(f"Error handling client: {str(e)}")

    finally:
        client_socket.close()
        logging.info("Connection closed.")

# Accept and handle clients
while True:
    client_socket, addr = server_socket.accept()
    logging.info(f"Connected to client at {addr}")
    handle_client(client_socket)
