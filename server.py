import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


class KeyManager:
    @staticmethod
    def generate_rsa_keys():
        rsa_key = RSA.generate(2048)
        return rsa_key, rsa_key.publickey()

    @staticmethod
    def save_key_to_file(key, filename):
        with open(filename, 'wb') as file:
            file.write(key.export_key())

    @staticmethod
    def load_key_from_file(filename):
        with open(filename, 'rb') as file:
            return RSA.import_key(file.read())


class AuthenticationModule:
    def __init__(self):
        self.user_credentials = {}  # Stores usernames and hashed passwords

    def add_user(self, username, password):
        if username in self.user_credentials:
            raise ValueError("Username already exists.")
        hashed_password = self._hash_password(password)
        self.user_credentials[username] = hashed_password

    def authenticate(self, username, password):
        hashed_password = self._hash_password(password)
        return self.user_credentials.get(username) == hashed_password

    @staticmethod
    def _hash_password(password):
        return SHA256.new(password.encode()).hexdigest()


class MessagingServer:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.auth_module = AuthenticationModule()

        # Generate RSA keys
        self.private_key, self.public_key = KeyManager.generate_rsa_keys()
        KeyManager.save_key_to_file(self.private_key, 'private_key.pem')
        KeyManager.save_key_to_file(self.public_key, 'public_key.pem')

    def handle_client(self, client_socket):
        try:
            # Authentication flow
            client_socket.send(b"Do you want to register? (yes/no): ")
            register_response = client_socket.recv(1024).decode().strip().lower()

            if register_response == "yes":
                client_socket.send(b"Enter new username: ")
                username = client_socket.recv(1024).decode().strip()
                client_socket.send(b"Enter new password: ")
                password = client_socket.recv(1024).decode().strip()

                try:
                    self.auth_module.add_user(username, password)
                    client_socket.send(b"Registration successful! You can now log in.\n")
                except ValueError as e:
                    client_socket.send(f"Error: {str(e)}\n".encode())
                    client_socket.close()
                    return

            client_socket.send(b"Enter username: ")
            username = client_socket.recv(1024).decode().strip()
            client_socket.send(b"Enter password: ")
            password = client_socket.recv(1024).decode().strip()

            if not self.auth_module.authenticate(username, password):
                client_socket.send(b"Authentication failed. Disconnecting...\n")
                client_socket.close()
                return

            client_socket.send(b"Authentication successful. Welcome!\n")

            # Encryption setup
            client_socket.send(self.public_key.export_key())  # Send public key to client
            encrypted_aes_key = client_socket.recv(2048)
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            aes_key = rsa_cipher.decrypt(encrypted_aes_key)

            while True:
                # Receive encrypted message
                received_data = client_socket.recv(1024)
                if not received_data:
                    break

                nonce, ciphertext, tag = (
                    received_data[:16],  # Nonce is 16 bytes
                    received_data[16:-16],  # Ciphertext
                    received_data[-16:],  # Tag
                )

                # Decrypt and verify message
                print(f"Encrypted: {ciphertext} -> Ciphertext: {ciphertext}")
                aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
                print(f"Decrypted: {ciphertext} -> Plaintext: {plaintext}")
                print(f"Decrypted Message: {plaintext.decode()}")

            client_socket.close()

        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()


if __name__ == "__main__":
    server = MessagingServer()
    server.start()
