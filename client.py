import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class MessagingClient:
    def __init__(self, server_ip='127.0.0.1', server_port=65432):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.client_socket.connect((self.server_ip, self.server_port))
        print("Connected to the server.")

        # Authentication flow
        while True:
            response = self.client_socket.recv(1024).decode()
            print(response, end="")
            user_input = input().strip()
            self.client_socket.send(user_input.encode())

            if "Authentication successful" in response:
                break

        # Receive public key from server
        public_key_data = self.client_socket.recv(2048)
        self.public_key = RSA.import_key(public_key_data)

        # Generate AES key
        aes_key = get_random_bytes(16)

        # Encrypt AES key with server's public key
        rsa_cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        # Send encrypted AES key to server
        self.client_socket.send(encrypted_aes_key)

        # Start messaging loop
        self.messaging_loop(aes_key)

    def messaging_loop(self, aes_key):
        while True:
            message = input("Enter message to send (or 'exit' to quit): ")
            if message.lower() == "exit":
                break

            # Encrypt message using AES
            aes_cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())

            # Send combined nonce + ciphertext + tag to the server
            self.client_socket.send(aes_cipher.nonce + ciphertext + tag)

        self.client_socket.close()


if __name__ == "__main__":
    client = MessagingClient()
    client.connect()