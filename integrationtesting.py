import threading
import time
from server import MessagingServer
from client import MessagingClient


def start_server():
    """Start the server in a separate thread."""
    server = MessagingServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)  # Allow server time to start


def test_client_registration_and_login():
    """Test the client registration and login functionality."""
    client = MessagingClient()

    def client_actions():
        try:
            # Connect to the server
            client.connect()

            # Simulate registration and login
            client.client_socket.sendall(b"yes\n")  # Register new user
            time.sleep(0.1)
            client.client_socket.sendall(b"test_user\n")  # Username
            time.sleep(0.1)
            client.client_socket.sendall(b"test_password\n")  # Password

            # Attempt to log in
            client.client_socket.sendall(b"test_user\n")  # Username
            time.sleep(0.1)
            client.client_socket.sendall(b"test_password\n")  # Correct password

            # Messaging loop simulation
            time.sleep(0.1)
            client.client_socket.sendall(b"exit\n")
        except Exception as e:
            print(f"Client Error: {e}")
        finally:
            client.client_socket.close()

    client_thread = threading.Thread(target=client_actions)
    client_thread.start()
    client_thread.join()


def main():
    start_server()  # Start the server
    test_client_registration_and_login()  # Run integration tests


if __name__ == "__main__":
    main()